//! Linux: everything comes from procfs; container runtime CLIs and
//! systemctl are consulted best-effort for attribution.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::Path;
use std::time::Duration;

use crate::model::{FileOverview, LockEntry, Pid, Process, Socket, Source};
use crate::util::{now_unix, run_ok, strip_deleted_suffix};
use crate::platform::{Capabilities, PlatError, PlatResult, Platform, SystemStats, Users};

const CLK_TCK: f64 = 100.0; // kernel CONFIG_HZ userspace value on effectively all distros
const CMD_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Linux {
    users: Users,
    /// /proc/stat tick snapshot from the previous [`Linux::system_stats`]
    /// call — CPU% is a tick delta, so the first call reports no percents.
    prev_stat: std::cell::RefCell<Option<StatSnapshot>>,
}

impl Linux {
    pub fn new(users: Users) -> Self {
        Linux {
            users,
            prev_stat: std::cell::RefCell::new(None),
        }
    }

    fn boot_time(&self) -> Option<i64> {
        let stat = read_ok(Path::new("/proc/stat"))?;
        for line in stat.lines() {
            if let Some(v) = line.strip_prefix("btime ") {
                return v.trim().parse().ok();
            }
        }
        None
    }
}

fn read_ok(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok()
}

fn readlink_ok(p: &Path) -> Option<String> {
    std::fs::read_link(p).ok().map(|s| s.to_string_lossy().into_owned())
}

// ---------- system resources (system page 'y') ----------

/// One cpu line's tick buckets from /proc/stat: `idle` includes iowait,
/// everything else counts as busy.
#[derive(Debug, Clone, Copy, PartialEq)]
struct StatTicks {
    idle: u64,
    total: u64,
}

/// The aggregate `cpu` line plus every `cpuN` line of one /proc/stat read.
#[derive(Debug, Clone, Default, PartialEq)]
struct StatSnapshot {
    total: Option<StatTicks>,
    cores: Vec<StatTicks>,
}

/// Tick buckets for one cpu line ("12 0 345 6789 0 0 0 0 0 0").
fn sum_ticks(nums: &str) -> StatTicks {
    let mut vals = nums
        .split_whitespace()
        .filter_map(|v| v.parse::<u64>().ok());
    let user = vals.next().unwrap_or(0);
    let nice = vals.next().unwrap_or(0);
    let system = vals.next().unwrap_or(0);
    let idle = vals.next().unwrap_or(0);
    let iowait = vals.next().unwrap_or(0);
    let mut total = user + nice + system + idle + iowait;
    for extra in vals {
        total += extra;
    }
    StatTicks {
        idle: idle + iowait,
        total,
    }
}

/// (aggregate, per-core) from a /proc/stat body; the btime and intr lines
/// don't start with "cpu" and drop out naturally.
fn parse_stat_snapshot(text: &str) -> StatSnapshot {
    let mut snap = StatSnapshot::default();
    for line in text.lines() {
        let Some(body) = line.strip_prefix("cpu") else {
            continue;
        };
        if let Some(nums) = body.strip_prefix(' ') {
            snap.total = Some(sum_ticks(nums));
        } else if body.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            if let Some((_, nums)) = body.split_once(' ') {
                snap.cores.push(sum_ticks(nums));
            }
        }
    }
    snap
}

/// Busy percent between two tick snapshots; None when no ticks elapsed
/// or the counters went backwards (cpu hotplug reordering — rare).
fn busy_between(prev: StatTicks, cur: StatTicks) -> Option<f64> {
    let d_total = cur.total.checked_sub(prev.total)?;
    let d_idle = cur.idle.checked_sub(prev.idle)?;
    (d_total > 0).then(|| (1.0 - d_idle as f64 / d_total as f64).clamp(0.0, 1.0) * 100.0)
}

/// MemAvailable-based used (what free(1) reports) plus swap, from
/// /proc/meminfo. Returns (mem_used, mem_total, swap_used, swap_total) KiB.
fn parse_meminfo(
    text: &str,
) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
    let get_kb = |key: &str| -> Option<u64> {
        text.lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
    };
    let mem_total = get_kb("MemTotal:");
    let avail = get_kb("MemAvailable:").or_else(|| get_kb("MemFree:"));
    let mem_used = mem_total.zip(avail).map(|(t, a)| t.saturating_sub(a));
    let swap_total = get_kb("SwapTotal:");
    let swap_free = get_kb("SwapFree:");
    let swap_used = swap_total.zip(swap_free).map(|(t, f)| t.saturating_sub(f));
    (mem_used, mem_total, swap_used, swap_total)
}

/// `0.52 0.58 0.59 2/1234 5678` → (1, 5, 15-minute load averages).
fn parse_loadavg(text: &str) -> (Option<f64>, Option<f64>, Option<f64>) {
    let mut it = text.split_whitespace();
    (
        it.next().and_then(|v| v.parse().ok()),
        it.next().and_then(|v| v.parse().ok()),
        it.next().and_then(|v| v.parse().ok()),
    )
}

/// The /proc/<pid>/stat fields witr uses. comm may contain spaces and
/// parentheses, so the parse cuts at the LAST ')' — everything after it is
/// field 3+ of stat(5), indexed here by the canonical field number.
#[derive(Debug, Clone)]
pub struct StatInfo {
    pub comm: String,
    /// field 4: parent pid
    pub ppid: Pid,
    /// field 3: state letter (R/S/D/Z/T)
    pub state: char,
    /// field 5: process group id
    pub pgid: Pid,
    /// field 6: session id (the session leader's pid)
    pub sid: Pid,
    /// field 7: controlling terminal as a dev_t (0 = none)
    pub tty_nr: u64,
    /// field 22: start time in clock ticks since boot
    pub starttime: u64,
    /// fields 14+15: utime + stime in clock ticks
    pub cpu_ticks: u64,
    /// field 24: resident set size in pages
    pub rss_pages: u64,
}

fn parse_stat(raw: &str) -> Option<StatInfo> {
    let rparen = raw.rfind(')')?;
    let comm = raw[raw.find('(')? + 1..rparen].to_string();
    let rest = raw[rparen + 2..].split_whitespace().collect::<Vec<_>>();
    // rest[i] = field i+3: rest[0]=state(3) rest[1]=ppid(4) rest[2]=pgid(5)
    // rest[3]=sid(6) rest[4]=tty_nr(7) rest[11]=utime(14) rest[12]=stime(15)
    // rest[19]=starttime(22) rest[21]=rss(24, pages)
    let state = rest.first()?.chars().next()?;
    let ppid: Pid = rest.get(1)?.parse().ok()?;
    let pgid: Pid = rest.get(2)?.parse().unwrap_or(0);
    let sid: Pid = rest.get(3)?.parse().unwrap_or(0);
    let tty_nr: u64 = rest.get(4)?.parse().unwrap_or(0);
    let starttime: u64 = rest.get(19)?.parse().ok()?;
    let utime: u64 = rest.get(11)?.parse().unwrap_or(0);
    let stime: u64 = rest.get(12)?.parse().unwrap_or(0);
    let rss: i64 = rest.get(21)?.parse().unwrap_or(0);
    Some(StatInfo {
        comm,
        ppid,
        state,
        pgid,
        sid,
        tty_nr,
        starttime,
        cpu_ticks: utime + stime,
        rss_pages: rss.max(0) as u64,
    })
}

/// Decode a /proc stat tty_nr (a dev_t) into the short terminal name ps
/// prints: pts/N (major 136), ttyN (major 4), tty/console (major 5),
/// otherwise dev(major:minor). 0 = no controlling terminal → "-".
fn tty_name(tty_nr: u64) -> String {
    if tty_nr == 0 {
        return "-".to_string();
    }
    let major = (tty_nr >> 8) & 0xfff;
    let minor = (tty_nr & 0xff) | ((tty_nr >> 12) & 0xfff00);
    match major {
        136 => format!("pts/{minor}"),
        4 => format!("tty{minor}"),
        // /dev/tty (5:0), /dev/console (5:1); other major-5 minors are
        // oddballs (ptmx…) — keep the dev() literal
        5 if minor == 0 => "tty".to_string(),
        5 if minor == 1 => "console".to_string(),
        _ => format!("dev({major}:{minor})"),
    }
}

fn parse_uid_from_status(raw: &str) -> Option<u32> {
    for line in raw.lines() {
        if let Some(v) = line.strip_prefix("Uid:") {
            // real, effective, saved, fs
            return v.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

fn socket_state_name(st: &str, proto: &str) -> String {
    // /proc/net/tcp6 carries the same state codes as tcp — strip the
    // family suffix so the map covers both; otherwise every tcp6 state
    // (LISTEN included) falls through to the udp catch-all.
    match (proto.strip_suffix('6').unwrap_or(proto), st) {
        ("tcp", "01") => "ESTABLISHED".into(),
        ("tcp", "02") => "SYN_SENT".into(),
        ("tcp", "03") => "SYN_RECV".into(),
        ("tcp", "04") => "FIN_WAIT1".into(),
        ("tcp", "05") => "FIN_WAIT2".into(),
        ("tcp", "06") => "TIME_WAIT".into(),
        ("tcp", "07") => "CLOSE".into(),
        ("tcp", "08") => "CLOSE_WAIT".into(),
        ("tcp", "0A") => "LISTEN".into(),
        ("tcp", _) => format!("0x{}", st),
        _ => "UNCONNECTED".into(),
    }
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn hex_v4(s: &str) -> Option<String> {
    let b = hex_bytes(s)?;
    if b.len() != 4 {
        return None;
    }
    // /proc/net/tcp stores IPv4 little-endian.
    Some(format!("{}.{}.{}.{}", b[3], b[2], b[1], b[0]))
}

fn hex_v6(s: &str) -> Option<String> {
    if s.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(8).enumerate() {
        let cs = std::str::from_utf8(chunk).ok()?;
        let b = hex_bytes(cs)?;
        // Each 32-bit word is stored little-endian.
        bytes[i * 4..i * 4 + 4].copy_from_slice(&[b[3], b[2], b[1], b[0]]);
    }
    Some(
        std::net::Ipv6Addr::from(bytes)
            .to_string(),
    )
}

/// One line of /proc/net/{tcp,udp}[6] (minus the header).
fn parse_net_entry(line: &str, proto: &str) -> Option<(String, u16, String, String, u64)> {
    // local remote state ... inode is the 10th column.
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 10 {
        return None;
    }
    let (local, rem) = (cols[1], cols[2]);
    let (lip, lport) = local.split_once(':')?;
    let lport = u16::from_str_radix(lport, 16).ok()?;
    let local_addr = if proto.ends_with('6') {
        hex_v6(lip)?
    } else {
        hex_v4(lip)?
    };
    let state = socket_state_name(cols[3], proto);
    let inode: u64 = cols[9].parse().ok()?;
    Some((local_addr, lport, rem.to_string(), state, inode))
}

fn read_socket_table(proto: &str) -> Vec<(String, u16, String, String, u64)> {
    let path = format!("/proc/net/{}", proto);
    let Some(text) = read_ok(Path::new(&path)) else {
        return Vec::new();
    };
    text.lines()
        .skip(1)
        .filter_map(|l| parse_net_entry(l, proto))
        .collect()
}

/// remote column + inode + owner map → finished Socket.
fn build_socket(
    proto: &str,
    addr: String,
    port: u16,
    rem: String,
    state: String,
    inode: u64,
    owners: &HashMap<u64, Pid>,
) -> Socket {
    let (peer_addr, peer_port) = match rem.split_once(':') {
        Some((ip, pt)) => {
            let pt = u16::from_str_radix(pt, 16).unwrap_or(0);
            let ip = if proto.ends_with('6') {
                hex_v6(ip)
            } else {
                hex_v4(ip)
            };
            match ip {
                Some(ip) if pt != 0 => (Some(ip), Some(pt)),
                _ => (None, None),
            }
        }
        None => (None, None),
    };
    Socket {
        proto: proto.to_string(),
        local_addr: addr,
        local_port: port,
        peer_addr,
        peer_port,
        state,
        pid: owners.get(&inode).copied(),
    }
}

/// inode -> pid, from /proc/<pid>/fd/* links ("socket:[inode]").
fn inode_owner_map() -> HashMap<u64, Pid> {
    let mut map = HashMap::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return map;
    };
    for entry in procs.flatten() {
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<Pid>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue; // other user's process without root
        };
        for fd in fds.flatten() {
            if let Some(target) = readlink_ok(&fd.path()) {
                if let Some(inode) = target
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                    .and_then(|s| s.parse().ok())
                {
                    map.insert(inode, pid);
                }
            }
        }
    }
    map
}

/// One /proc/locks row:
/// `1: FLOCK ADVISORY WRITE 4242 00:1f:12345 0 EOF` →
/// (id, kind, mode, pid, device:inode).
fn parse_proc_lock_line(line: &str) -> Option<(String, String, String, Pid, String)> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 6 {
        return None;
    }
    Some((
        f[0].trim_end_matches(':').to_string(),
        f[1].to_string(),
        f[3].to_string(),
        f[4].parse().ok()?,
        f[5].to_string(),
    ))
}

fn comm_of(pid: Pid) -> String {
    read_ok(Path::new(&format!("/proc/{}/comm", pid)))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Read cumulative disk counters out of a /proc/<pid>/io file into `p`.
/// Missing keys / unreadable file leave the fields untouched (None).
fn fill_io_from_proc(io_path: &Path, p: &mut Process) {
    let Ok(io) = std::fs::read_to_string(io_path) else {
        return;
    };
    for line in io.lines() {
        if let Some((k, v)) = line.split_once(": ") {
            let val = v.trim().parse().ok();
            match k {
                "read_bytes" => p.io_read_bytes = val,
                "syscr" => p.io_read_ops = val,
                "write_bytes" => p.io_write_bytes = val,
                "syscw" => p.io_write_ops = val,
                _ => {}
            }
        }
    }
}

/// (open fds, soft "Max open files" limit) from procfs. None when either
/// file is unreadable (other user's process without root).
fn fd_usage(pid: Pid) -> Option<(u64, u64)> {
    let used = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?.count() as u64;
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).ok()?;
    let soft = parse_max_open_files(&limits)?;
    Some((used, soft))
}

/// Soft limit from a /proc/<pid>/limits "Max open files" row:
/// `Max open files  1024  4096  1048576` → fields[3].
fn parse_max_open_files(limits: &str) -> Option<u64> {
    let line = limits.lines().find(|l| l.starts_with("Max open files"))?;
    line.split_whitespace().nth(3)?.parse().ok()
}

/// fd link targets worth showing in the "all open files" view: real files
/// on disk, not kernel-internal handles (sockets, pipes, eventfds, memfds,
/// procfs/sysfs bookkeeping, terminals).
fn open_file_target(target: &str) -> bool {
    !(target.starts_with("socket:[")
        || target.starts_with("pipe:[")
        || target.starts_with("anon_inode:")
        || target.starts_with("/memfd:")
        || target.starts_with("/proc/")
        || target.starts_with("/sys/")
        || target == "/dev/null"
        || target.starts_with("/dev/tty")
        || target.starts_with("/dev/pts/"))
}

/// R/W/RW from the O_ACCMODE bits in /proc/<pid>/fdinfo/<fd>; "" when the
/// fdinfo isn't readable.
fn fdinfo_access(pid: Pid, fd: &str) -> String {
    let Ok(data) = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")) else {
        return String::new();
    };
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix("flags:") {
            if let Ok(flags) = i64::from_str_radix(rest.trim(), 8) {
                return match flags & 3 {
                    0 => "R",
                    1 => "W",
                    2 => "RW",
                    _ => "",
                }
                .into();
            }
        }
    }
    String::new()
}

/// Inode of `path` — std has no portable inode, so this is unix-only; the
/// module type-checks everywhere, hence the cfg pair.
fn inode_of(path: &std::path::Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|m| m.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// inode -> path map for one pid's fd table, cached per scan. /proc/locks
/// emits device:inode but its device numbering doesn't always match what
/// userspace stat returns, so matching is on the inode alone (collisions
/// across filesystems are vanishingly rare).
fn fd_inode_paths(
    pid: Pid,
    cache: &mut HashMap<Pid, HashMap<String, String>>,
) -> &HashMap<String, String> {
    cache.entry(pid).or_insert_with(|| {
        let mut m = HashMap::new();
        if let Ok(fds) = std::fs::read_dir(format!("/proc/{}/fd", pid)) {
            for fd in fds.flatten() {
                if let Some(target) = readlink_ok(&fd.path()) {
                    if let Some(ino) = inode_of(std::path::Path::new(&target)) {
                        m.insert(ino.to_string(), target);
                    }
                }
            }
        }
        m
    })
}

impl Platform for Linux {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn file_overview(&self, pid: Pid) -> FileOverview {
        FileOverview {
            files: self.open_files(pid),
            locks: self.list_locks(Some(pid)),
            fd_usage: fd_usage(pid),
        }
    }

    fn fd_count(&self, pid: Pid) -> Option<u64> {
        std::fs::read_dir(format!("/proc/{pid}/fd"))
            .ok()
            .map(|d| d.count() as u64)
    }

    fn fd_counts(&self) -> Option<std::collections::HashMap<Pid, u64>> {
        let mut out = std::collections::HashMap::new();
        let dirs = std::fs::read_dir("/proc").ok()?;
        for d in dirs.flatten() {
            let Ok(pid) = d.file_name().to_string_lossy().parse::<Pid>() else {
                continue;
            };
            if pid <= 0 {
                continue;
            }
            if let Some(n) = self.fd_count(pid) {
                out.insert(pid, n);
            }
        }
        Some(out)
    }

    fn list_all_open_files(&self) -> Vec<LockEntry> {
        let mut out = Vec::new();
        let mut comms: HashMap<Pid, String> = HashMap::new();
        let Ok(dirs) = std::fs::read_dir("/proc") else {
            return out;
        };
        for d in dirs.flatten() {
            let Ok(pid) = d.file_name().to_string_lossy().parse::<Pid>() else {
                continue;
            };
            if pid <= 0 {
                continue;
            }
            let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
                continue; // permission denied or the process just exited
            };
            for fd in fds.flatten() {
                let Some(target) = readlink_ok(&fd.path()) else {
                    continue;
                };
                if !open_file_target(&target) {
                    continue;
                }
                let fdnum = fd.file_name().to_string_lossy().to_string();
                let owner = comms.entry(pid).or_insert_with(|| comm_of(pid)).clone();
                out.push(LockEntry {
                    id: fdnum.clone(),
                    kind: "OPEN".into(),
                    mode: fdinfo_access(pid, &fdnum),
                    pid: Some(pid),
                    owner,
                    path: target,
                });
            }
        }
        out
    }

    fn list_locks(&self, pid: Option<Pid>) -> Vec<LockEntry> {
        let Some(text) = read_ok(Path::new("/proc/locks")) else {
            return Vec::new();
        };
        let mut fd_cache: HashMap<Pid, HashMap<String, String>> = HashMap::new();
        let mut comm_cache: HashMap<Pid, String> = HashMap::new();
        text.lines()
            .filter_map(|line| {
                let (id, kind, mode, holder, dev_inode) = parse_proc_lock_line(line)?;
                if let Some(want) = pid {
                    if holder != want {
                        return None;
                    }
                }
                // resolve the holder's fd table only for the locks we keep
                let inode = dev_inode.rsplit(':').next().unwrap_or(&dev_inode);
                let path = fd_inode_paths(holder, &mut fd_cache)
                    .get(inode)
                    .cloned()
                    .unwrap_or(dev_inode);
                let owner = comm_cache
                    .entry(holder)
                    .or_insert_with(|| comm_of(holder))
                    .clone();
                Some(LockEntry {
                    id,
                    kind,
                    mode,
                    pid: Some(holder),
                    owner,
                    path,
                })
            })
            .collect()
    }


    fn capabilities(&self) -> Capabilities {
        Capabilities {
            file_lookup: true,
            env: true,
        }
    }

    fn list_processes(&self) -> PlatResult<Vec<Process>> {
        let btime = self
            .boot_time()
            .ok_or_else(|| PlatError::Failed("cannot read boot time".into()))?;
        let mut procs = Vec::new();
        let entries =
            std::fs::read_dir("/proc").map_err(|e| PlatError::Failed(format!("read /proc: {}", e)))?;
        for entry in entries.flatten() {
            let fname = entry.file_name();
            let Ok(pid) = fname.to_string_lossy().parse::<Pid>() else {
                continue;
            };
            let base = entry.path();
            let Some(stat) = read_ok(&base.join("stat")) else {
                continue;
            };
            let Some(s) = parse_stat(&stat) else {
                continue;
            };
            let (ppid, state, starttime, cpu_ticks, rss_pages, tty_nr) = (
                s.ppid,
                s.state,
                s.starttime,
                s.cpu_ticks,
                s.rss_pages,
                s.tty_nr,
            );
            let uid = read_ok(&base.join("status"))
                .and_then(|s| parse_uid_from_status(&s));
            let kernel_thread = pid == 2 || ppid == 2;
            let started = if !kernel_thread {
                Some(btime + (starttime as f64 / CLK_TCK).round() as i64)
            } else {
                None
            };
            let cpu = (!kernel_thread && started.is_some()).then(|| {
                let elapsed = now_unix() - started.unwrap();
                if elapsed > 0 {
                    (cpu_ticks as f64 / CLK_TCK) / elapsed as f64 * 100.0
                } else {
                    0.0
                }
            });
            let cpu_time_ms = (!kernel_thread && cpu_ticks > 0)
                .then_some((cpu_ticks as f64 * 1000.0 / CLK_TCK) as u64);
            let mem_kb = (rss_pages > 0).then_some(rss_pages * 4); // 4 KiB pages
            procs.push(Process {
                pid,
                ppid: Some(ppid),
                name: s.comm,
                user: uid.and_then(|u| self.users.name_for(u)),
                uid,
                started,
                kernel_thread,
                cpu: cpu.filter(|c| *c > 0.05),
                mem_kb: mem_kb.filter(|m| *m > 0),
                cpu_time_ms,
                state: Some(state.to_string()),
                tty: Some(tty_name(tty_nr)),
                pgid: Some(s.pgid),
                sid: Some(s.sid),
                ..Default::default()
            });
        }
        Ok(procs)
    }

    fn detail(&self, brief: &Process, want_env: bool) -> Process {
        let mut p = brief.clone();
        let base = Path::new("/proc").join(brief.pid.to_string());
        // lifetime-average CPU, unfiltered (the listing drops 0.0% rows to
        // cut table noise, but in the detail pane 0.0% is meaningful)
        if !p.kernel_thread {
            if let (Some(stat), Some(btime)) = (read_ok(&base.join("stat")), self.boot_time()) {
                if let Some(s) = parse_stat(&stat) {
                    let started_at = btime + (s.starttime as f64 / CLK_TCK).round() as i64;
                    let elapsed = now_unix() - started_at;
                    p.cpu = Some(if elapsed > 0 {
                        (s.cpu_ticks as f64 / CLK_TCK) / elapsed as f64 * 100.0
                    } else {
                        0.0
                    });
                }
            }
        }
        if let Some(exe) = readlink_ok(&base.join("exe")) {
            let (path, deleted) = strip_deleted_suffix(&exe);
            p.exe = Some(path.to_string());
            p.exe_deleted = deleted;
        }
        p.cwd = readlink_ok(&base.join("cwd"));
        if let Ok(raw) = std::fs::read(base.join("cmdline")) {
            let parts: Vec<String> = raw
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            if !parts.is_empty() {
                p.cmdline = parts;
            }
        }
        if want_env && !p.kernel_thread {
            match std::fs::read(base.join("environ")) {
                Ok(raw) => {
                    p.env = Some(
                        raw.split(|&b| b == 0)
                            .filter(|s| !s.is_empty())
                            .filter_map(|kv| {
                                let s = String::from_utf8_lossy(kv);
                                let (k, v) = s.split_once('=')?;
                                Some((k.to_string(), v.to_string()))
                            })
                            .collect(),
                    );
                }
                Err(e) if e.kind() == ErrorKind::PermissionDenied => { /* leave None */ }
                Err(_) => { /* leave None */ }
            }
        }
        // memory / threads from status; a fresh VmRSS beats the statm
        // snapshot the brief listing took
        if let Some(status) = read_ok(&base.join("status")) {
            let mut vm_kb = None;
            let mut rss_kb = None;
            let mut private_kb = None;
            let mut threads = None;
            for line in status.lines() {
                let mut it = line.split_whitespace();
                match it.next().unwrap_or("") {
                    "VmSize:" => vm_kb = it.next().and_then(|v| v.parse().ok()),
                    "VmRSS:" => rss_kb = it.next().and_then(|v| v.parse().ok()),
                    "RssAnon:" => private_kb = it.next().and_then(|v| v.parse().ok()),
                    "Threads:" => threads = it.next().and_then(|v| v.parse().ok()),
                    _ => {}
                }
            }
            p.vm_kb = vm_kb;
            p.private_kb = private_kb;
            p.threads = threads;
            if let Some(kb) = rss_kb {
                p.mem_kb = Some(kb).filter(|m| *m > 0);
            }
        }
        // disk I/O (same-user only; kernel threads and other users -> None)
        fill_io_from_proc(&base.join("io"), &mut p);
        // cgroup v2 panel: the control-group path from /proc/<pid>/cgroup's
        // "0::" line (a v1-only system has no such line — skip), plus the
        // group's memory.current and cpu.stat usage_usec read back from
        // /sys/fs/cgroup<path>. The root group is the whole machine, not
        // per-process information, so "/" stays empty.
        if let Some(cg) = read_ok(&base.join("cgroup")) {
            if let Some(path) = cg.lines().find_map(|l| l.strip_prefix("0::")) {
                let path = path.trim();
                if path != "/" {
                    p.cgroup = Some(path.to_string());
                    let cg_root =
                        Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/'));
                    if let Some(txt) = read_ok(&cg_root.join("memory.current")) {
                        p.cgroup_mem_bytes = txt.trim().parse().ok();
                    }
                    if let Some(stat) = read_ok(&cg_root.join("cpu.stat")) {
                        for line in stat.lines() {
                            if let Some(v) = line.strip_prefix("usage_usec ") {
                                p.cgroup_cpu_usec = v.trim().parse().ok();
                            }
                        }
                    }
                }
            }
        }
        p.capabilities = self.process_capabilities(brief.pid);
        p.hup_ignored = sigign_hup(brief.pid);
        p
    }

    /// Listing pass for the TUI IO column: read each pid's cumulative disk
    /// counters straight from /proc/<pid>/io (a tiny file per pid). Same-user
    /// processes succeed; under ptrace_scope other users' io files are
    /// unreadable and stay `None`, which the column treats as "no data".
    fn enrich_listing(&self, procs: &mut [Process]) {
        for p in procs.iter_mut() {
            fill_io_from_proc(
                &Path::new("/proc").join(p.pid.to_string()).join("io"),
                p,
            );
        }
    }

    /// Three /proc file reads — microseconds, sampled every refresh. CPU
    /// needs two calls (tick delta), so the first reports memory/load only.
    fn system_stats(&self) -> Option<SystemStats> {
        let stat = read_ok(Path::new("/proc/stat"))?;
        let snapshot = parse_stat_snapshot(&stat);
        let mut out = SystemStats::default();

        let mut prev = self.prev_stat.borrow_mut();
        if let Some(p) = prev.as_ref() {
            out.cpu_percent = p
                .total
                .zip(snapshot.total)
                .and_then(|(a, b)| busy_between(a, b));
            out.cores = p
                .cores
                .iter()
                .zip(&snapshot.cores)
                .filter_map(|(a, b)| busy_between(*a, *b))
                .collect();
        }
        *prev = Some(snapshot);
        drop(prev);

        if let Some(mi) = read_ok(Path::new("/proc/meminfo")) {
            let (mu, mt, su, st) = parse_meminfo(&mi);
            out.mem_used_mb = mu.map(|kb| kb / 1024);
            out.mem_total_mb = mt.map(|kb| kb / 1024);
            out.swap_used_mb = su.map(|kb| kb / 1024);
            out.swap_total_mb = st.map(|kb| kb / 1024);
        }
        if let Some(la) = read_ok(Path::new("/proc/loadavg")) {
            let (l1, l5, l15) = parse_loadavg(&la);
            out.load1 = l1;
            out.load5 = l5;
            out.load15 = l15;
        }
        Some(out)
    }

    /// Effective capabilities from /proc/<pid>/status CapEff, decoded to the
    /// kernel's names. A process in another user namespace (rootless
    /// container) holds them only over that namespace — report none, like
    /// Go witr.
    fn process_capabilities(&self, pid: Pid) -> Vec<String> {
        if in_other_user_namespace(pid) {
            return Vec::new();
        }
        let Some(status) = read_ok(&Path::new("/proc").join(pid.to_string()).join("status"))
        else {
            return Vec::new();
        };
        for line in status.lines() {
            if let Some(hex) = line.strip_prefix("CapEff:") {
                return decode_capabilities(hex.trim());
            }
        }
        Vec::new()
    }

    fn port_to_sockets(&self, port: u16) -> PlatResult<Vec<Socket>> {
        let owners = inode_owner_map();
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for proto in ["tcp", "tcp6", "udp", "udp6"] {
            for (addr, p, rem, state, inode) in read_socket_table(proto) {
                if p != port || !seen.insert(inode) {
                    continue;
                }
                out.push(build_socket(proto, addr, p, rem, state, inode, &owners));
            }
        }
        Ok(out)
    }

    fn list_sockets(&self) -> PlatResult<Vec<Socket>> {
        socket_snapshot_impl(false)
    }

    fn list_all_sockets(&self) -> PlatResult<Vec<Socket>> {
        socket_snapshot_impl(true)
    }

    fn container_processes(&self, id: &str) -> Vec<Process> {
        let procs = self.list_processes().unwrap_or_default();
        procs
            .into_iter()
            .filter(|p| {
                read_ok(&std::path::PathBuf::from(format!("/proc/{}/cgroup", p.pid)))
                    .map(|cg| cg.contains(id))
                    .unwrap_or(false)
            })
            .collect()
    }

    fn open_files(&self, pid: Pid) -> Vec<String> {
        let mut files: Vec<String> = Vec::new();
        let mut unknown_socks = 0usize;
        let mut pipes = 0usize;
        // inode -> "tcp 127.0.0.1:5432 -> 10.0.0.1:443 (ESTABLISHED)" from
        // the kernel tables, so socket fds show their endpoints instead of
        // a bare socket:[inode] (a few file reads, no /proc scan)
        let mut sock_info: HashMap<u64, String> = HashMap::new();
        let no_owners = HashMap::new();
        for proto in ["tcp", "tcp6", "udp", "udp6"] {
            for (addr, port, rem, state, inode) in read_socket_table(proto) {
                let s = build_socket(proto, addr, port, rem, state, inode, &no_owners);
                let line = match (s.peer_addr, s.peer_port) {
                    (Some(pa), Some(pp)) => format!(
                        "{} {}:{} -> {}:{} ({})",
                        s.proto, s.local_addr, s.local_port, pa, pp, s.state
                    ),
                    _ => format!("{} {}:{} ({})", s.proto, s.local_addr, s.local_port, s.state),
                };
                sock_info.entry(inode).or_insert(line);
            }
        }
        let Ok(fds) = std::fs::read_dir(format!("/proc/{}/fd", pid)) else {
            return files; // other user's process without root
        };
        for fd in fds.flatten() {
            if let Some(target) = readlink_ok(&fd.path()) {
                if let Some(rest) = target
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                {
                    match rest.parse::<u64>().ok().and_then(|i| sock_info.get(&i)) {
                        Some(line) => {
                            let l = format!("socket {line}");
                            if !files.contains(&l) {
                                files.push(l);
                            }
                        }
                        None => unknown_socks += 1, // unix / netlink socket
                    }
                } else if target.starts_with("pipe:") {
                    pipes += 1;
                } else if target.starts_with("anon_inode:") {
                    continue;
                } else {
                    let (p, deleted) = strip_deleted_suffix(&target);
                    let line = if deleted {
                        format!("{} (deleted)", p)
                    } else {
                        p.to_string()
                    };
                    if !files.contains(&line) {
                        files.push(line);
                    }
                }
            }
        }
        if unknown_socks > 0 {
            files.push(format!("[{} unix/netlink socket(s)]", unknown_socks));
        }
        if pipes > 0 {
            files.push(format!("[{} pipe(s)]", pipes));
        }
        files.truncate(200);
        files
    }

    fn file_to_pids(&self, path: &str) -> PlatResult<Vec<Pid>> {
        let want = std::fs::canonicalize(path)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string());
        let mut out = Vec::new();
        let entries =
            std::fs::read_dir("/proc").map_err(|e| PlatError::Failed(format!("read /proc: {}", e)))?;
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<Pid>() else {
                continue;
            };
            let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                if let Some(target) = readlink_ok(&fd.path()) {
                    let (t, _deleted) = strip_deleted_suffix(&target);
                    if t == want {
                        out.push(pid);
                        break;
                    }
                }
            }
        }
        Ok(out)
    }

    fn container_of(&self, pid: Pid) -> Option<Source> {
        let cg = read_ok(&std::path::PathBuf::from(format!("/proc/{}/cgroup", pid)))?;
        for line in cg.lines() {
            let Some(path) = line.splitn(3, ':').nth(2) else {
                continue;
            };
            let (runtime, id) = if let Some(rest) = path.strip_prefix("/docker/") {
                ("docker", rest)
            } else if let Some(rest) = path
                .strip_prefix("/system.slice/docker-")
                .and_then(|s| s.strip_suffix(".scope"))
            {
                ("docker", rest)
            } else if let Some(rest) = path
                .strip_prefix("/system.slice/containerd-")
                .or_else(|| path.split("cri-containerd:").nth(1))
                .or_else(|| path.split("cri-containerd-").nth(1))
            {
                ("containerd", rest)
            } else if let Some(rest) = path
                .split("libpod-")
                .nth(1)
                .and_then(|s| s.split(".scope").next())
            {
                ("podman", rest)
            } else if path.contains("kubepods") {
                // .../kubepods/<qos>/pod<uid>/<container-id>
                let id = path.rsplit('/').next().unwrap_or(path);
                ("kubernetes", id)
            } else if path.contains("colima") {
                // colima's docker cgroups live under its own slice
                let id = path.rsplit('/').next().unwrap_or(path);
                ("colima", id)
            } else if let Some(rest) = path.strip_prefix("/lxc/") {
                ("lxc", rest)
            } else {
                continue;
            };
            let id = id.split('/').next().unwrap_or(id);
            let mut label = id.chars().take(12).collect::<String>();
            let mut detail = format!("runtime: {}", runtime);
            if runtime == "docker" || runtime == "colima" {
                if let Some(name) = run_ok(
                    "docker",
                    &["ps", "--filter", &format!("id={}", label), "--format", "{{.Names}}"],
                    CMD_TIMEOUT,
                ) {
                    let name = name.trim();
                    if !name.is_empty() {
                        detail = format!("docker container \"{}\"", name);
                        label = name.to_string();
                    }
                }
            }
            return Some(Source {
                kind: "container".into(),
                label: Some(label),
                detail: Some(detail),
                ..Default::default()
            });
        }
        None
    }

    fn service_source(&self, chain: &[Process]) -> Option<Source> {
        let init = chain.first()?;
        let target = chain.last()?;
        if !init.name.contains("systemd") && init.pid != 1 {
            return None;
        }
        let out = match run_ok(
            "systemctl",
            &["status", &target.pid.to_string(), "--no-pager"],
            CMD_TIMEOUT,
        ) {
            Some(o) => o,
            None => {
                return Some(Source {
                    kind: "init".into(),
                    label: Some(init.name.clone()),
                    detail: Some("systemctl unavailable; started under init".into()),
                    ..Default::default()
                })
            }
        };
        let mut unit_line: Option<(String, Option<String>)> = None;
        let mut loaded_from: Option<String> = None;
        for line in out.lines() {
            let t = line.trim_start();
            let bullet = t
                .strip_prefix('●')
                .or_else(|| t.strip_prefix('*'))
                .map(|rest| rest.trim());
            if let Some(l) = bullet {
                let mut it = l.splitn(2, " - ");
                let unit = it.next().unwrap_or("").trim().to_string();
                let desc = it.next().map(|s| s.trim().to_string());
                unit_line = Some((unit, desc));
            }
            // Loaded: loaded (/lib/systemd/system/nginx.service; enabled; preset: enabled)
            if let Some(rest) = t.strip_prefix("Loaded:") {
                loaded_from = rest
                    .split(['(', ';'])
                    .map(|t| t.trim())
                    .find(|t| {
                        t.ends_with(".service")
                            || t.ends_with(".timer")
                            || t.ends_with(".scope")
                            || t.ends_with(".slice")
                    })
                    .map(|t| t.to_string());
            }
        }
        match unit_line {
            Some((unit, desc)) => {
                let detail = match (desc, loaded_from) {
                    (Some(d), Some(p)) => Some(format!("{} — loaded from {}", d, p)),
                    (Some(d), None) => Some(d),
                    (None, Some(p)) => Some(format!("loaded from {}", p)),
                    (None, None) => None,
                };
                Some(Source {
                    kind: "systemd".into(),
                    label: Some(unit.clone()),
                    detail,
                    ..enrich_systemd_unit(&unit)
                })
            }
            None => Some(Source {
                kind: "init".into(),
                label: Some(init.name.clone()),
                detail: Some(format!("pid {} is not part of a systemd unit", target.pid)),
                ..Default::default()
            }),
        }
    }

    fn service_pid(&self, name: &str) -> Option<Pid> {
        // Accept both "nginx" and "nginx.service".
        let unit = if name.ends_with(".service") {
            name.to_string()
        } else {
            format!("{}.service", name)
        };
        let out = run_ok(
            "systemctl",
            &["show", &unit, "--no-pager", "--property=MainPID"],
            CMD_TIMEOUT,
        )?;
        let pid: Pid = out
            .lines()
            .find_map(|l| l.strip_prefix("MainPID="))
            .and_then(|v| v.trim().parse().ok())?;
        (pid > 0).then_some(pid)
    }
}

/// One sweep over /proc/net/{tcp,tcp6,udp,udp6}. `all_states` keeps tcp
/// connections in any state (Ports-tab 'a' toggle); otherwise only
/// listening tcp + bound udp, mirroring the Go witr's default view.
fn socket_snapshot_impl(all_states: bool) -> PlatResult<Vec<Socket>> {
    let owners = inode_owner_map();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for proto in ["tcp", "tcp6", "udp", "udp6"] {
        for (addr, p, rem, state, inode) in read_socket_table(proto) {
            let keep = if proto.starts_with("tcp") {
                all_states || state == "LISTEN"
            } else {
                true
            };
            if !keep || !seen.insert(inode) {
                continue;
            }
            out.push(build_socket(proto, addr, p, rem, state, inode, &owners));
        }
    }
    out.sort_by_key(|a| (a.proto.clone(), a.local_port));
    Ok(out)
}

/// Best-effort `systemctl show` enrichment for a unit: description file,
/// restart count and the timer that triggers it (when one exists).
fn enrich_systemd_unit(unit: &str) -> Source {
    let mut src = Source::default();
    let Ok(out) = crate::util::run(
        "systemctl",
        &[
            "show",
            unit,
            "--no-pager",
            "--property=Description,FragmentPath,SourcePath,NRestarts,Triggers",
        ],
        std::time::Duration::from_secs(3),
    ) else {
        return src;
    };
    let mut triggers: Vec<String> = Vec::new();
    for line in out.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "Description" if !v.is_empty() && v != unit => {
                src.detail = Some(v.to_string());
            }
            "FragmentPath" if !v.is_empty() => src.detail = src.detail.map(|d| format!("{d} — loaded from {v}")),
            "SourcePath" if !v.is_empty() && !out.contains("FragmentPath=") => {
                src.detail = src.detail.map(|d| format!("{d} — loaded from {v}"))
            }
            "NRestarts" => src.restarts = v.parse::<u32>().ok(),
            "Triggers" if !v.is_empty() => {
                triggers = v.split_whitespace().map(|t| t.to_string()).collect()
            }
            _ => {}
        }
    }
    if let Some(timer) = triggers.iter().find(|t| t.ends_with(".timer")) {
        if let Some(extra) = src.detail.as_mut() {
            extra.push_str(&format!(" — triggered by {timer}"));
        } else {
            src.detail = Some(format!("triggered by {timer}"));
        }
    }
    src
}

fn in_other_user_namespace(pid: Pid) -> bool {
    let (Ok(own), Ok(theirs)) = (
        std::fs::read_link("/proc/self/ns/user"),
        std::fs::read_link(format!("/proc/{}/ns/user", pid)),
    ) else {
        return false;
    };
    own != theirs
}

/// Capability bit names from include/uapi/linux/capability.h.
fn cap_name(bit: u32) -> Option<&'static str> {
    Some(match bit {
        0 => "CAP_CHOWN",
        1 => "CAP_DAC_OVERRIDE",
        2 => "CAP_DAC_READ_SEARCH",
        3 => "CAP_FOWNER",
        4 => "CAP_FSETID",
        5 => "CAP_KILL",
        6 => "CAP_SETGID",
        7 => "CAP_SETUID",
        8 => "CAP_SETPCAP",
        9 => "CAP_LINUX_IMMUTABLE",
        10 => "CAP_NET_BIND_SERVICE",
        11 => "CAP_NET_BROADCAST",
        12 => "CAP_NET_ADMIN",
        13 => "CAP_NET_RAW",
        14 => "CAP_IPC_LOCK",
        15 => "CAP_IPC_OWNER",
        16 => "CAP_SYS_MODULE",
        17 => "CAP_SYS_RAWIO",
        18 => "CAP_SYS_CHROOT",
        19 => "CAP_SYS_PTRACE",
        20 => "CAP_SYS_PACCT",
        21 => "CAP_SYS_ADMIN",
        22 => "CAP_SYS_BOOT",
        23 => "CAP_SYS_NICE",
        24 => "CAP_SYS_RESOURCE",
        25 => "CAP_SYS_TIME",
        26 => "CAP_SYS_TTY_CONFIG",
        27 => "CAP_MKNOD",
        28 => "CAP_LEASE",
        29 => "CAP_AUDIT_WRITE",
        30 => "CAP_AUDIT_CONTROL",
        31 => "CAP_SETFCAP",
        32 => "CAP_MAC_OVERRIDE",
        33 => "CAP_MAC_ADMIN",
        34 => "CAP_SYSLOG",
        35 => "CAP_WAKE_ALARM",
        36 => "CAP_BLOCK_SUSPEND",
        37 => "CAP_AUDIT_READ",
        38 => "CAP_PERFMON",
        39 => "CAP_BPF",
        40 => "CAP_CHECKPOINT_RESTORE",
        _ => return None,
    })
}

fn decode_capabilities(hex: &str) -> Vec<String> {
    let Ok(val) = u64::from_str_radix(hex, 16) else {
        return Vec::new();
    };
    if val == 0 {
        return Vec::new();
    }
    (0..64)
        .filter(|bit| val & (1u64 << bit) != 0)
        .filter_map(|bit| cap_name(bit).map(|n| n.to_string()))
        .collect()
}

/// True when the process ignores SIGHUP (nohup / disown): signal 1 = bit 0
/// of /proc/<pid>/status SigIgn. Unreadable status degrades to false —
/// no evidence, no note.
fn sigign_hup(pid: Pid) -> bool {
    let Some(status) = read_ok(&Path::new("/proc").join(pid.to_string()).join("status")) else {
        return false;
    };
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("SigIgn:") {
            return hup_bit(hex.trim());
        }
    }
    false
}

/// The SIGHUP bit of a hex signal mask (SigIgn layout: bit n = signal n+1).
fn hup_bit(hex: &str) -> bool {
    u64::from_str_radix(hex, 16).is_ok_and(|m| m & 0x1 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_state_names_cover_both_address_families() {
        // tcp6 shares tcp's state codes; before the family-strip, every
        // tcp6 socket (LISTEN included) fell through to "UNCONNECTED"
        assert_eq!(socket_state_name("0A", "tcp"), "LISTEN");
        assert_eq!(socket_state_name("0A", "tcp6"), "LISTEN");
        assert_eq!(socket_state_name("01", "tcp6"), "ESTABLISHED");
        assert_eq!(socket_state_name("06", "tcp6"), "TIME_WAIT");
        // unknown tcp code keeps the raw hex; udp families stay UNCONNECTED
        assert_eq!(socket_state_name("FF", "tcp6"), "0xFF");
        assert_eq!(socket_state_name("01", "udp"), "UNCONNECTED");
        assert_eq!(socket_state_name("01", "udp6"), "UNCONNECTED");
    }

    #[test]
    fn stat_parse() {
        // fields after ')': state(3) ppid(4) pgid(5) sid(6) tty_nr(7) ...
        // starttime(22)=token 19, vsize(23), rss(24)=token 21. tty_nr 0 =
        // no controlling terminal.
        let line = "1234 (nginx: worker) S 350 1234 1234 0 -1 4194560 ... 0 0 0 0 0 0 0 0 0 0 0 123456 789012 123";
        let s = parse_stat(line).unwrap();
        assert_eq!(s.comm, "nginx: worker");
        assert_eq!(s.ppid, 350);
        assert_eq!(s.pgid, 1234);
        assert_eq!(s.sid, 1234);
        assert_eq!(s.state, 'S');
        assert_eq!(s.starttime, 123456);
        assert_eq!(s.cpu_ticks, 0);
        assert_eq!(s.rss_pages, 123);
        assert_eq!(s.tty_nr, 0);
        assert_eq!(tty_name(s.tty_nr), "-");
        // kernel MKDEV: (major << 8) | (minor & 0xff) | ((minor >> 8) << 12)
        assert_eq!(tty_name((136 << 8) | 3), "pts/3");
        // high pty minor (>=256) is stored above bit 20 in the raw dev_t
        // (it lands above bit 12 only after the >>12 decode shift)
        assert_eq!(
            tty_name((136 << 8) | (300 & 0xff) | ((300 >> 8) << 20)),
            "pts/300"
        );
        assert_eq!(tty_name((4 << 8) | 2), "tty2");
        assert_eq!(tty_name((5 << 8) | 1), "console");
        assert_eq!(tty_name((5 << 8) | 2), "dev(5:2)");
    }

    #[test]
    fn net_tcp_line() {
        let line = "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0";
        let (addr, port, rem, state, inode) = parse_net_entry(line, "tcp").unwrap();
        assert_eq!(addr, "127.0.0.1");
        assert_eq!(port, 8080);
        assert_eq!(state, "LISTEN");
        assert_eq!(inode, 12345);
        assert_eq!(rem, "00000000:0000");
    }

    #[test]
    fn v6_format() {
        // ::1 in /proc/net/tcp6 layout
        assert_eq!(hex_v6("00000000000000000000000001000000").unwrap(), "::1");
        assert_eq!(hex_v4("0100007F").unwrap(), "127.0.0.1");
    }

    #[test]
    fn proc_lock_line() {
        let (id, kind, mode, pid, dev) =
            parse_proc_lock_line("1: FLOCK ADVISORY WRITE 4242 00:1f:12345 0 EOF").unwrap();
        assert_eq!(id, "1");
        assert_eq!(kind, "FLOCK");
        assert_eq!(mode, "WRITE");
        assert_eq!(pid, 4242);
        assert_eq!(dev, "00:1f:12345");
        // too short / bad pid -> None
        assert!(parse_proc_lock_line("1: POSIX ADVISORY READ 42").is_none());
        assert!(parse_proc_lock_line("1: POSIX ADVISORY READ x 00:1f:1 0 EOF").is_none());
    }

    #[test]
    fn max_open_files_parse() {
        let limits = "Limit                     Soft Limit           Hard Limit           Units\n\
                      Max open files            1024                 4096                 files\n\
                      Max locked memory         65536                65536                bytes";
        assert_eq!(parse_max_open_files(limits), Some(1024));
        assert_eq!(parse_max_open_files("Max stack size 8388608 unlimited"), None);
        assert_eq!(parse_max_open_files(""), None);
    }

    #[test]
    fn proc_io_fill() {
        let dir = std::env::temp_dir().join(format!("witr-io-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let io = dir.join("io");
        std::fs::write(
            &io,
            "rchar: 100\nwchar: 200\nsyscr: 10\nsyscw: 20\nread_bytes: 4096\nwrite_bytes: 8192\n",
        )
        .unwrap();
        let mut p = Process::default();
        fill_io_from_proc(&io, &mut p);
        assert_eq!(p.io_read_bytes, Some(4096));
        assert_eq!(p.io_write_bytes, Some(8192));
        assert_eq!(p.io_read_ops, Some(10));
        assert_eq!(p.io_write_ops, Some(20));
        // unreadable path leaves fields untouched
        let mut q = Process::default();
        fill_io_from_proc(&dir.join("nonexistent"), &mut q);
        assert_eq!(q.io_read_bytes, None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_file_target_classification() {
        assert!(open_file_target("/usr/lib/libSystem.dylib"));
        assert!(open_file_target("/var/run/nginx.pid"));
        // kernel-internal handles and bookkeeping paths are dropped
        assert!(!open_file_target("socket:[12345]"));
        assert!(!open_file_target("pipe:[777]"));
        assert!(!open_file_target("anon_inode:[eventfd]"));
        assert!(!open_file_target("/memfd:name (deleted)"));
        assert!(!open_file_target("/proc/123/fd"));
        assert!(!open_file_target("/sys/fs/cgroup/x"));
        assert!(!open_file_target("/dev/null"));
        assert!(!open_file_target("/dev/ttys001"));
        assert!(!open_file_target("/dev/pts/3"));
    }

    #[test]
    fn cgroup_docker() {
        let line = "11:pids:/docker/9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a";
        let p = line.splitn(3, ':').nth(2).unwrap();
        assert!(p.strip_prefix("/docker/").is_some());
    }

    #[test]
    fn hup_bit_detects_sighup_ignores() {
        // SigIgn hex masks: bit 0 = SIGHUP (signal 1)
        assert!(hup_bit("0000000000000001")); // only SIGHUP ignored (nohup)
        assert!(hup_bit("0000000000000007")); // SIGHUP + INT + QUIT
        assert!(!hup_bit("0000000000000004")); // SIGINT ignored, HUP not
        assert!(!hup_bit("0000000000000000"));
        assert!(!hup_bit("not-hex"));
    }

    #[test]
    fn proc_stat_parses_aggregate_and_cores() {
        let text = "\
cpu  100 0 50 800 10 0 10 5 0 0
cpu0 60 0 30 400 10 0 5 5 0 0
cpu1 40 0 20 400 0 0 5 0 0 0
intr 12345
btime 1700000000
";
        let snap = parse_stat_snapshot(text);
        let t = snap.total.expect("aggregate cpu line");
        // total = user+nice+sys+idle+iowait+irq+softirq+steal = 975
        assert_eq!(t.total, 975);
        // idle bucket includes iowait: 800+10
        assert_eq!(t.idle, 810);
        assert_eq!(snap.cores.len(), 2);
        assert_eq!(snap.cores[0].total, 510);
        // a header-only read still parses (empty snapshot)
        assert_eq!(parse_stat_snapshot("intr 1\n").total, None);
    }

    #[test]
    fn busy_percent_math() {
        let prev = StatTicks { idle: 810, total: 975 };
        let cur = StatTicks { idle: 900, total: 1175 };
        // 200 new ticks, 90 idle → 55% busy
        let p = busy_between(prev, cur).expect("delta");
        assert!((p - 55.0).abs() < 0.01, "{p}");
        // no elapsed ticks → None (not a fake 0%)
        assert_eq!(busy_between(cur, cur), None);
        // counters going backwards (hotplug) → None
        assert_eq!(busy_between(cur, prev), None);
    }

    #[test]
    fn meminfo_and_loadavg_parse() {
        let text = "\
MemTotal:       16384000 kB
MemFree:         1024000 kB
MemAvailable:    8192000 kB
SwapTotal:       2048000 kB
SwapFree:        1024000 kB
HugePages_Total:       0
";
        let (mu, mt, su, st) = parse_meminfo(text);
        // the parser reports KiB; system_stats does the /1024 to MB
        assert_eq!(mt, Some(16_384_000));
        assert_eq!(mu, Some(8_192_000), "used = total - MemAvailable");
        // no MemAvailable → MemFree fallback
        let fallback = text.replace("MemAvailable:    8192000 kB\n", "");
        assert_eq!(parse_meminfo(&fallback).0, Some(15_360_000));
        assert_eq!((su, st), (Some(1_024_000), Some(2_048_000)));
        let (l1, l5, l15) = parse_loadavg("0.52 0.58 0.59 2/1234 5678\n");
        assert_eq!((l1, l5, l15), (Some(0.52), Some(0.58), Some(0.59)));
    }
}
