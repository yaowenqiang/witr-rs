//! macOS: ps/lsof/launchctl shell-outs (the same strategy as the Go witr).
//! SIP prevents reading other users' env vars, so `--env` is not served here.

use std::time::Duration;

use crate::model::{FileOverview, LockEntry, Pid, Process, Socket, Source};
use crate::platform::{Capabilities, PlatError, PlatResult, Platform, SystemStats, Users};
use crate::util::{basename, now_unix, parse_etime_to_secs, run_ok, split_host_port};

const CMD_TIMEOUT: Duration = Duration::from_secs(8);
const LSOF_TIMEOUT: Duration = Duration::from_secs(15);

// ---------- per-process disk I/O (libproc rusage) ----------

/// Cumulative disk bytes for one pid, via proc_pid_rusage(RUSAGE_INFO_V2).
/// libproc lives in libSystem — no extra link setup. The struct layout below
/// was probed empirically on Darwin 25 (write a 4 MiB file → words 18/19
/// move by exactly the payload): the two diskio counters sit at offsets
/// 144/152, not where the public rusage_info_v2 docs place them. We only
/// ever read our own zeroed buffer, so a layout drift on a future macOS
/// would degrade to odd numbers, never memory unsafety — the unit test
/// guards the offsets live.
#[cfg(target_os = "macos")]
fn disk_io_of(pid: Pid) -> Option<(u64, u64)> {
    #[repr(C)]
    struct RUsageInfoV2 {
        uuid: [u8; 16],           // words 0-1
        user_time: u64,           // word 2
        system_time: u64,         // word 3
        _mid: [u64; 14],          // words 4-17: fault/syscall counters, unused
        diskio_bytesread: u64,    // word 18
        diskio_byteswritten: u64, // word 19
        _tail: [u64; 6],          // words 20-25
    }
    const RUSAGE_INFO_V2: i32 = 2;
    extern "C" {
        fn proc_pid_rusage(pid: i32, flavor: i32, buffer: *mut RUsageInfoV2) -> i32;
    }
    let mut info: RUsageInfoV2 = unsafe { std::mem::zeroed() };
    let rc = unsafe { proc_pid_rusage(pid, RUSAGE_INFO_V2, &mut info) };
    (rc == 0).then_some((info.diskio_bytesread, info.diskio_byteswritten))
}

/// Platforms without libproc: no listing-level disk counters.
#[cfg(not(target_os = "macos"))]
fn disk_io_of(_pid: Pid) -> Option<(u64, u64)> {
    None
}

// ---------- system resources (system page 'y') ----------
//
// CPU comes from host_processor_info (the same per-core tick buckets top(1)
// shows), memory from `vm_stat` (page counts; no safe fixed-size Mach struct
// to hand-roll), everything else from sysctl/getloadavg — all in libSystem,
// no new dependencies. CPU% is a delta between calls, so the previous tick
// snapshot rides in the platform struct (the TUI samples from one thread).

/// Per-core tick buckets `[user, system, idle, nice]` (PROCESSOR_CPU_LOAD_INFO order).
#[cfg(target_os = "macos")]
fn host_cpu_ticks() -> Option<Vec<[u64; 4]>> {
    extern "C" {
        fn mach_host_self() -> u32;
        fn host_processor_info(
            host: u32,
            flavor: i32,
            count: *mut u32,
            info: *mut *mut i32,
            tick_count: *mut u32,
        ) -> i32;
        fn mig_deallocate(target: *mut std::ffi::c_void, size: u32) -> i32;
    }
    const PROCESSOR_CPU_LOAD_INFO: i32 = 2;
    unsafe {
        let (mut count, mut ticks): (u32, u32) = (0, 0);
        let mut loads: *mut i32 = std::ptr::null_mut();
        if host_processor_info(
            mach_host_self(),
            PROCESSOR_CPU_LOAD_INFO,
            &mut count,
            &mut loads,
            &mut ticks,
        ) != 0
        {
            return None;
        }
        let per = ticks as usize; // 4 buckets
        let mut out = Vec::with_capacity(count as usize);
        for c in 0..count as usize {
            let row = loads.add(c * per);
            out.push([
                *row as u64,
                *row.add(1) as u64,
                *row.add(2) as u64,
                *row.add(3) as u64,
            ]);
        }
        mig_deallocate(loads.cast(), count * ticks);
        Some(out)
    }
}

/// Non-macOS targets never call [`MacOs::system_stats`] — but the trait impl
/// must still compile there, so mirror the [`disk_io_of`] stub pattern.
#[cfg(not(target_os = "macos"))]
fn host_cpu_ticks() -> Option<Vec<[u64; 4]>> {
    None
}

/// (total busy %, per-core busy %) between two tick snapshots. Pure so the
/// math is pinned by tests; compiled everywhere for the same reason.
fn cpu_busy_between(prev: &[[u64; 4]], cur: &[[u64; 4]]) -> (Option<f64>, Vec<f64>) {
    let one = |p: [u64; 4], c: [u64; 4]| -> Option<f64> {
        let busy = c[0].saturating_sub(p[0])
            + c[1].saturating_sub(p[1])
            + c[3].saturating_sub(p[3]);
        let total = busy + c[2].saturating_sub(p[2]);
        (total > 0).then(|| (busy as f64 / total as f64 * 100.0).clamp(0.0, 100.0))
    };
    let mut cores = Vec::new();
    let mut tot_busy = 0u64;
    let mut tot_all = 0u64;
    for (p, c) in prev.iter().zip(cur) {
        tot_busy += c[0].saturating_sub(p[0]) + c[1].saturating_sub(p[1]) + c[3].saturating_sub(p[3]);
        tot_all += c[0].saturating_sub(p[0])
            + c[1].saturating_sub(p[1])
            + c[2].saturating_sub(p[2])
            + c[3].saturating_sub(p[3]);
        if let Some(pct) = one(*p, *c) {
            cores.push(pct);
        }
    }
    let total = (tot_all > 0).then(|| (tot_busy as f64 / tot_all as f64 * 100.0).clamp(0.0, 100.0));
    (total, cores)
}

/// One sysctl value as a string (`vm.swapusage`, `hw.memsize`, `hw.pagesize`).
#[cfg(target_os = "macos")]
fn sysctl_str(name: &str) -> Option<String> {
    extern "C" {
        fn sysctlbyname(
            name: *const i8,
            oldp: *mut u8,
            oldlenp: *mut usize,
            newp: *mut u8,
            newlen: usize,
        ) -> i32;
    }
    let cname = std::ffi::CString::new(name).ok()?;
    unsafe {
        let mut len: usize = 0;
        if sysctlbyname(cname.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
        let mut buf = vec![0u8; len];
        if sysctlbyname(cname.as_ptr(), buf.as_mut_ptr(), &mut len, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
        buf.truncate(len);
        Some(String::from_utf8_lossy(&buf).trim_end_matches('\0').to_string())
    }
}

/// Non-macOS stub — see [`host_cpu_ticks`].
#[cfg(not(target_os = "macos"))]
fn sysctl_str(_name: &str) -> Option<String> {
    None
}

/// Per-pid descriptor counts from one `lsof -F pf` scan: `p<pid>` opens a
/// process section, each `f<fd>` line inside counts one descriptor. Pure —
/// compiled everywhere so the trait impl does.
#[cfg(any(target_os = "macos", test))]
fn parse_lsof_fd_counts(text: &str) -> std::collections::HashMap<Pid, u64> {
    let mut out: std::collections::HashMap<Pid, u64> = std::collections::HashMap::new();
    let mut cur: Option<Pid> = None;
    for l in text.lines() {
        if let Some(rest) = l.strip_prefix('p') {
            cur = rest.parse().ok();
        } else if l.starts_with('f') {
            if let Some(pid) = cur {
                *out.entry(pid).or_insert(0) += 1;
            }
        }
    }
    out
}

/// Non-macOS stub — see [`parse_lsof_fd_counts`].
#[cfg(not(target_os = "macos"))]
fn parse_lsof_fd_counts(_text: &str) -> std::collections::HashMap<Pid, u64> {
    std::collections::HashMap::new()
}

/// (1, 5, 15-minute load) via getloadavg — empty on platforms without it.
#[cfg(target_os = "macos")]
fn loadavg() -> (Option<f64>, Option<f64>, Option<f64>) {
    extern "C" {
        fn getloadavg(avgs: *mut f64, nelem: i32) -> i32;
    }
    let mut a = [0f64; 3];
    let n = unsafe { getloadavg(a.as_mut_ptr(), 3) };
    match n {
        3 => (Some(a[0]), Some(a[1]), Some(a[2])),
        2 => (Some(a[0]), Some(a[1]), None),
        1 => (Some(a[0]), None, None),
        _ => (None, None, None),
    }
}

/// Non-macOS stub — see [`host_cpu_ticks`].
#[cfg(not(target_os = "macos"))]
fn loadavg() -> (Option<f64>, Option<f64>, Option<f64>) {
    (None, None, None)
}

/// Memory-in-use MB from `vm_stat` output: active + wired + compressor
/// pages (the "Memory Used" Activity Monitor shows), scaled by `page_size`.
/// Pure — compiled everywhere so the trait impl does.
fn parse_vm_stat(text: &str, page_size: u64) -> Option<u64> {
    let get = |label: &str| -> u64 {
        text.lines()
            .find_map(|l| l.strip_prefix(label))
            .and_then(|rest| {
                rest.trim_end_matches('.')
                    .trim()
                    .replace(',', "")
                    .parse()
                    .ok()
            })
            .unwrap_or(0)
    };
    let used_pages = get("Pages active: ")
        + get("Pages wired down: ")
        + get("Pages occupied by compressor: ")
        + get("Pages stored in compressor: "); // older label; the two never coexist
    (used_pages > 0).then(|| used_pages * page_size / (1024 * 1024))
}

/// `total = 3072.00M used = 12.53M free = ... (encrypted)` → (used, total) MB.
/// Pure — compiled everywhere so the trait impl does.
fn parse_swapusage(text: &str) -> (Option<u64>, Option<u64>) {
    let get = |key: &str| -> Option<u64> {
        let idx = text.find(key)? + key.len();
        let rest = &text[idx..];
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let v: f64 = rest[..end].parse().ok()?;
        let mult = match rest[end..].chars().next()? {
            'G' => 1024.0,
            'K' => 1.0 / 1024.0,
            _ => 1.0, // M and B both land here (B ≈ 0 MB, close enough)
        };
        Some((v * mult) as u64)
    };
    (get("used = "), get("total = "))
}

pub struct MacOs {
    users: Users,
    /// Tick snapshot from the previous [`MacOs::system_stats`] call — CPU%
    /// is a delta, so the first call reports memory/load only.
    prev_cpu: std::cell::RefCell<Option<Vec<[u64; 4]>>>,
}

impl MacOs {
    pub fn new(users: Users) -> Self {
        MacOs {
            users,
            prev_cpu: std::cell::RefCell::new(None),
        }
    }

    /// One `lsof` run, stdout salvaged (it exits non-zero when it can't
    /// read some process while still emitting valid rows).
    fn lsof_rows(&self, args: &[&str]) -> Vec<String> {
        match std::process::Command::new("lsof").args(args).output() {
            Ok(o) => String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::to_string)
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

/// `ps -axo pid=,ppid=,uid=,state=,etime=,time=,pcpu=,rss=,vsz=,comm=` — comm
/// is the last column and may contain spaces, so the first nine whitespace
/// tokens are fixed and the rest is the executable path.
fn parse_ps_list_line(line: &str, users: &Users) -> Option<Process> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let bytes = line.as_bytes();
    let mut idx = 0usize;
    // skip leading whitespace, then consume nine fixed fields
    let mut fixed: [Option<&str>; 9] = [None; 9];
    for slot in fixed.iter_mut() {
        while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        let start = idx;
        while idx < bytes.len() && !bytes[idx].is_ascii_whitespace() {
            idx += 1;
        }
        *slot = Some(&line[start..idx]);
    }
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    let comm = &line[idx..];

    let pid: Pid = fixed[0]?.parse().ok()?;
    let ppid: Pid = fixed[1]?.parse().ok()?;
    let uid: u32 = fixed[2]?.parse().ok()?;
    let state = fixed[3].and_then(|s| s.chars().next()).map(|c| c.to_string());
    let started = parse_etime_to_secs(fixed[4]?).map(|age| now_unix() - age);
    let cpu_time_ms = parse_cpu_time_to_ms(fixed[5]?);
    let cpu = fixed[6]?.parse::<f64>().ok().filter(|c| *c > 0.05);
    let mem_kb = fixed[7]?.parse::<u64>().ok().filter(|m| *m > 0);
    let vm_kb = fixed[8]?.parse::<u64>().ok().filter(|m| *m > 0);
    Some(Process {
        pid,
        ppid: Some(ppid),
        name: basename(comm),
        exe: if comm.is_empty() { None } else { Some(comm.to_string()) },
        user: users.name_for(uid),
        uid: Some(uid),
        started,
        state,
        cpu,
        mem_kb,
        vm_kb,
        cpu_time_ms,
        ..Default::default()
    })
}

/// `ps -wwO pid=,pcpu=,command= -p N` → (pid, lifetime-avg cpu %, command).
fn parse_ps_detail_line(line: &str) -> Option<(Pid, Option<f64>, String)> {
    let line = line.trim_start();
    let (pid_str, rest) = line.split_once(' ')?;
    let pid: Pid = pid_str.parse().ok()?;
    let rest = rest.trim_start();
    let (cpu_str, cmd) = rest.split_once(' ')?;
    Some((pid, cpu_str.parse::<f64>().ok(), cmd.trim().to_string()))
}

/// Parse one data row of `lsof -nP -i :PORT`.
fn parse_lsof_net_line(line: &str) -> Option<Socket> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 8 {
        return None;
    }
    let pid: Pid = cols[1].parse().ok()?;
    let node = cols[7].to_ascii_lowercase(); // TCP / UDP
    if node != "tcp" && node != "udp" {
        return None;
    }
    // NAME may span several whitespace tokens: "addr:port (STATE)".
    let v6 = cols[4].contains('6');
    let tail = cols[8..].join(" ");
    let (name, state) = match tail.rfind(" (") {
        Some(open) if tail.ends_with(')') => (
            tail[..open].to_string(),
            tail[open + 2..tail.len() - 1].to_string(),
        ),
        _ => (tail.clone(), "CONNECTED".to_string()),
    };
    let (local, peer) = match name.split_once("->") {
        Some((l, r)) => (l.to_string(), Some(r.to_string())),
        None => (name.clone(), None),
    };
    let (laddr, lport) = split_host_port(&local)?;
    let (paddr, pport) = match peer.as_deref().map(split_host_port) {
        Some(Some((a, p))) => (Some(a), Some(p)),
        _ => (None, None),
    };
    let mut proto = node.clone();
    if v6 {
        proto.push('6');
    }
    Some(Socket {
        proto,
        local_addr: laddr,
        local_port: lport,
        peer_addr: paddr,
        peer_port: pport,
        state,
        pid: Some(pid),
    })
}

/// `launchctl list` row: "PID\tStatus\tLabel" (PID is "-" when not running).
fn parse_launchctl_pid_label(line: &str) -> Option<(Pid, String)> {
    let mut it = line.split_whitespace();
    let pid: Pid = it.next()?.parse().ok()?;
    let _status: i64 = it.next()?.parse().ok()?;
    let label_start = line.splitn(3, char::is_whitespace).nth(2)?;
    Some((pid, label_start.trim().to_string()))
}

/// `ps -ww -p PID -E -o command=` appends KEY=VALUE env fields after the
/// command; scan whitespace-separated fields that look like env names.
/// Same strategy as the Go witr (best-effort: values containing whitespace
/// lose their tail, and the command line itself can yield false positives).
fn parse_ps_env(output: &str) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for part in output.split_whitespace() {
        if let Some(eq) = part.find('=') {
            let name = &part[..eq];
            if !name.is_empty()
                && !name.chars().next().unwrap().is_ascii_digit()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && seen.insert(name.to_string())
            {
                env.push((name.to_string(), part[eq + 1..].to_string()));
            }
        }
    }
    env
}

/// FD column → access mode ("3w" → WRITE). lsof appends the access-mode
/// char (r/w/u) after the fd number, optionally followed by a lock char.
fn lsof_fd_access(fd: &str) -> Option<&'static str> {
    let last = fd.chars().rev().find(|c| c.is_ascii_alphabetic())?;
    match last {
        'r' => Some("READ"),
        'w' => Some("WRITE"),
        'u' => Some("RW"),
        _ => None,
    }
}

/// FD column → lock mode. The lock char comes AFTER the access char
/// (lsof(8): W/w = write lock, R/r = read lock, u = read+write lock, N =
/// unknown), so only a fd with two trailing alpha chars carries a lock —
/// plain "5u" is just an unlocked read/write fd.
fn lsof_fd_lock(fd: &str) -> Option<&'static str> {
    let alphas: Vec<char> = fd.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    if alphas.len() < 2 {
        return None;
    }
    match alphas[alphas.len() - 1] {
        'W' | 'w' => Some("WRITE"),
        'R' | 'r' => Some("READ"),
        'u' => Some("RW"),
        _ => None,
    }
}

/// Paths that are almost certainly lock artifacts a user recognizes:
/// daemon lock/pid files. macOS's kernel exports no lock table (no
/// /proc/locks), so lsof lock flags rarely appear; this heuristic is what
/// surfaces the lock file a daemon holds open.
fn looks_like_lock_file(p: &str) -> bool {
    p.ends_with(".lock") || p.ends_with(".pid") || p.contains("/lock")
}

/// Parse one data row of `lsof -l -n -P`:
/// COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME.
/// Rows with an explicit lock flag become FLOCK entries; regular files
/// whose path looks like a lock file are surfaced too (mode = fd access).
fn parse_lsof_lock_line(line: &str) -> Option<LockEntry> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 9 {
        return None;
    }
    let pid: Pid = f[1].parse().ok()?;
    if pid <= 0 {
        return None;
    }
    let fd = f[3];
    let ty = f[4];
    let path = f[8..].join(" ");
    let (kind, mode) = if let Some(mode) = lsof_fd_lock(fd) {
        ("FLOCK", mode)
    } else if ty == "REG" && looks_like_lock_file(&path) {
        ("FLOCK", lsof_fd_access(fd)?)
    } else {
        return None;
    };
    Some(LockEntry {
        id: fd.to_string(),
        kind: kind.to_string(),
        mode: mode.to_string(),
        pid: Some(pid),
        owner: f[0].to_string(),
        path,
    })
}

/// Parse `lsof -l -n -P [-p PID]` table output into (open-file display
/// lines, lock entries). One scan feeds both the open-files panel and the
/// locks view.
fn parse_lsof_files_and_locks(rows: &[String]) -> (Vec<String>, Vec<LockEntry>) {
    let mut files: Vec<String> = Vec::new();
    let mut pipes = 0usize;
    let mut locks: Vec<LockEntry> = Vec::new();
    for line in rows {
        let f: Vec<&str> = line.split_whitespace().collect();
        // header / malformed rows: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        if f.len() < 9 || f[1].parse::<Pid>().map(|p| p <= 0).unwrap_or(true) {
            continue;
        }
        if let Some(l) = parse_lsof_lock_line(line) {
            // same lock file can appear once per holding fd
            if !locks.iter().any(|x| x.pid == l.pid && x.path == l.path) {
                locks.push(l);
            }
        }
        let (fd, ty) = (f[3], f[4]);
        let path = f[8..].join(" ");
        match ty {
            "REG" | "VREG" | "DIR" | "VDIR" => {
                let _ = fd;
                if !path.starts_with("/dev/") && !files.contains(&path) {
                    files.push(path.to_string());
                }
            }
            "IPv4" | "IPv6" | "TCP" | "UDP" => {
                // table rows append the state: strip a trailing " (...)"
                let name = match path.rfind(" (") {
                    Some(i) if path.ends_with(')') => &path[..i],
                    _ => path.as_str(),
                };
                let l = format!("socket {} {}", ty.to_lowercase(), name);
                if !files.contains(&l) {
                    files.push(l);
                }
            }
            "UNIX" | "unix" | "PIPE" | "PSHM" => pipes += 1,
            _ => {} // txt/cwd/KQUEUE/... shown elsewhere
        }
    }
    if pipes > 0 {
        files.push(format!("[{} pipe/unix-socket(s)]", pipes));
    }
    files.truncate(200);
    (files, locks)
}

/// Soft max-open-files limit as launchd reports it (`launchctl limit
/// maxfiles` → "maxfiles <soft> <hard>"). "unlimited" or a failed run →
/// None — the per-process NOFILE limit can differ per session, so this is
/// explicitly a heuristic.
fn maxfiles_soft() -> Option<u64> {
    let out = run_ok("launchctl", &["limit", "maxfiles"], CMD_TIMEOUT)?;
    parse_launchctl_maxfiles(&out)
}

/// "maxfiles  256  unlimited" → 256 (the soft limit, field 1).
fn parse_launchctl_maxfiles(out: &str) -> Option<u64> {
    out.split_whitespace().nth(1)?.parse().ok()
}

/// Parse a full `lsof -l -n -P` scan into lock-tab entries: rows with a
/// lock flag become FLOCK entries, REG/DIR rows become OPEN entries with
/// the fd access mode. /dev/null and /dev/tty* are dropped (kernel-internal
/// noise), the rest of /dev stays. Deduped by (pid, path), lock rows
/// winning — the Go witr's merge rule, satisfied in a single scan.
fn parse_lsof_open_files(rows: &[String]) -> Vec<LockEntry> {
    let mut map: std::collections::HashMap<(Pid, String), LockEntry> =
        std::collections::HashMap::new();
    for line in rows {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 9 {
            continue;
        }
        let pid: Pid = match f[1].parse() {
            Ok(p) if p > 0 => p,
            _ => continue,
        };
        let fd = f[3];
        let ty = f[4];
        let path = f[8..].join(" ");
        let entry = if let Some(l) = parse_lsof_lock_line(line) {
            l
        } else {
            if !matches!(ty, "REG" | "VREG" | "DIR" | "VDIR") {
                continue;
            }
            if path == "/dev/null" || path.starts_with("/dev/tty") {
                continue;
            }
            let Some(mode) = lsof_fd_access(fd) else { continue };
            LockEntry {
                id: fd.to_string(),
                kind: "OPEN".into(),
                mode: mode.to_string(),
                pid: Some(pid),
                owner: f[0].to_string(),
                path: path.clone(),
            }
        };
        let is_lock = entry.kind != "OPEN";
        map.entry((pid, path))
            .and_modify(|e| {
                if is_lock {
                    *e = entry.clone();
                }
            })
            .or_insert(entry);
    }
    let mut out: Vec<LockEntry> = map.into_values().collect();
    out.sort_by(|a, b| (a.pid, &a.path).cmp(&(b.pid, &b.path)));
    out
}

fn find_plist(label: &str) -> Option<String> {
    let dirs = [
        "~/Library/LaunchAgents",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        "/System/Library/LaunchDaemons",
    ];
    for d in dirs {
        let expanded = if let Some(rest) = d.strip_prefix("~/") {
            if let Ok(home) = std::env::var("HOME") {
                format!("{}/{}", home, rest)
            } else {
                continue;
            }
        } else {
            d.to_string()
        };
        let p = format!("{}/{}.plist", expanded, label);
        if std::path::Path::new(&p).exists() {
            return Some(p);
        }
    }
    None
}

/// One lsof sweep for the Ports tab. `listen_only` (the default view) asks
/// lsof for LISTEN tcp; the TUI's 'a' toggle pulls every tcp state too.
fn socket_snapshot(listen_only: bool) -> PlatResult<Vec<Socket>> {
    let mut out = Vec::new();
    let mut tcp_args = vec!["-nP", "-w", "-iTCP"];
    if listen_only {
        tcp_args.push("-sTCP:LISTEN");
    }
    for args in [tcp_args, vec!["-nP", "-w", "-iUDP"]] {
        match std::process::Command::new("lsof").args(&args).output() {
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stdout);
                for line in text.lines().skip(1) {
                    if let Some(s) = parse_lsof_net_line(line) {
                        // same socket can appear once per owning fd
                        if !out.iter().any(|x: &Socket| {
                            x.pid == s.pid
                                && x.proto == s.proto
                                && x.local_port == s.local_port
                                && x.local_addr == s.local_addr
                        }) {
                            out.push(s);
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(PlatError::Unsupported("lsof not found on PATH".into()))
            }
            Err(e) => return Err(PlatError::Failed(format!("lsof: {}", e))),
        }
    }
    out.sort_by(|a, b| (a.proto.clone(), a.local_port).cmp(&(b.proto.clone(), b.local_port)));
    Ok(out)
}

impl Platform for MacOs {
    fn name(&self) -> &'static str {
        "macos"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            file_lookup: true,
            // same-user processes via `ps -E`; empty for the rest (SIP)
            env: true,
        }
    }

    fn list_processes(&self) -> PlatResult<Vec<Process>> {
        let out = run_ok(
            "ps",
            &[
                "-axo",
                "pid=,ppid=,uid=,state=,etime=,time=,pcpu=,rss=,vsz=,comm=",
            ],
            CMD_TIMEOUT,
        )
        .ok_or_else(|| PlatError::Failed("ps failed".into()))?;
        Ok(out.lines().filter_map(|l| parse_ps_list_line(l, &self.users)).collect())
    }

    /// Listing pass for the TUI IO column: one proc_pid_rusage call per pid
    /// (a single mach call each — cheap for the full table). Works across
    /// users without root, unlike the env probe.
    fn enrich_listing(&self, procs: &mut [Process]) {
        for p in procs.iter_mut() {
            if p.kernel_thread {
                continue;
            }
            if let Some((r, w)) = disk_io_of(p.pid) {
                p.io_read_bytes = Some(r);
                p.io_write_bytes = Some(w);
            }
        }
    }

    /// One mach tick call + one `vm_stat` spawn + a few sysctls — ~50ms,
    /// sampled only while the system page is open. CPU needs two calls
    /// (tick delta); the first reports memory/load only. No per-core list
    /// until the second call either.
    fn system_stats(&self) -> Option<SystemStats> {
        let mut out = SystemStats::default();

        let cur = host_cpu_ticks()?;
        let mut prev = self.prev_cpu.borrow_mut();
        if let Some(p) = prev.as_ref() {
            let (total, cores) = cpu_busy_between(p, &cur);
            out.cpu_percent = total;
            out.cores = cores;
        }
        *prev = Some(cur);
        drop(prev);

        let page_size: u64 = sysctl_str("hw.pagesize")
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(16384);
        if let Ok(text) = crate::util::run("vm_stat", &[], CMD_TIMEOUT) {
            out.mem_used_mb = parse_vm_stat(&text, page_size);
        }
        out.mem_total_mb = sysctl_str("hw.memsize")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|b| b / (1024 * 1024));
        if let Some(su) = sysctl_str("vm.swapusage") {
            let (used, total) = parse_swapusage(&su);
            out.swap_used_mb = used;
            out.swap_total_mb = total;
        }
        let (l1, l5, l15) = loadavg();
        out.load1 = l1;
        out.load5 = l5;
        out.load15 = l15;
        Some(out)
    }

    fn open_files(&self, pid: Pid) -> Vec<String> {
        self.file_overview(pid).files
    }

    fn list_sockets(&self) -> PlatResult<Vec<Socket>> {
        socket_snapshot(true)
    }

    fn list_all_sockets(&self) -> PlatResult<Vec<Socket>> {
        socket_snapshot(false)
    }

    fn detail(&self, brief: &Process, want_env: bool) -> Process {
        let mut p = brief.clone();
        if let Some(out) = run_ok(
            "ps",
            &["-ww", "-o", "pid=,pcpu=,command=", "-p", &brief.pid.to_string()],
            CMD_TIMEOUT,
        ) {
            for line in out.lines() {
                if let Some((_, cpu, cmd)) = parse_ps_detail_line(line) {
                    // unfiltered lifetime average — 0.0% is meaningful here
                    p.cpu = cpu;
                    if !cmd.is_empty() {
                        p.cmdline = vec![cmd];
                    }
                    break;
                }
            }
        }
        // thread count: ps -M prints one line per thread (+ header)
        if let Some(out) = run_ok(
            "ps",
            &["-M", "-p", &brief.pid.to_string()],
            CMD_TIMEOUT,
        ) {
            let n = out.lines().count().saturating_sub(1);
            if n > 0 {
                p.threads = Some(n as u32);
            }
        }
        // environment: ps -E appends KEY=VALUE after the command for
        // same-user processes; other users yield nothing (SIP)
        if want_env && !p.kernel_thread {
            if let Some(out) = run_ok(
                "ps",
                &["-ww", "-p", &brief.pid.to_string(), "-E", "-o", "command="],
                CMD_TIMEOUT,
            ) {
                let env = parse_ps_env(&out);
                if !env.is_empty() {
                    p.env = Some(env);
                }
            }
        }
        // executable path via the text (program image) fd
        if let Some(out) = run_ok(
            "lsof",
            &["-a", "-w", "-p", &brief.pid.to_string(), "-d", "txt", "-Fn"],
            LSOF_TIMEOUT,
        ) {
            for line in out.lines() {
                if let Some(path) = line.strip_prefix('n') {
                    if path.starts_with('/') {
                        p.exe = Some(path.to_string());
                    }
                    break;
                }
            }
        }
        // cwd via lsof (-a with -p and -d cwd)
        if let Some(out) = run_ok(
            "lsof",
            &["-a", "-w", "-p", &brief.pid.to_string(), "-d", "cwd", "-Fn"],
            LSOF_TIMEOUT,
        ) {
            for line in out.lines() {
                if let Some(path) = line.strip_prefix('n') {
                    p.cwd = Some(path.to_string());
                    break;
                }
            }
        }
        p
    }

    fn port_to_sockets(&self, port: u16) -> PlatResult<Vec<Socket>> {
        match std::process::Command::new("lsof")
            .args(["-nP", "-w", "-i", &format!(":{}", port)])
            .output()
        {
            Ok(out) => {
                if !out.stdout.is_empty() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    let mut sockets: Vec<Socket> = text
                        .lines()
                        .skip(1) // header
                        .filter_map(parse_lsof_net_line)
                        // `lsof -i :PORT` also matches the client side of
                        // connections TO that port; the contract is local
                        // ports only
                        .filter(|s| s.local_port == port)
                        .collect();
                    // Same socket may appear once per owning fd; dedup.
                    sockets.dedup_by(|a, b| {
                        a.pid == b.pid
                            && a.proto == b.proto
                            && a.local_port == b.local_port
                            && a.local_addr == b.local_addr
                            && a.state == b.state
                    });
                    Ok(sockets)
                } else {
                    let err = String::from_utf8_lossy(&out.stderr);
                    if err.contains("Permission denied") {
                        Err(PlatError::Permission(err.trim().to_string()))
                    } else {
                        // exit 1 with no output just means "nothing found"
                        Ok(Vec::new())
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(PlatError::Unsupported(
                "lsof not found on PATH".into(),
            )),
            Err(e) => Err(PlatError::Failed(format!("lsof: {}", e))),
        }
    }

    fn file_to_pids(&self, path: &str) -> PlatResult<Vec<Pid>> {
        let out = std::process::Command::new("lsof")
            .args(["-w", "--", path])
            .output()
            .map_err(|e| PlatError::Failed(format!("lsof: {}", e)))?;
        let err = String::from_utf8_lossy(&out.stderr);
        if out.stdout.is_empty() {
            if err.contains("Permission denied") {
                return Err(PlatError::Permission(
                    "lsof needs root to see other users' files".into(),
                ));
            }
            return Ok(Vec::new());
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let pids = text
            .lines()
            .skip(1)
            .filter_map(|l| l.split_whitespace().nth(1)?.parse().ok())
            .collect();
        Ok(pids)
    }

    fn file_overview(&self, pid: Pid) -> FileOverview {
        // a single scan serves the open-files panel, the locks section AND
        // the fd count — each lsof run costs hundreds of ms
        let rows = self.lsof_rows(&["-l", "-n", "-P", "-w", "-p", &pid.to_string()]);
        let (files, locks) = parse_lsof_files_and_locks(&rows);
        // rows include the header; every data row is one open fd
        let used = rows.len().saturating_sub(1) as u64;
        let fd_usage = if used > 0 {
            maxfiles_soft().map(|limit| (used, limit))
        } else {
            None // unreadable (other user) — no honest count
        };
        FileOverview { files, locks, fd_usage }
    }

    fn fd_count(&self, pid: Pid) -> Option<u64> {
        // field mode (-F f) prints one `f<fd>` line per descriptor — the
        // leanest lsof shape for a count-only probe
        let out = crate::util::run_ok(
            "lsof",
            &["-w", "-p", &pid.to_string(), "-F", "f"],
            std::time::Duration::from_secs(5),
        )?;
        let n = out
            .lines()
            .filter(|l| l.starts_with('f') && l[1..].chars().all(|c| c.is_ascii_digit()))
            .count() as u64;
        (n > 0).then_some(n)
    }

    fn fd_counts(&self) -> Option<std::collections::HashMap<Pid, u64>> {
        // one system-wide field-mode scan: `p<pid>` opens each process's
        // section, every `f<fd>` line inside counts one descriptor
        let out = crate::util::run_ok(
            "lsof",
            &["-w", "-n", "-P", "-F", "pf"],
            std::time::Duration::from_secs(10),
        )?;
        Some(parse_lsof_fd_counts(&out))
    }

    fn list_locks(&self, pid: Option<Pid>) -> Vec<LockEntry> {
        let mut args = vec!["-l", "-n", "-P", "-w"];
        let pid_arg;
        if let Some(p) = pid {
            pid_arg = p.to_string();
            args.push("-p");
            args.push(&pid_arg);
        }
        parse_lsof_files_and_locks(&self.lsof_rows(&args)).1
    }

    fn list_all_open_files(&self) -> Vec<LockEntry> {
        // one full scan yields both the lock rows and the plain open files
        parse_lsof_open_files(&self.lsof_rows(&["-l", "-n", "-P", "-w"]))
    }

    fn container_of(&self, pid: Pid) -> Option<Source> {
        // No cgroups on macOS: attribute from the target's own command line
        // (colima, Docker Desktop helpers...), like Go witr.
        let cmdline = self
            .detail(
                &Process {
                    pid,
                    ..Default::default()
                },
                false,
            )
            .command_line();
        let label = crate::platform::windows::container_from_cmdline(&cmdline)?;
        Some(Source {
            kind: "container".into(),
            label: Some(label),
            detail: Some("detected from the process command line".into()),
            ..Default::default()
        })
    }

    fn service_source(&self, chain: &[Process]) -> Option<Source> {
        let init = chain.first()?;
        let target = chain.last()?;
        if init.pid != 1 && init.name != "launchd" {
            return None;
        }
        if let Some(out) = run_ok("launchctl", &["list"], CMD_TIMEOUT) {
            for line in out.lines() {
                if let Some((pid, label)) = parse_launchctl_pid_label(line) {
                    if pid == target.pid {
                        let mut detail = format!("launchd job \"{}\"", label);
                        if let Some(plist) = find_plist(&label) {
                            detail.push_str(&format!(" (plist: {})", plist));
                            if let Some(extra) = plist_details(&plist) {
                                detail.push_str(&format!(" — {}", extra.join(" — ")));
                            }
                        }
                        return Some(Source {
                            kind: "launchd".into(),
                            label: Some(label),
                            detail: Some(detail),
                            ..Default::default()
                        });
                    }
                }
            }
        }
        // No owning LaunchAgent/Daemon: only claim launchd when it is the
        // direct parent (XPC spawn); otherwise let the generic detectors
        // (shell, ssh, tmux...) attribute the process.
        let direct_child_of_launchd = chain.len() >= 2
            && (chain[chain.len() - 2].pid == 1 || chain[chain.len() - 2].name == "launchd");
        if direct_child_of_launchd {
            Some(Source {
                kind: "launchd".into(),
                label: None,
                detail: Some(format!(
                    "spawned directly by launchd (pid {}), but no LaunchAgent/Daemon claims it (XPC?)",
                    target.pid
                )),
                ..Default::default()
            })
        } else {
            None
        }
    }

    fn service_pid(&self, name: &str) -> Option<Pid> {
        if let Some(out) = run_ok("launchctl", &["list"], CMD_TIMEOUT) {
            for line in out.lines() {
                if let Some((pid, label)) = parse_launchctl_pid_label(line) {
                    if label == name {
                        return Some(pid);
                    }
                }
            }
        }
        None
    }
}
/// schedule, keepalive. `plutil` normalizes binary plists to XML, then a
/// small scanner pulls the root-dict keys out (nested dicts are skipped).
fn plist_details(plist_path: &str) -> Option<Vec<String>> {
    let xml = run_ok(
        "plutil",
        &["-convert", "xml1", "-o", "-", plist_path],
        CMD_TIMEOUT,
    )?;
    let parsed = parse_plist_root_keys(&xml);
    let mut out = Vec::new();
    let domain = if plist_path.contains("/LaunchDaemons/") {
        "Launch Daemon"
    } else if plist_path.contains("/LaunchAgents/") {
        "Launch Agent"
    } else {
        "launchd service"
    };
    out.push(domain.to_string());
    if parsed.bool("RunAtLoad").unwrap_or(false) {
        out.push("RunAtLoad (starts at login/boot)".into());
    }
    if let Some(secs) = parsed.int("StartInterval") {
        out.push(format!("StartInterval (every {})", fmt_duration_short(secs)));
    }
    if let Some(cal) = parsed.text("StartCalendarInterval") {
        out.push(format!("StartCalendarInterval ({})", cal));
    }
    if let Some(paths) = parsed.array("WatchPaths") {
        for p in paths {
            out.push(format!("WatchPaths: {}", p));
        }
    }
    if let Some(dirs) = parsed.array("QueueDirectories") {
        for d in dirs {
            out.push(format!("QueueDirectories: {}", d));
        }
    }
    if parsed.bool("KeepAlive").unwrap_or(false) {
        out.push("KeepAlive: Yes (restarts if killed)".into());
    }
    Some(out)
}

/// Minimal XML-plist root-dict reader: collects key → value for the scalar
/// types (<string>/<integer>/<true>/<false>) and flattens
/// <array>/<dict> values to their string form. Good enough for launchd
/// trigger metadata; not a general plist parser.
struct PlistRoot {
    keys: Vec<(String, PlistVal)>,
}

enum PlistVal {
    Str(String),
    Int(i64),
    Bool(bool),
    List(Vec<String>),
}

impl PlistRoot {
    fn get(&self, key: &str) -> Option<&PlistVal> {
        self.keys.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
    fn bool(&self, key: &str) -> Option<bool> {
        match self.get(key) {
            Some(PlistVal::Bool(b)) => Some(*b),
            _ => None,
        }
    }
    fn int(&self, key: &str) -> Option<i64> {
        match self.get(key) {
            Some(PlistVal::Int(i)) => Some(*i),
            _ => None,
        }
    }
    fn text(&self, key: &str) -> Option<String> {
        match self.get(key) {
            Some(PlistVal::Str(s)) => Some(s.clone()),
            Some(PlistVal::List(l)) if !l.is_empty() => Some(l.join("; ")),
            _ => None,
        }
    }
    fn array(&self, key: &str) -> Option<Vec<String>> {
        match self.get(key) {
            Some(PlistVal::List(l)) => Some(l.clone()),
            Some(PlistVal::Str(s)) => Some(vec![s.clone()]),
            _ => None,
        }
    }
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Extract one XML element's text (no nesting): returns (inner text, index
/// after the closing tag).
fn xml_element_text(s: &str, open: &str, close: &str, from: usize) -> Option<(String, usize)> {
    let start = s[from..].find(&format!("<{}>", open))? + from + open.len() + 2;
    let end = s[start..].find(close)? + start;
    Some((xml_unescape(s[start..end].trim()), end + close.len() + 2))
}

fn parse_plist_root_keys(xml: &str) -> PlistRoot {
    let mut keys = Vec::new();
    // The root dict spans the first <dict> to the last </dict>; nested dicts
    // live inside it.
    let Some(body_start) = xml.find("<dict>").map(|p| p + "<dict>".len()) else {
        return PlistRoot { keys };
    };
    let Some(body_end) = xml.rfind("</dict>") else {
        return PlistRoot { keys };
    };
    let body = &xml[body_start..body_end];
    let mut i = 0usize;
    while let Some((key, after_key)) = xml_element_text(body, "key", "</key>", i) {
        i = scan_plist_value(body, after_key, key, &mut keys);
    }
    PlistRoot { keys }
}

/// Read the value element that follows a root-dict key, record it, and
/// return the offset just past the value block.
fn scan_plist_value(body: &str, from: usize, key: String, keys: &mut Vec<(String, PlistVal)>) -> usize {
    let rest = &body[from..];
    let (value, consumed): (Option<PlistVal>, usize) = if let Some(rest2) = rest.strip_prefix("<string>") {
        match rest2.find("</string>") {
            Some(e) => (
                Some(PlistVal::Str(xml_unescape(rest2[..e].trim()))),
                "<string>".len() + e + "</string>".len(),
            ),
            None => (None, 0),
        }
    } else if let Some(rest2) = rest.strip_prefix("<integer>") {
        match rest2.find("</integer>") {
            Some(e) => (
                rest2[..e].trim().parse::<i64>().ok().map(PlistVal::Int),
                "<integer>".len() + e + "</integer>".len(),
            ),
            None => (None, 0),
        }
    } else if rest.starts_with("<true/>") {
        (Some(PlistVal::Bool(true)), "<true/>".len())
    } else if rest.starts_with("<false/>") {
        (Some(PlistVal::Bool(false)), "<false/>".len())
    } else if let Some(rest2) = rest.strip_prefix("<array>") {
        match rest2.find("</array>") {
            Some(end) => {
                let inner = &rest2[..end];
                let mut items: Vec<String> = Vec::new();
                let mut j = 0usize;
                while let Some((text, next)) = xml_element_text(inner, "string", "</string>", j) {
                    items.push(text);
                    j = next;
                }
                if items.is_empty() {
                    // array of dicts: format each one's key/integer pairs
                    let mut k = 0usize;
                    while let Some((dict, next)) = dict_block(inner, k) {
                        if let Some(s) = format_calendar(&dict) {
                            items.push(s);
                        }
                        k = next;
                    }
                }
                let v = (!items.is_empty()).then_some(PlistVal::List(items));
                (v, "<array>".len() + end + "</array>".len())
            }
            None => (None, 0),
        }
    } else if let Some(rest2) = rest.strip_prefix("<dict>") {
        // value dict: StartCalendarInterval most notably
        match matching_dict_close(rest2) {
            Some(end) => {
                let cal = format_calendar(&rest2[..end]).map(PlistVal::Str);
                (cal, "<dict>".len() + end + "</dict>".len())
            }
            None => (None, 0),
        }
    } else {
        (None, 0)
    };
    if let Some(v) = value {
        keys.push((key, v));
    }
    from + consumed.max(1)
}

/// The first `<dict>…</dict>` block starting at `from`, respecting nesting.
fn dict_block(s: &str, from: usize) -> Option<(String, usize)> {
    let start = s[from..].find("<dict>")? + from;
    let inner_from = start + "<dict>".len();
    let mut depth = 1usize;
    let mut j = inner_from;
    while depth > 0 {
        let next_open = s[j..].find("<dict>");
        let next_close = s[j..].find("</dict>")? + j;
        match next_open {
            Some(o) if o + j < next_close => {
                depth += 1;
                j = o + j + "<dict>".len();
            }
            _ => {
                depth -= 1;
                if depth == 0 {
                    return Some((s[inner_from..next_close].to_string(), next_close + "</dict>".len()));
                }
                j = next_close + "</dict>".len();
            }
        }
    }
    None
}

/// matching_dict_close finds where the dict starting at s[0] (which is just
/// past its opening <dict>) closes, respecting nesting; returns the offset of
/// its </dict>.
fn matching_dict_close(s: &str) -> Option<usize> {
    let mut depth = 1usize;
    let mut j = 0usize;
    while depth > 0 {
        let next_open = s[j..].find("<dict>").map(|p| p + j);
        let next_close = s[j..].find("</dict>").map(|p| p + j)?;
        match next_open {
            Some(o) if o < next_close => {
                depth += 1;
                j = o + "<dict>".len();
            }
            _ => {
                depth -= 1;
                j = next_close + "</dict>".len();
                if depth == 0 {
                    return Some(next_close);
                }
            }
        }
    }
    None
}

/// "Sun at 06:00", "month 3 day 15 at 02:30" — Go's formatCalendarInterval.
fn format_calendar(dict_inner: &str) -> Option<String> {
    let mut cal: Vec<(String, i64)> = Vec::new();
    let mut j = 0usize;
    while let Some((key, after)) = xml_element_text(dict_inner, "key", "</key>", j) {
        if let Some((val, next)) = xml_element_text(dict_inner, "integer", "</integer>", after) {
            if let Ok(v) = val.parse::<i64>() {
                cal.push((key, v));
            }
            j = next;
        } else {
            break;
        }
    }
    if cal.is_empty() {
        return None;
    }
    let get = |name: &str| cal.iter().find(|(k, _)| k == name).map(|(_, v)| *v);
    let weekdays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let mut parts: Vec<String> = Vec::new();
    if let Some(w) = get("Weekday") {
        if let Some(name) = weekdays.get(w as usize) {
            parts.push(name.to_string());
        }
    }
    if let Some(m) = get("Month") {
        parts.push(format!("month {}", m));
    }
    if let Some(d) = get("Day") {
        parts.push(format!("day {}", d));
    }
    match (get("Hour"), get("Minute")) {
        (Some(h), Some(m)) => parts.push(format!("at {:02}:{:02}", h, m)),
        (Some(h), None) => parts.push(format!("at {:02}:00", h)),
        (None, Some(m)) => parts.push(format!("at *:{:02}", m)),
        (None, None) => {}
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

/// "5m"-style short duration for StartInterval.
fn fmt_duration_short(secs: i64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// `ps time` = cumulative CPU time: "0:00.42", "12:03.5", "1:02:03.4".
fn parse_cpu_time_to_ms(s: &str) -> Option<u64> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.is_empty() {
        return None;
    }
    let mut total: f64 = parts.last()?.parse().ok()?;
    let mut mult = 60f64;
    for p in parts.iter().rev().skip(1) {
        total += p.parse::<f64>().ok()? * mult;
        mult *= 60.0;
    }
    Some((total * 1000.0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsof_fd_counts_sections_and_garbage() {
        let text = "\
p42
f0
f1
f2
f256
p7
f3
pnotapid
f9
f10
";
        let m = parse_lsof_fd_counts(text);
        assert_eq!(m.get(&42), Some(&4));
        assert_eq!(m.get(&7), Some(&1));
        // an unparseable `p` line closes the section — the orphan fds that
        // follow count into no pid instead of leaking into the previous one
        assert_eq!(m.len(), 2, "{m:?}");
    }

    #[test]
    #[cfg(target_os = "macos")]
    // The kernel updates a task's rusage IO counters lazily; under the
    // parallel test runner it can lag the write() by more than the poll
    // window below, so this only runs explicitly:
    //   cargo test rusage -- --ignored --nocapture
    #[ignore = "kernel rusage IO counters lag under parallel test load"]
    fn rusage_diskio_tracks_written_bytes() {
        // Proves the FFI offsets live: a 4 MiB write() must move the
        // written counter by at least the payload. (The read-back of the
        // same file hits the page cache, so bytesread legitimately stays 0.)
        let path = std::env::temp_dir().join(format!("witr-rusage-{}", std::process::id()));
        let payload = vec![0xABu8; 4 * 1024 * 1024];
        let (_r0, w0) = disk_io_of(std::process::id() as Pid).expect("proc_pid_rusage on self");
        std::fs::write(&path, &payload).unwrap();
        // kernel rusage counters can lag the syscall under parallel test
        // load — poll briefly until the write shows up
        let target = w0 + payload.len() as u64;
        let mut w1 = w0;
        for _ in 0..40 {
            let (_, w) = disk_io_of(std::process::id() as Pid).unwrap();
            w1 = w;
            if w1 >= target {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(w1 >= target, "written stuck at {w1}, expected >= {target} (w0={w0})");
        // counters are cumulative: a second read never goes down
        let (_, w2) = disk_io_of(std::process::id() as Pid).unwrap();
        assert!(w2 >= w1);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn ps_env_parse() {
        let out = "1234 /usr/bin/python3 -c x PATH=/usr/bin:/bin HOME=/Users/me SHELL=/bin/zsh TERM=xterm-256color";
        let env = parse_ps_env(out);
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("PATH").as_deref(), Some("/usr/bin:/bin"));
        assert_eq!(get("HOME").as_deref(), Some("/Users/me"));
        assert_eq!(get("SHELL").as_deref(), Some("/bin/zsh"));
        assert_eq!(get("TERM").as_deref(), Some("xterm-256color"));
        // the command's own tokens don't produce entries
        assert!(!env.iter().any(|(n, _)| n == "c"));
    }

    #[test]
    fn ps_env_parse_filters_and_dedups() {
        // numbers-only / weird names are dropped, duplicates keep first
        let out = "1 run 1BAD=x _PRIVATE=y LC_CTYPE=UTF-8 LC_CTYPE=dup";
        let env = parse_ps_env(out);
        assert!(env.iter().all(|(n, _)| n != "1BAD"));
        assert_eq!(
            env.iter().find(|(n, _)| n == "_PRIVATE").map(|(_, v)| v.as_str()),
            Some("y")
        );
        assert_eq!(
            env.iter().filter(|(n, _)| n == "LC_CTYPE").count(),
            1,
            "duplicate names keep one entry"
        );
    }

    #[test]
    fn ps_list_line() {
        let p = parse_ps_list_line(
            "  350   1   501 S 2-03:10:31 0:05.00  1.2  45600 456780 /opt/homebrew/bin/nginx",
            &Users::load(),
        )
        .unwrap();
        assert_eq!(p.pid, 350);
        assert_eq!(p.ppid, Some(1));
        assert_eq!(p.uid, Some(501));
        assert_eq!(p.state.as_deref(), Some("S"));
        // started = parse-time now − elapsed; the test's own now may tick a
        // second later, so compare with a ±1s tolerance
        let expect = now_unix() - 184_231;
        assert!(
            (p.started.unwrap() - expect).abs() <= 1,
            "started {:?} vs expected {expect}",
            p.started
        );
        assert_eq!(p.cpu_time_ms, Some(5_000));
        assert_eq!(p.cpu, Some(1.2));
        assert_eq!(p.mem_kb, Some(45600));
        assert_eq!(p.vm_kb, Some(456780));
        assert_eq!(p.name, "nginx");
        assert_eq!(p.exe.as_deref(), Some("/opt/homebrew/bin/nginx"));
    }

    #[test]
    fn ps_list_line_with_spaces_in_path() {
        let p = parse_ps_list_line(
            "  999   1   0  S 42 1:02:03.4  0.0   1024   2048 /Applications/My App/Helper --flag",
            &Users::load(),
        )
        .unwrap();
        assert_eq!(p.exe.as_deref(), Some("/Applications/My App/Helper --flag"));
        assert_eq!(p.name, "Helper --flag");
        assert_eq!(p.state.as_deref(), Some("S"));
        assert_eq!(p.cpu_time_ms, Some(3_723_400));
    }

    #[test]
    fn cpu_time_formats() {
        assert_eq!(parse_cpu_time_to_ms("0:00.42"), Some(420));
        assert_eq!(parse_cpu_time_to_ms("12:03.5"), Some(723_500));
        assert_eq!(parse_cpu_time_to_ms("1:02:03.4"), Some(3_723_400));
        assert_eq!(parse_cpu_time_to_ms("junk"), None);
    }

    #[test]
    fn ps_detail_line() {
        let (pid, cpu, cmd) = parse_ps_detail_line("  1234 0.7 nginx: worker process").unwrap();
        assert_eq!(pid, 1234);
        assert_eq!(cpu, Some(0.7));
        assert_eq!(cmd, "nginx: worker process");
    }

    #[test]
    fn lsof_listen_line() {
        let s = parse_lsof_net_line(
            "nginx  1234  yao   12u  IPv4  0xttt  0t0  TCP *:8080 (LISTEN)",
        )
        .unwrap();
        assert_eq!(s.pid, Some(1234));
        assert_eq!(s.proto, "tcp");
        assert_eq!(s.local_addr, "*");
        assert_eq!(s.local_port, 8080);
        assert_eq!(s.state, "LISTEN");
    }

    #[test]
    fn lsof_established_v6() {
        let s = parse_lsof_net_line(
            "curl  4321  yao   5u  IPv6  0xttt  0t0  TCP [2001:db8::1]:54321->[2001:db8::2]:443 (ESTABLISHED)",
        )
        .unwrap();
        assert_eq!(s.proto, "tcp6");
        assert_eq!(s.local_addr, "2001:db8::1");
        assert_eq!(s.local_port, 54321);
        assert_eq!(s.peer_addr.as_deref(), Some("2001:db8::2"));
        assert_eq!(s.peer_port, Some(443));
        assert_eq!(s.state, "ESTABLISHED");
    }

    #[test]
    fn lsof_fd_modes() {
        // access mode only (single trailing alpha) — not a lock
        assert_eq!(lsof_fd_lock("5u"), None);
        assert_eq!(lsof_fd_lock("3r"), None);
        assert_eq!(lsof_fd_lock("4w"), None);
        assert_eq!(lsof_fd_access("5u"), Some("RW"));
        assert_eq!(lsof_fd_access("3r"), Some("READ"));
        assert_eq!(lsof_fd_access("4w"), Some("WRITE"));
        // real lock flags ride after the access char
        assert_eq!(lsof_fd_lock("5uW"), Some("WRITE"));
        assert_eq!(lsof_fd_lock("10uw"), Some("WRITE"));
        assert_eq!(lsof_fd_lock("5ur"), Some("READ"));
        assert_eq!(lsof_fd_lock("5uR"), Some("READ"));
        assert_eq!(lsof_fd_lock("5uu"), Some("RW"));
        // special fd names never look like locks
        assert_eq!(lsof_fd_lock("cwd"), None);
        assert_eq!(lsof_fd_lock("txt"), None);
        assert_eq!(lsof_fd_lock("KQUEUE"), None);
    }

    #[test]
    fn lsof_lock_flag_line() {
        let l = parse_lsof_lock_line(
            "pg 1234 501 3uW REG 1,4 0 154117320 /private/tmp/witr_lock_test.lock",
        )
        .unwrap();
        assert_eq!(l.pid, Some(1234));
        assert_eq!(l.kind, "FLOCK");
        assert_eq!(l.mode, "WRITE");
        assert_eq!(l.owner, "pg");
        assert_eq!(l.id, "3uW");
        assert_eq!(l.path, "/private/tmp/witr_lock_test.lock");
    }

    #[test]
    fn lsof_lock_file_heuristic() {
        // opened for write, path looks like a lock file -> surfaced
        let l = parse_lsof_lock_line(
            "openclaw 87370 501 4u REG 1,14 0 154117389 /Users/me/.openclaw/tmp/gateway.eabed588.lock",
        )
        .unwrap();
        assert_eq!(l.mode, "RW");
        assert_eq!(l.path, "/Users/me/.openclaw/tmp/gateway.eabed588.lock");
        // .pid files too
        assert!(parse_lsof_lock_line(
            "nginx 350 501 5w REG 1,4 6 999 /var/run/nginx.pid"
        )
        .is_some());
        // regular file without lock-ish name -> dropped
        assert!(parse_lsof_lock_line(
            "nginx 350 501 5u REG 1,4 0 99 /var/log/access.log"
        )
        .is_none());
        // non-REG types never pass the heuristic (only real flags do)
        assert!(parse_lsof_lock_line(
            "nginx 350 501 1u CHR 1,2 0t0 1234 /dev/null"
        )
        .is_none());
        assert!(parse_lsof_lock_line(
            "foo 350 501 0u KQUEUE 0,0 0 0 (not listed)"
        )
        .is_none());
    }

    #[test]
    fn launchctl_maxfiles_parse() {
        assert_eq!(parse_launchctl_maxfiles("maxfiles    256    unlimited"), Some(256));
        // unlimited soft limit → no usable number
        assert_eq!(parse_launchctl_maxfiles("maxfiles    unlimited    unlimited"), None);
        assert_eq!(parse_launchctl_maxfiles(""), None);
    }

    #[test]
    fn lsof_open_files_parse() {
        let rows: Vec<String> = [
            "COMMAND   PID    USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME",
            "pg       1234     501  3uW   REG                1,4        0  100 /tmp/witr_lock_test.lock",
            "nginx     350     501  5u    REG                1,4      123  101 /var/log/access.log",
            "nginx     350     501  6u    REG                1,4      123  101 /var/log/access.log",
            "sh        400     501  0u    CHR                1,2    0t0 9999 /dev/null",
            "sh        400     501  1u    CHR                1,2    0t0 9998 /dev/ttys001",
            "curl     4321     501  7u   IPv6  0x7130f663bb98979a      0t0  TCP [::1]:54321->[::1]:443 (ESTABLISHED)",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let out = parse_lsof_open_files(&rows);
        // dup (pid,path) collapses; /dev/null and /dev/tty* drop; IPv6 drops
        assert_eq!(out.len(), 2, "{out:?}");
        let log = out.iter().find(|l| l.path == "/var/log/access.log").unwrap();
        assert_eq!(log.kind, "OPEN");
        assert_eq!(log.mode, "RW");
        assert_eq!(log.pid, Some(350));
        let lock = out.iter().find(|l| l.path == "/tmp/witr_lock_test.lock").unwrap();
        assert_eq!(lock.kind, "FLOCK");
        assert_eq!(lock.mode, "WRITE");
    }

    #[test]
    fn lsof_files_and_locks_parse() {
        let rows: Vec<String> = [
            "COMMAND   PID    USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME",
            "pg       1234     501  3uW   REG                1,4        0  100 /tmp/witr_lock_test.lock",
            "nginx     350     501  5u    REG                1,4      123  101 /var/log/access.log",
            "nginx     350     501  6u    REG                1,4      123  101 /var/log/access.log",
            "curl     4321     501  7u   IPv6  0x7130f663bb98979a      0t0  TCP [2001:db8::1]:54321->[2001:db8::2]:443 (ESTABLISHED)",
            "nginx     350     501  8u   IPv4  0x402a7cce126c4085      0t0  TCP *:8080 (LISTEN)",
            "foo      9999     501  0u    CHR                1,2      0t0  102 /dev/null",
            "bar      9998     501  1u   PIPE  0xdeadbeef              0    103 ->0xcafebabe",
            "baz      9997     501  2u   unix 0xfeedface              0    104 /tmp/x.sock",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let (files, locks) = parse_lsof_files_and_locks(&rows);
        // regular files kept, deduped, /dev and CHR dropped
        assert!(files.iter().any(|f| f == "/tmp/witr_lock_test.lock"));
        assert_eq!(
            files.iter().filter(|f| *f == "/var/log/access.log").count(),
            1,
            "same file via two fds appears once"
        );
        assert!(!files.iter().any(|f| f.contains("/dev/null")));
        // sockets keep endpoints, state suffix stripped
        assert!(files
            .iter()
            .any(|f| f == "socket ipv6 [2001:db8::1]:54321->[2001:db8::2]:443"));
        assert!(files.iter().any(|f| f == "socket ipv4 *:8080"));
        // pipe + unix socket summarized
        assert!(files
            .iter()
            .any(|f| f == "[2 pipe/unix-socket(s)]"));
        // locks: real flag + .lock heuristic, deduped
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].mode, "WRITE");
        assert_eq!(locks[0].path, "/tmp/witr_lock_test.lock");
    }

    #[test]
    fn launchctl_line() {
        let (pid, label) = parse_launchctl_pid_label("350\t0\torg.example.nginx").unwrap();
        assert_eq!(pid, 350);
        assert_eq!(label, "org.example.nginx");
        assert!(parse_launchctl_pid_label("-\t0\tnot.running").is_none());
    }

    #[test]
    fn cpu_busy_percent_math() {
        // two cores; core 0 busy, core 1 idle
        let prev = vec![[100u64, 50, 800, 10], [10, 5, 900, 0]];
        let cur = vec![[150, 70, 850, 10], [10, 5, 950, 0]];
        let (total, cores) = cpu_busy_between(&prev, &cur);
        // core 0: busy delta 50+20+0=70 of 120 elapsed → 58.33%
        assert!((cores[0] - 58.3333).abs() < 0.01, "{:?}", cores);
        // core 1: only idle ticks elapsed → a real 0%, still on the grid
        assert!(cores[1].abs() < 0.01, "{:?}", cores);
        // aggregate: 70 busy of 170 elapsed ticks (core 1 contributes 50 idle)
        let t = total.expect("ticks elapsed");
        assert!((t - 70.0 / 170.0 * 100.0).abs() < 0.01, "{t}");
        // no elapsed ticks anywhere → no percentages at all
        let (total, cores) = cpu_busy_between(&cur, &cur);
        assert!(total.is_none() && cores.is_empty());
    }

    #[test]
    fn vm_stat_and_swapusage_parse() {
        let text = "\
Mach Virtual Memory Statistics: (page size of 4096 bytes)
Pages free:                               12345.
Pages active:                           500000.
Pages inactive:                         200000.
Pages speculative:                       30000.
Pages wired down:                       150000.
Pages occupied by compressor:            75000.
";
        // used = active + wired + compressor = 725000 pages × 4096 B
        // = 2969600000 bytes → 2832 MB
        assert_eq!(parse_vm_stat(text, 4096), Some(2832));
        // the older compressor label still counts
        let old = text.replace("Pages occupied by compressor:", "Pages stored in compressor:");
        assert_eq!(parse_vm_stat(&old, 4096), Some(2832));
        // a broken read yields nothing rather than 0
        assert_eq!(parse_vm_stat("Pages free: 1.", 4096), None);

        let (used, total) = parse_swapusage("total = 3072.00M used = 12.53M free = 3059.47M (encrypted)");
        assert_eq!((used, total), (Some(12), Some(3072)));
        // gigabyte units scale up
        let (used, total) = parse_swapusage("total = 2.00G used = 0B free = 2.00G");
        assert_eq!((used, total), (Some(0), Some(2048)));
        // garbage in → nothing out
        assert_eq!(parse_swapusage("no numbers here"), (None, None));
    }
}

