//! Linux: everything comes from procfs; container runtime CLIs and
//! systemctl are consulted best-effort for attribution.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::Path;
use std::time::Duration;

use crate::model::{Pid, Process, Socket, Source};
use crate::util::{now_unix, run_ok, strip_deleted_suffix};
use crate::platform::{Capabilities, PlatError, PlatResult, Platform, Users};

const CLK_TCK: f64 = 100.0; // kernel CONFIG_HZ userspace value on effectively all distros
const CMD_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Linux {
    users: Users,
}

impl Linux {
    pub fn new(users: Users) -> Self {
        Linux { users }
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

/// Parse /proc/<pid>/stat: comm may contain spaces and parentheses, so
/// cut at the LAST ')'. Fields after it: state, ppid, ... (field 3+).
fn parse_stat(raw: &str) -> Option<(String, Pid, char, u64, u64, u64)> {
    // (comm, ppid, state, starttime_ticks, cpu_ticks_total, rss_pages)
    let rparen = raw.rfind(')')?;
    let comm = raw[raw.find('(')? + 1..rparen].to_string();
    let rest = raw[rparen + 2..].split_whitespace().collect::<Vec<_>>();
    // rest[0]=state(3) rest[1]=ppid(4) rest[11]=utime(14) rest[12]=stime(15)
    // rest[19]=starttime(22) rest[21]=rss(24, pages)
    let state = rest.first()?.chars().next()?;
    let ppid: Pid = rest.get(1)?.parse().ok()?;
    let starttime: u64 = rest.get(19)?.parse().ok()?;
    let utime: u64 = rest.get(11)?.parse().unwrap_or(0);
    let stime: u64 = rest.get(12)?.parse().unwrap_or(0);
    let rss: i64 = rest.get(21)?.parse().unwrap_or(0);
    Some((comm, ppid, state, starttime, utime + stime, rss.max(0) as u64))
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
    match (proto, st) {
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

impl Platform for Linux {
    fn name(&self) -> &'static str {
        "linux"
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
            let Some((comm, ppid, state, starttime, cpu_ticks, rss_pages)) = parse_stat(&stat)
            else {
                continue;
            };
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
            let mem_kb = (rss_pages > 0).then(|| rss_pages as u64 * 4); // 4 KiB pages
            let _ = state;
            procs.push(Process {
                pid,
                ppid: Some(ppid),
                name: comm,
                user: uid.and_then(|u| self.users.name_for(u)),
                uid,
                started,
                kernel_thread,
                cpu: cpu.filter(|c| *c > 0.05),
                mem_kb: mem_kb.filter(|m| *m > 0),
                cpu_time_ms,
                ..Default::default()
            });
        }
        Ok(procs)
    }

    fn detail(&self, brief: &Process, want_env: bool) -> Process {
        let mut p = brief.clone();
        let base = Path::new("/proc").join(brief.pid.to_string());
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
        p
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
        let owners = inode_owner_map();
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for proto in ["tcp", "tcp6", "udp", "udp6"] {
            for (addr, p, rem, state, inode) in read_socket_table(proto) {
                // Ports tab mirrors the Go witr: listening tcp + bound udp.
                let keep = if proto.starts_with("tcp") {
                    state == "LISTEN"
                } else {
                    true
                };
                if !keep || !seen.insert(inode) {
                    continue;
                }
                out.push(build_socket(proto, addr, p, rem, state, inode, &owners));
            }
        }
        out.sort_by(|a, b| (a.proto.clone(), a.local_port).cmp(&(b.proto.clone(), b.local_port)));
        Ok(out)
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
        let mut sockets = 0usize;
        let mut pipes = 0usize;
        let Ok(fds) = std::fs::read_dir(format!("/proc/{}/fd", pid)) else {
            return files; // other user's process without root
        };
        for fd in fds.flatten() {
            if let Some(target) = readlink_ok(&fd.path()) {
                if target.starts_with("socket:[") {
                    sockets += 1;
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
        if sockets > 0 {
            files.push(format!("[{} socket(s) — see Ports tab]", sockets));
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
            } else if let Some(rest) = path.strip_prefix("/lxc/") {
                ("lxc", rest)
            } else {
                continue;
            };
            let id = id.split('/').next().unwrap_or(id);
            let mut label = id.chars().take(12).collect::<String>();
            let mut detail = format!("runtime: {}", runtime);
            if runtime == "docker" {
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
                    .split(|c| c == '(' || c == ';')
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
                    label: Some(unit),
                    detail,
                })
            }
            None => Some(Source {
                kind: "init".into(),
                label: Some(init.name.clone()),
                detail: Some(format!("pid {} is not part of a systemd unit", target.pid)),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parse() {
        // fields after ')': state(3) ppid(4) ... starttime(22)=token 19, vsize(23), rss(24)=token 21
        let line = "1234 (nginx: worker) S 350 1234 1234 0 -1 4194560 ... 0 0 0 0 0 0 0 0 0 0 0 123456 789012 123";
        let (comm, ppid, state, start, cpu_ticks, rss) = parse_stat(line).unwrap();
        assert_eq!(comm, "nginx: worker");
        assert_eq!(ppid, 350);
        assert_eq!(state, 'S');
        assert_eq!(start, 123456);
        assert_eq!(cpu_ticks, 0);
        assert_eq!(rss, 123);
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
    fn cgroup_docker() {
        let line = "11:pids:/docker/9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a";
        let p = line.splitn(3, ':').nth(2).unwrap();
        assert!(p.strip_prefix("/docker/").is_some());
    }
}
