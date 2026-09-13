//! macOS: ps/lsof/launchctl shell-outs (the same strategy as the Go witr).
//! SIP prevents reading other users' env vars, so `--env` is not served here.

use std::time::Duration;

use crate::model::{Pid, Process, Socket, Source};
use crate::platform::{Capabilities, PlatError, PlatResult, Platform, Users};
use crate::util::{basename, now_unix, parse_etime_to_secs, run_ok, split_host_port};

const CMD_TIMEOUT: Duration = Duration::from_secs(8);
const LSOF_TIMEOUT: Duration = Duration::from_secs(15);

pub struct MacOs {
    users: Users,
}

impl MacOs {
    pub fn new(users: Users) -> Self {
        MacOs { users }
    }
}

/// `ps -axo pid=,ppid=,uid=,etime=,pcpu=,rss=,comm=` — comm is the last
/// column and may contain spaces, so the first six whitespace tokens are
/// fixed and the rest is the executable path.
fn parse_ps_list_line(line: &str, users: &Users) -> Option<Process> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let bytes = line.as_bytes();
    let mut idx = 0usize;
    // skip leading whitespace, then consume six fixed fields
    let mut fixed: [Option<&str>; 6] = [None; 6];
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
    let started = parse_etime_to_secs(fixed[3]?).map(|age| now_unix() - age);
    let cpu = fixed[4]?.parse::<f64>().ok().filter(|c| *c > 0.05);
    let mem_kb = fixed[5]?.parse::<u64>().ok().filter(|m| *m > 0);
    Some(Process {
        pid,
        ppid: Some(ppid),
        name: basename(comm),
        exe: if comm.is_empty() { None } else { Some(comm.to_string()) },
        user: users.name_for(uid),
        uid: Some(uid),
        started,
        cpu,
        mem_kb,
        ..Default::default()
    })
}

/// `ps -wwO pid=,command= -p N` → (pid, full command line as one string).
fn parse_ps_detail_line(line: &str) -> Option<(Pid, String)> {
    let line = line.trim_start();
    let (pid_str, rest) = line.split_once(' ')?;
    let pid: Pid = pid_str.parse().ok()?;
    Some((pid, rest.trim().to_string()))
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
            &["-axo", "pid=,ppid=,uid=,etime=,pcpu=,rss=,comm="],
            CMD_TIMEOUT,
        )
        .ok_or_else(|| PlatError::Failed("ps failed".into()))?;
        Ok(out.lines().filter_map(|l| parse_ps_list_line(l, &self.users)).collect())
    }

    fn list_sockets(&self) -> PlatResult<Vec<Socket>> {
        let mut out = Vec::new();
        for args in [
            vec!["-nP", "-w", "-iTCP", "-sTCP:LISTEN"],
            vec!["-nP", "-w", "-iUDP"],
        ] {
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

    fn detail(&self, brief: &Process, want_env: bool) -> Process {
        let mut p = brief.clone();
        if let Some(out) = run_ok(
            "ps",
            &["-ww", "-o", "pid=,command=", "-p", &brief.pid.to_string()],
            CMD_TIMEOUT,
        ) {
            for line in out.lines() {
                if let Some((_, cmd)) = parse_ps_detail_line(line) {
                    if !cmd.is_empty() {
                        p.cmdline = vec![cmd];
                    }
                    break;
                }
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

    fn container_of(&self, _pid: Pid) -> Option<Source> {
        None // best-effort container attribution ships later (docker/podman CLIs)
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
                        let detail = match find_plist(&label) {
                            Some(p) => format!("launchd job \"{}\" (plist: {})", label, p),
                            None => format!("launchd job \"{}\"", label),
                        };
                        return Some(Source {
                            kind: "launchd".into(),
                            label: Some(label),
                            detail: Some(detail),
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
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "  350   1   501 2-03:10:31  1.2  45600 /opt/homebrew/bin/nginx",
            &Users::load(),
        )
        .unwrap();
        assert_eq!(p.pid, 350);
        assert_eq!(p.ppid, Some(1));
        assert_eq!(p.uid, Some(501));
        assert_eq!(p.started, Some(now_unix() - 184_231));
        assert_eq!(p.cpu, Some(1.2));
        assert_eq!(p.mem_kb, Some(45600));
        assert_eq!(p.name, "nginx");
        assert_eq!(p.exe.as_deref(), Some("/opt/homebrew/bin/nginx"));
    }

    #[test]
    fn ps_list_line_with_spaces_in_path() {
        let p = parse_ps_list_line(
            "  999   1   0  42  0.0   1024 /Applications/My App/Helper --flag",
            &Users::load(),
        )
        .unwrap();
        assert_eq!(p.exe.as_deref(), Some("/Applications/My App/Helper --flag"));
        assert_eq!(p.name, "Helper --flag");
    }

    #[test]
    fn ps_detail_line() {
        let (pid, cmd) = parse_ps_detail_line("  1234 nginx: worker process").unwrap();
        assert_eq!(pid, 1234);
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
    fn launchctl_line() {
        let (pid, label) = parse_launchctl_pid_label("350\t0\torg.example.nginx").unwrap();
        assert_eq!(pid, 350);
        assert_eq!(label, "org.example.nginx");
        assert!(parse_launchctl_pid_label("-\t0\tnot.running").is_none());
    }
}
