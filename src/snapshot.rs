//! Process-table snapshots: `--snap FILE` writes the full listing as JSON,
//! `--diff FILE` compares the current listing against a saved one and
//! reports what appeared, disappeared, restarted (same program identity
//! under a new pid) or changed its command line.
//!
//! Identity mirrors the TUI sampler's crash-loop detector
//! (`history::identity`): (name, exe, user) — stable across restarts.

use crate::model::{Pid, Process};
use std::collections::{HashMap, HashSet};

/// Stable program identity — shared with --follow's restart re-acquisition
/// and the TUI sampler's crash-loop detector (see util::identity).
pub fn identity(p: &Process) -> u64 {
    crate::util::identity(p)
}

pub fn save(path: &str, procs: &[Process]) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(procs).unwrap_or_else(|_| "[]".into());
    std::fs::write(path, json)
}

pub fn load(path: &str) -> Result<Vec<Process>, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("{path}: invalid snapshot JSON: {e}"))
}

fn command_of(p: &Process) -> String {
    if p.cmdline.is_empty() {
        p.name.clone()
    } else {
        p.cmdline.join(" ")
    }
}

/// One line of diff output. `kind` is one of new / gone / restarted /
/// changed; `detail` carries the human-readable specifics.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiffEntry {
    pub kind: &'static str,
    pub pid: Pid,
    pub name: String,
    pub detail: String,
}

/// Compare two process listings (old = the snapshot, now = current).
/// Order: new, gone, restarted, changed — each grouped, pids ascending.
pub fn diff(old: &[Process], now: &[Process]) -> Vec<DiffEntry> {
    let mut out = Vec::new();

    let old_by_pid: HashMap<_, _> = old.iter().map(|p| (p.pid, p)).collect();
    let now_by_pid: HashMap<_, _> = now.iter().map(|p| (p.pid, p)).collect();

    // appeared
    let mut new_pids: Vec<_> = now.iter().filter(|p| !old_by_pid.contains_key(&p.pid)).collect();
    new_pids.sort_by_key(|p| p.pid);

    // disappeared
    let mut gone: Vec<_> = old.iter().filter(|p| !now_by_pid.contains_key(&p.pid)).collect();
    gone.sort_by_key(|p| p.pid);

    // restarted first: a process that is gone now, whose identity exists
    // again under a different pid in the current listing. Those pids are
    // restarts, not genuinely "new" — excluded from the new list below.
    let now_identities: HashMap<u64, &Process> =
        new_pids.iter().map(|p| (identity(p), *p)).collect();
    let mut restarted_pids: HashSet<Pid> = HashSet::new();
    let mut restarted: Vec<DiffEntry> = Vec::new();
    let mut seen_identity: HashSet<u64> = HashSet::new();
    for p in &gone {
        let id = identity(p);
        if let Some(nu) = now_identities.get(&id) {
            // report each identity once (the new pid, not the old one)
            if seen_identity.insert(id) {
                restarted_pids.insert(nu.pid);
                restarted.push(DiffEntry {
                    kind: "restarted",
                    pid: nu.pid,
                    name: nu.name.clone(),
                    detail: format!("was pid {}, now pid {}", p.pid, nu.pid),
                });
            }
        }
    }
    restarted.sort_by_key(|e| e.pid);

    for p in &new_pids {
        if restarted_pids.contains(&p.pid) {
            continue;
        }
        out.push(DiffEntry {
            kind: "new",
            pid: p.pid,
            name: p.name.clone(),
            detail: command_of(p),
        });
    }
    for p in now {
        if let Some(prev) = old_by_pid.get(&p.pid) {
            if !command_of(p).is_empty() && command_of(p) != command_of(prev) {
                out.push(DiffEntry {
                    kind: "changed",
                    pid: p.pid,
                    name: p.name.clone(),
                    detail: format!("{} → {}", command_of(prev), command_of(p)),
                });
            }
        }
    }
    for p in &gone {
        out.push(DiffEntry {
            kind: "gone",
            pid: p.pid,
            name: p.name.clone(),
            detail: command_of(p),
        });
    }
    out.extend(restarted);

    out
}

/// Render the diff as plain text; empty when nothing changed.
pub fn render(entries: &[DiffEntry]) -> String {
    if entries.is_empty() {
        return "no changes".into();
    }
    let mut s = String::new();
    for e in entries {
        s.push_str(&format!(
            "{:<9} pid {:<7} {}\n    {}\n",
            e.kind, e.pid, e.name, e.detail
        ));
    }
    s.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: i32, name: &str, exe: Option<&str>, user: Option<&str>, cmd: &str) -> Process {
        Process {
            pid,
            name: name.into(),
            exe: exe.map(|e| e.into()),
            user: user.map(|u| u.into()),
            cmdline: if cmd.is_empty() {
                vec![]
            } else {
                cmd.split_whitespace().map(|s| s.into()).collect()
            },
            ..Default::default()
        }
    }

    #[test]
    fn diff_reports_all_four_kinds() {
        let old = vec![
            proc(10, "nginx", Some("/usr/sbin/nginx"), Some("root"), "nginx -g daemon off;"),
            proc(20, "worker", Some("/app/worker"), Some("svc"), "worker --queue a"),
            proc(30, "mongo", Some("/usr/bin/mongod"), Some("mongo"), "mongod --port 27017"),
        ];
        let now = vec![
            // same pid, different cmdline → changed
            proc(10, "nginx", Some("/usr/sbin/nginx"), Some("root"), "nginx -g daemon off; -t"),
            // 20 exited, 21 is the same program under a new pid → restarted
            proc(21, "worker", Some("/app/worker"), Some("svc"), "worker --queue b"),
            // brand new
            proc(40, "redis", Some("/usr/bin/redis"), Some("svc"), "redis-server"),
            // 30 exited for good → gone
        ];
        let d = diff(&old, &now);
        let kinds: Vec<_> = d.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&"changed"));
        assert!(kinds.contains(&"gone"));
        assert_eq!(kinds.iter().filter(|k| **k == "new").count(), 1);
        let rst = d.iter().find(|e| e.kind == "restarted").unwrap();
        assert_eq!(rst.pid, 21);
        assert!(rst.detail.contains("was pid 20"));
    }

    #[test]
    fn restarted_distinguishes_identity() {
        // same name but different user → two instances, not a restart
        let old = vec![proc(10, "python", Some("/usr/bin/python"), Some("alice"), "python s.py")];
        let now = vec![proc(11, "python", Some("/usr/bin/python"), Some("bob"), "python s.py")];
        let d = diff(&old, &now);
        assert!(d.iter().any(|e| e.kind == "gone"));
        assert!(d.iter().any(|e| e.kind == "new"));
        assert!(!d.iter().any(|e| e.kind == "restarted"));
    }

    #[test]
    fn round_trip_save_load() {
        let dir = std::env::temp_dir().join(format!("witr-snap-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("snap.json");
        let procs = vec![proc(7, "a", None, None, "")];
        save(path.to_str().unwrap(), &procs).unwrap();
        let loaded = load(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].pid, 7);
        assert_eq!(loaded[0].name, "a");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_changes() {
        let ps = vec![proc(1, "init", None, None, "")];
        assert_eq!(render(&diff(&ps, &ps)), "no changes");
    }
}
