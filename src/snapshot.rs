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

/// Minimum start-time advance (seconds) for a same-pid, same-identity pair
/// to count as a restart — etime-derived start estimates jitter ±1s between
/// passes, so anything smaller is measurement noise.
const SAME_PID_RESTART_SLACK_SECS: i64 = 5;

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

    // appeared — includes processes that took over a pid (different identity
    // behind a pid both listings share is reuse, not a changed command line)
    let mut new_pids: Vec<_> = now.iter().filter(|p| !old_by_pid.contains_key(&p.pid)).collect();
    new_pids.sort_by_key(|p| p.pid);

    // disappeared
    let mut gone: Vec<_> = old.iter().filter(|p| !now_by_pid.contains_key(&p.pid)).collect();
    gone.sort_by_key(|p| p.pid);

    // pid reuse: the pid exists on both sides but names a different program.
    // The old process is simply gone; the new one is genuinely new — neither
    // is a "changed" command line. Both sides get a reuse note so the pair
    // reads as one story ("this pid changed hands").
    let mut reused_new: HashSet<Pid> = HashSet::new();
    let mut reused_gone: HashSet<Pid> = HashSet::new();
    for (pid, prev) in &old_by_pid {
        if let Some(nu) = now_by_pid.get(pid) {
            if identity(prev) != identity(nu) {
                gone.push(*prev);
                new_pids.push(*nu);
                reused_new.insert(nu.pid);
                reused_gone.insert(*pid);
            }
        }
    }
    new_pids.sort_by_key(|p| p.pid);
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
        let detail = match old_by_pid.get(&p.pid) {
            Some(prev) => format!(
                "{} (pid reused — was {})",
                command_of(p),
                command_of(prev)
            ),
            None => command_of(p),
        };
        out.push(DiffEntry {
            kind: "new",
            pid: p.pid,
            name: p.name.clone(),
            detail,
        });
    }
    for p in now {
        if let Some(prev) = old_by_pid.get(&p.pid) {
            if identity(prev) == identity(p) {
                // same pid + same identity + a start time meaningfully later:
                // the program restarted and the new incarnation landed on the
                // same pid. The 5s slack absorbs the ±1s jitter of etime-
                // derived start estimates (two passes a second apart shift
                // every process's estimate by a second — that is NOT a
                // restart). Outweighs a cmdline flip: a fresh process may
                // legitimately start with different arguments.
                if let (Some(o), Some(n)) = (prev.started, p.started) {
                    if n.saturating_sub(o) >= SAME_PID_RESTART_SLACK_SECS {
                        out.push(DiffEntry {
                            kind: "restarted",
                            pid: p.pid,
                            name: p.name.clone(),
                            detail: format!(
                                "restarted on the same pid (started {} → {})",
                                crate::util::fmt_time(o),
                                crate::util::fmt_time(n)
                            ),
                        });
                        continue;
                    }
                }
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
    }
    for p in &gone {
        let detail = if reused_gone.contains(&p.pid) {
            format!("{} (pid taken over)", command_of(p))
        } else {
            command_of(p)
        };
        out.push(DiffEntry {
            kind: "gone",
            pid: p.pid,
            name: p.name.clone(),
            detail,
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

    #[test]
    fn pid_reuse_by_another_program_is_new_and_gone_not_changed() {
        // pid 10 was nginx, later an unrelated redis holds pid 10
        let old = vec![proc(10, "nginx", Some("/usr/sbin/nginx"), Some("root"), "nginx")];
        let now = vec![proc(10, "redis", Some("/usr/bin/redis"), Some("svc"), "redis-server")];
        let d = diff(&old, &now);
        assert!(
            !d.iter().any(|e| e.kind == "changed"),
            "a different program behind the same pid is not a changed cmdline"
        );
        let new_e = d.iter().find(|e| e.kind == "new").unwrap();
        assert_eq!(new_e.pid, 10);
        assert!(new_e.detail.contains("pid reused"), "{}", new_e.detail);
        assert!(new_e.detail.contains("nginx"), "names the previous holder: {}", new_e.detail);
        let gone_e = d.iter().find(|e| e.kind == "gone").unwrap();
        assert!(gone_e.detail.contains("taken over"), "{}", gone_e.detail);
    }

    #[test]
    fn same_pid_same_program_new_start_time_is_restarted() {
        let start: i64 = 1_000_000;
        let mut old = proc(10, "nginx", Some("/usr/sbin/nginx"), Some("root"), "nginx");
        old.started = Some(start);
        let mut now = proc(10, "nginx", Some("/usr/sbin/nginx"), Some("root"), "nginx");
        now.started = Some(start + 100);
        let d = diff(std::slice::from_ref(&old), std::slice::from_ref(&now));
        let rst = d.iter().find(|e| e.kind == "restarted").expect("restarted");
        assert_eq!(rst.pid, 10);
        assert!(rst.detail.contains("same pid"), "{}", rst.detail);
        assert!(!d.iter().any(|e| e.kind == "changed"), "no spurious changed entry");
        // etime-derived start estimates jitter by a second or two between
        // passes — that noise must NOT read as a restart
        now.started = Some(start + 2);
        assert!(diff(
            std::slice::from_ref(&old),
            std::slice::from_ref(&now)
        )
        .is_empty(), "±2s jitter is measurement noise");
        now.started = Some(start - 1);
        assert!(diff(
            std::slice::from_ref(&old),
            std::slice::from_ref(&now)
        )
        .is_empty(), "backwards drift is noise, not a restart");
        // identical start times (or unknown on either side) stay silent
        now.started = Some(start);
        assert!(diff(
            std::slice::from_ref(&old),
            std::slice::from_ref(&now)
        )
        .is_empty());
        now.started = None;
        assert!(diff(
            std::slice::from_ref(&old),
            std::slice::from_ref(&now)
        )
        .is_empty());
    }
}
