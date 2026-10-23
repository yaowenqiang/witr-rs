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

/// Bumped when the snapshot envelope changes shape. v1 was a bare JSON
/// array of processes; v2 is an envelope that can carry LISTEN ports.
pub const SNAPSHOT_VERSION: u32 = 2;

/// One LISTEN binding at snap time — (proto, port) plus who owned it, so a
/// later --diff can report "something started serving on :8080".
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Listener {
    pub proto: String,
    pub port: u16,
    /// Owners as "name (pid N)" — one per process bound to the port.
    pub who: Vec<String>,
}

/// LISTEN sockets + the process table → listener records. Sockets without
/// a visible owner are skipped (nothing to attribute, nothing to compare).
pub fn to_listeners(sockets: &[crate::model::Socket], procs: &[Process]) -> Vec<Listener> {
    let names: HashMap<Pid, &str> = procs.iter().map(|p| (p.pid, p.name.as_str())).collect();
    let mut map: std::collections::BTreeMap<(String, u16), Vec<(Pid, String)>> = Default::default();
    for s in sockets {
        if s.state != "LISTEN" {
            continue;
        }
        let Some(pid) = s.pid else { continue };
        let label = match names.get(&pid) {
            Some(n) => format!("{n} (pid {pid})"),
            None => format!("pid {pid}"),
        };
        map.entry((s.proto.clone(), s.local_port)).or_default().push((pid, label));
    }
    map.into_iter()
        .map(|((proto, port), mut who)| {
            who.sort();
            who.dedup();
            Listener {
                proto,
                port,
                who: who.into_iter().map(|(_, l)| l).collect(),
            }
        })
        .collect()
}

pub fn save(path: &str, procs: &[Process], listeners: &[Listener]) -> std::io::Result<()> {
    let doc = serde_json::json!({
        "snapshot_version": SNAPSHOT_VERSION,
        "saved_at": crate::util::now_unix(),
        "processes": procs,
        "listeners": listeners,
    });
    let json = serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into());
    std::fs::write(path, json)
}

/// Loads both shapes: the v1 bare array (no listeners recorded) and the v2
/// envelope. Returns the process table plus the listener list (empty for
/// v1 or for snapshots taken without `--snap --sockets`).
pub fn load(path: &str) -> Result<(Vec<Process>, Vec<Listener>), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    if raw.trim_start().starts_with('[') {
        let procs: Vec<Process> = serde_json::from_str(&raw)
            .map_err(|e| format!("{path}: invalid snapshot JSON: {e}"))?;
        return Ok((procs, Vec::new()));
    }
    #[derive(serde::Deserialize)]
    struct Snap {
        processes: Vec<Process>,
        #[serde(default)]
        listeners: Vec<Listener>,
    }
    let snap: Snap =
        serde_json::from_str(&raw).map_err(|e| format!("{path}: invalid snapshot JSON: {e}"))?;
    Ok((snap.processes, snap.listeners))
}

/// Directory the auto snapshots live in: `<config dir>/snapshots`
/// (split out with an explicit home for tests — pure, see
/// [`Config::path_under`]).
#[cfg(test)]
pub fn auto_dir_under(home: &std::path::Path) -> std::path::PathBuf {
    crate::config::Config::path_under(home)
        .parent()
        .map(|p| p.join("snapshots"))
        .unwrap_or_else(|| home.join("witr-rs-snapshots"))
}

/// The auto-snapshot dir for the current user — the env-resolved twin of
/// [`auto_dir_under`]. Err carries user-facing guidance.
fn auto_dir() -> Result<std::path::PathBuf, String> {
    crate::config::Config::base_dir()
        .map(|base| base.join("witr-rs").join("snapshots"))
        .ok_or_else(|| "no config base dir — set $HOME (or $XDG_CONFIG_HOME)".to_string())
}

/// `--snap` without a FILE: write to `snap-<unixts>.json` in the auto dir
/// and prune everything but the newest `keep` files. Returns the path
/// written so the caller can print it.
pub fn save_auto(
    procs: &[Process],
    listeners: &[Listener],
    keep: usize,
) -> std::io::Result<std::path::PathBuf> {
    let dir = auto_dir().map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?;
    save_auto_dir(&dir, procs, listeners, keep)
}

/// save_auto under an explicit home dir (split out for tests; pure).
#[cfg(test)]
pub fn save_auto_under(
    home: &std::path::Path,
    procs: &[Process],
    listeners: &[Listener],
    keep: usize,
) -> std::io::Result<std::path::PathBuf> {
    save_auto_dir(&auto_dir_under(home), procs, listeners, keep)
}

fn save_auto_dir(
    dir: &std::path::Path,
    procs: &[Process],
    listeners: &[Listener],
    keep: usize,
) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("snap-{}.json", crate::util::now_unix()));
    save(path.to_str().unwrap_or_default(), procs, listeners)?;
    prune(dir, keep);
    Ok(path)
}

/// Keep only the newest `keep` `snap-*.json` files (by name — the
/// timestamp sorts lexicographically); failures to unlink are ignored
/// (a file another process grabbed is not worth failing the snapshot).
fn prune(dir: &std::path::Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("snap-") && n.ends_with(".json"))
        })
        .collect();
    files.sort();
    while files.len() > keep {
        let _ = std::fs::remove_file(files.remove(0));
    }
}

/// Newest `snap-*.json` in the user's auto dir (lexicographic =
/// chronological). None when there is no base dir or no snapshots yet.
pub fn newest_auto() -> Option<std::path::PathBuf> {
    newest_auto_dir(&auto_dir().ok()?)
}

fn newest_auto_dir(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("snap-") && n.ends_with(".json"))
        })
        .collect();
    files.sort();
    files.pop()
}

/// Resolve a `--diff` reference: `last` = newest auto snapshot, a duration
/// (`1h`) = the newest snapshot at least that old (so you diff against the
/// state as of roughly an hour ago), anything else = a literal path.
/// Without a config base dir only literal paths make sense — same as the
/// old no-`$HOME` behavior.
pub fn resolve_ref(re: &str) -> Result<std::path::PathBuf, String> {
    match auto_dir() {
        Ok(dir) => resolve_ref_dir(&dir, re),
        Err(_) => Ok(std::path::PathBuf::from(re)),
    }
}

/// resolve_ref under an explicit home dir (split out for tests; pure).
#[cfg(test)]
pub fn resolve_ref_under(home: &std::path::Path, re: &str) -> Result<std::path::PathBuf, String> {
    resolve_ref_dir(&auto_dir_under(home), re)
}

fn resolve_ref_dir(dir: &std::path::Path, re: &str) -> Result<std::path::PathBuf, String> {
    if re == "last" {
        return newest_auto_dir(dir)
            .ok_or_else(|| "no auto snapshots yet — run `witr-rs --snap` first".to_string());
    }
    if let Some(secs) = parse_age_ref(re) {
        let cutoff = crate::util::now_unix() - secs;
        let mut best: Option<(i64, std::path::PathBuf)> = None;
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Err("no auto snapshots yet — run `witr-rs --snap` first".into());
        };
        for e in entries.flatten() {
            let name = e.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(ts) = name
                .strip_prefix("snap-")
                .and_then(|s| s.strip_suffix(".json"))
                .and_then(|s| s.parse::<i64>().ok())
            else {
                continue;
            };
            if ts <= cutoff && best.as_ref().is_none_or(|(bt, _)| ts > *bt) {
                best = Some((ts, e.path()));
            }
        }
        return best.map(|(_, p)| p).ok_or_else(|| {
            format!("no snapshot older than {re} — the oldest auto snapshot is too recent")
        });
    }
    Ok(std::path::PathBuf::from(re))
}

/// `1h` / `5m` / `30s` — a duration used as a point-in-time reference.
/// Bare numbers are rejected (parse_duration would accept "30"; a plain
/// number is far more likely a pid or path fragment than a duration).
fn parse_age_ref(s: &str) -> Option<i64> {
    if s.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    crate::util::parse_duration(s)
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

/// Compare two listener sets: bindings that appeared ("a process started
/// serving on :8080") and ones that vanished. Keyed by (proto, port);
/// owner changes on an existing binding are not reported (the pid set
/// usually churns without anything interesting happening).
pub fn diff_listeners(old: &[Listener], new: &[Listener]) -> Vec<DiffEntry> {
    let key = |l: &Listener| (l.proto.clone(), l.port);
    let old_map: HashMap<(String, u16), &Listener> = old.iter().map(|l| (key(l), l)).collect();
    let new_map: HashMap<(String, u16), &Listener> = new.iter().map(|l| (key(l), l)).collect();
    let mut out = Vec::new();
    for l in new_map.values() {
        if !old_map.contains_key(&key(l)) {
            out.push(DiffEntry {
                kind: "listen-new",
                pid: 0,
                name: format!(":{}/{}", l.port, l.proto),
                detail: format!("port {} now served by {}", l.port, l.who.join(", ")),
            });
        }
    }
    for l in old_map.values() {
        if !new_map.contains_key(&key(l)) {
            out.push(DiffEntry {
                kind: "listen-gone",
                pid: 0,
                name: format!(":{}/{}", l.port, l.proto),
                detail: format!("port {} no longer served (was {})", l.port, l.who.join(", ")),
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
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
            "{:<11} pid {:<7} {}\n    {}\n",
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
        save(path.to_str().unwrap(), &procs, &[]).unwrap();
        let (loaded, listeners) = load(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].pid, 7);
        assert_eq!(loaded[0].name, "a");
        assert!(listeners.is_empty(), "no --sockets → no listeners");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn round_trip_with_listeners() {
        let dir = std::env::temp_dir().join(format!("witr-snaplis-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("snap.json");
        let procs = vec![proc(7, "nginx", None, None, "")];
        let listeners = vec![Listener {
            proto: "tcp".into(),
            port: 80,
            who: vec!["nginx (pid 7)".into()],
        }];
        save(path.to_str().unwrap(), &procs, &listeners).unwrap();
        let (loaded, lis) = load(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded[0].name, "nginx");
        assert_eq!(lis, listeners, "listeners round-trip verbatim");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn v1_bare_array_snapshots_still_load() {
        let dir = std::env::temp_dir().join(format!("witr-snapv1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v1.json");
        std::fs::write(&path, r#"[{"pid":3,"ppid":null,"name":"old","exe":null,"exe_deleted":false,"cmdline":[],"cwd":null,"user":null,"uid":null,"started":null,"env":null,"kernel_thread":false,"cpu":null,"mem_kb":null}]"#).unwrap();
        let (procs, listeners) = load(path.to_str().unwrap()).unwrap();
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].pid, 3);
        assert!(listeners.is_empty(), "v1 snapshots have no listener data");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn to_listeners_keeps_only_listen_rows_and_sorts() {
        let sock = |port: u16, state: &str, pid: Option<i32>| crate::model::Socket {
            proto: "tcp".into(),
            local_addr: "0.0.0.0".into(),
            local_port: port,
            peer_addr: None,
            peer_port: None,
            state: state.into(),
            pid,
        };
        let procs = vec![proc(7, "nginx", None, None, ""), proc(9, "redis", None, None, "")];
        let sockets = vec![
            sock(6379, "LISTEN", Some(9)),
            sock(80, "LISTEN", Some(7)),
            sock(80, "LISTEN", Some(7)),   // duplicate owner → deduped
            sock(5222, "ESTABLISHED", Some(7)), // not a listener
            sock(9999, "LISTEN", None),    // ownerless
        ];
        let l = to_listeners(&sockets, &procs);
        assert_eq!(l.len(), 2, "{l:?}");
        assert_eq!(l[0].port, 80);
        assert_eq!(l[0].who, vec!["nginx (pid 7)".to_string()]);
        assert_eq!(l[1].port, 6379);
        assert_eq!(l[1].who, vec!["redis (pid 9)".to_string()]);
    }

    #[test]
    fn diff_listeners_reports_new_and_gone_ports() {
        let mk = |port: u16, who: &str| Listener {
            proto: "tcp".into(),
            port,
            who: vec![who.into()],
        };
        let old = vec![mk(80, "nginx (pid 7)"), mk(443, "nginx (pid 7)")];
        let now = vec![mk(80, "nginx (pid 9)"), mk(8080, "webpack (pid 20)")];
        let d = diff_listeners(&old, &now);
        let new_e = d.iter().find(|e| e.kind == "listen-new").expect("listen-new");
        assert_eq!(new_e.pid, 0);
        assert_eq!(new_e.name, ":8080/tcp");
        assert!(new_e.detail.contains("8080") && new_e.detail.contains("webpack"));
        let gone_e = d.iter().find(|e| e.kind == "listen-gone").expect("listen-gone");
        assert_eq!(gone_e.name, ":443/tcp");
        // owner churn on an existing binding is NOT reported
        assert!(!d.iter().any(|e| e.name == ":80/tcp"), "{}", render(&d));
    }

    #[test]
    fn no_changes() {
        let ps = vec![proc(1, "init", None, None, "")];
        assert_eq!(render(&diff(&ps, &ps)), "no changes");
    }

    #[test]
    fn auto_snap_rotates_and_resolves_refs() {
        let dir = std::env::temp_dir().join(format!("witr-snapauto-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let home = dir.clone();
        // write 12 snapshots (distinct names — one per second is too slow,
        // so backdate the timestamps by renaming)
        let mut paths = Vec::new();
        for i in 0..12 {
            let p = save_auto_under(&home, &[proc(i, "p", None, None, "")], &[], 10).unwrap();
            let backdated = p.with_file_name(format!(
                "snap-{}.json",
                crate::util::now_unix() - 3600 + i as i64 * 10
            ));
            std::fs::rename(&p, &backdated).unwrap();
            paths.push(backdated);
        }
        let snapshots = auto_dir_under(&home);
        let kept: Vec<_> = std::fs::read_dir(&snapshots)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        assert_eq!(kept.len(), 10, "rotation prunes to --keep");
        assert!(!kept.contains(&paths[0]), "oldest pruned");
        assert!(kept.contains(paths.last().unwrap()), "newest kept");

        // `last` resolves to the newest
        let last = resolve_ref_under(&home, "last").unwrap();
        assert_eq!(last, *paths.last().unwrap());

        // a duration resolves to the newest snapshot at least that old
        let hour_ago = resolve_ref_under(&home, "59m").unwrap();
        assert!(
            paths.iter().take(11).any(|p| *p == hour_ago),
            "59m ref picks an old snapshot, got {}",
            hour_ago.display()
        );

        // a plain path passes through untouched (even when it doesn't exist)
        assert_eq!(
            resolve_ref_under(&home, "/tmp/whatever.json").unwrap(),
            std::path::PathBuf::from("/tmp/whatever.json")
        );
        // bare numbers are paths, not durations
        assert_eq!(resolve_ref_under(&home, "42").unwrap(), std::path::PathBuf::from("42"));
        // an impossible window fails with guidance
        assert!(resolve_ref_under(&home, "1d").is_err(), "nothing is 1d old yet");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn resolve_ref_without_auto_dir_fails_with_guidance() {
        let dir = std::env::temp_dir().join(format!("witr-snapnone-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok();
        let err = resolve_ref_under(&dir, "last").unwrap_err();
        assert!(err.contains("--snap"), "{err}");
        std::fs::remove_dir_all(dir).ok();
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
