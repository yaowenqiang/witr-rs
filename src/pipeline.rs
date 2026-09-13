use std::collections::{HashMap, HashSet};

use crate::ancestry;
use crate::model::{Pid, Process, Source, TargetReport, TargetSpec};
use crate::platform::{Capabilities, Platform};

pub struct Options {
    pub want_env: bool,
    /// cap for fuzzy name matches before we warn about truncation
    pub max_name_matches: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options { want_env: false, max_name_matches: 20 }
    }
}

pub fn run(platform: &dyn Platform, specs: Vec<TargetSpec>, opts: &Options) -> Vec<TargetReport> {
    let caps = platform.capabilities();
    let procs = match platform.list_processes() {
        Ok(p) if !p.is_empty() => p,
        Ok(_) => {
            return specs
                .into_iter()
                .map(|t| TargetReport::not_found(t, "no processes visible to this user".into()))
                .collect()
        }
        Err(e) => {
            return specs
                .into_iter()
                .map(|t| TargetReport::not_found(t, format!("cannot list processes: {}", e)))
                .collect()
        }
    };
    let map: HashMap<Pid, Process> = procs.into_iter().map(|p| (p.pid, p)).collect();
    specs
        .into_iter()
        .flat_map(|spec| analyze(platform, caps, &map, spec, opts))
        .collect()
}

/// One spec may resolve to several pids; each pid gets its own report so
/// ancestry/source are never shared between different processes.
fn analyze(
    platform: &dyn Platform,
    caps: Capabilities,
    map: &HashMap<Pid, Process>,
    spec: TargetSpec,
    opts: &Options,
) -> Vec<TargetReport> {
    let (pids, sockets, mut shared_warnings, error) = resolve(platform, caps, map, &spec, opts);
    let sockets = sockets.unwrap_or_default();
    if pids.is_empty() {
        return vec![TargetReport::not_found(
            spec,
            error.unwrap_or_else(|| "no process matched".into()),
        )];
    }

    let mut want_env = opts.want_env;
    if opts.want_env && !caps.env {
        shared_warnings.push(format!(
            "environment variables are not available on {} (platform restriction)",
            platform.name()
        ));
        want_env = false;
    }

    let mut reports = Vec::new();
    for pid in pids {
        let Some(brief) = map.get(&pid) else { continue };
        let anc = ancestry::build_ancestry(map, pid, 64);
        let mut warnings = shared_warnings.clone();
        warnings.extend(anc.warnings);
        let chain = anc.chain;

        let detailed = platform.detail(brief, want_env);
        inspect_risks(&detailed, &sockets, &mut warnings);
        let risk = crate::risk::assess(&detailed, &sockets);

        let source = detect_source(platform, &chain);
        let children = ancestry::direct_children(map, pid);

        // keep first occurrence order, drop duplicates
        let mut seen = HashSet::new();
        warnings.retain(|w| seen.insert(w.clone()));

        reports.push(TargetReport {
            target: spec.clone(),
            found: true,
            error: None,
            matches: vec![detailed],
            ancestry: chain,
            children,
            source,
            sockets: sockets.clone(),
            warnings,
            risk: Some(risk),
        });
    }
    reports
}

/// Target spec → (pids, sockets for port targets, warnings, error message).
#[allow(clippy::type_complexity)]
fn resolve(
    platform: &dyn Platform,
    caps: Capabilities,
    map: &HashMap<Pid, Process>,
    spec: &TargetSpec,
    opts: &Options,
) -> (Vec<Pid>, Option<Vec<crate::model::Socket>>, Vec<String>, Option<String>) {
    match spec {
        TargetSpec::Pid { pid } => {
            if map.contains_key(pid) {
                (vec![*pid], None, Vec::new(), None)
            } else {
                (
                    Vec::new(),
                    None,
                    Vec::new(),
                    Some(format!("no process with pid {} (already exited, or not visible to this user)", pid)),
                )
            }
        }
        TargetSpec::Name { pattern, exact } => {
            let pat = pattern.to_lowercase();
            let mut hits: Vec<Pid> = map
                .values()
                .filter(|p| {
                    if *exact {
                        p.name.eq_ignore_ascii_case(pattern)
                    } else {
                        let name_hit = p.name.to_lowercase().contains(&pat);
                        let exe_hit = p.exe.as_deref().map(|e| e.to_lowercase().contains(&pat)).unwrap_or(false);
                        name_hit || exe_hit
                    }
                })
                .map(|p| p.pid)
                .collect();
            hits.sort();
            let mut warnings = Vec::new();
            if hits.len() > opts.max_name_matches {
                warnings.push(format!(
                    "{} processes match \"{}\"; showing the first {}",
                    hits.len(),
                    pattern,
                    opts.max_name_matches
                ));
                hits.truncate(opts.max_name_matches);
            }
            let error = if hits.is_empty() {
                Some(format!(
                    "no process {} \"{}\"",
                    if *exact { "named" } else { "matching" },
                    pattern
                ))
            } else {
                None
            };
            (hits, None, warnings, error)
        }
        TargetSpec::Port { port } => match platform.port_to_sockets(*port) {
            Ok(sockets) => {
                if sockets.is_empty() {
                    return (
                        Vec::new(),
                        None,
                        Vec::new(),
                        Some(format!("nothing is using port {} (no tcp/udp socket)", port)),
                    );
                }
                let mut pids = Vec::new();
                let mut orphan_sockets = 0usize;
                for s in &sockets {
                    match s.pid {
                        Some(p) => {
                            if !pids.contains(&p) {
                                pids.push(p);
                            }
                        }
                        None => orphan_sockets += 1,
                    }
                }
                let mut warnings = Vec::new();
                if orphan_sockets > 0 {
                    warnings.push(format!(
                        "{} socket(s) on port {} have no owning process visible to this user — run with sudo to see them",
                        orphan_sockets, port
                    ));
                }
                let error = if pids.is_empty() {
                    Some(format!(
                        "port {} is only held by sockets no process owns (kernel/time-wait)",
                        port
                    ))
                } else {
                    None
                };
                (pids, Some(sockets), warnings, error)
            }
            Err(e) => (Vec::new(), None, Vec::new(), Some(format!("port lookup failed: {}", e))),
        },
        TargetSpec::File { path } => match platform.file_to_pids(path) {
            Ok(pids) => {
                let error = if pids.is_empty() {
                    Some(format!("no process holds {} open", path))
                } else {
                    None
                };
                (pids, None, Vec::new(), error)
            }
            Err(e) => {
                let mut warnings = Vec::new();
                if !caps.file_lookup {
                    warnings.push("file lookup is not supported on this platform".into());
                }
                (Vec::new(), None, warnings, Some(format!("file lookup failed: {}", e)))
            }
        },
    }
}

/// Platform-agnostic risk checks over the collected data.
fn inspect_risks(p: &Process, sockets: &[crate::model::Socket], warnings: &mut Vec<String>) {
    if p.uid == Some(0) {
        warnings.push(format!("pid {} runs as root", p.pid));
    }
    if p.exe_deleted {
        warnings.push(format!(
            "the binary of pid {} has been deleted from disk (updated in place?)",
            p.pid
        ));
    }
    if let Some(env) = &p.env {
        for (k, v) in env {
            let ku = k.to_ascii_uppercase();
            if (ku == "LD_PRELOAD" || ku == "DYLD_INSERT_LIBRARIES") && !v.is_empty() {
                warnings.push(format!("pid {} has {}={}", p.pid, k, v));
            }
        }
    }
    for s in sockets {
        if s.pid == Some(p.pid)
            && s.state.eq_ignore_ascii_case("LISTEN")
            && (s.local_addr == "0.0.0.0" || s.local_addr == "::" || s.local_addr == "*")
        {
            warnings.push(format!(
                "pid {} listens on all interfaces ({}:{})",
                p.pid, s.local_addr, s.local_port
            ));
        }
    }
}

fn detect_source(platform: &dyn Platform, chain: &[Process]) -> Option<Source> {
    if let Some(pid) = chain.last().map(|p| p.pid) {
        if let Some(c) = platform.container_of(pid) {
            return Some(c);
        }
    }
    if let Some(s) = platform.service_source(chain) {
        // service_source implementations return a generic "init" fallback on
        // linux when the process is not a unit — that should not shadow the
        // generic detectors below.
        if s.kind != "init" {
            return Some(s);
        }
    }
    generic_source(chain)
}

/// cron / tmux / screen / ssh / shell attribution from ancestor names.
fn generic_source(chain: &[Process]) -> Option<Source> {
    for p in chain.iter().rev().skip(1) {
        let n = p.name.as_str();
        if matches!(n, "cron" | "crond" | "anacron") {
            return Some(Source {
                kind: "cron".into(),
                label: Some(n.into()),
                detail: Some(format!("scheduled by {}", n)),
            });
        }
        if n.starts_with("tmux") {
            return Some(Source {
                kind: "tmux".into(),
                label: Some(n.into()),
                detail: Some(format!("runs inside a tmux session (pid {})", p.pid)),
            });
        }
        if n.starts_with("screen") {
            return Some(Source {
                kind: "screen".into(),
                label: Some(n.into()),
                detail: Some(format!("runs inside a screen session (pid {})", p.pid)),
            });
        }
        if n.starts_with("sshd") {
            return Some(Source {
                kind: "ssh".into(),
                label: Some(n.into()),
                detail: Some(format!("started via an ssh session (sshd pid {})", p.pid)),
            });
        }
    }
    if let Some(parent) = chain.iter().rev().nth(1) {
        const SHELLS: [&str; 10] = [
            "zsh", "bash", "sh", "fish", "dash", "ksh", "tcsh", "pwsh", "powershell", "cmd",
        ];
        if SHELLS.contains(&parent.name.as_str()) {
            return Some(Source {
                kind: "shell".into(),
                label: Some(parent.name.clone()),
                detail: Some(format!(
                    "started from a {} shell (pid {})",
                    parent.name, parent.pid
                )),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: Pid, name: &str) -> Process {
        Process { pid, name: name.into(), ..Default::default() }
    }

    #[test]
    fn chain_attribution() {
        let chain = vec![p(1, "launchd"), p(9, "sshd"), p(20, "zsh"), p(30, "tmux: server"), p(40, "sleep")];
        let s = generic_source(&chain).unwrap();
        // nearest interesting ancestor wins: tmux (closer to target than ssh)
        assert_eq!(s.kind, "tmux");
    }

    #[test]
    fn shell_attribution() {
        let chain = vec![p(1, "launchd"), p(20, "zsh"), p(30, "cargo")];
        let s = generic_source(&chain).unwrap();
        assert_eq!(s.kind, "shell");
        assert_eq!(s.label.as_deref(), Some("zsh"));
    }

    #[test]
    fn cron_attribution() {
        let chain = vec![p(1, "systemd"), p(5, "cron"), p(9, "backup.sh")];
        let s = generic_source(&chain).unwrap();
        assert_eq!(s.kind, "cron");
    }

    #[test]
    fn none_when_root_child() {
        let chain = vec![p(1, "launchd"), p(50, "WindowServer")];
        assert!(generic_source(&chain).is_none());
    }
}
