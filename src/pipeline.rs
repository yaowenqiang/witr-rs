use std::collections::{HashMap, HashSet};

use crate::ancestry;
use crate::model::{Container, Pid, Process, Source, TargetReport, TargetSpec};
use crate::platform::{Capabilities, Platform};

pub struct Options {
    pub want_env: bool,
    /// Also collect open files / locks / fd usage per matched process.
    /// Expensive on macOS (one lsof scan per pid), so the TUI only sets it
    /// for the full detail page, never the browse panel.
    pub deep_files: bool,
    /// cap for fuzzy name matches before we warn about truncation
    pub max_name_matches: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options { want_env: false, deep_files: false, max_name_matches: 20 }
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
    let (pids, sockets, container, mut shared_warnings, error, permission) =
        resolve(platform, caps, map, &spec, opts);
    let sockets = sockets.unwrap_or_default();
    if pids.is_empty() {
        // A container target whose main process lives outside this pid
        // namespace still has a story: the runtime-side fallback view.
        if let Some(c) = container {
            let mut report = TargetReport::not_found(
                spec,
                error
                    .unwrap_or_else(|| "the container's main process is not visible on this host".into()),
            );
            report.container = Some(c);
            return vec![report];
        }
        let mut report = TargetReport::not_found(
            spec,
            error.unwrap_or_else(|| "no process matched".into()),
        );
        report.permission_denied = permission;
        return vec![report];
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

        let mut detailed = platform.detail(brief, want_env);
        inspect_risks(&detailed, &sockets, &mut warnings);
        // git context: repo name + branch from the working directory
        if let Some((repo, branch)) = git_info(detailed.cwd.as_deref()) {
            detailed.git_repo = Some(repo);
            detailed.git_branch = branch;
        }
        // Go witr's {forked} tag: spawned by anything other than init
        detailed.forked = detailed.ppid.is_some_and(|pp| pp != 1)
            && !matches!(detailed.name.as_str(), "systemd" | "launchd" | "init");
        // -c target: tag the visible main process with its container line
        if let Some(c) = &container {
            detailed.container = Some(c.format_line());
        }
        let overview = if opts.deep_files {
            Some(platform.file_overview(pid))
        } else {
            None
        };
        let risk = crate::risk::assess(
            &detailed,
            &sockets,
            overview.as_ref().and_then(|o| o.fd_usage),
        );

        let source = detect_source(platform, &chain);
        match &source {
            None => warnings.push("no known supervisor or service manager detected".into()),
            Some(s) => {
                if s.restarts.is_some_and(|n| n > 5) {
                    warnings.push(format!(
                        "{} has restarted {} times",
                        s.label.as_deref().unwrap_or("service"),
                        s.restarts.unwrap()
                    ));
                }
            }
        }
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
            source: source.clone(),
            sockets: sockets.clone(),
            warnings,
            locks: overview.as_ref().map(|o| o.locks.clone()).unwrap_or_default(),
            fd_usage: overview.as_ref().and_then(|o| o.fd_usage),
            open_files: overview.map(|o| o.files),
            risk: Some(risk),
            permission_denied: false,
            container: match &source {
                Some(s) if s.kind == "container" => container.clone(),
                _ => None,
            },
        });
    }
    reports
}

/// Target spec → (pids, port sockets, container fallback, warnings, error,
/// permission wall).
#[allow(clippy::type_complexity)]
fn resolve(
    platform: &dyn Platform,
    caps: Capabilities,
    map: &HashMap<Pid, Process>,
    spec: &TargetSpec,
    opts: &Options,
) -> (
    Vec<Pid>,
    Option<Vec<crate::model::Socket>>,
    Option<Container>,
    Vec<String>,
    Option<String>,
    bool,
) {
    match spec {
        TargetSpec::Pid { pid } => {
            if map.contains_key(pid) {
                (vec![*pid], None, None, Vec::new(), None, false)
            } else {
                (
                    Vec::new(),
                    None,
                    None,
                    Vec::new(),
                    Some(format!("no process with pid {} (already exited, or not visible to this user)", pid)),
                    false,
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
            // Nothing matched by name: ask the service manager whether a
            // unit/label of that name holds a live pid (Go witr's fallback).
            if hits.is_empty() {
                if let Some(pid) = platform.service_pid(pattern) {
                    if map.contains_key(&pid) {
                        return (vec![pid], None, None, Vec::new(), None, false);
                    }
                }
            }
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
            (hits, None, None, warnings, error, false)
        }
        TargetSpec::Port { port } => match platform.port_to_sockets(*port) {
            Ok(sockets) => {
                if sockets.is_empty() {
                    // No host socket: a Docker Desktop / podman machine may
                    // be publishing the port from inside its VM.
                    if let Some(c) = crate::platform::container_by_port(*port) {
                        return (Vec::new(), None, Some(c), Vec::new(), None, false);
                    }
                    return (
                        Vec::new(),
                        None,
                        None,
                        Vec::new(),
                        Some(format!("nothing is using port {} (no tcp/udp socket)", port)),
                        false,
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
                (pids, Some(sockets), None, warnings, error, false)
            }
            Err(crate::platform::PlatError::Permission(m)) => (
                Vec::new(),
                None,
                None,
                Vec::new(),
                Some(format!("port lookup failed: {}", m)),
                true,
            ),
            Err(e) => (Vec::new(), None, None, Vec::new(), Some(format!("port lookup failed: {}", e)), false),
        },
        TargetSpec::File { path } => match platform.file_to_pids(path) {
            Ok(pids) => {
                let error = if pids.is_empty() {
                    Some(format!("no process holds {} open", path))
                } else {
                    None
                };
                (pids, None, None, Vec::new(), error, false)
            }
            Err(crate::platform::PlatError::Permission(m)) => {
                let mut warnings = Vec::new();
                if !caps.file_lookup {
                    warnings.push("file lookup is not supported on this platform".into());
                }
                (Vec::new(), None, None, warnings, Some(format!("file lookup failed: {}", m)), true)
            }
            Err(e) => {
                let mut warnings = Vec::new();
                if !caps.file_lookup {
                    warnings.push("file lookup is not supported on this platform".into());
                }
                (Vec::new(), None, None, warnings, Some(format!("file lookup failed: {}", e)), false)
            }
        },
        TargetSpec::Container { query, exact } => {
            let all = crate::platform::enumerate_containers();
            let matches: Vec<Container> = all
                .into_iter()
                .filter(|c| c.matches_query(query, *exact))
                .collect();
            if matches.is_empty() {
                return (
                    Vec::new(),
                    None,
                    None,
                    Vec::new(),
                    Some(format!("no container found matching \"{}\"", query)),
                    false,
                );
            }
            if matches.len() > 1 {
                let names: Vec<String> = matches
                    .iter()
                    .map(|c| format!("{} ({})", c.name, c.runtime))
                    .collect();
                return (
                    Vec::new(),
                    None,
                    None,
                    Vec::new(),
                    Some(format!(
                        "multiple containers matched ({} results): {} — re-run with -c <name> --exact",
                        matches.len(),
                        names.join(", ")
                    )),
                    false,
                );
            }
            let c = matches.into_iter().next().unwrap();
            // The container's main process may be visible on this host
            // (Linux, or rootless runtimes) — analyze it like any pid.
            if let Some(host_pid) = crate::platform::container_host_pid(&c.runtime, &c.id) {
                if map.contains_key(&host_pid) {
                    return (vec![host_pid], None, Some(c), Vec::new(), None, false);
                }
            }
            // Not visible (Docker Desktop / podman machine / stopped):
            // render the runtime-side view only.
            (
                Vec::new(),
                None,
                Some(c),
                Vec::new(),
                Some("the container's main process is not visible on this host (VM-backed runtime?)".into()),
                false,
            )
        }
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
            if ku == "LD_PRELOAD" && !v.is_empty() {
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

/// Source attribution, Go witr's detection order: platform-specific init
/// systems yield to the more specific context of a container or an ssh /
/// shell session, then supervisors, then cron.
fn detect_source(platform: &dyn Platform, chain: &[Process]) -> Option<Source> {
    if let Some(pid) = chain.last().map(|p| p.pid) {
        if let Some(c) = platform.container_of(pid) {
            return Some(c);
        }
    }
    if let Some(s) = detect_ssh(chain) {
        return Some(s);
    }
    if let Some(s) = detect_shell(chain) {
        return Some(s);
    }
    if let Some(s) = platform.service_source(chain) {
        // service_source implementations return a generic "init" fallback on
        // linux when the process is not a unit — that should not shadow the
        // generic detectors below.
        if s.kind != "init" {
            return Some(s);
        }
    }
    if let Some(s) = detect_supervisor(chain) {
        return Some(s);
    }
    if let Some(s) = detect_cron(chain) {
        return Some(s);
    }
    detect_init(chain)
}

/// An sshd ancestor: a login or remote-exec session. Enriched with the
/// client IP when SSH_* env vars were collected for the target.
fn detect_ssh(chain: &[Process]) -> Option<Source> {
    let sshd = chain.iter().rev().skip(1).find(|p| {
        let n = p.name.to_lowercase();
        n == "sshd" || n == "sshd-session" || n.starts_with("sshd:")
    })?;
    let target = chain.last()?;
    let mut detail = format!("started via an ssh session (sshd pid {})", sshd.pid);
    if let Some(env) = &target.env {
        if let Some((_, v)) = env.iter().find(|(k, _)| k == "SSH_CLIENT" || k == "SSH_CONNECTION") {
            if let Some(ip) = v.split_whitespace().next() {
                let tty = env
                    .iter()
                    .find(|(k, _)| k == "SSH_TTY")
                    .map(|(_, v)| v.trim_start_matches("/dev/").to_string());
                detail = match (&tty, &target.user) {
                    (Some(t), Some(u)) => format!("SSH session from {} ({}@{})", ip, u, t),
                    (Some(t), None) => format!("SSH session from {} ({})", ip, t),
                    (None, _) => format!("SSH session from {}", ip),
                };
            }
        }
    }
    Some(Source {
        kind: "ssh".into(),
        label: Some(sshd.name.clone()),
        detail: Some(detail),
        ..Default::default()
    })
}

/// Interactive shells, user tools and terminal multiplexers — anything that
/// says "a person (or their script) started this".
fn detect_shell(chain: &[Process]) -> Option<Source> {
    for p in chain.iter().rev().skip(1) {
        let base = p.name.to_lowercase();
        if is_shell(&base) || is_user_tool(&base) || base.starts_with("python") || base.starts_with("node") {
            let mut detail = format!("started from a {} shell (pid {})", p.name, p.pid);
            if let Some(mux) = multiplexer_detail(chain) {
                detail = mux;
            }
            return Some(Source {
                kind: "shell".into(),
                label: Some(p.name.clone()),
                detail: Some(detail),
                ..Default::default()
            });
        }
        // A command run directly in a tmux/screen window, with no shell in
        // between, was started by the multiplexer.
        if multiplexer_name(&base).is_some() {
            let detail = multiplexer_detail(chain)
                .unwrap_or_else(|| format!("runs inside a {} session (pid {})", base, p.pid));
            return Some(Source {
                kind: "shell".into(),
                label: Some(p.name.clone()),
                detail: Some(detail),
                ..Default::default()
            });
        }
    }
    None
}

fn is_shell(name: &str) -> bool {
    matches!(
        name,
        "bash" | "zsh" | "sh" | "fish" | "csh" | "tcsh" | "ksh" | "dash" | "ash"
            | "cmd" | "cmd.exe" | "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe"
            | "explorer.exe"
    )
}

fn is_user_tool(name: &str) -> bool {
    // strip .exe/.cmd/.bat/.com for windows-style names
    let n = name
        .strip_suffix(".exe")
        .or_else(|| name.strip_suffix(".cmd"))
        .or_else(|| name.strip_suffix(".bat"))
        .or_else(|| name.strip_suffix(".com"))
        .unwrap_or(name);
    matches!(
        n,
        // runtimes / build tools
        "python3" | "ruby" | "perl" | "php" | "go" | "java" | "cargo" | "npm" | "yarn" | "make"
        // editors / IDEs
        | "code" | "cursor" | "vim" | "nvim" | "emacs" | "nano"
        // terminals
        | "gnome-terminal" | "kitty" | "alacritty" | "wezterm" | "konsole"
    )
}

/// "tmux" / "screen" for the multiplexer's process names ("tmux: server").
fn multiplexer_name(base: &str) -> Option<&'static str> {
    if base == "tmux" || base.starts_with("tmux:") {
        Some("tmux")
    } else if base == "screen" || base.starts_with("screen") || base.starts_with("SCREEN") {
        Some("screen")
    } else {
        None
    }
}

/// Session description for a multiplexer in the chain: name + session when
/// the env was collected (TMUX holds "socket,pid,id"; STY the session name).
fn multiplexer_detail(chain: &[Process]) -> Option<String> {
    let target = chain.last()?;
    for p in chain.iter().rev().skip(1) {
        match multiplexer_name(&p.name.to_lowercase()) {
            Some("tmux") => {
                let mut detail = format!("tmux session (pid {})", p.pid);
                if let Some(env) = &target.env {
                    if let Some((_, v)) = env.iter().find(|(k, _)| k == "TMUX") {
                        let parts: Vec<&str> = v.split(',').collect();
                        if parts.len() == 3 && !parts[0].is_empty() && !parts[2].is_empty() {
                            if let Some(name) = tmux_session_name(parts[0], parts[2]) {
                                detail = format!("tmux session '{}' (pid {})", name, p.pid);
                            }
                        }
                    }
                }
                return Some(detail);
            }
            Some("screen") => {
                let mut detail = format!("screen session (pid {})", p.pid);
                if let Some(env) = &target.env {
                    if let Some((_, v)) = env.iter().find(|(k, _)| k == "STY") {
                        detail = format!("screen session '{}' (pid {})", v, p.pid);
                    }
                }
                return Some(detail);
            }
            _ => {}
        }
    }
    None
}

/// Ask the tmux server on `socket` for the name of session `id`.
fn tmux_session_name(socket: &str, id: &str) -> Option<String> {
    let out = crate::util::run(
        "tmux",
        &["-S", socket, "display-message", "-p", "-t", &format!("${}", id), "#{session_name}"],
        std::time::Duration::from_secs(1),
    )
    .ok()?;
    let name = out.trim().to_string();
    (!name.is_empty()).then_some(name)
}

/// Known process supervisors, from Go witr's knownSupervisors: a daemon
/// manager in the ancestry means "kept alive by X", not "started by a shell".
/// Go walks the ancestry from the root and also matches individual cmdline
/// tokens (so `/entrypoint.sh supervisord -c ...` still attributes).
fn detect_supervisor(chain: &[Process]) -> Option<Source> {
    for p in chain {
        let label = supervisor_label(&p.name)
            .or_else(|| supervisor_from_cmdline(&p.command_line()));
        if let Some(label) = label {
            return Some(Source {
                kind: "supervisor".into(),
                label: Some(label.clone()),
                detail: Some(format!("kept alive by {} (pid {})", label, p.pid)),
                ..Default::default()
            });
        }
    }
    None
}

/// Go witr's matchCmdlineTokens: every whitespace token that isn't a flag or
/// an env assignment, basename-matched against the supervisor table.
fn supervisor_from_cmdline(cmdline: &str) -> Option<String> {
    for tok in cmdline.split_whitespace() {
        if tok.starts_with('-') || tok.contains('=') {
            continue;
        }
        let base = tok.rsplit('/').next().unwrap_or(tok);
        if let Some(label) = supervisor_label(base) {
            return Some(label);
        }
    }
    None
}

fn supervisor_label(name: &str) -> Option<String> {
    let n = name.to_lowercase();
    let label = match n.as_str() {
        "pm2" => "pm2",
        "supervisord" | "supervisor" => "supervisord",
        "gunicorn" => "gunicorn",
        "uwsgi" => "uwsgi",
        "s6-supervise" | "s6" | "s6-svscan" => "s6",
        "runsv" | "runit" | "runit-init" => "runit",
        "openrc" | "openrc-init" => "openrc",
        "monit" => "monit",
        "circusd" | "circus" => "circus",
        "daemontools" => "daemontools",
        "initctl" => "upstart",
        "tini" => "tini",
        "docker-init" => "docker-init",
        "podman-init" => "podman-init",
        "god" => "god",
        "forever" => "forever",
        "nssm" => "nssm",
        _ => return None,
    };
    Some(label.to_string())
}

fn detect_cron(chain: &[Process]) -> Option<Source> {
    for p in chain.iter().rev().skip(1) {
        let n = p.name.as_str();
        if matches!(n, "cron" | "crond" | "anacron") {
            return Some(Source {
                kind: "cron".into(),
                label: Some(n.into()),
                detail: Some(format!("scheduled by {}", n)),
                ..Default::default()
            });
        }
    }
    None
}

/// Catch-all from Go's detectInit: a pid-1 descendant with no shell in the
/// chain between is attributed to init, so kernel/system daemons resolve
/// instead of reading as unsupervised.
fn detect_init(chain: &[Process]) -> Option<Source> {
    let root = chain.first()?;
    if root.pid != 1 {
        return None;
    }
    let inner: &[Process] = if chain.len() > 1 {
        &chain[1..chain.len() - 1]
    } else {
        &[]
    };
    if inner.iter().any(|p| is_shell(&p.name.to_lowercase())) {
        return None;
    }
    Some(Source {
        kind: "init".into(),
        label: Some(if root.name.is_empty() {
            "init".to_string()
        } else {
            root.name.clone()
        }),
        detail: None,
        ..Default::default()
    })
}

/// Repo name + branch for a working directory: walk up looking for `.git`
/// (a dir, or a file pointing at the real gitdir in worktrees/submodules).
fn git_info(cwd: Option<&str>) -> Option<(String, Option<String>)> {
    let mut dir = std::path::PathBuf::from(cwd?);
    for _ in 0..10 {
        let git = dir.join(".git");
        if git.exists() {
            let git_dir = if git.is_dir() {
                git
            } else {
                // "gitdir: <path>" pointer
                let content = std::fs::read_to_string(&git).ok()?;
                let target = content
                    .lines()
                    .find_map(|l| l.strip_prefix("gitdir:"))?
                    .trim()
                    .to_string();
                let p = std::path::PathBuf::from(&target);
                if p.is_absolute() {
                    p
                } else {
                    dir.join(p)
                }
            };
            let repo = dir.file_name().map(|n| n.to_string_lossy().to_string())?;
            let branch = std::fs::read_to_string(git_dir.join("HEAD"))
                .ok()
                .and_then(|head| {
                    head.trim()
                        .strip_prefix("ref: refs/heads/")
                        .map(|b| b.to_string())
                });
            return Some((repo, branch));
        }
        if !dir.pop() {
            return None;
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
        // sshd is checked before shells and multiplexers (Go's order)
        let chain = vec![p(1, "launchd"), p(9, "sshd"), p(20, "zsh"), p(30, "tmux"), p(40, "sleep")];
        let s = detect_ssh(&chain).unwrap();
        assert_eq!(s.kind, "ssh");
        // a bare mux ancestor with no sshd above it wins as shell source
        let chain2 = vec![p(1, "launchd"), p(20, "zsh"), p(30, "tmux"), p(40, "sleep")];
        let s2 = detect_shell(&chain2).unwrap();
        assert_eq!(s2.kind, "shell");
        assert!(s2.detail.as_deref().unwrap().contains("tmux"));
    }

    #[test]
    fn shell_attribution() {
        let chain = vec![p(1, "launchd"), p(20, "zsh"), p(30, "cargo")];
        let s = detect_shell(&chain).unwrap();
        assert_eq!(s.kind, "shell");
        assert_eq!(s.label.as_deref(), Some("zsh"));
    }

    #[test]
    fn cron_attribution() {
        let chain = vec![p(1, "systemd"), p(5, "cron"), p(9, "backup.sh")];
        let s = detect_cron(&chain).unwrap();
        assert_eq!(s.kind, "cron");
    }

    #[test]
    fn none_when_root_child() {
        let chain = vec![p(1, "launchd"), p(50, "WindowServer")];
        assert!(detect_shell(&chain).is_none());
        assert!(detect_ssh(&chain).is_none());
        // init catch-all: pid-1 descendant without a shell in between
        assert_eq!(detect_init(&chain).unwrap().kind, "init");
        // the init system itself
        let solo = vec![p(1, "launchd")];
        assert_eq!(detect_init(&solo).unwrap().label.as_deref(), Some("launchd"));
        // a shell in the chain disqualifies
        let with_shell = vec![p(1, "launchd"), p(9, "zsh"), p(50, "WindowServer")];
        assert!(detect_init(&with_shell).is_none());
        // non-pid-1 root
        let odd = vec![p(44, "containerd"), p(50, "proc")];
        assert!(detect_init(&odd).is_none());
    }

    #[test]
    fn supervisor_attribution() {
        let chain = vec![p(1, "systemd"), p(7, "supervisord"), p(30, "gunicorn")];
        let s = detect_supervisor(&chain).unwrap();
        assert_eq!(s.kind, "supervisor");
        // Go walks the chain from the root: the outermost supervisor wins
        assert_eq!(s.label.as_deref(), Some("supervisord"));
        // the target itself counts (it may BE the supervisor)
        let solo = vec![p(1, "launchd"), p(30, "gunicorn")];
        assert_eq!(
            detect_supervisor(&solo).unwrap().label.as_deref(),
            Some("gunicorn")
        );
        // cmdline tokens attribute entrypoint-style wrappers
        let mut entry = p(9, "entrypoint");
        entry.cmdline = vec!["/entrypoint.sh".into(), "supervisord".into(), "-c".into(), "/etc/supervisor/supervisord.conf".into()];
        let wrapped = vec![entry, p(20, "nginx")];
        assert_eq!(
            detect_supervisor(&wrapped).unwrap().label.as_deref(),
            Some("supervisord")
        );
    }

    #[test]
    fn git_walk_and_branch() {
        let (repo, branch) = git_info(Some(env!("CARGO_MANIFEST_DIR"))).unwrap();
        assert_eq!(repo, "witr-rs");
        assert_eq!(branch.as_deref(), Some("main"));
        assert!(git_info(Some("/")).is_none());
        assert!(git_info(None).is_none());
    }
}
