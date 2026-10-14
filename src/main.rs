mod ancestry;
mod binary_id;
mod cli;
mod config;
mod gpu;
mod history;
mod k8s;
mod logs;
mod model;
mod pipeline;
mod platform;
mod render;
mod risk;
mod snapshot;
mod tui;
mod util;

use clap::Parser as _;
use std::io::{IsTerminal, Write};
use std::time::Duration;

use model::{Pid, Process, TargetReport, TargetSpec};

/// Print and ignore write errors — a closed pipe (`| head`) must not panic.
fn write_out(s: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(s.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

/// Exit code for one target, mirroring Go witr: 2 not found, 3 permission
/// wall, 5 internal error, 6 found but nothing could attribute it (never on
/// Windows, where ancestry routinely stops at an exited parent), 1 warnings,
/// 0 clean.
fn target_exit(r: &TargetReport, plat: &str) -> i32 {
    if !r.found {
        if r.permission_denied {
            3
        } else if r.error.as_deref().is_some_and(|e| e.contains("cannot list")) {
            5
        } else {
            2
        }
    } else if r.source.is_none() && plat != "windows" {
        6
    } else if !r.warnings.is_empty() {
        1
    } else {
        0
    }
}

/// Go's exitSeverity: how target exit codes rank against each other for
/// multi-target runs (most severe wins). Cause-unknown (6) ranks below
/// warnings (1) despite its number.
fn severity(code: i32) -> i32 {
    match code {
        0 => 0,
        1 => 1,
        6 => 2,
        2 => 3,
        3 => 4,
        4 => 5,
        _ => 6,
    }
}

fn overall_exit(reports: &[TargetReport], plat: &str) -> i32 {
    reports
        .iter()
        .map(|r| target_exit(r, plat))
        .max_by_key(|c| severity(*c))
        .unwrap_or(0)
}

/// Output format for the target path, from the mode flags.
fn format_for(cli: &cli::Cli) -> render::Format {
    if cli.json {
        render::Format::Json
    } else if cli.env {
        render::Format::EnvOnly
    } else if cli.warnings {
        render::Format::Warnings
    } else if cli.short {
        render::Format::Short
    } else if cli.tree {
        render::Format::Tree
    } else {
        render::Format::Standard
    }
}

/// --follow bookkeeping: the pid currently traced, its program identity
/// (name+exe+user hash, learned from the first successful trace), how
/// many consecutive refreshes the identity has been missing, and the
/// last move note (kept sticky so each re-render shows it).
#[derive(Default)]
struct FollowState {
    pid: Pid,
    identity: Option<u64>,
    missing: u32,
    note: Option<String>,
}

enum FollowStep {
    None,
    /// The identity came back under a new pid (note text explains).
    Moved(Pid, String),
    /// Identity missing for 3 consecutive refreshes — give up.
    Gone,
}

/// One --follow iteration: learn the identity from a successful trace,
/// rescan the process table when the pid vanished, move the spec to the
/// new pid or count down to giving up.
fn follow_step(
    reports: &[TargetReport],
    st: &mut FollowState,
    live_specs: &mut Vec<TargetSpec>,
    platform: &dyn platform::Platform,
) -> FollowStep {
    let Some(r) = reports.first() else { return FollowStep::None };
    if r.found {
        if let Some(m) = r.matches.first() {
            st.pid = m.pid;
            st.identity = Some(snapshot::identity(m));
            st.missing = 0;
        }
        return FollowStep::None;
    }
    // the traced pid is gone this pass
    st.missing += 1;
    let Some(want) = st.identity else { return FollowStep::None };
    let Ok(procs) = platform.list_processes() else { return FollowStep::None };
    // identity matches can be ambiguous when the same program runs in
    // several instances — prefer the most recently started one, which is
    // the restart rather than an older sibling
    let mut best: Option<&Process> = None;
    for p in procs.iter().filter(|p| p.pid != st.pid && snapshot::identity(p) == want) {
        let take = match best {
            None => true,
            Some(b) => match (p.started, b.started) {
                (Some(s), Some(bs)) => s > bs,
                (Some(_), None) => true,
                (None, _) => false,
            },
        };
        if take {
            best = Some(p);
        }
    }
    if let Some(nu) = best {
        let old = st.pid;
        st.pid = nu.pid;
        st.missing = 0;
        st.note = Some(format!(
            "pid {} exited — same program continues as pid {} ({})",
            old, nu.pid, nu.name
        ));
        *live_specs = vec![TargetSpec::Pid { pid: nu.pid }];
        return FollowStep::Moved(old, st.note.clone().unwrap_or_default());
    }
    if st.missing >= 3 {
        return FollowStep::Gone;
    }
    FollowStep::None
}

/// True only on the present→absent edge: armed by the first sighting,
/// fires once per disappearance, re-arms when it comes back.
fn on_exit_edge(had: &mut bool, present: bool) -> bool {
    let fire = *had && !present;
    if present {
        *had = true;
    } else if fire {
        *had = false;
    }
    fire
}

/// Best-effort `--on-exit` runner: sh -c on Unix, cmd /C on Windows.
fn run_on_exit(cmd: &str) {
    #[cfg(windows)]
    let _ = std::process::Command::new("cmd").args(["/C", cmd]).status();
    #[cfg(not(windows))]
    let _ = std::process::Command::new("sh").args(["-c", cmd]).status();
}

fn main() {
    let cli = match cli::Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // invalid input → exit code 4 (matches the witr convention)
            let _ = e.print();
            std::process::exit(4);
        }
    };
    let no_color = cli.no_color || std::env::var_os("NO_COLOR").is_some();

    // user config (flat toml subset): defaults only — CLI flags win
    let cfg = config::Config::load();

    // --completions: emit the shell script and exit (before anything else —
    // it must work everywhere, including without a process table)
    if let Some(shell) = cli.completions {
        use clap::CommandFactory as _;
        use clap_complete::Shell as CompShell;
        let comp = match shell {
            cli::Shell::Bash => CompShell::Bash,
            cli::Shell::Zsh => CompShell::Zsh,
            cli::Shell::Fish => CompShell::Fish,
            cli::Shell::PowerShell => CompShell::PowerShell,
        };
        clap_complete::generate(
            comp,
            &mut cli::Cli::command(),
            "witr-rs",
            &mut std::io::stdout(),
        );
        std::process::exit(0);
    }

    // --recent: parse the window up front and keep it a listing-only filter
    let recent_secs = match &cli.recent {
        Some(raw) => match util::parse_duration(raw) {
            Some(secs) => Some(secs),
            None => {
                eprintln!("invalid --recent duration {:?} (try 30s, 5m, 2h, 1d)", raw);
                std::process::exit(4);
            }
        },
        None => None,
    };
    // --since: session-digest window (replay digest or TUI summary page)
    let since_secs = match &cli.since {
        Some(raw) => match util::parse_duration(raw) {
            Some(secs) => Some(secs as u64),
            None => {
                eprintln!("invalid --since duration {:?} (try 30s, 5m, 2h, 1d)", raw);
                std::process::exit(4);
            }
        },
        None => None,
    };
    if recent_secs.is_some() && cli.interactive {
        eprintln!("--recent filters the static listing; drop --recent or drop -i");
        std::process::exit(4);
    }

    let mut specs: Vec<TargetSpec> = Vec::new();
    for n in &cli.names {
        specs.push(TargetSpec::Name { pattern: n.clone(), exact: cli.exact });
    }
    for pid in &cli.pids {
        specs.push(TargetSpec::Pid { pid: *pid });
    }
    for port in &cli.ports {
        specs.push(TargetSpec::Port { port: *port });
    }
    for f in &cli.files {
        specs.push(TargetSpec::File { path: f.clone() });
    }
    for c in &cli.containers {
        specs.push(TargetSpec::Container { query: c.clone(), exact: cli.exact });
    }
    if recent_secs.is_some() && !specs.is_empty() {
        eprintln!("--recent filters the process listing and cannot be combined with targets");
        std::process::exit(4);
    }
    if cli.follow && !matches!(specs.as_slice(), [TargetSpec::Pid { .. }]) {
        eprintln!("--follow tracks one pid across restarts: use exactly one --pid target");
        std::process::exit(4);
    }

    // --events-log records the TUI sampler; anywhere else it's a no-op
    let no_target_tui = specs.is_empty()
        && std::io::stdout().is_terminal()
        && std::io::stdin().is_terminal()
        && !cli.list
        && cli.watch.is_none()
        && recent_secs.is_none();
    if cli.events_log.is_some() && !cli.interactive && !no_target_tui {
        eprintln!("--events-log records the TUI event sampler; run without targets (or with -i) on a terminal");
        std::process::exit(4);
    }
    if cli.replay.is_some() && !cli.interactive && !specs.is_empty() {
        eprintln!("--replay opens the TUI; drop the targets or use -i");
        std::process::exit(4);
    }
    if since_secs.is_some() && !specs.is_empty() {
        eprintln!("--since digests a recorded events log or sets the TUI summary window; it does not filter targets");
        std::process::exit(4);
    }
    if cli.on_exit.is_some() && cli.watch.is_none() && !cli.follow {
        eprintln!("--on-exit fires in watch/follow mode; add --watch or --follow");
        std::process::exit(4);
    }
    if cli.on_exit.is_some() && specs.is_empty() {
        eprintln!("--on-exit watches a target; give a process name, --pid, --port or --file");
        std::process::exit(4);
    }

    // --replay: load a recorded --events-log JSONL — either to digest it
    // (`--since`, works piped) or to open the TUI on the Events tab (live
    // sampling continues on top of the imported history)
    let replayed = match &cli.replay {
        Some(path) => match history::load_events_log(path) {
            Ok(events) if !events.is_empty() => events,
            Ok(_) => {
                eprintln!("--replay {path}: no valid events found");
                std::process::exit(4);
            }
            Err(e) => {
                eprintln!("--replay {path}: {e}");
                std::process::exit(4);
            }
        },
        None => Vec::new(),
    };
    // --since + --replay without -i: print the recorded-activity digest
    // and exit (no terminal needed — the digest is plain text)
    if let Some(secs) = since_secs {
        if cli.replay.is_some() && !cli.interactive {
            let summary = history::summary_from_events(&replayed, secs);
            write_out(&summary.to_text());
            std::process::exit(0);
        }
    } else if cli.replay.is_some()
        && !cli.interactive
        && !(std::io::stdout().is_terminal() && std::io::stdin().is_terminal())
    {
        eprintln!("--replay opens the TUI; it needs a terminal (or add --since for a piped digest)");
        std::process::exit(4);
    }
    if since_secs.is_some() && cli.replay.is_none() && !cli.interactive {
        let on_tui_terminal =
            std::io::stdout().is_terminal() && std::io::stdin().is_terminal() && specs.is_empty();
        if !on_tui_terminal {
            eprintln!("--since needs --replay FILE for a CLI digest, or the TUI (-i) for the live summary page");
            std::process::exit(4);
        }
    }

    // --snap / --diff: whole-process-table snapshots, listing operations —
    // incompatible with targets and the TUI.
    if cli.snap.is_some() || cli.diff.is_some() {
        if cli.snap.is_some() && cli.diff.is_some() {
            eprintln!("--snap and --diff are separate operations; use one at a time");
            std::process::exit(4);
        }
        if !specs.is_empty() || cli.interactive {
            eprintln!("--snap/--diff snapshot the whole process table; drop the targets or -i");
            std::process::exit(4);
        }
        let platform = platform::get();
        let mut procs = match platform.list_processes() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cannot list processes: {}", e);
                std::process::exit(5);
            }
        };
        gpu::enrich(&mut procs);
        if let Some(path) = &cli.snap {
            if let Err(e) = snapshot::save(path, &procs) {
                eprintln!("--snap {path}: {e}");
                std::process::exit(5);
            }
            write_out(&format!("snapshot: {} processes → {}", procs.len(), path));
            std::process::exit(0);
        }
        let path = cli.diff.as_deref().unwrap_or_default();
        let old = match snapshot::load(path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("--diff {path}: {e}");
                std::process::exit(4);
            }
        };
        let entries = snapshot::diff(&old, &procs);
        if cli.json {
            write_out(&serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".into()));
        } else {
            write_out(&format!(
                "diff vs {} · {} new / {} gone / {} restarted / {} changed",
                path,
                entries.iter().filter(|e| e.kind == "new").count(),
                entries.iter().filter(|e| e.kind == "gone").count(),
                entries.iter().filter(|e| e.kind == "restarted").count(),
                entries.iter().filter(|e| e.kind == "changed").count(),
            ));
            write_out(&snapshot::render(&entries));
        }
        // script-friendly: 0 = no changes, 1 = something changed
        std::process::exit(i32::from(!entries.is_empty()));
    }

    // Keep the recent processes only (listing mode + --watch).
    let recent_only = |procs: Vec<Process>| -> Vec<Process> {
        match recent_secs {
            Some(secs) => {
                let cutoff = util::now_unix() - secs;
                procs.into_iter().filter(|p| p.started.is_some_and(|s| s >= cutoff)).collect()
            }
            None => procs,
        }
    };

    // --interactive: TUI seeded from the targets, terminal required
    // (mirrors the Go witr's -i, exit 4 without a tty)
    if cli.interactive {
        if !(std::io::stdout().is_terminal() && std::io::stdin().is_terminal()) {
            eprintln!(
                "interactive mode needs a terminal; give a target to explain: a process name, --pid, --port, --file or --container"
            );
            std::process::exit(4);
        }
        let seed = tui::Seed {
            events_log: cli.events_log.clone(),
            notify: cli.notify || cfg.notify.unwrap_or(false),
            replayed,
            since: since_secs,
            refresh_secs: cfg.refresh_secs,
            sort: cfg.sort.clone(),
            paused: cfg.paused.unwrap_or(false),
            alert_cpu: cli.alert_cpu,
            alert_mem: cli.alert_mem,
            ..tui::Seed::from_targets(
                &cli.names, &cli.pids, &cli.ports, &cli.files, &cli.containers,
            )
        };
        if let Err(e) = tui::run(seed) {
            eprintln!("tui error: {}", e);
            std::process::exit(5);
        }
        std::process::exit(0);
    }

    // No target: default browse mode — interactive TUI on a terminal
    // (like the Go witr), static listing when piped, with --list/--recent
    // or under --watch.
    if specs.is_empty() {
        let interactive = std::io::stdout().is_terminal()
            && std::io::stdin().is_terminal()
            && !cli.list
            && cli.watch.is_none()
            && recent_secs.is_none();
        if interactive {
            let seed = tui::Seed {
                events_log: cli.events_log.clone(),
                notify: cli.notify || cfg.notify.unwrap_or(false),
                replayed,
                since: since_secs,
                refresh_secs: cfg.refresh_secs,
                sort: cfg.sort.clone(),
                paused: cfg.paused.unwrap_or(false),
                alert_cpu: cli.alert_cpu,
                alert_mem: cli.alert_mem,
                ..tui::Seed::default()
            };
            if let Err(e) = tui::run(seed) {
                eprintln!("tui error: {}", e);
                std::process::exit(5);
            }
            std::process::exit(0);
        }
        let platform = platform::get();
        let format = if cli.json {
            render::Format::Json
        } else if cli.tree && recent_secs.is_none() {
            render::Format::Tree
        } else {
            render::Format::Standard
        };
        let color = !no_color && std::io::stdout().is_terminal() && format != render::Format::Json;
        let painter = render::Painter::new(color);

        // --watch on the listing: re-sample every N seconds until Ctrl-C.
        if let Some(secs) = cli.watch {
            let interval = secs.max(1);
            let label = cli.recent.clone().unwrap_or_else(|| "all processes".into());
            loop {
                let mut listed = match platform.list_processes() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("cannot list processes: {}", e);
                        std::process::exit(5);
                    }
                };
                gpu::enrich(&mut listed);
                let procs = recent_only(listed);
                write_out("\x1b[2J\x1b[1;1H");
                let now = util::fmt_time(util::now_unix());
                write_out(&format!(
                    "witr-rs watch · {} · every {}s · {} · Ctrl-C to stop",
                    label, interval, now
                ));
                let body = match format {
                    render::Format::Json => {
                        serde_json::to_string_pretty(&procs).unwrap_or_else(|_| "[]".into())
                    }
                    _ => render::render_process_table(&procs, &painter),
                };
                write_out(&body);
                std::thread::sleep(Duration::from_secs(interval));
            }
        }

        let procs = match platform.list_processes() {
            Ok(mut p) if !p.is_empty() => {
                gpu::enrich(&mut p);
                recent_only(p)
            }
            Ok(_) => {
                eprintln!("no processes visible to this user");
                std::process::exit(5);
            }
            Err(e) => {
                eprintln!("cannot list processes: {}", e);
                std::process::exit(5);
            }
        };
        if procs.is_empty() && recent_secs.is_some() && !cli.json {
            eprintln!(
                "no processes started within the last {}",
                cli.recent.clone().unwrap_or_default()
            );
            std::process::exit(2);
        }
        let body = match format {
            render::Format::Json => serde_json::to_string_pretty(&procs).unwrap_or_else(|_| "[]".into()),
            render::Format::Tree => render::render_process_forest(&procs, &painter),
            _ => render::render_process_table(&procs, &painter),
        };
        write_out(&body);
        std::process::exit(0);
    }

    let platform = platform::get();
    let want_env = cli.export || cli.env;
    let opts = pipeline::Options {
        want_env,
        deep_files: true,
        deep_binaries: cli.export,
        ..Default::default()
    };

    // --watch with targets: re-run the pipeline and re-render every N
    // seconds until Ctrl-C. With --follow the pid spec is re-acquired
    // across restarts (same name+exe+user identity under a new pid).
    let watch_secs = cli.watch.or_else(|| cli.follow.then_some(2));
    if let Some(secs) = watch_secs {
        let interval = secs.max(1);
        let color = !no_color && std::io::stdout().is_terminal() && !cli.json;
        let mut live_specs = specs.clone();
        let mut follow = FollowState::default();
        // --on-exit: armed once the target has been seen, fires on the
        // present→absent edge, re-arms if it comes back
        let mut had_target = false;
        loop {
            let reports = pipeline::run(platform.as_ref(), live_specs.clone(), &opts);
            write_out("\x1b[2J\x1b[1;1H");
            let now = util::fmt_time(util::now_unix());
            let mode = if cli.follow { " · follow" } else { "" };
            write_out(&format!(
                "witr-rs watch{mode} · every {}s · {} · Ctrl-C to stop",
                interval, now
            ));
            write_out(&render::render(&reports, format_for(&cli), color));
            if cli.follow {
                match follow_step(&reports, &mut follow, &mut live_specs, platform.as_ref()) {
                    FollowStep::None => {}
                    FollowStep::Moved(pid, note) => {
                        write_out(&format!("↻ pid {} — {}", pid, note));
                    }
                    FollowStep::Gone => {
                        write_out("target gone and its program (name+exe+user) not seen again — stopping");
                        if let Some(cmd) = &cli.on_exit {
                            run_on_exit(cmd);
                        }
                        std::process::exit(2);
                    }
                }
                // the ↻ note would be wiped by the next re-render — repeat
                // it under the header so it stays visible
                if let Some(note) = &follow.note {
                    write_out(&format!("↻ following restart: {note}"));
                }
            }
            // --on-exit edge detection (after the follow match, so the
            // final-Gone path above fires it exactly once, then exits)
            let present = reports.iter().any(|r| !r.matches.is_empty());
            if on_exit_edge(&mut had_target, present) && cli.on_exit.is_some() {
                let cmd = cli.on_exit.as_deref().unwrap_or_default();
                write_out(&format!("on-exit: running `{cmd}`"));
                run_on_exit(cmd);
            }
            std::thread::sleep(Duration::from_secs(interval));
        }
    }

    let reports = pipeline::run(platform.as_ref(), specs, &opts);

    // --export: paste-ready diagnostic reports
    if cli.export {
        write_out(&render::render_export(&reports));
        std::process::exit(overall_exit(&reports, platform.name()));
    }

    let format = if cli.json {
        render::Format::Json
    } else if cli.env {
        render::Format::EnvOnly
    } else if cli.warnings {
        render::Format::Warnings
    } else if cli.short {
        render::Format::Short
    } else if cli.tree {
        render::Format::Tree
    } else {
        render::Format::Standard
    };
    let color = !no_color && std::io::stdout().is_terminal() && format != render::Format::Json;

    write_out(&render::render(&reports, format, color));

    // --logs: tail the first match's logs; when the container's process
    // isn't visible on this host (VM-backed runtime), fall back to the
    // runtime-side container view the report carries
    if let Some(n) = cli.logs {
        let resolved = reports.iter().find_map(|r| {
            if let Some(p) = r.matches.first() {
                return Some((logs::LogSource::for_process(p), format!("pid {}", p.pid)));
            }
            r.container.as_ref().map(|c| (
                logs::LogSource::Container { runtime: c.runtime.clone(), ref_: c.id.clone() },
                format!("container {}", c.name),
            ))
        });
        match resolved {
            Some((src, what)) => {
                write_out("");
                write_out(&format!("== recent logs · {} ({what}) ==", src.describe()));
                match logs::fetch(&src, n.max(1) as usize) {
                    Ok(lines) if lines.is_empty() => {
                        write_out("(no log entries found for this process)");
                    }
                    Ok(lines) => {
                        for l in lines {
                            write_out(&l);
                        }
                    }
                    Err(e) => write_out(&format!("⚠ {e}")),
                }
            }
            None => {
                eprintln!("--logs: no matched process to fetch logs for");
                std::process::exit(4);
            }
        }
    }

    // exit codes mirror witr: 0 clean, 1 warnings, 2 not found, 3
    // permission, 4 invalid input (handled above), 5 internal error,
    // 6 cause unknown
    std::process::exit(overall_exit(&reports, platform.name()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_exit_edge_fires_once_per_disappearance() {
        let mut had = false;
        // never seen: no fire even though absent
        assert!(!on_exit_edge(&mut had, false));
        assert!(!on_exit_edge(&mut had, false));
        // first sighting arms (no fire)
        assert!(!on_exit_edge(&mut had, true));
        assert!(!on_exit_edge(&mut had, true));
        // present→absent fires exactly once
        assert!(on_exit_edge(&mut had, false));
        assert!(!on_exit_edge(&mut had, false));
        // comeback re-arms, next disappearance fires again
        assert!(!on_exit_edge(&mut had, true));
        assert!(on_exit_edge(&mut had, false));
    }
}
