mod ancestry;
mod cli;
mod history;
mod model;
mod pipeline;
mod platform;
mod render;
mod risk;
mod tui;
mod util;

use clap::Parser as _;
use std::io::{IsTerminal, Write};

use model::{TargetReport, TargetSpec};

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

    // --interactive: TUI seeded from the targets, terminal required
    // (mirrors the Go witr's -i, exit 4 without a tty)
    if cli.interactive {
        if !(std::io::stdout().is_terminal() && std::io::stdin().is_terminal()) {
            eprintln!(
                "interactive mode needs a terminal; give a target to explain: a process name, --pid, --port, --file or --container"
            );
            std::process::exit(4);
        }
        let seed = tui::Seed::from_targets(
            &cli.names, &cli.pids, &cli.ports, &cli.files, &cli.containers,
        );
        if let Err(e) = tui::run(seed) {
            eprintln!("tui error: {}", e);
            std::process::exit(5);
        }
        std::process::exit(0);
    }

    // No target: default browse mode — interactive TUI on a terminal
    // (like the Go witr), static listing when piped or with --list.
    if specs.is_empty() {
        let interactive = std::io::stdout().is_terminal()
            && std::io::stdin().is_terminal()
            && !cli.list;
        if interactive {
            if let Err(e) = tui::run(tui::Seed::default()) {
                eprintln!("tui error: {}", e);
                std::process::exit(5);
            }
            std::process::exit(0);
        }
        let platform = platform::get();
        let procs = match platform.list_processes() {
            Ok(p) if !p.is_empty() => p,
            Ok(_) => {
                eprintln!("no processes visible to this user");
                std::process::exit(5);
            }
            Err(e) => {
                eprintln!("cannot list processes: {}", e);
                std::process::exit(5);
            }
        };
        let format = if cli.json {
            render::Format::Json
        } else if cli.tree {
            render::Format::Tree
        } else {
            render::Format::Standard
        };
        let color = !no_color && std::io::stdout().is_terminal() && format != render::Format::Json;
        let painter = render::Painter::new(color);
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
    let opts = pipeline::Options { want_env, deep_files: true, ..Default::default() };
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

    // exit codes mirror witr: 0 clean, 1 warnings, 2 not found, 3
    // permission, 4 invalid input (handled above), 5 internal error,
    // 6 cause unknown
    std::process::exit(overall_exit(&reports, platform.name()));
}
