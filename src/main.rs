mod ancestry;
mod cli;
mod model;
mod pipeline;
mod platform;
mod render;
mod tui;
mod util;

use clap::Parser as _;
use std::io::{IsTerminal, Write};

use model::TargetSpec;

/// Print and ignore write errors — a closed pipe (`| head`) must not panic.
fn write_out(s: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(s.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();
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

    // No target: default browse mode — interactive TUI on a terminal
    // (like the Go witr), static listing when piped or with --list.
    if specs.is_empty() {
        let interactive = std::io::stdout().is_terminal()
            && std::io::stdin().is_terminal()
            && !cli.list;
        if interactive {
            if let Err(e) = tui::run() {
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
        let color = !cli.no_color && std::io::stdout().is_terminal() && format != render::Format::Json;
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
    let opts = pipeline::Options { want_env: cli.env, ..Default::default() };
    let reports = pipeline::run(platform.as_ref(), specs, &opts);

    let format = if cli.json {
        render::Format::Json
    } else if cli.short {
        render::Format::Short
    } else if cli.tree {
        render::Format::Tree
    } else {
        render::Format::Standard
    };
    let color = !cli.no_color && std::io::stdout().is_terminal() && format != render::Format::Json;

    write_out(&render::render(&reports, format, color));

    // exit codes mirror witr: 0 clean, 1 warnings, 2 not found,
    // 4 invalid input (handled above), 5 internal error
    let exit = if reports
        .iter()
        .any(|r| !r.found && r.error.as_deref().is_some_and(|e| e.contains("cannot list")))
    {
        5
    } else if reports.iter().any(|r| !r.found) {
        2
    } else if reports.iter().any(|r| !r.warnings.is_empty()) {
        1
    } else {
        0
    };
    std::process::exit(exit);
}
