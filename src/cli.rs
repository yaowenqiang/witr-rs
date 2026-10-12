use clap::{Parser, ValueEnum};

/// Shell for `--completions`.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

/// Why is this running? — trace processes, ports and files back to what
/// started them. A Rust rewrite inspired by pranshuparmar/witr.
#[derive(Parser, Debug)]
#[command(
    name = "witr-rs",
    version,
    after_help = "Examples:
  witr-rs                  list all processes
  witr-rs --tree           full process tree
  witr-rs nginx            why is nginx running?
  witr-rs --pid 1234       inspect one pid
  witr-rs --port 8080      who owns this port?
  witr-rs --file /var/log/x.log   who holds this file open?
  witr-rs -c web           why is container \"web\" running?
  witr-rs nginx --warnings show only the warnings
  witr-rs nginx --env      print the process environment
  witr-rs nginx --tree     full ancestry tree
  witr-rs -i --port 8080   TUI opened on this port"
)]
pub struct Cli {
    /// Process name(s) to trace (substring match; combine with --exact).
    /// With no target at all, witr-rs lists every process.
    pub names: Vec<String>,

    /// Trace by pid (repeatable)
    #[arg(short = 'p', long = "pid", value_name = "PID")]
    pub pids: Vec<i32>,

    /// Trace by local port (repeatable)
    #[arg(long = "port", value_name = "PORT")]
    pub ports: Vec<u16>,

    /// Trace by open file path (repeatable; globs like /var/log/*.log
    /// match every existing file)
    #[arg(short = 'f', long = "file", value_name = "PATH")]
    pub files: Vec<String>,

    /// Trace by container (name, image, id prefix; repeatable)
    #[arg(short = 'c', long = "container", value_name = "QUERY")]
    pub containers: Vec<String>,

    /// Match names exactly instead of by substring
    #[arg(short = 'x', long)]
    pub exact: bool,

    /// Show the ancestry as a tree
    #[arg(short = 't', long)]
    pub tree: bool,

    /// Single-line output per match (for scripts)
    #[arg(short = 's', long)]
    pub short: bool,

    /// Machine-readable JSON
    #[arg(short = 'j', long)]
    pub json: bool,

    /// Show only the collected warnings for the matched process(es)
    #[arg(long = "warnings")]
    pub warnings: bool,

    /// Print the process command and environment variables, nothing else
    #[arg(long = "env")]
    pub env: bool,

    /// Disable colored output (also honors the NO_COLOR environment variable)
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// Force the static process listing even on a terminal (no args = TUI)
    #[arg(long = "list")]
    pub list: bool,

    /// Open the interactive TUI even with targets, seeded from them
    /// (one target per type: name, pid, port, file, container)
    #[arg(short = 'i', long = "interactive")]
    pub interactive: bool,

    /// Plain-text diagnostic report (identity, source, chain, env values,
    /// open files) — combine with any target
    #[arg(long = "export")]
    pub export: bool,

    /// Only list processes started within this window (30, 30s, 5m, 2h,
    /// 1d, 1h30m). Filters the listing; cannot be combined with targets.
    #[arg(long = "recent", value_name = "DURATION")]
    pub recent: Option<String>,

    /// Re-run the current query every N seconds (default 2) until Ctrl-C.
    /// Works with targets, the plain listing and --recent.
    #[arg(
        long = "watch",
        value_name = "SECONDS",
        num_args = 0..=1,
        default_missing_value = "2"
    )]
    pub watch: Option<u64>,

    /// Print the last N log lines (default 100) of the matched process:
    /// container logs when attributed to one, else journald (Linux) or the
    /// unified log (macOS).
    #[arg(
        long = "logs",
        value_name = "N",
        num_args = 0..=1,
        default_missing_value = "100"
    )]
    pub logs: Option<u64>,

    /// Append every TUI event (started/exited/restarted) as JSON lines to
    /// this file — a durable record you can --replay later. TUI only.
    #[arg(long = "events-log", value_name = "FILE")]
    pub events_log: Option<String>,

    /// Open the TUI on the Events tab replaying a recorded --events-log
    /// file; live sampling continues on top of the imported history.
    #[arg(long = "replay", value_name = "FILE")]
    pub replay: Option<String>,

    /// Write every visible process as JSON to this file and exit — a
    /// snapshot to --diff against later.
    #[arg(long = "snap", value_name = "FILE")]
    pub snap: Option<String>,

    /// Compare the current process table against a --snap file: new /
    /// gone / restarted (same program, new pid) / changed (cmdline).
    #[arg(long = "diff", value_name = "FILE")]
    pub diff: Option<String>,

    /// With one --pid target: when the traced pid exits, keep going —
    /// re-acquire the same program (name+exe+user) under its new pid.
    /// Implies --watch; stops once the identity stays gone for 3
    /// consecutive refreshes.
    #[arg(short = 'o', long = "follow")]
    pub follow: bool,

    /// Print the shell completion script for the given shell and exit:
    /// source it from your rc file, e.g.
    /// `witr-rs --completions zsh >> ~/.zshrc`
    #[arg(long = "completions", value_name = "SHELL")]
    pub completions: Option<Shell>,
}
