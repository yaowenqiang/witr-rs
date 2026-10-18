use clap::{Parser, ValueEnum};

/// Shell for `--completions`.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

/// Metric for `--top`.
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq)]
pub enum TopMetric {
    /// Lifetime average CPU percent
    Cpu,
    /// Resident set size
    Mem,
    /// Open descriptor count (Linux cheap; one lsof scan on macOS;
    /// unsupported on Windows)
    Fd,
    /// Cumulative disk I/O bytes (read + write; Linux /proc)
    Io,
}

impl TopMetric {
    pub fn header(&self) -> &'static str {
        match self {
            TopMetric::Cpu => "CPU%",
            TopMetric::Mem => "RSS",
            TopMetric::Fd => "FDS",
            TopMetric::Io => "IO",
        }
    }
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
  witr-rs -i --port 8080   TUI opened on this port
  witr-rs --top cpu        hottest 15 processes, no TUI
  witr-rs --top mem -n 30 --csv   top-30 memory as CSV
  witr-rs --watch 5 --record load.csv   record a csv sample every 5s
  witr-rs --snap           auto snapshot (rotates, keeps 10)
  witr-rs --diff last      what changed since the last auto snapshot
  witr-rs --report-html status.html   self-contained html report"
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

    /// Print the top N processes by this metric instead of a full listing
    /// (default N = 15, override with --count). A no-target operation:
    /// cannot be combined with targets.
    #[arg(long = "top", value_name = "METRIC")]
    pub top: Option<TopMetric>,

    /// Row count for --top (default 15)
    #[arg(short = 'n', long = "count", value_name = "N")]
    pub count: Option<usize>,

    /// Emit the listing / --top rows as CSV (one header row + one row per
    /// process). A no-target format: cannot be combined with targets —
    /// use --json there.
    #[arg(long)]
    pub csv: bool,

    /// Emit the listing / --top rows as a Markdown table (pastes into
    /// issues and PRs). Same rules as --csv.
    #[arg(long)]
    pub markdown: bool,

    /// With --watch (no targets — it records the whole table): append one
    /// CSV row per visible process per refresh tick to this file
    /// (timestamp, pid, user, name, cpu%%, rss_mb, io read/write
    /// bytes-per-second where the platform reports them). Leaves the
    /// console output untouched.
    #[arg(long = "record", value_name = "FILE")]
    pub record: Option<String>,

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

    /// Session digest window (30, 30s, 5m, 2h, 1d): with --replay FILE,
    /// print a "what happened" digest of the recorded events and exit;
    /// with the TUI it sets the 'S' summary-page window.
    #[arg(long = "since", value_name = "DURATION")]
    pub since: Option<String>,

    /// Desktop notifications when a process restarts, or exits repeatedly
    /// (crash loop): macOS osascript / Linux notify-send. TUI only; the
    /// '!' key toggles it live.
    #[arg(long = "notify")]
    pub notify: bool,

    /// Alert when a process exceeds this CPU%% for 5 consecutive samples
    /// (~15s): desktop notification + Events-tab record + red row highlight.
    /// One alert per excursion — re-arms when usage drops back under.
    /// TUI only.
    #[arg(long = "alert-cpu", value_name = "PCT")]
    pub alert_cpu: Option<f64>,

    /// Alert when a process exceeds this RSS in MB for 5 consecutive
    /// samples (~15s) — same behavior as --alert-cpu. TUI only.
    #[arg(long = "alert-mem", value_name = "MB")]
    pub alert_mem: Option<u64>,

    /// Alert when a process exceeds this open-descriptor count for 5
    /// consecutive samples (~15s) — the threshold-alert twin of
    /// --alert-cpu/--alert-mem, for fd leaks. Costs one fd sweep per
    /// refresh (cheap on Linux, one lsof scan on macOS, unsupported on
    /// Windows). TUI only.
    #[arg(long = "alert-fd", value_name = "N")]
    pub alert_fd: Option<u64>,

    /// Alert when a process exceeds this disk-I/O rate in MB/s (read +
    /// write combined) for 5 consecutive samples (~15s). Per-process I/O
    /// counters are a Linux /proc feature — other platforms cannot check.
    /// TUI only.
    #[arg(long = "alert-io", value_name = "MB/S")]
    pub alert_io: Option<f64>,

    /// Run this shell command each time a threshold alert fires (needs
    /// --alert-cpu and/or --alert-mem; one run per excursion). The alert
    /// context is exported as WITR_ALERT_PID / WITR_ALERT_NAME /
    /// WITR_ALERT_DETAIL — e.g. `--alert-exec 'curl -s $SLACK_HOOK -d
    /// "$WITR_ALERT_NAME: $WITR_ALERT_DETAIL"'`. TUI only.
    #[arg(long = "alert-exec", value_name = "CMD")]
    pub alert_exec: Option<String>,

    /// Self-contained HTML report of the current process table (summary
    /// + full table with cpu/mem bars) written to this file and exit.
    /// A no-target operation: cannot be combined with targets.
    #[arg(long = "report-html", value_name = "FILE")]
    pub report_html: Option<String>,

    /// Run this shell command once whenever a watched/followed target
    /// disappears (watch/follow mode only) — e.g. `--on-exit 'say gone'`.
    /// In --follow mode the loop still exits 2 when the program never
    /// comes back under a new pid.
    #[arg(long = "on-exit", value_name = "CMD")]
    pub on_exit: Option<String>,

    /// Write every visible process as JSON and exit — a snapshot to --diff
    /// against later. Without a FILE the snapshot lands in the auto-rotate
    /// directory under the config dir (the 10 most recent are kept) and the
    /// chosen path is printed, so `--snap` / `--diff last` work without
    /// managing files by hand.
    #[arg(
        long = "snap",
        value_name = "FILE",
        num_args = 0..=1,
        default_missing_value = ""
    )]
    pub snap: Option<String>,

    /// Compare the current process table against a --snap file: new /
    /// gone / restarted (same program, new pid) / changed (cmdline).
    /// FILE can also be `last` (the newest auto snapshot) or a duration
    /// (`1h` — the newest snapshot at least that old).
    #[arg(long = "diff", value_name = "FILE|last|DURATION")]
    pub diff: Option<String>,

    /// How many auto snapshots --snap (without a FILE) keeps before
    /// pruning the oldest (default 10)
    #[arg(long = "keep", value_name = "N")]
    pub keep: Option<usize>,

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
