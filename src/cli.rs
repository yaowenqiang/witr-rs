use clap::Parser;

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
  witr-rs nginx --tree     full ancestry tree"
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

    /// Trace by open file path (repeatable)
    #[arg(short = 'f', long = "file", value_name = "PATH")]
    pub files: Vec<String>,

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

    /// Collect environment variables (same-user only on Linux)
    #[arg(long = "env")]
    pub env: bool,

    /// Disable colored output
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// Force the static process listing even on a terminal (no args = TUI)
    #[arg(long = "list")]
    pub list: bool,

    /// Plain-text diagnostic report (identity, source, chain, env values,
    /// open files) — combine with any target
    #[arg(long = "export")]
    pub export: bool,
}
