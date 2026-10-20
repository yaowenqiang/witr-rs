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
mod serve;
mod snapshot;
mod tui;
mod util;

use clap::Parser as _;
use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::time::Duration;

use model::{Pid, Process, TargetReport, TargetSpec};
use platform::Platform;

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

/// True only on the absent→present edge (the very first tick counts when
/// the target is already up): the `--on-start` twin of `on_exit_edge`.
fn on_start_edge(seen: &mut bool, present: bool) -> bool {
    let fire = present && !*seen;
    *seen = present;
    fire
}

/// Classic edit distance over chars (name suggestions are short — the
/// quadratic table is irrelevant).
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Up to `top` distinct process names closest to a missed name target —
/// the did-you-mean for typos, from the same table the pipeline searched.
fn suggest_names(table: &[Process], query: &str, top: usize) -> Vec<String> {
    let q = query.to_lowercase();
    let mut scored: Vec<(usize, &str)> = table
        .iter()
        .map(|p| (levenshtein(&q, &p.name.to_lowercase()), p.name.as_str()))
        .collect();
    scored.sort_by_key(|(d, _)| *d);
    scored.dedup_by(|a, b| a.1 == b.1);
    scored.into_iter().take(top).map(|(_, n)| n.to_string()).collect()
}

/// Ctrl-C during a headless `--watch`: the default disposition kills the
/// process mid-tick; instead the handler raises a flag the watch loops
/// poll between ticks, so the loop can unwind and print its exit summary.
/// Unix only — Windows console events have no std-level hook (there the
/// summary still comes via `--times`).
static SAW_SIGINT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn sigint_flagged(_sig: i32) {
    SAW_SIGINT.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(unix)]
fn install_sigint_flag() {
    extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    const SIGINT: i32 = 2;
    unsafe {
        signal(SIGINT, sigint_flagged as extern "C" fn(i32) as usize);
    }
}
#[cfg(not(unix))]
fn install_sigint_flag() {}

/// Sleep one watch interval in 100ms slices, aborting early on Ctrl-C.
/// Returns false when SIGINT arrived (the caller should unwind).
fn sleep_interruptible(interval: u64) -> bool {
    let slices = interval.max(1) * 10;
    for _ in 0..slices {
        if SAW_SIGINT.load(std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    !SAW_SIGINT.load(std::sync::atomic::Ordering::SeqCst)
}

/// Best-effort `--on-exit` runner: sh -c on Unix, cmd /C on Windows.
fn run_on_exit(cmd: &str) {
    #[cfg(windows)]
    let _ = std::process::Command::new("cmd").args(["/C", cmd]).status();
    #[cfg(not(windows))]
    let _ = std::process::Command::new("sh").args(["-c", cmd]).status();
}

/// The N highest-ranked processes by one metric, best first. Clones rather
/// than borrows — the count is small and the callers mix owned outputs.
fn top_procs(
    procs: &[Process],
    metric: cli::TopMetric,
    count: usize,
    fds: Option<&std::collections::HashMap<Pid, u64>>,
) -> Vec<Process> {
    let mut ranked: Vec<(f64, &Process)> = procs
        .iter()
        .filter_map(|p| {
            let v = match metric {
                cli::TopMetric::Cpu => p.cpu,
                cli::TopMetric::Mem => p.mem_kb.map(|kb| kb as f64),
                cli::TopMetric::Fd => fds.and_then(|m| m.get(&p.pid)).map(|&n| n as f64),
                cli::TopMetric::Io => {
                    let r = p.io_read_bytes.unwrap_or(0);
                    let w = p.io_write_bytes.unwrap_or(0);
                    (p.io_read_bytes.is_some() || p.io_write_bytes.is_some())
                        .then_some((r + w) as f64)
                }
                // age in seconds — desc order puts the oldest first
                cli::TopMetric::Age => {
                    p.started.map(|t| (util::now_unix().saturating_sub(t)) as f64)
                }
            }?;
            Some((v, p))
        })
        .collect();
    ranked.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    ranked.truncate(count.max(1));
    ranked.into_iter().map(|(_, p)| p.clone()).collect()
}

/// Versioned JSON envelope for whole-table outputs (`--json` listing and
/// `--top --json`): scripts can key off `schema_version` instead of
/// guessing the shape. Bump [`SCHEMA_VERSION`] on breaking field changes.
pub const SCHEMA_VERSION: u32 = 1;

fn json_envelope(procs: &[Process]) -> String {
    let doc = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "generated_at": util::now_unix(),
        "process_count": procs.len(),
        "processes": procs,
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into())
}

/// `--tree --json`: a process nested under its parent (children
/// pid-ascending; orphans and ppid cycles become roots — same rules as the
/// text forest).
#[derive(serde::Serialize)]
struct JsonProcNode<'a> {
    #[serde(flatten)]
    proc: &'a Process,
    children: Vec<JsonProcNode<'a>>,
}

/// The no-target listing as JSON: under `--tree` a nested children forest,
/// otherwise the flat versioned envelope.
fn json_listing_output(procs: &[Process], tree: bool) -> String {
    if !tree {
        return json_envelope(procs);
    }
    let by_pid: std::collections::HashMap<Pid, &Process> =
        procs.iter().map(|p| (p.pid, p)).collect();
    let mut children: std::collections::HashMap<Pid, Vec<&Process>> =
        std::collections::HashMap::new();
    let mut roots: Vec<&Process> = Vec::new();
    for p in procs {
        match p.ppid {
            Some(ppid) if by_pid.contains_key(&ppid) && ppid != p.pid => {
                children.entry(ppid).or_default().push(p);
            }
            _ => roots.push(p),
        }
    }
    fn attach<'a>(
        p: &'a Process,
        children: &std::collections::HashMap<Pid, Vec<&'a Process>>,
    ) -> JsonProcNode<'a> {
        let mut kids: Vec<JsonProcNode> = children
            .get(&p.pid)
            .map(|v| v.iter().map(|c| attach(c, children)).collect())
            .unwrap_or_default();
        kids.sort_by_key(|n| n.proc.pid);
        JsonProcNode { proc: p, children: kids }
    }
    roots.sort_by_key(|p| p.pid);
    let forest: Vec<JsonProcNode> = roots.iter().map(|p| attach(p, &children)).collect();
    let doc = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "generated_at": util::now_unix(),
        "process_count": procs.len(),
        "roots": forest,
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into())
}

/// One `--watch` tick of the threshold-alert machinery — the headless twin
/// of the TUI's alert_picks: sweeps fd/socket counters when armed, advances
/// each pid's per-metric cycle, returns the firings (one per excursion,
/// re-armed when the metric drops back under).
#[allow(clippy::too_many_arguments)]
fn watch_alert_picks(
    platform: &dyn Platform,
    cli: &cli::Cli,
    procs: &[Process],
    hist: &history::History,
    interval: u64,
    state: &mut HashMap<Pid, history::AlertTrack>,
    fd_counts: &mut HashMap<Pid, u64>,
    conn_counts: &mut HashMap<Pid, u64>,
) -> Vec<(Pid, String, String)> {
    let armed = cli.alert_cpu.is_some()
        || cli.alert_mem.is_some()
        || cli.alert_fd.is_some()
        || cli.alert_io.is_some()
        || cli.alert_conn.is_some();
    if !armed {
        return Vec::new();
    }
    if cli.alert_fd.is_some() {
        if let Some(c) = platform.fd_counts() {
            *fd_counts = c;
        }
    }
    if cli.alert_conn.is_some() {
        let socks = platform.list_all_sockets().unwrap_or_default();
        *conn_counts = tui::established_per_pid(&socks);
    }
    let secs = history::ALERT_CYCLES as u64 * interval.max(1);
    let mut out = Vec::new();
    for p in procs {
        let track = state.entry(p.pid).or_default();
        if let Some(limit) = cli.alert_cpu {
            let now = hist.cpu_now.get(&p.pid).copied();
            let over = now.is_some_and(|c| c > limit);
            if history::alert_cycle(&mut track.cpu_streak, &mut track.cpu_firing, over) {
                out.push((
                    p.pid,
                    p.name.clone(),
                    format!("CPU {:.0}% above {limit:.0}% for {secs}s", now.unwrap_or(0.0)),
                ));
            }
        }
        if let Some(limit_mb) = cli.alert_mem {
            let mb = p.mem_kb.map(|kb| kb / 1024);
            let over = mb.is_some_and(|m| m > limit_mb);
            if history::alert_cycle(&mut track.mem_streak, &mut track.mem_firing, over) {
                out.push((
                    p.pid,
                    p.name.clone(),
                    format!("RSS {} MB above {limit_mb} MB for {secs}s", mb.unwrap_or(0)),
                ));
            }
        }
        if let Some(limit) = cli.alert_fd {
            let n = fd_counts.get(&p.pid).copied();
            let over = n.is_some_and(|c| c > limit);
            if history::alert_cycle(&mut track.fd_streak, &mut track.fd_firing, over) {
                out.push((
                    p.pid,
                    p.name.clone(),
                    format!("{} open fds above {limit} for {secs}s", n.unwrap_or(0)),
                ));
            }
        }
        if let Some(limit_mbps) = cli.alert_io {
            let bps = hist.io_rate_of(p.pid).map(|(r, w)| r + w);
            let over = bps.is_some_and(|b| b > limit_mbps * 1024.0 * 1024.0);
            if history::alert_cycle(&mut track.io_streak, &mut track.io_firing, over) {
                out.push((
                    p.pid,
                    p.name.clone(),
                    format!(
                        "I/O {:.1} MB/s above {limit_mbps} MB/s for {secs}s",
                        bps.unwrap_or(0.0) / 1024.0 / 1024.0
                    ),
                ));
            }
        }
        if let Some(limit) = cli.alert_conn {
            let n = conn_counts.get(&p.pid).copied();
            let over = n.is_some_and(|c| c > limit);
            if history::alert_cycle(&mut track.conn_streak, &mut track.conn_firing, over) {
                out.push((
                    p.pid,
                    p.name.clone(),
                    format!(
                        "{} established connection(s) above {limit} for {secs}s",
                        n.unwrap_or(0)
                    ),
                ));
            }
        }
    }
    let seen: std::collections::HashSet<Pid> = procs.iter().map(|p| p.pid).collect();
    state.retain(|pid, _| seen.contains(pid));
    out
}

/// `--record` writer: appends one CSV row per process per --watch tick.
/// The header is written once at creation; rows leave out metrics the
/// platform doesn't report (empty cells), so the file stays loadable.
/// A `.jsonl` path switches formats: one versioned JSON envelope per tick
/// (richer — ppid, state, age ride along — and jq-friendly).
struct RecordWriter {
    file: std::fs::File,
    jsonl: bool,
}

impl RecordWriter {
    fn create(path: &str) -> std::io::Result<Self> {
        let jsonl = path.ends_with(".jsonl");
        let mut f = std::fs::File::create(path)?;
        use std::io::Write as _;
        if !jsonl {
            writeln!(f, "timestamp,pid,user,name,cpu_pct,rss_mb,io_read_bps,io_write_bps")?;
        }
        Ok(RecordWriter { file: f, jsonl })
    }

    fn append(&mut self, procs: &[Process], hist: &history::History) {
        use std::io::Write as _;
        if self.jsonl {
            let rows: Vec<serde_json::Value> = procs
                .iter()
                .map(|p| {
                    let (io_r, io_w) = hist
                        .io_rate_of(p.pid)
                        .unwrap_or((0.0, 0.0));
                    serde_json::json!({
                        "pid": p.pid,
                        "ppid": p.ppid,
                        "user": p.user,
                        "name": p.name,
                        "cpu_pct": hist.cpu_now.get(&p.pid),
                        "rss_mb": p.mem_kb.map(|kb| kb / 1024),
                        "state": p.state,
                        "age_secs": p.started.map(|t| util::now_unix().saturating_sub(t)),
                        "io_read_bps": (p.io_read_bytes.is_some()
                            || p.io_write_bytes.is_some())
                        .then_some(io_r),
                        "io_write_bps": (p.io_read_bytes.is_some()
                            || p.io_write_bytes.is_some())
                        .then_some(io_w),
                    })
                })
                .collect();
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "process_count": rows.len(),
                "processes": rows,
            });
            let _ = writeln!(self.file, "{}", serde_json::to_string(&doc).unwrap_or_default());
            return;
        }
        let ts = util::now_unix();
        for p in procs {
            let cpu = hist
                .cpu_now
                .get(&p.pid)
                .map(|c| format!("{c:.1}"))
                .unwrap_or_default();
            let rss = p.mem_kb.map(|kb| (kb / 1024).to_string()).unwrap_or_default();
            let io = hist
                .io_rate_of(p.pid)
                .map(|(r, w)| (format!("{r:.0}"), format!("{w:.0}")))
                .unwrap_or_default();
            let _ = writeln!(
                self.file,
                "{},{},{},{},{},{},{},{}",
                ts,
                p.pid,
                render::csv_field(p.user.as_deref().unwrap_or("-")),
                render::csv_field(&p.name),
                cpu,
                rss,
                io.0,
                io.1,
            );
        }
    }
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
            cli::Shell::Powershell => CompShell::PowerShell,
        };
        clap_complete::generate(
            comp,
            &mut cli::Cli::command(),
            "witr-rs",
            &mut std::io::stdout(),
        );
        std::process::exit(0);
    }

    // --man: render the roff man page to stdout (or FILE) and exit — like
    // --completions it needs nothing but the CLI definition
    if let Some(dest) = &cli.man {
        use clap::CommandFactory as _;
        let mut page = Vec::new();
        if let Err(e) = clap_mangen::Man::new(cli::Cli::command()).render(&mut page) {
            eprintln!("--man: {e}");
            std::process::exit(5);
        }
        let page = String::from_utf8_lossy(&page).into_owned();
        if dest.is_empty() {
            write_out(&page);
        } else {
            let path = std::path::Path::new(dest);
            if let Some(dir) = path.parent() {
                if !dir.as_os_str().is_empty() {
                    if let Err(e) = std::fs::create_dir_all(dir) {
                        eprintln!("--man {dest}: {e}");
                        std::process::exit(5);
                    }
                }
            }
            if let Err(e) = std::fs::write(path, page) {
                eprintln!("--man {dest}: {e}");
                std::process::exit(5);
            }
            write_out(&format!("man page → {dest}"));
        }
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

    // --events-log records the TUI sampler — or, headless, the plain
    // --watch table loop (no targets); anywhere else it's a no-op
    let no_target_tui = specs.is_empty()
        && std::io::stdout().is_terminal()
        && std::io::stdin().is_terminal()
        && !cli.list
        && cli.watch.is_none()
        && recent_secs.is_none();
    if cli.events_log.is_some()
        && !cli.interactive
        && !no_target_tui
        && !(cli.watch.is_some() && specs.is_empty())
    {
        eprintln!("--events-log records the TUI sampler or a target-less --watch; run without targets (or with -i) on a terminal");
        std::process::exit(4);
    }
    if cli.times.is_some() && cli.watch.is_none() {
        eprintln!("--times bounds a --watch run; add --watch SECONDS");
        std::process::exit(4);
    }
    if cli.quiet && cli.watch.is_none() {
        eprintln!("--quiet suppresses the --watch redraw; add --watch SECONDS");
        std::process::exit(4);
    }
    if cli.on_start.is_some() && cli.watch.is_none() && !cli.follow {
        eprintln!("--on-start fires in watch/follow mode; add --watch or --follow");
        std::process::exit(4);
    }
    if cli.on_start.is_some() && specs.is_empty() {
        eprintln!("--on-start watches a target; give a process name, --pid, --port or --file");
        std::process::exit(4);
    }
    if cli.sockets && cli.snap.is_none() {
        eprintln!("--sockets extends --snap; add --snap [FILE]");
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
    if cli.alert_exec.is_some()
        && cli.alert_cpu.is_none()
        && cli.alert_mem.is_none()
        && cli.alert_fd.is_none()
        && cli.alert_io.is_none()
        && cli.alert_conn.is_none()
    {
        eprintln!(
            "--alert-exec runs with threshold alerts; give --alert-cpu, --alert-mem, --alert-fd, --alert-io or --alert-conn"
        );
        std::process::exit(4);
    }
    if cli.serve.is_some() {
        if !specs.is_empty() || cli.interactive {
            eprintln!("--serve exposes the whole process table; drop the targets or -i");
            std::process::exit(4);
        }
        if cli.watch.is_some() {
            eprintln!("--serve samples on every scrape; drop --watch (the metrics endpoint does the refreshing)");
            std::process::exit(4);
        }
        let serve_clash = cli.top.is_some()
            || cli.csv
            || cli.markdown
            || cli.report_html.is_some()
            || cli.snap.is_some()
            || cli.diff.is_some()
            || cli.record.is_some()
            || cli.events_log.is_some()
            || cli.replay.is_some()
            || cli.since.is_some();
        if serve_clash {
            eprintln!("--serve is a standalone mode; drop the other output/operation flags");
            std::process::exit(4);
        }
    }
    if cli.record.is_some() && cli.watch.is_none() {
        eprintln!("--record samples alongside --watch; add --watch SECONDS");
        std::process::exit(4);
    }
    if cli.record.is_some() && !specs.is_empty() {
        eprintln!("--record records the whole process table under --watch; drop the targets (filter later, e.g. with --recent or in the CSV itself)");
        std::process::exit(4);
    }
    let listing_extras = cli.top.is_some() as u8
        + cli.csv as u8
        + cli.markdown as u8
        + cli.report_html.is_some() as u8;
    if listing_extras > 1 {
        eprintln!("--top, --csv, --markdown and --report-html are separate output modes; use one at a time");
        std::process::exit(4);
    }
    if listing_extras > 0 && !specs.is_empty() {
        eprintln!("--top/--csv/--markdown/--report-html operate on the whole process table; drop the targets");
        std::process::exit(4);
    }
    if (cli.csv || cli.markdown) && (cli.json || cli.tree || cli.short || cli.env || cli.warnings) {
        eprintln!("--csv/--markdown are standalone listing formats; drop --json/--tree/--short/--env/--warnings");
        std::process::exit(4);
    }
    if cli.count.is_some() && cli.top.is_none() {
        eprintln!("--count sizes the --top listing; add --top METRIC");
        std::process::exit(4);
    }
    if cli.watch.is_some() && cli.csv
        || cli.watch.is_some() && cli.markdown
        || cli.watch.is_some() && cli.report_html.is_some()
    {
        eprintln!("--watch refreshes --top rankings; it does not re-emit --csv/--markdown/--report-html");
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
        if cli.snap.is_some() && cli.watch.is_some() {
            eprintln!("--snap writes one snapshot and exits; drop --watch");
            std::process::exit(4);
        }
        if cli.diff.is_some() && cli.sockets {
            eprintln!("--sockets extends --snap (it records the listeners); --diff picks them up from the file");
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
        // --sockets: record LISTEN ports alongside the processes, so a later
        // --diff can report services that appeared or disappeared
        let (listeners, listeners_note) = if cli.sockets {
            let socks = platform.list_sockets().unwrap_or_default();
            let l = snapshot::to_listeners(&socks, &procs);
            (l.clone(), format!(" + {} listeners", l.len()))
        } else {
            (Vec::new(), String::new())
        };
        if let Some(path) = &cli.snap {
            if path.is_empty() {
                // no FILE: the auto-rotate directory under the config dir
                let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
                let Some(home) = home else {
                    eprintln!("--snap needs $HOME for the auto-rotate directory, or give a FILE");
                    std::process::exit(4);
                };
                let keep = cli.keep.unwrap_or(10).max(1);
                match snapshot::save_auto(&home, &procs, &listeners, keep) {
                    Ok(written) => write_out(&format!(
                        "snapshot: {} processes{} → {} (keeping {keep})",
                        procs.len(),
                        listeners_note,
                        written.display()
                    )),
                    Err(e) => {
                        eprintln!("--snap: {e}");
                        std::process::exit(5);
                    }
                }
            } else if let Err(e) = snapshot::save(path, &procs, &listeners) {
                eprintln!("--snap {path}: {e}");
                std::process::exit(5);
            } else {
                write_out(&format!(
                    "snapshot: {} processes{} → {}",
                    procs.len(),
                    listeners_note,
                    path
                ));
            }
            std::process::exit(0);
        }
        let raw_ref = cli.diff.as_deref().unwrap_or_default();
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        let resolved = match &home {
            Some(h) => match snapshot::resolve_ref(h, raw_ref) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("--diff {raw_ref}: {e}");
                    std::process::exit(4);
                }
            },
            None => std::path::PathBuf::from(raw_ref),
        };
        let path = resolved.to_string_lossy().into_owned();
        let (old, old_listeners) = match snapshot::load(&path) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("--diff {path}: {e}");
                std::process::exit(4);
            }
        };
        let mut entries = snapshot::diff(&old, &procs);
        // listener changes only make sense when the snapshot recorded them
        if !old_listeners.is_empty() {
            let now = snapshot::to_listeners(&platform.list_sockets().unwrap_or_default(), &procs);
            entries.extend(snapshot::diff_listeners(&old_listeners, &now));
        }
        if cli.json {
            let count = |k: &str| entries.iter().filter(|e| e.kind == k).count();
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "compared_to": path,
                "summary": {
                    "new": count("new"),
                    "gone": count("gone"),
                    "restarted": count("restarted"),
                    "changed": count("changed"),
                    "listen_new": count("listen-new"),
                    "listen_gone": count("listen-gone"),
                    "total": entries.len(),
                },
                "entries": entries,
            });
            write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
        } else {
            write_out(&format!(
                "diff vs {} · {} new / {} gone / {} restarted / {} changed / {} listen+ / {} listen-",
                path,
                entries.iter().filter(|e| e.kind == "new").count(),
                entries.iter().filter(|e| e.kind == "gone").count(),
                entries.iter().filter(|e| e.kind == "restarted").count(),
                entries.iter().filter(|e| e.kind == "changed").count(),
                entries.iter().filter(|e| e.kind == "listen-new").count(),
                entries.iter().filter(|e| e.kind == "listen-gone").count(),
            ));
            write_out(&snapshot::render(&entries));
        }
        // script-friendly: 0 = no changes, 1 = something changed
        std::process::exit(i32::from(!entries.is_empty()));
    }

    // --serve: Prometheus endpoint — samples the table on every scrape, so
    // it needs no interval of its own; a standalone mode like --snap/--diff
    // (compat rules validated above).
    if let Some(spec) = &cli.serve {
        let addr = serve::parse_addr(spec).unwrap_or_else(|| {
            eprintln!("--serve {spec}: expected [HOST]:PORT or a bare PORT");
            std::process::exit(4);
        });
        let fds_enabled = platform::get().fd_counts().is_some();
        if let Err(e) = serve::run(&addr, fds_enabled) {
            eprintln!("--serve: {e}");
            std::process::exit(5);
        }
        std::process::exit(0);
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
            alert_exec: cli.alert_exec.clone(),
            alert_fd: cli.alert_fd,
            alert_io: cli.alert_io,
            watch: cfg.watch.clone(),
            notes: cfg.notes,
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

    // --top / --csv / --markdown / --report-html: whole-table listings with
    // a different renderer, valid piped or on a terminal (never the TUI).
    if specs.is_empty() && listing_extras > 0 {
        let platform = platform::get();
        // --top --watch: re-rank in place every N seconds (a poor man's top)
        if let (Some(metric), Some(secs)) = (cli.top, cli.watch) {
            let interval = secs.max(1);
            let count = cli.count.unwrap_or(15).max(1);
            let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
            if metric == cli::TopMetric::Fd && platform.fd_counts().is_none() {
                eprintln!("--top fd is not supported on {}", platform.name());
                std::process::exit(4);
            }
            install_sigint_flag();
            let mut ticks: u64 = 0;
            loop {
                let mut listed = match platform.list_processes() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("cannot list processes: {}", e);
                        std::process::exit(5);
                    }
                };
                if metric == cli::TopMetric::Io {
                    platform.enrich_listing(&mut listed);
                }
                gpu::enrich(&mut listed);
                let procs = recent_only(listed);
                let fds = if metric == cli::TopMetric::Fd {
                    platform.fd_counts()
                } else {
                    None
                };
                write_out("\x1b[2J\x1b[1;1H");
                let now = util::fmt_time(util::now_unix());
                write_out(&format!(
                    "witr-rs top {} · every {}s · {} · Ctrl-C to stop",
                    format!("{metric:?}").to_lowercase(),
                    interval,
                    now
                ));
                write_out(&render::render_top(&procs, metric, count, fds.as_ref(), &painter));
                ticks += 1;
                if cli.times.is_some_and(|n| ticks >= n.max(1)) {
                    std::process::exit(0);
                }
                if !sleep_interruptible(interval) {
                    std::process::exit(130);
                }
            }
        }
        let mut procs = match platform.list_processes() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cannot list processes: {}", e);
                std::process::exit(5);
            }
        };
        let fds = if cli.top == Some(cli::TopMetric::Fd) {
            match platform.fd_counts() {
                Some(m) => Some(m),
                None => {
                    eprintln!("--top fd is not supported on {}", platform.name());
                    std::process::exit(4);
                }
            }
        } else {
            None
        };
        if cli.top == Some(cli::TopMetric::Io) {
            platform.enrich_listing(&mut procs);
        }
        gpu::enrich(&mut procs);
        let procs = recent_only(procs);
        if let Some(metric) = cli.top {
            let count = cli.count.unwrap_or(15).max(1);
            let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
            if cli.json {
                let ranked = top_procs(&procs, metric, count, fds.as_ref());
                write_out(&json_envelope(&ranked));
            } else if cli.csv {
                write_out(&render::render_csv(&top_procs(&procs, metric, count, fds.as_ref())));
            } else if cli.markdown {
                write_out(&render::render_markdown(&top_procs(
                    &procs, metric, count, fds.as_ref(),
                )));
            } else {
                write_out(&render::render_top(&procs, metric, count, fds.as_ref(), &painter));
            }
        } else if cli.report_html.is_some() {
            let path = cli.report_html.as_deref().unwrap_or_default();
            if let Err(e) = std::fs::write(path, render::render_html_report(&procs)) {
                eprintln!("--report-html {path}: {e}");
                std::process::exit(5);
            }
            write_out(&format!("report: {} processes → {}", procs.len(), path));
        } else if cli.json {
            // --csv/--markdown wins over plain table; --json alone keeps the
            // versioned envelope shape
            write_out(&json_envelope(&procs));
        } else if cli.csv {
            write_out(&render::render_csv(&procs));
        } else {
            write_out(&render::render_markdown(&procs));
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
                alert_exec: cli.alert_exec.clone(),
                alert_fd: cli.alert_fd,
                alert_io: cli.alert_io,
                watch: cfg.watch.clone(),
                notes: cfg.notes,
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
        // With --record each tick also appends one CSV/JSONL row per
        // process; --events-log records the sampler's events headless;
        // --alert-* turns the loop into a watchdog; --quiet drops the
        // redraw so only alerts/hooks reach the terminal.
        if let Some(secs) = cli.watch {
            let interval = secs.max(1);
            let label = cli.recent.clone().unwrap_or_else(|| "all processes".into());
            let json_stream = cli.json; // one envelope per tick, no redraw
            let redraw = !cli.quiet && !json_stream;
            install_sigint_flag();
            let mut recorder = match &cli.record {
                Some(path) => match RecordWriter::create(path) {
                    Ok(w) => {
                        write_out(&format!("recording per-process samples → {path}"));
                        Some(w)
                    }
                    Err(e) => {
                        eprintln!("--record {path}: {e}");
                        std::process::exit(5);
                    }
                },
                None => None,
            };
            let mut events_file = match &cli.events_log {
                Some(path) => match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    Ok(f) => {
                        write_out(&format!("recording events → {path}"));
                        Some(f)
                    }
                    Err(e) => {
                        eprintln!("--events-log {path}: {e}");
                        std::process::exit(5);
                    }
                },
                None => None,
            };
            let mut hist = history::History::new();
            let mut alert_state: HashMap<Pid, history::AlertTrack> = HashMap::new();
            let mut fd_counts: HashMap<Pid, u64> = HashMap::new();
            let mut conn_counts: HashMap<Pid, u64> = HashMap::new();
            // the most recent firings, repeated under the header so a redraw
            // doesn't erase them from view
            let mut recent_alerts: Vec<String> = Vec::new();
            let mut ticks: u64 = 0;
            let interrupted;
            loop {
                let mut listed = match platform.list_processes() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("cannot list processes: {}", e);
                        std::process::exit(5);
                    }
                };
                // per-process io counters feed the recorded rates and the
                // --alert-io check (a no-op where the platform has none)
                platform.enrich_listing(&mut listed);
                gpu::enrich(&mut listed);
                let procs = recent_only(listed);
                let fresh = hist.update(&procs);
                if let Some(f) = events_file.as_mut() {
                    use std::io::Write as _;
                    for e in &fresh {
                        if let Ok(json) = serde_json::to_string(e) {
                            let _ = writeln!(f, "{json}");
                        }
                    }
                    let _ = f.flush();
                }
                if let Some(w) = recorder.as_mut() {
                    w.append(&procs, &hist);
                }
                for (pid, name, detail) in watch_alert_picks(
                    platform.as_ref(),
                    &cli,
                    &procs,
                    &hist,
                    interval,
                    &mut alert_state,
                    &mut fd_counts,
                    &mut conn_counts,
                ) {
                    // in JSON-stream mode the stdout pipe carries data only —
                    // alerts go to stderr so jq output stays parseable
                    let alert_line = format!("⚠ alert: {name} (pid {pid}) — {detail}");
                    if json_stream {
                        eprintln!("{alert_line}");
                    } else {
                        write_out(&alert_line);
                    }
                    // same durable stream as the TUI: alerts land in
                    // --events-log too, so --replay shows them later
                    if let Some(f) = events_file.as_mut() {
                        use std::io::Write as _;
                        let e = hist.push_alert(pid, &name, &detail);
                        if let Ok(json) = serde_json::to_string(&e) {
                            let _ = writeln!(f, "{json}");
                            let _ = f.flush();
                        }
                    }
                    if let Some(cmd) = &cli.alert_exec {
                        tui::spawn_alert_exec(cmd, pid, &name, &detail);
                    }
                    recent_alerts.push(format!("{name} (pid {pid}) — {detail}"));
                    let excess = recent_alerts.len().saturating_sub(5);
                    recent_alerts.drain(..excess);
                }
                if redraw {
                    write_out("\x1b[2J\x1b[1;1H");
                    let now = util::fmt_time(util::now_unix());
                    write_out(&format!(
                        "witr-rs watch · {} · every {}s · {} · Ctrl-C to stop",
                        label, interval, now
                    ));
                    for a in &recent_alerts {
                        write_out(&format!("⚠ {a}"));
                    }
                    write_out(&render::render_process_table(&procs, &painter));
                } else if json_stream {
                    write_out(&json_listing_output(&procs, cli.tree));
                }
                ticks += 1;
                if cli.times.is_some_and(|n| ticks >= n.max(1)) {
                    interrupted = false;
                    break;
                }
                if !sleep_interruptible(interval) {
                    interrupted = true;
                    break;
                }
            }
            // leaving the loop (Ctrl-C or --times): print the run's digest —
            // what appeared, exited, restarted and spiked while watched
            let summary = hist.summary(u64::MAX);
            if json_stream {
                let doc = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "generated_at": util::now_unix(),
                    "ticks": ticks,
                    "interrupted": interrupted,
                    "summary": summary,
                });
                write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
            } else {
                write_out("");
                write_out(&format!(
                    "== watch summary · {ticks} tick{}{} ==",
                    if ticks == 1 { "" } else { "s" },
                    if interrupted { " · interrupted" } else { "" },
                ));
                write_out(&summary.to_text());
            }
            std::process::exit(i32::from(interrupted) * 130);
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
            render::Format::Json => json_listing_output(&procs, cli.tree),
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
        // --on-start: the mirror — fires on absent→present, including the
        // first tick when the target is already up
        let mut seen_target = false;
        let mut ticks: u64 = 0;
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
            if on_start_edge(&mut seen_target, present) && cli.on_start.is_some() {
                let cmd = cli.on_start.as_deref().unwrap_or_default();
                write_out(&format!("on-start: running `{cmd}`"));
                run_on_exit(cmd);
            }
            ticks += 1;
            if cli.times.is_some_and(|n| ticks >= n.max(1)) {
                std::process::exit(0);
            }
            if !sleep_interruptible(interval) {
                std::process::exit(130);
            }
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

    // not-found nudges (text formats only — machine outputs stay clean):
    // a dead pid is one --follow away; a misspelled name gets its closest
    // real matches from the table
    if reports.iter().any(|r| r.matches.is_empty())
        && matches!(format, render::Format::Standard | render::Format::Tree)
    {
        for pid in &cli.pids {
            let missed = reports.iter().any(|r| {
                r.matches.is_empty()
                    && matches!(&r.target, TargetSpec::Pid { pid: p } if p == pid)
            });
            if missed {
                eprintln!(
                    "hint: pid {pid} not found — did it just exit? `--pid {pid} --follow` keeps tracing the program under its new pid"
                );
            }
        }
        let name_misses: Vec<&String> = cli
            .names
            .iter()
            .filter(|name| {
                reports.iter().any(|r| {
                    r.matches.is_empty()
                        && matches!(&r.target, TargetSpec::Name { pattern, .. } if pattern == *name)
                })
            })
            .collect();
        if !name_misses.is_empty() {
            let table = platform.list_processes().unwrap_or_default();
            for name in name_misses {
                let suggestions = suggest_names(&table, name, 3);
                if !suggestions.is_empty() {
                    eprintln!(
                        "hint: no process matches `{name}` — closest: {}",
                        suggestions.join(", ")
                    );
                }
            }
        }
    }

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

    fn proc(pid: i32, name: &str, cpu: Option<f64>, mem_kb: Option<u64>) -> Process {
        Process {
            pid,
            name: name.into(),
            cpu,
            mem_kb,
            ..Default::default()
        }
    }

    #[test]
    fn top_procs_ranks_and_truncates() {
        let procs = vec![
            proc(1, "a", Some(1.0), Some(1024)),
            proc(2, "b", Some(9.0), Some(8192)),
            proc(3, "c", Some(4.0), Some(4096)),
        ];
        let top = top_procs(&procs, cli::TopMetric::Cpu, 2, None);
        let names: Vec<&str> = top.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["b", "c"]);
        // mem ranking uses the same rows, different key
        let top_mem = top_procs(&procs, cli::TopMetric::Mem, 1, None);
        assert_eq!(top_mem[0].name, "b");
        // fd with no map → nothing
        assert!(top_procs(&procs, cli::TopMetric::Fd, 5, None).is_empty());
    }

    #[test]
    fn json_envelope_carries_schema_version() {
        let procs = vec![proc(7, "nginx", None, None)];
        let v: serde_json::Value =
            serde_json::from_str(&json_envelope(&procs)).unwrap();
        assert_eq!(v["schema_version"], SCHEMA_VERSION);
        assert_eq!(v["process_count"], 1);
        assert_eq!(v["processes"][0]["pid"], 7);
        assert!(v["generated_at"].is_number());
    }

    #[test]
    fn record_writer_writes_header_and_rows() {
        let path = std::env::temp_dir().join(format!("witr-record-{}.csv", std::process::id()));
        let mut w = RecordWriter::create(path.to_str().unwrap()).unwrap();
        let mut hist = history::History::new();
        let procs = vec![proc(3, "worker", None, Some(2048))];
        let _ = hist.update(&procs); // first sample: no cpu/io deltas yet
        w.append(&procs, &hist);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "timestamp,pid,user,name,cpu_pct,rss_mb,io_read_bps,io_write_bps"
        );
        assert_eq!(lines.len(), 2, "one header + one row");
        let row = lines[1];
        // first sample: no cpu/io deltas yet → empty cells; rss 2048 KiB → 2
        let fields: Vec<&str> = row.split(',').collect();
        assert_eq!(fields.len(), 8, "{row}");
        assert_eq!((fields[1], fields[2], fields[3]), ("3", "-", "worker"), "{row}");
        assert_eq!(fields[4], "", "no cpu delta on the first sample: {row}");
        assert_eq!(fields[5], "2", "2048 KiB → 2 MB rss: {row}");
        assert_eq!((fields[6], fields[7]), ("", ""), "no io yet: {row}");
        assert!(fields[0].parse::<u64>().is_ok(), "unix timestamp: {row}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn record_writer_jsonl_appends_versioned_envelopes() {
        let path = std::env::temp_dir().join(format!("witr-record-{}.jsonl", std::process::id()));
        let mut w = RecordWriter::create(path.to_str().unwrap()).unwrap();
        assert!(w.jsonl, "the extension selects the format");
        let mut hist = history::History::new();
        let procs = vec![proc(9, "daemon", None, Some(8192))];
        let _ = hist.update(&procs);
        w.append(&procs, &hist);
        w.append(&procs, &hist);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one envelope per tick, no header");
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["schema_version"], SCHEMA_VERSION, "{line}");
            assert_eq!(v["process_count"], 1);
            assert_eq!(v["processes"][0]["pid"], 9);
            assert_eq!(v["processes"][0]["rss_mb"], 8);
            assert_eq!(v["processes"][0]["ppid"], serde_json::Value::Null);
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn json_listing_tree_nests_children_under_roots() {
        let mut parent = proc(1, "launchd", None, None);
        parent.ppid = Some(1); // self-cycle: still a root
        let mut child = proc(2, "worker", None, None);
        child.ppid = Some(1);
        let mut orphan = proc(3, "stray", None, None);
        orphan.ppid = Some(99); // parent not in the set → root
        let v: serde_json::Value = serde_json::from_str(&json_listing_output(
            &[child.clone(), orphan.clone(), parent.clone()],
            true,
        ))
        .unwrap();
        assert_eq!(v["process_count"], 3);
        let roots = v["roots"].as_array().unwrap();
        assert_eq!(
            roots.iter().map(|r| r["pid"].as_i64()).collect::<Vec<_>>(),
            vec![Some(1), Some(3)],
            "pid-ascending roots, parent stays a root despite the self-cycle"
        );
        assert_eq!(
            roots[0]["children"][0]["pid"].as_i64(),
            Some(2),
            "worker nests under launchd"
        );
        assert!(roots[0]["children"][0]["name"] == "worker");
        // flat mode is the plain envelope, no nesting
        let flat: serde_json::Value =
            serde_json::from_str(&json_listing_output(&procs_of(parent), false)).unwrap();
        assert!(flat["processes"].is_array());
        assert!(flat.get("roots").is_none());
    }

    fn procs_of(p: Process) -> Vec<Process> {
        vec![p]
    }

    struct NoPlatform;

    impl Platform for NoPlatform {
        fn name(&self) -> &'static str {
            "test"
        }
        fn capabilities(&self) -> platform::Capabilities {
            platform::Capabilities { file_lookup: false, env: false }
        }
        fn list_processes(&self) -> platform::PlatResult<Vec<Process>> {
            Ok(Vec::new())
        }
        fn detail(&self, brief: &Process, _want_env: bool) -> Process {
            brief.clone()
        }
        fn port_to_sockets(&self, _port: u16) -> platform::PlatResult<Vec<model::Socket>> {
            Ok(Vec::new())
        }
        fn list_sockets(&self) -> platform::PlatResult<Vec<model::Socket>> {
            Ok(Vec::new())
        }
        fn file_to_pids(&self, _path: &str) -> platform::PlatResult<Vec<i32>> {
            Ok(Vec::new())
        }
        fn container_of(&self, _pid: i32) -> Option<model::Source> {
            None
        }
        fn service_source(&self, _procs: &[Process]) -> Option<model::Source> {
            None
        }
    }

    #[test]
    fn watch_alerts_fire_once_per_excursion() {
        let cli = cli::Cli::parse_from(["witr", "--alert-mem", "10"]);
        let platform = NoPlatform;
        let hist = history::History::new();
        let mut state = HashMap::new();
        let mut fds = HashMap::new();
        let mut conns = HashMap::new();
        let hog = vec![proc(5, "hog", None, Some(20 * 1024))]; // 20 MB
        for _ in 0..history::ALERT_CYCLES - 1 {
            assert!(
                watch_alert_picks(&platform, &cli, &hog, &hist, 1, &mut state, &mut fds, &mut conns)
                    .is_empty(),
                "no fire before the streak completes"
            );
        }
        let fired =
            watch_alert_picks(&platform, &cli, &hog, &hist, 1, &mut state, &mut fds, &mut conns);
        assert_eq!(fired.len(), 1, "{fired:?}");
        assert_eq!(fired[0].0, 5);
        assert!(fired[0].2.contains("20 MB above 10"), "{}", fired[0].2);
        // still over: no re-fire
        assert!(watch_alert_picks(&platform, &cli, &hog, &hist, 1, &mut state, &mut fds, &mut conns)
            .is_empty());
        // one under-tick re-arms; a new streak fires once more
        let quiet = vec![proc(5, "hog", None, Some(1024))];
        watch_alert_picks(&platform, &cli, &quiet, &hist, 1, &mut state, &mut fds, &mut conns);
        let mut again = Vec::new();
        for _ in 0..history::ALERT_CYCLES {
            again = watch_alert_picks(&platform, &cli, &hog, &hist, 1, &mut state, &mut fds, &mut conns);
        }
        assert_eq!(again.len(), 1, "{again:?}");
        // unlisted pids are pruned from the state map
        assert!(state.contains_key(&5));
        assert_eq!(state.len(), 1);
    }
}
