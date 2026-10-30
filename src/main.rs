mod ancestry;
mod audit;
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
use std::time::{Duration, Instant};

use cli::Cli;
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

#[cfg(unix)]
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

/// SIGHUP during --watch / the TUI: the classic daemon convention —
/// `kill -HUP <pid>` re-reads the config file between ticks without
/// losing the session (alert latches, history, recordings all stay).
/// The handler only raises a flag; the loops poll it like SIGINT's.
static SAW_SIGHUP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn sighup_flagged(_sig: i32) {
    SAW_SIGHUP.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(unix)]
fn install_sighup_flag() {
    extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    const SIGHUP: i32 = 1;
    unsafe {
        signal(SIGHUP, sighup_flagged as extern "C" fn(i32) as usize);
    }
}
#[cfg(not(unix))]
fn install_sighup_flag() {}

/// Consume the SIGHUP flag — true exactly once per delivered signal.
pub(crate) fn take_sighup() -> bool {
    SAW_SIGHUP.swap(false, std::sync::atomic::Ordering::SeqCst)
}

/// Re-resolve the effective settings: the pre-apply CLI snapshot plus a
/// fresh read of the config file — CLI flags still win over the file on
/// reload, same as at startup.
fn reload_resolved(base: &Cli) -> Cli {
    let mut cli = base.clone();
    cli.apply_config(&config::Config::load());
    cli
}

// ---- --install-service: bake the current flags into a system service ----

/// The headless knobs a service definition carries: the alert set plus
/// watch cadence and the durable outputs. Targets (bare names) ride along
/// too — `witr-rs nginx --watch 3` is a legitimate service.
fn service_flag_args(cli: &Cli) -> Vec<String> {
    fn opt(a: &mut Vec<String>, flag: &str, v: Option<String>) {
        if let Some(v) = v {
            a.push(format!("--{flag}"));
            a.push(v);
        }
    }
    let mut a: Vec<String> = Vec::new();
    if let Some(secs) = cli.watch {
        a.push("--watch".into());
        a.push(secs.max(1).to_string());
    }
    for n in &cli.names {
        a.push(n.clone());
    }
    opt(&mut a, "alert-cpu", cli.alert_cpu.map(|v| v.to_string()));
    opt(&mut a, "alert-mem", cli.alert_mem.map(|v| v.to_string()));
    opt(&mut a, "alert-fd", cli.alert_fd.map(|v| v.to_string()));
    opt(&mut a, "alert-io", cli.alert_io.map(|v| v.to_string()));
    opt(&mut a, "alert-conn", cli.alert_conn.map(|v| v.to_string()));
    opt(&mut a, "alert-load", cli.alert_load.map(|v| v.to_string()));
    opt(&mut a, "alert-mem-pct", cli.alert_mem_pct.map(|v| v.to_string()));
    opt(&mut a, "alert-count", cli.alert_count.map(|v| v.to_string()));
    opt(&mut a, "alert-disk", cli.alert_disk.map(|v| v.to_string()));
    opt(&mut a, "alert-net", cli.alert_net.map(|v| v.to_string()));
    opt(&mut a, "alert-psi", cli.alert_psi.map(|v| v.to_string()));
    opt(
        &mut a,
        "alert-mem-avail-mb",
        cli.alert_mem_avail_mb.map(|v| v.to_string()),
    );
    opt(
        &mut a,
        "alert-swap-pct",
        cli.alert_swap_pct.map(|v| v.to_string()),
    );
    opt(
        &mut a,
        "alert-retrans",
        cli.alert_retrans.map(|v| v.to_string()),
    );
    opt(
        &mut a,
        "alert-nic-drop",
        cli.alert_nic_drop.map(|v| v.to_string()),
    );
    opt(
        &mut a,
        "alert-net-per-proc",
        cli.alert_net_per_proc.map(|v| v.to_string()),
    );
    opt(
        &mut a,
        "alert-deviation",
        cli.alert_deviation.map(|v| v.to_string()),
    );
    opt(&mut a, "alert-repeat", cli.alert_repeat.map(|v| v.to_string()));
    opt(&mut a, "alert-exec", cli.alert_exec.clone());
    opt(&mut a, "alert-webhook", cli.alert_webhook.clone());
    for s in &cli.alert_silence {
        a.push("--alert-silence".into());
        a.push(s.clone());
    }
    for s in &cli.alert_new_proc {
        a.push("--alert-new-proc".into());
        a.push(s.clone());
    }
    for p in &cli.alert_port {
        a.push("--alert-port".into());
        a.push(p.clone());
    }
    opt(&mut a, "events-log", cli.events_log.clone());
    opt(&mut a, "record", cli.record.clone());
    opt(
        &mut a,
        "record-max-mb",
        cli.record_max_mb.map(|v| v.to_string()),
    );
    if cli.quiet {
        a.push("--quiet".into());
    }
    a
}

/// Escape for XML attribute/element text (plist, schtasks).
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn systemd_unit(exe: &str, args: &[String]) -> String {
    // the watchdog only makes sense for a watching service, and its
    // deadline must outlive the ping cadence: the loop pings every tick,
    // so 3× the interval (60s floor) leaves ~2 missed ticks of headroom
    // before systemd pulls the plug
    let interval = args
        .iter()
        .position(|a| a == "--watch")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<u64>().ok())
        .map(|secs| secs.max(1) * 3)
        .unwrap_or(0)
        .max(60);
    let watchdog = if args.contains(&"--watch".to_string()) {
        format!("WatchdogSec={interval}\n")
    } else {
        String::new()
    };
    format!(
        "\
[Unit]
Description=witr-rs process watchdog
After=network-online.target

[Service]
ExecStart={exe} {}
Restart=on-failure
RestartSec=5
{watchdog}
[Install]
WantedBy=default.target
",
        args.join(" ")
    )
}

fn launchd_plist(exe: &str, args: &[String]) -> String {
    let mut s = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n\
         \x20 <key>Label</key><string>com.witr-rs.watchdog</string>\n\
         \x20 <key>ProgramArguments</key>\n  <array>\n",
    );
    for a in std::iter::once(&exe.to_string()).chain(args.iter()) {
        s.push_str(&format!("    <string>{}</string>\n", xml_escape(a)));
    }
    s.push_str(
        "  </array>\n\
         \x20 <key>RunAtLoad</key><true/>\n\
         \x20 <key>KeepAlive</key><true/>\n\
         \x20 <key>StandardOutPath</key><string>/tmp/witr-rs.log</string>\n\
         \x20 <key>StandardErrorPath</key><string>/tmp/witr-rs.err.log</string>\n\
         </dict>\n</plist>\n",
    );
    s
}

fn schtasks_xml(exe: &str, args: &[String]) -> String {
    let cmd = std::iter::once(&exe.to_string())
        .chain(args.iter())
        .map(|a| xml_escape(a))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "\
<?xml version=\"1.0\" encoding=\"UTF-16\"?>
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">
  <Triggers>
    <BootTrigger><Enabled>true</Enabled></BootTrigger>
  </Triggers>
  <Principals>
    <Principal id=\"Author\"><LogonType>LeastPrivilege</LogonType></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT5S</Interval><Count>999</Count></RestartOnFailure>
  </Settings>
  <Actions Context=\"Author\">
    <Exec><Command>{cmd}</Command></Exec>
  </Actions>
</Task>
"
    )
}

/// Where the service definition lands when --install-service gets no path.
fn service_default_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))?;
    let home = std::path::PathBuf::from(home);
    if cfg!(target_os = "macos") {
        Some(home.join("Library/LaunchAgents/com.witr-rs.watchdog.plist"))
    } else if cfg!(target_os = "linux") {
        Some(home.join(".config/systemd/user/witr-rs.service"))
    } else {
        Some(home.join("witr-rs-task.xml"))
    }
}

/// Best-effort registration after the definition file is written. Never
/// fatal: the printed hint is the source of truth when the manager isn't
/// reachable (rootless CI, no systemd session bus…).
fn service_register(path: &std::path::Path) {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        let ok = std::process::Command::new("systemctl")
            .args(["--user", "enable", "--now", "witr-rs.service"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            crate::write_out("registered: systemctl --user enable --now witr-rs.service");
        } else {
            service_register_hint(path);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let ok = std::process::Command::new("launchctl")
            .arg("load")
            .arg(path)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            crate::write_out("registered: launchctl load (starts now, at every login)");
        } else {
            service_register_hint(path);
        }
    }
    #[cfg(target_os = "windows")]
    service_register_hint(path);
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    service_register_hint(path);
}

/// The manual registration command — printed when registration didn't
/// run (custom --install-service path) or didn't succeed.
fn service_register_hint(path: &std::path::Path) {
    if cfg!(target_os = "linux") {
        crate::write_out("register manually: systemctl --user daemon-reload && systemctl --user enable --now witr-rs.service");
    } else if cfg!(target_os = "macos") {
        crate::write_out(&format!(
            "register manually: launchctl load {}",
            path.display()
        ));
    } else {
        crate::write_out(&format!(
            "register manually (admin): schtasks /Create /TN witr-rs /XML \"{}\"",
            path.display()
        ));
    }
}

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

/// --remote core: fetch the process table from a `witr-rs --serve` peer
/// (`/api/ps`) and push it through the same renderers as the local
/// listing — one host's dashboard over plain HTTP, no local sampling.
/// `--tree` is presentation only: the flat table comes over the wire and
/// the forest is built locally, so both sides agree on the shape.
/// `--watch N` re-fetches on an interval until Ctrl-C.
fn remote_mode(base: &str, cli: &cli::Cli, no_color: bool) {
    let url = format!("{}/api/ps", base.trim_end_matches('/'));
    let fetch = || -> Result<Vec<Process>, String> {
        let body = util::http_get(&url)?;
        let doc: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("response is not JSON: {e}"))?;
        let schema = doc.get("schema_version").and_then(|v| v.as_u64());
        let procs: Vec<Process> = serde_json::from_value(
            doc.get("processes")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .map_err(|e| format!("response shape mismatch (schema_version {schema:?}): {e}"))?;
        Ok(procs)
    };
    let render_once = |procs: &[Process]| -> String {
        let color = !no_color && std::io::stdout().is_terminal() && !cli.json;
        let painter = render::Painter::new(color);
        if cli.json {
            json_listing_output(procs, cli.tree)
        } else if cli.csv {
            render::render_csv(procs)
        } else if cli.markdown {
            render::render_markdown(procs)
        } else if cli.tree {
            render::render_process_forest(procs, &painter)
        } else {
            render::render_process_table(procs, &painter)
        }
    };
    if let Some(secs) = cli.watch {
        let interval = secs.max(1);
        let json_stream = cli.json; // one envelope per tick, no redraw
        let redraw = !cli.quiet && !json_stream;
        install_sigint_flag();
        let mut ticks = 0u64;
        loop {
            match fetch() {
                Ok(procs) => {
                    if redraw {
                        write_out("\x1b[2J\x1b[1;1H");
                        let now = util::fmt_time(util::now_unix());
                        write_out(&format!(
                            "witr-rs remote · {base} · every {interval}s · {now} · Ctrl-C to stop"
                        ));
                    }
                    write_out(&render_once(&procs));
                }
                Err(e) => eprintln!("--remote {base}: {e}"),
            }
            ticks += 1;
            if cli.times.is_some_and(|n| ticks >= n.max(1)) {
                break;
            }
            if !sleep_interruptible(interval) {
                break;
            }
        }
        std::process::exit(0);
    }
    match fetch() {
        Ok(procs) => write_out(&render_once(&procs)),
        Err(e) => {
            eprintln!("--remote {base}: {e}");
            std::process::exit(5);
        }
    }
}

/// The N highest-ranked processes by one metric, best first. Clones rather
/// than borrows — the count is small and the callers mix owned outputs.
/// `rates` carries the sampler's per-pid I/O rates (bytes/s) for IoRate.
fn top_procs(
    procs: &[Process],
    metric: cli::TopMetric,
    count: usize,
    fds: Option<&std::collections::HashMap<Pid, u64>>,
    rates: Option<&history::History>,
    conns: Option<&std::collections::HashMap<Pid, u64>>,
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
                cli::TopMetric::IoRate => rates
                    .and_then(|h| h.io_rate_of(p.pid))
                    .map(|(r, w)| r + w),
                // age in seconds — desc order puts the oldest first
                cli::TopMetric::Age => {
                    p.started.map(|t| (util::now_unix().saturating_sub(t)) as f64)
                }
                cli::TopMetric::Gpu => p.gpu_sm_pct.map(|v| v as f64),
                cli::TopMetric::Threads => p.threads.map(|n| n as f64),
                cli::TopMetric::Conn => conns.and_then(|m| m.get(&p.pid)).map(|&n| n as f64),
                cli::TopMetric::Net => rates.and_then(|h| h.net_rate_of(p.pid)),
                cli::TopMetric::GpuMem => p.gpu_mem_mb.map(|mb| mb as f64),
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

/// One `--sys` frame: platform stats + mounts, plus per-NIC rates diffed
/// against the caller's previous sweep (`net_prev` — None only arms; the
/// first frame carries no rates, like the machine page's sparkline).
fn sys_frame(
    platform: &dyn Platform,
    net_prev: &mut Option<(Vec<platform::NicCounters>, Instant)>,
    procs: usize,
) -> render::SysFrame {
    let stats = platform.system_stats().unwrap_or_default();
    let mounts = platform.mount_usage();
    let counters = platform.net_counters();
    let mut nics: Vec<(String, f64, f64)> = Vec::new();
    if let Some((prev, at)) = net_prev.as_ref() {
        let elapsed = at.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            for c in &counters {
                if let Some(p) = prev.iter().find(|p| p.name == c.name) {
                    nics.push((
                        c.name.clone(),
                        c.rx_bytes.saturating_sub(p.rx_bytes) as f64 / elapsed / 1024.0 / 1024.0,
                        c.tx_bytes.saturating_sub(p.tx_bytes) as f64 / elapsed / 1024.0 / 1024.0,
                    ));
                }
            }
            nics.sort_by(|a, b| {
                (b.1 + b.2)
                    .partial_cmp(&(a.1 + a.2))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
    }
    *net_prev = Some((counters, Instant::now()));
    render::SysFrame {
        stats,
        mounts,
        nics,
        procs,
    }
}

pub(crate) fn json_envelope(procs: &[Process]) -> String {
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
    json_tree_forest(procs)
}

/// The nested process forest as a versioned JSON envelope (children under
/// parents, orphans and ppid cycles as roots) — shared by `--tree --json`
/// and the `/api/tree` serve endpoint.
pub(crate) fn json_tree_forest(procs: &[Process]) -> String {
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
/// each pid's per-metric cycle, returns the edges (pid, name, detail,
/// is_recovery) — firings one per excursion, recoveries when a firing
/// excursion drops back under; with --alert-repeat, re-sent about every N
/// seconds while the excursion keeps burning.
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
) -> Vec<(Pid, String, String, bool)> {
    let armed = cli.alert_cpu.is_some()
        || cli.alert_mem.is_some()
        || cli.alert_fd.is_some()
        || cli.alert_io.is_some()
        || cli.alert_conn.is_some()
        || cli.alert_threads.is_some()
        || cli.alert_net_per_proc.is_some()
        || cli.alert_deviation.is_some();
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
    let repeat = cli.alert_repeat;
    let mut out = Vec::new();
    for p in procs {
        let track = state.entry(p.pid).or_default();
        if let Some(limit) = cli.alert_cpu {
            let now = hist.cpu_now.get(&p.pid).copied();
            let over = now.is_some_and(|c| c > limit);
            let edge = history::alert_cycle_repeat(
                &mut track.cpu_streak,
                &mut track.cpu_firing,
                over,
                &mut track.cpu_fired_secs,
                repeat,
                interval,
            );
            if edge == history::AlertEdge::Fire {
                out.push((
                    p.pid,
                    p.name.clone(),
                    format!("CPU {:.0}% above {limit:.0}% for {secs}s", now.unwrap_or(0.0)),
                    false,
                ));
            } else if edge == history::AlertEdge::Recover {
                out.push((p.pid, p.name.clone(), format!("CPU back under {limit:.0}%"), true));
            }
        }
        if let Some(limit_mb) = cli.alert_mem {
            let mb = p.mem_kb.map(|kb| kb / 1024);
            let over = mb.is_some_and(|m| m > limit_mb);
            let edge = history::alert_cycle_repeat(
                &mut track.mem_streak,
                &mut track.mem_firing,
                over,
                &mut track.mem_fired_secs,
                repeat,
                interval,
            );
            if edge == history::AlertEdge::Fire {
                out.push((
                    p.pid,
                    p.name.clone(),
                    format!("RSS {} MB above {limit_mb} MB for {secs}s", mb.unwrap_or(0)),
                    false,
                ));
            } else if edge == history::AlertEdge::Recover {
                out.push((p.pid, p.name.clone(), format!("RSS back under {limit_mb} MB"), true));
            }
        }
        if let Some(limit) = cli.alert_fd {
            let n = fd_counts.get(&p.pid).copied();
            let over = n.is_some_and(|c| c > limit);
            let edge = history::alert_cycle_repeat(
                &mut track.fd_streak,
                &mut track.fd_firing,
                over,
                &mut track.fd_fired_secs,
                repeat,
                interval,
            );
            if edge == history::AlertEdge::Fire {
                out.push((
                    p.pid,
                    p.name.clone(),
                    format!("{} open fds above {limit} for {secs}s", n.unwrap_or(0)),
                    false,
                ));
            } else if edge == history::AlertEdge::Recover {
                out.push((p.pid, p.name.clone(), format!("open fds back under {limit}"), true));
            }
        }
        if let Some(limit_mbps) = cli.alert_io {
            let bps = hist.io_rate_of(p.pid).map(|(r, w)| r + w);
            let over = bps.is_some_and(|b| b > limit_mbps * 1024.0 * 1024.0);
            let edge = history::alert_cycle_repeat(
                &mut track.io_streak,
                &mut track.io_firing,
                over,
                &mut track.io_fired_secs,
                repeat,
                interval,
            );
            if edge == history::AlertEdge::Fire {
                out.push((
                    p.pid,
                    p.name.clone(),
                    format!(
                        "I/O {:.1} MB/s above {limit_mbps} MB/s for {secs}s",
                        bps.unwrap_or(0.0) / 1024.0 / 1024.0
                    ),
                    false,
                ));
            } else if edge == history::AlertEdge::Recover {
                out.push((p.pid, p.name.clone(), format!("I/O back under {limit_mbps} MB/s"), true));
            }
        }
        if let Some(limit) = cli.alert_conn {
            let n = conn_counts.get(&p.pid).copied();
            let over = n.is_some_and(|c| c > limit);
            let edge = history::alert_cycle_repeat(
                &mut track.conn_streak,
                &mut track.conn_firing,
                over,
                &mut track.conn_fired_secs,
                repeat,
                interval,
            );
            if edge == history::AlertEdge::Fire {
                out.push((
                    p.pid,
                    p.name.clone(),
                    format!(
                        "{} established connection(s) above {limit} for {secs}s",
                        n.unwrap_or(0)
                    ),
                    false,
                ));
            } else if edge == history::AlertEdge::Recover {
                out.push((p.pid, p.name.clone(), format!("connections back under {limit}"), true));
            }
        }
        if let Some(limit) = cli.alert_threads {
            let n = p.threads.map(|t| t as u64);
            let over = n.is_some_and(|c| c > limit);
            let edge = history::alert_cycle_repeat(
                &mut track.threads_streak,
                &mut track.threads_firing,
                over,
                &mut track.threads_fired_secs,
                repeat,
                interval,
            );
            if edge == history::AlertEdge::Fire {
                out.push((
                    p.pid,
                    p.name.clone(),
                    format!("{} thread(s) above {limit} for {secs}s", n.unwrap_or(0)),
                    false,
                ));
            } else if edge == history::AlertEdge::Recover {
                out.push((p.pid, p.name.clone(), format!("threads back under {limit}"), true));
            }
        }
        if let Some(limit) = cli.alert_net_per_proc {
            let rate = hist.net_rate_of(p.pid);
            let over = rate.is_some_and(|r| r > (limit as f64) * 1024.0 * 1024.0);
            let edge = history::alert_cycle_repeat(
                &mut track.net_streak,
                &mut track.net_firing,
                over,
                &mut track.net_fired_secs,
                repeat,
                interval,
            );
            if edge == history::AlertEdge::Fire {
                let mbps = rate.unwrap_or(0.0) / 1024.0 / 1024.0;
                out.push((
                    p.pid,
                    p.name.clone(),
                    format!("{mbps:.1} MB/s above {limit} MB/s for {secs}s"),
                    false,
                ));
            } else if edge == history::AlertEdge::Recover {
                out.push((p.pid, p.name.clone(), format!("net back under {limit} MB/s"), true));
            }
        }
        if let Some(factor) = cli.alert_deviation {
            let msg = hist.deviation_of(p.pid, factor);
            let over = msg.is_some();
            let edge = history::alert_cycle_repeat(
                &mut track.dev_streak,
                &mut track.dev_firing,
                over,
                &mut track.dev_fired_secs,
                repeat,
                interval,
            );
            if edge == history::AlertEdge::Fire {
                out.push((
                    p.pid,
                    p.name.clone(),
                    msg.unwrap_or_else(|| "deviated from its own baseline".into()),
                    false,
                ));
            } else if edge == history::AlertEdge::Recover {
                out.push((p.pid, p.name.clone(), "back near its own baseline".to_string(), true));
            }
        }
    }
    let seen: std::collections::HashSet<Pid> = procs.iter().map(|p| p.pid).collect();
    state.retain(|pid, _| seen.contains(pid));
    out
}

/// Parse one `--alert-port` value: `8080` (alert when a listener appears)
/// or `!8080` (alert when a listener that was up disappears).
fn parse_alert_port(raw: &str) -> Option<(u16, bool)> {
    let (negate, rest) = match raw.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, raw),
    };
    rest.parse::<u16>().ok().map(|port| (port, negate))
}

/// One `--watch` tick of the `--alert-port` canary: compares each armed
/// port's LISTEN presence against the previous tick. The first observation
/// only arms — a port already in whatever state at startup is the status
/// quo, not an event (mirrors `--on-exit`/`--on-start` edge semantics).
/// Returns (owner_pid_or_0, name, detail) firings; `owner` remembers the
/// last-known listener label so the "gone" message can say what vanished.
pub(crate) fn port_alert_picks(
    armed: &[(u16, bool)],
    socks: &[model::Socket],
    procs: &[Process],
    seen: &mut HashMap<u16, bool>,
    owner: &mut HashMap<u16, String>,
) -> Vec<(Pid, String, String)> {
    if armed.is_empty() {
        return Vec::new();
    }
    let listeners = snapshot::to_listeners(socks, procs);
    let mut out = Vec::new();
    for &(port, negate) in armed {
        let hit = listeners.iter().find(|l| l.port == port);
        let now_present = hit.is_some();
        let who = hit.map(|l| l.who.join(", ")).unwrap_or_default();
        // "name (pid N)" → the pid, for the event record
        let pid = hit
            .and_then(|l| l.who.first())
            .and_then(|w| w.split("(pid ").nth(1))
            .and_then(|rest| rest.split(')').next())
            .and_then(|num| num.parse::<Pid>().ok())
            .unwrap_or(0);
        match seen.get(&port) {
            None => {
                seen.insert(port, now_present);
                if now_present {
                    owner.insert(port, who);
                }
            }
            Some(&prev) => {
                seen.insert(port, now_present);
                match (now_present, prev) {
                    (true, false) => {
                        // remember the owner even on a negated arm — the
                        // "gone" report should name what was listening
                        owner.insert(port, who.clone());
                        if !negate {
                            out.push((
                                pid,
                                format!(":{port}"),
                                format!("listener appeared on :{port} ({who})"),
                            ));
                        }
                    }
                    (false, true) if negate => {
                        let was = owner.get(&port).map(String::as_str).unwrap_or("?");
                        out.push((
                            0,
                            format!(":{port}"),
                            format!("listener gone from :{port} (was {was})"),
                        ));
                    }
                    _ => {}
                }
            }
        }
    }
    out
}

/// `--record` writer: appends one CSV row per process per --watch tick.
/// The header is written once at creation; rows leave out metrics the
/// platform doesn't report (empty cells), so the file stays loadable.
/// A `.jsonl` path switches formats: one versioned JSON envelope per tick
/// (richer — ppid, state, age ride along — and jq-friendly).
/// Every tick also carries a machine-level sample: a `_system` row in CSV
/// (dedicated `sys_*` columns) or a `system` key in the JSONL envelope.
/// --events-log with long-run hygiene: the same rotation cap as
/// --record. Append-mode (an explicit `--events-log ev.jsonl` never
/// loses prior sessions' lines), rotated to `<path>.1` once the cap
/// passes — a months-long watchdog's disk use stays bounded.
struct EventLog {
    path: std::path::PathBuf,
    file: Option<std::fs::File>,
    cap_bytes: Option<u64>,
    written: u64,
}

impl EventLog {
    fn create(path: &str, cap_mb: Option<u64>) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(EventLog {
            path: path.into(),
            file: Some(file),
            cap_bytes: cap_mb.map(|mb| mb.saturating_mul(1024 * 1024)),
            written,
        })
    }

    /// Serialize one event to JSONL; serialization failure stays silent,
    /// like every other events-log writer.
    fn log_json<T: serde::Serialize>(&mut self, value: &T) {
        let Ok(json) = serde_json::to_string(value) else {
            return;
        };
        self.log_str(&json);
    }

    fn log_str(&mut self, json: &str) {
        use std::io::Write as _;
        if self.cap_bytes.is_some_and(|cap| self.written >= cap) {
            self.file = None; // close before the rename (Windows can't rename open files)
            let rotated = self.path.with_file_name(format!(
                "{}.1",
                self.path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("events")
            ));
            let _ = std::fs::remove_file(&rotated);
            let _ = std::fs::rename(&self.path, &rotated);
            match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
            {
                Ok(f) => {
                    self.file = Some(f);
                    self.written = 0;
                }
                Err(e) => {
                    eprintln!(
                        "--events-log rotate {}: {e} — event logging stops here",
                        self.path.display()
                    );
                }
            }
        }
        let Some(f) = self.file.as_mut() else {
            return;
        };
        if writeln!(f, "{json}").is_ok() {
            self.written += json.len() as u64 + 1;
        }
        let _ = f.flush();
    }
}

struct RecordWriter {
    file: Option<std::fs::File>,
    jsonl: bool,
    path: std::path::PathBuf,
    cap_bytes: Option<u64>,
    written: u64,
}

impl RecordWriter {
    #[cfg(test)] // production goes through create_with_cap (--record-max-mb)
    fn create(path: &str) -> std::io::Result<Self> {
        Self::create_with_cap(path, None)
    }

    /// `cap_bytes` (from --record-max-mb) rotates the file to `<path>.1`
    /// once it passes the cap — the previous .1 is dropped, so disk stays
    /// bounded at twice the cap however long the watchdog runs.
    fn create_with_cap(path: &str, cap_bytes: Option<u64>) -> std::io::Result<Self> {
        let jsonl = path.ends_with(".jsonl");
        let (f, written) = Self::reopen(std::path::Path::new(path), jsonl)?;
        Ok(RecordWriter {
            file: Some(f),
            jsonl,
            path: path.into(),
            cap_bytes,
            written,
        })
    }

    /// Pass the cap: close, drop the old .1, rename current → .1, reopen
    /// fresh (the CSV header rewrites — the rotation must leave a file
    /// --plot/--samples can read without special cases). A failed reopen
    /// leaves `file` None and recording quietly stops (one stderr note).
    fn rotate_if_over_cap(&mut self) {
        if !self.cap_bytes.is_some_and(|cap| self.written >= cap) {
            return;
        }
        self.file = None; // close before the rename (Windows can't rename open files)
        let rotated = self.path.with_file_name(format!(
            "{}.1",
            self.path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("record")
        ));
        let _ = std::fs::remove_file(&rotated);
        let _ = std::fs::rename(&self.path, &rotated);
        match Self::reopen(&self.path, self.jsonl) {
            Ok((f, written)) => {
                self.file = Some(f);
                self.written = written;
            }
            Err(e) => {
                eprintln!(
                    "--record rotate {}: {e} — recording stops here",
                    self.path.display()
                );
            }
        }
    }

    /// Fresh file + the CSV header when the mode needs one; the byte count
    /// the cap diffs against.
    fn reopen(path: &std::path::Path, jsonl: bool) -> std::io::Result<(std::fs::File, u64)> {
        use std::io::Write as _;
        let mut f = std::fs::File::create(path)?;
        let mut written = 0u64;
        if !jsonl {
            let header = "timestamp,pid,user,name,cpu_pct,rss_mb,io_read_bps,io_write_bps,gpu_sm,\
                 sys_load1,sys_mem_pct,sys_procs,sys_net_bps";
            writeln!(f, "{header}")?;
            written = header.len() as u64 + 1;
        }
        Ok((f, written))
    }

    fn append(
        &mut self,
        procs: &[Process],
        hist: &history::History,
        stats: Option<&crate::platform::SystemStats>,
        net_bps: Option<f64>,
    ) {
        self.rotate_if_over_cap();
        let Some(file) = self.file.as_mut() else {
            return;
        };
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
                        "gpu_sm_pct": p.gpu_sm_pct,
                    })
                })
                .collect();
            let system = stats.map(|s| {
                let mem_pct = match (s.mem_used_mb, s.mem_total_mb) {
                    (Some(u), Some(t)) if t > 0 => Some((u * 100) / t),
                    _ => None,
                };
                serde_json::json!({
                    "load1": s.load1,
                    "cpu_pct": s.cpu_percent,
                    "mem_used_mb": s.mem_used_mb,
                    "mem_pct": mem_pct,
                    "proc_count": procs.len(),
                    "net_bps": net_bps,
                })
            });
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "process_count": rows.len(),
                "system": system,
                "processes": rows,
            });
            let _ = writeln!(file, "{}", serde_json::to_string(&doc).unwrap_or_default());
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
                file,
                "{},{},{},{},{},{},{},{},{},,,,",
                ts,
                p.pid,
                render::csv_field(p.user.as_deref().unwrap_or("-")),
                render::csv_field(&p.name),
                cpu,
                rss,
                io.0,
                io.1,
                p.gpu_sm_pct.map(|g| g.to_string()).unwrap_or_default(),
            );
        }
        // the machine's own row: cpu_pct/rss_mb reuse their columns (whole-
        // machine cpu and used MB), the sys_* columns carry what no process
        // row has — load, used-percent, visible count, combined net rate
        if let Some(s) = stats {
            let mem_pct = match (s.mem_used_mb, s.mem_total_mb) {
                (Some(u), Some(t)) if t > 0 => Some((u * 100) / t),
                _ => None,
            };
            let _ = writeln!(
                file,
                "{},_system,-,system,{},{},,,,{},{},{},{}",
                ts,
                s.cpu_percent.map(|c| format!("{c:.1}")).unwrap_or_default(),
                s.mem_used_mb.map(|mb| mb.to_string()).unwrap_or_default(),
                s.load1.map(|l| format!("{l:.2}")).unwrap_or_default(),
                mem_pct.map(|p| p.to_string()).unwrap_or_default(),
                procs.len(),
                net_bps.map(|b| format!("{b:.0}")).unwrap_or_default(),
            );
        }
    }
}

/// One machine-level sample pulled from a `--record` file: the `_system`
/// row (CSV) or the `system` key (JSONL).
#[derive(Debug, Clone)]
pub(crate) struct SysPoint {
    pub(crate) at: i64,
    pub(crate) cpu: Option<f64>,
    pub(crate) mem_pct: Option<f64>,
    pub(crate) load1: Option<f64>,
    pub(crate) procs: usize,
    pub(crate) net_bps: Option<f64>,
}

/// Collect the machine samples from a record file's text (either format —
/// the extension only changed what --record wrote, the reader accepts
/// both). Unparseable lines are skipped; empty input is an error.
pub(crate) fn parse_record_system(text: &str) -> Result<Vec<SysPoint>, String> {
    let mut out = Vec::new();
    let mut lines = text.lines().peekable();
    // CSV: a header naming the columns (order-tolerant), then `_system` rows
    if let Some(first) = lines.peek() {
        if first.starts_with("timestamp,") {
            let header: Vec<&str> = first.split(',').collect();
            let col = |name: &str| header.iter().position(|c| *c == name);
            let (t, pid, cpu, load, mem, procs, net) = (
                col("timestamp"),
                col("pid"),
                col("cpu_pct"),
                col("sys_load1"),
                col("sys_mem_pct"),
                col("sys_procs"),
                col("sys_net_bps"),
            );
            let (Some(t), Some(pid)) = (t, pid) else {
                return Err("csv missing timestamp/pid columns".into());
            };
            for line in lines {
                let f: Vec<&str> = line.split(',').collect();
                if f.len() <= t.max(pid) || f[pid] != "_system" {
                    continue;
                }
                let num = |i: Option<usize>| -> Option<f64> {
                    i.and_then(|i| f.get(i)).and_then(|v| v.trim().parse().ok())
                };
                let procs_n = procs
                    .and_then(|i| f.get(i))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                out.push(SysPoint {
                    at: f[t].trim().parse().unwrap_or(0),
                    cpu: num(cpu),
                    mem_pct: num(mem),
                    load1: num(load),
                    procs: procs_n,
                    net_bps: num(net),
                });
            }
            if out.is_empty() {
                return Err("no _system rows in the csv".to_string());
            }
            return Ok(out);
        }
    }
    // JSONL: one envelope per line with a `system` key
    for line in lines {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(sys) = v.get("system").filter(|s| !s.is_null()) else {
            continue;
        };
        out.push(SysPoint {
            at: v
                .get("generated_at")
                .and_then(|x| x.as_i64())
                .unwrap_or(0),
            cpu: sys.get("cpu_pct").and_then(|x| x.as_f64()),
            mem_pct: sys.get("mem_pct").and_then(|x| x.as_f64()),
            load1: sys.get("load1").and_then(|x| x.as_f64()),
            procs: sys
                .get("proc_count")
                .and_then(|x| x.as_u64())
                .unwrap_or(0) as usize,
            net_bps: sys.get("net_bps").and_then(|x| x.as_f64()),
        });
    }
    if out.is_empty() {
        return Err("no system samples in the jsonl".to_string());
    }
    Ok(out)
}

/// One inline-SVG line chart of `values` (None gaps skipped), w×h, with a
/// last-value label. Self-contained: polyline + text only.
fn svg_series(name: &str, unit: &str, values: &[Option<f64>], t0: i64, t1: i64) -> String {
    let pts: Vec<(f64, f64)> = values
        .iter()
        .enumerate()
        .filter_map(|(i, v)| v.map(|v| (i as f64, v)))
        .collect();
    if pts.is_empty() {
        return String::new();
    }
    let (w, h, pad) = (560.0, 110.0, 6.0);
    let max = pts.iter().map(|(_, v)| *v).fold(0.0f64, f64::max);
    let max = if max <= 0.0 { 1.0 } else { max * 1.1 };
    let n = values.len().saturating_sub(1).max(1) as f64;
    let x = |i: f64| pad + i / n * (w - 2.0 * pad);
    let y = |v: f64| h - pad - v / max * (h - 2.0 * pad - 14.0);
    let poly: String = pts
        .iter()
        .map(|(i, v)| format!("{:.1},{:.1}", x(*i), y(*v)))
        .collect::<Vec<_>>()
        .join(" ");
    let last = pts.last().unwrap().1;
    let at = |t: i64| {
        // HH:MM from unix seconds (local time via the util formatter)
        crate::util::fmt_time(t).get(11..16).unwrap_or("").to_string()
    };
    let s = format!(
        "<div style=\"display:inline-block;margin:8px\"><svg width=\"{w}\" height=\"{h}\" xmlns=\"http://www.w3.org/2000/svg\">\
<text x=\"{pad}\" y=\"14\" font-size=\"12\" fill=\"#8899a6\">{name}</text>\
<text x=\"{w:.0}\" y=\"14\" font-size=\"12\" fill=\"#e1e8ed\" text-anchor=\"end\">{last:.1} {unit} · max {max:.1}</text>\
<polyline fill=\"none\" stroke=\"#4dc3ff\" stroke-width=\"1.5\" points=\"{poly}\"/>\
<text x=\"{pad}\" y=\"{h:.0}\" font-size=\"10\" fill=\"#657786\">{}</text>\
<text x=\"{w:.0}\" y=\"{h:.0}\" font-size=\"10\" fill=\"#657786\" text-anchor=\"end\">{}</text>\
</svg></div>",
        at(t0),
        at(t1),
    );
    s
}

/// `--plot`: the self-contained HTML — a dark page with one chart per
/// series the record actually carried.
fn plot_html(points: &[SysPoint]) -> String {
    let t0 = points.first().map(|p| p.at).unwrap_or(0);
    let t1 = points.last().map(|p| p.at).unwrap_or(0);
    let col = |f: fn(&SysPoint) -> Option<f64>| -> Vec<Option<f64>> {
        points.iter().map(&f).collect()
    };
    let mut charts = String::new();
    for (name, unit, series) in [
        ("cpu %", "%", col(|p| p.cpu)),
        ("memory %", "%", col(|p| p.mem_pct)),
        ("load 1m", "", col(|p| p.load1)),
        (
            "network",
            "MB/s",
            col(|p| p.net_bps.map(|b| b / 1048576.0)),
        ),
    ] {
        charts.push_str(&svg_series(name, unit, &series, t0, t1));
    }
    // process count is a plain usize series — same chart shape
    let procs: Vec<Option<f64>> = points.iter().map(|p| Some(p.procs as f64)).collect();
    charts.push_str(&svg_series("processes", "", &procs, t0, t1));
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>witr-rs plot</title>\
<style>body{{background:#15202b;font-family:ui-monospace,Menlo,monospace;color:#e1e8ed;margin:24px}}</style>\
</head><body><h3>witr-rs · {} samples · {} – {}</h3><div>{charts}</div></body></html>",
        points.len(),
        crate::util::fmt_time(t0),
        crate::util::fmt_time(t1),
    )
}

/// One inline-SVG overlay chart: every series (already resolved to
/// `(unix_time, value)` points) drawn in its own color on a shared
/// time-based x-axis. `--plot a.csv b.csv` flavor — recordings of
/// different lengths and cadences still line up on the clock.
fn svg_overlay(
    name: &str,
    unit: &str,
    series: &[(String, Vec<(i64, f64)>)],
    t0: i64,
    t1: i64,
) -> String {
    let all: Vec<(i64, f64)> = series.iter().flat_map(|(_, pts)| pts.iter().copied()).collect();
    if all.is_empty() || t1 <= t0 {
        return String::new();
    }
    let (w, h, pad) = (560.0, 110.0, 6.0);
    let max = all.iter().map(|(_, v)| *v).fold(0.0f64, f64::max);
    let max = if max <= 0.0 { 1.0 } else { max * 1.1 };
    let x = |t: i64| pad + (t - t0) as f64 / (t1 - t0) as f64 * (w - 2.0 * pad);
    let y = |v: f64| h - pad - v / max * (h - 2.0 * pad - 14.0);
    let polys: String = series
        .iter()
        .filter(|(_, pts)| !pts.is_empty())
        .map(|(color, pts)| {
            let poly: String = pts
                .iter()
                .map(|(t, v)| format!("{:.1},{:.1}", x(*t), y(*v)))
                .collect::<Vec<_>>()
                .join(" ");
            format!("<polyline fill=\"none\" stroke=\"{color}\" stroke-width=\"1.5\" points=\"{poly}\"/>")
        })
        .collect();
    let at = |t: i64| crate::util::fmt_time(t).get(11..16).unwrap_or("").to_string();
    format!(
        "<div style=\"display:inline-block;margin:8px\"><svg width=\"{w}\" height=\"{h}\" xmlns=\"http://www.w3.org/2000/svg\">\
<text x=\"{pad}\" y=\"14\" font-size=\"12\" fill=\"#8899a6\">{name}</text>\
<text x=\"{w:.0}\" y=\"14\" font-size=\"12\" fill=\"#e1e8ed\" text-anchor=\"end\">{unit} · max {max:.1}</text>\
{polys}\
<text x=\"{pad}\" y=\"{h:.0}\" font-size=\"10\" fill=\"#657786\">{}</text>\
<text x=\"{w:.0}\" y=\"{h:.0}\" font-size=\"10\" fill=\"#657786\" text-anchor=\"end\">{}</text>\
</svg></div>",
        at(t0),
        at(t1),
    )
}

/// `--plot a.csv b.csv …`: the overlay flavor — every file's five machine
/// series drawn onto the same charts (one color per file, global legend),
/// so a before/after pair reads as one picture.
fn plot_html_multi(named: &[(String, Vec<SysPoint>)]) -> String {
    const PALETTE: [&str; 6] = ["#4dc3ff", "#ff6b6b", "#51cf66", "#fcc419", "#cc5de8", "#ff922b"];
    let color = |i: usize| PALETTE[i % PALETTE.len()];
    let t0 = named
        .iter()
        .filter_map(|(_, p)| p.first().map(|p| p.at))
        .min()
        .unwrap_or(0);
    let t1 = named
        .iter()
        .filter_map(|(_, p)| p.last().map(|p| p.at))
        .max()
        .unwrap_or(0);
    let legend: String = named
        .iter()
        .enumerate()
        .map(|(i, (name, _))| {
            format!(
                "<span style=\"margin-right:16px\"><span style=\"color:{}\">■</span> {}</span>",
                color(i),
                name
            )
        })
        .collect();
    let metric = |p: &SysPoint, f: fn(&SysPoint) -> Option<f64>| f(p).map(|v| (p.at, v));
    let mut charts = String::new();
    for (name, unit, f) in [
        ("cpu %", "%", (|p: &SysPoint| p.cpu) as fn(&SysPoint) -> Option<f64>),
        ("memory %", "%", (|p: &SysPoint| p.mem_pct) as fn(&SysPoint) -> Option<f64>),
        ("load 1m", "", (|p: &SysPoint| p.load1) as fn(&SysPoint) -> Option<f64>),
        (
            "network",
            "MB/s",
            (|p: &SysPoint| p.net_bps.map(|b| b / 1048576.0)) as fn(&SysPoint) -> Option<f64>,
        ),
        (
            "processes",
            "",
            (|p: &SysPoint| Some(p.procs as f64)) as fn(&SysPoint) -> Option<f64>,
        ),
    ] {
        let series: Vec<(String, Vec<(i64, f64)>)> = named
            .iter()
            .enumerate()
            .map(|(i, (_, pts))| {
                (color(i).to_string(), pts.iter().filter_map(|p| metric(p, f)).collect())
            })
            .collect();
        charts.push_str(&svg_overlay(name, unit, &series, t0, t1));
    }
    let samples: usize = named.iter().map(|(_, p)| p.len()).sum();
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>witr-rs plot</title>\
<style>body{{background:#15202b;font-family:ui-monospace,Menlo,monospace;color:#e1e8ed;margin:24px}}</style>\
</head><body><h3>witr-rs · {samples} samples · {} – {}</h3>\
<div style=\"margin-bottom:8px\">{legend}</div><div>{charts}</div></body></html>",
        crate::util::fmt_time(t0),
        crate::util::fmt_time(t1),
    )
}

fn main() {
    // pre-scan argv for `--en` before building the Command, so the help text
    // (and the man page / completions generated from it) comes out in the
    // chosen language — Chinese by default
    cli::init_language();
    let cli = match cli::Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            // --help / --version are informational, not failures — clap
            // surfaces them as Display* errors printing to stdout; real
            // invalid input keeps the witr convention of exit code 4
            if matches!(
                e.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                std::process::exit(0);
            }
            std::process::exit(4);
        }
    };
    let no_color = cli.no_color || std::env::var_os("NO_COLOR").is_some();

    // user config (flat toml subset): defaults only — CLI flags win
    let mut cli = cli;
    // pre-apply snapshot: SIGHUP reloads re-fold a fresh file under these
    // exact flags, so an explicit --alert-cpu still beats the file's
    let cli_base = cli.clone();
    let cfg = config::Config::load();
    cli.apply_config(&cfg);

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
    if cli.follow
        && !matches!(specs.as_slice(), [TargetSpec::Pid { .. }])
        && cli.replay.is_none()
    {
        eprintln!("--follow tracks one pid across restarts: use exactly one --pid target (or tail --replay FILE)");
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
    if cli.alert_container && cli.watch.is_none() {
        eprintln!("--alert-container rides a headless --watch; add --watch SECONDS");
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
    // --alert-port values parse up front (bad ports exit 4 here, not a
    // silent no-alert later)
    let alert_ports: Vec<(u16, bool)> = match cli
        .alert_port
        .iter()
        .map(|raw| parse_alert_port(raw).ok_or_else(|| raw.clone()))
        .collect::<Result<Vec<_>, String>>()
    {
        Ok(v) => v,
        Err(bad) => {
            eprintln!("--alert-port {bad}: expected PORT or !PORT (e.g. 9090 or '!8080')");
            std::process::exit(4);
        }
    };
    // --alert-silence specs parse up front (bad durations exit 4 here, not
    // a silent no-op later) — windows anchor at startup, like a
    // maintenance calendar
    let silence_rules: Vec<history::SilenceRule> = match cli
        .alert_silence
        .iter()
        .map(|raw| history::SilenceRule::parse(raw).ok_or_else(|| raw.clone()))
        .collect::<Result<Vec<_>, String>>()
    {
        Ok(v) => v,
        Err(bad) => {
            eprintln!("--alert-silence {bad}: expected NAME[=DUR] (e.g. backup=30m or '!cron')");
            std::process::exit(4);
        }
    };
    // --alert-new-proc: the only failure mode is mixed plain/! specs —
    // catch it here, not as a silently-unarmed watch
    if let Err(e) = history::NewProcWatch::parse(&cli.alert_new_proc) {
        eprintln!("--alert-new-proc: {e}");
        std::process::exit(4);
    }
    let any_alert_armed = cli.alert_cpu.is_some()
        || cli.alert_mem.is_some()
        || cli.alert_fd.is_some()
        || cli.alert_io.is_some()
        || cli.alert_conn.is_some()
        || cli.alert_threads.is_some()
        || cli.alert_net_per_proc.is_some()
        || cli.alert_deviation.is_some()
        || cli.alert_container
        || cli.alert_load.is_some()
        || cli.alert_mem_pct.is_some()
        || cli.alert_count.is_some()
        || cli.alert_disk.is_some()
        || cli.alert_net.is_some()
        || !alert_ports.is_empty();
    if cli.alert_repeat.is_some() && !any_alert_armed {
        eprintln!(
            "--alert-repeat re-sends threshold alerts; give one of the --alert-* thresholds"
        );
        std::process::exit(4);
    }
    if cli.grep.is_some() && cli.logs.is_none() {
        eprintln!("--grep filters --logs output; add --logs [N]");
        std::process::exit(4);
    }
    if (cli.kill || cli.kill_tree) && specs.is_empty() {
        eprintln!(
            "--kill/--kill-tree kill the processes matching a target; give a name, --pid, --port, --file or --container"
        );
        std::process::exit(4);
    }
    if cli.signal.is_some() && !cli.kill && !cli.kill_tree {
        eprintln!("--signal chooses the signal --kill/--kill-tree sends; add --kill or --kill-tree");
        std::process::exit(4);
    }
    if let Some(sig) = &cli.signal {
        // names only (TERM/KILL/USR1, optional SIG prefix); a typo'd number
        // silently meaning SIGKILL is worse than an error
        let bare = sig.strip_prefix("SIG").unwrap_or(sig);
        if bare.is_empty() || !bare.chars().all(|c| c.is_ascii_alphabetic()) {
            eprintln!("--signal {sig}: use a signal name like TERM, KILL, INT, HUP");
            std::process::exit(4);
        }
    }
    if cli.replay.is_some() && !cli.interactive && !specs.is_empty() {
        eprintln!("--replay opens the TUI; drop the targets or use -i");
        std::process::exit(4);
    }
    if cli.samples.is_some() && !cli.interactive && !specs.is_empty() {
        eprintln!("--samples opens the TUI; drop the targets or use -i");
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
        && cli.alert_load.is_none()
        && cli.alert_mem_pct.is_none()
        && cli.alert_count.is_none()
        && cli.alert_disk.is_none()
        && cli.alert_net.is_none()
        && cli.alert_port.is_empty()
    {
        eprintln!(
            "--alert-exec runs with threshold alerts; give one of the --alert-* thresholds"
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
            || cli.samples.is_some()
            || cli.since.is_some();
        if serve_clash {
            eprintln!("--serve is a standalone mode; drop the other output/operation flags");
            std::process::exit(4);
        }
    }
    // --ports: a listener table — standalone like --serve (pairs with
    // --csv/--json one-shot, or a --watch redraw of the human table)
    if cli.ports_list {
        let clash = !specs.is_empty()
            || cli.interactive
            || cli.top.is_some()
            || cli.markdown
            || cli.report_html.is_some()
            || cli.tree
            || cli.short
            || cli.env
            || cli.warnings
            || cli.snap.is_some()
            || cli.diff.is_some()
            || cli.serve.is_some()
            || cli.recent.is_some()
            || cli.conns
            || cli.locks
            || cli.zombies
            || cli.services
            || cli.sys;
        if clash {
            eprintln!("--ports is a standalone listing; drop the targets and other modes (it pairs with --csv/--json/--watch)");
            std::process::exit(4);
        }
        if cli.watch.is_some() && (cli.csv || cli.json) {
            eprintln!("machine-readable --ports is one-shot; drop --watch or the format flag");
            std::process::exit(4);
        }
    }
    // --conns: every socket outside LISTEN, with owner + loopback peer
    // attribution (the mirror of --ports)
    if cli.conns {
        let clash = !specs.is_empty()
            || cli.interactive
            || cli.top.is_some()
            || cli.report_html.is_some()
            || cli.tree
            || cli.short
            || cli.env
            || cli.warnings
            || cli.snap.is_some()
            || cli.diff.is_some()
            || cli.serve.is_some()
            || cli.recent.is_some()
            || cli.ports_list
            || cli.locks
            || cli.zombies
            || cli.services
            || cli.sys
            || cli.by_name;
        if clash {
            eprintln!("--conns is a standalone listing; drop the targets and other modes (it pairs with --csv/--markdown/--json/--watch)");
            std::process::exit(4);
        }
        if cli.watch.is_some() && (cli.csv || cli.markdown || cli.json) {
            eprintln!("machine-readable --conns is one-shot; drop --watch or the format flag");
            std::process::exit(4);
        }
    }
    // --diff-auto rides the target-less --watch loop (text drift lines or,
    // under --json, one versioned envelope per drift check)
    if cli.diff_auto.is_some() {
        if cli.watch.is_none() {
            eprintln!("--diff-auto re-checks the table every --watch tick interval; add --watch SECONDS");
            std::process::exit(4);
        }
        if !specs.is_empty() {
            eprintln!("--diff-auto watches the whole table; drop the targets");
            std::process::exit(4);
        }
    }
    // --wait blocks on target resolution; --timeout is its time bound
    if let Some(what) = cli.wait.as_deref() {
        if specs.is_empty() {
            eprintln!("--wait watches a target; give a name, --pid, --port, --file or --container");
            std::process::exit(4);
        }
        if what != "here" && what != "gone" {
            eprintln!("--wait expects `here` (the default) or `gone`");
            std::process::exit(4);
        }
        let wait_clash = cli.watch.is_some()
            || cli.interactive
            || cli.follow
            || cli.on_start.is_some()
            || cli.on_exit.is_some()
            || cli.kill
            || cli.kill_tree
            || cli.audit.is_some()
            || cli.serve.is_some()
            || cli.snap.is_some()
            || cli.diff.is_some()
            || cli.replay.is_some()
            || cli.since.is_some()
            || cli.diff_auto.is_some()
            || cli.record.is_some()
            || cli.ports_list
            || cli.by_name
            || cli.top.is_some();
        if wait_clash {
            eprintln!("--wait is a blocking one-shot; drop the other modes");
            std::process::exit(4);
        }
    }
    if cli.timeout.is_some() && cli.wait.is_none() {
        eprintln!("--timeout bounds --wait; add --wait");
        std::process::exit(4);
    }
    // --pids-only: a target query collapsed to its bare pid line
    if cli.pids_only {
        let clash = specs.is_empty()
            || cli.interactive
            || cli.json
            || cli.env
            || cli.warnings
            || cli.short
            || cli.tree
            || cli.export
            || cli.csv
            || cli.markdown
            || cli.report_html.is_some()
            || cli.top.is_some()
            || cli.ports_list
            || cli.by_name
            || cli.serve.is_some()
            || cli.snap.is_some()
            || cli.diff.is_some()
            || cli.watch.is_some();
        if clash {
            eprintln!("--pids-only prints the matched pids of a target query; drop the other modes");
            std::process::exit(4);
        }
    }
    // --by-name: the whole table folded by (name, user) identity
    if cli.by_name {
        let clash = !specs.is_empty()
            || cli.top.is_some()
            || cli.ports_list
            || cli.tree
            || cli.short
            || cli.env
            || cli.warnings
            || cli.report_html.is_some()
            || cli.snap.is_some()
            || cli.diff.is_some()
            || cli.serve.is_some()
            || cli.replay.is_some()
            || cli.since.is_some()
            || cli.pids_only
            || cli.wait.is_some();
        if clash {
            eprintln!("--by-name aggregates the whole table; drop the targets and other modes (it pairs with --csv/--markdown/--json/--watch)");
            std::process::exit(4);
        }
    }
    // --zombies / --locks / --services: whole-table no-target listings
    // (text, --json, --csv or --markdown)
    for (flag, on) in [
        ("--zombies", cli.zombies),
        ("--locks", cli.locks),
        ("--services", cli.services),
        ("--sys", cli.sys),
    ] {
        if on {
            let clash = !specs.is_empty()
                || cli.interactive
                || cli.top.is_some()
                || cli.ports_list
                || cli.conns
                || cli.tree
                || cli.short
                || cli.env
                || cli.warnings
                || cli.report_html.is_some()
                || cli.snap.is_some()
                || cli.diff.is_some()
                || cli.serve.is_some()
                || cli.replay.is_some()
                || cli.since.is_some()
                || cli.by_name
                || cli.pids_only
                || cli.wait.is_some()
                || (cli.watch.is_some() && flag != "--sys")
                || cli.follow
                || cli.audit.is_some()
                || cli.kill
                || cli.kill_tree;
            if clash {
                eprintln!("{flag} is a whole-table listing; drop the targets and other modes (pairs with --json/--csv/--markdown)");
                std::process::exit(4);
            }
        }
    }
    // --sys --watch redraws the human table only; machine-readable frames
    // are one-shot (their consumers own their cadence, like --ports)
    if cli.sys && cli.watch.is_some() && (cli.json || cli.csv || cli.markdown) {
        eprintln!("machine-readable --sys is one-shot; drop --watch or the format flag");
        std::process::exit(4);
    }
    if cli.record.is_some() && cli.watch.is_none() {
        eprintln!("--record samples alongside --watch; add --watch SECONDS");
        std::process::exit(4);
    }
    if cli.record.is_some() && !specs.is_empty() {
        eprintln!("--record records the whole process table under --watch; drop the targets (filter later, e.g. with --recent or in the CSV itself)");
        std::process::exit(4);
    }
    // --top pairs with the machine-readable formats (the ranked rows are
    // the same shape as the full table's); --csv/--markdown/--report-html
    // remain mutually exclusive among themselves
    let listing_extras = cli.csv as u8 + cli.markdown as u8 + cli.report_html.is_some() as u8;
    if listing_extras > 1 {
        eprintln!("--csv, --markdown and --report-html are separate output modes; use one at a time");
        std::process::exit(4);
    }
    if cli.top.is_some() && cli.report_html.is_some() {
        eprintln!("--top ranks rows; --report-html renders the whole table — use one at a time");
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
    // --audit runs a command of its own — it is the whole point, so nothing
    // else may drive the session
    if cli.audit.is_some()
        && (!specs.is_empty()
            || cli.interactive
            || cli.watch.is_some()
            || cli.follow
            || listing_extras > 0
            || cli.snap.is_some()
            || cli.diff.is_some()
            || cli.serve.is_some()
            || cli.kill
            || cli.kill_tree)
    {
        eprintln!("--audit runs and observes its own command; drop the other modes and targets");
        std::process::exit(4);
    }
    if (cli.kill || cli.kill_tree) && (cli.interactive || cli.watch.is_some() || cli.follow) {
        eprintln!("--kill/--kill-tree are one-shot; drop -i/--watch/--follow");
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

    // --samples: parse the record file once, up front — a bad file is an
    // exit-5 error before any TUI starts; the parsed points ride the Seed
    let (mut samples, mut samples_source) = (Vec::new(), String::new());
    if let Some(path) = &cli.samples {
        match std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|t| parse_record_system(&t))
        {
            Ok(pts) => {
                samples = pts;
                samples_source = path.clone();
            }
            Err(e) => {
                eprintln!("--samples {path}: {e}");
                std::process::exit(5);
            }
        }
        if !(std::io::stdout().is_terminal() && std::io::stdin().is_terminal()) && !cli.interactive
        {
            eprintln!("--samples opens the TUI; it needs a terminal");
            std::process::exit(4);
        }
    }

    // --audit: run a command under observation — its own standalone mode,
    // exit code mirrors the audited command's
    if let Some(cmd) = &cli.audit {
        if cmd.trim().is_empty() {
            eprintln!("--audit: empty command");
            std::process::exit(4);
        }
        let code = audit::run(cmd, !no_color, cli.json);
        std::process::exit(code);
    }

    // --kill / --kill-tree: trace the targets like a report run would, then
    // signal the matches instead of printing them. Exit 0 when everything
    // was delivered, 2 when nothing matched, 1 on partial failure.
    if cli.kill || cli.kill_tree {
        let platform = platform::get();
        let opts = pipeline::Options {
            want_env: false,
            deep_files: false,
            deep_binaries: false,
            ..Default::default()
        };
        let reports = pipeline::run(platform.as_ref(), specs, &opts);
        let mut matches: Vec<Process> = reports
            .iter()
            .flat_map(|r| r.matches.iter().cloned())
            .collect();
        matches.sort_by_key(|p| p.pid);
        matches.dedup_by(|a, b| a.pid == b.pid);
        if matches.is_empty() {
            eprintln!("--kill: no process matched the target(s)");
            std::process::exit(2);
        }
        let sig = cli
            .signal
            .as_deref()
            .unwrap_or("TERM")
            .trim_start_matches("SIG")
            .to_ascii_uppercase();
        // tree mode: descendants first (reversed BFS puts leaves before
        // roots), then the matches themselves
        let mut order: Vec<Process> = Vec::new();
        if cli.kill_tree {
            let table = platform.list_processes().unwrap_or_default();
            let mut extra: Vec<Process> = Vec::new();
            for m in &matches {
                for pid in tui::descendants_of(m.pid, &table).into_iter().rev() {
                    if pid == m.pid || matches.iter().any(|x| x.pid == pid) {
                        continue;
                    }
                    if let Some(p) = table.iter().find(|p| p.pid == pid) {
                        extra.push(p.clone());
                    }
                }
            }
            extra.sort_by_key(|p| p.pid);
            extra.dedup_by(|a, b| a.pid == b.pid);
            order.extend(extra);
        }
        order.extend(matches);
        // --dry-run: the plan, no signals — same ordering (--kill-tree's
        // descendants first) and same exit codes, so a script can preview
        // exactly what the real run would do
        if cli.dry_run {
            for p in &order {
                write_out(&format!("would kill {} (pid {}) [SIG{}]", p.name, p.pid, sig));
            }
            write_out(&format!(
                "{} process(es) would receive SIG{} (--dry-run: nothing signaled)",
                order.len(),
                sig
            ));
            std::process::exit(0);
        }
        let mut failed = 0usize;
        for p in &order {
            match tui::send_signal(p.pid, &sig) {
                Ok(()) => write_out(&format!("killed {} (pid {}) [SIG{}]", p.name, p.pid, sig)),
                Err(e) => {
                    eprintln!("⚠ kill {} (pid {}): {e}", p.name, p.pid);
                    failed += 1;
                }
            }
        }
        std::process::exit(i32::from(failed > 0));
    }

    // --plot: render one --record file into a self-contained HTML chart (or
    // overlay several into one comparison) — a no-target operation like
    // --snap/--diff.
    if !cli.plot.is_empty() {
        if !specs.is_empty() || cli.interactive {
            eprintln!("--plot renders the machine samples from a record file; drop the targets or -i");
            std::process::exit(4);
        }
        if cli.watch.is_some() {
            eprintln!("--plot writes one chart and exits; drop --watch");
            std::process::exit(4);
        }
        let mut named: Vec<(String, Vec<SysPoint>)> = Vec::new();
        for path in &cli.plot {
            let text = match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("--plot {path}: {e}");
                    std::process::exit(5);
                }
            };
            let points = match parse_record_system(&text) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("--plot {path}: {e}");
                    std::process::exit(5);
                }
            };
            named.push((path.clone(), points));
        }
        let (out, html, total) = if named.len() == 1 {
            let (path, points) = &named[0];
            (format!("{path}.html"), plot_html(points), points.len())
        } else {
            let total: usize = named.iter().map(|(_, p)| p.len()).sum();
            (
                "witr-plot.html".to_string(),
                plot_html_multi(&named),
                total,
            )
        };
        if let Err(e) = std::fs::write(&out, &html) {
            eprintln!("--plot: cannot write {out}: {e}");
            std::process::exit(5);
        }
        write_out(&format!(
            "plot: {} file{}, {total} samples → {out}",
            named.len(),
            if named.len() == 1 { "" } else { "s" },
        ));
        return;
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
                // (XDG respected via Config::base_dir)
                if crate::config::Config::base_dir().is_none() {
                    eprintln!("--snap needs $HOME (or $XDG_CONFIG_HOME) for the auto-rotate directory, or give a FILE");
                    std::process::exit(4);
                }
                let keep = cli.keep.unwrap_or(10).max(1);
                match snapshot::save_auto(&procs, &listeners, keep) {
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
        let resolved = match snapshot::resolve_ref(raw_ref) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("--diff {raw_ref}: {e}");
                std::process::exit(4);
            }
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

    // --ports: every LISTEN socket + owner as a table (the CLI twin of the
    // TUI Ports overview), text / --csv / --json — text optionally refreshed
    // in place under --watch
    if cli.ports_list {
        let platform = platform::get();
        if let Some(secs) = cli.watch {
            let interval = secs.max(1);
            let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
            install_sigint_flag();
            let mut ticks: u64 = 0;
            loop {
                let procs = match platform.list_processes() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("cannot list processes: {}", e);
                        std::process::exit(5);
                    }
                };
                let socks = platform.list_sockets().unwrap_or_default();
                let mut listeners = snapshot::to_listeners(&socks, &procs);
                listeners.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.proto.cmp(&b.proto)));
                write_out("\x1b[2J\x1b[1;1H");
                write_out(&format!(
                    "witr-rs ports · every {interval}s · {} · Ctrl-C to stop",
                    util::fmt_time(util::now_unix())
                ));
                write_out(&render::render_listeners(&listeners, &painter));
                ticks += 1;
                if cli.times.is_some_and(|n| ticks >= n.max(1)) {
                    std::process::exit(0);
                }
                if !sleep_interruptible(interval) {
                    std::process::exit(130);
                }
            }
        }
        let procs = match platform.list_processes() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cannot list processes: {}", e);
                std::process::exit(5);
            }
        };
        let socks = platform.list_sockets().unwrap_or_default();
        let mut listeners = snapshot::to_listeners(&socks, &procs);
        listeners.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.proto.cmp(&b.proto)));
        if cli.json {
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "listener_count": listeners.len(),
                "listeners": listeners,
            });
            write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
        } else if cli.csv {
            write_out(&render::render_listeners_csv(&listeners));
        } else {
            let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
            write_out(&render::render_listeners(&listeners, &painter));
        }
        std::process::exit(0);
    }

    // --sys: the machine dashboard (the system page's CLI twin). CPU% and
    // NIC rates are delta metrics — a one-shot takes two samples a second
    // apart (the io-rate pattern); --watch diffs across ticks.
    if cli.sys {
        let platform = platform::get();
        let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
        let count = |platform: &dyn Platform| -> usize {
            platform.list_processes().map(|p| p.len()).unwrap_or(0)
        };
        if let Some(secs) = cli.watch {
            let interval = secs.max(1);
            install_sigint_flag();
            let mut net_prev: Option<(Vec<platform::NicCounters>, Instant)> = None;
            let mut ticks: u64 = 0;
            loop {
                let frame = sys_frame(platform.as_ref(), &mut net_prev, count(platform.as_ref()));
                write_out("\x1b[2J\x1b[1;1H");
                write_out(&format!(
                    "witr-rs sys · every {interval}s · Ctrl-C to stop\n{}",
                    render::render_sys(&frame, &painter)
                ));
                ticks += 1;
                if cli.times.is_some_and(|n| ticks >= n.max(1)) {
                    std::process::exit(0);
                }
                if !sleep_interruptible(interval) {
                    std::process::exit(130);
                }
            }
        }
        let mut net_prev: Option<(Vec<platform::NicCounters>, Instant)> = None;
        let _ = sys_frame(platform.as_ref(), &mut net_prev, count(platform.as_ref()));
        std::thread::sleep(Duration::from_secs(1));
        let frame = sys_frame(platform.as_ref(), &mut net_prev, count(platform.as_ref()));
        if cli.json {
            let s = &frame.stats;
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "cpu_pct": s.cpu_percent,
                "cores": s.cores,
                "mem_used_mb": s.mem_used_mb,
                "mem_avail_mb": s.mem_avail_mb,
                "mem_total_mb": s.mem_total_mb,
                "swap_used_mb": s.swap_used_mb,
                "swap_total_mb": s.swap_total_mb,
                "load1": s.load1,
                "load5": s.load5,
                "load15": s.load15,
                "procs": frame.procs,
                "mounts": frame.mounts.iter().map(|m| serde_json::json!({
                    "target": m.target, "used_mb": m.used_mb, "total_mb": m.total_mb,
                })).collect::<Vec<_>>(),
                "nics": frame.nics.iter().map(|(n, r, t)| serde_json::json!({
                    "name": n, "rx_mbps": r, "tx_mbps": t,
                })).collect::<Vec<_>>(),
                "temp": s.temp.as_ref().map(|(l, c)| serde_json::json!({
                    "sensor": l, "celsius": c,
                })),
                "psi": s.psi.as_ref().map(|p| serde_json::json!({
                    "cpu_some": p.cpu_some, "cpu_full": p.cpu_full,
                    "mem_some": p.mem_some, "mem_full": p.mem_full,
                    "io_some": p.io_some, "io_full": p.io_full,
                })),
            });
            write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
        } else if cli.csv {
            write_out(&render::render_sys_csv(&frame));
        } else if cli.markdown {
            write_out(&render::render_sys_markdown(&frame));
        } else {
            write_out(&render::render_sys(&frame, &painter));
        }
        std::process::exit(0);
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
        if let Err(e) = serve::run(&addr, fds_enabled, cli.serve_token.as_deref()) {
            eprintln!("--serve: {e}");
            std::process::exit(5);
        }
        std::process::exit(0);
    }

    // --remote: render another host's table instead of the local machine's —
    // a standalone mode like --serve (the peer runs `witr-rs --serve`)
    if let Some(base) = &cli.remote {
        remote_mode(base, &cli, no_color);
        std::process::exit(0);
    }

    // --install-service: write the current flags as a service definition
    // and best-effort register it — a standalone mode (the point is to
    // persist what you just proved out interactively)
    if cli.install_service.is_some() {
        let armed = cli.watch.is_some()
            || cli.alert_cpu.is_some()
            || cli.alert_mem.is_some()
            || cli.alert_fd.is_some()
            || cli.alert_io.is_some()
            || cli.alert_conn.is_some()
            || cli.alert_load.is_some()
            || cli.alert_mem_pct.is_some()
            || cli.alert_count.is_some()
            || cli.alert_disk.is_some()
            || cli.alert_net.is_some()
            || cli.alert_psi.is_some()
            || cli.alert_mem_avail_mb.is_some()
            || cli.alert_swap_pct.is_some()
            || cli.alert_retrans.is_some()
            || cli.alert_nic_drop.is_some()
            || cli.alert_net_per_proc.is_some()
            || cli.alert_deviation.is_some()
            || !cli.alert_port.is_empty()
            || !cli.alert_new_proc.is_empty()
            || !cli.names.is_empty();
        if !armed {
            eprintln!(
                "--install-service needs something to run: give --watch, an --alert-* flag or a target"
            );
            std::process::exit(4);
        }
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "witr-rs".into());
        let args = service_flag_args(&cli);
        let body = if cfg!(target_os = "macos") {
            launchd_plist(&exe, &args)
        } else if cfg!(target_os = "linux") {
            systemd_unit(&exe, &args)
        } else {
            schtasks_xml(&exe, &args)
        };
        let explicit = cli.install_service.as_deref().filter(|s| !s.is_empty());
        let path = explicit
            .map(std::path::PathBuf::from)
            .or_else(service_default_path)
            .unwrap_or_else(|| {
                eprintln!("--install-service: no home directory known; give an explicit path");
                std::process::exit(4);
            });
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::write(&path, &body) {
            Ok(()) => {
                write_out(&format!("service definition → {}", path.display()));
                write_out(&format!("runs: {exe} {}", args.join(" ")));
                // a custom path means "just write the file" — auto-register
                // only the default install so staging elsewhere stays inert
                if explicit.is_none() {
                    service_register(&path);
                } else {
                    service_register_hint(&path);
                }
            }
            Err(e) => {
                eprintln!("--install-service {}: {e}", path.display());
                std::process::exit(5);
            }
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
        let cli_for_reload = cli_base.clone();
        let seed = tui::Seed {
            events_log: cli.events_log.clone(),
            replayed,
            samples,
            samples_source,
            since: since_secs,
            alert_port: alert_ports.clone(),
            replay_follow: cli.replay.clone().filter(|_| cli.follow),
            // SIGHUP rebuilds the seed from the pre-apply flag snapshot +
            // a fresh config read — with_knobs keeps startup and reload on
            // one code path
            reseed: Some(Box::new(move || {
                let fresh = reload_resolved(&cli_for_reload);
                // targets aren't carried: reseed() only reads knobs
                tui::Seed::default().with_knobs(&fresh, &config::Config::load())
            })),
            alert_threads: cli.alert_threads,
            ..tui::Seed::from_targets(
                &cli.names, &cli.pids, &cli.ports, &cli.files, &cli.containers,
            )
            .with_knobs(&cli, &cfg)
        };
        if let Err(e) = tui::run(seed) {
            eprintln!("tui error: {}", e);
            std::process::exit(5);
        }
        std::process::exit(0);
    }

    // --by-name: the whole table folded by (name, user) identity — text /
    // --csv / --markdown / --json, optionally re-aggregated under --watch
    if cli.by_name {
        let platform = platform::get();
        let emit = |groups: &[render::NameGroup]| -> String {
            if cli.json {
                let doc = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "generated_at": util::now_unix(),
                    "group_count": groups.len(),
                    "groups": groups,
                });
                serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into())
            } else if cli.csv {
                render::render_by_name_csv(groups)
            } else if cli.markdown {
                render::render_by_name_markdown(groups)
            } else {
                let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
                render::render_by_name(groups, &painter)
            }
        };
        if let Some(secs) = cli.watch {
            let interval = secs.max(1);
            let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
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
                gpu::enrich(&mut listed);
                let groups = render::aggregate_by_name(&recent_only(listed));
                write_out("\x1b[2J\x1b[1;1H");
                write_out(&format!(
                    "witr-rs by-name · every {interval}s · {} · Ctrl-C to stop",
                    util::fmt_time(util::now_unix())
                ));
                write_out(&render::render_by_name(&groups, &painter));
                ticks += 1;
                if cli.times.is_some_and(|n| ticks >= n.max(1)) {
                    std::process::exit(0);
                }
                if !sleep_interruptible(interval) {
                    std::process::exit(130);
                }
            }
        }
        let mut listed = match platform.list_processes() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cannot list processes: {}", e);
                std::process::exit(5);
            }
        };
        gpu::enrich(&mut listed);
        let groups = render::aggregate_by_name(&recent_only(listed));
        write_out(&emit(&groups));
        std::process::exit(0);
    }

    // --zombies: dead-but-unreaped processes + the parent that should have
    // reaped them. Exit 1 when any exist so scripts can branch directly.
    if cli.zombies {
        let platform = platform::get();
        let listed = match platform.list_processes() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cannot list processes: {}", e);
                std::process::exit(5);
            }
        };
        let rows = render::collect_zombies(&listed);
        if cli.json {
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "zombie_count": rows.len(),
                "zombies": rows,
            });
            write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
        } else if cli.csv {
            write_out(&render::render_zombies_csv(&rows));
        } else if cli.markdown {
            write_out(&render::render_zombies_markdown(&rows));
        } else {
            let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
            write_out(&render::render_zombies(&rows, &painter));
        }
        std::process::exit(if rows.is_empty() { 0 } else { 1 });
    }

    // --locks: every file lock currently held system-wide (the Locks tab's
    // CLI twin; --json shares the LockEntry rows)
    if cli.locks {
        let platform = platform::get();
        let locks = platform.list_locks(None);
        if cli.json {
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "lock_count": locks.len(),
                "locks": locks,
            });
            write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
        } else if cli.csv {
            write_out(&render::render_locks_csv(&locks));
        } else if cli.markdown {
            write_out(&render::render_locks_markdown(&locks));
        } else {
            let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
            write_out(&render::render_locks_table(&locks, &painter));
        }
        std::process::exit(0);
    }

    // --services: the service manager's units (the Services tab's CLI
    // twin). One enumerate call per invocation — the table is meant for
    // humans and scripts, not polling loops.
    if cli.services {
        let mut svcs = platform::enumerate_services();
        render::sort_services(&mut svcs);
        if cli.json {
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "service_count": svcs.len(),
                "services": svcs,
            });
            write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
        } else if cli.csv {
            write_out(&render::render_services_csv(&svcs));
        } else if cli.markdown {
            write_out(&render::render_services_markdown(&svcs));
        } else {
            let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
            write_out(&render::render_services(&svcs, &painter));
        }
        std::process::exit(0);
    }

    // --conns: the machine's sockets outside LISTEN, owners resolved and
    // loopback peers attributed (the Ports tab's "all states" view, CLI
    // twin of --ports)
    if cli.conns {
        let platform = platform::get();
        let board = || -> Vec<render::ConnRow> {
            let procs = match platform.list_processes() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("cannot list processes: {}", e);
                    std::process::exit(5);
                }
            };
            let socks = platform.list_all_sockets().unwrap_or_default();
            render::collect_conns(&socks, &procs)
        };
        if let Some(secs) = cli.watch {
            let interval = secs.max(1);
            let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
            install_sigint_flag();
            let mut ticks: u64 = 0;
            loop {
                let rows = board();
                write_out("\x1b[2J\x1b[1;1H");
                write_out(&format!(
                    "witr-rs conns · every {interval}s · {} · Ctrl-C to stop",
                    util::fmt_time(util::now_unix())
                ));
                write_out(&if cli.by_peer {
                    render::render_conns_by_peer(&render::collect_conns_by_peer(&rows), &painter)
                } else {
                    render::render_conns(&rows, &painter)
                });
                ticks += 1;
                if cli.times.is_some_and(|n| ticks >= n.max(1)) {
                    std::process::exit(0);
                }
                if !sleep_interruptible(interval) {
                    std::process::exit(130);
                }
            }
        }
        let rows = board();
        if cli.by_peer {
            let peers = render::collect_conns_by_peer(&rows);
            if cli.json {
                let doc = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "generated_at": util::now_unix(),
                    "peer_count": peers.len(),
                    "peers": peers,
                });
                write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
            } else if cli.csv {
                write_out(&render::render_conns_by_peer_csv(&peers));
            } else if cli.markdown {
                write_out(&render::render_conns_by_peer_markdown(&peers));
            } else {
                let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
                write_out(&render::render_conns_by_peer(&peers, &painter));
            }
            std::process::exit(0);
        }
        if cli.json {
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "connection_count": rows.len(),
                "connections": rows,
            });
            write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
        } else if cli.csv {
            write_out(&render::render_conns_csv(&rows));
        } else if cli.markdown {
            write_out(&render::render_conns_markdown(&rows));
        } else {
            let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
            write_out(&render::render_conns(&rows, &painter));
        }
        std::process::exit(0);
    }

    // --top / --csv / --markdown / --report-html: whole-table listings with
    // a different renderer, valid piped or on a terminal (never the TUI).
    if specs.is_empty() && (listing_extras > 0 || cli.top.is_some()) {
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
            // io-rate ranking samples the counters every tick; the history
            // turns the deltas into bytes/s
            let mut hist = history::History::new();
            let mut ticks: u64 = 0;
            loop {
                let mut listed = match platform.list_processes() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("cannot list processes: {}", e);
                        std::process::exit(5);
                    }
                };
                if matches!(metric, cli::TopMetric::Io | cli::TopMetric::IoRate) {
                    platform.enrich_listing(&mut listed);
                }
                gpu::enrich(&mut listed);
                let procs = recent_only(listed);
                hist.update(&procs);
                let fds = if metric == cli::TopMetric::Fd {
                    platform.fd_counts()
                } else {
                    None
                };
                let conns = if metric == cli::TopMetric::Conn {
                    Some(tui::established_per_pid(
                        &platform.list_all_sockets().unwrap_or_default(),
                    ))
                } else {
                    None
                };
                // net is a delta metric: feed each tick's ss sweep into the
                // persistent history; rates exist from the second tick on
                if metric == cli::TopMetric::Net {
                    if let Some(sweep) = platform::net_bytes_per_pid() {
                        hist.update_net(&sweep);
                    }
                }
                write_out("\x1b[2J\x1b[1;1H");
                let now = util::fmt_time(util::now_unix());
                write_out(&format!(
                    "witr-rs top {} · every {}s · {} · Ctrl-C to stop",
                    format!("{metric:?}").to_lowercase(),
                    interval,
                    now
                ));
                write_out(&render::render_top(
                    &procs,
                    metric,
                    count,
                    fds.as_ref(),
                    Some(&hist),
                    conns.as_ref(),
                    &painter,
                ));
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
        // conn ranking needs the socket table once (attribution rides the
        // same sweep the Ports page uses)
        let conns = if cli.top == Some(cli::TopMetric::Conn) {
            Some(tui::established_per_pid(
                &platform.list_all_sockets().unwrap_or_default(),
            ))
        } else {
            None
        };
        if matches!(
            cli.top,
            Some(cli::TopMetric::Io) | Some(cli::TopMetric::IoRate)
        ) {
            platform.enrich_listing(&mut procs);
        }
        gpu::enrich(&mut procs);
        let procs = recent_only(procs);
        if let Some(metric) = cli.top {
            let count = cli.count.unwrap_or(15).max(1);
            let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
            // io-rate / net are delta metrics: two samples one second apart
            // turn the cumulative counters into bytes/s (a running --watch
            // keeps its own persistent history instead)
            let rates = if matches!(metric, cli::TopMetric::IoRate | cli::TopMetric::Net) {
                let mut hist = history::History::new();
                if metric == cli::TopMetric::IoRate {
                    let _ = hist.update(&procs);
                    std::thread::sleep(Duration::from_secs(1));
                    let mut again = match platform.list_processes() {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("cannot list processes: {}", e);
                            std::process::exit(5);
                        }
                    };
                    platform.enrich_listing(&mut again);
                    let _ = hist.update(&again);
                } else {
                    // --top net: two ss(8) sweeps diff the per-socket byte
                    // counters; absent ss leaves the board to its note
                    if let Some(sweep) = platform::net_bytes_per_pid() {
                        hist.update_net(&sweep);
                        std::thread::sleep(Duration::from_secs(1));
                        let again = platform::net_bytes_per_pid().unwrap_or_default();
                        hist.update_net(&again);
                    }
                }
                Some(hist)
            } else {
                None
            };
            if cli.json {
                let ranked =
                    top_procs(&procs, metric, count, fds.as_ref(), rates.as_ref(), conns.as_ref());
                write_out(&json_envelope(&ranked));
            } else if cli.csv {
                write_out(&render::render_csv(&top_procs(
                    &procs,
                    metric,
                    count,
                    fds.as_ref(),
                    rates.as_ref(),
                    conns.as_ref(),
                )));
            } else if cli.markdown {
                write_out(&render::render_markdown(&top_procs(
                    &procs,
                    metric,
                    count,
                    fds.as_ref(),
                    rates.as_ref(),
                    conns.as_ref(),
                )));
            } else {
                write_out(&render::render_top(
                    &procs,
                    metric,
                    count,
                    fds.as_ref(),
                    rates.as_ref(),
                    conns.as_ref(),
                    &painter,
                ));
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
                samples,
                samples_source,
                since: since_secs,
                refresh_secs: cfg.refresh_secs,
                sort: cfg.sort.clone(),
                paused: cfg.paused.unwrap_or(false),
                alert_cpu: cli.alert_cpu,
                alert_mem: cli.alert_mem,
                alert_exec: cli.alert_exec.clone(),
                alert_fd: cli.alert_fd,
                alert_io: cli.alert_io,
                alert_conn: cli.alert_conn,
                alert_port: alert_ports.clone(),
                alert_load: cli.alert_load,
                alert_mem_pct: cli.alert_mem_pct,
                alert_count: cli.alert_count,
                alert_disk: cli.alert_disk,
                alert_net: cli.alert_net,
                alert_psi: cli.alert_psi,
                alert_mem_avail_mb: cli.alert_mem_avail_mb,
                alert_swap_pct: cli.alert_swap_pct,
                alert_retrans: cli.alert_retrans,
                alert_nic_drop: cli.alert_nic_drop,
                alert_webhook: cli.alert_webhook.clone(),
                alert_repeat: cli.alert_repeat,
                watch: cfg.watch.clone(),
                notes: cfg.notes,
                replay_follow: cli.replay.clone().filter(|_| cli.follow),
                alert_threads: cli.alert_threads,
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
            install_sighup_flag();
            // brief-process capture: spawns and dies between the ticks
            // would be invisible otherwise (not on Windows — no cheap
            // pid sweep). The thread self-terminates when this loop's
            // channel drops at Ctrl-C.
            let brief_rx = if platform::quick_pids().is_some() {
                let (rx, _stop) = history::spawn_brief_poller(250);
                Some(rx)
            } else {
                None
            };
            // container edges from the runtime's own event stream: deaths,
            // OOM and health flips arrive in milliseconds (None without
            // docker/podman/nerdctl on PATH; killing the child on drop is
            // the stream struct's job)
            let container_stream = history::spawn_container_events();
            let mut recorder = match &cli.record {
                Some(path) => match RecordWriter::create_with_cap(
                    path,
                    cli.record_max_mb.map(|mb| mb.saturating_mul(1024 * 1024)),
                ) {
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
                Some(path) => match EventLog::create(path, cli.record_max_mb) {
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
            // supervised by systemd (--install-service sets WatchdogSec)?
            // announce readiness, then prove the loop stays alive every
            // tick — a hung watchdog gets restarted instead of going deaf
            util::sd_notify("READY=1");
            let mut alert_state: HashMap<Pid, history::AlertTrack> = HashMap::new();
            let mut fd_counts: HashMap<Pid, u64> = HashMap::new();
            let mut conn_counts: HashMap<Pid, u64> = HashMap::new();
            // --alert-port bookkeeping: presence + last-known owner per port
            let mut port_seen: HashMap<u16, bool> = HashMap::new();
            let mut port_owner: HashMap<u16, String> = HashMap::new();
            // --alert-load / --alert-mem-pct: one machine-wide state
            let mut sys_alert = history::SysAlertState::default();
            // --alert-new-proc: first-sighting tracker (armed per session)
            let mut new_proc = history::NewProcWatch::parse(&cli.alert_new_proc)
                .ok()
                .flatten();
            // --diff-auto: the previous frame to diff against
            let mut last_frame: Option<(Vec<Process>, Vec<snapshot::Listener>)> = None;
            let mut last_diff = Instant::now();
            // --alert-container: the container/pod sweep rides a background
            // thread (runtime CLIs take seconds) on a slower cadence than
            // the tick; the shared edge detector fires once per edge
            let mut container_edges = history::ContainerEdges::default();
            let mut container_rx: Option<std::sync::mpsc::Receiver<(Vec<model::Container>, Vec<crate::k8s::Pod>)>> = None;
            let mut container_swept_at: Option<Instant> = None;
            let container_every = Duration::from_secs(10).max(Duration::from_secs(interval.max(1)));
            // the most recent firings, repeated under the header so a redraw
            // doesn't erase them from view
            let mut recent_alerts: Vec<String> = Vec::new();
            let mut ticks: u64 = 0;
            let interrupted;
            loop {
                // kill -HUP: re-fold the config file under the startup
                // flags — alert latches and recordings stay put
                if take_sighup() {
                    cli = reload_resolved(&cli_base);
                    write_out(&format!(
                        "SIGHUP: reloaded config from {}",
                        config::Config::path()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "(no path)".into()),
                    ));
                }
                // brief-process capture: drain the high-frequency poller —
                // each spawn-and-die becomes a line + ring/log entry
                if let Some(rx) = &brief_rx {
                    let mut briefs = Vec::new();
                    while let Ok(e) = rx.try_recv() {
                        briefs.push(e);
                    }
                    for e in briefs {
                        let who = if e.pid > 0 {
                            format!("{} (pid {})", e.name, e.pid)
                        } else {
                            e.name.clone()
                        };
                        let line = format!(">> brief: {who} — {}", e.detail);
                        if json_stream {
                            eprintln!("{line}");
                        } else {
                            write_out(&line);
                        }
                        if let Some(log) = events_file.as_mut() {
                            log.log_json(&e);
                        }
                        hist.ingest(vec![e]);
                    }
                }
                // container events: one line per death/OOM/health edge,
                // same stdout/jsonl/ring treatment as the brief captures
                if let Some(stream) = &container_stream {
                    let mut edges = Vec::new();
                    while let Ok(e) = stream.rx.try_recv() {
                        edges.push(e);
                    }
                    for e in edges {
                        let line = format!(">> container: {} — {}", e.name, e.detail);
                        if json_stream {
                            eprintln!("{line}");
                        } else {
                            write_out(&line);
                        }
                        if let Some(log) = events_file.as_mut() {
                            log.log_json(&e);
                        }
                        hist.ingest(vec![e]);
                    }
                }
                util::sd_notify("WATCHDOG=1");
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
                if let Some(log) = events_file.as_mut() {
                    for e in &fresh {
                        log.log_json(e);
                    }
                }
                if let Some(w) = recorder.as_mut() {
                    // --record samples the machine alongside the processes —
                    // a `_system` row (CSV) / `system` key (JSONL) per tick.
                    // The net rate rides the shared SysAlertState so an
                    // armed --alert-net and the recorder diff the same
                    // counter stream.
                    let stats = platform.system_stats();
                    let nics = platform.net_counters();
                    let total = nics
                        .iter()
                        .fold((0u64, 0u64), |(rx, tx), n| (rx + n.rx_bytes, tx + n.tx_bytes));
                    let net_bps =
                        history::machine_net_rate(total, &mut sys_alert).map(|mbps| mbps * 1048576.0);
                    w.append(&procs, &hist, stats.as_ref(), net_bps);
                }
                // --alert-net-per-proc: feed this tick's ss sweep into the
                // persistent history so per-pid rates exist to compare
                // (absent ss leaves the sentinel quiet, like the board)
                if cli.alert_net_per_proc.is_some() {
                    if let Some(sweep) = platform::net_bytes_per_pid() {
                        hist.update_net(&sweep);
                    }
                }
                let mut picks = watch_alert_picks(
                    platform.as_ref(),
                    &cli,
                    &procs,
                    &hist,
                    interval,
                    &mut alert_state,
                    &mut fd_counts,
                    &mut conn_counts,
                );
                if !alert_ports.is_empty() {
                    let socks = platform.list_sockets().unwrap_or_default();
                    picks.extend(port_alert_picks(
                        &alert_ports,
                        &socks,
                        &procs,
                        &mut port_seen,
                        &mut port_owner,
                    ).into_iter().map(|(pid, n, d)| (pid, n, d, false)));
                }
                // --alert-new-proc: one pick per first-seen name the mode
                // covers (the tracker remembers, so a name never re-fires)
                if let Some(w) = new_proc.as_mut() {
                    for p in &procs {
                        if w.first_sighting(&p.name) {
                            picks.push((
                                p.pid,
                                p.name.clone(),
                                "first sighting of this process name".into(),
                                false,
                            ));
                        }
                    }
                }
                // machine-wide alerts (--alert-load / --alert-mem-pct /
                // --alert-count / --alert-net): sample the whole system when
                // armed — macOS's vm_stat spawn and Windows's PowerShell
                // query are paid only when watched
                if cli.alert_load.is_some()
                    || cli.alert_mem_pct.is_some()
                    || cli.alert_count.is_some()
                    || cli.alert_disk.is_some()
                    || cli.alert_net.is_some()
                    || cli.alert_psi.is_some()
                    || cli.alert_mem_avail_mb.is_some()
                    || cli.alert_swap_pct.is_some()
                    || cli.alert_retrans.is_some()
                    || cli.alert_nic_drop.is_some()
                {
                    if let Some(stats) = platform.system_stats() {
                        let mounts = if cli.alert_disk.is_some() {
                            platform.mount_usage()
                        } else {
                            Vec::new()
                        };
                        // one NIC sweep feeds both the throughput and the
                        // drop sentinel (deltas live in sys_alert either way)
                        let net_armed = cli.alert_net.is_some() || cli.alert_nic_drop.is_some();
                        let (net_rate, drop_rate) = if net_armed {
                            let nics = platform.net_counters();
                            let (rx, tx, drops) = nics.iter().fold(
                                (0u64, 0u64, 0u64),
                                |(rx, tx, drops), n| {
                                    (
                                        rx + n.rx_bytes,
                                        tx + n.tx_bytes,
                                        drops + n.rx_drops + n.tx_drops,
                                    )
                                },
                            );
                            (
                                cli.alert_net
                                    .is_some()
                                    .then(|| history::machine_net_rate((rx, tx), &mut sys_alert))
                                    .flatten(),
                                cli.alert_nic_drop
                                    .is_some()
                                    .then(|| history::machine_drop_rate(drops, &mut sys_alert))
                                    .flatten(),
                            )
                        } else {
                            (None, None)
                        };
                        // retrans rate diffs SystemStats' cumulative counter
                        let retrans_rate = if cli.alert_retrans.is_some() {
                            stats.retrans_segs.and_then(|segs| {
                                history::machine_retrans_rate(segs, &mut sys_alert)
                            })
                        } else {
                            None
                        };
                        let limits = history::SysAlertLimits {
                            load: cli.alert_load,
                            mem_pct: cli.alert_mem_pct,
                            count: cli.alert_count,
                            proc_count: procs.len(),
                            mounts,
                            disk_pct: cli.alert_disk,
                            net_limit: cli.alert_net,
                            net_rate,
                            psi_limit: cli.alert_psi,
                            mem_avail_floor: cli.alert_mem_avail_mb,
                            swap_pct_limit: cli.alert_swap_pct,
                            retrans_limit: cli.alert_retrans.map(|v| v as f64),
                            retrans_rate,
                            drop_limit: cli.alert_nic_drop.map(|v| v as f64),
                            drop_rate,
                            repeat: cli.alert_repeat,
                        };
                        for (name, detail, rec) in history::system_alert_picks(
                            &stats,
                            &mut sys_alert,
                            &limits,
                            interval,
                        ) {
                            picks.push((0, name, detail, rec));
                        }
                    }
                }
                // --alert-container: kick a background enumeration when the
                // last one is old enough, then fold in whatever landed —
                // firings ride the same picks pipeline as every other alert
                if cli.alert_container {
                    if container_rx.is_none() {
                        let due = match container_swept_at {
                            Some(t) => t.elapsed() >= container_every,
                            None => true,
                        };
                        if due {
                            container_swept_at = Some(Instant::now());
                            let (tx, rx) = std::sync::mpsc::channel();
                            std::thread::spawn(move || {
                                let mut cs = platform::enumerate_containers();
                                let pods = k8s::pods().unwrap_or_default();
                                k8s::annotate_with(&pods, &mut cs);
                                for c in cs.iter_mut().filter(|c| c.state == "running") {
                                    if c.restarts.is_none() {
                                        c.restarts = platform::container_restarts(&c.runtime, &c.id);
                                    }
                                }
                                // cgroup oom_kill totals feed the climb edge —
                                // a restart policy hiding an OOM exit still trips
                                let pressure = platform::container_pressure();
                                for c in cs.iter_mut() {
                                    let key: String = c.id.chars().take(12).collect();
                                    if let Some(p) = pressure.get(&key) {
                                        c.throttled_usec = Some(p.throttled_usec);
                                        c.oom_kills = Some(p.oom_kills);
                                        c.io_read_bytes = Some(p.io_read);
                                        c.io_write_bytes = Some(p.io_write);
                                    }
                                }
                                let _ = tx.send((cs, pods));
                            });
                            container_rx = Some(rx);
                        }
                    }
                    if let Some(rx) = &container_rx {
                        if let Ok((cs, pods)) = rx.try_recv() {
                            container_rx = None;
                            for (name, detail) in
                                container_edges.update(&cs, &pods, container_stream.is_some())
                            {
                                picks.push((0, name, detail, false));
                            }
                        }
                    }
                }
                // --diff-auto: every N seconds, diff the live table against
                // the previous check (in-memory — no snapshot files) and
                // print the drift as plain report lines
                if let Some(every) = cli.diff_auto {
                    if last_diff.elapsed() >= Duration::from_secs(every.max(1)) {
                        last_diff = Instant::now();
                        let listeners = snapshot::to_listeners(
                            &platform.list_sockets().unwrap_or_default(),
                            &procs,
                        );
                        if let Some((old, old_listeners)) = last_frame.take() {
                            let mut entries = snapshot::diff(&old, &procs);
                            entries.extend(snapshot::diff_listeners(&old_listeners, &listeners));
                            if !entries.is_empty() {
                                // counts computed before the envelope move —
                                // the closure can't borrow what json! takes
                                let count =
                                    |k: &str| entries.iter().filter(|e| e.kind == k).count();
                                let (n_new, n_gone, n_restarted, n_changed) = (
                                    count("new"),
                                    count("gone"),
                                    count("restarted"),
                                    count("changed"),
                                );
                                let (n_lnew, n_lgone) =
                                    (count("listen-new"), count("listen-gone"));
                                if json_stream {
                                    // the --diff --json envelope shape, one
                                    // per drift check — jq can watch the pipe
                                    let doc = serde_json::json!({
                                        "schema_version": SCHEMA_VERSION,
                                        "generated_at": util::now_unix(),
                                        "summary": {
                                            "new": n_new,
                                            "gone": n_gone,
                                            "restarted": n_restarted,
                                            "changed": n_changed,
                                            "listen_new": n_lnew,
                                            "listen_gone": n_lgone,
                                            "total": entries.len(),
                                        },
                                        "entries": entries,
                                    });
                                    write_out(&serde_json::to_string_pretty(&doc)
                                        .unwrap_or_else(|_| "{}".into()));
                                } else {
                                    write_out(&format!(
                                        "== drift · {n_new} new / {n_gone} gone / {n_restarted} restarted / {n_changed} changed / {n_lnew} listen+ / {n_lgone} listen- =="
                                    ));
                                    write_out(&snapshot::render(&entries));
                                }
                            }
                        }
                        last_frame = Some((procs.clone(), listeners));
                    }
                }
                for (pid, name, detail, recovery) in picks {
                    // silence windows (--alert-silence) hold down both the
                    // alert and its recovery — the pick still lands in the
                    // events ring/log as "silenced" so the mute is visible,
                    // but no line, exec, webhook or notify fires
                    if history::silenced(&silence_rules, &name, util::now_unix() as u64) {
                        if events_file.is_some() {
                            let e = hist.push_kind("silenced", pid, &name, &detail);
                            if let Some(log) = events_file.as_mut() {
                                log.log_json(&e);
                            }
                        } else {
                            hist.push_kind("silenced", pid, &name, &detail);
                        }
                        continue;
                    }
                    // in JSON-stream mode the stdout pipe carries data only —
                    // alerts go to stderr so jq output stays parseable
                    let who = if pid > 0 {
                        format!("{name} (pid {pid})")
                    } else {
                        name.clone()
                    };
                    let kind = if recovery { "recovered" } else { "alert" };
                    let alert_line = format!(
                        "{} {who} — {detail}",
                        if recovery { "✔ recovered:" } else { "⚠ alert:" }
                    );
                    if json_stream {
                        eprintln!("{alert_line}");
                    } else {
                        write_out(&alert_line);
                    }
                    // same durable stream as the TUI: alerts and recoveries
                    // land in --events-log too, so --replay shows them later
                    if events_file.is_some() {
                        let e = hist.push_kind(kind, pid, &name, &detail);
                        if let Some(log) = events_file.as_mut() {
                            log.log_json(&e);
                        }
                    }
                    if let Some(cmd) = &cli.alert_exec {
                        tui::spawn_alert_exec(cmd, pid, &name, &detail, kind);
                    }
                    if let Some(hook) = &cli.alert_webhook {
                        tui::send_alert_webhook(hook, pid, &name, &detail, kind);
                    }
                    recent_alerts.push(format!(
                        "{} {who} — {detail}",
                        if recovery { "✔" } else { "⚠" }
                    ));
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

    // --wait: poll the targets once a second until they all resolve
    // (`here`, the default — falls through to the normal output) or all
    // stop resolving (`gone` — one confirmation line, exit 0). --timeout
    // turns "not yet" into exit 124.
    let mut waited_reports: Option<Vec<TargetReport>> = None;
    if let Some(what) = cli.wait.as_deref() {
        let want_gone = what == "gone";
        let deadline = cli
            .timeout
            .filter(|t| *t > 0)
            .map(|t| Instant::now() + Duration::from_secs(t));
        install_sigint_flag();
        loop {
            let reports = pipeline::run(platform.as_ref(), specs.clone(), &opts);
            let all_present =
                !reports.is_empty() && reports.iter().all(|r| !r.matches.is_empty());
            if want_gone {
                if !all_present {
                    let names: Vec<String> =
                        reports.iter().map(|r| r.target.describe()).collect();
                    write_out(&format!("gone: {}", names.join(", ")));
                    std::process::exit(0);
                }
            } else if all_present {
                waited_reports = Some(reports);
                break;
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                eprintln!(
                    "--wait: gave up after {}s — target{} still {}",
                    cli.timeout.unwrap_or(0),
                    if specs.len() > 1 { "s" } else { "" },
                    if want_gone { "running" } else { "absent" }
                );
                std::process::exit(124);
            }
            if !sleep_interruptible(1) {
                std::process::exit(130);
            }
        }
    }
    let reports = match waited_reports {
        Some(r) => r,
        None => pipeline::run(platform.as_ref(), specs, &opts),
    };

    // --pids-only: the matched pids as one space-separated line — the
    // xargs/kill pipe shape
    if cli.pids_only {
        let mut pids: Vec<Pid> = reports
            .iter()
            .flat_map(|r| r.matches.iter().map(|m| m.pid))
            .collect();
        pids.sort_unstable();
        pids.dedup();
        if pids.is_empty() {
            std::process::exit(2);
        }
        write_out(&pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(" "));
        std::process::exit(0);
    }

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
                let grep_note = cli
                    .grep
                    .as_deref()
                    .map(|g| format!(" · grep '{g}'"))
                    .unwrap_or_default();
                write_out(&format!(
                    "== recent logs · {} ({what}){grep_note} ==",
                    src.describe()
                ));
                match logs::fetch(&src, n.max(1) as usize) {
                    Ok(lines) if lines.is_empty() => {
                        write_out("(no log entries found for this process)");
                    }
                    Ok(lines) => match cli.grep.as_deref() {
                        Some(pattern) => {
                            let hits: Vec<&String> =
                                lines.iter().filter(|l| l.contains(pattern)).collect();
                            if hits.is_empty() {
                                write_out(&format!("(no log lines matching '{pattern}')"));
                            }
                            for l in hits {
                                write_out(l);
                            }
                        }
                        None => {
                            for l in lines {
                                write_out(&l);
                            }
                        }
                    },
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

    #[test]
    fn parse_alert_port_accepts_port_and_negation() {
        assert_eq!(parse_alert_port("8080"), Some((8080, false)));
        assert_eq!(parse_alert_port("!8080"), Some((8080, true)));
        assert_eq!(parse_alert_port(""), None);
        assert_eq!(parse_alert_port("!"), None);
        assert_eq!(parse_alert_port("nope"), None);
        assert_eq!(parse_alert_port("99999"), None);
    }

    #[test]
    fn service_definitions_carry_the_flag_set() {
        let cli = Cli::parse_from([
            "witr-rs",
            "--watch",
            "5",
            "nginx",
            "--alert-cpu",
            "90",
            "--alert-silence",
            "backup=30m",
            "--alert-new-proc",
            "xmrig",
            "--alert-port",
            "9090",
            "--events-log",
            "/tmp/ev.jsonl",
            "--quiet",
        ]);
        let args = service_flag_args(&cli);
        // the serialized flag set re-parses to the same knobs
        assert_eq!(
            args,
            vec![
                "--watch", "5", "nginx", "--alert-cpu", "90", "--alert-silence", "backup=30m",
                "--alert-new-proc", "xmrig", "--alert-port", "9090", "--events-log",
                "/tmp/ev.jsonl", "--quiet"
            ]
        );
        let unit = systemd_unit("/usr/local/bin/witr-rs", &args);
        assert!(unit.contains("ExecStart=/usr/local/bin/witr-rs --watch 5 nginx"));
        assert!(unit.contains("WantedBy=default.target"));
        // the baked --watch 5 pings every 5s → WatchdogSec with headroom
        assert!(unit.contains("WatchdogSec=60"), "interval*3, 60s floor:\n{unit}");
        // no --watch in the args → no watchdog line (nothing pings)
        let bare = systemd_unit("/usr/local/bin/witr-rs", &["nginx".to_string()]);
        assert!(!bare.contains("WatchdogSec"));
        // a long interval scales the deadline past its ping cadence
        let slow = systemd_unit(
            "/usr/local/bin/witr-rs",
            &["--watch".to_string(), "90".to_string()],
        );
        assert!(slow.contains("WatchdogSec=270"), "90s interval → 270s deadline:\n{slow}");
        let plist = launchd_plist("/usr/local/bin/witr-rs", &args);
        assert!(plist.contains("<string>/usr/local/bin/witr-rs</string>"));
        assert!(plist.contains("<string>--alert-cpu</string>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        let task = schtasks_xml("/usr/local/bin/witr-rs", &args);
        assert!(task.contains("<Command>"));
        assert!(task.contains("BootTrigger"));
        // shell commands with XML-special chars survive the plist
        let plist = launchd_plist("/bin/sh", &["-c".into(), "notify-send \"a<b&c\"".into()]);
        assert!(plist.contains("notify-send"));
        assert!(!plist.contains("a<b&c"), "raw XML metacharacters must be escaped");
        assert!(plist.contains("a&lt;b&amp;c"));
    }

    #[test]
    fn port_alert_picks_arms_then_fires_edges() {
        let sock = |port: u16, pid: Option<Pid>| crate::model::Socket {
            proto: "tcp".into(),
            local_addr: "0.0.0.0".into(),
            local_port: port,
            peer_addr: None,
            peer_port: None,
            state: "LISTEN".into(),
            pid,
        };
        let procs = vec![proc(5, "nginx", None, None)];
        let armed = vec![(8080u16, false), (9090u16, true)];
        let up = vec![sock(8080, Some(5))];
        let mut seen = HashMap::new();
        let mut owner = HashMap::new();

        // first sighting only arms — whatever is up at startup is the
        // status quo, not an event
        assert!(port_alert_picks(&armed, &up, &procs, &mut seen, &mut owner).is_empty());

        // 8080 vanishes → quiet (a plain arm reports appears only);
        // 9090 still absent → quiet
        let empty: Vec<crate::model::Socket> = Vec::new();
        assert!(port_alert_picks(&armed, &empty, &procs, &mut seen, &mut owner).is_empty());

        // 8080 returns → appear fires, carrying the owning pid
        let hits = port_alert_picks(&armed, &up, &procs, &mut seen, &mut owner);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 5);
        assert_eq!(hits[0].1, ":8080");
        assert!(hits[0].2.contains("listener appeared on :8080"));

        // 9090 comes up (arms silently), then goes away → the negated arm
        // fires gone with the remembered owner
        let both = vec![sock(8080, Some(5)), sock(9090, Some(5))];
        assert!(port_alert_picks(&armed, &both, &procs, &mut seen, &mut owner).is_empty());
        let hits = port_alert_picks(&armed, &up, &procs, &mut seen, &mut owner);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, 0);
        assert!(hits[0].2.contains("listener gone from :9090 (was nginx (pid 5))"));
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
        let top = top_procs(&procs, cli::TopMetric::Cpu, 2, None, None, None);
        let names: Vec<&str> = top.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["b", "c"]);
        // mem ranking uses the same rows, different key
        let top_mem = top_procs(&procs, cli::TopMetric::Mem, 1, None, None, None);
        assert_eq!(top_mem[0].name, "b");
        // fd with no map → nothing
        assert!(top_procs(&procs, cli::TopMetric::Fd, 5, None, None, None).is_empty());
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
    fn rotation_caps_long_running_writers() {
        // RecordWriter: cap of one byte rotates on every append — the .1
        // generation holds the older rows, the fresh file carries the CSV
        // header so --plot/--samples keep reading it without special cases
        let path = std::env::temp_dir().join(format!("witr-rot-{}.csv", std::process::id()));
        let mut w = RecordWriter::create_with_cap(path.to_str().unwrap(), Some(1)).unwrap();
        let hist = history::History::new();
        let procs = vec![proc(3, "worker", None, None)];
        w.append(&procs, &hist, None, None);
        w.append(&procs, &hist, None, None);
        let rotated = path.with_file_name(format!(
            "{}.1",
            path.file_name().unwrap().to_str().unwrap()
        ));
        assert!(rotated.exists(), "first generation rolled aside");
        assert_eq!(
            std::fs::read_to_string(&rotated).unwrap().lines().count(),
            2,
            "header + row (no stats → no _system row)"
        );
        let cur = std::fs::read_to_string(&path).unwrap();
        assert!(cur.starts_with("timestamp,"), "fresh file re-carries the header");
        assert_eq!(cur.lines().count(), 2, "header + the second append's row");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&rotated);

        // EventLog: append-mode, cap zero rotates before every write —
        // each generation holds exactly one line
        let epath = std::env::temp_dir().join(format!("witr-evlog-{}.jsonl", std::process::id()));
        let mut log = EventLog::create(epath.to_str().unwrap(), Some(0)).unwrap();
        log.log_json(&serde_json::json!({"n": 1}));
        log.log_json(&serde_json::json!({"n": 2}));
        let erotated = epath.with_file_name(format!(
            "{}.1",
            epath.file_name().unwrap().to_str().unwrap()
        ));
        let first = std::fs::read_to_string(&erotated).unwrap();
        assert!(first.contains("\"n\":1"), "{first}");
        let cur = std::fs::read_to_string(&epath).unwrap();
        assert!(cur.contains("\"n\":2"), "{cur}");
        let _ = std::fs::remove_file(&epath);
        let _ = std::fs::remove_file(&erotated);

        // no cap → nothing ever rotates
        let epath = std::env::temp_dir().join(format!("witr-evlog2-{}.jsonl", std::process::id()));
        let mut log = EventLog::create(epath.to_str().unwrap(), None).unwrap();
        log.log_json(&serde_json::json!({"n": 1}));
        log.log_json(&serde_json::json!({"n": 2}));
        assert!(
            !epath
                .with_file_name(format!("{}.1", epath.file_name().unwrap().to_str().unwrap()))
                .exists()
        );
        assert_eq!(std::fs::read_to_string(&epath).unwrap().lines().count(), 2);
        let _ = std::fs::remove_file(&epath);
    }

    #[test]
    fn record_writer_writes_header_and_rows() {
        let path = std::env::temp_dir().join(format!("witr-record-{}.csv", std::process::id()));
        let mut w = RecordWriter::create(path.to_str().unwrap()).unwrap();
        let mut hist = history::History::new();
        let procs = vec![proc(3, "worker", None, Some(2048))];
        let _ = hist.update(&procs); // first sample: no cpu/io deltas yet
        let stats = crate::platform::SystemStats {
            load1: Some(1.25),
            mem_used_mb: Some(4096),
            mem_total_mb: Some(16384),
            ..Default::default()
        };
        w.append(&procs, &hist, Some(&stats), None);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "timestamp,pid,user,name,cpu_pct,rss_mb,io_read_bps,io_write_bps,gpu_sm,\
             sys_load1,sys_mem_pct,sys_procs,sys_net_bps"
        );
        assert_eq!(lines.len(), 3, "header + process row + _system row");
        let row = lines[1];
        // first sample: no cpu/io deltas yet → empty cells; rss 2048 KiB → 2
        let fields: Vec<&str> = row.split(',').collect();
        assert_eq!(fields.len(), 13, "{row}");
        assert_eq!((fields[1], fields[2], fields[3]), ("3", "-", "worker"), "{row}");
        assert_eq!(fields[4], "", "no cpu delta on the first sample: {row}");
        assert_eq!(fields[5], "2", "2048 KiB → 2 MB rss: {row}");
        assert_eq!((fields[6], fields[7], fields[8]), ("", "", ""), "no io/gpu yet: {row}");
        assert!(
            (fields[9], fields[10], fields[11], fields[12]) == ("", "", "", ""),
            "per-process rows leave the sys_* columns empty: {row}"
        );
        // the machine's own row: load, mem pct (4096/16384 = 25) and the
        // visible count land in the sys_* columns; no net rate on tick one
        let sys: Vec<&str> = lines[2].split(',').collect();
        assert_eq!(sys.len(), 13, "{}", lines[2]);
        assert_eq!(sys[1], "_system");
        assert_eq!(sys[4], "", "machine cpu is a delta — empty on tick one");
        assert_eq!(sys[5], "4096", "used MB rides the rss column");
        assert_eq!((sys[9], sys[10], sys[11], sys[12]), ("1.25", "25", "1", ""), "{}", lines[2]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn parse_record_system_reads_writer_csv_round_trip() {
        let path = std::env::temp_dir().join(format!("witr-plot-{}.csv", std::process::id()));
        let mut w = RecordWriter::create(path.to_str().unwrap()).unwrap();
        let mut hist = history::History::new();
        let procs = vec![proc(3, "worker", None, None)];
        let _ = hist.update(&procs);
        let stats = crate::platform::SystemStats {
            load1: Some(1.5),
            mem_used_mb: Some(4096),
            mem_total_mb: Some(16384),
            ..Default::default()
        };
        w.append(&procs, &hist, Some(&stats), Some(8_388_608.0)); // 8 MB/s
        w.append(&procs, &hist, Some(&stats), None);
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();
        let pts = parse_record_system(&text).unwrap();
        assert_eq!(pts.len(), 2, "one point per _system row");
        assert_eq!(pts[0].load1, Some(1.5));
        assert_eq!(pts[0].mem_pct, Some(25.0), "4096/16384");
        assert_eq!(pts[0].procs, 1);
        assert_eq!(pts[0].net_bps, Some(8_388_608.0));
        assert_eq!(pts[0].cpu, None, "machine cpu is a delta — empty on tick one");
        assert!(pts[0].at > 1_600_000_000 && pts[1].at >= pts[0].at, "timestamps parse as unix seconds");
        assert_eq!(pts[1].net_bps, None);
        // the process row must not leak into the samples
        // (already implied by len == 2)
    }

    #[test]
    fn parse_record_system_reads_jsonl_and_errors_on_empty() {
        let jsonl = concat!(
            r#"{"generated_at":1700000100,"system":{"load1":0.5,"cpu_pct":12.5,"mem_pct":40.0,"proc_count":210,"net_bps":1024.0}}"#, "\n",
            "not json at all\n",
            r#"{"generated_at":1700000160,"system":null}"#, "\n",
            r#"{"generated_at":1700000220,"system":{"load1":1.0,"mem_pct":50.0,"proc_count":220}}"#, "\n",
        );
        let pts = parse_record_system(jsonl).unwrap();
        assert_eq!(pts.len(), 2, "null-system ticks and unparseable lines are skipped");
        assert_eq!(pts[0].at, 1_700_000_100);
        assert_eq!(pts[0].cpu, Some(12.5));
        assert_eq!(pts[0].procs, 210);
        assert_eq!(pts[1].cpu, None);
        assert_eq!(pts[1].net_bps, None);
        // error surface: empty / headerless / no system rows at all
        assert!(parse_record_system("").is_err());
        assert!(parse_record_system("timestamp,pid\n").is_err(), "csv without _system rows");
        assert!(parse_record_system("no system key\n").is_err(), "jsonl without system samples");
    }

    #[test]
    fn plot_html_embeds_one_chart_per_series() {
        let pts = vec![
            SysPoint { at: 1_700_000_100, cpu: Some(12.5), mem_pct: Some(40.0), load1: Some(0.5), procs: 210, net_bps: Some(1_048_576.0) },
            SysPoint { at: 1_700_000_160, cpu: Some(25.0), mem_pct: Some(50.0), load1: Some(1.0), procs: 220, net_bps: None },
        ];
        let html = plot_html(&pts);
        assert!(html.starts_with("<!doctype html>"));
        assert!(
            html.contains("2 samples"),
            "{}",
            html.get(..120).unwrap_or("")
        );
        assert_eq!(html.matches("<svg").count(), 5, "cpu/mem/load/net/processes");
        assert_eq!(html.matches("<polyline").count(), 5);
        assert!(html.contains("network"), "the MB/s conversion is labelled");
        // every chart carries its last-value label
        assert!(html.contains("25.0 %"), "cpu last label");
        assert!(html.contains("max 27.5"), "max is 25 * 1.1");
    }

    #[test]
    fn plot_html_multi_overlays_files_on_a_shared_clock() {
        let mk = |cpu: f64, at: i64| SysPoint {
            at,
            cpu: Some(cpu),
            mem_pct: Some(40.0 + cpu),
            load1: Some(cpu / 10.0),
            procs: 200 + cpu as usize,
            net_bps: Some(1_000_000.0 + cpu),
        };
        let a = ("before.csv".to_string(), vec![mk(10.0, 1_700_000_000), mk(20.0, 1_700_000_060)]);
        // file b starts later and runs longer — the overlay still lines both
        // up on the global time axis (t0 = a's first, t1 = b's last)
        let b = ("after.csv".to_string(), vec![mk(55.0, 1_700_000_030), mk(5.0, 1_700_000_120)]);
        let html = plot_html_multi(&[a, b]);
        assert!(html.contains("before.csv"), "legend names every file");
        assert!(html.contains("after.csv"));
        assert_eq!(html.matches("<svg").count(), 5, "same five charts");
        // two polylines per chart — one per file
        assert_eq!(html.matches("<polyline").count(), 10);
        // the global window spans both files, and both colors appear
        assert!(html.contains("■"), "legend swatches rendered");
        assert!(html.contains("#ff6b6b"), "second file's palette color present");
        assert!(html.contains("4 samples"), "sample count is the sum");
    }

    #[test]
    fn record_writer_jsonl_appends_versioned_envelopes() {
        let path = std::env::temp_dir().join(format!("witr-record-{}.jsonl", std::process::id()));
        let mut w = RecordWriter::create(path.to_str().unwrap()).unwrap();
        assert!(w.jsonl, "the extension selects the format");
        let mut hist = history::History::new();
        let procs = vec![proc(9, "daemon", None, Some(8192))];
        let _ = hist.update(&procs);
        let stats = crate::platform::SystemStats {
            load1: Some(2.5),
            mem_used_mb: Some(8192),
            mem_total_mb: Some(32768),
            ..Default::default()
        };
        w.append(&procs, &hist, Some(&stats), Some(2_000_000.0));
        w.append(&procs, &hist, None, None);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one envelope per tick, no header");
        let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(v["schema_version"], SCHEMA_VERSION, "{}", lines[0]);
        assert_eq!(v["process_count"], 1);
        assert_eq!(v["processes"][0]["pid"], 9);
        assert_eq!(v["processes"][0]["rss_mb"], 8);
        assert_eq!(v["processes"][0]["ppid"], serde_json::Value::Null);
        // the machine rides along: load, mem pct (8192/32768 = 25), visible
        // count, and the net rate in bytes/s
        assert_eq!(v["system"]["load1"], 2.5);
        assert_eq!(v["system"]["mem_pct"], 25);
        assert_eq!(v["system"]["proc_count"], 1);
        assert_eq!(v["system"]["net_bps"], 2_000_000.0);
        // a tick without a system sample keeps the key, null-filled
        let v2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert!(v2["system"].is_null());
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

    #[test]
    fn top_procs_threads_and_conn_rank() {
        let mut a = proc(1, "a", None, None);
        a.threads = Some(4);
        let mut b = proc(2, "b", None, None);
        b.threads = Some(64);
        let c = proc(3, "c", None, None); // no thread data → drops out
        let top = top_procs(&[a, b, c], cli::TopMetric::Threads, 10, None, None, None);
        assert_eq!(top.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["b", "a"]);

        let mut conns = HashMap::new();
        conns.insert(1, 7u64);
        conns.insert(2, 2u64);
        let top = top_procs(
            &[proc(1, "a", None, None), proc(2, "b", None, None)],
            cli::TopMetric::Conn,
            10,
            None,
            None,
            Some(&conns),
        );
        assert_eq!(top.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["a", "b"]);
    }

    #[test]
    fn watch_alert_threads_fires_after_streak() {
        let cli = cli::Cli::parse_from(["witr", "--alert-threads", "100"]);
        let platform = NoPlatform;
        let hist = history::History::new();
        let mut state = HashMap::new();
        let mut fds = HashMap::new();
        let mut conns = HashMap::new();
        let mut leaky = proc(9, "leaky", None, None);
        leaky.threads = Some(120);
        let leaky = vec![leaky];
        for _ in 0..history::ALERT_CYCLES - 1 {
            assert!(watch_alert_picks(&platform, &cli, &leaky, &hist, 1, &mut state, &mut fds, &mut conns).is_empty());
        }
        let fired = watch_alert_picks(&platform, &cli, &leaky, &hist, 1, &mut state, &mut fds, &mut conns);
        assert_eq!(fired.len(), 1, "{fired:?}");
        assert!(fired[0].2.contains("120 thread(s) above 100"), "{}", fired[0].2);
        // latched until the count drops back under
        assert!(watch_alert_picks(&platform, &cli, &leaky, &hist, 1, &mut state, &mut fds, &mut conns).is_empty());
    }

    #[test]
    fn watch_alert_net_per_proc_fires_after_streak() {
        let cli = cli::Cli::parse_from(["witr", "--alert-net-per-proc", "1"]);
        let platform = NoPlatform;
        let mut hist = history::History::new();
        let mut state = HashMap::new();
        let mut fds = HashMap::new();
        let mut conns = HashMap::new();
        let leaky = vec![proc(9, "leaky", None, None)];
        // baseline sweep, then 8 MB between sweeps ~80ms apart (~100 MB/s)
        let mut sweep: HashMap<Pid, u64> = [(9, 0)].into_iter().collect();
        hist.update_net(&sweep);
        std::thread::sleep(Duration::from_millis(80));
        sweep.insert(9, 800_000);
        hist.update_net(&sweep);
        for _ in 0..history::ALERT_CYCLES - 1 {
            assert!(
                watch_alert_picks(&platform, &cli, &leaky, &hist, 1, &mut state, &mut fds, &mut conns)
                    .is_empty()
            );
        }
        let fired =
            watch_alert_picks(&platform, &cli, &leaky, &hist, 1, &mut state, &mut fds, &mut conns);
        assert_eq!(fired.len(), 1, "{fired:?}");
        assert!(fired[0].2.contains("above 1 MB/s"), "{}", fired[0].2);
        // latched while it stays over the line
        assert!(
            watch_alert_picks(&platform, &cli, &leaky, &hist, 1, &mut state, &mut fds, &mut conns)
                .is_empty()
        );
    }

    #[test]
    fn sys_frame_diffs_nic_rates_against_previous_sweep() {
        struct NetPlatform {
            rx: std::sync::atomic::AtomicU64,
        }
        impl Platform for NetPlatform {
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
            fn net_counters(&self) -> Vec<platform::NicCounters> {
                use std::sync::atomic::Ordering::Relaxed;
                vec![platform::NicCounters {
                    name: "eth0".into(),
                    rx_bytes: self.rx.load(Relaxed),
                    tx_bytes: 0,
                    rx_drops: 0,
                    tx_drops: 0,
                }]
            }
        }
        use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
        let platform = NetPlatform { rx: AtomicU64::new(0) };
        let mut prev = None;
        // first frame arms only — no rates yet
        let f = sys_frame(&platform, &mut prev, 3);
        assert!(f.nics.is_empty());
        assert_eq!(f.procs, 3);
        // 1 MB arriving over ~60 ms → a real rx rate on the second frame
        platform.rx.store(1024 * 1024, Relaxed);
        std::thread::sleep(Duration::from_millis(60));
        let frame = sys_frame(&platform, &mut prev, 3);
        assert_eq!(frame.nics.len(), 1);
        assert_eq!(frame.nics[0].0, "eth0");
        assert!(frame.nics[0].1 > 1.0, "rx MB/s: {:?}", frame.nics);
        assert_eq!(frame.nics[0].2, 0.0);
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
