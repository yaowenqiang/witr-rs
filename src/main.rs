mod ancestry;
mod audit;
mod doctor;
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

/// --remote core: fetch the process tables from one or more `witr-rs
/// --serve` peers (`/api/ps`) and push them through the same renderers as
/// the local listing — a fleet's dashboards over plain HTTP, no local
/// sampling. One host renders exactly as before; several hosts render
/// one divider-labeled section each (unreachable hosts report a ⚠ line
/// and never sink the rest — every host down exits 5). `--tree` is
/// presentation only: the flat table comes over the wire and the forest
/// is built locally, so both sides agree on the shape. `--watch N`
/// re-fetches on an interval until Ctrl-C.
/// The /api/ps envelope's machine snapshot, parsed back into the same
/// shapes the local sentinels judge — stats for [`system_alert_picks`],
/// cumulative NIC totals for the rate diffs, the mount sweep for the
/// disk/disk-eta sentinels. `None` when the server predates the `system`
/// key (older witr-rs --serve) — machine sentinels disarm for that host,
/// the table still renders.
#[derive(Clone)]
struct FleetSample {
    stats: crate::platform::SystemStats,
    net: Option<(u64, u64, u64)>,
    /// Per-NIC cumulative counters — the fleet --sys diffs them into
    /// rates (totals live in `net`; these feed the dashboard's NIC rows).
    /// Empty from servers predating the field.
    nics: Vec<crate::platform::NicCounters>,
    /// The far host's own failed-unit list — the snapshot carries it, so
    /// the fleet --alert-failed-units sentinel judges remotely what the
    /// local sweep could never see. Empty from servers predating the
    /// field (an honest "nothing seen").
    failed_units: Vec<String>,
    /// The far host's own service cgroup memory, (unit, bytes) biggest
    /// first — the fleet --alert-service-mem sentinel's input and the
    /// fleet --sys services line. Empty from servers predating the field.
    service_mems: Vec<(String, u64)>,
    /// Held-deleted space total + the biggest holders, per the far host's
    /// own walk — the fleet --alert-deleted-gb sentinel's input.
    deleted_reclaimable_mb: u64,
    deleted_files: Vec<crate::platform::DeletedFile>,
    mounts: Vec<crate::platform::MountUsage>,
}

fn parse_system_snapshot(doc: &serde_json::Value) -> Option<FleetSample> {
    let s = doc.get("system")?;
    if s.is_null() {
        return None;
    }
    let f = |k: &str| s.get(k).and_then(|v| v.as_f64());
    let u = |k: &str| s.get(k).and_then(|v| v.as_u64());
    let psi = s.get("psi").and_then(|p| p.as_object()).map(|p| {
        let g = |k: &str| p.get(k).and_then(|v| v.as_f64()).unwrap_or(0.0);
        crate::platform::PsiStats {
            cpu_some: g("cpu_some"),
            cpu_full: g("cpu_full"),
            mem_some: g("mem_some"),
            mem_full: g("mem_full"),
            io_some: g("io_some"),
            io_full: g("io_full"),
        }
    });
    let net = s.get("net").and_then(|n| n.as_object()).map(|n| {
        let g = |k: &str| n.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        (g("rx_bytes"), g("tx_bytes"), g("drop_total"))
    });
    let nics = s
        .get("nics")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|n| {
                    Some(crate::platform::NicCounters {
                        name: n.get("name")?.as_str()?.to_string(),
                        rx_bytes: n.get("rx_bytes").and_then(|v| v.as_u64()).unwrap_or(0),
                        tx_bytes: n.get("tx_bytes").and_then(|v| v.as_u64()).unwrap_or(0),
                        rx_drops: n.get("rx_drops").and_then(|v| v.as_u64()).unwrap_or(0),
                        tx_drops: n.get("tx_drops").and_then(|v| v.as_u64()).unwrap_or(0),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let failed_units = s
        .get("failed_units")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|u| u.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let service_mems = s
        .get("service_mems")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    Some((
                        m.get("unit")?.as_str()?.to_string(),
                        m.get("mem_bytes")?.as_u64()?,
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    let gpus = s
        .get("gpus")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|g| {
                    Some(crate::gpu::GpuSample {
                        id: g.get("id")?.as_str()?.to_string(),
                        name: g.get("name")?.as_str()?.to_string(),
                        util_pct: g.get("util_pct").and_then(|v| v.as_f64()),
                        mem_used_mb: g.get("mem_used_mb").and_then(|v| v.as_u64())?,
                        mem_total_mb: g.get("mem_total_mb").and_then(|v| v.as_u64())?,
                        temp_c: g.get("temp_c").and_then(|v| v.as_f64()),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let deleted_reclaimable_mb =
        s.get("deleted_reclaimable_mb").and_then(|v| v.as_u64()).unwrap_or(0);
    let deleted_files = s
        .get("deleted_files")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|d| {
                    Some(crate::platform::DeletedFile {
                        pid: d.get("pid")?.as_i64()? as Pid,
                        name: d.get("name")?.as_str()?.to_string(),
                        path: d.get("path")?.as_str()?.to_string(),
                        size_mb: d.get("size_mb")?.as_u64()?,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let disks = s
        .get("disks")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|d| {
                    Some(crate::platform::DiskIoSample {
                        device: d.get("device")?.as_str()?.to_string(),
                        busy_pct: d.get("busy_pct").and_then(|v| v.as_f64()),
                        in_flight: d
                            .get("in_flight")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u32,
                        read_iops: d.get("read_iops").and_then(|v| v.as_f64()),
                        write_iops: d.get("write_iops").and_then(|v| v.as_f64()),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let mounts = s
        .get("mounts")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    Some(crate::platform::MountUsage {
                        target: m.get("target")?.as_str()?.to_string(),
                        total_mb: m.get("total_mb")?.as_u64()?,
                        used_mb: m.get("used_mb")?.as_u64()?,
                        ..Default::default()
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(FleetSample {
        stats: crate::platform::SystemStats {
            load1: f("load1"),
            load5: f("load5"),
            load15: f("load15"),
            cpu_percent: f("cpu_pct"),
            mem_used_mb: u("mem_used_mb"),
            mem_total_mb: u("mem_total_mb"),
            mem_avail_mb: u("mem_avail_mb"),
            swap_used_mb: u("swap_used_mb"),
            swap_total_mb: u("swap_total_mb"),
            psi,
            temp: s.get("temp_c").and_then(|t| t.as_f64()).map(|c| ("remote".into(), c)),
            retrans_segs: u("retrans_segs"),
            oom_kills: u("oom_kills"),
            disks,
            gpus,
            ..Default::default()
        },
        net,
        nics,
        failed_units,
        service_mems,
        deleted_reclaimable_mb,
        deleted_files,
        mounts,
    })
}

/// One fleet host's /api/ps: the process table plus the machine snapshot.
fn fetch_fleet(base: &str) -> Result<(Vec<Process>, Option<FleetSample>), String> {
    let url = format!("{}/api/ps", base.trim_end_matches('/'));
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
    Ok((procs, parse_system_snapshot(&doc)))
}

/// The machine-wide sentinel flags, as the fleet watch judges them —
/// per-host state keeps the streaks/latches independent. The per-process
/// family can't work remotely (fd/conn/io/deviation probe the local
/// machine), so the entry points reject it instead of half-working.
fn fleet_machine_armed(cli: &cli::Cli) -> bool {
    cli.alert_load.is_some()
        || cli.alert_mem_pct.is_some()
        || cli.alert_count.is_some()
        || cli.alert_disk.is_some()
        || cli.alert_disk_eta.is_some()
        || cli.alert_mem_eta.is_some()
        || cli.alert_disk_busy.is_some()
        || cli.alert_temp.is_some()
        || cli.alert_zombies.is_some()
        || cli.alert_dstate.is_some()
        || cli.alert_failed_units.is_some()
        || cli.alert_net.is_some()
        || cli.alert_psi.is_some()
        || cli.alert_mem_avail_mb.is_some()
        || cli.alert_swap_pct.is_some()
        || cli.alert_retrans.is_some()
        || cli.alert_nic_drop.is_some()
        || cli.alert_oom.is_some()
        || cli.alert_baseline.is_some()
}

fn reject_fleet_per_process_alerts(cli: &cli::Cli) {
    if cli.alert_timers_stale.is_some() {
        eprintln!(
            "--alert-timers-stale judges timers via the local systemd; the fleet snapshot doesn't carry timer data — run it per host"
        );
        std::process::exit(4);
    }
    let per_process = cli.alert_cpu.is_some()
        || cli.alert_mem.is_some()
        || cli.alert_fd.is_some()
        || cli.alert_io.is_some()
        || cli.alert_conn.is_some()
        || cli.alert_threads.is_some()
        || cli.alert_net_per_proc.is_some()
        || cli.alert_leak.is_some()
        || cli.alert_fd_leak.is_some()
        || cli.alert_thr_leak.is_some()
        || cli.alert_exe_changed
        || cli.alert_new_remote
        || cli.alert_deviation.is_some()
        || !cli.alert_new_proc.is_empty()
        || !cli.alert_port.is_empty()
        || cli.alert_container;
    if per_process {
        eprintln!(
            "fleet mode runs the machine-wide sentinels (--alert-load/--alert-mem-pct/--alert-psi/...); per-process thresholds probe the local machine and are local-only"
        );
        std::process::exit(4);
    }
}

/// A fleet host's machine-sentinel verdicts: fold one snapshot into the
/// host's alert state and return the picks. Reuses the local machinery
/// wholesale — [`history::system_alert_picks`] over a per-host
/// [`history::SysAlertState`] (streaks, latches and the disk-eta history
/// all live in there, keyed by host at the caller).
/// Diff one fleet snapshot's cumulative counters into the per-host rate
/// values (net throughput, NIC drops, TCP retransmits, OOM window) —
/// the first call seeds, the second reads. Shared by the fleet watch
/// and the fleet check.
fn fleet_rates(
    cli: &cli::Cli,
    sample: &FleetSample,
    st: &mut history::SysAlertState,
) -> (
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<u64>,
) {
    let net_rate = if cli.alert_net.is_some() {
        sample
            .net
            .and_then(|(rx, tx, _)| history::machine_net_rate((rx, tx), st))
    } else {
        None
    };
    let drop_rate = if cli.alert_nic_drop.is_some() {
        sample
            .net
            .and_then(|(_, _, drops)| history::machine_drop_rate(drops, st))
    } else {
        None
    };
    let retrans_rate = if cli.alert_retrans.is_some() {
        sample
            .stats
            .retrans_segs
            .and_then(|segs| history::machine_retrans_rate(segs, st))
    } else {
        None
    };
    let oom_window = if cli.alert_oom.is_some() {
        sample
            .stats
            .oom_kills
            .map(|k| history::machine_oom_window(k, st, 1))
    } else {
        None
    };
    (net_rate, drop_rate, retrans_rate, oom_window)
}

type FleetFetch = Vec<(String, Result<(Vec<Process>, Option<FleetSample>), String>)>;
/// (host, pid) → the previous sweep's cumulative io bytes (the fleet io-rate diff's baseline).
type HashIo = std::collections::HashMap<(String, Pid), (u64, u64)>;

fn fleet_alert_picks(
    cli: &cli::Cli,
    sample: &FleetSample,
    procs: &[Process],
    st: &mut history::SysAlertState,
    interval: u64,
) -> Vec<history::SysPick> {
    let (net_rate, drop_rate, retrans_rate, _oom_window) = fleet_rates(cli, sample, st);
    let limits = history::SysAlertLimits {
        load: cli.alert_load,
        mem_pct: cli.alert_mem_pct,
        count: cli.alert_count,
        proc_count: procs.len(),
        mounts: sample.mounts.clone(),
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
        oom_limit: cli.alert_oom,
        oom_kills: sample.stats.oom_kills,
        disk_eta_hours: cli.alert_disk_eta,
        mem_eta_hours: cli.alert_mem_eta,
        inodes_limit: cli.alert_inodes,
        // the far host's whole-GPU readings and its held-deleted story
        // both ride the snapshot — the sentinels judge them here like
        // every machine reading
        gpu_mem_pct_limit: cli.alert_gpu_mem_pct,
        gpus: sample.stats.gpus.clone(),
        deleted_gb_limit: cli.alert_deleted_gb,
        deleted_files: sample.deleted_files.clone(),
        deleted_total_mb: sample.deleted_reclaimable_mb,
        disk_busy_limit: cli.alert_disk_busy,
        temp_limit: cli.alert_temp,
        zombie_limit: cli.alert_zombies,
        zombie_count: state_count(procs, &["Z"]),
        dstate_limit: cli.alert_dstate,
        dstate_count: state_count(procs, &["D", "U"]),
        // the failed-unit list rides the snapshot (the far host sweeps
        // its own systemctl per refresh) — the sentinel judges it here
        failed_limit: cli.alert_failed_units,
        failed_units: sample.failed_units.clone(),
        // the far host's service cgroup memory rides the snapshot (v0.78
        // peers) — the sentinel judges it here like every machine reading
        service_mem_limit: cli.alert_service_mem,
        service_mems: sample.service_mems.clone(),
        repeat: cli.alert_repeat,
    };
    history::system_alert_picks(&sample.stats, st, &limits, interval)
}

fn remote_mode(bases: &[String], cli: &cli::Cli, no_color: bool) {
    reject_fleet_per_process_alerts(cli);
    let fetch = |base: &str| -> Result<(Vec<Process>, Option<FleetSample>), String> {
        fetch_fleet(base)
    };
    // fleet rows carry their owning host when more than one peer is in
    // play — the top board's HOST column, the CSV host column and the
    // JSON host field all read it (single-host remote stays host-less,
    // exactly like local output)
    let multi = bases.len() > 1;
    let fetch_all = || -> FleetFetch {
        bases
            .iter()
            .map(|b| {
                let mut r = (b.clone(), fetch(b));
                if multi {
                    let label = crate::util::display_host(b);
                    if let Ok((ps, _)) = &mut r.1 {
                        for p in ps.iter_mut() {
                            p.host = Some(label.clone());
                        }
                    }
                }
                r
            })
            .collect()
    };

    // --outliers: the fleet compared against itself — per metric, each
    // host's robust z-score against the fleet median, hosts at/over the
    // threshold named worst-first. A different question from every other
    // fleet surface: not "how is each machine" but "which machine is off".
    if let Some(threshold) = cli.outliers {
        if cli.watch.is_some() {
            eprintln!("--outliers is one-shot; drop --watch");
            std::process::exit(4);
        }
        let results = fetch_all();
        let outliers = fleet_outliers(&results, threshold);
        let failed: Vec<&String> = results
            .iter()
            .filter(|(_, r)| r.is_err())
            .map(|(b, _)| b)
            .collect();
        if cli.json {
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "threshold": threshold,
                "hosts_reported": results.iter().filter(|(_, r)| r.is_ok()).count(),
                "outliers": outliers,
                "unreachable": failed,
            });
            write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
        } else if outliers.is_empty() {
            write_out(&format!(
                "✔ no outliers at |z| ≥ {threshold} across {} host(s){}",
                results.iter().filter(|(_, r)| r.is_ok()).count(),
                if failed.is_empty() {
                    String::new()
                } else {
                    format!(" · unreachable: {}", failed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))
                }
            ));
        } else {
            let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
            write_out(&format!(
                "{} outlier(s) at |z| ≥ {threshold} (fleet median per metric):",
                outliers.len()
            ));
            for o in &outliers {
                let line = format!(
                    "[{}] {} = {:.1} — fleet median {:.1}, |z| = {:.1}",
                    o.host, o.metric, o.value, o.median, o.z.abs()
                );
                write_out(&format!("⚠ {}", painter.red(&line)));
            }
            if !failed.is_empty() {
                write_out(&format!(
                    "· unreachable (skipped): {}",
                    failed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                ));
            }
        }
        std::process::exit(if outliers.is_empty() { 0 } else { 1 });
    }

    // --top across the fleet: merge the fetched tables and rank once. The
    // table-carried metrics (cpu/mem/age/threads/swap) work; anything
    // needing a local probe (fd/conn/io-rate/net/gpu) is refused with the
    // supported set named — a silent whole-table render used to eat the
    // flag.
    if let Some(metric) = cli.top {
        if !matches!(
            metric,
            cli::TopMetric::Cpu
                | cli::TopMetric::Mem
                | cli::TopMetric::Age
                | cli::TopMetric::Threads
                | cli::TopMetric::Swap
                | cli::TopMetric::Gpu
                | cli::TopMetric::GpuMem
                | cli::TopMetric::Io
        ) {
            eprintln!(
                "--top {metric:?} across --remote hosts reads the fetched process tables; fd/conn/net need local probes — use cpu/mem/age/threads/swap/gpu/gpu-mem/io (cumulative io rides the table; io-rate diffs two fetches)"
            );
            std::process::exit(4);
        }
        let color = !no_color && std::io::stdout().is_terminal();
        let painter = render::Painter::new(color);
        let count = cli.count.unwrap_or(15);
        let draw = |results: &FleetFetch,
                    prev_io: Option<&HashIo>,
                    elapsed: f64|
         -> String {
            let mut procs: Vec<Process> = Vec::new();
            for (_, result) in results {
                if let Ok((ps, _)) = result {
                    procs.extend(ps.iter().cloned());
                }
            }
            // the io-rate board needs its diffed values: fold the per-pid
            // rates into the rows' cumulative io fields (host+pid keyed),
            // so ranking and rendering see bytes/s like the local board
            if metric == cli::TopMetric::IoRate {
                if let Some(prev) = prev_io {
                    let rates = fleet_io_rates(prev, results, elapsed);
                    for p in procs.iter_mut() {
                        if let Some((r, w)) =
                            rates.get(&(p.host.clone().unwrap_or_default(), p.pid))
                        {
                            p.io_read_bytes = Some(*r as u64);
                            p.io_write_bytes = Some(*w as u64);
                        }
                    }
                }
            }
            // the machine-readable formats draw the exact board as rows:
            // json keeps the versioned envelope (host rides every row),
            // csv/markdown mirror the local twins' shapes
            if cli.by_user {
                let rows = render::rank_by_user(&procs, metric, count, None, None, None);
                if cli.json {
                    return json_user_envelope(&rows);
                }
                if cli.csv {
                    return render::render_top_by_user_csv(&rows);
                }
                if cli.markdown {
                    return render::render_top_by_user_markdown(&rows, metric);
                }
                return render::render_top_by_user(&rows, metric, &painter);
            }
            if cli.json {
                return json_envelope(&fleet_ranked(&procs, metric, count));
            }
            if cli.csv {
                return render::render_csv(&fleet_ranked(&procs, metric, count));
            }
            if cli.markdown {
                return render::render_markdown(&fleet_ranked(&procs, metric, count));
            }
            render::render_top(&procs, metric, count, None, None, None, &painter)
        };
        match cli.watch {
            Some(secs) => {
                let interval = secs.max(1);
                install_sigint_flag();
                let mut prev_io: Option<HashIo> = None;
                let label = bases.join(" · ");
                let mut ticks = 0u64;
                loop {
                    let results = fetch_all();
                    if !cli.quiet {
                        write_out("\x1b[2J\x1b[1;1H");
                        let now = util::fmt_time(util::now_unix());
                        write_out(&format!(
                            "witr-rs fleet top {} · {} host(s) · {label} · every {interval}s · {now} · Ctrl-C to stop",
                            format!("{metric:?}").to_lowercase(),
                            bases.len()
                        ));
                    }
                    // io-rate diffs against the previous tick's fetch
                    // (the first tick arms only, like the local board)
                    let elapsed_io = interval as f64;
                    write_out(&draw(&results, prev_io.as_ref(), elapsed_io));
                    if metric == cli::TopMetric::IoRate {
                        prev_io = Some(fleet_io_prev(&results));
                    }
                    ticks += 1;
                    if cli.times.is_some_and(|n| ticks >= n.max(1)) {
                        return;
                    }
                    if !sleep_interruptible(interval) {
                        return;
                    }
                }
            }
            None => {
                // one-shot io-rate: two fetches a second apart (the local
                // board's trick) — the first arms the per-pid baseline
                let (prev_io, elapsed_io) = if metric == cli::TopMetric::IoRate {
                    let first = fetch_all();
                    let prev = fleet_io_prev(&first);
                    std::thread::sleep(Duration::from_secs(1));
                    (Some(prev), 1.0)
                } else {
                    (None, 0.0)
                };
                let results = fetch_all();
                write_out(&draw(&results, prev_io.as_ref(), elapsed_io));
                return;
            }
        }
    }

    // --services across the fleet: every peer's unit list merged into one
    // table, running units first, HOST column when more than one peer is
    // in play. --failed intersects each peer's own failed-unit list from
    // the snapshot (a peer predating it honestly reports "nothing seen").
    if cli.services {
        if cli.watch.is_some() && (cli.json || cli.csv || cli.markdown) {
            eprintln!("machine-readable --services is one-shot; drop --watch or the format flag");
            std::process::exit(4);
        }
        let multi = bases.len() > 1;
        // one sweep: per-peer unit table (+ the snapshot's failed list
        // when --failed asks) merged, running units first
        let sweep = |failed_lists: &mut HashMap<String, Vec<String>>,
                     failed_peers: &mut usize|
         -> Vec<crate::model::Service> {
            if cli.failed {
                for base in bases {
                    match fetch_fleet(base) {
                        Ok((_, Some(sample))) => {
                            failed_lists.insert(base.clone(), sample.failed_units);
                        }
                        _ => {
                            failed_lists.insert(base.clone(), Vec::new());
                        }
                    }
                }
            }
            let mut svcs: Vec<crate::model::Service> = Vec::new();
            for base in bases {
                let label = crate::util::display_host(base);
                match fetch_fleet_services(base) {
                    Ok(mut table) => {
                        if multi {
                            for s in table.iter_mut() {
                                s.host = Some(label.clone());
                            }
                        }
                        if cli.failed {
                            let failed: std::collections::HashSet<&str> = failed_lists
                                .get(base)
                                .map(|l| l.iter().map(String::as_str).collect())
                                .unwrap_or_default();
                            table.retain(|s| failed.contains(s.name.as_str()));
                        }
                        svcs.extend(table);
                    }
                    Err(e) => {
                        *failed_peers += 1;
                        eprintln!("⚠ --remote {base}: {e}");
                    }
                }
            }
            render::sort_services(&mut svcs);
            svcs
        };
        let mut failed_peers = 0usize;
        let mut failed_lists: HashMap<String, Vec<String>> = HashMap::new();
        if cli.watch.is_some() {
            // the fleet family's text refresh: clear, header, re-merge
            let interval = cli.watch.unwrap_or(3).max(1);
            install_sigint_flag();
            let mut ticks = 0u64;
            loop {
                let svcs = sweep(&mut failed_lists, &mut failed_peers);
                if !cli.quiet {
                    write_out("\x1b[2J\x1b[1;1H");
                    let now = util::fmt_time(util::now_unix());
                    write_out(&format!(
                        "witr-rs fleet services · {} host(s) · every {interval}s · {now} · Ctrl-C to stop",
                        bases.len()
                    ));
                }
                let painter =
                    render::Painter::new(!no_color && std::io::stdout().is_terminal());
                write_out(&render::render_services(&svcs, &painter));
                ticks += 1;
                if cli.times.is_some_and(|n| ticks >= n.max(1)) {
                    return;
                }
                if !sleep_interruptible(interval) {
                    return;
                }
            }
        }
        let svcs = sweep(&mut failed_lists, &mut failed_peers);
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
            let mut body = render::render_services(&svcs, &painter);
            if multi {
                // the fleet banner the other fleet surfaces carry
                let heads: Vec<String> =
                    bases.iter().map(|b| crate::util::display_host(b)).collect();
                body.push_str(&format!("\n{} host(s) · {}\n", bases.len(), heads.join(" · ")));
            }
            write_out(&body);
        }
        if failed_peers == bases.len() {
            std::process::exit(5);
        }
        std::process::exit(0);
    }

    // --sys across the fleet: every peer's machine dashboard in one sweep —
    // the machine snapshot already rides the /api/ps envelope, so this is
    // pure rendering. `--watch` turns it into the estate's cockpit.
    if cli.sys {
        // machine-readable frames are one-shot, same rule as the local --sys
        if cli.watch.is_some() && (cli.json || cli.csv || cli.markdown) {
            eprintln!("machine-readable --sys is one-shot; drop --watch or the format flag");
            std::process::exit(4);
        }
        let multi = bases.len() > 1;
        // one rate-diff state per host — each machine's counters diff
        // against its own previous sweep, carried across ticks
        let mut net_prevs: HashMap<String, Option<(Vec<crate::platform::NicCounters>, Instant)>> =
            HashMap::new();
        let frames = |results: &FleetFetch,
                      net_prevs: &mut HashMap<
            String,
            Option<(Vec<crate::platform::NicCounters>, Instant)>,
        >|
         -> Vec<(String, Option<render::SysFrame>)> {
            results
                .iter()
                .map(|(base, result)| {
                    let frame = result.as_ref().ok().and_then(|(procs, sample)| {
                        sample
                            .as_ref()
                            .map(|smp| {
                                let prev = net_prevs.entry(base.clone()).or_default();
                                fleet_sys_frame(smp, procs, prev)
                            })
                    });
                    (base.clone(), frame)
                })
                .collect()
        };
        let draw = |results: &FleetFetch,
                    painter: &render::Painter,
                    net_prevs: &mut HashMap<
            String,
            Option<(Vec<crate::platform::NicCounters>, Instant)>,
        >|
         -> String {
            let mut out = String::new();
            for (base, entry) in frames(results, net_prevs) {
                let Some(frame) = entry else {
                    if multi {
                        out.push_str(&format!("----- [{base}] -----\nfetch failed\n"));
                    }
                    continue;
                };
                if multi {
                    out.push_str(&format!("----- [{base}] -----\n"));
                }
                if cli.json {
                    let doc = serde_json::json!({
                        "schema_version": SCHEMA_VERSION,
                        "generated_at": util::now_unix(),
                        "hosts": [render::sys_json(&frame, Some(&base))],
                    });
                    out.push_str(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
                    out.push('\n');
                } else if cli.csv {
                    out.push_str(&render::render_sys_csv(&frame));
                } else if cli.markdown {
                    out.push_str(&render::render_sys_markdown(&frame));
                } else {
                    out.push_str(&render::render_sys(&frame, painter));
                }
            }
            out
        };
        let color = !no_color && std::io::stdout().is_terminal();
        let painter = render::Painter::new(color);
        match cli.watch {
            Some(secs) => {
                let interval = secs.max(1);
                install_sigint_flag();
                let label = bases.join(" · ");
                let mut ticks = 0u64;
                loop {
                    let results = fetch_all();
                    if !cli.quiet {
                        write_out("\x1b[2J\x1b[1;1H");
                        let now = util::fmt_time(util::now_unix());
                        write_out(&format!(
                            "witr-rs fleet sys · {} host(s) · {label} · every {interval}s · {now} · Ctrl-C to stop",
                            bases.len()
                        ));
                    }
                    write_out(&draw(&results, &painter, &mut net_prevs));
                    ticks += 1;
                    if cli.times.is_some_and(|n| ticks >= n.max(1)) {
                        return;
                    }
                    if !sleep_interruptible(interval) {
                        return;
                    }
                }
            }
            None => {
                // NIC rates are a delta metric: two fetches a second
                // apart arm then feed the diff, the same trick the local
                // one-shot --sys runs (the first sweep only arms, so it
                // goes through frames and its output is dropped)
                let first = fetch_all();
                frames(&first, &mut net_prevs);
                std::thread::sleep(Duration::from_secs(1));
                let results = fetch_all();
                write_out(&draw(&results, &painter, &mut net_prevs));
                return;
            }
        }
    }
    let render_host = |procs: &[Process]| -> String {
        let color = !no_color && std::io::stdout().is_terminal() && !cli.json;
        let painter = render::Painter::new(color);
        if cli.csv {
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
        let mut events_file = match &cli.events_log {
            Some(path) => match EventLog::create(path, cli.record_max_mb) {
                Ok(l) => Some(l),
                Err(e) => {
                    eprintln!("--events-log {path}: {e}");
                    std::process::exit(5);
                }
            },
            None => None,
        };
        // one alert state per host — streaks, latches and the disk-eta
        // trend windows stay independent per machine
        let mut states: HashMap<String, history::SysAlertState> = HashMap::new();
        // the --alert-baseline norm: loaded once, judged per host (the
        // /api/ps processes carry name/exe/user — identity comparison is
        // exactly what the local judge does)
        let baseline: Option<(Vec<Process>, Vec<snapshot::Listener>, Vec<String>)> =
            match &cli.alert_baseline {
                Some(path) => match snapshot::load_baseline(path) {
                    Ok(b) => Some(b),
                    Err(e) => {
                        eprintln!("--alert-baseline {path}: {e}");
                        std::process::exit(4);
                    }
                },
                None => None,
            };
        let mut baseline_reported: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        let mut last_err: HashMap<String, String> = HashMap::new();
        install_sigint_flag();
        let label = bases.join(" · ");
        let mut ticks = 0u64;
        loop {
            let results = fetch_all();
            if redraw {
                write_out("\x1b[2J\x1b[1;1H");
                let now = util::fmt_time(util::now_unix());
                write_out(&format!(
                    "witr-rs remote · {} host(s) · {label} · every {interval}s · {now} · Ctrl-C to stop",
                    bases.len()
                ));
            }
            for (base, result) in &results {
                match result {
                    Ok((procs, sample)) => {
                        if bases.len() > 1 {
                            write_out(&format!("----- [{base}] -----"));
                        }
                        if json_stream {
                            write_out(&json_listing_output(procs, cli.tree));
                        } else {
                            write_out(&render_host(procs));
                        }
                        // the fleet sentinels: same machinery as the local
                        // --watch loop, one state per host, alerts name it
                        if let Some((base_procs, _, _base_services)) = &baseline {
                            // the security baseline judges the fetched
                            // table per host: new identities fire once
                            // each (vanishing doesn't — exit events have
                            // their own bookkeeping)
                            let now_ids = snapshot::identity_set(procs);
                            let base_ids = snapshot::identity_set(base_procs);
                            let mut new_ids: Vec<&String> =
                                now_ids.difference(&base_ids).collect();
                            new_ids.sort();
                            for id in new_ids {
                                if !baseline_reported.insert((base.clone(), id.clone())) {
                                    continue;
                                }
                                let who = procs
                                    .iter()
                                    .find(|p| crate::util::identity_key(p) == **id)
                                    .map(|p| {
                                        format!(
                                            "{} (pid {}, user {})",
                                            p.name,
                                            p.pid,
                                            p.user.as_deref().unwrap_or("-")
                                        )
                                    })
                                    .unwrap_or_default();
                                emit_fleet_pick(
                                    cli,
                                    base,
                                    "baseline",
                                    &format!("new process identity: {who} [{id}]"),
                                    false,
                                    json_stream,
                                    events_file.as_mut(),
                                );
                            }
                        }
                        if fleet_machine_armed(cli) {
                            let Some(sample) = sample else {
                                continue; // server predates the system key
                            };
                            let st = states.entry(base.clone()).or_default();
                            for (name, detail, rec) in
                                fleet_alert_picks(cli, sample, procs, st, interval)
                            {
                                emit_fleet_pick(
                                    cli,
                                    base,
                                    &name,
                                    &detail,
                                    rec,
                                    json_stream,
                                    events_file.as_mut(),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        // a flapping fetch error prints once per change,
                        // not once per tick
                        if last_err.get(base).map(|p| p != e).unwrap_or(true) {
                            eprintln!("⚠ --remote {base}: {e}");
                            last_err.insert(base.clone(), e.clone());
                        }
                    }
                }
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
    let results = fetch_all();
    let failed = results.iter().filter(|(_, r)| r.is_err()).count();
    if cli.json && bases.len() > 1 {
        // the fleet envelope, once: per-host entries in the order the
        // flags came, errors preserved as entries
        let doc = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "generated_at": util::now_unix(),
            "host_count": bases.len(),
            "hosts": results.iter().map(|(b, r)| match r {
                Ok((procs, _sample)) => serde_json::json!({
                    "host": b,
                    "process_count": procs.len(),
                    "processes": procs,
                }),
                Err(e) => serde_json::json!({"host": b, "error": e}),
            }).collect::<Vec<_>>(),
        });
        write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
    } else {
        for (base, result) in &results {
            match result {
                Ok((procs, _sample)) => {
                    if bases.len() > 1 {
                        write_out(&format!("----- [{base}] -----"));
                    }
                    if cli.json {
                        write_out(&json_listing_output(procs, cli.tree));
                    } else {
                        write_out(&render_host(procs));
                    }
                }
                Err(e) => eprintln!("⚠ --remote {base}: {e}"),
            }
        }
    }
    if failed == bases.len() {
        std::process::exit(5);
    }
}

/// One fleet sentinel pick, through the same side-effect pipeline as the
/// local --watch loop: stdout line (stderr under --json so jq stays
/// parseable), --events-log (the host rides as its own field), then
/// --alert-exec / --alert-webhook with the host prefixed to the detail.
fn emit_fleet_pick(
    cli: &cli::Cli,
    host: &str,
    name: &str,
    detail: &str,
    recovery: bool,
    json_stream: bool,
    mut events_file: Option<&mut EventLog>,
) {
    let kind = if recovery { "recovered" } else { "alert" };
    let e = history::TuiEvent {
        at_unix: util::now_unix(),
        kind: kind.to_string(),
        pid: 0,
        name: name.to_string(),
        detail: detail.to_string(),
    };
    if let Some(log) = events_file.as_mut() {
        log.log_json(&serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "at_unix": e.at_unix,
            "kind": e.kind,
            "pid": e.pid,
            "name": e.name,
            "detail": e.detail,
            "host": host,
        }));
    }
    let who = format!("[{host}] {name}");
    let line = format!(
        "{} {who} — {detail}",
        if recovery { "✔ recovered:" } else { "⚠ alert:" }
    );
    if json_stream {
        eprintln!("{line}");
    } else {
        write_out(&line);
    }
    let effect_detail = format!("[{host}] {detail}");
    if let Some(cmd) = &cli.alert_exec {
        tui::spawn_alert_exec(cmd, 0, name, &effect_detail, kind);
    }
    if let Some(hook) = &cli.alert_webhook {
        tui::send_alert_webhook(hook, 0, name, &effect_detail, kind);
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
                cli::TopMetric::Swap => p.swap_kb.map(|kb| kb as f64),
            }?;
            Some((v, p))
        })
        .collect();
    ranked.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    ranked.truncate(count.max(1));
    ranked.into_iter().map(|(_, p)| p.clone()).collect()
}

/// One peer's /api/services table — the fleet --services merge's input.
/// The snapshot's service_mems pairs would cover the mem column, but the
/// full unit list (state, desc, pid) only lives on this endpoint.
fn fetch_fleet_services(base: &str) -> Result<Vec<crate::model::Service>, String> {
    let url = format!("{}/api/services", base.trim_end_matches('/'));
    let body = util::http_get(&url)?;
    let doc: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("response is not JSON: {e}"))?;
    let svcs = doc
        .get("services")
        .and_then(|v| serde_json::from_value::<Vec<crate::model::Service>>(v.clone()).ok())
        .ok_or_else(|| "envelope has no parseable services table".to_string())?;
    Ok(svcs)
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
    procs: &[Process],
) -> render::SysFrame {
    let stats = platform.system_stats().unwrap_or_default();
    // the state waterlines the sentinels watch, from the table the caller
    // swept; failed units cost one systemctl sweep (None hides the line)
    let zombies = state_count(procs, &["Z"]);
    let dstates = state_count(procs, &["D", "U"]);
    let failed_units = platform.failed_units().unwrap_or_default();
    // one service sweep per frame — the failed-units sweep already pays
    // this cost class; biggest few only, the line names three
    let mut service_mems: Vec<(String, u64)> = crate::platform::enumerate_services()
        .iter()
        .filter_map(|s| s.mem_current.map(|m| (s.name.clone(), m)))
        .collect();
    service_mems.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
    service_mems.truncate(5);
    let deleted_files = platform.deleted_files();
    let deleted_total_mb = deleted_files.iter().map(|d| d.size_mb).sum();
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
        procs: procs.len(),
        zombies,
        dstates,
        failed_units,
        service_mems,
        deleted_files,
        deleted_total_mb,
    }
}

/// One fleet `--sys` frame from a peer's machine snapshot — the local
/// [`sys_frame`]'s remote twin. Per-NIC rates stay empty (the fleet
/// snapshot carries machine-wide totals, not per-interface counters), and
/// failed systemd units stay unknown (they live on the far host); the
/// state waterlines count from the fetched table, which does carry the
/// state letters.
fn fleet_sys_frame(
    sample: &FleetSample,
    procs: &[Process],
    net_prev: &mut Option<(Vec<crate::platform::NicCounters>, Instant)>,
) -> render::SysFrame {
    // per-NIC rates: this sweep's cumulative counters minus the previous
    // sweep's, over the elapsed wall time — the local sys_frame's diff,
    // fed from the snapshot's counters instead of a local netstat
    let mut nics: Vec<(String, f64, f64)> = Vec::new();
    if let Some((prev, at)) = net_prev.as_ref() {
        let elapsed = at.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            for c in &sample.nics {
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
    *net_prev = Some((sample.nics.clone(), Instant::now()));
    render::SysFrame {
        stats: sample.stats.clone(),
        mounts: sample.mounts.clone(),
        nics,
        procs: procs.len(),
        zombies: state_count(procs, &["Z"]),
        dstates: state_count(procs, &["D", "U"]),
        // the far host's own failed-unit list rides the snapshot — the
        // red line renders per host like every other reading here
        failed_units: sample.failed_units.clone(),
        // service cgroups ride the snapshot too (v0.78 peers); older
        // servers leave it empty — an honest "nothing seen"
        service_mems: sample.service_mems.clone(),
        deleted_files: sample.deleted_files.clone(),
        deleted_total_mb: sample.deleted_reclaimable_mb,
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

/// `--top --by-user --json`: the same versioned envelope shape over the
/// user rollup — `users` in place of `processes`.
pub(crate) fn json_user_envelope(rows: &[render::UserBoardRow]) -> String {
    let doc = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "generated_at": util::now_unix(),
        "user_count": rows.len(),
        "users": rows,
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
/// `--check`: one pass over the armed `--alert-*` thresholds. Levels are
/// single comparisons; rates take two samples a second apart (the
/// --top io-rate trick), which is also what the per-process CPU counters
/// and the machine NIC/TCP/OOM diffs need — every cumulative counter is
/// seeded on sweep 1 and diffed on sweep 2. Returns the exit code: 1
/// when anything sits over its line, 0 when clean. The history-hungry
/// sentinels (disk-eta trend, deviation baseline, new-process, port
/// canary, container edges) stay --watch's territory — a one-shot has no
/// trailing window to judge them with.
fn run_check_once(platform: &dyn Platform, cli: &cli::Cli) -> i32 {
    let armed = cli.alert_cpu.is_some()
        || cli.alert_mem.is_some()
        || cli.alert_fd.is_some()
        || cli.alert_io.is_some()
        || cli.alert_conn.is_some()
        || cli.alert_threads.is_some()
        || cli.alert_net_per_proc.is_some()
        || cli.alert_load.is_some()
        || cli.alert_mem_pct.is_some()
        || cli.alert_count.is_some()
        || cli.alert_disk.is_some()
        || cli.alert_disk_eta.is_some()
        || cli.alert_mem_eta.is_some()
        || cli.alert_inodes.is_some()
        || cli.alert_net.is_some()
        || cli.alert_psi.is_some()
        || cli.alert_mem_avail_mb.is_some()
        || cli.alert_swap_pct.is_some()
        || cli.alert_retrans.is_some()
        || cli.alert_nic_drop.is_some()
        || cli.alert_oom.is_some()
        || cli.alert_disk_busy.is_some()
        || cli.alert_gpu_mem_pct.is_some()
        || cli.alert_deleted_gb.is_some()
        || cli.alert_temp.is_some()
        || cli.alert_zombies.is_some()
        || cli.alert_dstate.is_some()
        || cli.alert_failed_units.is_some()
        || cli.alert_container_cpu.is_some()
        || cli.alert_container_mem_pct.is_some();
    if !armed {
        eprintln!(
            "--check evaluates --alert-* thresholds; arm at least one (e.g. --check --alert-cpu 90 --alert-load 4)"
        );
        std::process::exit(4);
    }
    let rate_checks = cli.alert_cpu.is_some()
        || cli.alert_io.is_some()
        || cli.alert_net_per_proc.is_some()
        || cli.alert_net.is_some()
        || cli.alert_retrans.is_some()
        || cli.alert_nic_drop.is_some()
        || cli.alert_oom.is_some()
        // busy% needs a previous tick to diff against
        || cli.alert_disk_busy.is_some();

    let sweep = || -> Vec<Process> {
        let mut procs = match platform.list_processes() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cannot list processes: {e}");
                std::process::exit(5);
            }
        };
        platform.enrich_listing(&mut procs);
        procs
    };

    let mut hist = history::History::new();
    // one shared state diffs sweep 1 → sweep 2 for every machine rate
    let mut sys = history::SysAlertState::default();

    // sweep 1: seeds every cumulative counter
    let procs1 = sweep();
    let _ = hist.update(&procs1);
    let nc1 = (cli.alert_net.is_some() || cli.alert_nic_drop.is_some())
        .then(|| platform.net_counters());
    let stats1 = platform.system_stats();
    if cli.alert_retrans.is_some() {
        if let Some(segs) = stats1.as_ref().and_then(|s| s.retrans_segs) {
            let _ = history::machine_retrans_rate(segs, &mut sys);
        }
    }
    if cli.alert_oom.is_some() {
        if let Some(kills) = stats1.as_ref().and_then(|s| s.oom_kills) {
            let _ = history::machine_oom_window(kills, &mut sys, 1);
        }
    }

    if rate_checks {
        std::thread::sleep(Duration::from_secs(1));
    }

    // sweep 2: the reading the verdicts come from
    let procs = sweep();
    let _ = hist.update(&procs);
    let nc2 = nc1.is_some().then(|| platform.net_counters());
    let stats = platform.system_stats().unwrap_or_default();
    let retrans_rate = if cli.alert_retrans.is_some() {
        stats
            .retrans_segs
            .and_then(|segs| history::machine_retrans_rate(segs, &mut sys))
    } else {
        None
    };
    let oom_in_window = if cli.alert_oom.is_some() {
        stats.oom_kills.map(|k| history::machine_oom_window(k, &mut sys, 1))
    } else {
        None
    };
    let fold = |nics: &[platform::NicCounters]| {
        nics.iter().fold((0u64, 0u64, 0u64), |(rx, tx, dr), n| {
            (rx + n.rx_bytes, tx + n.tx_bytes, dr + n.rx_drops + n.tx_drops)
        })
    };
    let (net_rate, drop_rate) = match (nc1.as_ref(), nc2.as_ref()) {
        (Some(a), Some(b)) => {
            let _ = history::machine_net_rate((fold(a).0, fold(a).1), &mut sys);
            let _ = history::machine_drop_rate(fold(a).2, &mut sys);
            let rate = history::machine_net_rate((fold(b).0, fold(b).1), &mut sys);
            let drop = history::machine_drop_rate(fold(b).2, &mut sys);
            (rate, drop)
        }
        _ => (None, None),
    };

    let mut violations: Vec<(Pid, String, String)> = Vec::new();

    // ---- per-process thresholds over the fresh table ----
    let fd_counts = if cli.alert_fd.is_some() {
        platform.fd_counts().unwrap_or_default()
    } else {
        HashMap::new()
    };
    let conn_counts = if cli.alert_conn.is_some() {
        tui::established_per_pid(&platform.list_all_sockets().unwrap_or_default())
    } else {
        HashMap::new()
    };
    for p in &procs {
        if let Some(limit) = cli.alert_cpu {
            if let Some(c) = hist.cpu_now.get(&p.pid) {
                if *c > limit {
                    violations.push((p.pid, p.name.clone(), format!("CPU {c:.0}% above {limit}%")));
                }
            }
        }
        if let Some(limit_mb) = cli.alert_mem {
            let mb = p.mem_kb.map(|kb| kb / 1024);
            if mb.is_some_and(|m| m > limit_mb) {
                violations.push((
                    p.pid,
                    p.name.clone(),
                    format!("RSS {} MB above {limit_mb} MB", mb.unwrap_or(0)),
                ));
            }
        }
        if let Some(limit) = cli.alert_fd {
            let n = fd_counts.get(&p.pid).copied();
            if n.is_some_and(|c| c > limit) {
                violations.push((
                    p.pid,
                    p.name.clone(),
                    format!("{} open fds above {limit}", n.unwrap_or(0)),
                ));
            }
        }
        if let Some(limit) = cli.alert_conn {
            let n = conn_counts.get(&p.pid).copied();
            if n.is_some_and(|c| c > limit) {
                violations.push((
                    p.pid,
                    p.name.clone(),
                    format!("{} established connection(s) above {limit}", n.unwrap_or(0)),
                ));
            }
        }
        if let Some(limit) = cli.alert_threads {
            let n = p.threads.map(|t| t as u64);
            if n.is_some_and(|c| c > limit) {
                violations.push((
                    p.pid,
                    p.name.clone(),
                    format!("{} thread(s) above {limit}", n.unwrap_or(0)),
                ));
            }
        }
        if let Some(limit) = cli.alert_io {
            let bps = hist.io_rate_of(p.pid).map(|(r, w)| r + w);
            if bps.is_some_and(|b| b > limit * 1024.0 * 1024.0) {
                violations.push((
                    p.pid,
                    p.name.clone(),
                    format!(
                        "I/O {:.1} MB/s above {limit} MB/s",
                        bps.unwrap_or(0.0) / 1024.0 / 1024.0
                    ),
                ));
            }
        }
        if let Some(limit) = cli.alert_net_per_proc {
            let rate = hist.net_rate_of(p.pid);
            if rate.is_some_and(|r| r > limit as f64 * 1024.0 * 1024.0) {
                violations.push((
                    p.pid,
                    p.name.clone(),
                    format!(
                        "TCP {r:.1} MB/s above {limit} MB/s",
                        r = rate.unwrap_or(0.0) / 1024.0 / 1024.0
                    ),
                ));
            }
        }
    }

    // ---- machine-wide thresholds over the fresh snapshot ----
    let mounts = if cli.alert_disk.is_some() {
        platform.mount_usage()
    } else {
        Vec::new()
    };
    let zombie_count = state_count(&procs, &["Z"]);
    let dstate_count = state_count(&procs, &["D", "U"]);
    // the failed-unit sweep is one systemctl call, paid only when armed
    let failed_units = if cli.alert_failed_units.is_some() {
        platform.failed_units().unwrap_or_default()
    } else {
        Vec::new()
    };
    let deleted_files = if cli.alert_deleted_gb.is_some() {
        platform.deleted_files()
    } else {
        Vec::new()
    };
    let service_mems = if cli.alert_service_mem.is_some() {
        let mut pairs: Vec<(String, u64)> = crate::platform::enumerate_services()
            .iter()
            .filter_map(|s| s.mem_current.map(|m| (s.name.clone(), m)))
            .collect();
        pairs.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
        pairs
    } else {
        Vec::new()
    };
    let mut machine_lines = machine_check_lines(
        cli,
        &stats,
        &mounts,
        &deleted_files,
        procs.len(),
        zombie_count,
        dstate_count,
        &failed_units,
        &service_mems,
        net_rate,
        drop_rate,
        retrans_rate,
        oom_in_window,
    );
    attribute_oom_lines(&mut machine_lines, platform);
    for detail in machine_lines {
        violations.push((0, "system".into(), detail));
    }
    for (name, detail) in container_check_lines(cli, &container_check_sweep()) {
        violations.push((0, name, detail));
    }

    if cli.json {
        let doc = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "generated_at": util::now_unix(),
            "violations": violations
                .iter()
                .map(|(pid, name, detail)| serde_json::json!({
                    "pid": pid,
                    "name": name,
                    "detail": detail,
                }))
                .collect::<Vec<_>>(),
        });
        write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
    } else if violations.is_empty() {
        write_out("✔ all armed checks clean");
    } else {
        for (pid, name, detail) in &violations {
            let who = if *pid == 0 {
                name.clone()
            } else {
                format!("{name} (pid {pid})")
            };
            write_out(&format!("⚠ {who} — {detail}"));
        }
        write_out(&format!("{} violation(s)", violations.len()));
    }
    i32::from(!violations.is_empty())
}

/// The kernel log's account of an OOM firing — ` — victims: nginx (pid
/// 123), python (pid 456)` — or None when the log is unreadable or names
/// nobody.
fn oom_victim_suffix(platform: &dyn Platform, since_secs: u64) -> Option<String> {
    let victims = platform.oom_victims(since_secs)?;
    if victims.is_empty() {
        return None;
    }
    Some(format!(" — victims: {}", victims.join(", ")))
}

/// Name the OOM killer's victims on a firing: any fresh "OOM killer"
/// detail gains the kernel log's account — `… — victims: nginx (pid 123),
/// python (pid 456)`. The window matches the sentinel's (ALERT_CYCLES
/// samples at the current cadence); unreadable kernel logs leave the
/// detail count-only. Fleet alerts skip this deliberately: the victims
/// died on the far host, whose kernel log the local fetch can't read.
pub(crate) fn attribute_oom(picks: &mut [history::SysPick], platform: &dyn Platform, interval: u64) {
    if !picks
        .iter()
        .any(|(_, d, rec)| !*rec && d.starts_with("OOM killer"))
    {
        return;
    }
    let Some(suffix) = oom_victim_suffix(platform, history::ALERT_CYCLES as u64 * interval.max(1))
    else {
        return;
    };
    for (_, detail, rec) in picks.iter_mut() {
        if !*rec && detail.starts_with("OOM killer") {
            detail.push_str(&suffix);
        }
    }
}

/// The `--check` twin of [`attribute_oom`]: a local check run can read the
/// kernel log, so its OOM violation line names victims too. The window is
/// the sample gap (two sweeps a second apart) padded to cover the
/// journal's timestamping lag; the fleet check path never calls this — the
/// victims died in the far host's log.
fn attribute_oom_lines(lines: &mut [String], platform: &dyn Platform) {
    if !lines.iter().any(|l| l.starts_with("OOM killer")) {
        return;
    }
    let Some(suffix) = oom_victim_suffix(platform, 2) else {
        return;
    };
    for line in lines.iter_mut() {
        if line.starts_with("OOM killer") {
            line.push_str(&suffix);
        }
    }
}

/// Judge one stats-merged container snapshot against the armed container
/// thresholds — the `--check` half of the container sentinels. Single
/// comparison per container (no streaks: check has no history), the same
/// lines the watch-path sentinel fires. Pure: the sweep happens in the
/// caller, so tests can hand it a literal snapshot.
fn container_check_lines(
    cli: &cli::Cli,
    cs: &[crate::model::Container],
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if cli.alert_container_cpu.is_none() && cli.alert_container_mem_pct.is_none() {
        return out;
    }
    let pod_tag = |c: &crate::model::Container| match &c.pod {
        Some(p) => format!(" · pod {p}"),
        None => String::new(),
    };
    for c in cs.iter().filter(|c| c.state == "running") {
        if let (Some(limit), Some(pct)) = (cli.alert_container_cpu, c.cpu_pct) {
            if pct > limit {
                out.push((
                    format!("container {}", c.name),
                    format!("CPU {pct:.0}% above {limit}%{}", pod_tag(c)),
                ));
            }
        }
        if let (Some(limit), Some(used), Some(total)) =
            (cli.alert_container_mem_pct, c.mem_used_mb, c.mem_total_mb)
        {
            if total > 0 {
                let pct = (used * 100).checked_div(total).unwrap_or(0);
                if pct > limit {
                    out.push((
                        format!("container {}", c.name),
                        format!(
                            "memory {pct}% of limit above {limit}%{}",
                            pod_tag(c)
                        ),
                    ));
                }
            }
        }
    }
    out
}

/// Sweep containers for [`container_check_lines`]: enumeration + pod
/// attribution + the stats sweep (seconds per container — paid only when
/// a container threshold is armed). Local only; the fleet's containers
/// live on the far host.
fn container_check_sweep() -> Vec<crate::model::Container> {
    let mut cs = platform::enumerate_containers();
    let pods = crate::k8s::pods().unwrap_or_default();
    crate::k8s::annotate_with(&pods, &mut cs);
    let stats = platform::container_stats();
    for c in cs.iter_mut() {
        let key: String = c.id.chars().take(12).collect();
        if let Some((pct, used, total)) = stats.get(&key) {
            c.cpu_pct = Some(*pct);
            c.mem_used_mb = Some(*used);
            c.mem_total_mb = Some(*total);
        }
    }
    cs
}

/// The ranked slice behind a fleet top board — the ordering render_top
/// draws (value desc, host-then-pid ties), as owned rows so the
/// machine-readable formats can print the exact board. Table-carried
/// metrics only: the fleet fetch has no fd/conn/io probes.
/// (host, pid) → the previous sweep's cumulative io bytes — the fleet
/// io-rate diff's baseline. Keyed by host+pid: the same pid on two
/// machines is two processes.
fn fleet_io_prev(results: &FleetFetch) -> HashIo {
    let mut out = HashIo::new();
    for (base, result) in results {
        if let Ok((ps, _)) = result {
            for p in ps {
                if p.io_read_bytes.is_some() || p.io_write_bytes.is_some() {
                    out.insert(
                        (base.clone(), p.pid),
                        (
                            p.io_read_bytes.unwrap_or(0),
                            p.io_write_bytes.unwrap_or(0),
                        ),
                    );
                }
            }
        }
    }
    out
}

/// Per-pid io rates (bytes/s) diffed against `prev` — the fleet io-rate
/// board's values, written into the rows the ranking draws.
fn fleet_io_rates(prev: &HashIo, results: &FleetFetch, elapsed: f64) -> std::collections::HashMap<(String, Pid), (f64, f64)> {
    let mut out = std::collections::HashMap::new();
    if elapsed <= 0.0 {
        return out;
    }
    for (base, result) in results {
        if let Ok((ps, _)) = result {
            for p in ps {
                let key = (base.clone(), p.pid);
                if let Some((pr, pw)) = prev.get(&key) {
                    let r = p
                        .io_read_bytes
                        .unwrap_or(0)
                        .saturating_sub(*pr) as f64
                        / elapsed;
                    let w = p
                        .io_write_bytes
                        .unwrap_or(0)
                        .saturating_sub(*pw) as f64
                        / elapsed;
                    out.insert(key, (r, w));
                }
            }
        }
    }
    out
}

fn fleet_ranked(procs: &[Process], metric: cli::TopMetric, count: usize) -> Vec<Process> {
    let now = util::now_unix();
    let mut ranked: Vec<(f64, &Process)> = procs
        .iter()
        .filter_map(|pr| {
            let v = match metric {
                cli::TopMetric::Cpu => pr.cpu,
                cli::TopMetric::Mem => pr.mem_kb.map(|kb| kb as f64),
                cli::TopMetric::Age => {
                    pr.started.map(|t| (now.saturating_sub(t)) as f64)
                }
                cli::TopMetric::Threads => pr.threads.map(|n| n as f64),
                cli::TopMetric::Swap => pr.swap_kb.map(|kb| kb as f64),
                // GPU columns ride the table where the peers run
                // nvidia-smi — the fleet board can rank them without any
                // local probing
                cli::TopMetric::Gpu => pr.gpu_sm_pct.map(|v| v as f64),
                cli::TopMetric::GpuMem => pr.gpu_mem_mb.map(|mb| mb as f64),
                // cumulative io rides the listing (the peers enrich it);
                // the io-rate board bakes diffed bytes/s into the same
                // fields before ranking, so one arm serves both
                cli::TopMetric::Io | cli::TopMetric::IoRate => {
                    let r = pr.io_read_bytes.unwrap_or(0);
                    let w = pr.io_write_bytes.unwrap_or(0);
                    (pr.io_read_bytes.is_some() || pr.io_write_bytes.is_some())
                        .then_some((r + w) as f64)
                }
                _ => None,
            }?;
            Some((v, pr))
        })
        .collect();
    ranked.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.1.host.cmp(&b.1.host))
            .then_with(|| a.1.pid.cmp(&b.1.pid))
    });
    ranked.truncate(count);
    ranked.into_iter().map(|(_, p)| p.clone()).collect()
}

/// One fleet outlier: a host whose metric sits far from the fleet norm.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct FleetOutlier {
    pub host: String,
    /// Metric name ("load 1m", "cpu %", "memory %", "disk used %",
    /// "disk busy %", "deleted MB", "gpu mem %").
    pub metric: &'static str,
    pub value: f64,
    /// The fleet median for the metric (the norm this host deviates from).
    pub median: f64,
    /// The modified z-score (Iglewicz–Hoaglin: 0.6745·(x−median)/MAD).
    pub z: f64,
}

/// The median of a slice (average of the two middles on even length).
fn median_of(mut vals: Vec<f64>) -> f64 {
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = vals.len();
    if n == 0 {
        return 0.0;
    }
    if n % 2 == 1 {
        vals[n / 2]
    } else {
        (vals[n / 2 - 1] + vals[n / 2]) / 2.0
    }
}

/// Modified z-scores per value: robust to the very outliers being hunted —
/// a classic z-score's σ gets inflated by the anomaly itself, which on a
/// five-host fleet means nothing ever reads as abnormal. MAD (median
/// absolute deviation) doesn't. A fleet where every value is identical
/// has MAD 0 → the fallback treats any deviation beyond 5% of the median
/// (or 0.05 absolute on a near-zero median) as the outlier.
fn modified_zscores(vals: &[f64]) -> Vec<f64> {
    let med = median_of(vals.to_vec());
    let mut devs: Vec<f64> = vals.iter().map(|v| (v - med).abs()).collect();
    let mad = median_of(devs.clone());
    if mad > 0.0 {
        devs.clear();
        return vals
            .iter()
            .map(|v| 0.6745 * (v - med) / mad)
            .collect();
    }
    let eps = 0.05 * med.abs().max(1.0);
    vals.iter()
        .map(|v| {
            let d = (v - med).abs();
            // scaled like a z: the deviation over the epsilon, growing
            // without bound — a 2× epsilon reads as z 2, a 4× as 4
            if d <= eps {
                0.0
            } else {
                (d / eps) * 1.0
            }
        })
        .collect()
}

/// One host's per-metric readings off its snapshot — every metric the
/// outlier sweep judges. Metrics the snapshot doesn't carry (older serve,
/// missing hardware) simply don't appear, and the sweep judges only what
/// it can see.
fn host_metric_values(sample: &FleetSample) -> Vec<(&'static str, f64)> {
    let s = &sample.stats;
    let mounts = &sample.mounts;
    let mut out = Vec::new();
    if let Some(v) = s.load1 {
        out.push(("load 1m", v));
    }
    if let Some(v) = s.cpu_percent {
        out.push(("cpu %", v));
    }
    if let (Some(u), Some(t)) = (s.mem_used_mb, s.mem_total_mb) {
        if t > 0 {
            out.push(("memory %", u as f64 * 100.0 / t as f64));
        }
    }
    if let (Some(u), Some(t)) = (s.swap_used_mb, s.swap_total_mb) {
        if t > 0 {
            out.push(("swap %", u as f64 * 100.0 / t as f64));
        }
    }
    if !mounts.is_empty() {
        let worst = mounts
            .iter()
            .filter(|m| m.total_mb > 0)
            .map(|m| m.used_mb as f64 * 100.0 / m.total_mb as f64)
            .fold(0.0, f64::max);
        if worst > 0.0 {
            out.push(("disk used %", worst));
        }
    }
    if let Some(busy) = s.disks.iter().filter_map(|d| d.busy_pct).fold(None, |acc, v| {
        Some(acc.map_or(v, |a: f64| a.max(v)))
    }) {
        out.push(("disk busy %", busy));
    }
    if sample.deleted_reclaimable_mb > 0 {
        out.push(("deleted MB", sample.deleted_reclaimable_mb as f64));
    }
    if let Some(pct) = s
        .gpus
        .iter()
        .filter(|g| g.mem_total_mb > 0)
        .map(|g| g.mem_used_mb as f64 * 100.0 / g.mem_total_mb as f64)
        .fold(None, |acc, v| Some(acc.map_or(v, |a: f64| a.max(v))))
    {
        out.push(("gpu mem %", pct));
    }
    out
}

/// The fleet outlier sweep: per metric, judge every reporting host with
/// the modified z-score; those at or over `threshold` come back, worst z
/// first. Metrics with fewer than three reporters are skipped — two
/// machines rarely make a norm.
fn fleet_outliers(
    results: &FleetFetch,
    threshold: f64,
) -> Vec<FleetOutlier> {
    // host → its metric readings (hosts whose fetch failed contribute
    // nothing, and their failure shows in the footer, not the ranking)
    let mut per_host: Vec<(String, Vec<(&'static str, f64)>)> = Vec::new();
    for (base, result) in results {
        if let Ok((_, Some(sample))) = result {
            per_host.push((base.clone(), host_metric_values(sample)));
        }
    }
    // metric → (host, value) across the fleet
    let mut by_metric: std::collections::HashMap<&'static str, Vec<(String, f64)>> =
        std::collections::HashMap::new();
    for (host, readings) in &per_host {
        for (metric, value) in readings {
            by_metric.entry(metric).or_default().push((host.clone(), *value));
        }
    }
    let mut out = Vec::new();
    let mut metrics: Vec<&&str> = by_metric.keys().collect();
    metrics.sort();
    for metric in metrics {
        let entries = &by_metric[*metric];
        if entries.len() < 3 {
            continue;
        }
        let values: Vec<f64> = entries.iter().map(|(_, v)| *v).collect();
        let zs = modified_zscores(&values);
        let med = median_of(values.clone());
        for ((host, value), z) in entries.iter().zip(&zs) {
            if z.abs() >= threshold {
                out.push(FleetOutlier {
                    host: host.clone(),
                    metric,
                    value: *value,
                    median: med,
                    z: *z,
                });
            }
        }
    }
    // worst deviation first
    out.sort_by(|a, b| {
        b.z.abs()
            .partial_cmp(&a.z.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

/// Count processes in the given single-letter kernel states — the
/// state-waterline sentinels' input: "Z" defunct, "D"/"U" stuck in
/// uninterruptible wait (Linux spells it D, macOS U).
fn state_count(procs: &[Process], states: &[&str]) -> usize {
    procs
        .iter()
        .filter(|p| {
            p.state
                .as_deref()
                .is_some_and(|s| states.contains(&s))
        })
        .count()
}

/// The machine-wide half of `--check`, shared by the local run and the
/// fleet run: every armed level/rate threshold judged against one
/// snapshot, violation detail lines back (no host/pid wrapping — the
/// caller wraps). Levels are single comparisons; the rates arrive
/// pre-diffed by the caller (two samples, or two fetches, a second
/// apart).
#[allow(clippy::too_many_arguments)] // one bundle per armed threshold family
fn machine_check_lines(
    cli: &cli::Cli,
    stats: &crate::platform::SystemStats,
    mounts: &[crate::platform::MountUsage],
    deleted_files: &[crate::platform::DeletedFile],
    proc_count: usize,
    zombie_count: usize,
    dstate_count: usize,
    failed_units: &[String],
    // (unit, cgroup bytes) pairs, only fetched when `alert_service_mem` is
    // armed — the service-memory sentinel's input; the local --check maps
    // its live sweep to pairs, the fleet --check reads the snapshot's
    service_mems: &[(String, u64)],
    net_rate: Option<f64>,
    drop_rate: Option<f64>,
    retrans_rate: Option<f64>,
    oom_in_window: Option<u64>,
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(limit) = cli.alert_load {
        if let Some(l) = stats.load1 {
            if l > limit {
                out.push(format!("load average {l:.2} above {limit}"));
            }
        }
    }
    if let Some(limit) = cli.alert_mem_pct {
        if let (Some(u), Some(t)) = (stats.mem_used_mb, stats.mem_total_mb) {
            if t > 0 {
                let pct = (u * 100).checked_div(t).unwrap_or(0);
                if pct > limit {
                    out.push(format!("RAM {pct}% above {limit}%"));
                }
            }
        }
    }
    if let Some(limit) = cli.alert_count {
        if proc_count > limit as usize {
            out.push(format!("{proc_count} visible processes above {limit}"));
        }
    }
    if let Some(limit) = cli.alert_inodes {
        let mut over: Vec<String> = mounts
            .iter()
            .filter_map(|m| {
                let (used, total) = (m.inodes_used?, m.inodes_total?);
                (total > 0 && used * 100 / total > limit)
                    .then(|| format!("{} {}%", m.target, used * 100 / total))
            })
            .collect();
        over.sort();
        if !over.is_empty() {
            out.push(format!(
                "inodes {} above {limit}% used",
                over.join(", ")
            ));
        }
    }
    if cli.alert_disk.is_some() {
        let mut over_mounts: Vec<(u64, &crate::platform::MountUsage)> = mounts
            .iter()
            .filter(|m| m.total_mb > 0)
            .map(|m| {
                let pct = (m.used_mb * 100).checked_div(m.total_mb).unwrap_or(0);
                (pct, m)
            })
            .filter(|(pct, _)| Some(*pct) > cli.alert_disk)

            .collect();
        over_mounts.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.target.cmp(&b.1.target)));
        if !over_mounts.is_empty() {
            let named: Vec<String> = over_mounts
                .iter()
                .take(3)
                .map(|(pct, m)| format!("{} {pct}%", m.target))
                .collect();
            out.push(format!(
                "disk {} above {}%",
                named.join(", "),
                cli.alert_disk.unwrap_or(0)
            ));
        }
    }
    if let (Some(limit), Some(rate)) = (cli.alert_net, net_rate) {
        if rate > limit as f64 {
            out.push(format!("net {rate:.1} MB/s above {limit} MB/s"));
        }
    }
    if let Some(limit) = cli.alert_psi {
        if let Some(psi) = &stats.psi {
            let over: Vec<String> = [
                ("cpu", psi.cpu_full),
                ("mem", psi.mem_full),
                ("io", psi.io_full),
            ]
            .into_iter()
            .filter(|(_, v)| *v > limit)
            .map(|(r, v)| format!("{r} {v:.1}%"))
            .collect();
            if !over.is_empty() {
                out.push(format!("PSI full {} above {limit}%", over.join(", ")));
            }
        }
    }
    if let Some(floor) = cli.alert_mem_avail_mb {
        if let Some(a) = stats.mem_avail_mb {
            if a < floor {
                out.push(format!("MemAvailable {a} MB below {floor} MB floor"));
            }
        }
    }
    if let Some(limit) = cli.alert_swap_pct {
        if let (Some(u), Some(t)) = (stats.swap_used_mb, stats.swap_total_mb) {
            if t > 0 {
                let pct = (u * 100).checked_div(t).unwrap_or(0);
                if pct > limit {
                    out.push(format!("swap {pct}% above {limit}%"));
                }
            }
        }
    }
    if let (Some(limit), Some(rate)) = (cli.alert_retrans.map(|v| v as f64), retrans_rate) {
        if rate > limit {
            out.push(format!("TCP retransmits {rate:.0}/s above {limit:.0}/s"));
        }
    }
    if let (Some(limit), Some(rate)) = (cli.alert_nic_drop.map(|v| v as f64), drop_rate) {
        if rate > limit {
            out.push(format!("NIC drops {rate:.0}/s above {limit:.0}/s"));
        }
    }
    if let Some(limit) = cli.alert_oom {
        if oom_in_window.is_some_and(|w| w >= limit) {
            out.push(format!(
                "OOM killer {} kill(s) within the sample gap",
                oom_in_window.unwrap_or(0)
            ));
        }
    }
    if let Some(limit) = cli.alert_disk_busy {
        let over: Vec<String> = stats
            .disks
            .iter()
            .filter(|d| d.busy_pct.is_some_and(|b| b > limit))
            .map(|d| format!("{} {:.0}%", d.device, d.busy_pct.unwrap_or(0.0)))
            .collect();
        if !over.is_empty() {
            out.push(format!("disk IO {} above {limit}% busy", over.join(", ")));
        }
    }
    if let Some(limit) = cli.alert_deleted_gb {
        let total_mb: u64 = deleted_files.iter().map(|d| d.size_mb).sum();
        if (total_mb as f64 / 1024.0) > limit {
            let named: Vec<String> = deleted_files
                .iter()
                .take(3)
                .map(|d| format!("{} (pid {})", d.path, d.pid))
                .collect();
            out.push(format!(
                "deleted-but-held files: {:.1} GB above {limit} GB — {}",
                total_mb as f64 / 1024.0,
                named.join(", ")
            ));
        }
    }
    if let Some(limit) = cli.alert_gpu_mem_pct {
        let over: Vec<String> = stats
            .gpus
            .iter()
            .filter(|g| g.mem_total_mb > 0 && g.mem_used_mb * 100 / g.mem_total_mb > limit)
            .map(|g| {
                format!(
                    "gpu {} ({}) {}%",
                    g.id,
                    g.name,
                    g.mem_used_mb * 100 / g.mem_total_mb
                )
            })
            .collect();
        if !over.is_empty() {
            out.push(format!(
                "GPU memory {} above {limit}% of capacity",
                over.join(", ")
            ));
        }
    }
    if let Some(limit) = cli.alert_temp {
        if let Some((label, c)) = &stats.temp {
            if *c > limit {
                out.push(format!("temperature {c:.0}°C at {label} above {limit}°C"));
            }
        }
    }
    if let Some(limit) = cli.alert_zombies {
        if zombie_count > limit as usize {
            out.push(format!(
                "{zombie_count} defunct (zombie) processes above {limit}"
            ));
        }
    }
    if let Some(limit) = cli.alert_dstate {
        if dstate_count > limit as usize {
            out.push(format!(
                "{dstate_count} processes stuck in uninterruptible IO wait above {limit}"
            ));
        }
    }
    if let Some(limit) = cli.alert_failed_units {
        if failed_units.len() > limit as usize {
            let named: Vec<String> = failed_units.iter().take(3).cloned().collect();
            out.push(format!(
                "{} systemd units failed above {limit} — {}{}",
                failed_units.len(),
                named.join(", "),
                if failed_units.len() > named.len() { "…" } else { "" }
            ));
        }
    }
    if let Some(limit) = cli.alert_service_mem {
        let mut over: Vec<(String, u64)> = service_mems
            .iter()
            .filter(|(_, b)| *b > limit * 1024 * 1024)
            .cloned()
            .collect();
        over.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
        if !over.is_empty() {
            let named: Vec<String> = over
                .iter()
                .take(3)
                .map(|(u, b)| format!("{u} {}", crate::util::fmt_bytes(*b)))
                .collect();
            out.push(format!(
                "{} service(s) above {limit} MB — {}{}",
                over.len(),
                named.join(", "),
                if over.len() > named.len() { "…" } else { "" }
            ));
        }
    }
    out
}

/// The fleet one-shot: `--check --remote a,b,c` — two fetches a second
/// apart per host (the same trick the local run uses), machine sentinels
/// evaluated per host, every violation prefixed with its host. Exit 1
/// when any host sits over a line.
fn run_check_fleet(bases: &[String], cli: &cli::Cli) -> i32 {
    if !fleet_machine_armed(cli) {
        eprintln!(
            "--check --remote evaluates the machine-wide --alert-* thresholds; arm at least one (e.g. --check --remote ... --alert-load 4)"
        );
        std::process::exit(4);
    }
    let sweep = || -> FleetFetch {
        bases
            .iter()
            .map(|b| (b.clone(), fetch_fleet(b)))
            .collect()
    };
    let mut states: HashMap<String, history::SysAlertState> = HashMap::new();
    // sweep 1 seeds every per-host cumulative counter — into the same
    // per-host states sweep 2 diffs against
    for (base, r) in sweep() {
        if let Ok((_, Some(sample))) = r {
            let st = states.entry(base).or_default();
            let _ = fleet_rates(cli, &sample, st);
        }
    }
    std::thread::sleep(Duration::from_secs(1));

    let mut violations: Vec<(String, String)> = Vec::new(); // (host, detail)
    let mut unreachable: Vec<String> = Vec::new();
    for (base, r) in sweep() {
        match r {
            Ok((procs, Some(sample))) => {
                let st = states.entry(base.clone()).or_default();
                let (net_rate, drop_rate, retrans_rate, oom_window) =
                    fleet_rates(cli, &sample, st);
                let zombie_count = state_count(&procs, &["Z"]);
                let dstate_count = state_count(&procs, &["D", "U"]);
                for detail in machine_check_lines(
                    cli,
                    &sample.stats,
                    &sample.mounts,
                    &[],
                    procs.len(),
                    zombie_count,
                    dstate_count,
                    // the snapshot carries the far host's own failed-unit
                    // list — the check judges it here
                    &sample.failed_units,
                    // the snapshot carries the far host's own service
                    // cgroup memory — the sentinel judges it here
                    &sample.service_mems,
                    net_rate,
                    drop_rate,
                    retrans_rate,
                    oom_window,
                ) {
                    violations.push((base.clone(), detail));
                }
            }
            Ok((_, None)) => unreachable.push(base.clone()),
            Err(e) => {
                violations.push((base.clone(), format!("fetch failed: {e}")));
            }
        }
    }

    if cli.json {
        let doc = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "generated_at": util::now_unix(),
            "violations": violations
                .iter()
                .map(|(host, detail)| serde_json::json!({
                    "host": host,
                    "pid": 0,
                    "name": "system",
                    "detail": detail,
                }))
                .collect::<Vec<_>>(),
        });
        write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
    } else if violations.is_empty() {
        write_out(&format!(
            "✔ all armed checks clean across {} host(s)",
            bases.len()
        ));
    } else {
        for (host, detail) in &violations {
            write_out(&format!("⚠ [{host}] system — {detail}"));
        }
        write_out(&format!("{} violation(s)", violations.len()));
    }
    if !unreachable.is_empty() {
        eprintln!(
            "⚠ {} host(s) predate the machine snapshot (old witr-rs --serve): {}",
            unreachable.len(),
            unreachable.join(", ")
        );
    }
    i32::from(!violations.is_empty())
}

#[allow(clippy::too_many_arguments)] // one bundle per armed threshold family
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

/// The per-tick state waterlines a recording carries in its machine
/// row — zombies and stuck-in-D come from the process table, the
/// failed-unit count from the service manager (Linux; other platforms
/// stay 0 rather than pay a PowerShell per tick), and the mem-eta
/// prediction from the recorder's own trend window (significance-gated,
/// so it appears once enough ticks accrue — the sentinel's number,
/// written down for offline replay).
struct RecordWaterlines {
    zombies: usize,
    dstates: usize,
    failed_units: usize,
    mem_eta_hours: Option<f64>,
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
                 sys_load1,sys_mem_pct,sys_procs,sys_net_bps,sys_zombies,sys_dstates,sys_failed_units,sys_mem_eta_hours";
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
        waterlines: &RecordWaterlines,
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
                "{},_system,-,system,{},{},,,,{},{},{},{},{},{},{},{}",
                ts,
                s.cpu_percent.map(|c| format!("{c:.1}")).unwrap_or_default(),
                s.mem_used_mb.map(|mb| mb.to_string()).unwrap_or_default(),
                s.load1.map(|l| format!("{l:.2}")).unwrap_or_default(),
                mem_pct.map(|p| p.to_string()).unwrap_or_default(),
                procs.len(),
                net_bps.map(|b| format!("{b:.0}")).unwrap_or_default(),
                waterlines.zombies,
                waterlines.dstates,
                waterlines.failed_units,
                waterlines
                    .mem_eta_hours
                    .map(|h| format!("{h:.2}"))
                    .unwrap_or_default(),
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
    /// The state waterlines + the mem-eta prediction, when the recording
    /// carries them (files from before v0.53 read as None).
    pub(crate) zombies: usize,
    pub(crate) dstates: usize,
    pub(crate) failed_units: usize,
    pub(crate) mem_eta_hours: Option<f64>,
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
                let int = |name: &str| -> usize {
                    col(name)
                        .and_then(|i| f.get(i))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0)
                };
                out.push(SysPoint {
                    at: f[t].trim().parse().unwrap_or(0),
                    cpu: num(cpu),
                    mem_pct: num(mem),
                    load1: num(load),
                    procs: procs_n,
                    net_bps: num(net),
                    // older files lack the columns → 0/None, honest blanks
                    zombies: int("sys_zombies"),
                    dstates: int("sys_dstates"),
                    failed_units: int("sys_failed_units"),
                    mem_eta_hours: num(col("sys_mem_eta_hours")),
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
            zombies: sys.get("zombies").and_then(|x| x.as_u64()).unwrap_or(0) as usize,
            dstates: sys.get("dstates").and_then(|x| x.as_u64()).unwrap_or(0) as usize,
            failed_units: sys
                .get("failed_units")
                .and_then(|x| x.as_u64())
                .unwrap_or(0) as usize,
            mem_eta_hours: sys.get("mem_eta_hours").and_then(|x| x.as_f64()),
        });
    }
    if out.is_empty() {
        return Err("no system samples in the jsonl".to_string());
    }
    Ok(out)
}

/// One per-process sample from a record file: who, when, how much CPU —
/// the heatmap feed (the machine-only `_system` rows carry none of this).
pub(crate) struct ProcSample {
    pub(crate) at: i64,
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) cpu: Option<f64>,
    /// Resident memory in MB (the CSV column; the JSONL envelope's
    /// rss_kb converts) — the --agg board's footprint stats.
    pub(crate) rss_mb: Option<f64>,
    /// The owning user (the CSV column / the envelope's user field) —
    /// the --agg --by-user rollup's key.
    pub(crate) user: Option<String>,
    /// Disk throughput (read + write, bytes/s). The CSV carries rates
    /// directly; the JSONL envelope carries cumulative counters, which
    /// the parser diffs per identity into rates (exact row spacing).
    pub(crate) io_bps: Option<f64>,
}

/// The per-process rows of a record file (either format). Empty when the
/// recording carried no process rows — the caller notes the heatmap as
/// skipped instead of failing the whole plot.
pub(crate) fn parse_record_processes(text: &str) -> Vec<ProcSample> {
    let mut out = Vec::new();
    let mut lines = text.lines().peekable();
    if let Some(first) = lines.peek() {
        if first.starts_with("timestamp,") {
            let header: Vec<&str> = first.split(',').collect();
            let col = |name: &str| header.iter().position(|c| *c == name);
            if let (Some(t), Some(pid)) = (col("timestamp"), col("pid")) {
                let (name, cpu, rss, user) =
                    (col("name"), col("cpu_pct"), col("rss_mb"), col("user"));
                // the rate columns were renamed once (io_rbps → io_read_bps);
                // the header is matched by name, so accept both
                let io_r = col("io_read_bps").or_else(|| col("io_rbps"));
                let io_w = col("io_write_bps").or_else(|| col("io_wbps"));
                for line in lines {
                    let f: Vec<&str> = line.split(',').collect();
                    if f.len() <= t.max(pid) || f[pid] == "_system" {
                        continue;
                    }
                    let Ok(at) = f[t].trim().parse::<i64>() else {
                        continue;
                    };
                    let Ok(id) = f[pid].trim().parse::<i64>() else {
                        continue;
                    };
                    if id < 0 {
                        continue;
                    }
                    out.push(ProcSample {
                        at,
                        pid: id as Pid,
                        name: name
                            .and_then(|i| f.get(i))
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                        cpu: cpu
                            .and_then(|i| f.get(i))
                            .and_then(|v| v.trim().parse().ok()),
                        rss_mb: rss
                            .and_then(|i| f.get(i))
                            .and_then(|v| v.trim().parse().ok()),
                        user: user
                            .and_then(|i| f.get(i))
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty()),
                        io_bps: {
                            let r = io_r
                                .and_then(|i| f.get(i))
                                .and_then(|v| v.trim().parse::<f64>().ok());
                            let w = io_w
                                .and_then(|i| f.get(i))
                                .and_then(|v| v.trim().parse::<f64>().ok());
                            match (r, w) {
                                (Some(r), Some(w)) => Some(r + w),
                                (Some(r), None) => Some(r),
                                (None, Some(w)) => Some(w),
                                (None, None) => None,
                            }
                        },
                    });
                }
            }
        }
    }
    if out.is_empty() {
        // JSONL: the processes array rides every envelope. The envelope's
        // io fields are cumulative counters — diffed per identity as the
        // file plays back, so the aggregator sees bytes/s like the CSV's
        // rate columns (the row spacing is exact, not the median guess)
        let mut io_prev: std::collections::HashMap<(Pid, String), (i64, u64, u64)> =
            std::collections::HashMap::new();
        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(ps) = v.get("processes").and_then(|p| p.as_array()) else {
                continue;
            };
            let Some(at) = v.get("generated_at").and_then(|x| x.as_i64()) else {
                continue;
            };
            for p in ps {
                let pid = p.get("pid").and_then(|x| x.as_i64()).unwrap_or(-1);
                if pid < 0 {
                    continue;
                }
                let name = p
                    .get("name")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string();
                out.push(ProcSample {
                    at,
                    pid: pid as Pid,
                    name: name.clone(),
                    cpu: p
                        .get("cpu_pct")
                        .and_then(|x| x.as_f64())
                        // the envelope serializes Process, whose field is
                        // `cpu` — accept both spellings
                        .or_else(|| p.get("cpu").and_then(|x| x.as_f64())),
                    // the envelope's rss is in KB, the CSV column in MB
                    rss_mb: p
                        .get("mem_kb")
                        .and_then(|x| x.as_f64())
                        .map(|kb| kb / 1024.0)
                        .or_else(|| p.get("rss_mb").and_then(|x| x.as_f64())),
                    user: p
                        .get("user")
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_string()),
                    io_bps: {
                        let r = p.get("io_read_bytes").and_then(|x| x.as_u64());
                        let w = p.get("io_write_bytes").and_then(|x| x.as_u64());
                        match (r, w) {
                            (Some(r), Some(w)) => {
                                let key = (pid as Pid, name.clone());
                                let rate = io_prev
                                    .get(&key)
                                    .filter(|(last_at, _, _)| at > *last_at)
                                    .map(|(last_at, last_r, last_w)| {
                                        let dt = (at - *last_at) as f64;
                                        let dr = r.saturating_sub(*last_r) as f64;
                                        let dw = w.saturating_sub(*last_w) as f64;
                                        (dr + dw) / dt
                                    });
                                io_prev.insert(key, (at, r, w));
                                rate
                            }
                            _ => None,
                        }
                    },
                });
            }
        }
    }
    out
}

/// One `--agg` row: a (pid, name) identity's window-wide stats. The
/// identity — not the pid alone — is the key: the same pid number serving
/// a different program mid-recording is a different row, and a program
/// that exited partway still gets its fair share of the integral.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct RecordAgg {
    pub(crate) name: String,
    pub(crate) pid: Pid,
    /// How many recorded ticks carried this identity — a process that
    /// lived 2 minutes inside a 1-hour recording shows 120, not 0.
    pub(crate) samples: usize,
    /// Mean CPU% over the samples that carried a reading.
    pub(crate) cpu_avg: Option<f64>,
    /// Peak CPU% — the burst the average hides.
    pub(crate) cpu_peak: Option<f64>,
    /// CPU-seconds: cpu_pct integrated over the window by the recording's
    /// median sample spacing (100% for one interval = one core-second).
    /// The honest "who ate the most CPU" rank — a process that hogged
    /// 90% for 5 minutes outranks one idling at 3% for an hour.
    pub(crate) cpu_seconds: Option<f64>,
    /// Mean resident MB over the samples that carried a reading.
    pub(crate) rss_avg_mb: Option<f64>,
    /// Peak resident MB — the footprint the sum can't show.
    pub(crate) rss_peak_mb: Option<f64>,
    /// Peak instantaneous disk throughput (read + write, bytes/s).
    pub(crate) io_peak_bps: Option<f64>,
    /// Total bytes moved, integrated over the window (rates × the tick
    /// spacing) — "this identity pushed 4 GB through the disk".
    pub(crate) io_total_bytes: Option<f64>,
}

/// Fold a recording's per-tick process rows into window aggregates,
/// ranked best-first by `metric` (cpu by integrated CPU-time, mem by
/// peak RSS) and truncated to `count`.
pub(crate) fn aggregate_record(
    samples: &[ProcSample],
    metric: crate::cli::TopMetric,
    count: usize,
) -> Vec<RecordAgg> {
    #[derive(Default)]
    struct Acc {
        cpu_seen: Vec<f64>,
        rss_seen: Vec<f64>,
        io_peak: f64,
        io_total: f64,
        io_seen: bool,
    }
    let mut groups: std::collections::BTreeMap<(Pid, String), Acc> =
        std::collections::BTreeMap::new();
    // the window's tick spacing: median gap between the recording's
    // distinct timestamps — one number for every row (the io integral
    // needs it before the loop), robust to a dropped tick
    let dt = record_median_dt(samples);
    for s in samples {
        let acc = groups.entry((s.pid, s.name.clone())).or_default();
        if let Some(c) = s.cpu {
            acc.cpu_seen.push(c);
        }
        if let Some(r) = s.rss_mb {
            acc.rss_seen.push(r);
        }
        if let Some(bps) = s.io_bps {
            acc.io_seen = true;
            acc.io_peak = acc.io_peak.max(bps);
            acc.io_total += bps * dt;
        }
    }
    let cpu_time = |acc: &Acc| {
        (!acc.cpu_seen.is_empty() && dt > 0.0)
            .then(|| acc.cpu_seen.iter().sum::<f64>() / 100.0 * dt)
    };
    let mut rows: Vec<RecordAgg> = groups
        .into_iter()
        .map(|((pid, name), acc)| {
            let mean = |v: &[f64]| {
                (!v.is_empty()).then(|| v.iter().sum::<f64>() / v.len() as f64)
            };
            RecordAgg {
                name,
                pid,
                samples: acc.cpu_seen.len().max(acc.rss_seen.len()),
                cpu_avg: mean(&acc.cpu_seen),
                cpu_peak: acc.cpu_seen.iter().cloned().reduce(f64::max),
                cpu_seconds: cpu_time(&acc),
                rss_avg_mb: mean(&acc.rss_seen),
                rss_peak_mb: acc.rss_seen.iter().cloned().reduce(f64::max),
                io_peak_bps: acc.io_seen.then_some(acc.io_peak),
                io_total_bytes: (acc.io_seen && dt > 0.0).then_some(acc.io_total),
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        let key = |r: &RecordAgg| match metric {
            crate::cli::TopMetric::Mem => r.rss_peak_mb.unwrap_or(f64::NEG_INFINITY),
            // --top io ranks by bytes moved — the window question "who
            // hammered the disk"
            crate::cli::TopMetric::Io => r.io_total_bytes.unwrap_or(f64::NEG_INFINITY),
            // everything else ranks by integrated CPU-time — the window
            // question is "who spent the core", not "who idled highest"
            _ => r.cpu_seconds.unwrap_or(f64::NEG_INFINITY),
        };
        key(b)
            .partial_cmp(&key(a))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.pid.cmp(&b.pid))
    });
    rows.truncate(count.max(1));
    rows
}

/// The recording's tick spacing: median gap between its distinct
/// timestamps — one number for every aggregate row, robust to a dropped
/// tick. `0.0` for a single-sample recording (nothing to integrate).
pub(crate) fn record_median_dt(samples: &[ProcSample]) -> f64 {
    let mut stamps: Vec<i64> = samples.iter().map(|s| s.at).collect();
    stamps.sort_unstable();
    stamps.dedup();
    let mut gaps: Vec<f64> = stamps.windows(2).map(|w| (w[1] - w[0]) as f64).collect();
    gaps.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    match gaps.len() {
        0 => 0.0,
        n => gaps[n / 2],
    }
}

/// One `--agg --by-user` row: a user's window-wide totals. Unlike the
/// per-identity board, memory sums the user's processes per tick — the
/// honest "how much did this user hold at once" — and the samples count
/// is distinct ticks the user appeared in.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct UserAgg {
    /// The owner, or "-" when the recording never attributed one.
    pub(crate) user: String,
    /// Distinct ticks carrying at least one process of this user.
    pub(crate) samples: usize,
    /// Mean per-tick CPU% summed across the user's processes.
    pub(crate) cpu_avg: Option<f64>,
    /// Peak per-tick CPU% — the burst instant.
    pub(crate) cpu_peak: Option<f64>,
    /// CPU-seconds across all the user's processes (same integral the
    /// identity board sums, grouped by owner).
    pub(crate) cpu_seconds: Option<f64>,
    /// Mean/peak of the per-tick RSS sum — the user's simultaneous
    /// footprint, not a sum of peaks.
    pub(crate) rss_avg_mb: Option<f64>,
    pub(crate) rss_peak_mb: Option<f64>,
    /// Peak instantaneous disk throughput (read + write bytes/s) across
    /// the user's processes — the spike the averages hide.
    pub(crate) io_peak_bps: Option<f64>,
    /// Total bytes the user's processes moved, integrated over the
    /// window (rates × tick spacing).
    pub(crate) io_total_bytes: Option<f64>,
}

/// Fold a recording into per-user window aggregates, ranked best-first
/// by `metric` (cpu by integrated CPU-time, mem by peak simultaneous
/// RSS) and truncated to `count`.
pub(crate) fn aggregate_record_by_user(
    samples: &[ProcSample],
    metric: crate::cli::TopMetric,
    count: usize,
) -> Vec<UserAgg> {
    #[derive(Default)]
    struct Acc {
        ticks: std::collections::BTreeSet<i64>,
        cpu_per_tick: std::collections::BTreeMap<i64, f64>,
        cpu_seconds: f64,
        rss_per_tick: std::collections::BTreeMap<i64, f64>,
        io_per_tick: std::collections::BTreeMap<i64, f64>,
        io_total: f64,
    }
    let dt = record_median_dt(samples);
    let mut groups: std::collections::BTreeMap<String, Acc> =
        std::collections::BTreeMap::new();
    for s in samples {
        let key = s.user.clone().unwrap_or_else(|| "-".into());
        let acc = groups.entry(key).or_default();
        acc.ticks.insert(s.at);
        if let Some(c) = s.cpu {
            *acc.cpu_per_tick.entry(s.at).or_default() += c;
            acc.cpu_seconds += c / 100.0 * dt;
        }
        if let Some(r) = s.rss_mb {
            *acc.rss_per_tick.entry(s.at).or_default() += r;
        }
        if let Some(bps) = s.io_bps {
            *acc.io_per_tick.entry(s.at).or_default() += bps;
            acc.io_total += bps * dt;
        }
    }
    let mut rows: Vec<UserAgg> = groups
        .into_iter()
        .map(|(user, acc)| {
            let cpu_vals: Vec<f64> = acc.cpu_per_tick.values().cloned().collect();
            let rss_vals: Vec<f64> = acc.rss_per_tick.values().cloned().collect();
            let mean = |v: &[f64]| {
                (!v.is_empty()).then(|| v.iter().sum::<f64>() / v.len() as f64)
            };
            let io_vals: Vec<f64> = acc.io_per_tick.values().cloned().collect();
            UserAgg {
                samples: acc.ticks.len(),
                cpu_avg: mean(&cpu_vals),
                cpu_peak: cpu_vals.iter().cloned().reduce(f64::max),
                cpu_seconds: (dt > 0.0).then_some(acc.cpu_seconds),
                rss_avg_mb: mean(&rss_vals),
                rss_peak_mb: rss_vals.iter().cloned().reduce(f64::max),
                // no io readings at all → absent, not a zero total
                io_peak_bps: io_vals.iter().cloned().reduce(f64::max),
                io_total_bytes: (!acc.io_per_tick.is_empty() && dt > 0.0)
                    .then_some(acc.io_total),
                user,
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        let key = |r: &UserAgg| match metric {
            crate::cli::TopMetric::Mem => r.rss_peak_mb.unwrap_or(f64::NEG_INFINITY),
            crate::cli::TopMetric::Io => r.io_total_bytes.unwrap_or(f64::NEG_INFINITY),
            _ => r.cpu_seconds.unwrap_or(f64::NEG_INFINITY),
        };
        key(b)
            .partial_cmp(&key(a))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.user.cmp(&b.user))
    });
    rows.truncate(count.max(1));
    rows
}

/// The cpu% heat color: dark at zero, blue as it wakes up, yellow when
/// it's working, red at saturation — one scale, no legend gymnastics.
fn heat_color(v: f64) -> String {
    let stops: [(f64, (u8, u8, u8)); 4] = [
        (0.0, (26, 39, 51)),
        (20.0, (77, 195, 255)),
        (60.0, (252, 196, 25)),
        (100.0, (255, 107, 107)),
    ];
    let v = v.clamp(0.0, 100.0);
    let mut lo = stops[0];
    let mut hi = stops[stops.len() - 1];
    for pair in stops.windows(2) {
        if v >= pair[0].0 && v <= pair[1].0 {
            lo = pair[0];
            hi = pair[1];
            break;
        }
    }
    let f = if hi.0 > lo.0 {
        (v - lo.0) / (hi.0 - lo.0)
    } else {
        0.0
    };
    let mix = |a: u8, b: u8| (a as f64 + (b as f64 - a as f64) * f).round() as u8;
    format!(
        "#{:02x}{:02x}{:02x}",
        mix(lo.1 .0, hi.1 .0),
        mix(lo.1 .1, hi.1 .1),
        mix(lo.1 .2, hi.1 .2)
    )
}

/// The top-identities × time CPU% heatmap: rows ranked by total CPU over
/// the file, one cell per sample. Bursts get a face — which process was
/// the spike — that the machine-level curves can't name.
fn proc_heatmap_svg(samples: &[ProcSample]) -> String {
    // rank identities by total cpu across the file, keep the top 12
    let mut totals: std::collections::HashMap<Pid, (String, f64)> =
        std::collections::HashMap::new();
    for s in samples.iter().filter(|s| s.cpu.is_some()) {
        totals
            .entry(s.pid)
            .and_modify(|(n, t)| {
                *t += s.cpu.unwrap_or(0.0);
                if n.is_empty() {
                    *n = s.name.clone();
                }
            })
            .or_insert((s.name.clone(), s.cpu.unwrap_or(0.0)));
    }
    let mut top: Vec<(Pid, String, f64)> = totals
        .into_iter()
        .map(|(pid, (name, t))| (pid, name, t))
        .collect();
    top.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    top.truncate(12);
    if top.is_empty() {
        return String::new();
    }
    let t0 = samples.iter().map(|s| s.at).min().unwrap_or(0);
    let t1 = samples.iter().map(|s| s.at).max().unwrap_or(t0).max(t0 + 1);
    let peak = samples.iter().filter_map(|s| s.cpu).fold(0.0f64, f64::max);
    let (w, label_w, cell_h, top_h) = (900.0, 170.0, 20.0, 30.0);
    let rows = top.len() as f64;
    let h = top_h + cell_h * rows + 24.0;
    let span = (t1 - t0).max(1) as f64;
    let x = |t: i64| label_w + (t - t0) as f64 / span * (w - label_w - 12.0);
    let at = |t: i64| crate::util::fmt_time(t).get(11..16).unwrap_or("").to_string();
    let rank = |pid: Pid| top.iter().position(|(p, _, _)| *p == pid);

    let mut svg = format!(
        "<div style=\"display:inline-block;margin:8px\"><svg width=\"{w}\" height=\"{h:.0}\" xmlns=\"http://www.w3.org/2000/svg\" font-family=\"ui-monospace,Menlo,monospace\">\
<text x=\"6\" y=\"14\" font-size=\"12\" fill=\"#8899a6\">top {} processes · cpu % · peak {peak:.1}%</text>",
        top.len()
    );
    for (i, (_, name, total)) in top.iter().enumerate() {
        let y = top_h + cell_h * i as f64;
        svg.push_str(&format!(
            "<text x=\"4\" y=\"{:.1}\" font-size=\"11\" fill=\"#e1e8ed\">{} ({total:.0}%)</text>",
            y + 14.0,
            crate::render::html_escape(name)
        ));
    }
    for s in samples {
        let Some(ri) = rank(s.pid) else {
            continue;
        };
        let Some(v) = s.cpu else {
            continue;
        };
        // half-cell-wide tiles with a 1px gutter — reads as a grid, keeps
        // the SVG from doubling as a wall of fill
        let cw = ((w - label_w - 12.0) / span * 1000.0).max(2.0) / 1000.0;
        let x1 = x(s.at);
        let y = top_h + cell_h * ri as f64;
        svg.push_str(&format!(
            "<rect x=\"{x1:.1}\" y=\"{y:.1}\" width=\"{cw:.1}\" height=\"{:.1}\" fill=\"{}\"><title>{} (pid {}) · {} · {v:.1}%</title></rect>",
            cell_h - 2.0,
            heat_color(v),
            crate::render::html_escape(&s.name),
            s.pid,
            at(s.at),
        ));
    }
    svg.push_str(&format!(
        "<text x=\"{label_w}\" y=\"{h:.0}\" font-size=\"10\" fill=\"#657786\">{}</text>\
<text x=\"{w:.0}\" y=\"{h:.0}\" font-size=\"10\" fill=\"#657786\" text-anchor=\"end\">{}</text>\
</svg></div>",
        at(t0),
        at(t1),
    ));
    svg
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
/// series the record actually carried, plus the per-process heatmap when
/// the file has process rows.
fn plot_html(points: &[SysPoint], proc_samples: &[ProcSample]) -> String {
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
        // the waterline columns (v0.53 recordings) — a recording replays
        // the machine story, drift included
        ("zombies", "", col(|p| Some(p.zombies as f64))),
        ("stuck in D", "", col(|p| Some(p.dstates as f64))),
        ("failed units", "", col(|p| Some(p.failed_units as f64))),
        ("mem eta (h)", "h", col(|p| p.mem_eta_hours)),
    ] {
        charts.push_str(&svg_series(name, unit, &series, t0, t1));
    }
    // process count is a plain usize series — same chart shape
    let procs: Vec<Option<f64>> = points.iter().map(|p| Some(p.procs as f64)).collect();
    charts.push_str(&svg_series("processes", "", &procs, t0, t1));
    // the per-process heatmap — the burst's face. Absent rows note the
    // skip rather than failing the machine charts.
    let heatmap_note = if proc_samples.is_empty() {
        "<p style=\"color:#657786\">no per-process rows in this recording — the heatmap is skipped (record with --watch 5 --record file.csv to feed it)</p>"
    } else {
        ""
    };
    let heatmap = proc_heatmap_svg(proc_samples);
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>witr-rs plot</title>\
<style>body{{background:#15202b;font-family:ui-monospace,Menlo,monospace;color:#e1e8ed;margin:24px}}</style>\
</head><body><h3>witr-rs · {} samples · {} – {}</h3><div>{charts}</div>{heatmap}{heatmap_note}</body></html>",
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

/// `--plot-events`: parse a `--events-log` JSONL file — one TuiEvent per
/// line, append order. Fleet lines carry an extra `host` field (serde
/// ignores unknown fields) and broken lines skip — it's a log, not a
/// contract.
fn parse_events_jsonl(text: &str) -> Vec<history::TuiEvent> {
    text.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// One process's life as the log saw it: a pid from its start (or the
/// log's first moment, if it was already running) to its exit, a restart
/// (the identity came back under a new pid), or the log's end (still
/// running when recording stopped).
struct LifeSeg {
    name: String,
    pid: Pid,
    from: i64,
    to: i64,
    /// "started" (alive at log end) | "exited" | "restarted"
    end: &'static str,
}

/// Rebuild the lifecycles from the log's lifecycle events. The log is
/// append-ordered but sort defensively; restarted events close every
/// open bar of the same identity (the detail names the old pid, but
/// matching by name is what survives a lost birth), and deaths with no
/// observed birth draw from the log's start — alive when the log began.
fn lifecycle_segments(events: &[history::TuiEvent], t_start: i64, t_end: i64) -> Vec<LifeSeg> {
    let mut evs: Vec<&history::TuiEvent> = events
        .iter()
        .filter(|e| {
            matches!(
                e.kind.as_str(),
                "started" | "exited" | "restarted"
            )
        })
        .collect();
    evs.sort_by_key(|e| e.at_unix);
    let mut open: std::collections::HashMap<Pid, (String, i64)> = std::collections::HashMap::new();
    let mut segs = Vec::new();
    for e in evs {
        match e.kind.as_str() {
            "started" => {
                open.insert(e.pid, (e.name.clone(), e.at_unix));
            }
            "restarted" => {
                let same: Vec<Pid> = open
                    .iter()
                    .filter(|(_, (n, _))| *n == e.name)
                    .map(|(p, _)| *p)
                    .collect();
                for p in same {
                    if let Some((name, from)) = open.remove(&p) {
                        segs.push(LifeSeg {
                            name,
                            pid: p,
                            from,
                            to: e.at_unix.max(from),
                            end: "restarted",
                        });
                    }
                }
                open.insert(e.pid, (e.name.clone(), e.at_unix));
            }
            _ => {
                // exited — with or without an observed birth
                let (name, from) = open
                    .remove(&e.pid)
                    .unwrap_or((e.name.clone(), t_start));
                segs.push(LifeSeg {
                    name,
                    pid: e.pid,
                    from,
                    to: e.at_unix.max(from),
                    end: "exited",
                });
            }
        }
    }
    for (pid, (name, from)) in open {
        segs.push(LifeSeg {
            name,
            pid,
            from,
            to: t_end,
            end: "started",
        });
    }
    segs.sort_by(|a, b| a.from.cmp(&b.from).then_with(|| a.pid.cmp(&b.pid)));
    segs
}

/// `--plot-events`: the self-contained HTML — a gantt of every identity's
/// lifecycle bars (restart deaths get a red tick, alerts a yellow one),
/// a system lane for the machine/container events, HH:MM axis. Zero JS,
/// zero external assets, double-clickable offline.
fn plot_events_html(events: &[history::TuiEvent], sources: &[String]) -> String {
    let t0 = events.iter().map(|e| e.at_unix).min().unwrap_or(0);
    let t1 = events
        .iter()
        .map(|e| e.at_unix)
        .max()
        .unwrap_or(t0)
        .max(t0 + 1);
    let segs = lifecycle_segments(events, t0, t1);

    // rows: one identity per row, first-seen order (already sorted by
    // from via the segments), capped — a fork storm shouldn't own the page
    const MAX_ROWS: usize = 30;
    let mut row_names: Vec<String> = Vec::new();
    for s in &segs {
        if !row_names.contains(&s.name) {
            row_names.push(s.name.clone());
        }
    }
    let hidden = row_names.len().saturating_sub(MAX_ROWS);
    row_names.truncate(MAX_ROWS);

    // alerts and container edges: pin to their identity's row when the
    // name matches, otherwise the system lane at the top
    let is_marker_kind = |k: &str| {
        matches!(
            k,
            "alert" | "recovered" | "container-death" | "container-health" | "container-events"
        )
    };
    let mut markers: Vec<(String, i64, &'static str)> = Vec::new(); // (name, at, color-key)
    let mut system_markers: Vec<(i64, &'static str, String)> = Vec::new(); // (at, key, name)
    for e in events.iter().filter(|e| is_marker_kind(&e.kind)) {
        if row_names.contains(&e.name) {
            let key = match e.kind.as_str() {
                "alert" => "alert",
                "recovered" => "recovered",
                _ => "container",
            };
            markers.push((e.name.clone(), e.at_unix, key));
        } else {
            let key = match e.kind.as_str() {
                "alert" => "alert",
                "recovered" => "recovered",
                _ => "container",
            };
            system_markers.push((e.at_unix, key, e.name.clone()));
        }
    }

    // geometry: label column + timeline, one row per identity, the
    // system lane on top
    let (w, label_w, row_h, top) = (1280.0, 200.0, 22.0, 46.0);
    let span = (t1 - t0).max(1) as f64;
    let x = |t: i64| label_w + (t - t0) as f64 / span * (w - label_w - 20.0);
    let at = |t: i64| crate::util::fmt_time(t).get(11..16).unwrap_or("").to_string();

    let mut svg = String::new();
    svg.push_str(&format!(
        "<svg width=\"{w}\" height=\"{}\" xmlns=\"http://www.w3.org/2000/svg\" font-family=\"ui-monospace,Menlo,monospace\">",
        (top + row_h * (row_names.len() + 1) as f64 + 30.0) as i32
    ));
    // time axis: ~6 HH:MM ticks
    for i in 0..=6 {
        let t = t0 + (span as i64) * i as i64 / 6;
        let px = x(t);
        svg.push_str(&format!(
            "<line x1=\"{px:.1}\" y1=\"{top}\" x2=\"{px:.1}\" y2=\"{}\" stroke=\"#22303c\"/>\
<text x=\"{px:.1}\" y=\"{}\" font-size=\"10\" fill=\"#657786\" text-anchor=\"middle\">{}</text>",
            top + row_h * (row_names.len() + 1) as f64,
            top - 6.0,
            at(t),
        ));
    }
    // the system lane (machine alerts + container edges that name no row)
    let sys_y = top + 6.0;
    svg.push_str(&format!(
        "<text x=\"4\" y=\"{}\" font-size=\"11\" fill=\"#8899a6\">system / containers</text>",
        sys_y + 12.0
    ));
    for (t, key, name) in &system_markers {
        let (color, shape) = match *key {
            "alert" => ("#fcc419", "M0,-6 L5,4 L-5,4 Z"),
            "recovered" => ("#51cf66", "M0,-5 L4,0 L0,5 L-4,0 Z"),
            _ => ("#cc5de8", "M-4,-4 L4,-4 L4,4 L-4,4 Z"),
        };
        let px = x(*t);
        svg.push_str(&format!(
            "<path d=\"{shape}\" transform=\"translate({px:.1},{:.1})\" fill=\"{color}\"><title>{} {}</title></path>",
            sys_y + 9.0,
            crate::util::fmt_time(*t),
            name
        ));
    }
    // identity rows
    let mut body = String::new();
    for (ri, name) in row_names.iter().enumerate() {
        let y = top + row_h * (ri + 1) as f64;
        // greedy sub-lanes so overlapping instances of one identity don't
        // overdraw (an nginx master + its workers share the name)
        let mut lanes: Vec<i64> = Vec::new(); // lane → free-from time
        let row_segs: Vec<&LifeSeg> = segs.iter().filter(|s| &s.name == name).collect();
        let mut placed: Vec<(usize, &LifeSeg)> = Vec::new();
        for s in &row_segs {
            let lane = lanes
                .iter()
                .position(|free| s.from >= *free)
                .unwrap_or(lanes.len());
            if lane == lanes.len() {
                lanes.push(0);
            }
            lanes[lane] = s.to;
            placed.push((lane, s));
        }
        body.push_str(&format!(
            "<text x=\"4\" y=\"{:.1}\" font-size=\"11\" fill=\"#e1e8ed\">{}</text>",
            y + 13.0,
            crate::render::html_escape(name)
        ));
        for (lane, s) in &placed {
            let (color, tag) = match s.end {
                "started" => ("#51cf66", "alive"),
                "exited" => ("#657786", "exited"),
                _ => ("#ff922b", "restarted"),
            };
            let x1 = x(s.from);
            let x2 = x(s.to).max(x1 + 2.0);
            let by = y + 4.0 + *lane as f64 * 14.0;
            body.push_str(&format!(
                "<rect x=\"{x1:.1}\" y=\"{by:.1}\" width=\"{:.1}\" height=\"10\" rx=\"2\" fill=\"{color}\" fill-opacity=\"0.75\"><title>{} (pid {}) · {} – {} · {tag}</title></rect>",
                x2 - x1,
                crate::render::html_escape(&s.name),
                s.pid,
                at(s.from),
                at(s.to),
            ));
        }
        // alert/recovery markers on this row
        for (mname, t, key) in markers.iter().filter(|(n, _, _)| n == name) {
            let (color, shape) = match *key {
                "alert" => ("#fcc419", "M0,-6 L5,4 L-5,4 Z"),
                _ => ("#51cf66", "M0,-5 L4,0 L0,5 L-4,0 Z"),
            };
            let px = x(*t);
            body.push_str(&format!(
                "<path d=\"{shape}\" transform=\"translate({px:.1},{:.1})\" fill=\"{color}\"><title>{} {mname}</title></path>",
                y + 12.0,
                at(*t),
            ));
        }
    }
    svg.push_str(&body);
    svg.push_str("</svg>");

    let counts = |k: &str| events.iter().filter(|e| e.kind == k).count();
    let legend = "\
<span style=\"margin-right:16px\"><span style=\"color:#51cf66\">■</span> alive at log end</span>\
<span style=\"margin-right:16px\"><span style=\"color:#657786\">■</span> exited</span>\
<span style=\"margin-right:16px\"><span style=\"color:#ff922b\">■</span> restarted</span>\
<span style=\"margin-right:16px\"><span style=\"color:#fcc419\">▲</span> alert</span>\
<span style=\"margin-right:16px\"><span style=\"color:#51cf66\">◆</span> recovered</span>\
<span style=\"margin-right:16px\"><span style=\"color:#cc5de8\">■</span> container</span>";
    let counts_line = format!(
        "{} started · {} exited · {} restarted · {} alerts · {} container edges",
        counts("started"),
        counts("exited"),
        counts("restarted"),
        counts("alert"),
        counts("container-death") + counts("container-health") + counts("container-events"),
    );
    let more_line = if hidden > 0 {
        format!("<p style=\"color:#657786\">+{hidden} more identities beyond the first {MAX_ROWS} rows</p>")
    } else {
        String::new()
    };
    let srcs = sources.join(" · ");
    let t0_s = crate::util::fmt_time(t0);
    let t1_s = crate::util::fmt_time(t1);
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>witr-rs events</title>\
<style>body{{background:#15202b;font-family:ui-monospace,Menlo,monospace;color:#e1e8ed;margin:24px}}</style>\
</head><body><h3>witr-rs events · {srcs} · {t0_s} – {t1_s}</h3>\
<div style=\"margin-bottom:8px\">{counts_line}</div>\
<div style=\"margin-bottom:8px\">{legend}</div>\
<div>{svg}</div>\
{more_line}\
</body></html>"
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
    if cli.sockets
        && cli.snap.is_none()
        && cli.baseline_save.is_none()
        && cli.baseline.is_none()
        && cli.alert_baseline.is_none()
    {
        eprintln!(
            "--sockets extends --snap, --baseline-save, --baseline or --alert-baseline; add one of them"
        );
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
                || (cli.watch.is_some()
                    && flag != "--sys"
                    // the fleet --services form refreshes under --watch
                    // like every fleet surface; the local listing is one-shot
                    && !(flag == "--services" && !cli.remote.is_empty()))
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
    if cli.by_user && cli.agg.is_none() && cli.top.is_none() {
        eprintln!("--by-user rolls up a --top board or an --agg recording; add one");
        std::process::exit(4);
    }
    if let Some(name) = one_shot_listing_name(&cli)
        .filter(|_| cli.watch.is_some())
        // the fleet --services form refreshes under --watch like the
        // other fleet surfaces; only the local listing is one-shot
        .filter(|_| cli.remote.is_empty())
    {
        eprintln!(
            "{name} is a one-shot listing — --watch would be silently ignored; drop --watch"
        );
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

    // --export-grafana: write the ready-made Grafana dashboard JSON — a
    // no-target standalone like --snap/--diff.
    if let Some(path) = &cli.export_grafana {
        if !specs.is_empty() || cli.interactive {
            eprintln!("--export-grafana writes a dashboard file; drop the targets or -i");
            std::process::exit(4);
        }
        if cli.watch.is_some() {
            eprintln!("--export-grafana writes one file and exits; drop --watch");
            std::process::exit(4);
        }
        let doc = render::grafana_dashboard();
        let body = serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into());
        if let Err(e) = std::fs::write(path, &body) {
            // the report writers create missing parent dirs — same courtesy
            let p = std::path::Path::new(path);
            if e.kind() == std::io::ErrorKind::NotFound {
                if let Some(dir) = p.parent() {
                    if std::fs::create_dir_all(dir).is_ok() {
                        let _ = std::fs::write(path, &body);
                    }
                }
            }
            if !std::path::Path::new(path).exists() {
                eprintln!("--export-grafana {path}: {e}");
                std::process::exit(5);
            }
        }
        let panels = doc["panels"].as_array().map(|a| a.len()).unwrap_or(0);
        write_out(&format!(
            "Grafana dashboard written → {path} ({panels} panels — import it in Grafana and pick the Prometheus datasource)"
        ));
        std::process::exit(0);
    }

    // --export-alert-rules: the Prometheus side of the same setup — write
    // the ready-made alerting rules and exit, a no-target standalone.
    if let Some(path) = &cli.export_alert_rules {
        if !specs.is_empty() || cli.interactive {
            eprintln!("--export-alert-rules writes a rules file; drop the targets or -i");
            std::process::exit(4);
        }
        if cli.watch.is_some() {
            eprintln!("--export-alert-rules writes one file and exits; drop --watch");
            std::process::exit(4);
        }
        let body = render::alert_rules_yaml();
        if let Err(e) = std::fs::write(path, &body) {
            // the report writers create missing parent dirs — same courtesy
            let p = std::path::Path::new(path);
            if e.kind() == std::io::ErrorKind::NotFound {
                if let Some(dir) = p.parent() {
                    if std::fs::create_dir_all(dir).is_ok() {
                        let _ = std::fs::write(path, &body);
                    }
                }
            }
            if !std::path::Path::new(path).exists() {
                eprintln!("--export-alert-rules {path}: {e}");
                std::process::exit(5);
            }
        }
        let n = body.matches("      - alert:").count();
        write_out(&format!(
            "Prometheus alert rules written → {path} ({n} rules — drop it in rule_files and reload Prometheus)"
        ));
        std::process::exit(0);
    }

    // --agg FILE: fold a --record sample file into one window board —
    // "who ate the most CPU over the past hour", answered from data that
    // already exists. A no-target standalone like --export-grafana.
    if let Some(path) = &cli.agg {
        if !specs.is_empty() || cli.interactive {
            eprintln!("--agg aggregates a record file; drop the targets or -i");
            std::process::exit(4);
        }
        if cli.watch.is_some() {
            eprintln!("--agg is one-shot; drop --watch");
            std::process::exit(4);
        }
        if !matches!(
            cli.top.unwrap_or(cli::TopMetric::Cpu),
            cli::TopMetric::Cpu | cli::TopMetric::Mem | cli::TopMetric::Io
        ) {
            eprintln!(
                "--agg ranks by --top cpu (integrated CPU-time), --top mem (peak RSS) or --top io (bytes moved); the recording carries no other metric"
            );
            std::process::exit(4);
        }
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("--agg {path}: {e}");
                std::process::exit(5);
            }
        };
        let samples = parse_record_processes(&text);
        if samples.is_empty() {
            eprintln!(
                "--agg {path}: no process rows (is this a --record file? .csv or .jsonl)"
            );
            std::process::exit(5);
        }
        let metric = cli.top.unwrap_or(cli::TopMetric::Cpu);
        let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
        // the window facts both boards share
        let window_to = samples.iter().map(|s| s.at).reduce(i64::max);
        let window_from = samples.iter().map(|s| s.at).reduce(i64::min);
        let ticks = samples
            .iter()
            .map(|s| s.at)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let ranked_by = match metric {
            cli::TopMetric::Mem => "rss_peak_mb",
            cli::TopMetric::Io => "io_total_bytes",
            _ => "cpu_seconds",
        };
        if cli.by_user {
            // the same recording rolled up by owner: per-tick sums mean
            // the RSS column reads as the user's simultaneous footprint
            let rows = aggregate_record_by_user(&samples, metric, cli.count.unwrap_or(15));
            if cli.json {
                let doc = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "generated_at": util::now_unix(),
                    "source": path,
                    "window": {"from": window_from, "to": window_to, "ticks": ticks},
                    "ranked_by": ranked_by,
                    "user_count": rows.len(),
                    "users": rows,
                });
                write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
            } else if cli.csv {
                write_out(&render::render_user_agg_csv(&rows));
            } else if cli.markdown {
                write_out(&render::render_user_agg_markdown(&rows));
            } else {
                write_out(&render::render_user_agg(&rows, &painter));
            }
            std::process::exit(0);
        }
        let rows = aggregate_record(&samples, metric, cli.count.unwrap_or(15));
        if cli.json {
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "source": path,
                "window": {"from": window_from, "to": window_to, "ticks": ticks},
                "ranked_by": ranked_by,
                "rows": rows,
            });
            write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
        } else if cli.csv {
            write_out(&render::render_record_agg_csv(&rows));
        } else if cli.markdown {
            write_out(&render::render_record_agg_markdown(&rows));
        } else {
            write_out(&render::render_record_agg(&rows, &painter));
        }
        std::process::exit(0);
    }

    // --check: the alert vocabulary without a resident watcher — one pass
    // over every armed threshold, violations exit 1, clean exits 0.
    // cron+mail health checks and pre-deploy gates run the same
    // thresholds the --watch loop patrols.
    if cli.check {
        if cli.interactive {
            eprintln!("--check sweeps the whole machine; drop -i");
            std::process::exit(4);
        }
        if cli.watch.is_some() {
            eprintln!("--check is one pass; plain --watch already patrols continuously");
            std::process::exit(4);
        }
        if !cli.remote.is_empty() {
            // the fleet one-shot: machine sentinels judged per host
            reject_fleet_per_process_alerts(&cli);
            let bases = cli.remote.clone();
            std::process::exit(run_check_fleet(&bases, &cli));
        }
        if !specs.is_empty() {
            eprintln!("--check sweeps the whole machine; drop the targets");
            std::process::exit(4);
        }
        let platform = platform::get();
        std::process::exit(run_check_once(&*platform, &cli));
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
        let mut named: Vec<(String, String, Vec<SysPoint>)> = Vec::new(); // (path, text, points)
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
            named.push((path.clone(), text, points));
        }
        let (out, html, total) = if named.len() == 1 {
            let (path, text, points) = &named[0];
            let samples = parse_record_processes(text);
            (format!("{path}.html"), plot_html(points, &samples), points.len())
        } else {
            let total: usize = named.iter().map(|(_, _, p)| p.len()).sum();
            let pairs: Vec<(String, Vec<SysPoint>)> = named
                .iter()
                .map(|(p, _, pts)| (p.clone(), pts.clone()))
                .collect();
            ("witr-plot.html".to_string(), plot_html_multi(&pairs), total)
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

    // --plot-events: render --events-log files into a self-contained HTML
    // lifecycle timeline (gantt) — a no-target operation like --plot.
    if !cli.plot_events.is_empty() {
        if !specs.is_empty() || cli.interactive {
            eprintln!("--plot-events renders event logs; drop the targets or -i");
            std::process::exit(4);
        }
        if cli.watch.is_some() {
            eprintln!("--plot-events writes one chart and exits; drop --watch");
            std::process::exit(4);
        }
        let mut events = Vec::new();
        for path in &cli.plot_events {
            let text = match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("--plot-events {path}: {e}");
                    std::process::exit(5);
                }
            };
            events.extend(parse_events_jsonl(&text));
        }
        if events.is_empty() {
            eprintln!(
                "--plot-events: no events parsed — is this a --events-log JSONL file?"
            );
            std::process::exit(5);
        }
        let (out, html) = if cli.plot_events.len() == 1 {
            let path = &cli.plot_events[0];
            (format!("{path}.html"), plot_events_html(&events, &cli.plot_events))
        } else {
            (
                "witr-events.html".to_string(),
                plot_events_html(&events, &cli.plot_events),
            )
        };
        if let Err(e) = std::fs::write(&out, &html) {
            eprintln!("--plot-events: cannot write {out}: {e}");
            std::process::exit(5);
        }
        write_out(&format!(
            "events: {} file{}, {} events → {out}",
            cli.plot_events.len(),
            if cli.plot_events.len() == 1 { "" } else { "s" },
            events.len(),
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
    if cli.sys && cli.remote.is_empty() {
        let platform = platform::get();
        let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
        if let Some(secs) = cli.watch {
            let interval = secs.max(1);
            install_sigint_flag();
            let mut net_prev: Option<(Vec<platform::NicCounters>, Instant)> = None;
            let mut ticks: u64 = 0;
            loop {
                let procs = platform.list_processes().unwrap_or_default();
                let frame = sys_frame(platform.as_ref(), &mut net_prev, &procs);
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
        let procs = platform.list_processes().unwrap_or_default();
        let _ = sys_frame(platform.as_ref(), &mut net_prev, &procs);
        std::thread::sleep(Duration::from_secs(1));
        let procs = platform.list_processes().unwrap_or_default();
        let frame = sys_frame(platform.as_ref(), &mut net_prev, &procs);
        if cli.json {
            // the flat fields merge straight into the envelope (the shape
            // predates the fleet form; keep it byte-compatible)
            let mut doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
            });
            if let serde_json::Value::Object(map) = render::sys_json(&frame, None) {
                for (k, v) in map {
                    doc[k] = v;
                }
            }
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

    // --remote: render other hosts' tables instead of the local machine's —
    // a standalone mode like --serve (the peers run `witr-rs --serve`)
    if !cli.remote.is_empty() {
        remote_mode(&cli.remote.clone(), &cli, no_color);
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
            state_file: cli.state_file.clone(),
            exit_state_slot: Some(std::sync::Arc::new(std::sync::Mutex::new(None))),
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
        let exit_slot = std::sync::Arc::new(std::sync::Mutex::new(None));
        // seed 拿走克隆;main 持原件读回
        let mut seed_for_slot = seed.clone();
        seed_for_slot.exit_state_slot = Some(exit_slot.clone());
        if let Err(e) = tui::run(seed_for_slot) {
            eprintln!("tui error: {}", e);
            std::process::exit(5);
        }
        // the session's sentinel state → the --state-file (same write as the watchdog)
        if let (Some(path), Some(slot)) = (&cli.state_file, exit_slot.lock().unwrap_or_else(|e| e.into_inner()).take()) {
            let persisted = slot.to_persisted();
            if let Ok(json) = serde_json::to_string(&persisted) {
                let _ = crate::util::write_atomic(std::path::Path::new(path), &json);
            }
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

    // --deleted: open-but-deleted files — the "df full, du disagrees"
    // answer. Exit 1 when any exist so scripts can branch directly.
    if cli.deleted {
        let platform = platform::get();
        let rows = render::collect_deleted(&platform.deleted_files());
        if cli.json {
            let total_mb: u64 = rows.iter().map(|r| r.size_mb).sum();
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "deleted_count": rows.len(),
                "reclaimable_mb": total_mb,
                "deleted": rows,
            });
            write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
        } else if cli.csv {
            write_out(&render::render_deleted_csv(&rows));
        } else if cli.markdown {
            write_out(&render::render_deleted_markdown(&rows));
        } else {
            let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
            write_out(&render::render_deleted(&rows, &painter));
        }
        std::process::exit(if rows.is_empty() { 0 } else { 1 });
    }

    // --dstate: processes stuck in uninterruptible wait — the --zombies
    // twin for the storage-hang signature. Exit 1 when any exist so
    // scripts can branch directly.
    if cli.dstate {
        let platform = platform::get();
        let listed = match platform.list_processes() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cannot list processes: {}", e);
                std::process::exit(5);
            }
        };
        let rows = render::collect_dstates(&listed);
        if cli.json {
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "dstate_count": rows.len(),
                "dstates": rows,
            });
            write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
        } else if cli.csv {
            write_out(&render::render_dstates_csv(&rows));
        } else if cli.markdown {
            write_out(&render::render_dstates_markdown(&rows));
        } else {
            let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
            write_out(&render::render_dstates(&rows, &painter));
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

    // --baseline-save: the security baseline — process identities (the
    // name|exe|user triples, pid-free so it survives reboots), listeners
    // (with --sockets) and the service set. The norm --baseline/--alert-
    // baseline judge against.
    if let Some(path) = &cli.baseline_save {
        let platform = platform::get();
        let procs = match platform.list_processes() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cannot list processes: {e}");
                std::process::exit(5);
            }
        };
        let listeners = if cli.sockets {
            let socks = platform.list_sockets().unwrap_or_default();
            snapshot::to_listeners(&socks, &procs)
        } else {
            Vec::new()
        };
        let services: Vec<String> = platform::enumerate_services()
            .iter()
            .map(|s| s.name.clone())
            .collect();
        match snapshot::save_baseline(path, &procs, &listeners, &services) {
            Ok(()) => write_out(&format!(
                "baseline saved: {} identities · {} listener(s){} · {} service(s) → {path}",
                procs.len(),
                listeners.len(),
                if cli.sockets { String::new() } else { " (add --sockets for port tracking)".to_string() },
                services.len(),
            )),
            Err(e) => {
                eprintln!("--baseline-save {path}: {e}");
                std::process::exit(5);
            }
        }
        std::process::exit(0);
    }

    // --baseline FILE: check the live state against a saved baseline.
    // Anything not in the baseline is an intruder until proven otherwise.
    if let Some(path) = &cli.baseline {
        let platform = platform::get();
        let procs = match platform.list_processes() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cannot list processes: {e}");
                std::process::exit(5);
            }
        };
        let now_listeners = if cli.sockets {
            let socks = platform.list_sockets().unwrap_or_default();
            snapshot::to_listeners(&socks, &procs)
        } else {
            Vec::new()
        };
        let baseline = match snapshot::load_baseline(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("--baseline {path}: {e}");
                std::process::exit(4);
            }
        };
        let now_services: Vec<String> = platform::enumerate_services()
            .iter()
            .map(|s| s.name.clone())
            .collect();
        let failed: Vec<String> = platform::get()
            .failed_units()
            .unwrap_or_default()
            .into_iter()
            .filter(|u| now_services.contains(u))
            .collect();
        let drift = snapshot::baseline_drift(
            &baseline,
            &procs,
            &now_listeners,
            &now_services,
            &failed,
        );
        if cli.json {
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "drift_count": drift.len(),
                "drift": drift,
            });
            write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
        } else if drift.is_empty() {
            write_out("✔ live state matches the baseline");
        } else {
            for line in &drift {
                write_out(&format!("⚠ {line}"));
            }
            write_out(&format!("{} drift entr(ies)", drift.len()));
        }
        std::process::exit(if drift.is_empty() { 0 } else { 1 });
    }

    // --doctor: the environment self-check — every optional capability
    // probed live, with the reason it's missing and what goes silent.
    // Informational: exit 0 regardless (--json for scripts).
    if cli.doctor {
        let checks = doctor::run_checks();
        if cli.json {
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "checks": checks,
            });
            write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
        } else {
            let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
            write_out(&doctor::render_checks(&checks, &painter));
        }
        std::process::exit(0);
    }

    // --timers: the systemd timers patrol list — next/last elapse per
    // timer, the "该跑没跑" visibility (a timer that never fired shows
    // last = n/a).
    // --timers: the systemd timers patrol list. One-shot by default;
    // --watch refreshes the TEXT view in place (machine-readable formats
    // stay one-shot, their consumers own their cadence — the --sys rule).
    if cli.timers {
        let machine_readable = cli.json || cli.csv || cli.markdown;
        if cli.watch.is_some() && machine_readable {
            eprintln!("machine-readable --timers is one-shot; drop --watch or the format flag");
            std::process::exit(4);
        }
        let render_rows = |rows: &[crate::platform::TimerRow],
                           painter: &render::Painter|
         -> String {
            if cli.json {
                let doc = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "generated_at": util::now_unix(),
                    "timer_count": rows.len(),
                    "timers": rows,
                });
                return serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into());
            }
            if cli.csv {
                let mut out = String::from("unit,next,left,last,passed,activates\n");
                for r in rows {
                    out.push_str(&format!(
                        "{},{},{},{},{},{}\n",
                        render::csv_field(&r.unit),
                        render::csv_field(&r.next),
                        render::csv_field(&r.left),
                        render::csv_field(r.last.as_deref().unwrap_or("")),
                        render::csv_field(&r.passed),
                        render::csv_field(&r.activates),
                    ));
                }
                return out;
            }
            if cli.markdown {
                let mut out = String::from(
                    "| UNIT | NEXT | LEFT | LAST | PASSED | ACTIVATES |\n|---|---|---|---|---|---|\n",
                );
                for r in rows {
                    out.push_str(&format!(
                        "| {} | {} | {} | {} | {} | {} |\n",
                        r.unit,
                        r.next,
                        r.left,
                        r.last.as_deref().unwrap_or("n/a"),
                        r.passed,
                        r.activates
                    ));
                }
                return out;
            }
            let mut out = String::new();
            out.push_str(&format!(
                "{:<24}  {:<26}  {:>8}  {:<26}  {:>10}  {}\n",
                painter.bold("UNIT"),
                painter.bold("NEXT"),
                painter.bold("LEFT"),
                painter.bold("LAST"),
                painter.bold("PASSED"),
                painter.bold("ACTIVATES")
            ));
            for r in rows {
                let last = match &r.last {
                    Some(l) => l.clone(),
                    None => painter.yellow("never fired"),
                };
                out.push_str(&format!(
                    "{:<24}  {:<26}  {:<26}  {:>8}  {:>10}  {}\n",
                    r.unit,
                    r.next,
                    r.left,
                    last,
                    r.passed,
                    r.activates
                ));
            }
            out
        };
        match cli.watch {
            Some(secs) => {
                let interval = secs.max(1);
                install_sigint_flag();
                let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
                let mut ticks = 0u64;
                loop {
                    let Some(rows) = platform::get().list_timers() else {
                        eprintln!("--timers: no systemd to ask");
                        std::process::exit(4);
                    };
                    if !cli.quiet {
                        write_out("\x1b[2J\x1b[1;1H");
                        let now = util::fmt_time(util::now_unix());
                        write_out(&format!(
                            "witr-rs timers · every {interval}s · {now} · Ctrl-C to stop"
                        ));
                    }
                    write_out(&render_rows(&rows, &painter));
                    ticks += 1;
                    if cli.times.is_some_and(|n| ticks >= n.max(1)) {
                        std::process::exit(0);
                    }
                    if !sleep_interruptible(interval) {
                        std::process::exit(130);
                    }
                }
            }
            None => {
                let Some(rows) = platform::get().list_timers() else {
                    eprintln!("--timers: no systemd to ask");
                    std::process::exit(4);
                };
                let painter = render::Painter::new(!no_color && std::io::stdout().is_terminal());
                write_out(&render_rows(&rows, &painter));
                std::process::exit(0);
            }
        }
    }

    // -u UNIT: a systemd unit's report — status line, main pid, restart
    // count, enablement, last exit code/signal, with --logs appending the
    // unit's journal tail. Exit mirrors the patrol probes: 0 clean,
    // 1 failed, 2 missing.
    if let Some(unit) = &cli.unit {
        let Some(r) = platform::get().unit_report(unit) else {
            if cli.json {
                let doc = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "generated_at": util::now_unix(),
                    "unit": unit,
                    "found": false,
                });
                write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
            } else {
                eprintln!("unit {unit}: not found (or no systemd to ask)");
            }
            std::process::exit(2);
        };
        let failed = r.active_state.as_deref() == Some("failed");
        if cli.json {
            let doc = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": util::now_unix(),
                "found": true,
                "failed": failed,
                "report": r,
            });
            write_out(&serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()));
        } else {
            let color = !no_color && std::io::stdout().is_terminal();
            let painter = render::Painter::new(color);
            let painter = &painter;
            let status = format!(
                "{} / {} / {}",
                r.load_state.as_deref().unwrap_or("?"),
                r.active_state.as_deref().unwrap_or("?"),
                r.sub_state.as_deref().unwrap_or("?"),
            );
            let status_line = if failed {
                painter.red(&status)
            } else {
                status
            };
            write_out(&format!("unit   {}  [{}]", r.unit, status_line));
            if let Some(d) = &r.description {
                write_out(&format!("desc   {d}"));
            }
            if let Some(pid) = r.main_pid {
                write_out(&format!(
                    "pid    {pid}  (witr-rs --pid {pid} traces it; --logs tails its journal)"
                ));
            }
            if let Some(n) = r.n_restarts.filter(|n| *n > 0) {
                let tag = if n >= 3 { " — crash loop?" } else { "" };
                write_out(&painter.yellow(&format!("restarts {n}{tag}")));
            }
            if let Some(s) = &r.unit_file_state {
                write_out(&format!("boot   {s}"));
            }
            if let Some(code) = &r.exit_code {
                let line = match r.exit_status {
                    Some(st) => format!("last exit {code} {st}"),
                    None => format!("last exit {code}"),
                };
                write_out(&painter.yellow(&line));
            }
            if let Some(since) = &r.since {
                write_out(&format!("since  {since}"));
            }
        }
        // --logs appends the unit's journal slice (the unit's own
        // `-u` filter, not a pid's)
        if let Some(n) = cli.logs {
            let src = logs::LogSource::SystemdUnit { unit: unit.clone() };
            write_out("");
            let grep_note = cli
                .grep
                .as_deref()
                .map(|g| format!(" · grep '{g}'"))
                .unwrap_or_default();
            write_out(&format!(
                "== recent logs · {} · last {n}{grep_note} ==",
                src.describe()
            ));
            match logs::fetch(&src, n.max(1) as usize) {
                Ok(lines) if lines.is_empty() => write_out("(no log entries for this unit)"),
                Ok(lines) => {
                    for l in lines {
                        match cli.grep.as_deref() {
                            Some(g) if !l.contains(g) => continue,
                            _ => write_out(&l),
                        }
                    }
                }
                Err(e) => write_out(&format!("⚠ {e}")),
            }
        }
        std::process::exit(if failed { 1 } else { 0 });
    }

    if cli.failed && !cli.services {
        eprintln!("--failed filters --services; add --services");
        std::process::exit(4);
    }
    // --services: the service manager's units (the Services tab's CLI
    // twin). One enumerate call per invocation — the table is meant for
    // humans and scripts, not polling loops.
    if cli.services {
        let mut svcs = platform::enumerate_services();
        if cli.failed {
            let failed: std::collections::HashSet<String> =
                crate::platform::get()
                    .failed_units()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
            svcs.retain(|s| failed.contains(&s.name));
        }
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
                if cli.by_user {
                    let rows = render::rank_by_user(
                        &procs,
                        metric,
                        count,
                        fds.as_ref(),
                        Some(&hist),
                        conns.as_ref(),
                    );
                    if cli.json {
                        write_out(&json_user_envelope(&rows));
                    } else if cli.csv {
                        write_out(&render::render_top_by_user_csv(&rows));
                    } else if cli.markdown {
                        write_out(&render::render_top_by_user_markdown(&rows, metric));
                    } else {
                        write_out(&render::render_top_by_user(&rows, metric, &painter));
                    }
                } else {
                    write_out(&render::render_top(
                        &procs,
                        metric,
                        count,
                        fds.as_ref(),
                        Some(&hist),
                        conns.as_ref(),
                        &painter,
                    ));
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
            if cli.by_user {
                let rows = render::rank_by_user(
                    &procs,
                    metric,
                    count,
                    fds.as_ref(),
                    rates.as_ref(),
                    conns.as_ref(),
                );
                if cli.json {
                    write_out(&json_user_envelope(&rows));
                } else if cli.csv {
                    write_out(&render::render_top_by_user_csv(&rows));
                } else if cli.markdown {
                    write_out(&render::render_top_by_user_markdown(&rows, metric));
                } else {
                    write_out(&render::render_top_by_user(&rows, metric, &painter));
                }
            } else if cli.json {
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
                state_file: cli.state_file.clone(),
                exit_state_slot: Some(std::sync::Arc::new(std::sync::Mutex::new(None))),
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
            let exit_slot = std::sync::Arc::new(std::sync::Mutex::new(None));
            let mut seed_for_slot = seed.clone();
            seed_for_slot.exit_state_slot = Some(exit_slot.clone());
            if let Err(e) = tui::run(seed_for_slot) {
                eprintln!("tui error: {}", e);
                std::process::exit(5);
            }
            // the session's sentinel state → the --state-file (same write as the watchdog)
            if let (Some(path), Some(slot)) = (&cli.state_file, exit_slot.lock().unwrap_or_else(|e| e.into_inner()).take()) {
                let persisted = slot.to_persisted();
                if let Ok(json) = serde_json::to_string(&persisted) {
                    let _ = crate::util::write_atomic(std::path::Path::new(path), &json);
                }
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
            // the recorder's own trend window: mem-eta needs 10+ minutes
            // of MemAvailable samples before the gate trusts a prediction
            let mut rec_eta = history::SysAlertState::default();

            // the --alert-baseline norm: loaded once (compare failures
            // would repeat forever — one loud exit-code-4 message instead)
            let baseline: Option<(Vec<Process>, Vec<snapshot::Listener>, Vec<String>)> =
                match &cli.alert_baseline {
                    Some(path) => match snapshot::load_baseline(path) {
                        Ok(b) => Some(b),
                        Err(e) => {
                            eprintln!("--alert-baseline {path}: {e}");
                            std::process::exit(4);
                        }
                    },
                    None => None,
                };
            let mut baseline_reported: std::collections::HashSet<String> =
                std::collections::HashSet::new();
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
            // --state-file: the sentinel state's restart-surviving slice
            // (eta windows, exe baseline, OOM anchor) — loaded once here,
            // written atomically each tick (a crash mid-write leaves the
            // previous state intact; a watchdog restart resumes instead
            // of re-accruing)
            let mut state_file: Option<String> = cli.state_file.clone();
            if let Some(path) = &state_file {
                match std::fs::read_to_string(path) {
                    Ok(text) => match serde_json::from_str::<history::PersistedState>(&text) {
                        Ok(persisted) => {
                            sys_alert.restore_persisted(&persisted);
                            write_out(&format!(
                                "state restored from {path} ({} eta sample(s), {} exe baseline entr(ies))",
                                persisted.mem_eta_hist.len() + persisted.disk_eta_hist.iter().map(|(_, d)| d.len()).sum::<usize>(),
                                persisted.exe_watched.len(),
                            ));
                        }
                        Err(e) => {
                            eprintln!("--state-file {path}: unreadable ({e}) — starting fresh");
                        }
                    },
                    Err(_) => {
                        write_out(&format!("state file {path} starts fresh"));
                    }
                }
            }
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
            let mut container_thresholds = history::ContainerThresholds::default();
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
                    let waterlines = RecordWaterlines {
                    zombies: state_count(&procs, &["Z"]),
                    dstates: state_count(&procs, &["D", "U"]),
                    failed_units: if platform.name() == "linux" {
                        platform.failed_units().unwrap_or_default().len()
                    } else {
                        0
                    },
                    mem_eta_hours: stats.as_ref().and_then(|s| s.mem_avail_mb).and_then(|a| {
                        history::mem_eta_picks(&mut rec_eta, Some(a), f64::INFINITY)
                            .map(|(h, _)| h)
                    }),
                };
                w.append(&procs, &hist, stats.as_ref(), net_bps, &waterlines);
                }
                // --alert-net-per-proc: feed this tick's ss sweep into the
                // persistent history so per-pid rates exist to compare
                // (absent ss leaves the sentinel quiet, like the board)
                if cli.alert_net_per_proc.is_some() {
                    if let Some(sweep) = platform::net_bytes_per_pid() {
                        hist.update_net(&sweep);
                    }
                }
                // the security sentinels: binary replacement (stat per
                // tick, hash only on an mtime move) and first-contact
                // remotes (one ss sweep, paid only while armed — the
                // net-per-proc precedent)

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
                // the leak sentinels ride the sampler's windows (RSS and
                // thread counts accrue for the whole table; the fd one
                // needs the full-table sweep fed first, paid only while
                // armed) — verdicts feed the same picks pipeline
                if cli.alert_fd_leak.is_some() {
                    if let Some(fds) = platform.fd_counts() {
                        for (pid, n) in &fds {
                            hist.record_fd(*pid, *n);
                        }
                    }
                }
                for (kind, min) in [
                    (history::LeakKind::Mem, cli.alert_leak),
                    (history::LeakKind::Fd, cli.alert_fd_leak),
                    (history::LeakKind::Threads, cli.alert_thr_leak),
                ] {
                    if let Some(min) = min {
                        picks.extend(history::leak_alert_picks(
                            &hist,
                            &procs,
                            kind,
                            min,
                            interval as f64,
                            interval,
                            &mut sys_alert,
                        ));
                    }
                }
                // the security sentinels: binary replacement (stat per
                // tick, hash only on an mtime move) and first-contact
                // remotes (one ss sweep, paid only while armed — the
                // net-per-proc precedent)
                if cli.alert_exe_changed {
                    picks.extend(history::exe_change_picks(&procs, &mut sys_alert));
                }
                if cli.alert_new_remote {
                    let socks = platform.list_all_sockets().unwrap_or_default();
                    picks.extend(history::new_remote_picks(&socks, &procs, &mut sys_alert));
                }
                // the timers-staleness sentinel: OnUnitActiveSec-type
                // timers whose last run outran FACTOR periods
                if let Some(factor) = cli.alert_timers_stale {
                    if let Some(timers) = platform.list_timers() {
                        picks.extend(
                            history::timers_stale_picks(&timers, factor, &mut sys_alert)
                                .into_iter()
                                .map(|(name, d, rec)| (0, name, d, rec)),
                        );
                    }
                }
                if let Some(path) = state_file.as_deref() {
                    let persisted = sys_alert.to_persisted();
                    if let Ok(json) = serde_json::to_string(&persisted) {
                        if let Err(e) = crate::util::write_atomic(std::path::Path::new(path), &json) {
                            eprintln!("--state-file {path}: write failed ({e}) — disabling");
                            state_file = None;
                        }
                    }
                }
                // the baseline-drift sentinel: the saved norm is judged per
                // tick — new identities and new listeners fire once each
                if cli.alert_baseline.is_some() {
                    let now_listeners = if cli.sockets {
                        let socks = platform.list_sockets().unwrap_or_default();
                        snapshot::to_listeners(&socks, &procs)
                    } else {
                        Vec::new()
                    };
                    let now_services: Vec<String> = platform::enumerate_services()
                        .iter()
                        .map(|s| s.name.clone())
                        .collect();
                    let Some(base) = baseline.as_ref() else {
                        continue;
                    };
                    for line in snapshot::baseline_drift(
                        base,
                        &procs,
                        &now_listeners,
                        &now_services,
                        &[],
                    ) {
                        if baseline_reported.insert(line.clone()) {
                            picks.push((0, "baseline".into(), line, false));
                        }
                    }
                }
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
                    || cli.alert_oom.is_some()
                    || cli.alert_disk_eta.is_some()
                    || cli.alert_mem_eta.is_some()
                    || cli.alert_disk_busy.is_some()
                    || cli.alert_gpu_mem_pct.is_some()
                    || cli.alert_deleted_gb.is_some()
                    || cli.alert_temp.is_some()
                    || cli.alert_zombies.is_some()
                    || cli.alert_dstate.is_some()
                    || cli.alert_failed_units.is_some()
                    || cli.alert_exe_changed
                    || cli.alert_new_remote
                    || cli.alert_timers_stale.is_some()
                    || cli.alert_baseline.is_some()
                    || cli.alert_leak.is_some()
                {
                    if let Some(stats) = platform.system_stats() {
                        let mounts = if cli.alert_disk.is_some() || cli.alert_disk_eta.is_some() {
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
                        let (deleted_files, deleted_total_mb) =
                            if cli.alert_deleted_gb.is_some() {
                                let files = platform.deleted_files();
                                let total = files.iter().map(|d| d.size_mb).sum();
                                (files, total)
                            } else {
                                (Vec::new(), 0)
                            };
                        let service_mems = if cli.alert_service_mem.is_some() {
                            crate::platform::enumerate_services()
                                .iter()
                                .filter_map(|s| s.mem_current.map(|m| (s.name.clone(), m)))
                                .collect()
                        } else {
                            Vec::new()
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
                            oom_limit: cli.alert_oom,
                            oom_kills: stats.oom_kills,
                            disk_eta_hours: cli.alert_disk_eta,
                            mem_eta_hours: cli.alert_mem_eta,
                            inodes_limit: cli.alert_inodes,
                            gpu_mem_pct_limit: cli.alert_gpu_mem_pct,
                            deleted_gb_limit: cli.alert_deleted_gb,
                            deleted_files: deleted_files.clone(),
                            deleted_total_mb,
                            gpus: stats.gpus.clone(),
                            disk_busy_limit: cli.alert_disk_busy,
                            temp_limit: cli.alert_temp,
                            zombie_limit: cli.alert_zombies,
                            zombie_count: state_count(&procs, &["Z"]),
                            dstate_limit: cli.alert_dstate,
                            dstate_count: state_count(&procs, &["D", "U"]),
                            failed_limit: cli.alert_failed_units,
                            failed_units: if cli.alert_failed_units.is_some() {
                                platform.failed_units().unwrap_or_default()
                            } else {
                                Vec::new()
                            },
                            service_mem_limit: cli.alert_service_mem,
                            service_mems,
                            repeat: cli.alert_repeat,
                        };
                        let mut sys_picks = history::system_alert_picks(
                            &stats,
                            &mut sys_alert,
                            &limits,
                            interval,
                        );
                        attribute_oom(&mut sys_picks, platform.as_ref(), interval);
                        for (name, detail, rec) in sys_picks {
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
                            let cpu_lim = cli.alert_container_cpu;
                            let mem_lim = cli.alert_container_mem_pct;
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
                                        c.io_by_device = Some(
                                            p.io_by_device
                                                .iter()
                                                .map(|(device, r, w)| crate::model::ContainerDeviceIo {
                                                    device: device.clone(),
                                                    read_bytes: *r,
                                                    write_bytes: *w,
                                                })
                                                .collect(),
                                        );
                                        c.io_write_bytes = Some(p.io_write);
                                    }
                                }
                                // the resource thresholds read cpu%/memory off
                                // this snapshot — merge the stats sweep in when
                                // armed (seconds per container, never paid
                                // otherwise); the threshold flags ride in by
                                // value because `cli` can't cross the spawn
                                if cpu_lim.is_some() || mem_lim.is_some() {
                                    let stats = platform::container_stats();
                                    for c in cs.iter_mut() {
                                        let key: String = c.id.chars().take(12).collect();
                                        if let Some((pct, used, total)) = stats.get(&key) {
                                            c.cpu_pct = Some(*pct);
                                            c.mem_used_mb = Some(*used);
                                            c.mem_total_mb = Some(*total);
                                        }
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
                            // level thresholds over the same snapshot — the
                            // stats sweep rides this enumeration only when
                            // armed, so unarmed runs pay nothing extra
                            for (name, detail, rec) in container_thresholds.update(
                                &cs,
                                cli.alert_container_cpu,
                                cli.alert_container_mem_pct,
                                cli.alert_repeat,
                                interval,
                            ) {
                                picks.push((0, name, detail, rec));
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

fn one_shot_listing_name(cli: &cli::Cli) -> Option<&'static str> {
    // --timers is exempt when watching: its text view supports --watch
    // refresh; the machine-readable forms stay one-shot
    let timers_text_refresh = cli.timers && cli.watch.is_some();
    [
        (cli.zombies, "--zombies"),
        (cli.deleted, "--deleted"),
        (cli.dstate, "--dstate"),
        (cli.locks, "--locks"),
        (cli.doctor, "--doctor"),
        (cli.timers && !timers_text_refresh, "--timers"),
        (cli.services, "--services"),
        (cli.failed, "--services --failed"),
        (cli.unit.is_some(), "-u UNIT"),
        (cli.baseline.is_some(), "--baseline FILE"),
        (cli.baseline_save.is_some(), "--baseline-save FILE"),
    ]
    .into_iter()
    .find(|(armed, _)| *armed)
    .map(|(_, name)| name)
}


#[cfg(test)]
mod tests {
    #[test]
    fn record_processes_parse_from_both_formats_for_the_heatmap() {
        // CSV: per-process rows feed it, _system rows don't
        let csv = "\
timestamp,pid,user,name,cpu_pct,rss_mb,io_rbps,io_wbps,gpu_sm,sys_load1,sys_mem_pct,sys_procs,sys_net_bps
1700000000,_system,,,.0,.0,,,,0.5,10,2,0.0
1700000000,3,root,worker,42.5,100,,,,,,,,
1700000000,4,root,other,0.0,50,,,,,,,,
";
        let s = parse_record_processes(csv);
        assert_eq!(s.len(), 2, "the _system row carries no process");
        assert_eq!((s[0].pid, s[0].name.as_str()), (3, "worker"));
        assert_eq!(s[0].cpu, Some(42.5));
        // JSONL: the processes array rides each envelope
        let jsonl = "\
{\"schema_version\":1,\"generated_at\":1700000000,\"process_count\":1,\"system\":{\"load1\":0.1},\"processes\":[{\"pid\":9,\"name\":\"beacon\",\"cpu_pct\":12.5}]}
{\"schema_version\":1,\"generated_at\":1700000005,\"process_count\":1,\"system\":null,\"processes\":[]}
";
        let s = parse_record_processes(jsonl);
        assert_eq!(s.len(), 1, "empty process arrays contribute nothing");
        assert_eq!((s[0].pid, s[0].name.as_str(), s[0].cpu), (9, "beacon", Some(12.5)));
    }

    #[test]
    fn heat_color_climbs_from_dark_to_red() {
        assert_eq!(heat_color(0.0), "#1a2733");
        assert_eq!(heat_color(100.0), "#ff6b6b");
        // and the walk is monotonic in redness: a hotter cell is never
        // less red than a cooler one (sampled across the stops)
        let redness = |v: f64| u8::from_str_radix(&heat_color(v)[1..3], 16).unwrap();
        let vs = [5.0, 30.0, 70.0, 95.0];
        for w in vs.windows(2) {
            assert!(redness(w[0]) < redness(w[1]), "{} → {}", w[0], w[1]);
        }
    }

    #[test]
    fn aggregate_record_ranks_by_integrated_cpu_and_peak_rss() {
        let s =
            |at: i64, pid: i32, name: &str, cpu: Option<f64>, rss: Option<f64>| ProcSample {
                at,
                pid,
                name: name.into(),
                cpu,
                rss_mb: rss,
                user: None,
                io_bps: None,
            };
        // ticks 10s apart; hog bursts 90% for three ticks then vanishes;
        // idler sits at 2% for all four
        let samples = vec![
            s(0, 1, "hog", Some(90.0), Some(500.0)),
            s(10, 1, "hog", Some(90.0), Some(510.0)),
            s(20, 1, "hog", Some(90.0), Some(520.0)),
            s(0, 2, "idler", Some(2.0), Some(80.0)),
            s(10, 2, "idler", Some(2.0), Some(80.0)),
            s(20, 2, "idler", Some(2.0), Some(80.0)),
            s(30, 2, "idler", Some(2.0), Some(80.0)),
            // the same pid serving another program mid-recording: its own
            // row, not a corruption of hog's numbers
            s(30, 1, "next-tenant", Some(50.0), Some(30.0)),
            // a reading-less row still counts the identity
            s(30, 3, "quiet", None, Some(64.0)),
        ];
        let rows = aggregate_record(&samples, crate::cli::TopMetric::Cpu, 10);
        assert_eq!(rows.len(), 4);
        // hog: 3×90% over 10s gaps = 27 CPU-seconds — beats idler's 8
        assert_eq!(rows[0].name, "hog");
        assert_eq!(rows[0].samples, 3);
        assert_eq!(rows[0].cpu_avg, Some(90.0));
        assert_eq!(rows[0].cpu_peak, Some(90.0));
        assert!((rows[0].cpu_seconds.unwrap() - 27.0).abs() < 1e-9, "{rows:?}");
        assert_eq!((rows[0].rss_peak_mb.unwrap() * 10.0).round(), 5200.0);
        // idler sat at 2% for four ticks: (2×4)/100 × 10s = 0.8 CPU-seconds
        assert_eq!(rows[1].name, "next-tenant");
        assert!((rows[1].cpu_seconds.unwrap() - 5.0).abs() < 1e-9, "{rows:?}");
        assert_eq!(rows[2].name, "idler");
        assert!((rows[2].cpu_seconds.unwrap() - 0.8).abs() < 1e-9, "{rows:?}");
        assert_eq!(rows[3].name, "quiet");
        assert_eq!(rows[3].cpu_seconds, None);
        assert_eq!(rows[3].rss_peak_mb, Some(64.0));

        // mem ranking goes by peak RSS, not CPU
        let rows = aggregate_record(&samples, crate::cli::TopMetric::Mem, 2);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "hog");
        assert_eq!(rows[1].name, "idler");

        // --count truncates after ranking
        let rows = aggregate_record(&samples, crate::cli::TopMetric::Cpu, 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "hog");

        // the board renders and the machine formats carry raw numbers
        let rows = aggregate_record(&samples, crate::cli::TopMetric::Cpu, 10);
        let p = render::Painter::new(false);
        let text = render::render_record_agg(&rows, &p);
        assert!(text.contains("SAMPLES") && text.contains("CPU-TIME"), "{text}");
        assert!(text.contains("hog") && text.contains("27s"), "{text}");
        let csv = render::render_record_agg_csv(&rows);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(
            lines[0],
            "name,pid,samples,cpu_avg_pct,cpu_peak_pct,cpu_seconds,rss_avg_mb,rss_peak_mb,io_peak_bps,io_total_bytes"
        );
        assert!(lines[1].starts_with("hog,1,3,90.00,90.00,27.00,510.00,520.00"), "{csv}");
        let md = render::render_record_agg_markdown(&rows);
        assert!(md.starts_with("| NAME | PID | SAMPLES |"), "{md}");
        // empty recording → the note, not a panic
        assert!(render::render_record_agg(&[], &p).contains("no process rows"));
    }

    #[test]
    fn aggregate_record_by_user_sums_ticks_and_footprints() {
        let s =
            |at: i64, pid: i32, user: Option<&str>, cpu: Option<f64>, rss: Option<f64>| ProcSample {
                at,
                pid,
                name: format!("p{pid}"),
                cpu,
                rss_mb: rss,
                user: user.map(|u| u.into()),
                io_bps: None,
            };
        let samples = vec![
            // alice runs two processes: 90% + 10% at t0, both 200M
            s(0, 1, Some("alice"), Some(90.0), Some(200.0)),
            s(0, 2, Some("alice"), Some(10.0), Some(200.0)),
            // bob idles at 2%, 80M
            s(0, 3, Some("bob"), Some(2.0), Some(80.0)),
            // t10: alice's first process dies, second doubles
            s(10, 2, Some("alice"), Some(50.0), Some(400.0)),
            s(10, 3, Some("bob"), Some(2.0), Some(80.0)),
            // an unattributed row lands in the "-" group, not a panic
            s(10, 4, None, Some(20.0), Some(64.0)),
        ];
        let rows = aggregate_record_by_user(&samples, crate::cli::TopMetric::Cpu, 10);
        assert_eq!(rows.len(), 3);
        // alice: integrals (90+10)/100*10 + 50/100*10 = 15 CPU-seconds;
        // per-tick cpu sums read 100 then 50 → avg 75, peak 100
        assert_eq!(rows[0].user, "alice");
        assert_eq!(rows[0].samples, 2);
        assert!((rows[0].cpu_seconds.unwrap() - 15.0).abs() < 1e-9, "{rows:?}");
        assert!((rows[0].cpu_avg.unwrap() - 75.0).abs() < 1e-9, "{rows:?}");
        assert_eq!(rows[0].cpu_peak, Some(100.0));
        // simultaneous footprint: 400 at t0, 400 at t10 — avg 400, not
        // the 1200 a sum-of-peaks would claim
        assert_eq!((rows[0].rss_avg_mb.unwrap() * 10.0).round(), 4000.0);
        assert_eq!(rows[0].rss_peak_mb, Some(400.0));
        // the unattributed "-" group ranks by its own numbers: its 2.0s
        // beats bob's 0.4s, so it takes the second slot
        assert_eq!(rows[1].user, "-");
        assert_eq!(rows[2].user, "bob");
        assert!((rows[2].cpu_seconds.unwrap() - 0.4).abs() < 1e-9, "{rows:?}");

        // mem ranking goes by peak simultaneous RSS
        let rows = aggregate_record_by_user(&samples, crate::cli::TopMetric::Mem, 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].user, "alice");

        // the board renders; the flat formats carry raw numbers
        let rows = aggregate_record_by_user(&samples, crate::cli::TopMetric::Cpu, 10);
        let p = render::Painter::new(false);
        let text = render::render_user_agg(&rows, &p);
        assert!(text.contains("TICKS") && text.contains("alice"), "{text}");
        let csv = render::render_user_agg_csv(&rows);
        assert!(csv.lines().nth(1).unwrap().starts_with("alice,2,75.00,100.00,15.00,400.00,400.00"), "{csv}");
        let md = render::render_user_agg_markdown(&rows);
        assert!(md.starts_with("| USER | TICKS |"), "{md}");
        assert!(render::render_user_agg(&[], &p).contains("no process rows"));

        // io rides the user rollup too: alice's two processes both write,
        // the tick sum doubles; bob carries no readings → absent cells
        let io_samples = vec![
            ProcSample { at: 0, pid: 1, name: "a".into(), cpu: None, rss_mb: None, user: Some("alice".into()), io_bps: Some(1_000_000.0) },
            ProcSample { at: 0, pid: 2, name: "b".into(), cpu: None, rss_mb: None, user: Some("alice".into()), io_bps: Some(3_000_000.0) },
            ProcSample { at: 0, pid: 3, name: "c".into(), cpu: None, rss_mb: None, user: Some("bob".into()), io_bps: None },
            ProcSample { at: 10, pid: 1, name: "a".into(), cpu: None, rss_mb: None, user: Some("alice".into()), io_bps: Some(2_000_000.0) },
        ];
        let rows = aggregate_record_by_user(&io_samples, crate::cli::TopMetric::Io, 5);
        assert_eq!(rows[0].user, "alice");
        assert_eq!(rows[0].io_peak_bps, Some(4_000_000.0), "the t0 tick sums both processes");
        assert!((rows[0].io_total_bytes.unwrap() - 60_000_000.0).abs() < 1.0, "{rows:?}");
        assert_eq!(rows[1].user, "bob");
        assert_eq!(rows[1].io_total_bytes, None, "no readings reads as absent, not zero");
    }

    #[test]
    fn record_parser_normalizes_io_rates_from_both_formats() {
        // CSV: rates ride directly; both historical column spellings match
        for header in [
            "timestamp,pid,user,name,cpu_pct,rss_mb,io_read_bps,io_write_bps,gpu_sm,sys_load1",
            "timestamp,pid,user,name,cpu_pct,rss_mb,io_rbps,io_wbps,gpu_sm,sys_load1",
        ] {
            let csv = format!(
                "{header}\n1700000000,3,root,writer,42.5,100.5,5000000,2000000,0,0.5\n"
            );
            let s = parse_record_processes(&csv);
            assert_eq!(s.len(), 1, "{header}");
            assert_eq!(s[0].io_bps, Some(7_000_000.0), "{header}");
        }
        // rows without io readings stay None
        let csv = "timestamp,pid,user,name,cpu_pct,rss_mb,io_read_bps,io_write_bps\n1700000000,3,root,idler,1.0,10.0,,\n";
        let s = parse_record_processes(csv);
        assert_eq!(s[0].io_bps, None);

        // JSONL: cumulative counters diff into rates at exact row spacing
        let jsonl = "{\"schema_version\":1,\"generated_at\":100,\"processes\":[{\"pid\":9,\"name\":\"w\",\"io_read_bytes\":1000,\"io_write_bytes\":0}]}
{\"schema_version\":1,\"generated_at\":110,\"processes\":[{\"pid\":9,\"name\":\"w\",\"io_read_bytes\":6000,\"io_write_bytes\":4000}]}
{\"schema_version\":1,\"generated_at\":120,\"processes\":[{\"pid\":9,\"name\":\"w\",\"io_read_bytes\":8000,\"io_write_bytes\":6000}]}
";
        let s = parse_record_processes(jsonl);
        assert_eq!(s.len(), 3);
        // first sighting has no previous → no rate; then 9kB total over
        // 10s, then 4kB total over 10s
        assert_eq!(s[0].io_bps, None);
        assert_eq!(s[1].io_bps, Some(900.0));
        assert_eq!(s[2].io_bps, Some(400.0));
        // a new identity (same pid number, other program) starts fresh
        let jsonl = "{\"schema_version\":1,\"generated_at\":100,\"processes\":[{\"pid\":9,\"name\":\"w\",\"io_read_bytes\":1000,\"io_write_bytes\":0}]}
{\"schema_version\":1,\"generated_at\":110,\"processes\":[{\"pid\":9,\"name\":\"next\",\"io_read_bytes\":1000,\"io_write_bytes\":0}]}
";
        let s = parse_record_processes(jsonl);
        assert_eq!(s[1].io_bps, None, "the recycled pid starts its own series");
    }

    #[test]
    fn aggregate_record_ranks_io_by_bytes_moved() {
        let s = |at: i64, pid: i32, name: &str, io: Option<f64>| ProcSample {
            at,
            pid,
            name: name.into(),
            cpu: None,
            rss_mb: None,
            user: None,
            io_bps: io,
        };
        // hammer: 10 MB/s for 3 ticks; drizzler: 1 MB/s for 6 ticks
        let samples = vec![
            s(0, 1, "hammer", Some(10_000_000.0)),
            s(10, 1, "hammer", Some(10_000_000.0)),
            s(20, 1, "hammer", Some(10_000_000.0)),
            s(0, 2, "drizzler", Some(1_000_000.0)),
            s(10, 2, "drizzler", Some(1_000_000.0)),
            s(20, 2, "drizzler", Some(1_000_000.0)),
            s(30, 2, "drizzler", Some(1_000_000.0)),
            s(40, 2, "drizzler", Some(1_000_000.0)),
            s(50, 2, "drizzler", Some(1_000_000.0)),
            s(60, 2, "drizzler", Some(1_000_000.0)),
        ];
        let rows = aggregate_record(&samples, crate::cli::TopMetric::Io, 10);
        // hammer moved 300 MB total despite fewer ticks — the integral
        // ranks it first, its 10M/s peak also beats the drizzle
        assert_eq!(rows[0].name, "hammer");
        assert!((rows[0].io_total_bytes.unwrap() - 300_000_000.0).abs() < 1.0, "{rows:?}");
        assert_eq!(rows[0].io_peak_bps, Some(10_000_000.0));
        assert_eq!(rows[1].name, "drizzler");
        // 7 ticks × 1M/s × 10s spacing = 70 MB
        assert!((rows[1].io_total_bytes.unwrap() - 70_000_000.0).abs() < 1.0, "{rows:?}");

        // no io readings → the cells read "-", not zero
        let quiet = vec![s(0, 5, "quiet", None)];
        let rows = aggregate_record(&quiet, crate::cli::TopMetric::Io, 5);
        assert_eq!(rows[0].io_total_bytes, None);
        assert_eq!(rows[0].io_peak_bps, None);
        let p = render::Painter::new(false);
        let text = render::render_record_agg(&rows, &p);
        assert!(text.contains("IO PEAK") && text.contains("IO TOTAL"), "{text}");
        let csv = render::render_record_agg_csv(&rows);
        let mut lines = csv.lines();
        assert!(lines.next().unwrap().ends_with("io_peak_bps,io_total_bytes"), "{csv}");
        assert!(lines.next().unwrap().ends_with(",,,"), "empty io cells: {csv}");
    }

    #[test]
    fn record_process_parser_carries_rss_in_both_formats() {
        // CSV: the rss_mb column rides along (older files with the same
        // header parse identically — the column is order-tolerant)
        let csv = "timestamp,pid,user,name,cpu_pct,rss_mb,io_rbps,io_wbps,gpu_sm,sys_load1,sys_mem_pct,sys_procs,sys_net_bps
1700000000,3,root,worker,42.5,100.5,,,,0.5,10,2,0.0
1700000000,_system,,,.0,.0,,,,0.5,10,2,0.0
1700000005,3,worker,,46.0,101.0,,,,0.5,10,2,0.0
";
        let s = parse_record_processes(csv);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].rss_mb, Some(100.5));
        assert_eq!(s[0].user.as_deref(), Some("root"));
        assert_eq!(s[1].rss_mb, Some(101.0));

        // JSONL: the envelope's rss is KB in, MB out; `cpu` (the Process
        // field) and `cpu_pct` (the CSV twin) both parse
        let jsonl = "{\"schema_version\":1,\"generated_at\":1700000000,\"processes\":[{\"pid\":9,\"name\":\"beacon\",\"user\":\"svc\",\"cpu\":12.5,\"mem_kb\":20480}]}
{\"schema_version\":1,\"generated_at\":1700000005,\"processes\":[{\"pid\":9,\"name\":\"beacon\",\"cpu_pct\":13.0,\"mem_kb\":21504}]}
";
        let s = parse_record_processes(jsonl);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].cpu, Some(12.5));
        assert_eq!(s[0].rss_mb, Some(20.0));
        assert_eq!(s[0].user.as_deref(), Some("svc"));
        assert_eq!(s[1].cpu, Some(13.0));
        assert_eq!(s[1].rss_mb, Some(21.0));
    }

    #[test]
    fn proc_heatmap_names_the_burst_process() {
        let sample = |at: i64, pid: i32, name: &str, cpu: f64| ProcSample {
            at,
            pid,
            name: name.into(),
            cpu: Some(cpu),
            rss_mb: None,
            user: None,
            io_bps: None,
        };
        let samples = vec![
            sample(100, 1, "idle", 1.0),
            sample(100, 2, "hog", 90.0),
            sample(200, 2, "hog", 95.0),
            sample(200, 1, "idle", 2.0),
        ];
        let svg = proc_heatmap_svg(&samples);
        assert!(svg.contains("hog (185%)"), "the top row names the hog: {svg}");
        assert!(svg.contains("peak 95.0%"), "{svg}");
        assert!(svg.contains("idle (3%)"), "the low row still exists: {svg}");
        assert!(
            svg.contains("fill=\"#ff7") || svg.contains("fill=\"#fe"),
            "hot cells sit in the red family: {svg}"
        );
    }

    #[test]
    fn lifecycle_segments_rebuild_lives_from_the_log() {
        let ev = |at: i64, kind: &str, pid: i32, name: &str| crate::history::TuiEvent {
            at_unix: at,
            kind: kind.into(),
            pid,
            name: name.into(),
            detail: String::new(),
        };
        let events = vec![
            // a daemon that restarts once and lives on, a worker that was
            // already running when the log began and dies mid-log, and a
            // short-lived process that exits after its birth
            ev(100, "started", 10, "nginx"),
            ev(100, "started", 20, "worker"),
            ev(150, "exited", 20, "worker"),
            ev(200, "restarted", 30, "nginx"),
            ev(300, "started", 40, "init"),
        ];
        let segs = lifecycle_segments(&events, 100, 300);
        let find = |pid: i32| segs.iter().find(|s| s.pid == pid).unwrap();
        // the restart closes the old bar (end=restarted) and opens the new
        let old = find(10);
        assert_eq!((old.from, old.to), (100, 200));
        assert_eq!(old.end, "restarted");
        let new = find(30);
        assert_eq!((new.from, new.to), (200, 300));
        assert_eq!(new.end, "started"); // alive at log end
        // a death with no observed birth draws from the log's start
        let orphan = find(20);
        assert_eq!((orphan.from, orphan.to), (100, 150));
        assert_eq!(orphan.end, "exited");
    }

    #[test]
    fn plot_events_html_renders_rows_markers_and_the_system_lane() {
        let ev = |at: i64, kind: &str, pid: i32, name: &str| crate::history::TuiEvent {
            at_unix: at,
            kind: kind.into(),
            pid,
            name: name.into(),
            detail: String::new(),
        };
        let events = vec![
            ev(100, "started", 10, "nginx"),
            ev(120, "alert", 10, "nginx"),
            ev(140, "recovered", 10, "nginx"),
            ev(160, "restarted", 11, "nginx"),
            ev(180, "container-death", 0, "container web"),
            ev(200, "alert", 0, "system"), // no matching row → system lane
        ];
        let html = plot_events_html(&events, &["/tmp/e.jsonl".to_string()]);
        assert!(html.contains("nginx"), "identity row label");
        assert!(html.contains("system / containers"), "system lane");
        assert!(html.contains("alive at log end"), "legend");
        assert!(html.contains("1 restarted"), "counts line");
        assert!(html.contains("fcc419"), "alert marker color");
        assert!(html.contains("#ff922b"), "restart bar color");
        assert!(!html.contains("<script"), "zero JS");
    }
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
        w.append(&procs, &hist, None, None, &RecordWaterlines { zombies: 0, dstates: 0, failed_units: 0, mem_eta_hours: None });
        w.append(&procs, &hist, None, None, &RecordWaterlines { zombies: 0, dstates: 0, failed_units: 0, mem_eta_hours: None });
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
        w.append(&procs, &hist, Some(&stats), None, &RecordWaterlines { zombies: 0, dstates: 0, failed_units: 0, mem_eta_hours: None });
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "timestamp,pid,user,name,cpu_pct,rss_mb,io_read_bps,io_write_bps,gpu_sm,\
             sys_load1,sys_mem_pct,sys_procs,sys_net_bps,sys_zombies,sys_dstates,sys_failed_units,sys_mem_eta_hours"
        );
        assert_eq!(lines.len(), 3, "header + process row + _system row");
        let row = lines[1];
        // first sample: no cpu/io deltas yet → empty cells; rss 2048 KiB → 2
        // (process rows keep the original 13 columns — the waterlines live
        // on the _system row only)
        let fields: Vec<&str> = row.split(',').collect();
        assert_eq!(fields.len(), 13, "{row}");
        // the machine row carries the new waterline columns too
        let sys_row = lines[2];
        let sys_fields: Vec<&str> = sys_row.split(',').collect();
        assert_eq!(
            (sys_fields[13], sys_fields[14], sys_fields[15]),
            ("0", "0", "0"),
            "the waterline columns ride the _system row: {sys_row}"
        );
        assert_eq!(
            sys_fields[16], "",
            "no eta until the trend gate trusts: {sys_row}"
        );
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
        assert_eq!(sys.len(), 17, "{}", lines[2]);
        assert_eq!(sys[1], "_system");
        assert_eq!(sys[4], "", "machine cpu is a delta — empty on tick one");
        assert_eq!(sys[5], "4096", "used MB rides the rss column");
        assert_eq!((sys[9], sys[10], sys[11], sys[12]), ("1.25", "25", "1", ""), "{}", lines[2]);
        assert_eq!(
            (sys[13], sys[14], sys[15]),
            ("0", "0", "0"),
            "the waterline columns ride along: {}",
            lines[2]
        );
        assert_eq!(sys[16], "", "no eta until the trend gate trusts: {}", lines[2]);
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
        w.append(&procs, &hist, Some(&stats), Some(8_388_608.0), &RecordWaterlines { zombies: 0, dstates: 0, failed_units: 0, mem_eta_hours: None }); // 8 MB/s
        w.append(&procs, &hist, Some(&stats), None, &RecordWaterlines { zombies: 0, dstates: 0, failed_units: 0, mem_eta_hours: None });
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
            SysPoint { at: 1_700_000_100, cpu: Some(12.5), mem_pct: Some(40.0), load1: Some(0.5), procs: 210, net_bps: Some(1_048_576.0),
            zombies: 0,
            dstates: 0,
            failed_units: 0,
            mem_eta_hours: None },
            SysPoint { at: 1_700_000_160, cpu: Some(25.0), mem_pct: Some(50.0), load1: Some(1.0), procs: 220, net_bps: None,
            zombies: 0,
            dstates: 0,
            failed_units: 0,
            mem_eta_hours: None },
        ];
        let html = plot_html(&pts, &[]);
        assert!(html.starts_with("<!doctype html>"));
        assert!(
            html.contains("2 samples"),
            "{}",
            html.get(..120).unwrap_or("")
        );
        assert_eq!(
            html.matches("<svg").count(),
            8,
            "cpu/mem/load/net/processes/zombies/dstates/failed — the eta series is
             all-None in this fixture (no gate-trusted prediction) and a chart
             of nothing is omitted"
        );
        assert_eq!(html.matches("<polyline").count(), 8);
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
            zombies: 0,
            dstates: 0,
            failed_units: 0,
            mem_eta_hours: None,
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
        w.append(&procs, &hist, Some(&stats), Some(2_000_000.0), &RecordWaterlines { zombies: 0, dstates: 0, failed_units: 0, mem_eta_hours: None });
        w.append(&procs, &hist, None, None, &RecordWaterlines { zombies: 0, dstates: 0, failed_units: 0, mem_eta_hours: None });
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

    /// `--check`'s test double: one hog (9.7 GB RSS) and an overloaded
    /// machine (load1 9), nothing else. Level checks only, so the run
    /// never sleeps.
    struct CheckPlatform;

    impl Platform for CheckPlatform {
        fn name(&self) -> &'static str {
            "test"
        }
        fn capabilities(&self) -> platform::Capabilities {
            platform::Capabilities { file_lookup: false, env: false }
        }
        fn list_processes(&self) -> platform::PlatResult<Vec<Process>> {
            Ok(vec![proc(9, "hog", None, Some(9999 * 1024))])
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
        fn system_stats(&self) -> Option<platform::SystemStats> {
            Some(platform::SystemStats {
                load1: Some(9.0),
                ..Default::default()
            })
        }
    }

    #[test]
    fn check_reports_violations_and_cleans() {
        // level thresholds only — no rate checks, no sleep, no history
        let cli = cli::Cli::parse_from(["witr", "--check", "--alert-mem", "1024", "--alert-load", "4"]);
        let code = run_check_once(&CheckPlatform, &cli);
        assert_eq!(code, 1, "hog RSS + load1 over the line");
        // under the line everywhere: clean, exit 0
        let cli = cli::Cli::parse_from(["witr", "--check", "--alert-mem", "999999", "--alert-load", "40"]);
        let code = run_check_once(&CheckPlatform, &cli);
        assert_eq!(code, 0, "everything under its line");
    }

    #[test]
    fn check_lines_cover_disk_busy_temp_and_zombies() {
        let cli = cli::Cli::parse_from([
            "witr",
            "--check",
            "--alert-disk-busy",
            "80",
            "--alert-temp",
            "80",
            "--alert-zombies",
            "5",
            "--alert-dstate",
            "3",
            "--alert-failed-units",
            "1",
            "--alert-inodes",
            "85",
            "--alert-gpu-mem-pct",
            "75",
            "--alert-deleted-gb",
            "2",
            "--alert-service-mem",
            "512",
        ]);
        let stats = crate::platform::SystemStats {
            temp: Some(("acpitz".into(), 85.0)),
            gpus: vec![crate::gpu::GpuSample {
                id: "0".into(),
                name: "NVIDIA A100".into(),
                util_pct: Some(85.0),
                mem_used_mb: 78_000,
                mem_total_mb: 81_920,
                temp_c: Some(67.0),
            }],
            disks: vec![
                crate::platform::DiskIoSample {
                    device: "vda".into(),
                    busy_pct: Some(87.4),
                    in_flight: 3,
                    ..Default::default()
                },
                crate::platform::DiskIoSample {
                    device: "vdb".into(),
                    busy_pct: Some(12.0),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let mounts = vec![crate::platform::MountUsage {
            target: "/data".into(),
            total_mb: 10_000,
            used_mb: 6_000,
            inodes_used: Some(900_000),
            inodes_total: Some(1_000_000),
        }];
        let failed = vec![
            "ipmi.service".to_string(),
            "lightdm.service".to_string(),
            "plymouth-quit.service".to_string(),
        ];
        let deleted = vec![crate::platform::DeletedFile {
            pid: 900,
            name: "rsyslogd".into(),
            path: "/var/log/journal.log".into(),
            size_mb: 6 * 1024,
        }];
        let lines = machine_check_lines(
            &cli,
            &stats,
            &mounts,
            &deleted,
            0,
            7,
            4,
            &failed,
            // service-memory sentinel inputs (the sweep when armed)
            &[("leaky.service".to_string(), 768 * 1024 * 1024)],
            None,
            None,
            None,
            None,
        );
        assert_eq!(lines.len(), 9, "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.contains(
                    "deleted-but-held files: 6.0 GB above 2 GB — /var/log/journal.log (pid 900)"
                )),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| {
                l.contains("GPU memory gpu 0 (NVIDIA A100) 95% above 75%")
            }),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("inodes /data 90% above 85%")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains(
                "3 systemd units failed above 1 — ipmi.service, lightdm.service, plymouth-quit.service"
            )),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("disk IO vda 87% above 80% busy")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("temperature 85°C at acpitz above 80°C")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("7 defunct (zombie) processes above 5")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| {
                l.contains("4 processes stuck in uninterruptible IO wait above 3")
            }),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("1 service(s) above 512 MB — leaky.service 768.0M")),
            "{lines:?}"
        );
        // under every line → nothing to report
        let quiet = crate::platform::SystemStats::default();
        assert!(
            machine_check_lines(
                &cli,
                &quiet,
                &[],
                &[],
                0,
                0,
                0,
                &[],
                &[],
                None,
                None,
                None,
                None
            )
            .is_empty()
        );

    }

    #[test]
    fn container_check_lines_judge_levels_without_history() {
        let c = |name: &str, cpu: Option<f64>, used: Option<u64>, total: Option<u64>,
                 state: &str, pod: Option<&str>| crate::model::Container {
            runtime: "docker".into(),
            id: name.to_string(),
            name: name.to_string(),
            image: String::new(),
            command: String::new(),
            state: state.into(),
            status: String::new(),
            ports: String::new(),
            pod: pod.map(|p| p.into()),
            restarts: None,
            cpu_pct: cpu,
            mem_used_mb: used,
            mem_total_mb: total,
            compose: None,
            io_read_bytes: None,
            io_write_bytes: None,
            throttled_usec: None,
            oom_kills: None,
            io_by_device: None,
        };
        let cli = cli::Cli::parse_from([
            "witr",
            "--check",
            "--alert-container-cpu",
            "200",
            "--alert-container-mem-pct",
            "80",
        ]);
        let cs = vec![
            c("hot", Some(250.0), Some(900), Some(1000), "running", Some("prod/web")),
            c("quiet", Some(4.0), Some(100), Some(1000), "running", None),
            // no limit: the memory judgment sits out, the CPU one doesn't
            c("nolimit", Some(250.0), Some(900), None, "running", None),
            // dead: never judged
            c("corpse", Some(250.0), Some(900), Some(1000), "exited", None),
        ];
        let lines = container_check_lines(&cli, &cs);
        assert_eq!(lines.len(), 3, "{lines:?}");
        let hot_cpu = lines
            .iter()
            .find(|(n, d)| *n == "container hot" && d.contains("CPU"))
            .unwrap();
        assert!(
            hot_cpu.1.contains("CPU 250% above 200% · pod prod/web"),
            "{}",
            hot_cpu.1
        );
        let hot_mem = lines
            .iter()
            .find(|(n, d)| *n == "container hot" && d.contains("memory"))
            .unwrap();
        assert!(hot_mem.1.contains("memory 90% of limit above 80%"), "{}", hot_mem.1);
        let nl = lines.iter().find(|(n, _)| *n == "container nolimit").unwrap();
        assert!(nl.1.contains("CPU"), "{:?}", nl);
        // under every line → nothing
        let quiet: Vec<crate::model::Container> =
            vec![c("calm", Some(1.0), Some(10), Some(1000), "running", None)];
        assert!(container_check_lines(&cli, &quiet).is_empty());
        // unarmed → no-op even over blazing containers
        let bare = cli::Cli::parse_from(["witr", "--check", "--alert-load", "4"]);
        assert!(container_check_lines(&bare, &cs).is_empty());
    }

    #[test]
    fn fleet_ranked_orders_value_desc_with_host_ties_and_truncates() {
        let p = |pid: i32, host: Option<&str>, cpu: Option<f64>| Process {
            pid,
            name: format!("p{pid}"),
            host: host.map(|h| h.into()),
            cpu,
            ..Default::default()
        };
        // the io twin: cumulative r+w ranks, table-carried
        let mut io_host = p(6, Some("hostA"), None);
        io_host.io_read_bytes = Some(1000);
        io_host.io_write_bytes = Some(3000);
        let mut io_big = p(7, Some("hostB"), None);
        io_big.io_read_bytes = Some(90_000);
        io_big.io_write_bytes = Some(10_000);
        let procs = vec![
            p(1, Some("hostB"), Some(30.0)),
            p(2, Some("hostA"), Some(30.0)),
            p(3, Some("hostA"), Some(90.0)),
            p(4, None, Some(5.0)),
            p(5, Some("hostA"), None), // unmeasurable: drops out
            io_host,
            io_big,
        ];
        let ranked = fleet_ranked(&procs, cli::TopMetric::Cpu, 3);
        let keys: Vec<String> = ranked
            .iter()
            .map(|r| format!("{}:{}/{}", r.cpu.unwrap_or(0.0), r.host.as_deref().unwrap_or("-"), r.pid))
            .collect();
        // value desc first; the 30/30 tie reads hostA pid2 before hostB pid1;
        // count truncates to 3; the cpu-less row never ranks
        assert_eq!(
            keys,
            vec!["90:hostA/3", "30:hostA/2", "30:hostB/1"],
            "{keys:?}"
        );
        // the io twin ranks the same way (cumulative r+w)
        let io_ranked = fleet_ranked(&procs, cli::TopMetric::Io, 2);
        let io_keys: Vec<String> = io_ranked
            .iter()
            .map(|r| {
                format!(
                    "{}/{}",
                    r.host.as_deref().unwrap_or("-"),
                    r.pid
                )
            })
            .collect();
        assert_eq!(io_keys, vec!["hostB/7", "hostA/6"], "{io_keys:?}");
    }

    #[test]
    fn fleet_sys_frame_counts_waterlines_and_skips_fleet_blind_sections() {
        let p = |pid: i32, state: Option<&str>| Process {
            pid,
            name: format!("p{pid}"),
            state: state.map(|s| s.to_string()),
            ..Default::default()
        };
        let sample = FleetSample {
            failed_units: vec!["ipmi.service".into()],
            service_mems: vec![("leaky.service".into(), 768 * 1024 * 1024)],
            deleted_reclaimable_mb: 0,
            deleted_files: Vec::new(),
            stats: crate::platform::SystemStats {
                load1: Some(3.0),
                mem_avail_mb: Some(2_000),
                ..Default::default()
            },
            nics: vec![crate::platform::NicCounters {
                name: "eth0".into(),
                rx_bytes: 1 << 20,
                tx_bytes: 0,
                rx_drops: 0,
                tx_drops: 0,
            }],
            net: Some((100, 200, 7)),
            mounts: vec![crate::platform::MountUsage {
                target: "/data".into(),
                total_mb: 10_000,
                used_mb: 6_000,
                inodes_used: Some(900_000),
                inodes_total: Some(1_000_000),
            }],
        };
        let procs = vec![p(1, Some("Z")), p(2, Some("D")), p(3, Some("R"))];
        let mut prev = None;
        let frame = fleet_sys_frame(&sample, &procs, &mut prev);
        assert_eq!(frame.procs, 3);
        assert_eq!(frame.zombies, 1);
        assert_eq!(frame.dstates, 1);
        assert_eq!(frame.stats.load1, Some(3.0));
        assert_eq!(frame.mounts.len(), 1);
        // the first sweep only arms the NIC diff
        assert!(frame.nics.is_empty());
        // the far host's own failed-unit list rides the snapshot — the
        // red line renders per host
        assert_eq!(frame.failed_units, vec!["ipmi.service"]);
        // service cgroup memory rides too — the cockpit's services line
        assert_eq!(
            frame.service_mems,
            vec![("leaky.service".to_string(), 768 * 1024 * 1024)]
        );
        // 2 MB arriving on eth0 over ~60 ms → a real rx rate on the next
        // sweep
        std::thread::sleep(std::time::Duration::from_millis(60));
        let mut sample2 = sample.clone();
        sample2.nics[0].rx_bytes += 2 * 1024 * 1024;
        let frame = fleet_sys_frame(&sample2, &procs, &mut prev);
        assert_eq!(frame.nics.len(), 1);
        assert_eq!(frame.nics[0].0, "eth0");
        assert!(frame.nics[0].1 > 1.0, "rx MB/s: {:?}", frame.nics);
        // a peer whose serve predates the system snapshot still renders:
        // empty stats, dashes in the text view, no panic
        let frame = fleet_sys_frame(
            &FleetSample {
                stats: crate::platform::SystemStats::default(),
                nics: Vec::new(),
                failed_units: Vec::new(),
                service_mems: Vec::new(),
                deleted_reclaimable_mb: 0,
                deleted_files: Vec::new(),
                net: None,
                mounts: Vec::new(),
            },
            &[],
            &mut None,
        );
        assert_eq!(frame.procs, 0);
        assert!(frame.stats.load1.is_none());
    }

    #[test]
    fn state_count_reads_the_kernel_state_letter() {
        let p = |pid: i32, state: Option<&str>| Process {
            pid,
            name: format!("p{pid}"),
            state: state.map(|s| s.to_string()),
            ..Default::default()
        };
        let procs = vec![
            p(1, Some("Z")),
            p(2, Some("Z")),
            p(3, Some("D")),
            p(4, Some("U")),
            p(5, Some("R")),
            p(6, Some("S")),
            p(7, None),
        ];
        assert_eq!(state_count(&procs, &["Z"]), 2);
        // D on Linux and U on macOS are the same uninterruptible wait
        assert_eq!(state_count(&procs, &["D", "U"]), 2);
        assert_eq!(state_count(&procs, &["R"]), 1);
        assert_eq!(state_count(&procs, &["T"]), 0);
    }

    #[test]
    fn check_oom_lines_name_victims_when_the_log_is_readable() {
        // one mock covers all three cases: log content Some/None, and a
        // `queried` flag proving the kernel log is never read without a
        // firing
        struct LogPlatform {
            log: Option<Vec<String>>,
            queried: std::sync::atomic::AtomicBool,
        }
        impl Platform for LogPlatform {
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
            fn oom_victims(&self, _since_secs: u64) -> Option<Vec<String>> {
                self.queried
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                self.log.clone()
            }
        }
        let readable = || LogPlatform {
            log: Some(vec!["nginx (pid 123)".into(), "python (pid 456)".into()]),
            queried: std::sync::atomic::AtomicBool::new(false),
        };
        let mut lines = vec![
            "OOM killer 2 kill(s) within the sample gap".to_string(),
            "load average 9.00 above 4".to_string(),
        ];
        attribute_oom_lines(&mut lines, &readable());
        assert!(
            lines[0].contains(" — victims: nginx (pid 123), python (pid 456)"),
            "{}",
            lines[0]
        );
        // non-OOM lines untouched
        assert_eq!(lines[1], "load average 9.00 above 4");

        // an unreadable (or victim-less) kernel log leaves the line
        // count-only — the pre-existing behavior
        let mut lines = vec!["OOM killer 1 kill(s) within the sample gap".to_string()];
        attribute_oom_lines(
            &mut lines,
            &LogPlatform {
                log: None,
                queried: std::sync::atomic::AtomicBool::new(false),
            },
        );
        assert_eq!(lines[0], "OOM killer 1 kill(s) within the sample gap");

        // no OOM line → the kernel log is never queried
        let blind = LogPlatform {
            log: Some(vec!["nginx (pid 123)".into()]),
            queried: std::sync::atomic::AtomicBool::new(false),
        };
        let mut lines = vec!["load average 9.00 above 4".to_string()];
        attribute_oom_lines(&mut lines, &blind);
        assert_eq!(lines[0], "load average 9.00 above 4");
        assert!(
            !blind.queried.load(std::sync::atomic::Ordering::Relaxed),
            "no firing, no journalctl call"
        );
    }

    #[test]
    fn fleet_snapshot_round_trips_into_the_local_sentinels() {
        let stats = crate::platform::SystemStats {
            load1: Some(7.25),
            cpu_percent: Some(42.0),
            mem_used_mb: Some(8000),
            mem_total_mb: Some(16000),
            mem_avail_mb: Some(4000),
            swap_used_mb: Some(512),
            swap_total_mb: Some(4096),
            psi: Some(crate::platform::PsiStats {
                cpu_some: 1.0,
                cpu_full: 0.0,
                mem_some: 2.0,
                mem_full: 3.0,
                io_some: 4.0,
                io_full: 5.0,
            }),
            retrans_segs: Some(12345),
            oom_kills: Some(2),
            disks: vec![crate::platform::DiskIoSample {
                device: "vda".into(),
                busy_pct: Some(87.4),
                in_flight: 3,
                read_iops: Some(120.0),
                write_iops: Some(45.0),
            }],
            gpus: vec![crate::gpu::GpuSample {
                id: "0".into(),
                name: "NVIDIA A100".into(),
                util_pct: Some(85.0),
                mem_used_mb: 40_960,
                mem_total_mb: 81_920,
                temp_c: Some(67.0),
            }],
            ..Default::default()
        };
        let nics = vec![crate::platform::NicCounters {
            name: "eth0".into(),
            rx_bytes: 100,
            tx_bytes: 200,
            rx_drops: 3,
            tx_drops: 4,
        }];
        let mounts = vec![crate::platform::MountUsage {
            target: "/data".into(),
            total_mb: 10_000,
            used_mb: 6_000,
            ..Default::default()
        }];
        let doc = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "system": crate::serve::system_snapshot(&stats, &nics, &mounts, 42, 3, &["ipmi.service".to_string(), "lightdm.service".to_string()],
                &[("leaky.service".to_string(), 768 * 1024 * 1024)],
                &[crate::platform::DeletedFile {
                    pid: 900,
                    name: "rsyslogd".into(),
                    path: "/var/log/journal.log".into(),
                    size_mb: 6 * 1024,
                }]),
            "processes": [],
        });
        let sample = parse_system_snapshot(&doc).expect("the system key parses");
        // the service sweep round-trips (unit, bytes), sorted server-side
        assert_eq!(
            sample.service_mems,
            vec![("leaky.service".to_string(), 768 * 1024 * 1024)]
        );
        let s = &sample.stats;
        assert_eq!(s.load1, Some(7.25));
        assert_eq!(s.mem_used_mb, Some(8000));
        assert_eq!(s.psi.as_ref().map(|p| p.io_full), Some(5.0));
        assert_eq!(s.retrans_segs, Some(12345));
        assert_eq!(s.oom_kills, Some(2));
        // the far host's own failed-unit list rides through for the fleet
        // --alert-failed-units sentinel
        assert_eq!(sample.failed_units, vec!["ipmi.service", "lightdm.service"]);
        // the GPU readings and the deleted-hold story ride through for the
        // fleet --sys cockpit and their fleet sentinels
        assert_eq!(sample.deleted_reclaimable_mb, 6 * 1024);
        assert_eq!(sample.deleted_files.len(), 1);
        assert_eq!(sample.deleted_files[0].path, "/var/log/journal.log");
        assert_eq!(sample.stats.gpus.len(), 1);
        assert_eq!(sample.stats.gpus[0].name, "NVIDIA A100");
        assert_eq!(sample.stats.gpus[0].mem_total_mb, 81_920);
        assert_eq!(sample.net, Some((100, 200, 7))); // (rx, tx, drops folded)
        // the per-NIC counters ride through for the fleet sys rate diff
        assert_eq!(sample.nics.len(), 1);
        assert_eq!(sample.nics[0].name, "eth0");
        assert_eq!(sample.nics[0].rx_bytes, 100);
        assert_eq!(sample.nics[0].rx_drops, 3);
        assert_eq!(sample.mounts[0].target, "/data");
        // the disk family rides through: the disk-busy sentinel reads it
        // fleet-side exactly as the local one does
        assert_eq!(s.disks.len(), 1);
        assert_eq!(s.disks[0].device, "vda");
        assert_eq!(s.disks[0].busy_pct, Some(87.4));
        assert_eq!(s.disks[0].in_flight, 3);
        // a server without the snapshot (or a null one) disarms cleanly
        assert!(parse_system_snapshot(&serde_json::json!({"processes": []})).is_none());
        assert!(parse_system_snapshot(&serde_json::json!({"system": null})).is_none());
    }

    #[test]
    fn modified_zscores_resist_the_outlier_itself() {
        // five identical loads plus one runaway: classic z-score's σ gets
        // inflated by the runaway (z ≈ 1.8, under any threshold) — MAD
        // names it unambiguously
        let vals = vec![0.5, 0.5, 0.6, 0.5, 0.4, 9.0];
        let zs = modified_zscores(&vals);
        assert!(
            zs[5].abs() > 3.5,
            "the runaway is flagged: {zs:?}"
        );
        assert!(
            zs[..5].iter().all(|z| z.abs() < 3.5),
            "the calm five stay well under the threshold: {zs:?}"
        );
        // all-identical values: MAD 0 → the 5%-epsilon fallback, silence
        let same = vec![2.0, 2.0, 2.0, 2.0];
        assert!(modified_zscores(&same).iter().all(|z| *z == 0.0));
        // 10% off the identical median is the outlier
        let drifted = vec![2.0, 2.0, 2.0, 2.4];
        let zs = modified_zscores(&drifted);
        assert!(zs[3].abs() > 3.5, "the drifter flags under MAD 0: {zs:?}");
    }

    #[test]
    fn fleet_outliers_rank_and_skip_sparse_metrics() {
        let sample = |load: f64, cpu: f64| FleetSample {
            stats: crate::platform::SystemStats {
                load1: Some(load),
                cpu_percent: Some(cpu),
                ..Default::default()
            },
            nics: Vec::new(),
            failed_units: Vec::new(),
            service_mems: Vec::new(),
            deleted_reclaimable_mb: 0,
            deleted_files: Vec::new(),
            net: None,
            mounts: Vec::new(),
        };
        let ok = |b: &str, s: FleetSample| (b.to_string(), Ok((Vec::new(), Some(s))));
        // five hosts, one runaway load (cpu everywhere normal): the load
        // outlier names h5; cpu — identical across the fleet — stays silent
        let results = vec![
            ok("h1", sample(0.5, 20.0)),
            ok("h2", sample(0.6, 20.0)),
            ok("h3", sample(0.4, 20.0)),
            ok("h4", sample(0.5, 21.0)),
            ok("h5", sample(9.0, 20.0)),
            // a two-host pair: cpu reports from only 2 hosts (7 total rows
            // but a third metric with <3 reporters skips — this fixture
            // exercises the sparse skip via load from a 6th host? no —
            // via a metric only h6 reports)
            (
                "h6".to_string(),
                Ok((
                    Vec::new(),
                    Some(FleetSample {
                        stats: crate::platform::SystemStats {
                            load1: Some(50.0),
                            ..Default::default()
                        },
                        nics: Vec::new(),
                        failed_units: Vec::new(),
                        service_mems: Vec::new(),
                        deleted_reclaimable_mb: 0,
                        deleted_files: Vec::new(),
                        net: None,
                        mounts: Vec::new(),
                    }),
                )),
            ),
        ];
        let outliers = fleet_outliers(&results, 3.5);
        // h6's load 50 joins load's values — six reporters, still judged;
        // the runaway crowd now includes h6 (50 vs ~0.5 fleet norm)
        assert!(outliers.iter().any(|o| o.host == "h5" && o.metric == "load 1m"), "{outliers:?}");
        assert!(outliers.iter().any(|o| o.host == "h6"), "{outliers:?}");
        // the calm hosts never appear
        assert!(!outliers.iter().any(|o| o.host == "h1" || o.host == "h2"), "{outliers:?}");
        // worst z first
        if outliers.len() >= 2 {
            assert!(outliers[0].z.abs() >= outliers[1].z.abs());
        }
        // a fetch-failed host contributes nothing and breaks nothing
        let mut results = results;
        results.insert(0, ("dead".to_string(), Err("connect failed".to_string())));
        assert!(fleet_outliers(&results, 3.5).len() >= 2);
    }

    #[test]
    fn fleet_outliers_skip_metrics_with_fewer_than_three_reporters() {
        // two hosts: every metric has two reporters — nothing judges,
        // nothing fires (the degenerate pair case is honest silence)
        let sample = |load: f64| FleetSample {
            stats: crate::platform::SystemStats {
                load1: Some(load),
                ..Default::default()
            },
            nics: Vec::new(),
            failed_units: Vec::new(),
            service_mems: Vec::new(),
            deleted_reclaimable_mb: 0,
            deleted_files: Vec::new(),
            net: None,
            mounts: Vec::new(),
        };
        let results = vec![
            ("a".to_string(), Ok((Vec::new(), Some(sample(0.5))))),
            ("b".to_string(), Ok((Vec::new(), Some(sample(50.0))))),
        ];
        assert!(fleet_outliers(&results, 1.0).is_empty());
    }

    #[test]
    fn one_shot_listings_reject_watch_by_name() {
        let named = |args: &[&str]| {
            let cli = cli::Cli::parse_from(
                std::iter::once("witr").chain(args.iter().copied()).collect::<Vec<_>>(),
            );
            one_shot_listing_name(&cli)
        };
        assert_eq!(named(&["--zombies"]), Some("--zombies"));
        assert_eq!(named(&["--timers"]), Some("--timers"));
        assert_eq!(named(&["-u", "nginx.service"]), Some("-u UNIT"));
        assert_eq!(named(&["--baseline", "b.json"]), Some("--baseline FILE"));
        // a plain run (or a watch run of plain listing) names nothing
        assert_eq!(named(&[]), None);
        assert_eq!(named(&["--watch", "5"]), None);
        // the machine sentinels are not listings
        assert_eq!(named(&["--alert-load", "4"]), None);
    }

    #[test]
    fn fleet_baseline_flags_new_identities_per_host() {
        // one baseline with systemd+nginx as the norm; two hosts fetched —
        // h1 runs exactly the norm, h2 runs an extra identity: only h2's
        // extra fires, named with the host prefix
        let base_procs = vec![
            proc(1, "systemd", None, None),
            proc(42, "nginx", None, None),
        ];
        let baseline = (
            base_procs.clone(),
            Vec::<snapshot::Listener>::new(),
            vec!["nginx.service".to_string()],
        );
        let mk = |host: &str, pids: &[(i32, &str)]| {
            let procs: Vec<Process> = pids
                .iter()
                .map(|(pid, name)| proc(*pid, name, None, None))
                .collect();
            (
                host.to_string(),
                Ok::<(Vec<Process>, Option<FleetSample>), String>((
                    procs,
                    Some(FleetSample {
                        stats: crate::platform::SystemStats::default(),
                        nics: Vec::new(),
                        failed_units: Vec::new(),
                        service_mems: Vec::new(),
                        deleted_reclaimable_mb: 0,
                        deleted_files: Vec::new(),
                        net: None,
                        mounts: Vec::new(),
                    }),
                )),
            )
        };
        let results = vec![
            mk("h1", &[(1, "systemd"), (42, "nginx")]),
            mk("h2", &[(1, "systemd"), (42, "nginx"), (99, "xmrig")]),
        ];
        // judge per host like the loop does: identity sets against the norm
        let mut reported: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        let mut fires = Vec::new();
        for (base, result) in &results {
            let Ok((procs, _)) = result else { continue };
            let now_ids = snapshot::identity_set(procs);
            let base_ids = snapshot::identity_set(&baseline.0);
            let mut new_ids: Vec<&String> = now_ids.difference(&base_ids).collect();
            new_ids.sort();
            for id in new_ids {
                if !reported.insert((base.clone(), id.clone())) {
                    continue;
                }
                fires.push(format!("[{base}] new process identity: {id}"));
            }
        }
        assert_eq!(fires.len(), 1, "{fires:?}");
        assert!(fires[0].contains("[h2]") && fires[0].contains("xmrig"), "{fires:?}");
        // a second pass reports nothing (the dedup set holds)
        for (base, result) in &results {
            let Ok((procs, _)) = result else { continue };
            let now_ids = snapshot::identity_set(procs);
            for id in now_ids.difference(&snapshot::identity_set(&baseline.0)) {
                assert!(!reported.insert((base.clone(), id.clone())));
            }
        }
    }

    #[test]
    fn fleet_gpu_and_deleted_sentinels_judge_the_far_host_s_own_readings() {
        let cli = cli::Cli::parse_from([
            "witr",
            "--remote",
            "http://h1:9100",
            "--watch",
            "3",
            "--alert-gpu-mem-pct",
            "90",
            "--alert-deleted-gb",
            "2",
        ]);
        let sample = FleetSample {
            stats: crate::platform::SystemStats {
                gpus: vec![crate::gpu::GpuSample {
                    id: "0".into(),
                    name: "NVIDIA A100".into(),
                    util_pct: Some(95.0),
                    mem_used_mb: 78_000,
                    mem_total_mb: 81_920,
                    temp_c: Some(67.0),
                }],
                ..Default::default()
            },
            nics: Vec::new(),
            failed_units: Vec::new(),
            service_mems: Vec::new(),
            deleted_reclaimable_mb: 6 * 1024,
            deleted_files: vec![crate::platform::DeletedFile {
                pid: 900,
                name: "rsyslogd".into(),
                path: "/var/log/journal.log".into(),
                size_mb: 6 * 1024,
            }],
            net: None,
            mounts: Vec::new(),
        };
        let mut st = history::SysAlertState::default();
        let procs: Vec<Process> = Vec::new();
        for _ in 0..history::ALERT_CYCLES - 1 {
            assert!(
                fleet_alert_picks(&cli, &sample, &procs, &mut st, 3).is_empty(),
                "no fire before the window completes"
            );
        }
        let picks = fleet_alert_picks(&cli, &sample, &procs, &mut st, 3);
        assert_eq!(picks.len(), 2, "{picks:?}");
        assert!(
            picks.iter().any(|(_, d, _)| d.contains(
                "GPU memory gpu 0 (NVIDIA A100) 95% above 90%"
            )),
            "{picks:?}"
        );
        assert!(
            picks.iter().any(|(_, d, _)| d.contains(
                "deleted-but-held files: 6.0 GB above 2 GB"
            )),
            "{picks:?}"
        );
    }

    #[test]
    fn fleet_failed_units_alert_judges_the_far_host_s_own_list() {
        let cli = cli::Cli::parse_from([
            "witr",
            "--remote",
            "http://h1:9100",
            "--watch",
            "3",
            "--alert-failed-units",
            "1",
        ]);
        let sample = FleetSample {
            stats: crate::platform::SystemStats::default(),
            nics: Vec::new(),
            failed_units: vec!["ipmi.service".into(), "lightdm.service".into()],
            service_mems: Vec::new(),
            deleted_reclaimable_mb: 6 * 1024,
            deleted_files: vec![crate::platform::DeletedFile {
                pid: 900,
                name: "rsyslogd".into(),
                path: "/var/log/journal.log".into(),
                size_mb: 6 * 1024,
            }],
            net: None,
            mounts: Vec::new(),
        };
        let mut st = history::SysAlertState::default();
        let procs: Vec<Process> = Vec::new();
        for _ in 0..history::ALERT_CYCLES - 1 {
            assert!(
                fleet_alert_picks(&cli, &sample, &procs, &mut st, 3).is_empty(),
                "no fire before the window completes"
            );
        }
        let picks = fleet_alert_picks(&cli, &sample, &procs, &mut st, 3);
        assert_eq!(picks.len(), 1, "{picks:?}");
        assert!(
            picks[0]
                .1
                .contains("2 systemd units failed above 1 for 15s — ipmi.service, lightdm.service"),
            "{}",
            picks[0].1
        );
        // a peer predating the field (empty list) judges clean, not blind
        let mut old_sample = sample.clone();
        old_sample.failed_units = Vec::new();
        let mut st2 = history::SysAlertState::default();
        for _ in 0..history::ALERT_CYCLES {
            assert!(
                fleet_alert_picks(&cli, &old_sample, &procs, &mut st2, 3).is_empty(),
                "empty list → clean, never fires"
            );
        }
    }

    #[test]
    fn fleet_sentinels_fire_per_host_with_local_machinery() {
        let cli = cli::Cli::parse_from([
            "witr", "--remote", "http://h1:9100", "--watch", "3", "--alert-load", "4",
        ]);
        let sample = FleetSample {
            stats: crate::platform::SystemStats {
                load1: Some(9.0),
                ..Default::default()
            },
            nics: Vec::new(),
            failed_units: Vec::new(),
            service_mems: Vec::new(),
            deleted_reclaimable_mb: 0,
            deleted_files: Vec::new(),
            net: None,
            mounts: Vec::new(),
        };
        let mut st = history::SysAlertState::default();
        for _ in 0..history::ALERT_CYCLES - 1 {
            assert!(
                fleet_alert_picks(&cli, &sample, &[], &mut st, 3).is_empty(),
                "no fire before the window completes"
            );
        }
        let picks = fleet_alert_picks(&cli, &sample, &[], &mut st, 3);
        assert_eq!(picks.len(), 1, "{picks:?}");
        assert!(
            picks[0].1.contains("load average 9.00 above 4"),
            "{}",
            picks[0].1
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
        // three table rows (any states — the frame only counts them)
        let procs: Vec<Process> = (0..3)
            .map(|i| Process { pid: i, name: format!("p{i}"), ..Default::default() })
            .collect();
        let mut prev = None;
        // first frame arms only — no rates yet
        let f = sys_frame(&platform, &mut prev, &procs);
        assert!(f.nics.is_empty());
        assert_eq!(f.procs, 3);
        // 1 MB arriving over ~60 ms → a real rx rate on the second frame
        platform.rx.store(1024 * 1024, Relaxed);
        std::thread::sleep(Duration::from_millis(60));
        let frame = sys_frame(&platform, &mut prev, &[]);
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
