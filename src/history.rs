//! Sampling history across TUI refreshes: instantaneous CPU percent
//! (delta of cumulative CPU time), sparklines, and crash-loop detection
//! (same process identity reappearing under a new pid).
//!
//! Also home of the threshold-alert primitives ([`alert_cycle`] /
//! [`AlertTrack`]) shared by the TUI and the headless `--watch` loop.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::model::{Pid, Process};

/// Consecutive over-threshold samples before an alert fires (~15s at the
/// default 3s refresh) — one transient spike shouldn't page anyone.
pub const ALERT_CYCLES: u32 = 5;

/// One pid's threshold-alert bookkeeping: how many consecutive samples
/// each metric has been over its limit, whether an alert for that
/// excursion already fired (one per excursion — re-arms when it drops
/// back under), and how long each firing excursion has been burning
/// (for `--alert-repeat` re-sends; seconds accumulate per sample).
#[derive(Default)]
pub struct AlertTrack {
    pub cpu_streak: u32,
    pub cpu_firing: bool,
    pub cpu_fired_secs: u32,
    pub mem_streak: u32,
    pub mem_firing: bool,
    pub mem_fired_secs: u32,
    pub fd_streak: u32,
    pub fd_firing: bool,
    pub fd_fired_secs: u32,
    pub io_streak: u32,
    pub io_firing: bool,
    pub io_fired_secs: u32,
    pub conn_streak: u32,
    pub conn_firing: bool,
    pub conn_fired_secs: u32,
    pub threads_streak: u32,
    pub threads_firing: bool,
    pub threads_fired_secs: u32,
    pub net_streak: u32,
    pub net_firing: bool,
    pub net_fired_secs: u32,
    pub dev_streak: u32,
    pub dev_firing: bool,
    pub dev_fired_secs: u32,
}

/// What one sample did to a metric's alert cycle: nothing, a threshold
/// crossing just fired, or a firing excursion dropped back under the line
/// (a recovery — reported once, then the cycle re-arms from zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertEdge {
    None,
    Fire,
    Recover,
}

/// One alert-silence rule: alerts about matching processes are held down
/// for a window (a maintenance `--alert-silence backup=30m`). `!pattern`
/// inverts the match (silence everything NOT matching). No duration means
/// the whole session.
#[derive(Debug, Clone, PartialEq)]
pub struct SilenceRule {
    /// substring matched against the process name
    pub pattern: String,
    /// true for a leading `!` — the rule covers names NOT containing it
    pub negate: bool,
    /// unix seconds the window ends; None = whole session
    pub until: Option<u64>,
}

impl SilenceRule {
    /// `backup=30m` / `backup` / `!backup=1h` — None on a bad duration.
    pub fn parse(spec: &str) -> Option<SilenceRule> {
        let (negate, spec) = match spec.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, spec),
        };
        let (pattern, dur) = match spec.split_once('=') {
            Some((p, d)) => (p, Some(d)),
            None => (spec, None),
        };
        let pattern = pattern.trim();
        if pattern.is_empty() {
            return None;
        }
        let until = match dur {
            Some(d) => {
                let secs = crate::util::parse_duration(d)?;
                Some((crate::util::now_unix() + secs) as u64)
            }
            None => None,
        };
        Some(SilenceRule {
            pattern: pattern.to_string(),
            negate,
            until,
        })
    }

    /// Does the rule cover this name right now?
    pub fn covers(&self, name: &str, now: u64) -> bool {
        self.until.is_none_or(|t| now < t) && (name.contains(&self.pattern) != self.negate)
    }
}

/// Any rule silences this pick?
pub fn silenced(rules: &[SilenceRule], name: &str, now: u64) -> bool {
    rules.iter().any(|r| r.covers(name, now))
}

/// `--alert-new-proc`: first-sighting alerts. Substring match on the
/// process name (case-insensitive); `!`-prefixed specs switch the whole
/// set to whitelist mode (alert when a name matches NONE of the
/// patterns). Mixing plain and `!` specs is a usage error.
#[derive(Default)]
pub struct NewProcWatch {
    pub patterns: Vec<String>,
    /// whitelist mode — alert names NOT matching any pattern
    pub negate: bool,
    /// names already sighted this session (alert fires once per name)
    pub seen: std::collections::HashSet<String>,
}

impl NewProcWatch {
    /// Ok(None) when not armed (no specs); Err on mixed modes.
    pub fn parse(specs: &[String]) -> Result<Option<NewProcWatch>, String> {
        if specs.is_empty() {
            return Ok(None);
        }
        let negate = specs.iter().any(|s| s.starts_with('!'));
        let plain = specs.iter().any(|s| !s.starts_with('!'));
        if negate && plain {
            return Err("specs can't mix plain and '!'-prefixed (whitelist) forms".into());
        }
        Ok(Some(NewProcWatch {
            patterns: specs
                .iter()
                .map(|s| s.trim_start_matches('!').to_lowercase())
                .collect(),
            negate,
            seen: Default::default(),
        }))
    }

    /// Does the mode cover this name? (case-insensitive substring)
    pub fn matches(&self, name: &str) -> bool {
        let n = name.to_lowercase();
        let hit = self.patterns.iter().any(|p| n.contains(p));
        hit != self.negate
    }

    /// True exactly once per session for a first-seen name the mode
    /// covers — the alert edge.
    pub fn first_sighting(&mut self, name: &str) -> bool {
        if self.seen.insert(name.to_lowercase()) {
            self.matches(name)
        } else {
            false
        }
    }
}

/// Processes that lived shorter than this never reach a regular tick's
/// started/exited pair — the poller owns them.
pub const BRIEF_MAX_MS: u64 = 5_000;

/// Short-lived process capture: a high-frequency poller diffs cheap pid
/// sweeps between the regular ticks; anything that spawns and dies in the
/// gap (a crashing worker, a cron one-shot, an exec probe) surfaces as a
/// "brief" event instead of vanishing. Departures older than
/// [`BRIEF_MAX_MS`] are dropped — the regular sampler owns those.
pub struct BriefTracker {
    seen: HashMap<Pid, (Instant, Option<String>)>,
}

impl Default for BriefTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl BriefTracker {
    pub fn new() -> Self {
        BriefTracker {
            seen: HashMap::new(),
        }
    }

    /// Feed one fast poll: returns "brief" events for pids that vanished
    /// since the previous poll. `name_of` resolves names at first
    /// sighting (once the process is gone it's too late to ask).
    pub fn poll(
        &mut self,
        pids: &[Pid],
        name_of: &dyn Fn(Pid) -> Option<String>,
    ) -> Vec<TuiEvent> {
        let now_unix = crate::util::now_unix();
        let mut events = Vec::new();
        let current: std::collections::HashSet<Pid> = pids.iter().copied().collect();
        for &pid in pids {
            self.seen
                .entry(pid)
                .or_insert_with(|| (Instant::now(), name_of(pid)));
        }
        let entries: Vec<(Pid, (Instant, Option<String>))> = self.seen.drain().collect();
        for (pid, (first, name)) in entries {
            if current.contains(&pid) {
                self.seen.insert(pid, (first, name));
                continue;
            }
            let ms = first.elapsed().as_millis() as u64;
            if ms <= BRIEF_MAX_MS {
                let name = name.unwrap_or_else(|| format!("pid {pid}"));
                events.push(TuiEvent {
                    at_unix: now_unix,
                    kind: "brief".into(),
                    pid,
                    name,
                    detail: format!("spawned and exited within ~{}ms", ms.max(1)),
                });
            }
        }
        events
    }
}

/// Background poller thread feeding "brief" events through a channel —
/// the TUI and the headless `--watch` loop drain it per tick. Stop by
/// setting the returned flag (the consumer's Drop does that); the thread
/// also exits when the channel's receiver is gone.
pub fn spawn_brief_poller(
    interval_ms: u64,
) -> (
    std::sync::mpsc::Receiver<TuiEvent>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    let (tx, rx) = std::sync::mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    std::thread::Builder::new()
        .name("brief-poller".into())
        .spawn(move || {
            let mut tracker = BriefTracker::new();
            while !stop_thread.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(interval_ms.max(50)));
                if let Some(pids) = crate::platform::quick_pids() {
                    let events =
                        tracker.poll(&pids, &|pid| crate::platform::quick_name(pid));
                    for e in events {
                        if tx.send(e).is_err() {
                            return; // consumer gone
                        }
                    }
                }
            }
        })
        .ok();
    (rx, stop)
}

/// A live `docker/podman/nerdctl events` follower: parsed container edges
/// arrive on `rx`; killing the runtime CLI on drop is the struct's job
/// (closing stdout is what ends the reader thread).
pub struct ContainerEventStream {
    pub rx: std::sync::mpsc::Receiver<TuiEvent>,
    pub child: std::process::Child,
}

impl Drop for ContainerEventStream {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the first runtime CLI that answers: death, OOM and health edges
/// arrive in milliseconds instead of waiting for the next enumeration
/// sweep (whose diff-based detector stays as the fallback when no runtime
/// is on PATH). The reader thread ends when the child is killed (owner
/// drops the stream) or the channel closes.
pub fn spawn_container_events() -> Option<ContainerEventStream> {
    // each runtime spells `--format` its own way: docker speaks Go
    // templates, podman/nerdctl take the `json` keyword
    for (rt, fmt) in [
        ("docker", vec!["--format", "{{json .}}"]),
        ("podman", vec!["--format", "json"]),
        ("nerdctl", vec!["--format", "json"]),
    ] {
        let mut child = match std::process::Command::new(rt)
            .arg("events")
            .args(&fmt)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => continue, // not on PATH — try the next runtime
        };
        let Some(out) = child.stdout.take() else {
            let _ = child.kill();
            continue;
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("container-events".into())
            .spawn(move || {
                use std::io::BufRead as _;
                let reader = std::io::BufReader::new(out);
                for line in reader.lines().map_while(Result::ok) {
                    let Some(e) = parse_container_event_line(&line) else {
                        continue;
                    };
                    if tx.send(e).is_err() {
                        break; // consumer gone
                    }
                }
            });
        match spawned {
            Ok(_) => return Some(ContainerEventStream { rx, child }),
            Err(_) => continue, // thread spawn failed — near-impossible
        }
    }
    None
}

/// Parse one `docker/podman/nerdctl events` JSON line into a [`TuiEvent`] —
/// only the alert-worthy edges: `die`/`died` (exit code in the detail),
/// `oom`, and a health check flipping unhealthy. Everything else (start,
/// create, exec, `health_status: healthy`…) is noise and returns None.
/// Old daemons carry `status`/`id`/`from` instead of `Action`/`Actor` —
/// the name then falls back to the image ref's last segment.
pub fn parse_container_event_line(line: &str) -> Option<TuiEvent> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let typ = v.get("Type").and_then(|x| x.as_str()).unwrap_or("container");
    if typ != "container" {
        return None;
    }
    let action = v
        .get("Action")
        .or_else(|| v.get("Status"))
        .or_else(|| v.get("status"))
        .and_then(|x| x.as_str())?;
    let attrs = v.pointer("/Actor/Attributes");
    let attr = |k: &str| {
        attrs
            .and_then(|a| a.get(k))
            .and_then(|x| x.as_str())
            .unwrap_or("")
    };
    let name = {
        let n = attr("name");
        if !n.is_empty() {
            n.to_string()
        } else {
            let from = v.get("from").and_then(|x| x.as_str()).unwrap_or("");
            from.rsplit('/').next().unwrap_or(from).to_string()
        }
    };
    if name.is_empty() {
        return None;
    }
    let (kind, detail) = match action {
        "die" | "died" => {
            let code = attr("exitCode");
            let why = if code.is_empty() {
                "exited".to_string()
            } else {
                format!("exited (exit code {code})")
            };
            ("container-death", why)
        }
        "oom" => (
            "container-death",
            "hit its memory limit — killed by the kernel (OOM)".to_string(),
        ),
        a if a.starts_with("health_status") && a.ends_with("unhealthy") => {
            ("container-health", "health check went unhealthy".to_string())
        }
        _ => return None,
    };
    Some(TuiEvent {
        at_unix: v
            .get("time")
            .and_then(|x| x.as_i64())
            .unwrap_or_else(crate::util::now_unix),
        kind: kind.to_string(),
        pid: 0,
        name,
        detail,
    })
}

/// Advance one metric's alert cycle by one sample. Returns [`AlertEdge::Fire`]
/// exactly when the streak first reaches [`ALERT_CYCLES`] on a not-yet-firing
/// excursion and [`AlertEdge::Recover`] when a firing excursion's sample
/// lands back under the threshold; any under sample resets the counters.
pub fn alert_cycle(streak: &mut u32, firing: &mut bool, over: bool) -> AlertEdge {
    if over {
        *streak += 1;
        if *streak >= ALERT_CYCLES && !*firing {
            *firing = true;
            return AlertEdge::Fire;
        }
    } else {
        let recovering = *firing;
        *streak = 0;
        *firing = false;
        if recovering {
            return AlertEdge::Recover;
        }
    }
    AlertEdge::None
}

/// [`alert_cycle`] plus `--alert-repeat`: on an excursion that is already
/// firing and still over the threshold, keep returning [`AlertEdge::Fire`]
/// about every `repeat_secs` seconds (samples arrive every `interval_secs`).
/// `None` repeat keeps the classic once-per-excursion behavior. A first fire
/// or a drop back under resets the repeat clock.
pub fn alert_cycle_repeat(
    streak: &mut u32,
    firing: &mut bool,
    over: bool,
    fired_secs: &mut u32,
    repeat_secs: Option<u64>,
    interval_secs: u64,
) -> AlertEdge {
    let first = alert_cycle(streak, firing, over);
    if !over {
        *fired_secs = 0;
        return first;
    }
    if first == AlertEdge::Fire {
        *fired_secs = 0;
        return AlertEdge::Fire;
    }
    if let Some(rp) = repeat_secs {
        // only an excursion that is actually firing re-fires — the arming
        // samples (streak below ALERT_CYCLES) don't tick the repeat clock
        if *firing {
            *fired_secs += interval_secs.max(1) as u32;
            if *fired_secs >= rp.max(1) as u32 {
                *fired_secs = 0;
                return AlertEdge::Fire;
            }
        }
    }
    AlertEdge::None
}

/// Streak/firing/repeat-clock state for the machine-wide alerts
/// (--alert-load / --alert-mem-pct) — one instance per sampler, shared by
/// the TUI and the headless --watch loop (the per-process counterpart
/// lives in [`AlertTrack`], keyed by pid; the machine has no pid).
#[derive(Debug, Default, Clone)]
pub struct SysAlertState {
    pub load_streak: u32,
    pub load_firing: bool,
    pub load_fired_secs: u32,
    pub mem_streak: u32,
    pub mem_firing: bool,
    pub mem_fired_secs: u32,
    pub count_streak: u32,
    pub count_firing: bool,
    pub count_fired_secs: u32,
    pub disk_streak: u32,
    pub disk_firing: bool,
    pub disk_fired_secs: u32,
    /// Total rx+tx bytes across non-loopback NICs at `net_prev_at` — the
    /// previous sample [`machine_net_rate`] diffs against.
    pub net_prev: Option<(u64, u64)>,
    pub net_prev_at: Option<std::time::Instant>,
    pub net_streak: u32,
    pub net_firing: bool,
    pub net_fired_secs: u32,
    pub psi_streak: u32,
    pub psi_firing: bool,
    pub psi_fired_secs: u32,
    pub mem_avail_streak: u32,
    pub mem_avail_firing: bool,
    pub mem_avail_fired_secs: u32,
    pub swap_streak: u32,
    pub swap_firing: bool,
    pub swap_fired_secs: u32,
    /// Cumulative TCP RetransSegs at `retrans_prev_at` — the previous
    /// sample [`machine_retrans_rate`] diffs against.
    pub retrans_prev: Option<u64>,
    pub retrans_prev_at: Option<std::time::Instant>,
    pub retrans_streak: u32,
    pub retrans_firing: bool,
    pub retrans_fired_secs: u32,
    /// Total rx+tx drop counters across non-loopback NICs at
    /// `drop_prev_at` — the previous sample [`machine_drop_rate`] diffs
    /// against.
    pub drop_prev: Option<u64>,
    pub drop_prev_at: Option<std::time::Instant>,
    pub drop_streak: u32,
    pub drop_firing: bool,
    pub drop_fired_secs: u32,
}

/// The armed machine-wide alert thresholds plus the inputs they compare
/// against — one bundle so [`system_alert_picks`] stays readable. Fields
/// left `None` are disarmed; `proc_count` is only read when `count` is
/// armed and `mounts` only when `disk_pct` is.
pub struct SysAlertLimits {
    pub load: Option<f64>,
    pub mem_pct: Option<u64>,
    pub count: Option<u32>,
    pub proc_count: usize,
    /// One device-backed mount sweep — only fetched when `disk_pct` is
    /// armed (the df subprocess is paid by watchers, not everyone).
    pub mounts: Vec<crate::platform::MountUsage>,
    /// --alert-disk: fire when any mount's used percent exceeds this.
    pub disk_pct: Option<u64>,
    /// --alert-net threshold in MB/s. Armed only when `net_rate` is too —
    /// the counters sweep is paid by whoever arms it.
    pub net_limit: Option<u64>,
    /// Machine-wide rx+tx throughput in MB/s, computed by the caller via
    /// [`machine_net_rate`] just before this call. `None` (first sample or
    /// counters unreadable) disarms the check for that tick.
    pub net_rate: Option<f64>,
    /// --alert-psi threshold in percent: fire when any resource's PSI full
    /// stall (avg10) exceeds it. Disarmed when the platform reports no PSI.
    pub psi_limit: Option<f64>,
    /// --alert-mem-avail-mb: fire when reclaimable memory (MemAvailable)
    /// drops below this absolute floor in MB. Percentage thresholds lie on
    /// big-RAM machines; "MB left" doesn't. Disarmed where the platform
    /// reports no avail figure.
    pub mem_avail_floor: Option<u64>,
    /// --alert-swap-pct: fire when swap used percent exceeds this. Disarmed
    /// when the platform reports no swap (or swap is 0 — nothing to
    /// saturate).
    pub swap_pct_limit: Option<u64>,
    /// --alert-retrans threshold in segments/s, compared against the
    /// caller's [`machine_retrans_rate`] output. `None` (first sample or
    /// the platform reports no TCP counters) disarms the check.
    pub retrans_limit: Option<f64>,
    pub retrans_rate: Option<f64>,
    /// --alert-nic-drop threshold in packets/s, compared against the
    /// caller's [`machine_drop_rate`] output. `None` disarms.
    pub drop_limit: Option<f64>,
    pub drop_rate: Option<f64>,
    pub repeat: Option<u64>,
}

/// Diff cumulative NIC byte totals into a machine-wide throughput in MB/s.
/// `total` is `(rx_bytes, tx_bytes)` summed over non-loopback interfaces.
/// Returns `None` on the first sample (no previous to diff against); a
/// counter reset (interface bounce producing a smaller total) counts as a
/// zero delta rather than a huge negative rate.
pub fn machine_net_rate(total: (u64, u64), state: &mut SysAlertState) -> Option<f64> {
    let now = std::time::Instant::now();
    let rate = state.net_prev.zip(state.net_prev_at).and_then(|(prev, at)| {
        let elapsed = now.duration_since(at).as_secs_f64();
        (elapsed > 0.0).then(|| {
            let d_rx = total.0.saturating_sub(prev.0);
            let d_tx = total.1.saturating_sub(prev.1);
            (d_rx + d_tx) as f64 / elapsed / 1024.0 / 1024.0
        })
    });
    state.net_prev = Some(total);
    state.net_prev_at = Some(now);
    rate
}

/// Diff the cumulative TCP RetransSegs counter into a segments-per-second
/// rate. `None` on the first sample (no previous to diff against); a
/// counter reset (the box's TCP stats restart — container namespace? net
/// stack reload?) counts as a zero delta rather than a huge spike.
pub fn machine_retrans_rate(total: u64, state: &mut SysAlertState) -> Option<f64> {
    let now = std::time::Instant::now();
    let rate = state.retrans_prev.zip(state.retrans_prev_at).and_then(|(prev, at)| {
        let elapsed = now.duration_since(at).as_secs_f64();
        (elapsed > 0.0).then(|| total.saturating_sub(prev) as f64 / elapsed)
    });
    state.retrans_prev = Some(total);
    state.retrans_prev_at = Some(now);
    rate
}

/// Diff summed NIC rx+tx drop/error counters into a packets-per-second
/// rate. `None` on the first sample. Drops are the NIC or queue throwing
/// work away — throughput can look fine while packets never arrive.
pub fn machine_drop_rate(total: u64, state: &mut SysAlertState) -> Option<f64> {
    let now = std::time::Instant::now();
    let rate = state.drop_prev.zip(state.drop_prev_at).and_then(|(prev, at)| {
        let elapsed = now.duration_since(at).as_secs_f64();
        (elapsed > 0.0).then(|| total.saturating_sub(prev) as f64 / elapsed)
    });
    state.drop_prev = Some(total);
    state.drop_prev_at = Some(now);
    rate
}

/// One machine-wide alert edge: `(name, detail, is_recovery)` — name is
/// always `"system"` (the machine has no pid); recoveries read
/// `<metric> back under <limit>`.
pub type SysPick = (String, String, bool);

/// Shared container/pod edge detector. The TUI (Containers tab open) and
/// the headless `--watch --alert-container` loop both feed it fresh
/// enumerations; first sighting arms quietly, afterwards each edge fires
/// exactly once: a running container dying (with the inspect'ed cause of
/// death), a climbing runtime RestartCount, and — with a reachable
/// cluster — pod waiting reasons (CrashLoopBackOff & co), Running →
/// Pending, Failed phase, climbing k8s restart totals.
#[derive(Default)]
pub struct ContainerEdges {
    /// "runtime/id" → (state, restarts, oom_kills) of the previous
    /// enumeration.
    container_seen: std::collections::HashMap<String, (String, Option<u32>, Option<u64>)>,
    /// pod key → (phase, restarts, waiting reason) of the previous sweep.
    pod_seen: std::collections::HashMap<String, (Option<String>, u32, Option<String>)>,
}

impl ContainerEdges {
    /// Fold one enumeration in, return the (name, detail) firings. Inspect
    /// calls (exit reason) happen only on the death edge. `stream_live`
    /// suppresses the death edge — a live docker/podman `events` stream
    /// owns instant death reporting, and the sweep-diff double-firing it
    /// would be noise (the sweep still records state, so the detector's
    /// memory stays correct for every other edge).
    pub fn update(
        &mut self,
        cs: &[crate::model::Container],
        pods: &[crate::k8s::Pod],
        stream_live: bool,
    ) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for c in cs {
            let key = format!("{}/{}", c.runtime, c.id);
            if let Some((st, rst, oom)) = self.container_seen.get(&key) {
                let pod_tag = match &c.pod {
                    Some(p) => format!(" · pod {p}"),
                    None => String::new(),
                };
                let was_running = st == "running";
                let now_dead = matches!(c.state.as_str(), "exited" | "dead");
                if was_running && now_dead && !stream_live {
                    let reason = crate::platform::container_exit_reason(&c.runtime, &c.id)
                        .unwrap_or_else(|| c.status.clone());
                    out.push((
                        format!("container {}", c.name),
                        format!("exited — {reason}{pod_tag}"),
                    ));
                }
                if let (Some(old), Some(new)) = (*rst, c.restarts) {
                    if new > old {
                        out.push((
                            format!("container {}", c.name),
                            format!("restart count {old} → {new} (crash loop?){pod_tag}"),
                        ));
                    }
                }
                // cgroup memory.events oom_kill climb — the kernel OOM
                // killer went to work inside this container even if a
                // restart policy hid the exit code
                if let (Some(old), Some(new)) = (*oom, c.oom_kills) {
                    if new > old {
                        out.push((
                            format!("container {}", c.name),
                            format!(
                                "OOM kill count {old} → {new} — the kernel OOM-killed inside this container{pod_tag}"
                            ),
                        ));
                    }
                }
            }
            self.container_seen
                .insert(key, (c.state.clone(), c.restarts, c.oom_kills));
        }
        // removed containers drop out of the edge detector's memory
        let live: std::collections::HashSet<String> = cs
            .iter()
            .map(|c| format!("{}/{}", c.runtime, c.id))
            .collect();
        self.container_seen.retain(|k, _| live.contains(k));

        for p in pods {
            if let Some((phase, restarts, waiting)) = self.pod_seen.get(&p.key) {
                if p.waiting.is_some() && *waiting != p.waiting {
                    out.push((
                        format!("pod {}", p.key),
                        format!(
                            "containers waiting: {}{}",
                            p.waiting.clone().unwrap_or_default(),
                            match &p.phase {
                                Some(ph) => format!(" (phase {ph})"),
                                None => String::new(),
                            }
                        ),
                    ));
                }
                if phase.as_deref() == Some("Running") && p.phase.as_deref() == Some("Pending") {
                    out.push((format!("pod {}", p.key), "went Pending again".into()));
                }
                if p.phase.as_deref() == Some("Failed") && phase.as_deref() != Some("Failed") {
                    out.push((format!("pod {}", p.key), "phase Failed".into()));
                }
                if p.restarts > *restarts {
                    out.push((
                        format!("pod {}", p.key),
                        format!("restart count {} → {} (crash loop?)", restarts, p.restarts),
                    ));
                }
            }
            self.pod_seen
                .insert(p.key.clone(), (p.phase.clone(), p.restarts, p.waiting.clone()));
        }
        let live_pods: std::collections::HashSet<&str> =
            pods.iter().map(|p| p.key.as_str()).collect();
        self.pod_seen
            .retain(|k, _| live_pods.contains(k.as_str()));
        out
    }

    // test-only peeks at the edge detector's memory
    #[cfg(test)]
    pub(crate) fn tracks_container(&self, key: &str) -> bool {
        self.container_seen.contains_key(key)
    }

    #[cfg(test)]
    pub(crate) fn containers_tracked(&self) -> usize {
        self.container_seen.len()
    }

    #[cfg(test)]
    pub(crate) fn pods_tracked(&self) -> usize {
        self.pod_seen.len()
    }
}

/// One tick of the machine-wide alerts. `stats` comes from the platform's
/// `system_stats()`; firings are [`SysPick`]s with no pid (the machine is
/// not a process). Same 5-samples-and-latch cycle as the per-process
/// alerts, including --alert-repeat — plus a recovery edge when a firing
/// excursion drops back under.
pub fn system_alert_picks(
    stats: &crate::platform::SystemStats,
    state: &mut SysAlertState,
    limits: &SysAlertLimits,
    interval_secs: u64,
) -> Vec<SysPick> {
    let SysAlertLimits {
        load: load_limit,
        mem_pct: mem_pct_limit,
        count: count_limit,
        proc_count,
        mounts,
        disk_pct: disk_pct_limit,
        net_limit: net_limit_opt,
        net_rate: net_rate_opt,
        psi_limit: psi_limit_opt,
        mem_avail_floor,
        swap_pct_limit,
        retrans_limit,
        retrans_rate: retrans_rate_opt,
        drop_limit,
        drop_rate: drop_rate_opt,
        repeat: repeat_secs,
    } = limits;
    let load_limit = *load_limit;
    let mem_pct_limit = *mem_pct_limit;
    let count_limit = *count_limit;
    let proc_count = *proc_count;
    let disk_pct_limit = *disk_pct_limit;
    let net_limit = *net_limit_opt;
    let net_rate = *net_rate_opt;
    let psi_limit = *psi_limit_opt;
    let retrans_rate = *retrans_rate_opt;
    let drop_rate = *drop_rate_opt;
    let mem_avail_floor = *mem_avail_floor;
    let swap_pct_limit = *swap_pct_limit;
    let retrans_limit = *retrans_limit;
    let drop_limit = *drop_limit;
    let repeat_secs = *repeat_secs;
    let mut out = Vec::new();
    if let Some(limit) = load_limit {
        let now = stats.load1;
        let over = now.is_some_and(|l| l > limit);
        let edge = alert_cycle_repeat(
            &mut state.load_streak,
            &mut state.load_firing,
            over,
            &mut state.load_fired_secs,
            repeat_secs,
            interval_secs,
        );
        if edge == AlertEdge::Fire {
            out.push((
                "system".to_string(),
                format!(
                    "load average {:.2} above {limit} for {}s",
                    now.unwrap_or(0.0),
                    ALERT_CYCLES as u64 * interval_secs.max(1)
                ),
                false,
            ));
        } else if edge == AlertEdge::Recover {
            out.push(("system".to_string(), format!("load average back under {limit}"), true));
        }
    }
    if let Some(limit) = mem_pct_limit {
        let pct = match (stats.mem_used_mb, stats.mem_total_mb) {
            (Some(u), Some(t)) if t > 0 => Some((u * 100) / t),
            _ => None,
        };
        let over = pct.is_some_and(|p| p > limit);
        let edge = alert_cycle_repeat(
            &mut state.mem_streak,
            &mut state.mem_firing,
            over,
            &mut state.mem_fired_secs,
            repeat_secs,
            interval_secs,
        );
        if edge == AlertEdge::Fire {
            out.push((
                "system".to_string(),
                format!(
                    "RAM {}% above {limit}% for {}s",
                    pct.unwrap_or(0),
                    ALERT_CYCLES as u64 * interval_secs.max(1)
                ),
                false,
            ));
        } else if edge == AlertEdge::Recover {
            out.push(("system".to_string(), format!("RAM back under {limit}%"), true));
        }
    }
    if let Some(limit) = count_limit {
        let over = proc_count > limit as usize;
        let edge = alert_cycle_repeat(
            &mut state.count_streak,
            &mut state.count_firing,
            over,
            &mut state.count_fired_secs,
            repeat_secs,
            interval_secs,
        );
        if edge == AlertEdge::Fire {
            out.push((
                "system".to_string(),
                format!(
                    "{proc_count} visible processes above {limit} for {}s",
                    ALERT_CYCLES as u64 * interval_secs.max(1)
                ),
                false,
            ));
        } else if edge == AlertEdge::Recover {
            out.push((
                "system".to_string(),
                format!("process count back under {limit}"),
                true,
            ));
        }
    }
    if let Some(limit) = disk_pct_limit {
        // the fullest mounts first, capped at three in the detail line —
        // the message is a pointer, not a report
        let mut over_mounts: Vec<(u64, &crate::platform::MountUsage)> = mounts
            .iter()
            .filter(|m| m.total_mb > 0)
            .map(|m| ((m.used_mb * 100) / m.total_mb, m))
            .filter(|(pct, _)| *pct > limit)
            .collect();
        over_mounts.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.target.cmp(&b.1.target)));
        let over = !over_mounts.is_empty();
        let edge = alert_cycle_repeat(
            &mut state.disk_streak,
            &mut state.disk_firing,
            over,
            &mut state.disk_fired_secs,
            repeat_secs,
            interval_secs,
        );
        if edge == AlertEdge::Fire {
            let worst: Vec<String> = over_mounts
                .iter()
                .take(3)
                .map(|(pct, m)| format!("{} {pct}%", m.target))
                .collect();
            out.push((
                "system".to_string(),
                format!(
                    "disk {} above {limit}% for {}s",
                    worst.join(", "),
                    ALERT_CYCLES as u64 * interval_secs.max(1)
                ),
                false,
            ));
        } else if edge == AlertEdge::Recover {
            out.push((
                "system".to_string(),
                format!("disk back under {limit}%"),
                true,
            ));
        }
    }
    if let (Some(limit), Some(rate)) = (net_limit, net_rate) {
        let over = rate > limit as f64;
        let edge = alert_cycle_repeat(
            &mut state.net_streak,
            &mut state.net_firing,
            over,
            &mut state.net_fired_secs,
            repeat_secs,
            interval_secs,
        );
        if edge == AlertEdge::Fire {
            out.push((
                "system".to_string(),
                format!(
                    "net {rate:.1} MB/s above {limit} MB/s for {}s",
                    ALERT_CYCLES as u64 * interval_secs.max(1)
                ),
                false,
            ));
        } else if edge == AlertEdge::Recover {
            out.push((
                "system".to_string(),
                format!("net back under {limit} MB/s"),
                true,
            ));
        }
    }
    if let Some(limit) = psi_limit {
        // full stall on any resource — cpu has no full line (0), so this is
        // really mem/io. detail names the resources over the line.
        let over_resources: Vec<(&str, f64)> = stats
            .psi
            .as_ref()
            .map(|p| {
                [
                    ("cpu", p.cpu_full),
                    ("mem", p.mem_full),
                    ("io", p.io_full),
                ]
                .into_iter()
                .filter(|(_, v)| *v > limit)
                .collect()
            })
            .unwrap_or_default();
        let over = !over_resources.is_empty();
        let edge = alert_cycle_repeat(
            &mut state.psi_streak,
            &mut state.psi_firing,
            over,
            &mut state.psi_fired_secs,
            repeat_secs,
            interval_secs,
        );
        if edge == AlertEdge::Fire {
            let named: Vec<String> = over_resources
                .iter()
                .map(|(r, v)| format!("{r} {v:.1}%"))
                .collect();
            out.push((
                "system".to_string(),
                format!(
                    "PSI full {} above {limit}% for {}s",
                    named.join(", "),
                    ALERT_CYCLES as u64 * interval_secs.max(1)
                ),
                false,
            ));
        } else if edge == AlertEdge::Recover {
            out.push(("system".to_string(), format!("PSI back under {limit}%"), true));
        }
    }
    if let Some(floor) = mem_avail_floor {
        let avail = stats.mem_avail_mb;
        // the floor is a *lower* bound: over = we've fallen under it
        let under = avail.is_some_and(|a| a < floor);
        let edge = alert_cycle_repeat(
            &mut state.mem_avail_streak,
            &mut state.mem_avail_firing,
            under,
            &mut state.mem_avail_fired_secs,
            repeat_secs,
            interval_secs,
        );
        if edge == AlertEdge::Fire {
            out.push((
                "system".to_string(),
                format!(
                    "MemAvailable {} MB below {floor} MB floor for {}s",
                    avail.unwrap_or(0),
                    ALERT_CYCLES as u64 * interval_secs.max(1)
                ),
                false,
            ));
        } else if edge == AlertEdge::Recover {
            out.push((
                "system".to_string(),
                format!("memory avail back above {floor} MB"),
                true,
            ));
        }
    }
    if let Some(limit) = swap_pct_limit {
        let pct = match (stats.swap_used_mb, stats.swap_total_mb) {
            (Some(u), Some(t)) if t > 0 => Some(u * 100 / t),
            _ => None,
        };
        let over = pct.is_some_and(|p| p > limit);
        let edge = alert_cycle_repeat(
            &mut state.swap_streak,
            &mut state.swap_firing,
            over,
            &mut state.swap_fired_secs,
            repeat_secs,
            interval_secs,
        );
        if edge == AlertEdge::Fire {
            out.push((
                "system".to_string(),
                format!(
                    "swap {}% above {limit}% for {}s",
                    pct.unwrap_or(0),
                    ALERT_CYCLES as u64 * interval_secs.max(1)
                ),
                false,
            ));
        } else if edge == AlertEdge::Recover {
            out.push(("system".to_string(), format!("swap back under {limit}%"), true));
        }
    }
    if let Some(limit) = retrans_limit {
        let over = retrans_rate.is_some_and(|r| r > limit);
        let edge = alert_cycle_repeat(
            &mut state.retrans_streak,
            &mut state.retrans_firing,
            over,
            &mut state.retrans_fired_secs,
            repeat_secs,
            interval_secs,
        );
        if edge == AlertEdge::Fire {
            out.push((
                "system".to_string(),
                format!(
                    "TCP retransmits {:.0}/s above {limit:.0}/s for {}s",
                    retrans_rate.unwrap_or(0.0),
                    ALERT_CYCLES as u64 * interval_secs.max(1)
                ),
                false,
            ));
        } else if edge == AlertEdge::Recover {
            out.push((
                "system".to_string(),
                format!("TCP retransmits back under {limit:.0}/s"),
                true,
            ));
        }
    }
    if let Some(limit) = drop_limit {
        let over = drop_rate.is_some_and(|r| r > limit);
        let edge = alert_cycle_repeat(
            &mut state.drop_streak,
            &mut state.drop_firing,
            over,
            &mut state.drop_fired_secs,
            repeat_secs,
            interval_secs,
        );
        if edge == AlertEdge::Fire {
            out.push((
                "system".to_string(),
                format!(
                    "NIC drops {:.0}/s above {limit:.0}/s for {}s",
                    drop_rate.unwrap_or(0.0),
                    ALERT_CYCLES as u64 * interval_secs.max(1)
                ),
                false,
            ));
        } else if edge == AlertEdge::Recover {
            out.push((
                "system".to_string(),
                format!("NIC drops back under {limit:.0}/s"),
                true,
            ));
        }
    }
    out
}

const SAMPLES: usize = 8;
/// Self-baseline deviation ([`History::deviation_of`]): the trailing
/// window its median is computed over, the minimum history before it
/// arms, and the absolute floor under which a reading is noise no matter
/// how many times the baseline it clears.
const DEV_SAMPLES: usize = 40; // ~2 min at the 3s TUI refresh
const DEV_MIN_SAMPLES: usize = 12;
const DEV_FLOOR_PCT: f64 = 5.0;
/// Detail-page CPU chart window (~10 min at the 3s TUI refresh).
const BIG_SAMPLES: usize = 120;
const RESTART_WINDOW: Duration = Duration::from_secs(5 * 60);
const PRUNE_AFTER: Duration = Duration::from_secs(10 * 60);
pub(crate) const SPARK_LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
/// Leak suspicion: RSS up at least this many MB across this many trailing
/// samples, rising at least this fraction of the time.
const LEAK_SAMPLES: usize = 60; // ~5 min at the 3s TUI refresh
const LEAK_MB: f64 = 20.0;
const LEAK_FRACTION: f64 = 0.7;
/// FD leak suspicion: same shape, on the open-descriptor count. Growth is
/// in fds (a socket-per-request service that never closes them climbs
/// steadily; a healthy one oscillates).
const FD_LEAK_SAMPLES: usize = 60; // ~5 min at the 3s TUI refresh
const FD_LEAK_GROWTH: f64 = 64.0;
const FD_LEAK_FRACTION: f64 = 0.7;
/// Thread leak suspicion: same shape on the kernel thread count. Sixteen
/// steady new threads over ~5 min is a leak; healthy thread pools oscillate.
const THR_LEAK_SAMPLES: usize = 60;
const THR_LEAK_GROWTH: f64 = 16.0;
const THR_LEAK_FRACTION: f64 = 0.7;

#[derive(Default, Clone)]
struct RestartState {
    last_pid: Pid,
    total: u32,
    events: Vec<Instant>,
    last_seen: Option<Instant>,
    /// argv of the last pid under this identity — a restart that changed
    /// its command line (or env, when both sides sampled it) says so in
    /// the event detail
    last_cmdline: Option<Vec<String>>,
    last_env: Option<Vec<(String, String)>>,
}

/// One thing that happened while the TUI watched the system: a process
/// appeared, exited, or came back under a new pid (restart). Fed from
/// [`History::update`] refresh deltas; the newest events come first.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TuiEvent {
    /// Wall-clock seconds when the delta was observed.
    pub at_unix: i64,
    /// "started" | "exited" | "restarted"
    pub kind: String,
    pub pid: Pid,
    pub name: String,
    /// Extra context: what replaced an exited pid, or the pid it restarted
    /// from, as a human string.
    pub detail: String,
}

/// Cap on the in-memory event ring (newest first).
const EVENT_CAP: usize = 500;
/// Board sizes for the session summary (spikes / climbers / chains).
const SUMMARY_CAP: usize = 8;

/// One row of the summary CPU-spike board.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SpikeRow {
    pub pid: Pid,
    pub name: String,
    /// Peak instantaneous CPU percent across the sampled window.
    pub peak: f64,
}

/// One row of the summary memory-climber board.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ClimbRow {
    pub pid: Pid,
    pub name: String,
    /// RSS growth from the first to the last sample, in MB.
    pub grew_mb: f64,
}

/// A program that restarted in-window, with the count.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ChainRow {
    pub name: String,
    pub count: u32,
}

/// The "what happened" digest behind `--since` and the TUI summary page
/// ('S'): appear/exit/restart activity inside the window, restart chains,
/// and the CPU-spike / memory-climber boards. Boards are built from the
/// live sample buffers, which only cover processes alive at the last
/// refresh — a replayed events log digests activity counts only.
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize)]
pub struct SessionSummary {
    /// Window length in seconds (`u64::MAX` = whole session).
    pub since_secs: u64,
    pub started: usize,
    pub exited: usize,
    pub restarted: usize,
    /// Restart chains in-window, hottest first, capped.
    pub chains: Vec<ChainRow>,
    /// Peak CPU per sampled pid, hottest first, capped.
    pub spikes: Vec<SpikeRow>,
    /// RSS growth per sampled pid, fastest first, capped.
    pub climbers: Vec<ClimbRow>,
}

/// `12345` → `3h25m45s` (summary windows and headers).
pub fn human_secs(secs: u64) -> String {
    let (d, rem) = (secs / 86400, secs % 86400);
    let (h, rem) = (rem / 3600, rem % 3600);
    let (m, s) = (rem / 60, rem % 60);
    let mut out = String::new();
    if d > 0 {
        out.push_str(&format!("{d}d"));
    }
    if h > 0 {
        out.push_str(&format!("{h}h"));
    }
    if m > 0 {
        out.push_str(&format!("{m}m"));
    }
    if s > 0 || out.is_empty() {
        out.push_str(&format!("{s}s"));
    }
    out
}

/// Earliest event second still inside the window.
fn cutoff_for(now_unix: i64, since_secs: u64) -> i64 {
    now_unix.saturating_sub(since_secs.min(i64::MAX as u64) as i64)
}

/// Activity counts + restart chains from a newest-first event ring,
/// windowed by `cutoff`.
fn activity_from_events(events: &[TuiEvent], cutoff: i64) -> (usize, usize, usize, Vec<ChainRow>) {
    let (mut started, mut exited, mut restarted) = (0usize, 0usize, 0usize);
    let mut chains: HashMap<String, u32> = HashMap::new();
    for e in events {
        if e.at_unix < cutoff {
            continue;
        }
        match e.kind.as_str() {
            "started" => started += 1,
            "exited" => exited += 1,
            "restarted" => {
                restarted += 1;
                *chains.entry(e.name.clone()).or_default() += 1;
            }
            _ => {}
        }
    }
    let mut rows: Vec<ChainRow> = chains
        .into_iter()
        .map(|(name, count)| ChainRow { name, count })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    rows.truncate(SUMMARY_CAP);
    (started, exited, restarted, rows)
}

/// Digest a recorded event ring (`--since` + `--replay`): activity counts
/// and restart chains only — the file carries no CPU/memory samples.
pub fn summary_from_events(events: &[TuiEvent], since_secs: u64) -> SessionSummary {
    let cutoff = cutoff_for(crate::util::now_unix(), since_secs);
    let (started, exited, restarted, chains) = activity_from_events(events, cutoff);
    SessionSummary {
        since_secs,
        started,
        exited,
        restarted,
        chains,
        ..Default::default()
    }
}

impl SessionSummary {
    /// Plain-text digest (the CLI `--since` output; the TUI page renders
    /// its own styled version from the same fields).
    pub fn to_text(&self) -> String {
        let window = if self.since_secs >= i64::MAX as u64 {
            "whole session".to_string()
        } else {
            format!("last {}", human_secs(self.since_secs))
        };
        let mut lines = vec![format!(
            "Session summary ({window}): started {} · exited {} · restarted {}",
            self.started, self.exited, self.restarted
        )];
        if !self.chains.is_empty() {
            let list: Vec<String> = self
                .chains
                .iter()
                .map(|c| format!("{} ×{}", c.name, c.count))
                .collect();
            lines.push(format!("  restart chains: {}", list.join(", ")));
        }
        if !self.spikes.is_empty() {
            lines.push("  CPU spikes:".into());
            for s in &self.spikes {
                lines.push(format!("    {} (pid {}) peak {:.0}%", s.name, s.pid, s.peak));
            }
        }
        if !self.climbers.is_empty() {
            lines.push("  memory climbers:".into());
            for c in &self.climbers {
                lines.push(format!("    {} (pid {}) +{:.1} MB", c.name, c.pid, c.grew_mb));
            }
        }
        lines.join("\n")
    }
}

/// One whole-machine sample for the system page ('y'): the fields the
/// page charts. Per-core percentages stay in the platform snapshot —
/// only the current grid is shown, no history.
#[derive(Debug, Clone, PartialEq)]
pub struct SystemSample {
    pub at_unix: i64,
    pub cpu: Option<f64>,
    pub mem_used_mb: Option<u64>,
    pub swap_used_mb: Option<u64>,
    pub load1: Option<f64>,
}

#[derive(Default)]
pub struct History {
    /// pid → (cpu ms at last sample, sampled at)
    cpu_prev: HashMap<Pid, (u64, Instant)>,
    /// pid → instantaneous percent (valid for pids in the last update)
    pub cpu_now: HashMap<Pid, f64>,
    /// pid → (read bytes, write bytes at last sample, sampled at)
    io_prev: HashMap<Pid, (u64, u64, Instant)>,
    /// pid → (read bytes/s, write bytes/s) from cumulative io deltas
    /// (Linux /proc/<pid>/io; empty on platforms that don't report it)
    pub io_rate: HashMap<Pid, (f64, f64)>,
    /// pid → (cumulative TCP bytes at last sweep, swept at) — fed by
    /// [`History::update_net`] from `ss` sweeps (Linux, when ss(8) is on
    /// PATH; empty elsewhere)
    net_prev: HashMap<Pid, (u64, Instant)>,
    /// pid → combined bytes/s (sent + received) from the sweep deltas
    pub net_rate: HashMap<Pid, f64>,
    /// pid → last SAMPLES instantaneous percents as a sparkline
    pub sparks: HashMap<Pid, String>,
    samples: HashMap<Pid, VecDeque<f64>>,
    /// pid → last DEV_SAMPLES instantaneous percents — the trailing window
    /// [`History::deviation_of`] takes its median baseline over
    dev_samples: HashMap<Pid, VecDeque<f64>>,
    /// pid → last BIG_SAMPLES instantaneous percents (detail-page chart)
    big: HashMap<Pid, VecDeque<f64>>,
    /// pid → last BIG_SAMPLES RSS values in KiB (detail-page memory chart
    /// and leak suspicion)
    mem_big: HashMap<Pid, VecDeque<u64>>,
    /// pid → last BIG_SAMPLES open-descriptor counts (detail-page fd chart
    /// and fd leak suspicion). Only sampled for the selected process while
    /// the detail page is open — a cheap native read on Linux and macOS
    /// (/proc, libproc), a full-table handle sweep on Windows.
    fd_big: HashMap<Pid, VecDeque<u64>>,
    /// pid → last SAMPLES fd counts as a sparkline (peak-normalized)
    pub fd_sparks: HashMap<Pid, String>,
    /// pid → last BIG_SAMPLES kernel thread counts (detail-page thread
    /// chart and thread leak suspicion). Rides the listing — Linux
    /// /proc/<pid>/stat and the Windows thread snapshot carry it for the
    /// whole table; macOS fills it only at detail time, so its window
    /// builds only while the detail page keeps the field populated.
    thr_big: HashMap<Pid, VecDeque<u32>>,
    /// pid → last BIG_SAMPLES (read, write) rates in bytes/s (detail-page
    /// I/O chart). Filled from the same cumulative deltas as `io_rate`,
    /// so it covers exactly the platforms that report per-process I/O.
    io_big: HashMap<Pid, VecDeque<(f64, f64)>>,
    /// pid → identity hash
    identity_of: HashMap<Pid, u64>,
    restarts: HashMap<u64, RestartState>,
    /// Newest-first ring of appear/exit/restart events.
    pub events: Vec<TuiEvent>,
    /// pid → name at the previous refresh (for appear/exit deltas).
    prev_seen: HashMap<Pid, String>,
    /// Whole-machine samples for the system page ('y'), oldest first.
    sys: VecDeque<SystemSample>,
}

impl History {
    pub fn new() -> Self {
        History::default()
    }

    /// Feed one refresh snapshot. Call before rebuilding views so tables
    /// can read `cpu_now` / `sparks`. Returns the events generated by this
    /// round (in generation order) so callers can persist them.
    pub fn update(&mut self, procs: &[Process]) -> Vec<TuiEvent> {
        let now = Instant::now();
        let now_unix = crate::util::now_unix();
        let seen: std::collections::HashSet<Pid> =
            procs.iter().map(|p| p.pid).collect();
        let mut fresh: Vec<TuiEvent> = Vec::new();
        let event = |h: &mut History, fresh: &mut Vec<TuiEvent>, kind: &str, pid: Pid, name: &str, detail: String| {
            let e = TuiEvent { at_unix: now_unix, kind: kind.to_string(), pid, name: name.to_string(), detail };
            h.events.insert(0, e.clone());
            h.events.truncate(EVENT_CAP);
            fresh.push(e);
        };

        for p in procs {
            if p.kernel_thread {
                continue;
            }
            let h = crate::util::identity(p);
            self.identity_of.insert(p.pid, h);

            // instantaneous cpu from cumulative cpu-time deltas
            if let Some(ms) = p.cpu_time_ms {
                match self.cpu_prev.get(&p.pid) {
                    Some((prev_ms, at)) if ms >= *prev_ms => {
                        let wall = now.duration_since(*at).as_millis() as f64;
                        let inst = if wall >= 50.0 {
                            ((ms - prev_ms) as f64 / wall * 100.0).min(400.0)
                        } else {
                            // sample too close to the previous one — keep last
                            self.cpu_now.get(&p.pid).copied().unwrap_or(0.0)
                        };
                        self.cpu_now.insert(p.pid, inst);
                        self.push_sample(p.pid, inst);
                    }
                    _ => {}
                }
                self.cpu_prev.insert(p.pid, (ms, now));
            }

            // instantaneous disk I/O from cumulative byte deltas (only the
            // Linux /proc listing fills these fields)
            if let Some(kb) = p.mem_kb {
                let dq = self.mem_big.entry(p.pid).or_default();
                dq.push_back(kb);
                while dq.len() > BIG_SAMPLES {
                    dq.pop_front();
                }
            }
            // thread counts ride the listing (Linux stat / Windows thread
            // snapshot) — same window as the memory chart
            if let Some(t) = p.threads {
                let dq = self.thr_big.entry(p.pid).or_default();
                dq.push_back(t);
                while dq.len() > BIG_SAMPLES {
                    dq.pop_front();
                }
            }
            if p.io_read_bytes.is_some() || p.io_write_bytes.is_some() {
                let (rb, wb) = (p.io_read_bytes.unwrap_or(0), p.io_write_bytes.unwrap_or(0));
                if let Some((prb, pwb, at)) = self.io_prev.get(&p.pid) {
                    let wall = now.duration_since(*at).as_millis() as f64;
                    if wall >= 50.0 && rb >= *prb && wb >= *pwb {
                        let s = wall / 1000.0;
                        let rate = ((rb - prb) as f64 / s, (wb - pwb) as f64 / s);
                        self.io_rate.insert(p.pid, rate);
                        let dq = self.io_big.entry(p.pid).or_default();
                        dq.push_back(rate);
                        while dq.len() > BIG_SAMPLES {
                            dq.pop_front();
                        }
                    }
                }
                self.io_prev.insert(p.pid, (rb, wb, now));
            }

            // restart bookkeeping: same identity, different pid
            let rs = self.restarts.entry(h).or_default();
            let is_restart = rs.last_pid != 0 && rs.last_pid != p.pid;
            if is_restart {
                rs.total += 1;
                rs.events.push(now);
            }
            let total = rs.total;
            let argv_changed = is_restart
                && match (&rs.last_cmdline, &p.cmdline) {
                    (Some(old), new) if !new.is_empty() => old != new,
                    _ => false,
                };
            let env_changed = is_restart
                && matches!((&rs.last_env, &p.env), (Some(old), Some(new)) if old != new);
            rs.last_pid = p.pid;
            rs.last_seen = Some(now);
            if !p.cmdline.is_empty() {
                rs.last_cmdline = Some(p.cmdline.clone());
            }
            if p.env.is_some() {
                rs.last_env = p.env.clone();
            }

            // appear / restart events for the Events tab
            match self.prev_seen.remove(&p.pid) {
                Some(_) => {}
                None if is_restart => {
                    let mut detail =
                        format!("came back after exiting ({total} restarts total)");
                    if argv_changed {
                        let argv: String = p
                            .command_line()
                            .chars()
                            .take(100)
                            .collect();
                        detail = format!(
                            "{detail} — argv changed to `{argv}`"
                        );
                    }
                    if env_changed {
                        detail.push_str(" — env changed");
                    }
                    event(self, &mut fresh, "restarted", p.pid, &p.name, detail);
                }
                None => event(self, &mut fresh, "started", p.pid, &p.name, String::new()),
            }
        }

        // everything still in prev_seen vanished since the last refresh
        let vanished: Vec<(Pid, String)> = self.prev_seen.drain().collect();
        for (pid, name) in vanished {
            event(self, &mut fresh, "exited", pid, &name, String::new());
        }
        self.prev_seen = procs
            .iter()
            .filter(|p| !p.kernel_thread)
            .map(|p| (p.pid, p.name.clone()))
            .collect();

        // drop history for processes that vanished
        self.cpu_now.retain(|pid, _| seen.contains(pid));
        self.sparks.retain(|pid, _| seen.contains(pid));
        self.samples.retain(|pid, _| seen.contains(pid));
        self.dev_samples.retain(|pid, _| seen.contains(pid));
        self.big.retain(|pid, _| seen.contains(pid));
        self.cpu_prev.retain(|pid, _| seen.contains(pid));
        self.io_rate.retain(|pid, _| seen.contains(pid));
        self.io_prev.retain(|pid, _| seen.contains(pid));
        self.mem_big.retain(|pid, _| seen.contains(pid));
        self.thr_big.retain(|pid, _| seen.contains(pid));
        self.fd_big.retain(|pid, _| seen.contains(pid));
        self.fd_sparks.retain(|pid, _| seen.contains(pid));
        self.io_big.retain(|pid, _| seen.contains(pid));
        self.identity_of.retain(|pid, _| seen.contains(pid));
        self.restarts.retain(|_, rs| {
            rs.last_seen
                .map(|at| now.duration_since(at) < PRUNE_AFTER)
                .unwrap_or(false)
        });
        for rs in self.restarts.values_mut() {
            rs.events.retain(|at| now.duration_since(*at) < RESTART_WINDOW);
        }
        fresh
    }

    fn push_sample(&mut self, pid: Pid, v: f64) {
        let dq = self.samples.entry(pid).or_default();
        dq.push_back(v);
        while dq.len() > SAMPLES {
            dq.pop_front();
        }
        // the deviation baseline keeps its own, longer window — 8 samples
        // is a sparkline, not a character reference
        let dev = self.dev_samples.entry(pid).or_default();
        dev.push_back(v);
        while dev.len() > DEV_SAMPLES {
            dev.pop_front();
        }
        let spark: String = dq
            .iter()
            .map(|v| {
                let idx = ((*v / 100.0).clamp(0.0, 0.999) * 8.0) as usize;
                SPARK_LEVELS[idx]
            })
            .collect();
        self.sparks.insert(pid, spark);
        let big = self.big.entry(pid).or_default();
        big.push_back(v);
        while big.len() > BIG_SAMPLES {
            big.pop_front();
        }
    }

    /// Restarts of `pid`'s identity within the tracking window (5 min).
    pub fn recent_restarts(&self, pid: Pid) -> Option<u32> {
        let h = self.identity_of.get(&pid)?;
        let rs = self.restarts.get(h)?;
        (!rs.events.is_empty()).then_some(rs.events.len() as u32)
    }

    /// Total restarts seen since the TUI started.
    pub fn total_restarts(&self, pid: Pid) -> u32 {
        self.identity_of
            .get(&pid)
            .and_then(|h| self.restarts.get(h))
            .map(|rs| rs.total)
            .unwrap_or(0)
    }

    /// Instantaneous percent with lifetime-average fallback (for display
    /// and sorting).
    pub fn display_cpu(&self, p: &Process) -> Option<f64> {
        self.cpu_now.get(&p.pid).copied().or(p.cpu)
    }

    /// Sparkline for the last samples; None when there aren't any yet.
    pub fn spark(&self, pid: Pid) -> Option<&str> {
        self.sparks.get(&pid).map(|s| s.as_str())
    }

    /// (read bytes/s, write bytes/s) from the last two samples; None until
    /// two samples exist (first refresh has no delta to diff).
    pub fn io_rate_of(&self, pid: Pid) -> Option<(f64, f64)> {
        self.io_rate.get(&pid).copied()
    }

    /// Fold one `ss` sweep in: diff each pid's cumulative TCP bytes
    /// against the previous sweep into a combined bytes/s figure (sent +
    /// received — the --top net board and --alert-net-per-proc both rank
    /// on it). Pids missing from this sweep leave the window (their
    /// sockets closed); the first sweep only arms the baseline.
    pub fn update_net(&mut self, per_pid: &HashMap<Pid, u64>) {
        let now = Instant::now();
        for (pid, cur) in per_pid {
            if let Some((prev, at)) = self.net_prev.get(pid) {
                let elapsed = now.duration_since(*at).as_secs_f64();
                if elapsed > 0.0 {
                    let rate = cur.saturating_sub(*prev) as f64 / elapsed;
                    self.net_rate.insert(*pid, rate);
                }
            }
            self.net_prev.insert(*pid, (*cur, now));
        }
        let seen: std::collections::HashSet<Pid> = per_pid.keys().copied().collect();
        self.net_prev.retain(|pid, _| seen.contains(pid));
        self.net_rate.retain(|pid, _| seen.contains(pid));
    }

    /// The pid's network throughput in bytes/s (sent + received) from the
    /// last two `ss` sweeps. `None` before the second sweep or off the
    /// platforms that can't measure it.
    pub fn net_rate_of(&self, pid: Pid) -> Option<f64> {
        self.net_rate.get(&pid).copied()
    }

    /// Self-baseline deviation — the "--alert-deviation" check. A process
    /// whose instantaneous CPU has left its own trailing median (over the
    /// [`DEV_SAMPLES`] window) by `factor`, and cleared the absolute
    /// [`DEV_FLOOR_PCT`] floor, reads as "changed character": the quiet
    /// daemon suddenly busy, no per-process threshold having to exist.
    /// The floor keeps 0.1%→1% noise from ever counting, and the median
    /// can't be dragged by the burst itself until half the window turns
    /// over. `None` while the history is still short or the reading is
    /// unremarkable.
    pub fn deviation_of(&self, pid: Pid, factor: f64) -> Option<String> {
        let cur = *self.cpu_now.get(&pid)?;
        if cur < DEV_FLOOR_PCT {
            return None;
        }
        let dq = self.dev_samples.get(&pid)?;
        if dq.len() < DEV_MIN_SAMPLES {
            return None;
        }
        let mut vals: Vec<f64> = dq.iter().copied().collect();
        vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = vals[vals.len() / 2];
        if median <= 0.0 || cur < factor * median {
            return None;
        }
        Some(format!(
            "cpu {cur:.1}% is {:.0}× its own {median:.1}% baseline — sustained change of character",
            cur / median
        ))
    }

    /// Block-char CPU chart over the long sample window, normalized to the
    /// window max and thinned to `width` columns, plus the peak. None until
    /// a couple of samples exist.
    pub fn cpu_chart(&self, pid: Pid, width: usize) -> Option<String> {
        let dq = self.big.get(&pid)?;
        if dq.len() < 2 {
            return None;
        }
        let vals: Vec<f64> = if dq.len() > width {
            let stride = dq.len() as f64 / width as f64;
            (0..width)
                .map(|i| dq[(i as f64 * stride) as usize])
                .collect()
        } else {
            dq.iter().copied().collect()
        };
        let peak = vals.iter().copied().fold(0.0f64, f64::max);
        let bars: String = vals
            .iter()
            .map(|v| {
                let idx = ((v / peak.max(1.0)).clamp(0.0, 0.999) * 8.0) as usize;
                SPARK_LEVELS[idx]
            })
            .collect();
        Some(format!("{bars}  peak {peak:.0}%"))
    }

    /// The session digest for the TUI summary page ('S'): windowed
    /// activity from the event ring plus the CPU-spike / memory-climber
    /// boards from the sample buffers. Only processes alive at the last
    /// refresh have samples (dead pids are pruned), so a spike-then-exit
    /// shows up in the counts, not on the boards.
    pub fn summary(&self, since_secs: u64) -> SessionSummary {
        let cutoff = cutoff_for(crate::util::now_unix(), since_secs);
        let (started, exited, restarted, chains) = activity_from_events(&self.events, cutoff);

        let mut spikes: Vec<SpikeRow> = self
            .big
            .iter()
            .filter_map(|(pid, dq)| {
                let peak = dq.iter().copied().fold(0.0f64, f64::max);
                (peak > 0.0).then(|| SpikeRow {
                    pid: *pid,
                    name: self.prev_seen.get(pid).cloned().unwrap_or_else(|| "?".into()),
                    peak,
                })
            })
            .collect();
        spikes.sort_by(|a, b| b.peak.total_cmp(&a.peak));
        spikes.truncate(SUMMARY_CAP);

        let mut climbers: Vec<ClimbRow> = self
            .mem_big
            .iter()
            .filter_map(|(pid, dq)| {
                let first = dq.front().copied()? as f64;
                let last = dq.back().copied()? as f64;
                let grew_mb = (last - first) / 1024.0;
                (grew_mb > 0.5).then(|| ClimbRow {
                    pid: *pid,
                    name: self.prev_seen.get(pid).cloned().unwrap_or_else(|| "?".into()),
                    grew_mb,
                })
            })
            .collect();
        climbers.sort_by(|a, b| b.grew_mb.total_cmp(&a.grew_mb));
        climbers.truncate(SUMMARY_CAP);

        SessionSummary {
            since_secs,
            started,
            exited,
            restarted,
            chains,
            spikes,
            climbers,
        }
    }

    /// Block-char RSS chart over the long window, normalized to the window
    /// peak and thinned to `width` columns. Unlike the CPU chart this is an
    /// absolute scale (the peak is reported in MB) — a flat line at 2 GB is
    /// the interesting case, not a boring one. None until two samples exist.
    pub fn mem_chart(&self, pid: Pid, width: usize) -> Option<String> {
        let dq = self.mem_big.get(&pid)?;
        if dq.len() < 2 {
            return None;
        }
        let vals: Vec<f64> = if dq.len() > width {
            let stride = dq.len() as f64 / width as f64;
            (0..width)
                .map(|i| dq[(i as f64 * stride) as usize] as f64)
                .collect()
        } else {
            dq.iter().copied().map(|kb| kb as f64).collect()
        };
        let peak = vals.iter().copied().fold(0.0f64, f64::max);
        let bars: String = vals
            .iter()
            .map(|v| {
                let idx = ((v / peak.max(1.0)).clamp(0.0, 0.999) * 8.0) as usize;
                SPARK_LEVELS[idx]
            })
            .collect();
        Some(format!("{bars}  peak {:.1} MB", peak / 1024.0))
    }

    /// Record a whole-machine sample (system page 'y'), oldest at the
    /// back, capped like the per-process charts.
    pub fn update_system(&mut self, s: crate::platform::SystemStats) {
        self.sys.push_back(SystemSample {
            at_unix: crate::util::now_unix(),
            cpu: s.cpu_percent,
            mem_used_mb: s.mem_used_mb,
            swap_used_mb: s.swap_used_mb,
            load1: s.load1,
        });
        while self.sys.len() > BIG_SAMPLES {
            self.sys.pop_front();
        }
    }

    /// The freshest system sample (page header's "now" values).
    pub fn sys_latest(&self) -> Option<&SystemSample> {
        self.sys.back()
    }

    /// System CPU chart on a fixed 0–100 scale (the max is known, unlike
    /// the per-process charts) plus (current, peak). None until two
    /// samples exist.
    pub fn sys_cpu_chart(&self, width: usize) -> Option<(String, f64, f64)> {
        let vals: Vec<f64> = self
            .sys
            .iter()
            .filter_map(|s| s.cpu)
            .collect();
        if vals.len() < 2 {
            return None;
        }
        let thinned: Vec<f64> = if vals.len() > width {
            let stride = vals.len() as f64 / width as f64;
            (0..width)
                .map(|i| vals[(i as f64 * stride) as usize])
                .collect()
        } else {
            vals
        };
        let peak = thinned.iter().copied().fold(0.0f64, f64::max);
        let bars: String = thinned
            .iter()
            .map(|v| {
                let idx = ((v / 100.0).clamp(0.0, 0.999) * 8.0) as usize;
                SPARK_LEVELS[idx]
            })
            .collect();
        let now = self.sys_latest().and_then(|s| s.cpu).unwrap_or(0.0);
        Some((bars, now, peak))
    }

    /// System memory chart, absolute scale like the per-process mem chart
    /// (peak annotated in GB/MB), plus (used, peak) MB. None until two
    /// samples exist.
    pub fn sys_mem_chart(&self, width: usize) -> Option<(String, f64, f64)> {
        let vals: Vec<f64> = self
            .sys
            .iter()
            .filter_map(|s| s.mem_used_mb)
            .map(|mb| mb as f64)
            .collect();
        if vals.len() < 2 {
            return None;
        }
        let thinned: Vec<f64> = if vals.len() > width {
            let stride = vals.len() as f64 / width as f64;
            (0..width)
                .map(|i| vals[(i as f64 * stride) as usize])
                .collect()
        } else {
            vals
        };
        let peak = thinned.iter().copied().fold(0.0f64, f64::max);
        let bars: String = thinned
            .iter()
            .map(|v| {
                let idx = ((v / peak.max(1.0)).clamp(0.0, 0.999) * 8.0) as usize;
                SPARK_LEVELS[idx]
            })
            .collect();
        let now = self
            .sys_latest()
            .and_then(|s| s.mem_used_mb)
            .unwrap_or(0) as f64;
        Some((bars, now, peak))
    }

    /// Leak suspicion over the trailing [`LEAK_SAMPLES`] RSS samples: grew
    /// by at least [`LEAK_MB`] while rising at least [`LEAK_FRACTION`] of
    /// the time. `sample_secs` is the per-refresh interval, used only to
    /// phrase the elapsed time. Returns a human summary, None otherwise.
    pub fn leak_suspicion(&self, pid: Pid, sample_secs: f64) -> Option<String> {
        let dq = self.mem_big.get(&pid)?;
        let tail_len = dq.len().min(LEAK_SAMPLES);
        if tail_len < 8 {
            return None;
        }
        let start = dq.len() - tail_len;
        let tail: Vec<u64> = dq.iter().skip(start).copied().collect();
        let first = tail[0] as f64;
        let last = *tail.last().unwrap() as f64;
        let grew_mb = (last - first) / 1024.0;
        if grew_mb < LEAK_MB {
            return None;
        }
        let ups = tail.windows(2).filter(|w| w[1] > w[0]).count();
        let pairs = tail_len - 1;
        if (ups as f64 / pairs as f64) < LEAK_FRACTION {
            return None;
        }
        let mins = (pairs as f64 * sample_secs) / 60.0;
        Some(format!(
            "RSS +{grew_mb:.1} MB over the last {mins:.0} min, steadily increasing — possible leak"
        ))
    }

    /// Record one open-descriptor count for `pid` (selected detail page
    /// only). Feeds the fd sparkline and the fd leak suspicion window.
    pub fn record_fd(&mut self, pid: Pid, count: u64) {
        let dq = self.fd_big.entry(pid).or_default();
        dq.push_back(count);
        while dq.len() > BIG_SAMPLES {
            dq.pop_front();
        }
        let peak = dq.iter().copied().fold(0u64, u64::max).max(1) as f64;
        let tail_len = dq.len().min(SAMPLES);
        let start = dq.len() - tail_len;
        let spark: String = dq
            .iter()
            .skip(start)
            .map(|v| {
                let idx = ((*v as f64 / peak).clamp(0.0, 0.999) * 8.0) as usize;
                SPARK_LEVELS[idx]
            })
            .collect();
        self.fd_sparks.insert(pid, spark);
    }

    /// FD sparkline + latest count for the detail page, None until two
    /// samples exist.
    pub fn fd_chart(&self, pid: Pid, width: usize) -> Option<(String, u64)> {
        let dq = self.fd_big.get(&pid)?;
        let vals: Vec<u64> = dq.iter().copied().collect();
        if vals.len() < 2 {
            return None;
        }
        let last = *vals.last().unwrap();
        let thinned: Vec<u64> = if vals.len() > width {
            let stride = vals.len() as f64 / width as f64;
            (0..width)
                .map(|i| vals[(i as f64 * stride) as usize])
                .collect()
        } else {
            vals
        };
        let peak = thinned.iter().copied().fold(0u64, u64::max).max(1) as f64;
        let bars: String = thinned
            .iter()
            .map(|v| {
                let idx = ((*v as f64 / peak).clamp(0.0, 0.999) * 8.0) as usize;
                SPARK_LEVELS[idx]
            })
            .collect();
        Some((bars, last))
    }

    /// FD leak suspicion over the trailing [`FD_LEAK_SAMPLES`] samples:
    /// the count grew by at least [`FD_LEAK_GROWTH`] descriptors while
    /// rising at least [`FD_LEAK_FRACTION`] of the time — the signature of
    /// a socket/fd-per-request path that never closes them.
    pub fn fd_suspicion(&self, pid: Pid, sample_secs: f64) -> Option<String> {
        let dq = self.fd_big.get(&pid)?;
        let tail_len = dq.len().min(FD_LEAK_SAMPLES);
        if tail_len < 8 {
            return None;
        }
        let start = dq.len() - tail_len;
        let tail: Vec<u64> = dq.iter().skip(start).copied().collect();
        // saturating: a shrinking count is not a leak (and u64 would panic)
        let grew = tail.last().unwrap().saturating_sub(tail[0]) as f64;
        if grew < FD_LEAK_GROWTH {
            return None;
        }
        let ups = tail.windows(2).filter(|w| w[1] > w[0]).count();
        let pairs = tail_len - 1;
        if (ups as f64 / pairs as f64) < FD_LEAK_FRACTION {
            return None;
        }
        let mins = (pairs as f64 * sample_secs) / 60.0;
        Some(format!(
            "+{grew:.0} fds over the last {mins:.0} min, steadily increasing — possible fd leak"
        ))
    }

    /// Thread leak suspicion — the fd one applied to kernel thread counts
    /// (a service spawning threads per request without reaping them climbs
    /// steadily). Growth is in threads, so [`THR_LEAK_GROWTH`] is far
    /// smaller than the fd window.
    pub fn thread_suspicion(&self, pid: Pid, sample_secs: f64) -> Option<String> {
        let dq = self.thr_big.get(&pid)?;
        let tail_len = dq.len().min(THR_LEAK_SAMPLES);
        if tail_len < 8 {
            return None;
        }
        let start = dq.len() - tail_len;
        let tail: Vec<u32> = dq.iter().skip(start).copied().collect();
        let grew = tail.last().unwrap().saturating_sub(tail[0]) as f64;
        if grew < THR_LEAK_GROWTH {
            return None;
        }
        let ups = tail.windows(2).filter(|w| w[1] > w[0]).count();
        let pairs = tail_len - 1;
        if (ups as f64 / pairs as f64) < THR_LEAK_FRACTION {
            return None;
        }
        let mins = (pairs as f64 * sample_secs) / 60.0;
        Some(format!(
            "+{grew:.0} threads over the last {mins:.0} min, steadily increasing — possible thread leak"
        ))
    }

    /// Detail-page thread chart: a peak-normalized sparkline of the
    /// thread-count window plus the latest reading. None until two
    /// samples exist (or the platform never reported threads).
    pub fn thread_chart(&self, pid: Pid, width: usize) -> Option<(String, u32)> {
        let dq = self.thr_big.get(&pid)?;
        let vals: Vec<u32> = dq.iter().copied().collect();
        if vals.len() < 2 {
            return None;
        }
        let last = *vals.last().unwrap();
        let thinned: Vec<u32> = if vals.len() > width {
            let stride = vals.len() as f64 / width as f64;
            (0..width)
                .map(|i| vals[(i as f64 * stride) as usize])
                .collect()
        } else {
            vals
        };
        let peak = thinned.iter().copied().fold(0u32, u32::max).max(1) as f64;
        let bars: String = thinned
            .iter()
            .map(|v| {
                let idx = ((*v as f64 / peak).clamp(0.0, 0.999) * 8.0) as usize;
                SPARK_LEVELS[idx]
            })
            .collect();
        Some((bars, last))
    }

    /// Detail-page disk I/O chart: (read line, write line), each a
    /// peak-normalized sparkline with a human peak rate label. None until
    /// two samples exist.
    pub fn io_chart(&self, pid: Pid, width: usize) -> Option<(String, String)> {
        let dq = self.io_big.get(&pid)?;
        if dq.len() < 2 {
            return None;
        }
        let bars_for = |pick: fn(&(f64, f64)) -> f64| -> (String, f64) {
            let vals: Vec<f64> = if dq.len() > width {
                let stride = dq.len() as f64 / width as f64;
                (0..width)
                    .map(|i| pick(&dq[(i as f64 * stride) as usize]))
                    .collect()
            } else {
                dq.iter().map(pick).collect()
            };
            let peak = vals.iter().copied().fold(0.0f64, f64::max);
            let bars: String = vals
                .iter()
                .map(|v| {
                    let idx = ((v / peak.max(1.0)).clamp(0.0, 0.999) * 8.0) as usize;
                    SPARK_LEVELS[idx]
                })
                .collect();
            (bars, peak)
        };
        let (rb, rpeak) = bars_for(|s| s.0);
        let (wb, wpeak) = bars_for(|s| s.1);
        Some((
            format!("r {rb}  peak {}", crate::util::fmt_rate(rpeak)),
            format!("w {wb}  peak {}", crate::util::fmt_rate(wpeak)),
        ))
    }

    /// Record a threshold alert (kind "alert") or a recovery (kind
    /// "recovered" — a firing excursion dropped back under its limit) in
    /// the event ring (newest first, same cap) and return it so callers can
    /// persist it to `--events-log`. Alerts are sampler-generated — `update`
    /// never emits this kind itself.
    pub fn push_kind(&mut self, kind: &str, pid: Pid, name: &str, detail: &str) -> TuiEvent {
        let e = TuiEvent {
            at_unix: crate::util::now_unix(),
            kind: kind.to_string(),
            pid,
            name: name.to_string(),
            detail: detail.to_string(),
        };
        self.events.insert(0, e.clone());
        self.events.truncate(EVENT_CAP);
        e
    }

    /// Merge tail-replayed events (append-ordered, oldest first) into the
    /// ring, newest first — the `--replay FILE --follow` feed.
    pub fn ingest(&mut self, mut events: Vec<TuiEvent>) {
        events.reverse();
        for e in events {
            self.events.insert(0, e);
        }
        self.events.truncate(EVENT_CAP);
    }
}

/// Read a `--events-log` JSONL file back into a newest-first event ring
/// (the file is append-ordered, so replay reverses it). Unparseable lines
/// are skipped; a missing file surfaces as an error.
pub fn load_events_log(path: &str) -> std::io::Result<Vec<TuiEvent>> {
    let text = std::fs::read_to_string(path)?;
    let mut events: Vec<TuiEvent> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    events.reverse();
    Ok(events)
}

/// Tail a growing `--events-log` JSONL file — the live half of
/// `--replay FILE --follow`. `poll()` reads only the bytes appended since
/// the last call (the initial `load_events_log` already replayed history,
/// so the tail starts at the file's current end), parses complete lines,
/// and returns them append-ordered. A torn final write waits for its
/// newline; a shrunk file (truncation/rotation) restarts from the top.
/// All errors are swallowed — a vanished or unreadable file just polls
/// empty, the same tolerance the recorder side has.
pub struct EventTail {
    path: String,
    offset: u64,
    pending: String,
}

impl EventTail {
    /// Start tailing at the file's current end.
    pub fn at_end(path: &str) -> std::io::Result<Self> {
        let offset = std::fs::metadata(path)?.len();
        Ok(Self {
            path: path.to_string(),
            offset,
            pending: String::new(),
        })
    }

    /// Events appended since the last poll, oldest first (the ring's
    /// insert-at-0 does the newest-first flip).
    pub fn poll(&mut self) -> Vec<TuiEvent> {
        let mut out = Vec::new();
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.len() < self.offset {
                // truncated or rotated: start over from the top
                self.offset = 0;
                self.pending.clear();
            }
            if let Ok(mut f) = std::fs::File::open(&self.path) {
                use std::io::{Read as _, Seek as _};
                if self.offset > 0
                    && f.seek(std::io::SeekFrom::Start(self.offset)).is_err()
                {
                    return out;
                }
                let mut bytes = Vec::new();
                if f.read_to_end(&mut bytes).is_ok() {
                    self.offset += bytes.len() as u64;
                    self.pending.push_str(&String::from_utf8_lossy(&bytes));
                    while let Some(pos) = self.pending.find('\n') {
                        let line: String = self.pending.drain(..=pos).collect();
                        let line = line.trim_end();
                        if let Ok(e) = serde_json::from_str::<TuiEvent>(line) {
                            out.push(e);
                        }
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: Pid, exe: &str, cpu_ms: Option<u64>) -> Process {
        Process {
            pid,
            name: "worker".into(),
            exe: Some(exe.into()),
            user: Some("u".into()),
            cpu_time_ms: cpu_ms,
            ..Default::default()
        }
    }

    #[test]
    fn alert_repeat_refires_on_interval_and_resets_under() {
        // feed `n` over-threshold samples, return the per-sample firings
        let run_over = |repeat: Option<u64>, n: usize, interval: u64,
                        streak: &mut u32, firing: &mut bool, fired: &mut u32| -> Vec<bool> {
            (0..n)
                .map(|_| {
                    alert_cycle_repeat(streak, firing, true, fired, repeat, interval)
                        == AlertEdge::Fire
                })
                .collect()
        };
        let count = |hits: &[bool]| hits.iter().filter(|h| **h).count();

        // no repeat configured: exactly one fire per excursion, however long
        // it stays over (arming takes ALERT_CYCLES samples)
        let n = ALERT_CYCLES as usize;
        let mut streak = 0u32;
        let mut firing = false;
        let mut fired = 0u32;
        let hits = run_over(None, n * 2, 5, &mut streak, &mut firing, &mut fired);
        assert_eq!(count(&hits), 1);
        assert!(hits[n - 1], "fires exactly when the streak completes");

        // repeat every 10s at a 5s sample interval: the first fire, then a
        // re-fire every second sample (samples 7 and 9)
        let mut streak = 0u32;
        let mut firing = false;
        let mut fired = 0u32;
        let hits = run_over(Some(10), n + 4, 5, &mut streak, &mut firing, &mut fired);
        assert_eq!(count(&hits), 3);
        assert!(hits[n - 1] && hits[6] && hits[8]);

        // dropping back under resets the repeat clock — and reads as a
        // recovery — then the next excursion fires on its own ALERT_CYCLES
        // cadence and repeats again
        assert_eq!(
            alert_cycle_repeat(&mut streak, &mut firing, false, &mut fired, Some(10), 5),
            AlertEdge::Recover
        );
        assert_eq!(fired, 0);
        let hits = run_over(Some(10), n + 2, 5, &mut streak, &mut firing, &mut fired);
        assert_eq!(count(&hits), 2);
    }

    #[test]
    fn alert_recovery_fires_once_when_a_firing_excursion_drops_under() {
        fn step(over: bool, streak: &mut u32, firing: &mut bool, fired: &mut u32) -> AlertEdge {
            alert_cycle_repeat(streak, firing, over, fired, None, 3)
        }
        let mut streak = 0;
        let mut firing = false;
        let mut fired = 0u32;
        // arming samples stay quiet until the streak completes, which fires
        for _ in 1..ALERT_CYCLES {
            assert_eq!(step(true, &mut streak, &mut firing, &mut fired), AlertEdge::None);
        }
        assert_eq!(step(true, &mut streak, &mut firing, &mut fired), AlertEdge::Fire);
        // the first under sample re-arms and reports recovery exactly once
        assert_eq!(step(false, &mut streak, &mut firing, &mut fired), AlertEdge::Recover);
        assert_eq!(step(false, &mut streak, &mut firing, &mut fired), AlertEdge::None);
        assert!(!firing);
        assert_eq!(streak, 0);
        // an excursion that never reached the firing threshold has no
        // recovery to report
        for _ in 1..ALERT_CYCLES {
            step(true, &mut streak, &mut firing, &mut fired);
        }
        assert_eq!(step(false, &mut streak, &mut firing, &mut fired), AlertEdge::None);
        // the raw cycle primitive behaves the same way
        let mut s = 0;
        let mut f = false;
        assert_eq!(alert_cycle(&mut s, &mut f, false), AlertEdge::None);
        for _ in 0..ALERT_CYCLES {
            alert_cycle(&mut s, &mut f, true);
        }
        assert_eq!(alert_cycle(&mut s, &mut f, true), AlertEdge::None);
        assert_eq!(alert_cycle(&mut s, &mut f, false), AlertEdge::Recover);
        assert_eq!(alert_cycle(&mut s, &mut f, false), AlertEdge::None);
    }

    #[test]
    fn system_alerts_fire_on_load_and_ram_percent() {
        let stats = |load1: Option<f64>, used: Option<u64>, total: Option<u64>| {
            crate::platform::SystemStats {
                load1,
                mem_used_mb: used,
                mem_total_mb: total,
                ..Default::default()
            }
        };
        let mut state = SysAlertState::default();
        // nothing armed → no output even over the line
        let s = stats(Some(20.0), Some(9900), Some(10_000));
        let limits = |load, mem_pct, count, proc_count| SysAlertLimits {
            load,
            mem_pct,
            count,
            proc_count,
            mounts: Vec::new(),
            disk_pct: None,
            net_limit: None,
            net_rate: None,
            psi_limit: None,
            mem_avail_floor: None,
            swap_pct_limit: None,
            retrans_limit: None,
            retrans_rate: None,
            drop_limit: None,
            drop_rate: None,
            repeat: None,
        };
        assert!(
            system_alert_picks(&s, &mut state, &limits(None, None, None, 0), 3).is_empty()
        );

        // load over the line: quiet until ALERT_CYCLES completes, then one
        // fire naming the value and the sustained window
        let mut fires = Vec::new();
        for _ in 0..ALERT_CYCLES {
            fires = system_alert_picks(&s, &mut state, &limits(Some(8.0), None, None, 0), 3);
        }
        assert_eq!(fires.len(), 1);
        assert_eq!(fires[0].0, "system");
        assert!(fires[0].1.contains("load average 20.00 above 8"), "{}", fires[0].1);

        // RAM percent: 9900/10000 = 99% over 90 → fires after the cycle
        let mut state = SysAlertState::default();
        let mut fired = false;
        for _ in 0..ALERT_CYCLES {
            fired |= !system_alert_picks(&s, &mut state, &limits(None, Some(90), None, 0), 3)
                .is_empty();
        }
        assert!(fired, "99% over 90 fires");
        // total unknown → no measurement, no fire
        let mut state = SysAlertState::default();
        let s2 = stats(None, Some(9900), None);
        for _ in 0..ALERT_CYCLES {
            assert!(
                system_alert_picks(&s2, &mut state, &limits(None, Some(90), None, 0), 3)
                    .is_empty()
            );
        }
    }

    #[test]
    fn system_alerts_fire_on_memory_floor_and_swap() {
        let stats = crate::platform::SystemStats {
            mem_avail_mb: Some(120),
            mem_used_mb: Some(9880),
            mem_total_mb: Some(10_000),
            swap_used_mb: Some(850),
            swap_total_mb: Some(1024),
            ..Default::default()
        };
        let limits = |avail: Option<u64>, swap: Option<u64>| SysAlertLimits {
            load: None,
            mem_pct: None,
            count: None,
            proc_count: 0,
            mounts: Vec::new(),
            disk_pct: None,
            net_limit: None,
            net_rate: None,
            psi_limit: None,
            mem_avail_floor: avail,
            swap_pct_limit: swap,
            retrans_limit: None,
            retrans_rate: None,
            drop_limit: None,
            drop_rate: None,
            repeat: None,
        };
        // 120 MB avail above the 100 MB floor → never fires
        let mut state = SysAlertState::default();
        for _ in 0..ALERT_CYCLES + 2 {
            assert!(
                system_alert_picks(&stats, &mut state, &limits(Some(100), None), 3).is_empty()
            );
        }
        // drop the floor to 200: quiet through the cycle, then one fire
        // naming the reading and the window
        let mut state = SysAlertState::default();
        for _ in 0..ALERT_CYCLES - 1 {
            assert!(
                system_alert_picks(&stats, &mut state, &limits(Some(200), None), 3).is_empty()
            );
        }
        let fires = system_alert_picks(&stats, &mut state, &limits(Some(200), None), 3);
        assert_eq!(fires.len(), 1);
        assert!(fires[0].1.contains("MemAvailable 120 MB below 200 MB floor"), "{}", fires[0].1);
        assert!(!fires[0].2, "not a recovery");
        // recovery fires once the avail climbs back above the floor
        let ok = crate::platform::SystemStats {
            mem_avail_mb: Some(900),
            ..stats.clone()
        };
        let rec = system_alert_picks(&ok, &mut state, &limits(Some(200), None), 3);
        assert_eq!(rec.len(), 1);
        assert!(rec[0].2, "recovery");
        assert!(rec[0].1.contains("back above 200 MB"));

        // swap: 850/1024 = 82% over 80 → fires after the cycle
        let mut state = SysAlertState::default();
        for _ in 0..ALERT_CYCLES - 1 {
            assert!(
                system_alert_picks(&stats, &mut state, &limits(None, Some(80)), 3).is_empty()
            );
        }
        let fires = system_alert_picks(&stats, &mut state, &limits(None, Some(80)), 3);
        assert_eq!(fires.len(), 1);
        assert!(fires[0].1.contains("swap 83% above 80%"), "{}", fires[0].1);
        // no swap → disarmed even with the limit set
        let noswap = crate::platform::SystemStats {
            swap_used_mb: None,
            swap_total_mb: None,
            ..stats.clone()
        };
        let mut state = SysAlertState::default();
        for _ in 0..ALERT_CYCLES + 2 {
            assert!(
                system_alert_picks(&noswap, &mut state, &limits(None, Some(80)), 3).is_empty()
            );
        }
    }

    #[test]
    fn system_alerts_fire_on_retrans_and_drop_rates() {
        let stats = crate::platform::SystemStats {
            retrans_segs: Some(9999),
            ..Default::default()
        };
        let limits = |retrans: Option<u64>, retrans_rate: Option<f64>, drop: Option<u64>, drop_rate: Option<f64>| SysAlertLimits {
            load: None,
            mem_pct: None,
            count: None,
            proc_count: 0,
            mounts: Vec::new(),
            disk_pct: None,
            net_limit: None,
            net_rate: None,
            psi_limit: None,
            mem_avail_floor: None,
            swap_pct_limit: None,
            retrans_limit: retrans.map(|v| v as f64),
            retrans_rate,
            drop_limit: drop.map(|v| v as f64),
            drop_rate,
            repeat: None,
        };
        // no rate yet (first sample disarms) — even over the line
        let mut state = SysAlertState::default();
        for _ in 0..ALERT_CYCLES + 2 {
            assert!(
                system_alert_picks(&stats, &mut state, &limits(Some(50), None, Some(10), None), 3)
                    .is_empty()
            );
        }
        // retrans 80/s over 50: fires after the cycle
        let mut state = SysAlertState::default();
        for _ in 0..ALERT_CYCLES - 1 {
            assert!(
                system_alert_picks(&stats, &mut state, &limits(Some(50), Some(80.0), None, None), 3)
                    .is_empty()
            );
        }
        let fires = system_alert_picks(&stats, &mut state, &limits(Some(50), Some(80.0), None, None), 3);
        assert_eq!(fires.len(), 1);
        assert!(fires[0].1.contains("TCP retransmits 80/s above 50/s"), "{}", fires[0].1);
        let rec = system_alert_picks(&stats, &mut state, &limits(Some(50), Some(5.0), None, None), 3);
        assert_eq!(rec.len(), 1);
        assert!(rec[0].2 && rec[0].1.contains("retransmits back under 50/s"));

        // drops 4/s over 2: same machinery
        let mut state = SysAlertState::default();
        for _ in 0..ALERT_CYCLES - 1 {
            assert!(
                system_alert_picks(&stats, &mut state, &limits(None, None, Some(2), Some(4.0)), 3)
                    .is_empty()
            );
        }
        let fires = system_alert_picks(&stats, &mut state, &limits(None, None, Some(2), Some(4.0)), 3);
        assert_eq!(fires.len(), 1);
        assert!(fires[0].1.contains("NIC drops 4/s above 2/s"), "{}", fires[0].1);
    }

    #[test]
    fn deviation_flags_a_changed_character() {
        let mut h = History::new();
        let base = proc(10, "/bin/quiet", None);
        // deltas ride ~60ms-apart updates — the <50ms guard keeps
        // back-to-back updates from inventing rates, so 1ms per tick
        // reads as ~1.7%
        let mut cpu = 0u64;
        for _ in 0..14 {
            std::thread::sleep(Duration::from_millis(60));
            cpu += 1;
            let mut p = base.clone();
            p.cpu_time_ms = Some(cpu);
            h.update(&[p]);
        }
        // a ~3% blip: above the baseline but under the 5% floor — noise
        std::thread::sleep(Duration::from_millis(60));
        cpu += 2;
        let mut p = base.clone();
        p.cpu_time_ms = Some(cpu);
        h.update(&[p]);
        assert!(
            h.deviation_of(10, 5.0).is_none(),
            "floor gates sub-5% readings: {:?}",
            h.cpu_now.get(&10)
        );
        // ~67% sustained (40ms more over one tick): far over both the
        // 5% floor and 5× the ~1.7% median
        std::thread::sleep(Duration::from_millis(60));
        cpu += 40;
        let mut p = base.clone();
        p.cpu_time_ms = Some(cpu);
        h.update(&[p]);
        let msg = h.deviation_of(10, 5.0).unwrap();
        assert!(msg.contains("× its own"), "{msg}");
        assert!(msg.contains("sustained change of character"));
        // a short history hasn't earned a baseline yet
        let mut h2 = History::new();
        let mut cpu = 0u64;
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(60));
            cpu += 1;
            let mut p = base.clone();
            p.cpu_time_ms = Some(cpu);
            h2.update(&[p]);
        }
        std::thread::sleep(Duration::from_millis(60));
        cpu += 40;
        let mut p = base.clone();
        p.cpu_time_ms = Some(cpu);
        h2.update(&[p]);
        assert!(h2.deviation_of(10, 5.0).is_none(), "5 samples is not a baseline");
    }

    #[test]
    fn net_rate_diffs_ss_sweeps() {
        use std::collections::HashMap;
        let mut h = History::new();
        // first sweep arms the baseline — no rates yet
        let mut sweep: HashMap<Pid, u64> = [(1, 10_000), (2, 5_000)].into_iter().collect();
        h.update_net(&sweep);
        assert!(h.net_rate_of(1).is_none());
        // 50 KB arriving between sweeps → a real combined rate
        std::thread::sleep(std::time::Duration::from_millis(60));
        sweep.insert(1, 60_000);
        h.update_net(&sweep);
        let rate = h.net_rate_of(1).unwrap();
        assert!((rate - 50_000.0 / 0.06).abs() < 20_000.0, "~830KB/s: {rate}");
        // pid 2 sent nothing → 0 B/s is still a reading
        assert_eq!(h.net_rate_of(2), Some(0.0));
        // a pid missing from the sweep leaves the window (sockets closed)
        sweep.remove(&2);
        h.update_net(&sweep);
        assert!(h.net_rate_of(2).is_none());
        // a counter reset (process restart reusing the pid) is not a spike
        std::thread::sleep(std::time::Duration::from_millis(60));
        sweep.insert(1, 10);
        h.update_net(&sweep);
        assert_eq!(h.net_rate_of(1), Some(0.0), "reset → no spike");
    }

    #[test]
    fn retrans_and_drop_rate_differs_accumulate_counters() {
        // first sample arms only; a counter reset counts as zero delta
        let mut state = SysAlertState::default();
        assert_eq!(machine_retrans_rate(1000, &mut state), None);
        state.retrans_prev_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(10));
        let rate = machine_retrans_rate(6000, &mut state).unwrap();
        assert!((rate - 500.0).abs() < 1.0, "5000 segs / ~10s: {rate}");
        state.retrans_prev_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(10));
        assert_eq!(machine_retrans_rate(400, &mut state), Some(0.0), "reset → no spike");

        let mut state = SysAlertState::default();
        assert_eq!(machine_drop_rate(10, &mut state), None);
        state.drop_prev_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(5));
        let rate = machine_drop_rate(60, &mut state).unwrap();
        assert!((rate - 10.0).abs() < 1.0, "50 drops / ~5s: {rate}");
    }

    #[test]
    fn system_alert_fires_on_process_count() {
        let s = crate::platform::SystemStats::default();
        let mut state = SysAlertState::default();
        let limits = |count, proc_count| SysAlertLimits {
            load: None,
            mem_pct: None,
            count,
            proc_count,
            mounts: Vec::new(),
            disk_pct: None,
            net_limit: None,
            net_rate: None,
            psi_limit: None,
            mem_avail_floor: None,
            swap_pct_limit: None,
            retrans_limit: None,
            retrans_rate: None,
            drop_limit: None,
            drop_rate: None,
            repeat: None,
        };
        // 5 visible, limit 10 → under, never fires
        for _ in 0..ALERT_CYCLES + 2 {
            assert!(system_alert_picks(&s, &mut state, &limits(Some(10), 5), 3).is_empty());
        }
        // climb to 12: quiet until the cycle completes, then one fire naming
        // the count and the sustained window
        let mut fires = Vec::new();
        for _ in 0..ALERT_CYCLES {
            fires = system_alert_picks(&s, &mut state, &limits(Some(10), 12), 3);
        }
        assert_eq!(fires.len(), 1);
        assert!(fires[0].1.contains("12 visible processes above 10"), "{}", fires[0].1);
        // latched: still over → no repeat without --alert-repeat
        assert!(system_alert_picks(&s, &mut state, &limits(Some(10), 12), 3).is_empty());
        // dropping back under re-arms
        for _ in 0..ALERT_CYCLES {
            system_alert_picks(&s, &mut state, &limits(Some(10), 5), 3);
        }
    }

    #[test]
    fn system_alert_fires_on_full_disk_and_names_the_worst_mount() {
        let s = crate::platform::SystemStats::default();
        let mount = |target: &str, used: u64, total: u64| crate::platform::MountUsage {
            target: target.into(),
            total_mb: total,
            used_mb: used,
        };
        let limits = |disk_pct: Option<u64>, mounts: Vec<crate::platform::MountUsage>| {
            SysAlertLimits {
                load: None,
                mem_pct: None,
                count: None,
                proc_count: 0,
                mounts,
                disk_pct,
                net_limit: None,
                net_rate: None,
                psi_limit: None,
                mem_avail_floor: None,
                swap_pct_limit: None,
                retrans_limit: None,
                retrans_rate: None,
                drop_limit: None,
                drop_rate: None,
                repeat: None,
            }
        };
        // no mount sweeps in (never fetched) → nothing to compare, no fire
        let mut state = SysAlertState::default();
        for _ in 0..ALERT_CYCLES + 2 {
            assert!(system_alert_picks(&s, &mut state, &limits(Some(90), Vec::new()), 3).is_empty());
        }
        // 80% used, limit 90 → under, never fires
        let mut state = SysAlertState::default();
        let under = vec![mount("/", 800, 1000)];
        for _ in 0..ALERT_CYCLES + 2 {
            assert!(
                system_alert_picks(&s, &mut state, &limits(Some(90), under.clone()), 3).is_empty()
            );
        }
        // two mounts over the line: fires after the cycle, worst first,
        // both named
        let over = vec![mount("/", 950, 1000), mount("/data", 990, 1000)];
        let mut fires = Vec::new();
        for _ in 0..ALERT_CYCLES {
            fires = system_alert_picks(&s, &mut state, &limits(Some(90), over.clone()), 3);
        }
        assert_eq!(fires.len(), 1);
        assert_eq!(fires[0].0, "system");
        assert!(
            fires[0].1.contains("disk /data 99%, / 95% above 90%"),
            "{}",
            fires[0].1
        );
        // latched: no repeat without --alert-repeat
        assert!(system_alert_picks(&s, &mut state, &limits(Some(90), over), 3).is_empty());
    }

    #[test]
    fn net_rate_diffs_counters_and_alert_fires_over_the_line() {
        // machine_net_rate: None on the first sample, MB/s after
        let mut state = SysAlertState::default();
        assert_eq!(machine_net_rate((1000, 1000), &mut state), None);
        // a counter reset (total shrinks) diffs as zero, not negative
        assert_eq!(machine_net_rate((0, 0), &mut state), Some(0.0));

        let s = crate::platform::SystemStats::default();
        let limits = |net_limit: Option<u64>, net_rate: Option<f64>, psi_limit: Option<f64>| SysAlertLimits {
            load: None,
            mem_pct: None,
            count: None,
            proc_count: 0,
            mounts: Vec::new(),
            disk_pct: None,
            net_limit,
            net_rate,
            psi_limit,
            mem_avail_floor: None,
            swap_pct_limit: None,
            retrans_limit: None,
            retrans_rate: None,
            drop_limit: None,
            drop_rate: None,
            repeat: None,
        };
        // first tick has no rate (None disarms) — even over the line
        let mut state = SysAlertState::default();
        for _ in 0..ALERT_CYCLES + 2 {
            assert!(
                system_alert_picks(&s, &mut state, &limits(Some(10), None, None), 3).is_empty(),
                "no measurement → no fire"
            );
        }
        // 50 MB/s sustained over a 40 MB/s line: quiet for the arming
        // samples, then one fire naming the rate and window
        let mut fires = Vec::new();
        for _ in 0..ALERT_CYCLES {
            fires = system_alert_picks(&s, &mut state, &limits(Some(40), Some(50.0), None), 3);
        }
        assert_eq!(fires.len(), 1);
        assert_eq!(fires[0].0, "system");
        assert!(fires[0].1.contains("net 50.0 MB/s above 40"), "{}", fires[0].1);
        // latched; dropping back under reports one recovery, then re-arms
        assert!(system_alert_picks(&s, &mut state, &limits(Some(40), Some(50.0), None), 3).is_empty());
        let rec = system_alert_picks(&s, &mut state, &limits(Some(40), Some(5.0), None), 3);
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0], ("system".into(), "net back under 40 MB/s".into(), true));
        for _ in 0..ALERT_CYCLES {
            assert!(system_alert_picks(&s, &mut state, &limits(Some(40), Some(5.0), None), 3).is_empty());
        }
    }

    #[test]
    fn psi_full_stall_alert_fires_and_names_resources() {
        // mem full-stall over the line; cpu/io quiet
        let s = crate::platform::SystemStats {
            psi: Some(crate::platform::PsiStats {
                mem_full: 12.0,
                ..Default::default()
            }),
            ..Default::default()
        };
        let limits = |psi_limit: Option<f64>| SysAlertLimits {
            load: None,
            mem_pct: None,
            count: None,
            proc_count: 0,
            mounts: Vec::new(),
            disk_pct: None,
            net_limit: None,
            net_rate: None,
            psi_limit,
            mem_avail_floor: None,
            swap_pct_limit: None,
            retrans_limit: None,
            retrans_rate: None,
            drop_limit: None,
            drop_rate: None,
            repeat: None,
        };
        // no PSI report at all → silent even with the limit armed
        let none = crate::platform::SystemStats::default();
        let mut state = SysAlertState::default();
        for _ in 0..ALERT_CYCLES + 2 {
            assert!(
                system_alert_picks(&none, &mut state, &limits(Some(10.0)), 3).is_empty(),
                "no measurement → no fire"
            );
        }
        // 12% mem full over a 10% line: quiet for the arming samples, then
        // one fire naming the resource
        let mut fires = Vec::new();
        for _ in 0..ALERT_CYCLES {
            fires = system_alert_picks(&s, &mut state, &limits(Some(10.0)), 3);
        }
        assert_eq!(fires.len(), 1);
        assert_eq!(fires[0].0, "system");
        assert!(
            fires[0].1.contains("PSI full mem 12.0% above 10"),
            "{}",
            fires[0].1
        );
        // latched; repeat=None means one fire per excursion
        assert!(system_alert_picks(&s, &mut state, &limits(Some(10.0)), 3).is_empty());
    }

    #[test]
    fn event_tail_streams_new_lines_only() {
        let dir = std::env::temp_dir().join(format!("witr-tail-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let ev = |pid: Pid, kind: &str| TuiEvent {
            at_unix: 0,
            kind: kind.into(),
            pid,
            name: "worker".into(),
            detail: String::new(),
        };
        let line = |e: &TuiEvent| serde_json::to_string(e).unwrap();
        // two events recorded before the tail attaches
        std::fs::write(&path, format!("{}\n", line(&ev(1, "started")))).unwrap();
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(f, "{}", line(&ev(2, "started"))).unwrap();
        }
        let mut tail = EventTail::at_end(path.to_str().unwrap()).unwrap();
        // nothing new → empty poll
        assert!(tail.poll().is_empty());
        // appends stream in, oldest first; a torn final line waits
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(f, "{}", line(&ev(1, "exited"))).unwrap();
            write!(f, "{}", line(&ev(3, "started"))).unwrap(); // no newline yet
        }
        let got = tail.poll();
        assert_eq!(got.len(), 1, "torn line held back: {got:?}");
        assert_eq!((got[0].pid, got[0].kind.as_str()), (1, "exited"));
        // newline arrives → the held event completes
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(f).unwrap();
        }
        let got = tail.poll();
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].pid, got[0].kind.as_str()), (3, "started"));
        // truncation (rotation) restarts from the top, history re-streams
        std::fs::write(&path, format!("{}\n", line(&ev(9, "started")))).unwrap();
        let got = tail.poll();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].pid, 9);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_detection() {
        let mut h = History::new();
        h.update(&[proc(100, "/bin/worker", None)]);
        assert_eq!(h.total_restarts(100), 0);
        // same identity reappears as pid 200 → one restart
        h.update(&[proc(200, "/bin/worker", None)]);
        assert_eq!(h.total_restarts(200), 1);
        h.update(&[proc(300, "/bin/worker", None)]);
        assert_eq!(h.total_restarts(300), 2);
        assert_eq!(h.recent_restarts(300), Some(2));
        // a different process isn't affected
        h.update(&[proc(400, "/bin/other", None)]);
        assert_eq!(h.total_restarts(400), 0);
    }

    #[test]
    fn cpu_delta_sampling() {
        let mut h = History::new();
        h.update(&[proc(10, "/bin/w", Some(1_000))]);
        assert!(!h.cpu_now.contains_key(&10), "first sample has no delta");
        std::thread::sleep(Duration::from_millis(120));
        h.update(&[proc(10, "/bin/w", Some(1_120))]);
        // 120ms cpu in ~120ms wall → ~100%
        let v = h.cpu_now.get(&10).copied().unwrap_or(-1.0);
        assert!(v > 40.0, "expected high instantaneous cpu, got {v}");
        assert!(h.spark(10).is_some());
    }

    #[test]
    fn io_rate_sampling() {
        let mut h = History::new();
        let mut p = proc(10, "/bin/w", None);
        p.io_read_bytes = Some(1_000);
        p.io_write_bytes = Some(500);
        h.update(&[p.clone()]);
        assert!(h.io_rate_of(10).is_none(), "first sample has no delta");
        std::thread::sleep(Duration::from_millis(120));
        p.io_read_bytes = Some(13_000);
        p.io_write_bytes = Some(500);
        h.update(&[p]);
        // 12KB read in ~120ms → ~100KB/s read, 0 write
        let (r, w) = h.io_rate_of(10).unwrap_or((0.0, 0.0));
        assert!(r > 50_000.0, "expected ~100KB/s read, got {r}");
        assert_eq!(w, 0.0);
        // vanished → pruned
        h.update(&[]);
        assert!(h.io_rate_of(10).is_none());
    }

    #[test]
    fn cpu_chart_builds_and_thins() {
        let mut h = History::new();
        h.update(&[proc(10, "/bin/w", Some(0))]);
        assert!(h.cpu_chart(10, 80).is_none(), "needs 2+ samples");
        // the first delta lands on the second update, the chart (which
        // needs two deltas) on the third
        std::thread::sleep(Duration::from_millis(120));
        h.update(&[proc(10, "/bin/w", Some(1_000))]);
        assert!(h.cpu_chart(10, 80).is_none(), "one delta is not a chart");
        std::thread::sleep(Duration::from_millis(120));
        h.update(&[proc(10, "/bin/w", Some(2_000))]);
        // then a quiet sample: 1000/120 → ~400% (capped), then ~50%
        std::thread::sleep(Duration::from_millis(120));
        h.update(&[proc(10, "/bin/w", Some(2_060))]);
        let chart = h.cpu_chart(10, 80).unwrap();
        let bars = chart.split_whitespace().next().unwrap();
        let last = bars.chars().last().unwrap();
        assert!(
            "▁▂▃".contains(last),
            "quiet sample renders as a low bar: {chart}"
        );
        assert!(chart.contains("peak"), "chart carries the peak: {chart}");
        // thinning to a tiny window still works
        let small = h.cpu_chart(10, 4).unwrap();
        let bars = small.split_whitespace().next().unwrap();
        assert!(bars.chars().count() <= 4, "thinned to width 4: {small}");
    }

    #[test]
    fn mem_chart_and_leak_suspicion() {
        let mut h = History::new();
        let mut p = proc(10, "/bin/leaky", None);
        p.mem_kb = Some(100 * 1024);
        h.update(&[p.clone()]);
        assert!(h.mem_chart(10, 80).is_none(), "needs 2+ samples");
        // climb 10 MB per round: 100 → 130 MB
        for kb in [110u64, 120, 130] {
            p.mem_kb = Some(kb * 1024);
            h.update(&[p.clone()]);
        }
        let chart = h.mem_chart(10, 80).unwrap();
        assert!(chart.contains("peak 130.0 MB"), "absolute-scale peak: {chart}");
        let bars = chart.split_whitespace().next().unwrap();
        let last = bars.chars().last().unwrap();
        assert_eq!(last, '█', "monotonic climb ends at the top bar: {chart}");
        // thinning works like the CPU chart
        let thin = h.mem_chart(10, 2).unwrap();
        assert_eq!(thin.split_whitespace().next().unwrap().chars().count(), 2);

        // leak suspicion needs a window (8+ samples): climb on to 144 MB
        for kb in [132u64, 136, 140, 144] {
            p.mem_kb = Some(kb * 1024);
            h.update(&[p.clone()]);
        }
        let msg = h.leak_suspicion(10, 3.0).unwrap();
        assert!(msg.contains("+44.0 MB"), "summary carries the growth: {msg}");
        assert!(msg.contains("possible leak"));

        // below the MB threshold: quiet
        let mut h2 = History::new();
        for kb in [100u64, 105, 110] {
            let mut q = proc(10, "/bin/leaky", None);
            q.mem_kb = Some(kb * 1024);
            h2.update(&[q]);
        }
        assert!(h2.leak_suspicion(10, 3.0).is_none(), "+10 MB is not a leak");

        // big but oscillating: rises only half the time → not "steady"
        let mut h3 = History::new();
        for kb in [100u64, 120, 105, 125, 110, 130, 115, 135] {
            let mut q = proc(10, "/bin/leaky", None);
            q.mem_kb = Some(kb * 1024);
            h3.update(&[q]);
        }
        assert!(
            h3.leak_suspicion(10, 3.0).is_none(),
            "sawtooth growth is not flagged"
        );

        // a process that vanished leaves no data behind
        h3.update(&[]);
        assert!(h3.mem_chart(10, 80).is_none());
        assert!(h3.leak_suspicion(10, 3.0).is_none());
    }

    #[test]
    fn fd_chart_and_leak_suspicion() {
        let mut h = History::new();
        h.record_fd(10, 100);
        assert!(h.fd_chart(10, 80).is_none(), "needs 2+ samples");
        // steady climb, +2 fds per sample: the trailing 60-sample window
        // sees +120 — well past the 64-fd threshold
        for i in 0..70u64 {
            h.record_fd(10, 100 + i * 2);
        }
        let (bars, now) = h.fd_chart(10, 80).unwrap();
        assert_eq!(now, 238);
        assert_eq!(bars.chars().last().unwrap(), '█', "climb ends at the top bar");
        let thin = h.fd_chart(10, 2).unwrap().0;
        assert_eq!(thin.chars().count(), 2, "thinning caps the width");
        let msg = h.fd_suspicion(10, 3.0).unwrap();
        assert!(msg.contains("+118 fds"), "summary carries the growth: {msg}");
        assert!(msg.contains("possible fd leak"));

        // small growth stays quiet (32 fds < 64 threshold)
        let mut h2 = History::new();
        for i in 0..10u64 {
            h2.record_fd(10, 100 + i * 3);
        }
        assert!(h2.fd_suspicion(10, 3.0).is_none(), "+27 fds is not a leak");

        // big but sawtooth: every other step drops, so it is not "steadily
        // increasing" (grew +90 overall, rose only 4 of 9 steps)
        let mut h3 = History::new();
        for i in 0..10u64 {
            h3.record_fd(10, 100 + i * 10 + if i % 2 == 1 { 40 } else { 0 });
        }
        assert!(h3.fd_suspicion(10, 3.0).is_none(), "sawtooth is not flagged");

        // sparkline bookkeeping follows the pid
        assert!(h.fd_sparks.contains_key(&10));
        h.update(&[]);
        assert!(h.fd_chart(10, 80).is_none(), "vanished pid leaves no data");
        assert!(!h.fd_sparks.contains_key(&10));
    }

    #[test]
    fn thread_chart_and_leak_suspicion() {
        let mut h = History::new();
        let base = proc(10, "/bin/leaky", None);
        h.update(std::slice::from_ref(&base));
        assert!(h.thread_chart(10, 80).is_none(), "needs 2+ samples");
        // +1 thread per refresh: the 60-sample window sees +59 of the 70 —
        // past the 16-thread threshold, and the fd-style sawtooth checks below
        for i in 0..70u32 {
            let mut p = base.clone();
            p.threads = Some(8 + i);
            h.update(&[p]);
        }
        let (bars, now) = h.thread_chart(10, 80).unwrap();
        assert_eq!(now, 77);
        assert_eq!(bars.chars().last().unwrap(), '█', "climb ends at the top bar");
        let msg = h.thread_suspicion(10, 3.0).unwrap();
        assert!(msg.contains("+59 threads"), "growth in the message: {msg}");
        assert!(msg.contains("possible thread leak"));

        // small growth stays quiet (+7 < 16)
        let mut h2 = History::new();
        for i in 0..10u32 {
            let mut p = base.clone();
            p.threads = Some(8 + i);
            h2.update(&[p]);
        }
        assert!(h2.thread_suspicion(10, 3.0).is_none(), "+7 threads is not a leak");

        // shrinking counts never flag (and would u64-panic without the
        // saturating diff the fd chart shares)
        let mut h3 = History::new();
        for i in 0..10u32 {
            let mut p = base.clone();
            p.threads = Some(64 - i);
            h3.update(&[p]);
        }
        assert!(h3.thread_suspicion(10, 3.0).is_none(), "shrinking is not a leak");

        // a vanished pid leaves no data behind
        h3.update(&[]);
        assert!(h3.thread_chart(10, 80).is_none());
    }

    #[test]
    fn container_edges_fire_once_per_edge() {
        let mk = |id: &str, name: &str, state: &str, restarts: Option<u32>| crate::model::Container {
            runtime: "docker".into(),
            id: id.into(),
            name: name.into(),
            image: String::new(),
            command: String::new(),
            state: state.into(),
            status: "Up".into(),
            ports: String::new(),
            pod: None,
            restarts,
            cpu_pct: None,
            mem_used_mb: None,
            mem_total_mb: None,
    throttled_usec: None,
    oom_kills: None,
    compose: None,
    io_read_bytes: None,
    io_write_bytes: None,
        };
        let mut edges = ContainerEdges::default();
        // first sighting arms quietly
        assert!(edges.update(&[mk("a1", "web", "running", Some(0))], &[], false).is_empty());
        assert!(edges.tracks_container("docker/a1"));
        // restart climb fires once and latches
        let hits = edges.update(&[mk("a1", "web", "running", Some(3))], &[], false);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].1.contains("restart count 0 → 3"));
        assert!(edges.update(&[mk("a1", "web", "running", Some(3))], &[], false).is_empty());
        // death edge (inspect fetch hits no daemon for the fixture id)
        let hits = edges.update(&[mk("a1", "web", "exited", Some(3))], &[], false);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].0 == "container web" && hits[0].1.starts_with("exited — "));
        assert!(edges.update(&[mk("a1", "web", "exited", Some(3))], &[], false).is_empty());
        // removed containers leave the memory
        assert!(edges.update(&[], &[], false).is_empty());
        assert_eq!(edges.containers_tracked(), 0);

        // cgroup oom_kill climb fires once and latches (a restart policy
        // may hide the exit, memory.events still tells the truth)
        let mut edges = ContainerEdges::default();
        let oom = |n: u64| {
            let mut c = mk("d1", "worker", "running", Some(0));
            c.oom_kills = Some(n);
            c
        };
        assert!(edges.update(&[oom(0)], &[], false).is_empty(), "first sighting arms");
        let hits = edges.update(&[oom(2)], &[], false);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].1.contains("OOM kill count 0 → 2"));
        assert!(edges.update(&[oom(2)], &[], false).is_empty(), "latched");
        // a live events stream suppresses only deaths — the oom climb
        // still reports (the stream carries no such edge)
        let hits = edges.update(&[oom(4)], &[], true);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].1.contains("OOM kill count 2 → 4"));

        // a live events stream owns death reporting: the death edge stays
        // quiet but the state still records (the next death fires once the
        // stream is gone)
        let mut edges = ContainerEdges::default();
        assert!(edges.update(&[mk("b1", "db", "running", Some(0))], &[], true).is_empty());
        assert!(edges.update(&[mk("b1", "db", "exited", Some(0))], &[], true).is_empty(), "stream owns deaths");
        assert!(edges.update(&[mk("b1", "db", "exited", Some(0))], &[], false).is_empty(), "already-armed stays latched");
        let mut edges = ContainerEdges::default();
        assert!(edges.update(&[mk("c1", "api", "running", Some(0))], &[], true).is_empty());
        let hits = edges.update(&[mk("c1", "api", "exited", Some(0))], &[], false);
        assert_eq!(hits.len(), 1, "fallback sweeps still report: {hits:?}");

        // pod edges ride the same core
        let mkpod = |restarts: u32, phase: &str, waiting: Option<&str>| crate::k8s::Pod {
            key: "prod/web".into(),
            container_ids: Vec::new(),
            phase: Some(phase.into()),
            restarts,
            waiting: waiting.map(str::to_string),
        };
        let mut edges = ContainerEdges::default();
        assert!(edges.update(&[], &[mkpod(0, "Running", None)], false).is_empty());
        let hits = edges.update(&[], &[mkpod(2, "Running", Some("CrashLoopBackOff"))], false);
        assert!(hits[0].1.contains("containers waiting: CrashLoopBackOff (phase Running)"));
        // same reason latches; the restart climb fires independently
        let hits = edges.update(&[], &[mkpod(5, "Running", Some("CrashLoopBackOff"))], false);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].1.contains("restart count 2 → 5"));
        // Running → Pending, then Failed, each once
        let hits = edges.update(&[], &[mkpod(5, "Pending", None)], false);
        assert!(hits[0].1.contains("went Pending again"));
        let hits = edges.update(&[], &[mkpod(5, "Failed", None)], false);
        assert!(hits[0].1.contains("phase Failed"));
        assert!(edges.update(&[], &[mkpod(5, "Failed", None)], false).is_empty(), "Failed latches");
        assert!(edges.update(&[], &[], false).is_empty());
        assert_eq!(edges.pods_tracked(), 0);
    }

    #[test]
    fn io_chart_tracks_read_write_rates() {
        let mut h = History::new();
        // first sample seeds the baseline (no rate yet)
        let mut p = proc(10, "/bin/io", None);
        p.io_read_bytes = Some(1_000_000);
        p.io_write_bytes = Some(500_000);
        h.update(&[p.clone()]);
        assert!(h.io_chart(10, 80).is_none(), "needs 2+ samples");
        // each round accumulates 2 MB read / 1 MB write → 666K/s at 3s
        // (real sleeps: the rate needs ≥50 ms between samples)
        for i in 1..=4u64 {
            std::thread::sleep(std::time::Duration::from_millis(60));
            p.io_read_bytes = Some(1_000_000 + i * 2_000_000);
            p.io_write_bytes = Some(500_000 + i * 1_000_000);
            h.update(&[p.clone()]);
        }
        let (r, w) = h.io_chart(10, 80).unwrap();
        assert!(r.starts_with("r "), "{r}");
        assert!(w.starts_with("w "), "{w}");
        // 2 MB over a real ~60 ms gap lands in the M/s range; the write
        // line is half the read's magnitude
        assert!(r.contains("M/s"), "read peak rate humanized: {r}");
        assert!(w.contains("M/s"), "write peak rate humanized: {w}");
        assert_eq!(r.chars().count(), w.chars().count(), "aligned sparklines");
        // vanished pid leaves no data
        h.update(&[]);
        assert!(h.io_chart(10, 80).is_none());
    }

    #[test]
    fn system_ring_feeds_both_charts() {
        let mut h = History::new();
        let stats = |cpu: f64, mem: u64| crate::platform::SystemStats {
            cpu_percent: Some(cpu),
            mem_used_mb: Some(mem),
            ..Default::default()
        };
        // one sample: charts wait for a second
        h.update_system(stats(10.0, 1000));
        assert!(h.sys_cpu_chart(40).is_none());
        assert!(h.sys_mem_chart(40).is_none());
        h.update_system(stats(50.0, 2000));
        h.update_system(stats(90.0, 1500));
        let (bars, now, peak) = h.sys_cpu_chart(40).expect("cpu chart");
        assert_eq!(bars.chars().count(), 3, "unthinned below width: {bars}");
        assert_eq!(now, 90.0);
        assert_eq!(peak, 90.0, "fixed 0-100 scale, peak is the window max");
        assert!(bars.ends_with('█'), "90% renders near the top: {bars}");
        let (bars, used, peak) = h.sys_mem_chart(40).expect("mem chart");
        assert_eq!(bars.chars().count(), 3);
        assert_eq!(used, 1500.0);
        assert_eq!(peak, 2000.0);
        assert!(!bars.is_empty());
        // the ring caps like the per-process charts
        for i in 0..(BIG_SAMPLES as u64 + 10) {
            h.update_system(stats(i as f64, i));
        }
        assert_eq!(h.sys.len(), BIG_SAMPLES);
        assert_eq!(
            h.sys.front().map(|s| s.mem_used_mb),
            Some(Some(10)),
            "oldest samples dropped, not the newest"
        );
    }

    #[test]
    fn summary_boards_rank_spikes_and_climbers() {
        let mut h = History::new();
        h.update(&[proc(10, "/bin/busy", Some(0)), proc(20, "/bin/idle", Some(0))]);
        std::thread::sleep(Duration::from_millis(120));
        h.update(&[proc(10, "/bin/busy", Some(1_200)), proc(20, "/bin/idle", Some(10))]);
        // memory climber: +30 MB over three refreshes
        for kb in [100u64, 115, 130] {
            let mut p = proc(30, "/bin/leaky", None);
            p.mem_kb = Some(kb * 1024);
            h.update(&[proc(10, "/bin/busy", Some(1_200)), proc(20, "/bin/idle", Some(10)), p]);
        }
        let s = h.summary(u64::MAX);
        assert_eq!(s.since_secs, u64::MAX);
        assert!(
            s.spikes.first().is_some_and(|r| r.pid == 10 && r.peak > 40.0),
            "busy pid tops the spike board: {:?}",
            s.spikes
        );
        assert!(
            s.climbers.first().is_some_and(|r| r.pid == 30 && r.grew_mb > 25.0),
            "leaky pid tops the climber board: {:?}",
            s.climbers
        );
        // a flat or shrinking series makes no board
        assert!(s.climbers.iter().all(|r| r.pid != 20), "idle pid never climbs");
        // text form carries the boards (the proc helper names everything
        // "worker"; pids disambiguate)
        let text = s.to_text();
        assert!(text.contains("CPU spikes:"));
        assert!(text.contains("worker (pid 10)"));
        assert!(text.contains("memory climbers:"));
    }

    #[test]
    fn summary_counts_windowed_activity() {
        let mut h = History::new();
        h.update(&[proc(1, "/bin/worker", None)]);
        h.update(&[]);
        h.update(&[proc(2, "/bin/worker", None)]);
        h.update(&[proc(2, "/bin/worker", None), proc(9, "/bin/one-off", None)]);
        let s = h.summary(u64::MAX);
        assert_eq!((s.started, s.exited, s.restarted), (2, 1, 1));
        assert_eq!(s.chains, vec![ChainRow { name: "worker".into(), count: 1 }]);
        assert!(s.to_text().starts_with("Session summary (whole session): started 2"));
        // windowing math itself is pinned by summary_from_events (synthetic
        // timestamps); live events can't be backdated
    }

    #[test]
    fn restart_events_report_changed_argv_and_env() {
        let with_argv = |cmdline: &[&str], pid: Pid| {
            let mut p = proc(pid, "/bin/worker", None);
            p.cmdline = cmdline.iter().map(|s| s.to_string()).collect();
            p
        };
        // same identity across pids; argv unchanged → plain restart detail
        let mut h = History::new();
        h.update(&[with_argv(&["worker", "-q"], 1)]);
        h.update(&[]);
        h.update(&[with_argv(&["worker", "-q"], 2)]);
        let ev = h
            .events
            .iter()
            .find(|e| e.kind == "restarted")
            .expect("restart event");
        assert!(
            ev.detail.contains("(1 restarts total)") && !ev.detail.contains("argv"),
            "{}",
            ev.detail
        );

        // argv changed → the new command line rides the detail
        let mut h = History::new();
        h.update(&[with_argv(&["worker", "-q"], 1)]);
        h.update(&[]);
        h.update(&[with_argv(&["worker", "--daemon"], 2)]);
        let ev = h
            .events
            .iter()
            .find(|e| e.kind == "restarted")
            .expect("restart event");
        assert!(
            ev.detail.contains("argv changed to `worker --daemon`"),
            "{}",
            ev.detail
        );

        // env compared only when both sides sampled it
        let env_proc = |pid: Pid, flag: &str| {
            let mut p = proc(pid, "/bin/worker", None);
            p.env = Some(vec![("MODE".to_string(), flag.to_string())]);
            p
        };
        let mut h = History::new();
        h.update(&[env_proc(1, "a")]);
        h.update(&[]);
        h.update(&[env_proc(2, "b")]);
        let ev = h
            .events
            .iter()
            .find(|e| e.kind == "restarted")
            .expect("restart event");
        assert!(ev.detail.contains("env changed"), "{}", ev.detail);

        // one side unsampled → no env claim
        let mut h = History::new();
        h.update(&[proc(1, "/bin/worker", None)]);
        h.update(&[]);
        h.update(&[env_proc(2, "a")]);
        let ev = h
            .events
            .iter()
            .find(|e| e.kind == "restarted")
            .expect("restart event");
        assert!(!ev.detail.contains("env"), "{}", ev.detail);
    }

    #[test]
    fn summary_from_events_round_trips_text() {
        let now = crate::util::now_unix();
        let events = vec![
            TuiEvent { at_unix: now, kind: "restarted".into(), pid: 2, name: "worker".into(), detail: String::new() },
            TuiEvent { at_unix: now - 3600, kind: "exited".into(), pid: 1, name: "worker".into(), detail: String::new() },
            TuiEvent { at_unix: now - 7200, kind: "started".into(), pid: 1, name: "worker".into(), detail: String::new() },
        ];
        let s = summary_from_events(&events, 5 * 60);
        assert_eq!((s.started, s.exited, s.restarted), (0, 0, 1), "only in-window events count");
        assert_eq!(s.chains.len(), 1);
        assert!(s.spikes.is_empty() && s.climbers.is_empty(), "no samples in a file digest");
        let text = s.to_text();
        assert!(text.contains("last 5m"));
        assert!(text.contains("restart chains: worker ×1"));
    }

    #[test]
    fn brief_tracker_catches_spawn_and_die_between_polls() {
        let name_of = |pid: Pid| match pid {
            1 => Some("init".into()),
            42 => Some("worker.sh".into()),
            _ => None,
        };
        let mut t = BriefTracker::new();
        // first poll seeds; nothing has died yet
        assert!(t.poll(&[1, 42], &name_of).is_empty());
        // second poll: 42 is gone → one brief event with its name
        let events = t.poll(&[1], &name_of);
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.kind, "brief");
        assert_eq!(e.pid, 42);
        assert_eq!(e.name, "worker.sh");
        assert!(e.detail.contains("ms"), "{e:?}");
        // 1 survives every poll — never reported, and re-polls stay quiet
        assert!(t.poll(&[1], &name_of).is_empty());
        // unnamed pids get a pid-N fallback name
        let mut t = BriefTracker::new();
        t.poll(&[7], &name_of);
        let events = t.poll(&[], &name_of);
        assert_eq!(events[0].name, "pid 7");
    }

    #[test]
    fn container_event_lines_parse_to_death_oom_and_health_edges() {
        // modern docker die: Actor.Attributes carries name + exit code
        let e = parse_container_event_line(
            r#"{"status":"die","id":"abc","from":"nginx:1.25","Type":"container","Action":"die","Actor":{"ID":"abc","Attributes":{"exitCode":"137","name":"web","image":"nginx:1.25"}},"scope":"local","time":1700000000}"#,
        )
        .unwrap();
        assert_eq!(e.kind, "container-death");
        assert_eq!(e.name, "web");
        assert_eq!(e.detail, "exited (exit code 137)");
        assert_eq!(e.at_unix, 1700000000);
        // podman spells the exit "died" (no exit code attr → plain detail)
        let e = parse_container_event_line(
            r#"{"Status":"died","Type":"container","Actor":{"ID":"dd","Attributes":{"name":"db"}},"time":1700000001}"#,
        )
        .unwrap();
        assert_eq!(e.kind, "container-death");
        assert_eq!(e.name, "db");
        assert_eq!(e.detail, "exited");
        // oom is a death edge with its own wording
        let e = parse_container_event_line(
            r#"{"Type":"container","Action":"oom","Actor":{"Attributes":{"name":"hog"}},"time":1700000002}"#,
        )
        .unwrap();
        assert_eq!(e.kind, "container-death");
        assert!(e.detail.contains("OOM"), "{e:?}");
        // health flip only when unhealthy
        let e = parse_container_event_line(
            r#"{"Type":"container","Action":"health_status: unhealthy","Actor":{"Attributes":{"name":"api"}},"time":1700000003}"#,
        )
        .unwrap();
        assert_eq!(e.kind, "container-health");
        assert!(parse_container_event_line(
            r#"{"Type":"container","Action":"health_status: healthy","Actor":{"Attributes":{"name":"api"}},"time":4}"#,
        )
        .is_none());
        // old-daemon shape: status/id/from only, image-ref fallback name
        let e = parse_container_event_line(
            r#"{"status":"die","id":"abc","from":"library/redis:7"}"#,
        )
        .unwrap();
        assert_eq!(e.kind, "container-death");
        assert_eq!(e.name, "redis:7");
        // noise: lifecycle churn and non-container scopes
        assert!(parse_container_event_line(
            r#"{"Type":"container","Action":"start","Actor":{"Attributes":{"name":"web"}},"time":5}"#,
        )
        .is_none());
        assert!(parse_container_event_line(
            r#"{"Type":"image","Action":"die","Actor":{"Attributes":{"name":"web"}},"time":6}"#,
        )
        .is_none());
        assert!(parse_container_event_line("not json at all").is_none());
    }

    #[test]
    fn new_proc_watch_first_sighting_fires_once_per_name() {
        // plain mode: substring, case-insensitive, once per name
        let mut w = NewProcWatch::parse(&["xmrig".into(), "Miner".into()]).unwrap().unwrap();
        assert!(w.first_sighting("XMRIG-proxy"));
        assert!(!w.first_sighting("XMRIG-proxy"), "second sighting is silent");
        assert!(w.first_sighting("coin-miner.sh"));
        assert!(!w.first_sighting("nginx"));
        assert!(!w.first_sighting("nginx"));
        // whitelist mode: only names matching NO pattern alert
        let mut w = NewProcWatch::parse(&["!nginx".into(), "!cron".into()]).unwrap().unwrap();
        assert!(w.negate);
        assert!(w.first_sighting("redis-server"));
        assert!(!w.first_sighting("nginx worker"));
        assert!(!w.first_sighting("crond"));
        // not armed / mixed modes
        assert!(NewProcWatch::parse(&[]).unwrap().is_none());
        assert!(NewProcWatch::parse(&["nginx".into(), "!cron".into()]).is_err());
    }

    #[test]
    fn silence_rules_parse_match_and_expire() {
        let r = SilenceRule::parse("backup=30m").unwrap();
        assert_eq!(r.pattern, "backup");
        assert!(!r.negate);
        assert!(r.until.is_some());
        let now = crate::util::now_unix() as u64;
        assert!(r.covers("pg_backup.sh", now), "substring match");
        assert!(!r.covers("nginx", now));
        // whole-session rule
        let r = SilenceRule::parse("cron").unwrap();
        assert!(r.until.is_none());
        assert!(r.covers("crond", 0));
        assert!(r.covers("crond", u64::MAX / 2));
        // negation: silence everything NOT matching the pattern
        let r = SilenceRule::parse("!nginx").unwrap();
        assert!(r.negate);
        assert!(r.covers("redis", now));
        assert!(!r.covers("nginx worker", now));
        // expired window stops covering
        let r = SilenceRule {
            pattern: "backup".into(),
            negate: false,
            until: Some(100),
        };
        assert!(!r.covers("backup", now));
        // garbage specs
        assert!(SilenceRule::parse("").is_none());
        assert!(SilenceRule::parse("=30m").is_none());
        assert!(SilenceRule::parse("backup=soon").is_none());
        // the batch helper answers for any rule
        let rules = vec![SilenceRule::parse("db=1h").unwrap()];
        assert!(silenced(&rules, "pg_db_backup", now));
        assert!(!silenced(&rules, "nginx", now));
        assert!(!silenced(&[], "postgres", now));
    }

    #[test]
    fn human_secs_formats() {
        assert_eq!(human_secs(45), "45s");
        assert_eq!(human_secs(300), "5m");
        assert_eq!(human_secs(3661), "1h1m1s");
        assert_eq!(human_secs(2 * 86400), "2d");
    }

    #[test]
    fn vanished_processes_are_pruned() {
        let mut h = History::new();
        h.update(&[proc(1, "/bin/a", None)]);
        h.update(&[]);
        assert!(h.cpu_now.is_empty());
        assert!(h.identity_of.is_empty());
    }

    #[test]
    fn events_feed_start_exit_restart() {
        let mut h = History::new();
        h.update(&[proc(1, "/bin/worker", None)]);
        h.update(&[]);
        h.update(&[proc(2, "/bin/worker", None)]);
        let kinds: Vec<&str> = h.events.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds, vec!["restarted", "exited", "started"], "newest first");
        assert_eq!(h.events[0].pid, 2);
        assert!(h.events[0].detail.contains("1 restarts"));
        assert_eq!(h.events[1].pid, 1);
        // events stay capped (within one refresh the exit delta is
        // inserted after the appear delta, so it sits on top)
        for i in 0..600u32 {
            h.update(&[proc(i as i32 + 10, "/bin/x", None)]);
        }
        assert_eq!(h.events.len(), 500);
        assert_eq!(h.events[0].kind, "exited");
    }

    #[test]
    fn events_update_returns_fresh_and_round_trips() {
        let mut h = History::new();
        let fresh = h.update(&[proc(1, "/bin/worker", None)]);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].kind, "started");
        // unchanged snapshot → no new events
        assert!(h.update(&[proc(1, "/bin/worker", None)]).is_empty());
        let fresh = h.update(&[]);
        assert_eq!(fresh[0].kind, "exited");

        // JSONL round trip: file is oldest-first, load returns newest-first
        let dir = std::env::temp_dir().join(format!("witr-events-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let text: String = fresh
            .iter()
            .chain(fresh.iter())
            .map(|e| serde_json::to_string(e).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, &text).unwrap();
        let loaded = load_events_log(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0], fresh[0].clone()); // reversed: last line first
        std::fs::remove_dir_all(&dir).ok();

        // garbage lines are skipped, missing file errors
        assert!(load_events_log("/nonexistent/witr-events.jsonl").is_err());
    }
}
