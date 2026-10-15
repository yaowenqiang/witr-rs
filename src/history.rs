//! Sampling history across TUI refreshes: instantaneous CPU percent
//! (delta of cumulative CPU time), sparklines, and crash-loop detection
//! (same process identity reappearing under a new pid).

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::model::{Pid, Process};

const SAMPLES: usize = 8;
/// Detail-page CPU chart window (~10 min at the 3s TUI refresh).
const BIG_SAMPLES: usize = 120;
const RESTART_WINDOW: Duration = Duration::from_secs(5 * 60);
const PRUNE_AFTER: Duration = Duration::from_secs(10 * 60);
const SPARK_LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
/// Leak suspicion: RSS up at least this many MB across this many trailing
/// samples, rising at least this fraction of the time.
const LEAK_SAMPLES: usize = 60; // ~5 min at the 3s TUI refresh
const LEAK_MB: f64 = 20.0;
const LEAK_FRACTION: f64 = 0.7;

#[derive(Default, Clone)]
struct RestartState {
    last_pid: Pid,
    total: u32,
    events: Vec<Instant>,
    last_seen: Option<Instant>,
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
    /// pid → last SAMPLES instantaneous percents as a sparkline
    pub sparks: HashMap<Pid, String>,
    samples: HashMap<Pid, VecDeque<f64>>,
    /// pid → last BIG_SAMPLES instantaneous percents (detail-page chart)
    big: HashMap<Pid, VecDeque<f64>>,
    /// pid → last BIG_SAMPLES RSS values in KiB (detail-page memory chart
    /// and leak suspicion)
    mem_big: HashMap<Pid, VecDeque<u64>>,
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
            if p.io_read_bytes.is_some() || p.io_write_bytes.is_some() {
                let (rb, wb) = (p.io_read_bytes.unwrap_or(0), p.io_write_bytes.unwrap_or(0));
                if let Some((prb, pwb, at)) = self.io_prev.get(&p.pid) {
                    let wall = now.duration_since(*at).as_millis() as f64;
                    if wall >= 50.0 && rb >= *prb && wb >= *pwb {
                        let s = wall / 1000.0;
                        self.io_rate.insert(
                            p.pid,
                            ((rb - prb) as f64 / s, (wb - pwb) as f64 / s),
                        );
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
            rs.last_pid = p.pid;
            rs.last_seen = Some(now);

            // appear / restart events for the Events tab
            match self.prev_seen.remove(&p.pid) {
                Some(_) => {}
                None if is_restart => event(
                    self,
                    &mut fresh,
                    "restarted",
                    p.pid,
                    &p.name,
                    format!("came back after exiting ({total} restarts total)"),
                ),
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
        self.big.retain(|pid, _| seen.contains(pid));
        self.cpu_prev.retain(|pid, _| seen.contains(pid));
        self.io_rate.retain(|pid, _| seen.contains(pid));
        self.io_prev.retain(|pid, _| seen.contains(pid));
        self.mem_big.retain(|pid, _| seen.contains(pid));
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

    /// Record a threshold alert in the event ring (kind "alert", newest
    /// first, same cap) and return it so callers can persist it to
    /// `--events-log`. Alerts are TUI-generated — `update` never emits them.
    pub fn push_alert(&mut self, pid: Pid, name: &str, detail: &str) -> TuiEvent {
        let e = TuiEvent {
            at_unix: crate::util::now_unix(),
            kind: "alert".into(),
            pid,
            name: name.to_string(),
            detail: detail.to_string(),
        };
        self.events.insert(0, e.clone());
        self.events.truncate(EVENT_CAP);
        e
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
        assert!(h.cpu_now.get(&10).is_none(), "first sample has no delta");
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
