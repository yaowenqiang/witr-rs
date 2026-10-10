//! Sampling history across TUI refreshes: instantaneous CPU percent
//! (delta of cumulative CPU time), sparklines, and crash-loop detection
//! (same process identity reappearing under a new pid).

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use crate::model::{Pid, Process};

const SAMPLES: usize = 8;
const RESTART_WINDOW: Duration = Duration::from_secs(5 * 60);
const PRUNE_AFTER: Duration = Duration::from_secs(10 * 60);
const SPARK_LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

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
#[derive(Debug, Clone, serde::Serialize)]
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

#[derive(Default)]
pub struct History {
    /// pid → (cpu ms at last sample, sampled at)
    cpu_prev: HashMap<Pid, (u64, Instant)>,
    /// pid → instantaneous percent (valid for pids in the last update)
    pub cpu_now: HashMap<Pid, f64>,
    /// pid → last SAMPLES instantaneous percents as a sparkline
    pub sparks: HashMap<Pid, String>,
    samples: HashMap<Pid, VecDeque<f64>>,
    /// pid → identity hash
    identity_of: HashMap<Pid, u64>,
    restarts: HashMap<u64, RestartState>,
    /// Newest-first ring of appear/exit/restart events.
    pub events: Vec<TuiEvent>,
    /// pid → name at the previous refresh (for appear/exit deltas).
    prev_seen: HashMap<Pid, String>,
}

fn identity(p: &Process) -> u64 {
    let mut h = DefaultHasher::new();
    p.name.hash(&mut h);
    p.exe.hash(&mut h);
    p.user.hash(&mut h);
    h.finish()
}

impl History {
    pub fn new() -> Self {
        History::default()
    }

    /// Feed one refresh snapshot. Call before rebuilding views so tables
    /// can read `cpu_now` / `sparks`.
    pub fn update(&mut self, procs: &[Process]) {
        let now = Instant::now();
        let now_unix = crate::util::now_unix();
        let seen: std::collections::HashSet<Pid> =
            procs.iter().map(|p| p.pid).collect();
        let event = |h: &mut History, kind: &str, pid: Pid, name: &str, detail: String| {
            h.events.insert(
                0,
                TuiEvent { at_unix: now_unix, kind: kind.to_string(), pid, name: name.to_string(), detail },
            );
            h.events.truncate(EVENT_CAP);
        };

        for p in procs {
            if p.kernel_thread {
                continue;
            }
            let h = identity(p);
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
                    "restarted",
                    p.pid,
                    &p.name,
                    format!("came back after exiting ({total} restarts total)"),
                ),
                None => event(self, "started", p.pid, &p.name, String::new()),
            }
        }

        // everything still in prev_seen vanished since the last refresh
        let vanished: Vec<(Pid, String)> = self.prev_seen.drain().collect();
        for (pid, name) in vanished {
            event(self, "exited", pid, &name, String::new());
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
        self.cpu_prev.retain(|pid, _| seen.contains(pid));
        self.identity_of.retain(|pid, _| seen.contains(pid));
        self.restarts.retain(|_, rs| {
            rs.last_seen
                .map(|at| now.duration_since(at) < PRUNE_AFTER)
                .unwrap_or(false)
        });
        for rs in self.restarts.values_mut() {
            rs.events.retain(|at| now.duration_since(*at) < RESTART_WINDOW);
        }
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
}
