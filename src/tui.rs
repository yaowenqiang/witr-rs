//! Interactive TUI (ratatui/crossterm), mirroring the Go witr's interface:
//! tab bar, mode line, search box, process table + live details panel with
//! the ancestry tree, footer key hints, 3s auto refresh.

use std::collections::HashMap;
use std::io::Result;
use std::time::{Duration, Instant};

use ratatui::{
    crossterm::{
        execute,
        event::{
            self, Event as CEvent, KeyCode, KeyEventKind, MouseButton, MouseEvent, MouseEventKind,
        },
    },
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    symbols::border,
    text::{Line, Span},
    widgets::{Block, Cell, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};

use crate::model::{Container, LockEntry, Pid, Process, Socket, TargetSpec};
use crate::pipeline;
use crate::platform::Platform;

const REFRESH: Duration = Duration::from_secs(3);
/// Crash forensics: lines fetched per dead process, and how many dead
/// processes keep their "last words" cached.
const DEATH_LINES: usize = 25;
const DEATH_CAP: usize = 50;
const PURPLE: Color = Color::Rgb(125, 86, 243);
const GREEN: Color = Color::Rgb(34, 170, 34);
const GRAY: Color = Color::Rgb(88, 88, 88);
const MID: Color = Color::Rgb(118, 118, 118);
const ACCENT: Color = Color::Rgb(95, 95, 215);
/// how many series the Samples page cycles through (↑/↓)
const SAMPLE_SERIES: usize = 5;

/// One sparkline row for `values`: downsampled to `width` block cells
/// (per-cell max, so peaks survive shrinking), gaps (None) as a space.
/// Returns the cells plus which cell the sample at `cursor` landed on.
fn spark_row(values: &[Option<f64>], width: usize, cursor: usize) -> (Vec<char>, Option<usize>) {
    const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if values.is_empty() || width == 0 {
        return (Vec::new(), None);
    }
    let max = values.iter().filter_map(|v| *v).fold(0.0f64, f64::max);
    let max = if max <= 0.0 { 1.0 } else { max * 1.05 };
    let n = values.len();
    let cell_of = |i: usize| i * width / n;
    let mut cells = vec![' '; width];
    for (i, v) in values.iter().enumerate() {
        if let Some(v) = v {
            let level = ((v / max) * 7.0).round().clamp(0.0, 7.0) as usize;
            let cell = cell_of(i);
            // keep the tallest sample seen in the cell (peaks read better
            // than the last one in)
            if BLOCKS[level] > cells[cell] || cells[cell] == ' ' {
                cells[cell] = BLOCKS[level];
            }
        }
    }
    let cur = if cursor < n { Some(cell_of(cursor)) } else { None };
    (cells, cur)
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Tab {
    Processes,
    Ports,
    Containers,
    Locks,
    Events,
    Services,
}

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Processes => "1. Processes",
            Tab::Ports => "2. Ports",
            Tab::Containers => "3. Containers",
            Tab::Locks => "4. Locks",
            Tab::Events => "5. Events",
            Tab::Services => "6. Services",
        }
    }
    fn from_digit(c: char) -> Option<Self> {
        match c {
            '1' => Some(Tab::Processes),
            '2' => Some(Tab::Ports),
            '3' => Some(Tab::Containers),
            '4' => Some(Tab::Locks),
            '5' => Some(Tab::Events),
            '6' => Some(Tab::Services),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
#[derive(Debug)]
enum SortKey {
    Pid,
    Name,
    User,
    Cpu,
    Mem,
    /// combined read+write bytes/s from the IO sampling history
    Io,
    Started,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Focus {
    Table,
    Details,
}

/// Consecutive over-threshold samples before an alert fires — re-exported
/// from history (shared with the headless --watch loop).
#[cfg(test)]
use crate::history::alert_cycle;
use crate::history::AlertTrack;
use crate::history::ALERT_CYCLES;

/// the parked result of an in-flight death-logs fetch (see `TuiApp::death_rx`)
type DeathLogsRx = std::sync::mpsc::Receiver<(Pid, std::result::Result<Vec<String>, String>)>;

struct TuiApp {
    platform: Box<dyn Platform>,
    tab: Tab,
    focus: Focus,
    procs: Vec<Process>,
    sockets: Vec<Socket>,
    locks: Vec<LockEntry>,
    locks_supported: bool,
    /// indices into `procs` after filter + sort
    view: Vec<usize>,
    /// parallel to `view`: DFS depth of each row in tree mode ('T');
    /// empty in flat mode or while a search filter is active
    view_depth: Vec<usize>,
    /// Processes-tab tree mode: children nest under their parent
    tree_mode: bool,
    sort_key: SortKey,
    sort_desc: bool,
    search: String,
    search_mode: bool,
    table_state: TableState,
    detail_scroll: u16,
    /// height of the details viewport, for half-page scrolls
    detail_height: u16,
    detail_lines: Vec<Line<'static>>,
    detail_pid: Option<Pid>,
    /// socket snapshot taken when the full detail page opened; the per-tick
    /// page rebuild (render_detail_page) reuses it so the expensive probes
    /// run once, at open
    detail_socks: Vec<Socket>,
    /// full-page detail view (Enter from the table), mirroring the Go witr's
    /// stateDetail: left "Process Detail" pane + right "Environment Variables"
    page: Page,
    detail_pane: bool, // true = Process Detail focused, false = Environment
    detail_report: Option<crate::model::TargetReport>,
    detail_line_count: u16,
    env_scroll: u16,
    env_line_count: u16,
    /// Environment-pane filter on the process detail page (/ to enter):
    /// matches KEY=VALUE substrings, case-insensitive
    env_search: String,
    env_search_mode: bool,
    /// tmux-style zoom (z): the focused pane temporarily fills the whole row
    detail_zoom: bool,
    /// Actions bar on the process detail page (a): [k]ill [t]erm [p]ause
    /// [r]esume [n]ice — mirrors the Go witr's action bar
    actions_open: bool,
    /// same zoom for the Processes tab (table <-> details panel)
    browse_zoom: bool,
    /// Ports-tab detail page (Enter on a port): every socket touching that
    /// port (LISTEN + ESTABLISHED requests) plus the owning process report
    port_detail_port: u16,
    port_detail_sockets: Vec<Socket>,
    port_detail_report: Option<crate::model::TargetReport>,
    port_scroll: u16,
    port_owner_scroll: u16,
    port_pane_conn: bool, // true = connections pane focused
    port_pane_height: u16,
    /// Containers-tab detail page (Enter on a container)
    container_detail: Option<Container>,
    container_procs: Vec<Process>,
    cd_scroll: u16,
    cdp_scroll: u16,
    cd_pane_info: bool, // true = container info pane focused
    /// set when the selection moved; details recompute after DEBOUNCE so a
    /// held-down j/k doesn't spawn a fetch per row (same as the Go witr)
    detail_pending_since: Option<Instant>,
    /// Ports-tab filter (independent of the process search): matches port,
    /// pid, process name, address, proto and state substrings
    port_search: String,
    /// indices into `sockets` after the port filter
    socket_view: Vec<usize>,
    /// Ports-tab 'a' toggle: false = listening tcp + bound udp (the Go
    /// witr's default view), true = every socket incl. connections
    ports_show_all: bool,
    /// Ports-tab sort column ('p/t/n/s', Go witr parity) + direction
    port_sort: PortSort,
    port_sort_desc: bool,
    /// Ports-tab 'o' toggle: aggregate view — one row per (port, owner)
    /// instead of one row per socket
    ports_overview: bool,
    /// overview rows rebuilt from the filtered socket view every refresh
    port_overview_view: Vec<PortOverviewRow>,
    containers: Vec<Container>,
    container_search: String,
    /// indices into `containers` after the filter
    container_view: Vec<usize>,
    /// Containers-tab sort column ('i/n/r/g/s/p', Go witr parity + compose); None =
    /// the runtime's natural order. Direction flips when the same key is
    /// pressed again.
    container_sort: Option<ContainerSort>,
    container_sort_desc: bool,
    /// 'n' in the actions bar opens this free-form nice value (−20…19)
    renice_input: Option<String>,
    /// last left-click (time + cell) for double-click → open detail
    last_click: Option<(Instant, u16, u16)>,
    /// screen rects captured during draw so mouse events can be mapped
    /// back to rows / tabs / panes
    tab_rect: Option<ratatui::prelude::Rect>,
    table_rect: Option<ratatui::prelude::Rect>,
    detail_rect: Option<ratatui::prelude::Rect>,
    /// Locks-tab filter (kind / mode / pid / process / path)
    lock_search: String,
    /// indices into `locks` after the filter
    lock_view: Vec<usize>,
    /// selection state for the Locks table (j/k + Enter opens the holder)
    lock_state: TableState,
    /// Locks-tab "all open files" mode ('a'): locks merged with every open
    /// file on the system, lock entries winning on (pid, path)
    locks_show_all: bool,
    /// Locks-tab sort column ('p/n/t/m/f', Go witr parity) + direction
    lock_sort: LockSort,
    lock_sort_desc: bool,
    /// lock_view size before the OPEN-mode 100-row display cap
    locks_total: usize,
    /// Events-tab filter (kind / pid / name / detail) + selection over the
    /// history event ring (newest first)
    event_search: String,
    event_view: Vec<usize>,
    event_state: TableState,
    /// Events-tab sort column ('t/e/p/n') + direction (Time defaults
    /// newest-first to match the ring's natural order)
    event_sort: EventSort,
    event_sort_desc: bool,
    /// Services tab: units from the platform service manager, enumerated
    /// on a background thread (systemctl can take a second)
    services: Vec<crate::model::Service>,
    services_loading: bool,
    services_rx: Option<std::sync::mpsc::Receiver<Vec<crate::model::Service>>>,
    service_search: String,
    service_view: Vec<usize>,
    /// Services-tab sort column ('n/m/s/p') + direction
    service_sort: Option<ServiceSort>,
    service_sort_desc: bool,
    /// Logs page ('l'): what we asked for, the fetched lines, scroll offset,
    /// and the in-flight background fetch (log tools take seconds)
    logs_for: Option<String>,
    logs_lines: Vec<String>,
    logs_scroll: u16,
    logs_rx: Option<std::sync::mpsc::Receiver<std::result::Result<Vec<String>, String>>>,
    /// what the Logs page was opened on — 'F' follow needs the container
    logs_src: Option<crate::logs::LogSource>,
    /// live `runtime logs -f` stream: line receiver + child to kill
    follow_rx: Option<std::sync::mpsc::Receiver<String>>,
    follow_child: Option<std::process::Child>,
    /// follow autoscroll: pane height + line count at the previous poll
    logs_pane_h: u16,
    follow_prev_len: usize,
    /// crash forensics: the moment a process exits, its last log lines are
    /// fetched in the background and parked here (oldest first, capped) so
    /// the Events tab's 'l' can show "last words" instantly — a live re-query
    /// minutes later often misses the window (macOS `log show --last 10m`)
    death_logs: std::collections::VecDeque<(Pid, Vec<String>)>,
    /// the one in-flight death-logs fetch
    death_rx: Option<DeathLogsRx>,
    /// --events-log sink: every event the sampler generates is appended as
    /// one JSON line (single writer — the event loop thread)
    events_log: Option<std::fs::File>,
    /// --replay FILE --follow: tails the recorded file; appended events
    /// stream into the ring on every refresh tick
    event_tail: Option<crate::history::EventTail>,
    /// desktop notifications enabled (--notify, '!' toggles)
    notify: bool,
    /// watchlist: persisted "name|exe_basename|user" identity keys (config
    /// `watch`). Watched processes get a ★, pin to the top of the flat
    /// Processes table, and stay watched across restarts — the pid is not
    /// part of the key. 'w' toggles on the selection and writes the config.
    watch: Vec<String>,
    /// process name → restart count seen this session; a name that has
    /// restarted ≥2 times is a crash looper — its plain exits notify too
    restart_tally: HashMap<String, u32>,
    /// container enumeration runs on a background thread (a hung runtime
    /// CLI must not freeze the UI); results arrive via this channel
    containers_loading: bool,
    /// first enumeration finished — afterwards refreshes keep the stale
    /// table visible instead of flashing the loading placeholder
    containers_loaded: bool,
    containers_rx: Option<std::sync::mpsc::Receiver<(Vec<Container>, Vec<crate::k8s::Pod>)>>,
    /// live per-container CPU% + memory (full id → stats): a background
    /// `stats --no-stream` sweep rides the containers thread path — stats
    /// cost ~2s per runtime, so they refresh on a slower cadence than the
    /// listing itself and outlive re-enumerations (merged back by id)
    container_stats: ContainerStatsMap,
    container_stats_at: Option<Instant>,
    container_stats_loading: bool,
    container_stats_rx: Option<ContainerStatsRx>,
    /// per-container throttle percent over the last sweep (12-char id →
    /// %) — diffed from the cumulative throttled_usec each containers
    /// sweep brings back; empty until the second sweep arms the delta
    throttle_pct: HashMap<String, f64>,
    /// the throttled_usec reading + sweep time the percentage diffs against
    throttle_prev: HashMap<String, (u64, Instant)>,
    /// sampling history: instantaneous cpu, sparklines, restart detection
    hist: crate::history::History,
    /// open files fetched when the full detail page opens
    open_files: Option<Vec<String>>,
    last_refresh: Instant,
    /// 'P' freezes sampling: no refresh, no event deltas, no pings
    paused: bool,
    /// Processes-tab 'B' aggregation mode + the aggregated rows
    group_mode: GroupMode,
    group_view: Vec<GroupRow>,
    /// 'S' session digest (computed when the page opens) + its window
    summary: Option<crate::history::SessionSummary>,
    summary_window: u64,
    /// Latest whole-machine snapshot ('y' system page "now" column:
    /// load / cores / swap live here, history rings only chart cpu+mem)
    sys_stats: Option<crate::platform::SystemStats>,
    /// device-backed mounts for the system page's disk section — one df /
    /// CIM sweep per refresh while the page is open
    sys_mounts: Vec<crate::platform::MountUsage>,
    /// per-NIC cumulative byte counters from the previous y-page sample —
    /// the net section's rates are diffs between consecutive sweeps
    sys_net_prev: HashMap<String, (u64, u64)>,
    /// when `sys_net_prev` was taken (the rate's denominator)
    sys_net_prev_at: Option<Instant>,
    /// last computed per-NIC (name, rx MB/s, tx MB/s); empty until two
    /// sweeps — the first only arms the counters
    sys_net_rows: Vec<(String, f64, f64)>,
    /// total rx+tx MB/s history for the net sparkline (oldest first)
    sys_net_hist: Vec<f64>,
    /// sampling interval (config refresh_secs, built-in default REFRESH)
    refresh: Duration,
    status: String,
    confirm_kill: Option<Pid>,
    /// 'K' in the actions bar arms this: (root pid, descendant pids). y
    /// confirms — TERM to every pid in the tree; any other key cancels.
    confirm_tree_kill: Option<(Pid, Vec<Pid>)>,
    /// --alert-cpu / --alert-mem thresholds (None = that metric unchecked)
    alert_cpu: Option<f64>,
    /// --alert-mem in MB (mem_kb is KiB)
    alert_mem: Option<u64>,
    /// --alert-fd open-descriptor threshold (None = unchecked)
    alert_fd: Option<u64>,
    /// fd counts from the last refresh (only sampled when alert_fd is set —
    /// the sweep costs one lsof scan per tick on macOS)
    fd_counts: HashMap<Pid, u64>,
    /// --alert-io disk rate threshold in MB/s, read+write (None = unchecked)
    alert_io: Option<f64>,
    /// --alert-conn ESTABLISHED-connection threshold (None = unchecked)
    alert_conn: Option<u64>,
    /// established-connection counts from the last refresh (only sampled
    /// when alert_conn is set — one socket sweep per tick)
    conn_counts: HashMap<Pid, u64>,
    /// --alert-threads kernel-thread threshold (None = unchecked; the count
    /// rides the listing — Linux stat / Windows thread snapshot)
    alert_threads: Option<u64>,
    /// --alert-net-per-proc TCP-throughput threshold (None = unchecked;
    /// rates ride hist's ss-sweep diffs)
    alert_net_per_proc: Option<u64>,
    /// --alert-deviation self-baseline factor (None = unchecked; the
    /// baseline lives in hist's dev_samples window)
    alert_deviation: Option<f64>,
    /// --alert-port canaries: (port, negate) — negate=true means the
    /// listener must stay up; alerts fire on the appear/gone edges
    alert_port: Vec<(u16, bool)>,
    /// per-port LISTEN presence from the last refresh (edge detection;
    /// the first observation only arms)
    port_seen: HashMap<u16, bool>,
    /// last-known "name (pid N)" label per watched port (the "gone"
    /// message says what vanished)
    port_owner: HashMap<u16, String>,
    /// --alert-repeat: re-send a firing alert about every N seconds while
    /// its excursion keeps burning (None = once per excursion)
    alert_repeat: Option<u64>,
    /// --alert-load: machine-wide 1-minute load-average threshold
    alert_load: Option<f64>,
    /// --alert-mem-pct: machine-wide used-RAM percent threshold
    alert_mem_pct: Option<u64>,
    /// --alert-count: machine-wide visible-process-count threshold
    alert_count: Option<u32>,
    /// --alert-disk: machine-wide fullest-mount used-percent threshold
    alert_disk: Option<u64>,
    /// --alert-net: machine-wide rx+tx throughput threshold (MB/s)
    alert_net: Option<u64>,
    /// --alert-psi: PSI "full" stall percent threshold (Linux only)
    alert_psi: Option<f64>,
    alert_mem_avail_mb: Option<u64>,
    alert_swap_pct: Option<u64>,
    alert_retrans: Option<u64>,
    alert_nic_drop: Option<u64>,
    /// streak/firing state for the machine-wide alerts
    sys_alert: crate::history::SysAlertState,
    /// shared container/pod edge detector memory (first sighting arms, no
    /// alerts) — the same core the headless `--alert-container` loop runs
    container_edges: crate::history::ContainerEdges,
    /// container alerts (death edge / climbing restarts) waiting for the
    /// next refresh's picks loop to dispatch them
    pending_alerts: Vec<(Pid, String, String)>,
    /// --alert-exec: shell command per alert firing (context in env vars)
    alert_exec: Option<String>,
    /// --alert-webhook: POST each alert firing as JSON to this URL
    alert_webhook: Option<String>,
    /// --alert-silence maintenance windows (reloaded on SIGHUP)
    alert_silence: Vec<crate::history::SilenceRule>,
    /// --alert-new-proc first-sighting tracker (None = not armed)
    new_proc: Option<crate::history::NewProcWatch>,
    /// time-replay ring — (sampled-at, capped frame) snapshots of the
    /// live table; `<`/`>` scrub it on the Processes tab
    replay_ring: std::collections::VecDeque<(i64, Vec<Process>)>,
    /// position in the ring while scrubbing; None = live view
    replay_pos: Option<usize>,
    /// brief-process poller feed (spawned by run() when the platform has
    /// a cheap pid sweep) + its stop flag (set on Drop)
    brief_rx: Option<std::sync::mpsc::Receiver<crate::history::TuiEvent>>,
    brief_stop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// docker/podman `events` stream — container death/OOM/health edges
    /// in milliseconds. Spawned once the first container enumeration
    /// succeeds; None keeps the enumeration-diff detector in charge.
    container_events: Option<crate::history::ContainerEventStream>,
    /// one-shot guard so a runtime-less host doesn't re-attempt the spawn
    /// on every sweep (reset when a live stream disconnects)
    container_events_tried: bool,
    /// 'M' session-wide mute — no alert firing at all while set (the
    /// picks still land in the ring as "silenced")
    muted: bool,
    /// pid → per-metric streak/firing state (pruned to live pids)
    alert_state: HashMap<Pid, AlertTrack>,
    /// process annotations ("name|exe|user|note"), identity-keyed like the
    /// watchlist; 'N' edits the selection's entry, config notes persist it
    notes: Vec<String>,
    /// 'N' on the Processes table: free-form note input for the selection
    note_input: Option<String>,
    /// SIGHUP hot-reload builder (from the seed) — None where reload
    /// doesn't apply
    reseed_fn: Option<Box<dyn Fn() -> Seed>>,
    /// 'D' page: snapshot-diff entries (newest auto snapshot vs the live
    /// table), computed at open time — 'r' on the page recomputes
    diff_entries: Vec<crate::snapshot::DiffEntry>,
    /// 'D' page: which snapshot was compared (shown under the header)
    diff_source: String,
    /// 'D' page: selected entry
    diff_sel: usize,
    /// --samples: the record file's machine samples + browse state
    /// (cursor into `samples`, which of the 5 series is charted)
    samples: Vec<crate::SysPoint>,
    samples_source: String,
    samples_cursor: usize,
    samples_series: usize,
    /// where '?' was pressed — the Help overlay returns here
    help_prev: Page,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Page {
    Browse,
    Detail,
    PortDetail,
    ContainerDetail,
    Logs,
    Summary,
    System,
    /// 'D': newest auto snapshot vs the live table, one row per DiffEntry
    Diff,
    /// --samples: a --record file's machine samples browsed as sparklines
    Samples,
    /// '?' overlay: the keymap for the current tab; returns to
    /// `help_prev` on close
    Help,
}

/// Locks-tab sort columns — keys p/n/t/m/f, matching the Go witr.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LockSort {
    Pid,
    Process,
    Type,
    Mode,
    Path,
}

/// Ports-tab sort columns — keys p/t/n/s, matching the Go witr.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PortSort {
    Port,
    Proto,
    Addr,
    State,
}

/// Containers-tab sort columns — keys i/n/r/g/s (+ p for compose
/// project), matching the Go witr.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ContainerSort {
    Id,
    Name,
    Runtime,
    Image,
    Status,
    Project,
}

/// One full-id → (cpu_pct, mem_used_bytes, mem_total_bytes) stats sweep,
/// delivered from the background sampler thread.
type ContainerStatsMap = HashMap<String, (f64, u64, u64)>;
type ContainerStatsRx = std::sync::mpsc::Receiver<ContainerStatsMap>;

/// Events-tab sort columns — keys t/e/p/n (Time defaults newest-first).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EventSort {
    Time,
    Kind,
    Pid,
    Process,
}

/// Services-tab sort columns — keys n/m/s/p.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ServiceSort {
    Name,
    Manager,
    State,
    Pid,
}

const DEBOUNCE: Duration = Duration::from_millis(500);
const DOUBLE_CLICK: Duration = Duration::from_millis(400);

/// Time-replay ring: how many past frames `<`/`>` can scrub through and
/// how many rows each frame keeps (busiest-by-CPU win the slots).
const REPLAY_FRAMES: usize = 30;
const REPLAY_FRAME_ROWS: usize = 200;

/// CLI targets carried into the TUI, so `witr -i --pid 42` opens where a
/// one-shot run would have looked (Go witr parity).
#[derive(Default)]
pub struct Seed {
    pub name: Option<String>,
    pub pid: Option<Pid>,
    pub port: Option<u16>,
    pub container: Option<String>,
    pub file: Option<String>,
    /// targets past the first of each type — the TUI shows one per type
    pub skipped: Vec<String>,
    /// --events-log: append every sampled event as JSON lines to this file
    pub events_log: Option<String>,
    /// --replay: pre-recorded events (newest first) loaded into the ring
    /// before the live sampler starts
    pub replayed: Vec<crate::history::TuiEvent>,
    /// --replay FILE --follow: keep tailing the file — events appended by
    /// the recording side stream into the ring live
    pub replay_follow: Option<String>,
    /// --samples: machine samples parsed out of a --record file (csv or
    /// jsonl), browsed on the Samples page while live sampling continues
    pub samples: Vec<crate::SysPoint>,
    /// the --samples file path, shown as the page's source line
    pub samples_source: String,
    /// --notify: desktop notifications on restarts / repeated exits
    /// ('!' toggles live inside the TUI)
    pub notify: bool,
    /// config watch — pre-seeded watchlist ("name|exe_basename|user" keys)
    pub watch: Vec<String>,
    /// --since: 'S' summary-page window in seconds (None = whole session)
    pub since: Option<u64>,
    /// config refresh_secs — the TUI sampling interval (None = built-in 3s)
    pub refresh_secs: Option<u64>,
    /// config sort — default Processes-tab sort (pid/name/user/cpu/mem/started)
    pub sort: Option<String>,
    /// config paused — start with sampling frozen ('P' state)
    pub paused: bool,
    /// --alert-cpu: CPU%% threshold; sustained excess → alert
    pub alert_cpu: Option<f64>,
    /// --alert-mem: RSS threshold in MB; sustained excess → alert
    pub alert_mem: Option<u64>,
    /// --alert-fd: open-descriptor threshold; sustained excess → alert
    pub alert_fd: Option<u64>,
    /// --alert-io: disk-I/O rate threshold in MB/s (read+write); Linux only
    pub alert_io: Option<f64>,
    /// --alert-conn: ESTABLISHED-connection-count threshold; sustained
    /// excess → alert (connection-leak detection)
    pub alert_conn: Option<u64>,
    /// --alert-threads: kernel-thread-count threshold; sustained excess →
    /// alert (thread-leak detection)
    pub alert_threads: Option<u64>,
    /// --alert-net-per-proc: per-process TCP throughput threshold (MB/s);
    /// sustained excess → alert (quiet-exfiltration detection)
    pub alert_net_per_proc: Option<u64>,
    /// --alert-deviation: self-baseline CPU deviation factor; sustained
    /// excess → alert ("the quiet daemon suddenly busy")
    pub alert_deviation: Option<f64>,
    /// --alert-port canaries: (port, negate) — alert on the LISTEN
    /// appear edge, or (negated) on the listener-gone edge
    pub alert_port: Vec<(u16, bool)>,
    /// --alert-repeat: re-send firing alerts about every N seconds
    pub alert_repeat: Option<u64>,
    /// --alert-load: machine-wide 1-minute load-average threshold
    pub alert_load: Option<f64>,
    /// --alert-mem-pct: machine-wide used-RAM percent threshold
    pub alert_mem_pct: Option<u64>,
    /// --alert-count: machine-wide visible-process-count threshold
    pub alert_count: Option<u32>,
    /// --alert-disk: machine-wide used-percent threshold over local mounts
    pub alert_disk: Option<u64>,
    /// --alert-net: machine-wide rx+tx throughput threshold (MB/s)
    pub alert_net: Option<u64>,
    /// --alert-psi: PSI "full" stall percent threshold (Linux only)
    pub alert_psi: Option<f64>,
    /// --alert-mem-avail-mb: reclaimable-memory absolute floor (MB)
    pub alert_mem_avail_mb: Option<u64>,
    /// --alert-swap-pct: swap saturation threshold (percent)
    pub alert_swap_pct: Option<u64>,
    /// --alert-retrans: TCP retransmit rate threshold (segments/s)
    pub alert_retrans: Option<u64>,
    /// --alert-nic-drop: NIC drop/error rate threshold (packets/s)
    pub alert_nic_drop: Option<u64>,
    /// --alert-exec: shell command run on every threshold-alert firing;
    /// context exported as WITR_ALERT_PID/NAME/DETAIL
    pub alert_exec: Option<String>,
    /// --alert-webhook: POST each alert firing as JSON to this URL
    pub alert_webhook: Option<String>,
    /// --alert-silence: maintenance windows — matching alerts are held
    /// down (one "silenced" event each, no side effects)
    pub alert_silence: Vec<crate::history::SilenceRule>,
    /// --alert-new-proc raw specs (parsed into the live tracker)
    pub alert_new_proc: Vec<String>,
    /// config notes — per-process annotations ("name|exe|user|note"),
    /// identity-keyed like the watchlist so they survive restarts
    pub notes: Vec<String>,
    /// SIGHUP hot-reload: builds a fresh Seed from the pre-apply CLI
    /// snapshot plus a re-read of the config file. None where reload
    /// doesn't apply (replay-only entry points).
    pub reseed: Option<Box<dyn Fn() -> Seed>>,
}

impl Seed {
    /// First target of each type wins, extras are reported (mirrors the Go
    /// witr's withTargets).
    pub fn from_targets(
        names: &[String],
        pids: &[Pid],
        ports: &[u16],
        files: &[String],
        containers: &[String],
    ) -> Seed {
        let mut s = Seed::default();
        for n in names {
            if s.name.is_none() {
                s.name = Some(n.clone());
            } else {
                s.skipped.push(format!("name {n}"));
            }
        }
        for p in pids {
            if s.pid.is_none() {
                s.pid = Some(*p);
            } else {
                s.skipped.push(format!("pid {p}"));
            }
        }
        for p in ports {
            if s.port.is_none() {
                s.port = Some(*p);
            } else {
                s.skipped.push(format!("port {p}"));
            }
        }
        for c in containers {
            if s.container.is_none() {
                s.container = Some(c.clone());
            } else {
                s.skipped.push(format!("container {c}"));
            }
        }
        for f in files {
            if s.file.is_none() {
                s.file = Some(f.clone());
            } else {
                s.skipped.push(format!("file {f}"));
            }
        }
        s
    }

    /// Fold the reloadable knobs (config keys + alert flags) onto this
    /// seed — the exact mapping the --interactive entry point applies at
    /// startup, reused by the SIGHUP reload so both paths stay in step.
    /// Targets stay fixed; only knobs move.
    pub fn with_knobs(mut self, cli: &crate::cli::Cli, cfg: &crate::config::Config) -> Seed {
        self.notify = cli.notify || cfg.notify.unwrap_or(false);
        self.refresh_secs = cfg.refresh_secs;
        self.sort = cfg.sort.clone();
        self.paused = cfg.paused.unwrap_or(false);
        self.alert_cpu = cli.alert_cpu;
        self.alert_mem = cli.alert_mem;
        self.alert_fd = cli.alert_fd;
        self.alert_io = cli.alert_io;
        self.alert_conn = cli.alert_conn;
        self.alert_threads = cli.alert_threads;
        self.alert_net_per_proc = cli.alert_net_per_proc;
        self.alert_deviation = cli.alert_deviation;
        self.alert_repeat = cli.alert_repeat;
        self.alert_load = cli.alert_load;
        self.alert_mem_pct = cli.alert_mem_pct;
        self.alert_count = cli.alert_count;
        self.alert_disk = cli.alert_disk;
        self.alert_net = cli.alert_net;
        self.alert_psi = cli.alert_psi;
        self.alert_mem_avail_mb = cli.alert_mem_avail_mb;
        self.alert_swap_pct = cli.alert_swap_pct;
        self.alert_retrans = cli.alert_retrans;
        self.alert_nic_drop = cli.alert_nic_drop;
        self.alert_exec = cli.alert_exec.clone();
        self.alert_webhook = cli.alert_webhook.clone();
        self.alert_silence = cli
            .alert_silence
            .iter()
            .filter_map(|s| crate::history::SilenceRule::parse(s))
            .collect();
        self.alert_new_proc = cli.alert_new_proc.clone();
        self.watch = cfg.watch.clone();
        self.notes = cfg.notes.clone();
        self
    }
}

impl Tab {
    fn next(self) -> Self {
        match self {
            Tab::Processes => Tab::Ports,
            Tab::Ports => Tab::Containers,
            Tab::Containers => Tab::Locks,
            Tab::Locks => Tab::Events,
            Tab::Events => Tab::Services,
            Tab::Services => Tab::Processes,
        }
    }
    fn prev(self) -> Self {
        match self {
            Tab::Processes => Tab::Services,
            Tab::Ports => Tab::Processes,
            Tab::Containers => Tab::Ports,
            Tab::Locks => Tab::Containers,
            Tab::Events => Tab::Locks,
            Tab::Services => Tab::Events,
        }
    }
}

/// Quitting the TUI kills a running `logs -f` child so the runtime CLI
/// doesn't outlive the UI.
impl Drop for TuiApp {
    fn drop(&mut self) {
        self.stop_logs_follow();
        if let Some(stop) = &self.brief_stop {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

impl TuiApp {
    fn new(platform: Box<dyn Platform>, seed: Seed) -> Self {
        let locks_supported = matches!(platform.name(), "linux" | "macos");
        let refresh = Duration::from_secs(seed.refresh_secs.unwrap_or(REFRESH.as_secs()).max(1));
        let mut app = TuiApp {
            platform,
            tab: Tab::Processes,
            focus: Focus::Table,
            procs: Vec::new(),
            sockets: Vec::new(),
            locks: Vec::new(),
            locks_supported,
            locks_show_all: false,
            lock_sort: LockSort::Pid,
            lock_sort_desc: false,
            locks_total: 0,
            view: Vec::new(),
            view_depth: Vec::new(),
            tree_mode: false,
            sort_key: SortKey::Mem,
            sort_desc: true,
            search: String::new(),
            search_mode: false,
            table_state: TableState::default(),
            detail_scroll: 0,
            detail_height: 12,
            detail_lines: vec![Line::from("loading...".fg(MID))],
            detail_pid: None,
            detail_socks: Vec::new(),
            page: Page::Browse,
            detail_pane: true,
            detail_report: None,
            detail_line_count: 1,
            env_scroll: 0,
            env_line_count: 1,
            env_search: String::new(),
            env_search_mode: false,
            detail_zoom: false,
            actions_open: false,
            browse_zoom: false,
            port_detail_port: 0,
            port_detail_sockets: Vec::new(),
            port_detail_report: None,
            port_scroll: 0,
            port_owner_scroll: 0,
            port_pane_conn: true,
            port_pane_height: 10,
            container_detail: None,
            container_procs: Vec::new(),
            cd_scroll: 0,
            cdp_scroll: 0,
            cd_pane_info: true,
            detail_pending_since: None,
            port_search: String::new(),
            socket_view: Vec::new(),
            ports_show_all: false,
            port_sort: PortSort::Port,
            port_sort_desc: false,
            ports_overview: false,
            port_overview_view: Vec::new(),
            containers: Vec::new(),
            container_search: String::new(),
            container_view: Vec::new(),
            container_sort: None,
            container_sort_desc: false,
            renice_input: None,
            last_click: None,
            tab_rect: None,
            alert_cpu: seed.alert_cpu,
            alert_mem: seed.alert_mem,
            alert_fd: seed.alert_fd,
            fd_counts: HashMap::new(),
            alert_io: seed.alert_io,
            alert_conn: seed.alert_conn,
            conn_counts: HashMap::new(),
            alert_threads: seed.alert_threads,
            alert_net_per_proc: seed.alert_net_per_proc,
            alert_deviation: seed.alert_deviation,
            alert_port: seed.alert_port.clone(),
            port_seen: HashMap::new(),
            port_owner: HashMap::new(),
            alert_repeat: seed.alert_repeat,
            alert_load: seed.alert_load,
            alert_mem_pct: seed.alert_mem_pct,
            alert_count: seed.alert_count,
            alert_disk: seed.alert_disk,
            alert_net: seed.alert_net,
            alert_psi: seed.alert_psi,
            alert_mem_avail_mb: seed.alert_mem_avail_mb,
            alert_swap_pct: seed.alert_swap_pct,
            alert_retrans: seed.alert_retrans,
            alert_nic_drop: seed.alert_nic_drop,
            sys_alert: crate::history::SysAlertState::default(),
            container_edges: crate::history::ContainerEdges::default(),
            pending_alerts: Vec::new(),
            alert_exec: seed.alert_exec.clone(),
            alert_webhook: seed.alert_webhook.clone(),
            alert_silence: seed.alert_silence,
            new_proc: crate::history::NewProcWatch::parse(&seed.alert_new_proc)
                .ok()
                .flatten(),
            replay_ring: std::collections::VecDeque::new(),
            replay_pos: None,
            brief_rx: None,
            brief_stop: None,
            container_events: None,
            container_events_tried: false,
            muted: false,
            alert_state: HashMap::new(),
            notes: seed.notes,
            note_input: None,
            reseed_fn: seed.reseed,
            diff_entries: Vec::new(),
            diff_source: String::new(),
            diff_sel: 0,
            samples: Vec::new(),
            samples_source: String::new(),
            samples_cursor: 0,
            samples_series: 0,
            help_prev: Page::Browse,
            confirm_tree_kill: None,
            table_rect: None,
            detail_rect: None,
            lock_search: String::new(),
            lock_view: Vec::new(),
            lock_state: TableState::default(),
            event_search: String::new(),
            event_view: Vec::new(),
            event_state: TableState::default(),
            event_sort: EventSort::Time,
            event_sort_desc: true,
            logs_for: None,
            logs_lines: Vec::new(),
            logs_scroll: 0,
            logs_rx: None,
            logs_src: None,
            follow_rx: None,
            follow_child: None,
            logs_pane_h: 0,
            follow_prev_len: 0,
            death_logs: std::collections::VecDeque::new(),
            death_rx: None,
            events_log: None,
            event_tail: None,
            notify: false,
            watch: seed.watch,
            restart_tally: HashMap::new(),
            containers_loading: false,
            containers_loaded: false,
            containers_rx: None,
            container_stats: HashMap::new(),
            throttle_pct: HashMap::new(),
            throttle_prev: HashMap::new(),
            container_stats_at: None,
            container_stats_loading: false,
            container_stats_rx: None,
            hist: crate::history::History::new(),
            open_files: None,
            last_refresh: Instant::now() - REFRESH, // force first refresh
            paused: false,
            group_mode: GroupMode::Off,
            group_view: Vec::new(),
            services: Vec::new(),
            services_loading: false,
            services_rx: None,
            service_search: String::new(),
            service_view: Vec::new(),
            service_sort: None,
            service_sort_desc: false,
            summary: None,
            summary_window: seed.since.unwrap_or(u64::MAX),
            sys_stats: None,
            sys_mounts: Vec::new(),
            sys_net_prev: HashMap::new(),
            sys_net_prev_at: None,
            sys_net_rows: Vec::new(),
            sys_net_hist: Vec::new(),
            refresh,
            status: String::new(),
            confirm_kill: None,
        };
        // CLI seeding: filters before the first refresh, then tab + selection
        if let Some(n) = seed.name {
            app.search = n;
        }
        app.refresh();
        if let Some(pid) = seed.pid {
            let row = app.view.iter().position(|&i| app.procs[i].pid == pid);
            match row {
                Some(r) => app.table_state.select(Some(r)),
                None => app.status = format!("pid {pid} is not in the process list"),
            }
        }
        // one target type per tab; the last one wins the tab (Go witr parity)
        if let Some(port) = seed.port {
            app.switch_tab(Tab::Ports);
            app.port_search = port.to_string();
            app.rebuild_socket_view();
        }
        if let Some(c) = seed.container {
            app.switch_tab(Tab::Containers);
            app.container_search = c;
            app.rebuild_container_view();
        }
        if let Some(f) = seed.file {
            app.switch_tab(Tab::Locks);
            app.lock_search = f;
            app.rebuild_lock_view();
        }
        if !seed.skipped.is_empty() {
            app.status = format!(
                "interactive mode shows one target of each type; not shown: {}",
                seed.skipped.join(", ")
            );
        }
        if let Some(path) = &seed.events_log {
            match std::fs::OpenOptions::new().create(true).append(true).open(path) {
                Ok(f) => app.events_log = Some(f),
                Err(e) => app.status = format!("--events-log {path}: {e}"),
            }
        }
        if !seed.replayed.is_empty() {
            app.hist.events = seed.replayed;
            app.switch_tab(Tab::Events);
            app.rebuild_event_view();
        }
        // --samples FILE: import the record's machine samples and open on
        // the Samples page (cursor at the newest sample)
        if !seed.samples.is_empty() {
            app.samples = seed.samples;
            app.samples_source = seed.samples_source.clone();
            app.samples_cursor = app.samples.len() - 1;
            app.page = Page::Samples;
        }
        // --replay FILE --follow: after the one-shot history load, tail the
        // file from its current end so only new appends stream in
        if let Some(path) = &seed.replay_follow {
            match crate::history::EventTail::at_end(path) {
                Ok(tail) => app.event_tail = Some(tail),
                Err(e) => app.status = format!("--replay --follow {path}: {e}"),
            }
        }
        app.notify = seed.notify;
        // config defaults: start frozen, and sort the process table
        if seed.paused {
            app.paused = true;
            app.status = "sampling paused (config) — 'P' resumes".into();
        }
        if let Some(sort) = &seed.sort {
            if let Some(k) = sort_key_from_str(sort) {
                app.sort_key = k;
                app.rebuild_view();
            }
        }
        app.update_details(); // cold start: no debounce for the first fill
        app
    }

    /// Switch tab and pull the data that tab needs.
    fn switch_tab(&mut self, tab: Tab) {
        self.tab = tab;
        if tab == Tab::Ports {
            self.load_sockets();
            self.rebuild_socket_view();
        }
        if tab == Tab::Containers {
            self.request_containers();
        }
        if tab == Tab::Services {
            self.request_services();
        }
        if tab == Tab::Locks && self.locks_supported {
            self.load_locks();
        }
        if tab == Tab::Events {
            // events accumulated while other tabs were open — apply the
            // filter so the table isn't stale until the next refresh
            self.rebuild_event_view();
        }
        if tab == Tab::Processes {
            self.rebuild_view();
        }
        self.status.clear();
    }

    /// Sockets for the Ports tab: the full table so the 'a' toggle can
    /// widen the view without a refetch.
    fn load_sockets(&mut self) {
        self.sockets = self.platform.list_all_sockets().unwrap_or_default();
    }

    /// SIGHUP: fold a freshly built Seed's knobs onto the live app —
    /// alert thresholds, exec/webhook, notify, notes/watch lists, sampling
    /// cadence and default sort. Session state (alert latches, history,
    /// recordings) is deliberately kept: a reload moves the goalposts,
    /// not the scoreboard.
    fn reseed(&mut self, seed: &Seed) {
        self.refresh = Duration::from_secs(seed.refresh_secs.unwrap_or(REFRESH.as_secs()).max(1));
        if let Some(k) = seed.sort.as_deref().and_then(sort_key_from_str) {
            self.sort_key = k;
            self.rebuild_view();
        }
        self.notify = seed.notify;
        self.alert_cpu = seed.alert_cpu;
        self.alert_mem = seed.alert_mem;
        self.alert_fd = seed.alert_fd;
        self.alert_io = seed.alert_io;
        self.alert_conn = seed.alert_conn;
        self.alert_port = seed.alert_port.clone();
        self.alert_repeat = seed.alert_repeat;
        self.alert_load = seed.alert_load;
        self.alert_mem_pct = seed.alert_mem_pct;
        self.alert_count = seed.alert_count;
        self.alert_disk = seed.alert_disk;
        self.alert_net = seed.alert_net;
        self.alert_psi = seed.alert_psi;
        self.alert_mem_avail_mb = seed.alert_mem_avail_mb;
        self.alert_swap_pct = seed.alert_swap_pct;
        self.alert_retrans = seed.alert_retrans;
        self.alert_nic_drop = seed.alert_nic_drop;
        self.alert_exec = seed.alert_exec.clone();
        self.alert_webhook = seed.alert_webhook.clone();
        self.alert_silence = seed.alert_silence.clone();
        // a bad reload keeps the old tracker rather than disarming it
        if let Ok(np) = crate::history::NewProcWatch::parse(&seed.alert_new_proc) {
            self.new_proc = np;
        }
        self.watch = seed.watch.clone();
        self.notes = seed.notes.clone();
    }

    fn refresh(&mut self) {
        // brief-process capture: drain the high-frequency poller —
        // spawn-and-die events land in the ring (Events tab) and the log
        if let Some(rx) = &self.brief_rx {
            let mut briefs = Vec::new();
            while let Ok(e) = rx.try_recv() {
                briefs.push(e);
            }
            if !briefs.is_empty() {
                if let Some(f) = self.events_log.as_mut() {
                    use std::io::Write as _;
                    for e in &briefs {
                        if let Ok(json) = serde_json::to_string(e) {
                            let _ = writeln!(f, "{json}");
                        }
                    }
                    let _ = f.flush();
                }
                for e in briefs {
                    self.hist.ingest(vec![e]);
                }
            }
        }
        if crate::take_sighup() {
            let fresh = self.reseed_fn.as_ref().map(|build| build());
            if let Some(f) = fresh {
                self.reseed(&f);
                self.status = "SIGHUP: config reloaded".into();
            }
        }
        if let Ok(mut p) = self.platform.list_processes() {
            crate::gpu::enrich(&mut p);
            self.platform.enrich_listing(&mut p);
            // time-replay ring: bounded frames, bounded rows — sampling
            // keeps recording while you scrub, so nothing is lost while
            // you inspect the past
            let mut frame = p.clone();
            if frame.len() > REPLAY_FRAME_ROWS {
                frame.sort_by(|a, b| {
                    b.cpu.unwrap_or(0.0)
                        .partial_cmp(&a.cpu.unwrap_or(0.0))
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                frame.truncate(REPLAY_FRAME_ROWS);
            }
            self.replay_ring.push_back((crate::util::now_unix(), frame));
            while self.replay_ring.len() > REPLAY_FRAMES {
                self.replay_ring.pop_front();
            }
            let replaying = self.replay_pos.is_some();
            if !replaying {
                self.procs = p;
            }
            let fresh = if replaying {
                Vec::new()
            } else {
                self.hist.update(&self.procs)
            };
            if !fresh.is_empty() {
                if let Some(f) = self.events_log.as_mut() {
                    use std::io::Write as _;
                    for e in &fresh {
                        if let Ok(json) = serde_json::to_string(e) {
                            let _ = writeln!(f, "{json}");
                        }
                    }
                    let _ = f.flush();
                }
                // crash forensics: an exit is the only moment a "last words"
                // query is guaranteed to still hit — kick off one background
                // fetch for the dying process (restarted implies an exited
                // for the old pid, so `exited` alone covers both)
                for e in fresh.iter().filter(|e| e.kind == "exited") {
                    self.request_death_logs(e.pid, &e.name);
                }
                // desktop pings: restarts always, repeated exits (crash
                // loop) when --notify / '!' is on
                for body in self.notify_picks(&fresh) {
                    send_desktop_notify("witr-rs", &body);
                }
            }
            // --replay FILE --follow: events appended by the recording side
            // join the ring; the Events tab rebuild below picks them up
            if let Some(tail) = self.event_tail.as_mut() {
                let tailed = tail.poll();
                if !tailed.is_empty() {
                    self.hist.ingest(tailed);
                }
            }
            // --alert-fd needs descriptor counts for every pid: one sweep
            // per refresh, only when the alert is armed (cheap native reads
            // on Linux/macOS; a PowerShell sweep on Windows). A failed sweep
            // keeps the previous sample — a missing count just doesn't
            // advance any streak. An `fd>` search filter samples too, so
            // the comparison has data after the next tick.
            if self.alert_fd.is_some()
                || parse_metric_filter(&self.search)
                    .is_some_and(|f| f.metric == FilterMetric::Fd)
            {
                if let Some(counts) = self.platform.fd_counts() {
                    self.fd_counts = counts;
                }
            }
            // --alert-conn: established connections per pid, from the same
            // socket sweep the Ports tab uses (only sampled when armed)
            if self.alert_conn.is_some() {
                let socks = self.platform.list_all_sockets().unwrap_or_default();
                self.conn_counts = established_per_pid(&socks);
            }
            // --alert-net-per-proc: the ss sweep feeds the same history the
            // --top net board reads (only sampled when armed)
            if self.alert_net_per_proc.is_some() {
                if let Some(sweep) = crate::platform::net_bytes_per_pid() {
                    self.hist.update_net(&sweep);
                }
            }
            // threshold alerts (--alert-cpu / --alert-mem): a metric over
            // its limit for ALERT_CYCLES samples fires once per excursion —
            // ring record, --events-log line, desktop ping. Always notifies:
            // the flag IS the opt-in.
            // while scrubbing history the alert machinery pauses (like
            // 'P') — evaluation runs on live rows, not replayed ones
            let mut picks = if replaying { Vec::new() } else { self.alert_picks() };
            // --alert-new-proc: one pick per first-seen name the mode
            // covers (the tracker remembers, so a name never re-fires)
            if !replaying {
                if let Some(w) = self.new_proc.as_mut() {
                    for p in &self.procs {
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
            }
            if !self.alert_port.is_empty() && !replaying {
                // --alert-port: listener appear/gone edges from the same
                // socket sweep the Ports tab uses; first sighting only arms,
                // so listeners already up at startup don't fire
                let socks = self.platform.list_all_sockets().unwrap_or_default();
                picks.extend(crate::port_alert_picks(
                    &self.alert_port,
                    &socks,
                    &self.procs,
                    &mut self.port_seen,
                    &mut self.port_owner,
                ).into_iter().map(|(pid, n, d)| (pid, n, d, false)));
            }
            if !replaying
                && (self.alert_load.is_some()
                    || self.alert_mem_pct.is_some()
                    || self.alert_count.is_some()
                    || self.alert_disk.is_some()
                    || self.alert_net.is_some()
                    || self.alert_psi.is_some()
                    || self.alert_mem_avail_mb.is_some()
                    || self.alert_swap_pct.is_some()
                    || self.alert_retrans.is_some()
                    || self.alert_nic_drop.is_some())
            {
                // --alert-load / --alert-mem-pct / --alert-count /
                // --alert-disk / --alert-net: sample the whole machine when
                // armed (macOS's vm_stat / df spawns are paid only when
                // watched)
                if let Some(stats) = self.platform.system_stats() {
                    let interval = self.refresh.max(Duration::from_secs(1)).as_secs();
                    let mounts = if self.alert_disk.is_some() {
                        self.platform.mount_usage()
                    } else {
                        Vec::new()
                    };
                    // one NIC sweep feeds both the throughput and drop
                    // sentinels (the deltas live in sys_alert either way)
                    let net_armed =
                        self.alert_net.is_some() || self.alert_nic_drop.is_some();
                    let (net_rate, drop_rate) = if net_armed {
                        let nics = self.platform.net_counters();
                        let (rx, tx, drops) = nics
                            .iter()
                            .fold((0u64, 0u64, 0u64), |(rx, tx, drops), n| {
                                (
                                    rx + n.rx_bytes,
                                    tx + n.tx_bytes,
                                    drops + n.rx_drops + n.tx_drops,
                                )
                            });
                        (
                            self.alert_net
                                .is_some()
                                .then(|| {
                                    crate::history::machine_net_rate((rx, tx), &mut self.sys_alert)
                                })
                                .flatten(),
                            self.alert_nic_drop
                                .is_some()
                                .then(|| {
                                    crate::history::machine_drop_rate(drops, &mut self.sys_alert)
                                })
                                .flatten(),
                        )
                    } else {
                        (None, None)
                    };
                    let retrans_rate = if self.alert_retrans.is_some() {
                        stats.retrans_segs.and_then(|segs| {
                            crate::history::machine_retrans_rate(segs, &mut self.sys_alert)
                        })
                    } else {
                        None
                    };
                    let limits = crate::history::SysAlertLimits {
                        load: self.alert_load,
                        mem_pct: self.alert_mem_pct,
                        count: self.alert_count,
                        proc_count: self.procs.len(),
                        mounts,
                        disk_pct: self.alert_disk,
                        net_limit: self.alert_net,
                        net_rate,
                        psi_limit: self.alert_psi,
                        mem_avail_floor: self.alert_mem_avail_mb,
                        swap_pct_limit: self.alert_swap_pct,
                        retrans_limit: self.alert_retrans.map(|v| v as f64),
                        retrans_rate,
                        drop_limit: self.alert_nic_drop.map(|v| v as f64),
                        drop_rate,
                        repeat: self.alert_repeat,
                    };
                    picks.extend(
                        crate::history::system_alert_picks(
                            &stats,
                            &mut self.sys_alert,
                            &limits,
                            interval,
                        )
                        .into_iter()
                        .map(|(name, detail, rec)| (0, name, detail, rec)),
                    );
                }
            }
            for (pid, name, detail, recovery) in picks.into_iter().chain(
                self.pending_alerts
                    .drain(..)
                    .map(|(pid, n, d)| (pid, n, d, false)),
            ) {
                let kind = if recovery { "recovered" } else { "alert" };
                // 'M' mutes the session; --alert-silence holds down
                // maintenance windows — either way the pick lands in the
                // ring as "silenced" (visible on the Events tab) with no
                // line, notify, exec or webhook side effects
                let now = crate::util::now_unix() as u64;
                if self.muted || crate::history::silenced(&self.alert_silence, &name, now) {
                    let e = self.hist.push_kind("silenced", pid, &name, &detail);
                    if let Some(f) = self.events_log.as_mut() {
                        use std::io::Write as _;
                        if let Ok(json) = serde_json::to_string(&e) {
                            let _ = writeln!(f, "{json}");
                            let _ = f.flush();
                        }
                    }
                    continue;
                }
                let e = self.hist.push_kind(kind, pid, &name, &detail);
                if let Some(f) = self.events_log.as_mut() {
                    use std::io::Write as _;
                    if let Ok(json) = serde_json::to_string(&e) {
                        let _ = writeln!(f, "{json}");
                        let _ = f.flush();
                    }
                }
                send_desktop_notify("witr-rs", &format!("{name}: {detail}"));
                if let Some(cmd) = &self.alert_exec {
                    spawn_alert_exec(cmd, pid, &name, &detail, kind);
                }
                if let Some(hook) = &self.alert_webhook {
                    send_alert_webhook(hook, pid, &name, &detail, kind);
                }
                self.status = format!(
                    "{} {name} — {detail}",
                    if recovery { "RECOVERED" } else { "ALERT" }
                );
            }
        }
        // System page ('y'): Linux's three /proc reads are µs-cheap, so
        // they sample every cycle and history is already there when the
        // page opens. macOS (vm_stat spawn) and Windows (PowerShell) only
        // sample while the page is open.
        if self.page == Page::System || self.platform.name() == "linux" {
            if let Some(s) = self.platform.system_stats() {
                self.hist.update_system(s.clone());
                self.sys_stats = Some(s);
            }
            if self.page == Page::System {
                self.sys_mounts = self.platform.mount_usage();
            }
            // net section: Windows pays a PowerShell subprocess per sweep
            // (page open only); Linux's /proc/net/dev and macOS's
            // NET_RT_IFLIST2 sysctl reads are µs-cheap, so they sample with
            // system_stats and the chart is already full when the page
            // opens. An empty sweep (no NICs reported) keeps the previous
            // rows visible rather than flashing the section off.
            if self.page == Page::System || self.platform.name() != "windows" {
                self.sample_net_rates();
            }
        }
        // FD sampling for the fd chart + leak suspicion: only while the
        // full detail page shows this pid (same gating as the system page;
        // Linux a /proc read, macOS a native libproc call, Windows a
        // full-table handle sweep via the fd_counts fallback)
        if self.page == Page::Detail {
            if let Some(pid) = self.detail_pid {
                let n = match self.platform.fd_count(pid) {
                    Some(n) => Some(n),
                    // per-pid unavailable (Windows): the whole-table sweep
                    // answers for every pid at once — same cost class as a
                    // single read, so it's fine behind this gate
                    None => self.platform.fd_counts().and_then(|m| m.get(&pid).copied()),
                };
                if let Some(n) = n {
                    self.hist.record_fd(pid, n);
                }
                // live charts: re-render the page from the open-time cache
                // so cpu/mem/fd/io sections track samples taken since open
                self.render_detail_page(pid);
            }
        }
        if self.tab == Tab::Ports {
            self.load_sockets();
            self.rebuild_socket_view();
        }
        if self.tab == Tab::Containers {
            self.request_containers();
            self.request_container_stats();
        }
        if self.tab == Tab::Services {
            self.request_services();
        }
        // Locks: Linux re-reads /proc/locks every cycle (a cheap file
        // read); macOS would re-run a full `lsof` scan (1-2s), so its
        // snapshot only refreshes on tab switch.
        if self.tab == Tab::Locks && self.platform.name() == "linux" {
            self.load_locks();
        }
        self.rebuild_view();
        if self.tab == Tab::Events {
            // hist.update() above appended new events; reapply the filter
            self.rebuild_event_view();
        }
        self.last_refresh = Instant::now();
    }

    /// Kick off a background container enumeration (no-op while one is
    /// already in flight).
    fn request_containers(&mut self) {
        if self.containers_loading {
            return;
        }
        self.containers_loading = true;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut cs = crate::platform::enumerate_containers();
            // pod attribution rides the same background thread (kubectl
            // adds ~1s when a cluster is reachable); the pod snapshot also
            // feeds the pod-alert edges (phase / waiting / restart climbs)
            let pods = crate::k8s::pods().unwrap_or_default();
            crate::k8s::annotate_with(&pods, &mut cs);
            // restart counts per running container (one inspect each) feed
            // the crash-loop edge detector; None is fine on failure
            for c in cs.iter_mut().filter(|c| c.state == "running") {
                if c.restarts.is_none() {
                    c.restarts = crate::platform::container_restarts(&c.runtime, &c.id);
                }
            }
            // cgroup pressure readings (throttle time + oom_kill totals)
            // merge by 12-char id prefix — a Linux-only sweep of a few
            // file reads, no runtime CLI involved
            let pressure = crate::platform::container_pressure();
            for c in cs.iter_mut() {
                if c.throttled_usec.is_some() && c.oom_kills.is_some() {
                    continue;
                }
                let key: String = c.id.chars().take(12).collect();
                if let Some(p) = pressure.get(&key) {
                    c.throttled_usec = Some(p.throttled_usec);
                    c.oom_kills = Some(p.oom_kills);
                }
            }
            let _ = tx.send((cs, pods));
        });
        self.containers_rx = Some(rx);
    }

    /// Pick up finished background enumeration, if any.
    fn poll_containers(&mut self) {
        if !self.containers_loading {
            return;
        }
        let arrived = self.containers_rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some((cs, pods)) = arrived {
            self.containers = cs;
            self.containers_loading = false;
            self.containers_loaded = true;
            self.containers_rx = None;
            // the events stream rides the first successful enumeration: a
            // runtime that answered `ps` should answer `events` too, moving
            // death/OOM/health edges from sweep-diff to instant
            if !self.container_events_tried {
                self.container_events_tried = true;
                self.container_events = crate::history::spawn_container_events();
            }
            // throttle percent per container: diff this sweep's cumulative
            // throttled_usec against the previous one over the elapsed wall
            // time (the first sweep only arms the baseline)
            let now_instant = Instant::now();
            for c in self.containers.iter().filter(|c| c.throttled_usec.is_some()) {
                let key: String = c.id.chars().take(12).collect();
                let cur = c.throttled_usec.unwrap_or(0);
                if let Some((prev, at)) = self.throttle_prev.get(&key) {
                    let elapsed = now_instant.duration_since(*at).as_micros() as f64;
                    if elapsed > 0.0 {
                        let pct = (cur.saturating_sub(*prev) as f64 / elapsed * 100.0).clamp(0.0, 100.0);
                        self.throttle_pct.insert(key.clone(), pct);
                    }
                }
                self.throttle_prev.insert(key, (cur, now_instant));
            }
            self.container_alert_edges(&self.containers.clone(), &pods);
            self.apply_container_stats();
            self.rebuild_container_view();
        }
    }

    /// Drain the container events stream into the ring; a death edge also
    /// kicks a fresh enumeration so the table reflects it within a tick.
    /// A disconnected stream (runtime CLI exited — daemon restart?) resets
    /// the one-shot spawn so the next sweep re-arms it, and the
    /// enumeration-diff edges cover the gap meanwhile.
    fn poll_container_events(&mut self) {
        let mut events = Vec::new();
        let mut dead_stream = false;
        if let Some(stream) = &self.container_events {
            loop {
                match stream.rx.try_recv() {
                    Ok(e) => events.push(e),
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        dead_stream = true;
                        break;
                    }
                }
            }
        }
        if dead_stream {
            self.container_events = None;
            self.container_events_tried = false;
        }
        let deaths = events
            .iter()
            .filter(|e| e.kind == "container-death")
            .count();
        for e in events {
            self.hist.ingest(vec![e]);
        }
        if deaths > 0 {
            self.request_containers();
        }
    }

    /// Container death / crash-loop edges: the fresh enumeration vs the
    /// previous one. Delegates to the shared [`crate::history::ContainerEdges`]
    /// core (the headless `--watch --alert-container` sentinel runs the
    /// same detector); firings land in `pending_alerts` like every other
    /// alert channel. The death edge never fires while the `events` stream
    /// is live — that channel owns instant death reporting (the sweep-diff
    /// stays as the fallback when the stream couldn't spawn).
    fn container_alert_edges(
        &mut self,
        cs: &[crate::model::Container],
        pods: &[crate::k8s::Pod],
    ) {
        let stream_live = self.container_events.is_some();
        for (name, detail) in self.container_edges.update(cs, pods, stream_live) {
            self.pending_alerts.push((0, name, detail));
        }
    }

    /// Kick off a background `stats --no-stream` sweep (no-op while one is
    /// in flight or the last one is younger than ~10s — each runtime CLI
    /// needs ~2s to sample, so this can't follow the listing's cadence).
    fn request_container_stats(&mut self) {
        if self.container_stats_loading
            || self
                .container_stats_at
                .is_some_and(|t| t.elapsed() < Duration::from_secs(10))
        {
            return;
        }
        self.container_stats_loading = true;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(crate::platform::container_stats());
        });
        self.container_stats_rx = Some(rx);
    }

    /// Pick up a finished stats sweep and fold it into the table.
    fn poll_container_stats(&mut self) {
        if !self.container_stats_loading {
            return;
        }
        let arrived = self
            .container_stats_rx
            .as_ref()
            .and_then(|rx| rx.try_recv().ok());
        if let Some(stats) = arrived {
            self.container_stats = stats;
            self.container_stats_at = Some(Instant::now());
            self.container_stats_loading = false;
            self.container_stats_rx = None;
            self.apply_container_stats();
            self.rebuild_container_view();
        }
    }

    /// Merge cached stats sweeps into `self.containers` by id (exact, then
    /// 12-char prefix — runtimes may abbreviate either side). Re-enumerations
    /// wipe the merged fields; this reapplies them.
    fn apply_container_stats(&mut self) {
        if self.container_stats.is_empty() {
            return;
        }
        for c in &mut self.containers {
            let hit = self
                .container_stats
                .get(&c.id)
                .or_else(|| {
                    let prefix: String = c.id.chars().take(12).collect();
                    self.container_stats
                        .iter()
                        .find(|(k, _)| k.starts_with(&prefix))
                        .map(|(_, v)| v)
                })
                .copied();
            if let Some((cpu, used, total)) = hit {
                c.cpu_pct = Some(cpu);
                c.mem_used_mb = Some(used / (1024 * 1024));
                c.mem_total_mb = Some(total / (1024 * 1024));
            }
        }
    }

    /// Kick off a background service enumeration (no-op while one is in
    /// flight) — systemctl list-units can take a second on loaded hosts.
    fn request_services(&mut self) {
        if self.services_loading {
            return;
        }
        self.services_loading = true;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(crate::platform::enumerate_services());
        });
        self.services_rx = Some(rx);
    }

    /// Pick up finished service enumeration, if any.
    fn poll_services(&mut self) {
        if !self.services_loading {
            return;
        }
        let arrived = self.services_rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some(ss) = arrived {
            self.services = ss;
            self.services_loading = false;
            self.services_rx = None;
            self.rebuild_service_view();
        }
    }

    /// Enter on a Services row: jump into the unit's main process. launchd
    /// / SCM listings carry the pid inline; systemd resolves MainPID on
    /// demand (one quick `systemctl show` call).
    fn open_service_detail(&mut self) {
        let Some(svc) = self
            .table_state
            .selected()
            .and_then(|i| self.service_view.get(i))
            .map(|&i| self.services[i].clone())
        else {
            return;
        };
        let pid = svc.pid.or_else(|| crate::platform::service_pid_of(&svc));
        match pid {
            Some(pid) if self.procs.iter().any(|p| p.pid == pid) => {
                self.open_detail_page_for(pid);
            }
            Some(pid) => self.status = format!("pid {pid} has exited — details unavailable"),
            None => self.status = format!("{} is not running (no main pid)", svc.name),
        }
    }

    /// Open the Logs page for a resolved source, fetching in the background
    /// (journalctl / log show / docker logs all take seconds).
    fn open_logs(&mut self, src: crate::logs::LogSource) {
        let header = src.describe();
        self.logs_for = Some(header);
        self.logs_src = Some(src.clone());
        self.logs_lines.clear();
        self.logs_scroll = 0;
        self.page = Page::Logs;
        let (tx, rx) = std::sync::mpsc::channel();
        self.logs_rx = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(crate::logs::fetch(&src, 200));
        });
    }

    /// Compute the session digest and open the summary page ('S'). The
    /// snapshot is taken at open time — 'r' on the page re-computes.
    fn open_summary(&mut self) {
        self.summary = Some(self.hist.summary(self.summary_window));
        self.logs_scroll = 0;
        self.page = Page::Summary;
    }

    /// Open the system resources page ('y') with one immediate sample so
    /// memory/load show at once — CPU is delta-based and arrives on the
    /// next refresh (this call was the first of the two it needs).
    fn open_system(&mut self) {
        if let Some(s) = self.platform.system_stats() {
            self.hist.update_system(s.clone());
            self.sys_stats = Some(s);
        }
        self.logs_scroll = 0;
        self.page = Page::System;
    }

    /// Open the snapshot-diff page ('D'): diff the newest auto snapshot
    /// (`--snap` with no FILE writes it) against the live table. Computed
    /// at open time — 'r' on the page re-diffs. The CLI's `--diff` is the
    /// scripted twin of this page.
    fn open_diff_page(&mut self) {
        let Some(path) = crate::snapshot::newest_auto() else {
            self.status = "no auto snapshots yet — run `witr --snap` once to seed one".into();
            return;
        };
        match crate::snapshot::load(&path.to_string_lossy()) {
            Ok((old, old_listeners)) => {
                let mut entries = crate::snapshot::diff(&old, &self.procs);
                if !old_listeners.is_empty() {
                    let now = crate::snapshot::to_listeners(
                        &self.platform.list_sockets().unwrap_or_default(),
                        &self.procs,
                    );
                    entries.extend(crate::snapshot::diff_listeners(&old_listeners, &now));
                }
                self.diff_entries = entries;
                self.diff_source = path.display().to_string();
                self.diff_sel = 0;
                self.logs_scroll = 0;
                self.page = Page::Diff;
            }
            Err(e) => {
                self.status = format!("snapshot {}: {e}", path.display());
            }
        }
    }

    /// Lines for the snapshot-diff page ('D') — shared by the renderer and
    /// the 'c' copy. One row per entry; kind carries the color.
    fn diff_page_lines(&self) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();
        if self.diff_source.is_empty() {
            lines.push(Line::from(styled(
                Style::new().fg(MID),
                "no snapshot compared yet",
            )));
            return lines;
        }
        lines.push(Line::from(vec![
            Span::styled("vs        ", Style::new().bold()),
            Span::raw(self.diff_source.clone()),
        ]));
        let counts = |k: &str| self.diff_entries.iter().filter(|e| e.kind == k).count();
        lines.push(Line::from(vec![
            Span::styled("summary   ", Style::new().bold()),
            Span::raw(format!(
                "{} new · {} gone · {} restarted · {} changed · {} listen+ · {} listen-",
                counts("new"),
                counts("gone"),
                counts("restarted"),
                counts("changed"),
                counts("listen-new"),
                counts("listen-gone")
            )),
        ]));
        lines.push(Line::from(Span::styled(
            format!("{:>9}  {:>7}  {:<22} {}", "KIND", "PID", "NAME", "DETAIL"),
            Style::new().fg(ACCENT).bold(),
        )));
        for (i, e) in self.diff_entries.iter().enumerate() {
            let color = match e.kind {
                "new" => Color::Green,
                "gone" => Color::Red,
                "restarted" => Color::Yellow,
                "listen-new" => Color::Cyan,
                "listen-gone" => Color::Magenta,
                _ => Color::Blue,
            };
            let marker = if i == self.diff_sel { "▸" } else { " " };
            let text = format!(
                "{marker}{:>9}  {:>7}  {:<22} {}",
                e.kind, e.pid, e.name, e.detail
            );
            let span = if i == self.diff_sel {
                Span::styled(text, Style::new().fg(color).bold())
            } else {
                Span::styled(text, Style::new().fg(color))
            };
            lines.push(Line::from(span));
        }
        if self.diff_entries.is_empty() {
            lines.push(Line::from(styled(
                Style::new().fg(MID),
                "no differences — the machine looks like the snapshot",
            )));
        }
        lines
    }

    /// The Samples page's chartable series: label, unit, per-sample values.
    fn samples_series(&self, k: usize) -> (&'static str, &'static str, Vec<Option<f64>>) {
        let pts = &self.samples;
        match k % SAMPLE_SERIES {
            0 => ("cpu %", "%", pts.iter().map(|p| p.cpu).collect()),
            1 => ("memory %", "%", pts.iter().map(|p| p.mem_pct).collect()),
            2 => ("load 1m", "", pts.iter().map(|p| p.load1).collect()),
            3 => (
                "network",
                "MB/s",
                pts.iter().map(|p| p.net_bps.map(|b| b / 1048576.0)).collect(),
            ),
            _ => (
                "processes",
                "",
                pts.iter().map(|p| Some(p.procs as f64)).collect(),
            ),
        }
    }

    /// Lines for the --samples page — shared by the renderer and the 'c'
    /// copy. `width` bounds the sparkline (the copy path passes 0 → a
    /// modest default).
    fn samples_page_lines(&self, width: usize) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();
        if self.samples.is_empty() {
            lines.push(Line::from(styled(
                Style::new().fg(MID),
                "no samples loaded — open one with --samples FILE (a --record .csv/.jsonl)",
            )));
            return lines;
        }
        let n = self.samples.len();
        let t0 = crate::util::fmt_time(self.samples[0].at);
        let t1 = crate::util::fmt_time(self.samples[n - 1].at);
        lines.push(Line::from(vec![
            Span::styled("from      ", Style::new().bold()),
            Span::raw(format!("{0} · {n} samples · {t0} – {t1}", self.samples_source)),
        ]));
        let k = self.samples_series % SAMPLE_SERIES;
        let (name, _unit, values) = self.samples_series(k);
        let inner = width.saturating_sub(12).clamp(20, 400);
        let (cells, cur) = spark_row(&values, inner, self.samples_cursor);
        let mut spans: Vec<Span<'static>> = vec![Span::styled(
            format!("{name:<12}"),
            Style::new().fg(ACCENT).bold(),
        )];
        for (i, ch) in cells.iter().enumerate() {
            let style = if Some(i) == cur {
                Style::new().fg(Color::White).bg(ACCENT)
            } else {
                Style::new().fg(ACCENT)
            };
            spans.push(Span::styled(ch.to_string(), style));
        }
        lines.push(Line::from(spans));
        // every series' value at the cursor — the numeric readout under
        // the chart
        let p = &self.samples[self.samples_cursor];
        let at = crate::util::fmt_time(p.at);
        let f = |v: Option<f64>, unit: &str| match v {
            Some(v) => format!("{v:.1}{unit}"),
            None => "-".into(),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{:>10}", at.get(at.len() - 8..).unwrap_or("")), Style::new().bold()),
            Span::raw(format!(
                "  cpu {}  mem {}  load {}  net {}  procs {}",
                f(p.cpu, "%"),
                f(p.mem_pct, "%"),
                f(p.load1, ""),
                f(p.net_bps.map(|b| b / 1048576.0), "MB/s"),
                p.procs,
            )),
        ]));
        lines.push(Line::from(styled(
            Style::new().fg(MID),
            "←/→ h/l: move · ↑/↓ j/k: series · g/G: ends · Esc: back",
        )));
        lines
    }

    /// Lines for the system resources page ('y') — shared by the renderer
    /// and the 'c' copy. Charts come from the history rings, "now" values
    /// (load, swap, per-core grid) from the latest snapshot.
    /// One net_counters sweep → per-NIC MB/s rows + the total-rate history
    /// sample for the y page. The first sweep only arms the counters (no
    /// previous to diff against, rows stay empty); counter resets (NIC
    /// bounce) diff as zero rather than a negative rate.
    fn sample_net_rates(&mut self) {
        let nics = self.platform.net_counters();
        if nics.is_empty() {
            return;
        }
        let now = Instant::now();
        let elapsed = self
            .sys_net_prev_at
            .map(|t| now.duration_since(t).as_secs_f64());
        let mut rows = Vec::new();
        let mut total = 0.0f64;
        for n in nics {
            let (rx, tx) = match self.sys_net_prev.get(&n.name) {
                Some((prx, ptx)) => (
                    n.rx_bytes.saturating_sub(*prx) as f64,
                    n.tx_bytes.saturating_sub(*ptx) as f64,
                ),
                None => (0.0, 0.0),
            };
            let (rx, tx) = match elapsed {
                Some(e) if e > 0.0 => (rx / e / 1048576.0, tx / e / 1048576.0),
                _ => (0.0, 0.0),
            };
            total += rx + tx;
            rows.push((n.name.clone(), rx, tx));
            self.sys_net_prev.insert(n.name, (n.rx_bytes, n.tx_bytes));
        }
        self.sys_net_prev_at = Some(now);
        self.sys_net_rows = rows;
        self.sys_net_hist.push(total);
        while self.sys_net_hist.len() > 60 {
            self.sys_net_hist.remove(0);
        }
    }

    fn system_page_lines(&self) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();
        let Some(stats) = self.sys_stats.as_ref() else {
            lines.push(Line::from(styled(
                Style::new().fg(MID),
                "waiting for samples — the first refresh fills memory and load, the second draws CPU",
            )));
            return lines;
        };
        // cpu history (fixed 0–100 scale — the max is known)
        let cpu = match self.hist.sys_cpu_chart(60) {
            Some((bars, now, peak)) => Line::from(vec![
                Span::styled("cpu     ", Style::new().bold()),
                Span::raw(bars),
                Span::raw(format!("  {now:.0}% now · window peak {peak:.0}%")),
            ]),
            None => Line::from(styled(
                Style::new().fg(MID),
                "cpu     one more refresh needed (usage is a delta between samples)",
            )),
        };
        lines.push(cpu);
        // load average
        if stats.load1.is_some() {
            let f = |v: Option<f64>| v.map(|x| format!("{x:.2}")).unwrap_or_else(|| "–".into());
            lines.push(Line::from(vec![
                Span::styled("load    ", Style::new().bold()),
                Span::raw(format!(
                    "{} · {} · {}  (1/5/15 min)",
                    f(stats.load1),
                    f(stats.load5),
                    f(stats.load15)
                )),
            ]));
        }
        // memory: now/total even before the chart has two samples
        let mem_now = match (stats.mem_used_mb, stats.mem_total_mb) {
            (Some(u), Some(t)) if t > 0 => format!(
                "{} / {} used ({:.0}%)",
                human_mb(u),
                human_mb(t),
                u as f64 / t as f64 * 100.0
            ),
            (Some(u), _) => format!("{} used", human_mb(u)),
            _ => "unavailable".into(),
        };
        let mut mem_spans = vec![Span::styled("memory  ", Style::new().bold())];
        match self.hist.sys_mem_chart(60) {
            Some((bars, _, peak)) => {
                mem_spans.push(Span::raw(format!("{}  ", human_mb(peak as u64))));
                mem_spans.push(Span::raw(bars));
                mem_spans.push(Span::raw(format!("  {mem_now}")));
            }
            None => mem_spans.push(Span::raw(mem_now)),
        }
        lines.push(Line::from(mem_spans));
        // swap
        if let (Some(u), Some(t)) = (stats.swap_used_mb, stats.swap_total_mb) {
            lines.push(Line::from(vec![
                Span::styled("swap    ", Style::new().bold()),
                Span::raw(if t > 0 {
                    format!("{} / {} used ({:.0}%)", human_mb(u), human_mb(t), u as f64 / t as f64 * 100.0)
                } else {
                    "0 B / 0 B".into()
                }),
            ]));
        }
        // per-core grid, two cores per row; saturated cores render red
        if !stats.cores.is_empty() {
            lines.push(Line::from(Span::styled("cores", Style::new().bold())));
            for (row, pair) in stats.cores.chunks(2).enumerate() {
                let mut spans = Vec::new();
                for (col, pct) in pair.iter().enumerate() {
                    let n = ((pct / 100.0).clamp(0.0, 0.999) * 10.0) as usize;
                    let text = format!(
                        "  {:>2} │{}{}│ {:>3.0}%  ",
                        row * 2 + col,
                        "█".repeat(n),
                        "░".repeat(10 - n),
                        pct
                    );
                    spans.push(if *pct >= 90.0 {
                        Span::styled(text, Style::new().fg(Color::Red))
                    } else {
                        Span::raw(text)
                    });
                }
                lines.push(Line::from(spans));
            }
        }
        // disk: one bar per device-backed mount; ≥90% full renders red
        if !self.sys_mounts.is_empty() {
            lines.push(Line::from(Span::styled("disk", Style::new().bold())));
            for m in self.sys_mounts.iter().take(8) {
                let pct = if m.total_mb > 0 {
                    m.used_mb as f64 / m.total_mb as f64 * 100.0
                } else {
                    0.0
                };
                let n = ((pct / 100.0).clamp(0.0, 0.999) * 10.0) as usize;
                let text = format!(
                    "  {:<24}│{}{}│ {:>3.0}%  {} / {}",
                    m.target,
                    "█".repeat(n),
                    "░".repeat(10 - n),
                    pct,
                    human_mb(m.used_mb),
                    human_mb(m.total_mb)
                );
                lines.push(Line::from(if pct >= 90.0 {
                    Span::styled(text, Style::new().fg(Color::Red))
                } else {
                    Span::raw(text)
                }));
            }
        }
        // network: total-rate sparkline (window peak annotated) plus one
        // row per non-loopback NIC — ↓ rx ↑ tx MB/s. Rates need two sweeps,
        // so the section appears on the second refresh.
        if !self.sys_net_rows.is_empty() {
            lines.push(Line::from(Span::styled("net", Style::new().bold())));
            let peak = self
                .sys_net_hist
                .iter()
                .copied()
                .fold(0.0f64, f64::max)
                .max(1.0);
            let bars: String = self
                .sys_net_hist
                .iter()
                .map(|v| {
                    let idx = ((v / peak).clamp(0.0, 0.999) * 8.0) as usize;
                    crate::history::SPARK_LEVELS[idx]
                })
                .collect();
            let now = self.sys_net_hist.last().copied().unwrap_or(0.0);
            lines.push(Line::from(vec![
                Span::raw(bars),
                Span::raw(format!("  {now:.1} MB/s now · peak {peak:.1}")),
            ]));
            let mut rows = self.sys_net_rows.clone();
            rows.sort_by(|a, b| {
                (b.1 + b.2)
                    .total_cmp(&(a.1 + a.2))
                    .then_with(|| a.0.cmp(&b.0))
            });
            for (name, rx, tx) in rows.iter().take(8) {
                lines.push(Line::from(format!(
                    "  {name:<24}↓ {rx:>7.1}  ↑ {tx:>7.1} MB/s"
                )));
            }
        }
        // pressure stall information (Linux PSI): some/full avg10 per
        // resource; full ≥10% paints red — everything stalled on that
        // resource is the "machine is dying" signature
        if let Some(psi) = &stats.psi {
            lines.push(Line::from(vec![
                Span::styled("pressure", Style::new().bold()),
                Span::raw(format!(
                    "  (some/full %, last 10s)  {}",
                    psi.line()
                )),
            ]));
            let worst = psi.worst_full();
            if worst > 0.0 {
                let text = format!("  worst full {worst:.1}%");
                lines.push(Line::from(if worst >= 10.0 {
                    Span::styled(text, Style::new().fg(Color::Red).bold())
                } else if worst >= 1.0 {
                    Span::styled(text, Style::new().fg(Color::Yellow))
                } else {
                    Span::styled(text, Style::new().fg(MID))
                }));
            }
        }
        // hottest thermal sensor (Linux hwmon): ≥80°C red, ≥65°C yellow
        if let Some((label, c)) = &stats.temp {
            let text = format!("temp    {c:.1}°C  ({label})");
            lines.push(Line::from(if *c >= 80.0 {
                Span::styled(text, Style::new().fg(Color::Red).bold())
            } else if *c >= 65.0 {
                Span::styled(text, Style::new().fg(Color::Yellow))
            } else {
                Span::raw(text)
            }));
        }
        lines
    }

    /// Logs for whatever the process-detail cursor is on: the attribution's
    /// container source (cgroup) wins when present, then the container
    /// identity line, then the platform log system.
    fn open_logs_for_detail(&mut self) {
        let source = self.detail_report.as_ref().and_then(|r| {
            if r.source.as_ref().is_some_and(|s| s.kind == "container") {
                let s = r.source.as_ref().unwrap();
                let runtime = s
                    .detail
                    .as_deref()
                    .and_then(|d| d.strip_prefix("runtime: "))
                    .unwrap_or("docker")
                    .to_string();
                let ref_ = s.label.clone().unwrap_or_default();
                if !ref_.is_empty() {
                    return Some(crate::logs::LogSource::Container { runtime, ref_ });
                }
            }
            r.matches.first().map(crate::logs::LogSource::for_process)
        });
        match source {
            Some(src) => self.open_logs(src),
            None => self.status = "no process selected".into(),
        }
    }

    /// Crash forensics: is there room to start a death-logs fetch for `pid`?
    /// One in-flight fetch at a time; processes already captured are skipped.
    fn death_fetch_needed(&self, pid: Pid) -> bool {
        self.death_rx.is_none() && !self.death_logs.iter().any(|(p, _)| *p == pid)
    }

    /// Kick off the background "last words" fetch for a process that just
    /// exited. Best-effort and throttled to one at a time — a mass exit
    /// (crashed supervisor) captures the first victim, which shares the
    /// crash anyway.
    fn request_death_logs(&mut self, pid: Pid, name: &str) {
        if !self.death_fetch_needed(pid) {
            return;
        }
        let src = death_log_source(self.platform.name(), pid, name);
        let (tx, rx) = std::sync::mpsc::channel();
        self.death_rx = Some(rx);
        std::thread::spawn(move || {
            let res = crate::logs::fetch(&src, DEATH_LINES);
            let _ = tx.send((pid, res));
        });
    }

    /// Collect a finished death-logs fetch into the forensics cache.
    fn poll_death_logs(&mut self) {
        let Some(rx) = &self.death_rx else { return };
        if let Ok((pid, res)) = rx.try_recv() {
            self.death_rx = None;
            if let Ok(lines) = res {
                if !lines.is_empty() {
                    if self.death_logs.len() >= DEATH_CAP {
                        self.death_logs.pop_front();
                    }
                    self.death_logs.push_back((pid, lines));
                }
            }
        }
    }

    /// Which fresh events deserve a desktop notification, updating the
    /// per-name restart tally: every restart notifies; a plain exit only
    /// notifies once its name has restarted ≥2 times this session (a
    /// crash loop in progress).
    fn notify_picks(&mut self, fresh: &[crate::history::TuiEvent]) -> Vec<String> {
        if !self.notify {
            return Vec::new();
        }
        let mut out = Vec::new();
        for e in fresh {
            match e.kind.as_str() {
                "restarted" => {
                    *self.restart_tally.entry(e.name.clone()).or_insert(0) += 1;
                    out.push(format!("{} restarted — now pid {}", e.name, e.pid));
                }
                "exited" => {
                    let looped = self.restart_tally.get(&e.name).copied().unwrap_or(0) >= 2;
                    if looped {
                        out.push(format!("{} (pid {}) exited again — crash loop?", e.name, e.pid));
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// Check every visible process against the alert thresholds. Returns
    /// (pid, name, detail, is_recovery) for excursions that just crossed
    /// ALERT_CYCLES — or that just dropped back under after firing (the
    /// recovery edge). CPU comes from the sampler's instantaneous percents;
    /// RSS straight from the current listing (mem_kb is KiB, thresholds are
    /// MB); fd counts from the last sweep (only sampled when alert_fd is
    /// set); I/O rates from the sampler's cumulative deltas (Linux). Also
    /// prunes bookkeeping for pids that left the table.
    fn alert_picks(&mut self) -> Vec<(Pid, String, String, bool)> {
        if self.alert_cpu.is_none()
            && self.alert_mem.is_none()
            && self.alert_fd.is_none()
            && self.alert_io.is_none()
            && self.alert_conn.is_none()
            && self.alert_threads.is_none()
            && self.alert_net_per_proc.is_none()
            && self.alert_deviation.is_none()
        {
            return Vec::new();
        }
        let interval = self.refresh.max(Duration::from_secs(1)).as_secs();
        let secs = ALERT_CYCLES as u64 * interval;
        let mut out = Vec::new();
        for p in &self.procs {
            let track = self.alert_state.entry(p.pid).or_default();
            if let Some(limit) = self.alert_cpu {
                let now = self.hist.cpu_now.get(&p.pid).copied();
                let over = now.is_some_and(|c| c > limit);
                let edge = crate::history::alert_cycle_repeat(
                    &mut track.cpu_streak,
                    &mut track.cpu_firing,
                    over,
                    &mut track.cpu_fired_secs,
                    self.alert_repeat,
                    interval,
                );
                if edge == crate::history::AlertEdge::Fire {
                    out.push((
                        p.pid,
                        p.name.clone(),
                        format!("CPU {:.0}% above {limit:.0}% for {secs}s", now.unwrap_or(0.0)),
                        false,
                    ));
                } else if edge == crate::history::AlertEdge::Recover {
                    out.push((
                        p.pid,
                        p.name.clone(),
                        format!("CPU back under {limit:.0}%"),
                        true,
                    ));
                }
            }
            if let Some(limit_mb) = self.alert_mem {
                let mb = p.mem_kb.map(|kb| kb / 1024);
                let over = mb.is_some_and(|m| m > limit_mb);
                let edge = crate::history::alert_cycle_repeat(
                    &mut track.mem_streak,
                    &mut track.mem_firing,
                    over,
                    &mut track.mem_fired_secs,
                    self.alert_repeat,
                    interval,
                );
                if edge == crate::history::AlertEdge::Fire {
                    out.push((
                        p.pid,
                        p.name.clone(),
                        format!("RSS {} MB above {limit_mb} MB for {secs}s", mb.unwrap_or(0)),
                        false,
                    ));
                } else if edge == crate::history::AlertEdge::Recover {
                    out.push((p.pid, p.name.clone(), format!("RSS back under {limit_mb} MB"), true));
                }
            }
            if let Some(limit) = self.alert_fd {
                let n = self.fd_counts.get(&p.pid).copied();
                let over = n.is_some_and(|c| c > limit);
                let edge = crate::history::alert_cycle_repeat(
                    &mut track.fd_streak,
                    &mut track.fd_firing,
                    over,
                    &mut track.fd_fired_secs,
                    self.alert_repeat,
                    interval,
                );
                if edge == crate::history::AlertEdge::Fire {
                    out.push((
                        p.pid,
                        p.name.clone(),
                        format!(
                            "{} open fds above {limit} for {secs}s",
                            n.unwrap_or(0)
                        ),
                        false,
                    ));
                } else if edge == crate::history::AlertEdge::Recover {
                    out.push((p.pid, p.name.clone(), format!("open fds back under {limit}"), true));
                }
            }
            if let Some(limit_mbps) = self.alert_io {
                let bps = self.hist.io_rate_of(p.pid).map(|(r, w)| r + w);
                let over = bps.is_some_and(|b| b > limit_mbps * 1024.0 * 1024.0);
                let edge = crate::history::alert_cycle_repeat(
                    &mut track.io_streak,
                    &mut track.io_firing,
                    over,
                    &mut track.io_fired_secs,
                    self.alert_repeat,
                    interval,
                );
                if edge == crate::history::AlertEdge::Fire {
                    out.push((
                        p.pid,
                        p.name.clone(),
                        format!(
                            "I/O {:.1} MB/s above {limit_mbps} MB/s for {secs}s",
                            bps.unwrap_or(0.0) / 1024.0 / 1024.0
                        ),
                        false,
                    ));
                } else if edge == crate::history::AlertEdge::Recover {
                    out.push((
                        p.pid,
                        p.name.clone(),
                        format!("I/O back under {limit_mbps} MB/s"),
                        true,
                    ));
                }
            }
            if let Some(limit) = self.alert_conn {
                let n = self.conn_counts.get(&p.pid).copied();
                let over = n.is_some_and(|c| c > limit);
                let edge = crate::history::alert_cycle_repeat(
                    &mut track.conn_streak,
                    &mut track.conn_firing,
                    over,
                    &mut track.conn_fired_secs,
                    self.alert_repeat,
                    interval,
                );
                if edge == crate::history::AlertEdge::Fire {
                    out.push((
                        p.pid,
                        p.name.clone(),
                        format!(
                            "{} established connection(s) above {limit} for {secs}s",
                            n.unwrap_or(0)
                        ),
                        false,
                    ));
                } else if edge == crate::history::AlertEdge::Recover {
                    out.push((
                        p.pid,
                        p.name.clone(),
                        format!("connections back under {limit}"),
                        true,
                    ));
                }
            }
            if let Some(limit) = self.alert_threads {
                let n = p.threads.map(|t| t as u64);
                let over = n.is_some_and(|c| c > limit);
                let edge = crate::history::alert_cycle_repeat(
                    &mut track.threads_streak,
                    &mut track.threads_firing,
                    over,
                    &mut track.threads_fired_secs,
                    self.alert_repeat,
                    interval,
                );
                if edge == crate::history::AlertEdge::Fire {
                    out.push((
                        p.pid,
                        p.name.clone(),
                        format!("{} thread(s) above {limit} for {secs}s", n.unwrap_or(0)),
                        false,
                    ));
                } else if edge == crate::history::AlertEdge::Recover {
                    out.push((p.pid, p.name.clone(), format!("threads back under {limit}"), true));
                }
            }
            if let Some(factor) = self.alert_deviation {
                let msg = self.hist.deviation_of(p.pid, factor);
                let edge = crate::history::alert_cycle_repeat(
                    &mut track.dev_streak,
                    &mut track.dev_firing,
                    msg.is_some(),
                    &mut track.dev_fired_secs,
                    self.alert_repeat,
                    interval,
                );
                if edge == crate::history::AlertEdge::Fire {
                    out.push((
                        p.pid,
                        p.name.clone(),
                        msg.unwrap_or_else(|| "deviated from its own baseline".into()),
                        false,
                    ));
                } else if edge == crate::history::AlertEdge::Recover {
                    out.push((
                        p.pid,
                        p.name.clone(),
                        "back near its own baseline".to_string(),
                        true,
                    ));
                }
            }
        }
        let seen: std::collections::HashSet<Pid> = self.procs.iter().map(|p| p.pid).collect();
        self.alert_state.retain(|pid, _| seen.contains(pid));
        out
    }

    /// Events tab 'l' on an exited/restarted row: show the captured last
    /// words when we have them (instant), else fall back to a live fetch.
    fn open_death_logs(&mut self, ev: &crate::history::TuiEvent) {
        if let Some((_, lines)) = self.death_logs.iter().find(|(p, _)| *p == ev.pid) {
            self.logs_for = Some(format!("last words — {} (pid {})", ev.name, ev.pid));
            self.logs_lines = lines.clone();
            self.logs_scroll = 0;
            self.logs_src = None;
            self.page = Page::Logs;
            return;
        }
        self.open_logs(death_log_source(self.platform.name(), ev.pid, &ev.name));
    }

    /// Collect the pending logs fetch, if it finished.
    fn poll_logs(&mut self) {
        let Some(rx) = &self.logs_rx else { return };
        let arrived = rx.try_recv().ok();
        if let Some(res) = arrived {
            self.logs_rx = None;
            match res {
                Ok(mut lines) => {
                    if lines.is_empty() {
                        lines.push("(no log entries found — the process may not log to this source)".into());
                    }
                    self.logs_lines = lines;
                }
                Err(e) => self.logs_lines = vec![format!("⚠ {e}")],
            }
        }
    }

    /// 'F' on the Logs page: stream the source's logs live — container
    /// `logs -f`, `journalctl -f _PID=`, or macOS `log stream
    /// --predicate`. Toggles — pressing F again (or leaving the page)
    /// stops the stream and kills the child CLI.
    fn toggle_logs_follow(&mut self) {
        if self.follow_child.is_some() {
            self.stop_logs_follow(); // reports "follow stopped" itself
            return;
        }
        let Some(src) = self.logs_src.clone() else {
            self.status = "no log source for this view".into();
            return;
        };
        if self.logs_rx.is_some() {
            self.status = "still fetching the initial tail… try again in a moment".into();
            return;
        }
        // the follow command per source (Windows has no streaming
        // equivalent for the event log)
        let Some((prog, args, label)) = follow_command_for(&src) else {
            self.status = "live follow has no Windows event-log equivalent".into();
            return;
        };
        match std::process::Command::new(&prog)
            .args(&args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                self.logs_lines.clear();
                self.logs_scroll = 0;
                self.follow_prev_len = 0;
                let (tx, rx) = std::sync::mpsc::channel();
                // both pipes carry output (CLIs write diagnostics down stderr)
                let streams: Vec<Box<dyn std::io::Read + Send>> = [
                    child.stdout.take().map(|s| Box::new(s) as _),
                    child.stderr.take().map(|s| Box::new(s) as _),
                ]
                .into_iter()
                .flatten()
                .collect();
                for stream in streams {
                    let tx = tx.clone();
                    std::thread::spawn(move || {
                        use std::io::BufRead as _;
                        let reader = std::io::BufReader::new(stream);
                        for line in reader.lines().map_while(Result::ok) {
                            if tx.send(line).is_err() {
                                break;
                            }
                        }
                    });
                }
                self.follow_rx = Some(rx);
                self.follow_child = Some(child);
                self.status = format!("following {label} — F/Esc to stop");
            }
            Err(e) => self.status = format!("follow: {e}"),
        }
    }

    /// Kill the streaming child (page exit, toggle off, TUI shutdown).
    /// Reports "follow stopped" only when a stream was actually running —
    /// a no-op stop stays quiet.
    fn stop_logs_follow(&mut self) {
        if let Some(mut child) = self.follow_child.take() {
            let _ = child.kill();
            let _ = child.wait();
            self.status = "follow stopped".into();
        }
        self.follow_rx = None;
    }
    /// Drain new lines from the live stream into the view (capped), pinning
    /// the scroll to the bottom while the user is already near it.
    fn poll_follow_logs(&mut self) {
        let Some(rx) = &self.follow_rx else { return };
        const FOLLOW_CAP: usize = 500;
        let prev_count = self.follow_prev_len;
        let mut got = false;
        while let Ok(line) = rx.try_recv() {
            self.logs_lines.push(line);
            got = true;
        }
        if self.logs_lines.len() > FOLLOW_CAP {
            let excess = self.logs_lines.len() - FOLLOW_CAP;
            self.logs_lines.drain(0..excess);
        }
        if got {
            let count = self.logs_lines.len() as u16;
            let h = self.logs_pane_h.max(1);
            // was the viewport at (or within a few lines of) the bottom?
            if self.logs_scroll + h + 3 >= prev_count as u16 {
                self.logs_scroll = count.saturating_sub(h);
            }
            self.follow_prev_len = self.logs_lines.len();
        }
    }

    /// Apply the Containers-tab filter (name / image / id / runtime / state)
    /// + sort ('i/n/r/g/s'), keeping the selection in range.
    fn rebuild_container_view(&mut self) {
        let needle = self.container_search.to_lowercase();
        let mut view = filter_containers(&self.containers, &needle);
        if let Some(col) = self.container_sort {
            let desc = self.container_sort_desc;
            let cs = &self.containers;
            view.sort_by(|&a, &b| {
                let ord = match col {
                    ContainerSort::Id => cs[a].id.cmp(&cs[b].id),
                    ContainerSort::Name => cs[a].name.to_lowercase().cmp(&cs[b].name.to_lowercase()),
                    ContainerSort::Runtime => cs[a].runtime.cmp(&cs[b].runtime),
                    ContainerSort::Image => cs[a].image.cmp(&cs[b].image),
                    ContainerSort::Status => cs[a].status.cmp(&cs[b].status),
                    ContainerSort::Project => cs[a]
                        .compose
                        .as_deref()
                        .unwrap_or("~")
                        .cmp(cs[b].compose.as_deref().unwrap_or("~")),
                };
                if desc { ord.reverse() } else { ord }
            });
        }
        self.container_view = view;
        if self.container_view.is_empty() {
            self.table_state.select(None);
        } else {
            let cur = self
                .table_state
                .selected()
                .unwrap_or(0)
                .min(self.container_view.len() - 1);
            self.table_state.select(Some(cur));
        }
    }

    /// Apply the Services-tab filter (name / manager / state / description
    /// / pid) + sort ('n/m/s/p'), keeping the selection in range.
    fn rebuild_service_view(&mut self) {
        let needle = self.service_search.to_lowercase();
        let mut view = filter_services(&self.services, &needle);
        if let Some(col) = self.service_sort {
            let desc = self.service_sort_desc;
            let ss = &self.services;
            view.sort_by(|&a, &b| {
                let ord = match col {
                    ServiceSort::Name => ss[a].name.to_lowercase().cmp(&ss[b].name.to_lowercase()),
                    ServiceSort::Manager => ss[a].manager.cmp(&ss[b].manager),
                    ServiceSort::State => ss[a].state.cmp(&ss[b].state),
                    ServiceSort::Pid => ss[a].pid.cmp(&ss[b].pid),
                };
                if desc { ord.reverse() } else { ord }
            });
        }
        self.service_view = view;
        if self.service_view.is_empty() {
            self.table_state.select(None);
        } else {
            let cur = self
                .table_state
                .selected()
                .unwrap_or(0)
                .min(self.service_view.len() - 1);
            self.table_state.select(Some(cur));
        }
    }

    /// Apply the Ports-tab LISTEN-only gate ('a' lifts it), filter (port /
    /// pid / process / address / state) and sort ('p/t/n/s'), keeping the
    /// selection in range.
    fn rebuild_socket_view(&mut self) {
        let needle = self.port_search.to_lowercase();
        let names: HashMap<Pid, String> =
            self.procs.iter().map(|p| (p.pid, p.name.to_lowercase())).collect();
        let name_of = |pid: Pid| -> Option<String> { names.get(&pid).cloned() };
        let mut view = filter_sockets(&self.sockets, &needle, name_of);
        if !self.ports_show_all {
            // default view: listening tcp + bound udp, like the Go witr
            view.retain(|&i| {
                let s = &self.sockets[i];
                s.proto.starts_with("udp") || s.state.eq_ignore_ascii_case("LISTEN")
            });
        }
        let (col, desc) = (self.port_sort, self.port_sort_desc);
        let socks = &self.sockets;
        view.sort_by(|&a, &b| {
            let (x, y) = (&socks[a], &socks[b]);
            let ord = match col {
                PortSort::Port => x.local_port.cmp(&y.local_port),
                PortSort::Proto => x.proto.cmp(&y.proto),
                PortSort::Addr => x.local_addr.cmp(&y.local_addr),
                PortSort::State => x.state.cmp(&y.state),
            };
            if desc { ord.reverse() } else { ord }
        });
        self.socket_view = view;
        if self.socket_view.is_empty() {
            self.table_state.select(None);
        } else {
            let cur = self
                .table_state
                .selected()
                .unwrap_or(0)
                .min(self.socket_view.len() - 1);
            self.table_state.select(Some(cur));
        }
        // overview ('o') aggregates the same filtered socket list, so the
        // port search narrows it too
        let filtered: Vec<Socket> = self
            .socket_view
            .iter()
            .filter_map(|&i| self.sockets.get(i).cloned())
            .collect();
        self.port_overview_view = port_overview_rows(&filtered, &self.procs);
        if self.ports_overview {
            if self.port_overview_view.is_empty() {
                self.table_state.select(None);
            } else {
                let cur = self
                    .table_state
                    .selected()
                    .unwrap_or(0)
                    .min(self.port_overview_view.len() - 1);
                self.table_state.select(Some(cur));
            }
        }
    }

    /// (Re)fetch the Locks-tab snapshot: locks plus, in "all open files"
    /// mode ('a'), every open file merged underneath them — on the same
    /// (pid, path) the real lock entry wins, like the Go witr's merge.
    fn load_locks(&mut self) {
        self.locks = self.platform.list_locks(None);
        if self.locks_show_all {
            let mut merged = std::mem::take(&mut self.locks);
            let mut seen: std::collections::HashSet<(Option<Pid>, String)> =
                merged.iter().map(|l| (l.pid, l.path.clone())).collect();
            for e in self.platform.list_all_open_files() {
                if seen.insert((e.pid, e.path.clone())) {
                    merged.push(e);
                }
            }
            self.locks = merged;
        }
        self.rebuild_lock_view();
    }

    /// Apply the Locks-tab filter + sort (p/n/t/m/f), keeping the selection
    /// in range. In OPEN mode with an empty search the display is capped at
    /// 100 rows; typing lifts the cap (the Go witr's openFilesDisplayCap).
    fn rebuild_lock_view(&mut self) {
        let needle = self.lock_search.to_lowercase();
        let mut view = filter_locks(&self.locks, &needle);
        let (col, desc) = (self.lock_sort, self.lock_sort_desc);
        let locks = &self.locks;
        view.sort_by(|&a, &b| {
            let ord = match col {
                LockSort::Pid => locks[a].pid.cmp(&locks[b].pid),
                LockSort::Process => locks[a]
                    .owner
                    .to_lowercase()
                    .cmp(&locks[b].owner.to_lowercase()),
                LockSort::Type => locks[a].kind.cmp(&locks[b].kind),
                LockSort::Mode => locks[a].mode.cmp(&locks[b].mode),
                LockSort::Path => locks[a].path.cmp(&locks[b].path),
            };
            if desc { ord.reverse() } else { ord }
        });
        self.locks_total = view.len();
        if self.locks_show_all && needle.is_empty() && view.len() > 100 {
            view.truncate(100);
        }
        self.lock_view = view;
        if self.lock_view.is_empty() {
            self.lock_state.select(None);
        } else {
            let cur = self
                .lock_state
                .selected()
                .unwrap_or(0)
                .min(self.lock_view.len() - 1);
            self.lock_state.select(Some(cur));
        }
    }

    /// Pid of the lock row the Locks-tab cursor is on.
    fn selected_lock_pid(&self) -> Option<Pid> {
        let i = self.lock_state.selected()?;
        self.lock_view.get(i).and_then(|&li| self.locks[li].pid)
    }

    /// Apply the Events-tab filter over the history ring (kind / pid /
    /// name / detail substrings), then order by the active sort column.
    fn rebuild_event_view(&mut self) {
        let needle = self.event_search.to_lowercase();
        let events = &self.hist.events;
        self.event_view = events
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                needle.is_empty()
                    || e.kind.contains(&needle)
                    || e.name.to_lowercase().contains(&needle)
                    || e.detail.to_lowercase().contains(&needle)
                    || e.pid.to_string().contains(&needle)
            })
            .map(|(i, _)| i)
            .collect();
        let (col, desc) = (self.event_sort, self.event_sort_desc);
        self.event_view.sort_by(|&a, &b| {
            let ord = match col {
                EventSort::Time => events[a].at_unix.cmp(&events[b].at_unix),
                EventSort::Kind => events[a].kind.cmp(&events[b].kind),
                EventSort::Pid => events[a].pid.cmp(&events[b].pid),
                EventSort::Process => events[a]
                    .name
                    .to_lowercase()
                    .cmp(&events[b].name.to_lowercase()),
            };
            if desc { ord.reverse() } else { ord }
        });
        if self.event_view.is_empty() {
            self.event_state.select(None);
        } else {
            let cur = self
                .event_state
                .selected()
                .unwrap_or(0)
                .min(self.event_view.len() - 1);
            self.event_state.select(Some(cur));
        }
    }

    /// Pid of the event row the Events-tab cursor is on.
    fn selected_event_pid(&self) -> Option<Pid> {
        let i = self.event_state.selected()?;
        self.event_view.get(i).and_then(|&ei| self.hist.events.get(ei)).map(|e| e.pid)
    }

    /// Apply search filter + sort, keeping the selection in range.
    fn rebuild_view(&mut self) {
        let needle = self.search.to_lowercase();
        // a `/` query that parses as a numeric expression (cpu>50, age>1h…)
        // filters by metric instead of substring
        let metric_filter = parse_metric_filter(&self.search);
        let procs = &self.procs;
        // snapshots for the sort/filter comparators (they can't borrow self
        // while procs is held)
        let cpu_disp: HashMap<Pid, f64> = procs
            .iter()
            .map(|p| (p.pid, self.hist.display_cpu(p).unwrap_or(-1.0)))
            .collect();
        let io_disp: HashMap<Pid, f64> = procs
            .iter()
            .map(|p| {
                (
                    p.pid,
                    self.hist
                        .io_rate_of(p.pid)
                        .map(|(r, w)| r + w)
                        .unwrap_or(-1.0),
                )
            })
            .collect();
        let fd_disp: HashMap<Pid, f64> = self
            .fd_counts
            .iter()
            .map(|(pid, n)| (*pid, *n as f64))
            .collect();
        let now = crate::util::now_unix();
        let mut idx: Vec<usize> = procs
            .iter()
            .enumerate()
            .filter(|(_, p)| match metric_filter {
                Some(f) => {
                    let v = match f.metric {
                        FilterMetric::Cpu => cpu_disp.get(&p.pid).copied().unwrap_or(-1.0),
                        FilterMetric::Mem => p.mem_kb.map(|kb| kb as f64).unwrap_or(-1.0),
                        FilterMetric::Fd => fd_disp.get(&p.pid).copied().unwrap_or(-1.0),
                        FilterMetric::Age => p.started.map(|t| (now - t) as f64).unwrap_or(-1.0),
                        FilterMetric::Io => io_disp.get(&p.pid).copied().unwrap_or(-1.0),
                        FilterMetric::Threads => p.threads.map(|t| t as f64).unwrap_or(-1.0),
                    };
                    if f.gt {
                        v > f.value
                    } else {
                        v < f.value
                    }
                }
                None => {
                    needle.is_empty()
                        || p.name.to_lowercase().contains(&needle)
                        || p.user.as_deref().unwrap_or("").to_lowercase().contains(&needle)
                        || p.pid.to_string().contains(&needle)
                }
            })
            .map(|(i, _)| i)
            .collect();

        let key = self.sort_key;
        let desc = self.sort_desc;
        idx.sort_by(|&a, &b| {
            let (x, y) = (&procs[a], &procs[b]);
            let ord = match key {
                SortKey::Pid => x.pid.cmp(&y.pid),
                SortKey::Name => x.name.to_lowercase().cmp(&y.name.to_lowercase()),
                SortKey::User => x
                    .user
                    .as_deref()
                    .unwrap_or("~")
                    .cmp(y.user.as_deref().unwrap_or("~")),
                SortKey::Cpu => cpu_disp
                    .get(&x.pid)
                    .copied()
                    .unwrap_or(-1.0)
                    .partial_cmp(&cpu_disp.get(&y.pid).copied().unwrap_or(-1.0))
                    .unwrap_or(std::cmp::Ordering::Equal),
                SortKey::Mem => x.mem_kb.unwrap_or(0).cmp(&y.mem_kb.unwrap_or(0)),
                SortKey::Io => io_disp
                    .get(&x.pid)
                    .copied()
                    .unwrap_or(-1.0)
                    .partial_cmp(&io_disp.get(&y.pid).copied().unwrap_or(-1.0))
                    .unwrap_or(std::cmp::Ordering::Equal),
                SortKey::Started => x
                    .started
                    .unwrap_or(i64::MAX)
                    .cmp(&y.started.unwrap_or(i64::MAX)),
            };
            if desc { ord.reverse() } else { ord }
        });
        // watchlist ('w'): watched processes pin to the top, keeping the
        // chosen sort within the pinned block (stable partition). Skipped in
        // tree mode — pinning would tear children away from their parents.
        if !self.watch.is_empty() && !(self.tree_mode && needle.is_empty()) {
            idx.sort_by_key(|&i| !self.is_watched(&procs[i]));
        }
        // tree mode ('T'): re-order the sorted indices depth-first so
        // children sit directly under their parent; a live search keeps the
        // flat order (an arbitrary subset has no meaningful tree shape)
        if self.tree_mode && needle.is_empty() {
            let (order, depth) = tree_order(procs, &idx);
            self.view = order;
            self.view_depth = depth;
        } else {
            self.view = idx;
            self.view_depth.clear();
        }
        if self.view.is_empty() {
            self.table_state.select(None);
        } else {
            let cur = self
                .table_state
                .selected()
                .unwrap_or(0)
                .min(self.view.len() - 1);
            self.table_state.select(Some(cur));
        }
        // group mode ('B'): aggregate the filtered view into group rows —
        // the cursor now indexes group_view instead of view
        if self.group_mode == GroupMode::Off {
            self.group_view.clear();
        } else {
            self.group_view = group_rows(procs, &self.view, self.group_mode, &self.hist, key);
            if self.group_view.is_empty() {
                self.table_state.select(None);
            } else {
                let cur = self
                    .table_state
                    .selected()
                    .unwrap_or(0)
                    .min(self.group_view.len() - 1);
                self.table_state.select(Some(cur));
            }
        }
    }

    fn selected_pid(&self) -> Option<Pid> {
        // grouped mode: the "selection" is the group's busiest member
        if self.group_mode != GroupMode::Off {
            return self
                .table_state
                .selected()
                .and_then(|i| self.group_view.get(i))
                .map(|g| g.top_pid);
        }
        self.table_state
            .selected()
            .and_then(|i| self.view.get(i))
            .and_then(|&i| self.procs.get(i))
            .map(|p| p.pid)
    }

    fn is_watched(&self, p: &Process) -> bool {
        let key = crate::util::identity_key(p);
        self.watch.iter().any(|k| k == &key)
    }

    /// 'w' on the Processes table: toggle the selected process's watchlist
    /// entry and persist it to the user config. Matching is by identity
    /// (name + exe basename + user), never pid, so the star follows the
    /// program across restarts.
    fn toggle_watch(&mut self) {
        let (added, name) = self.toggle_watch_in_memory();
        if name.is_empty() {
            return; // nothing selected — status already set
        }
        match crate::config::Config::save_watch(&self.watch) {
            Ok(()) => {
                self.status = if added {
                    format!("★ watching {name} — pinned to top, survives restarts")
                } else {
                    format!("unwatched {name}")
                };
            }
            Err(e) => self.status = format!("watchlist not saved: {e}"),
        }
    }

    /// The in-memory half of [toggle_watch] (no config write — tests stay
    /// hermetic): flips the selected process's entry, returns (added?, name).
    fn toggle_watch_in_memory(&mut self) -> (bool, String) {
        let Some(p) = self
            .table_state
            .selected()
            .and_then(|i| self.view.get(i))
            .and_then(|&i| self.procs.get(i))
            .cloned()
        else {
            self.status = "no process selected".into();
            return (false, String::new());
        };
        let key = crate::util::identity_key(&p);
        let added = if let Some(pos) = self.watch.iter().position(|k| k == &key) {
            self.watch.remove(pos);
            false
        } else {
            self.watch.push(key);
            true
        };
        self.rebuild_view();
        (added, p.name)
    }

    /// The note text for a process, by its identity key ("name|exe|user"
    /// — the 4th pipe field onwards is the note).
    fn note_of(&self, p: &Process) -> Option<String> {
        let key = crate::util::identity_key(p);
        self.notes.iter().find(|e| {
            e.splitn(4, '|')
                .take(3)
                .collect::<Vec<_>>()
                .join("|")
                == key
        }).map(|e| {
            e.splitn(4, '|').nth(3).unwrap_or_default().to_string()
        })
    }

    /// Commit the 'N' input: upsert the selected process's note (empty
    /// text removes it) and persist the config.
    fn save_note(&mut self, text: &str) {
        let (name, saved_empty) = self.apply_note_in_memory(text);
        if name.is_empty() {
            return; // nothing selected — status already set
        }
        match crate::config::Config::save_notes(&self.notes) {
            Ok(()) => {
                self.status = if saved_empty {
                    format!("note removed from {name}")
                } else {
                    format!("notated {name} — survives restarts, shows as ✎")
                };
            }
            Err(e) => self.status = format!("note not saved: {e}"),
        }
    }

    /// The in-memory half of [save_note]: upsert (or remove) the selected
    /// process's note entry, returns (name, was-removal). No config write —
    /// tests stay hermetic.
    fn apply_note_in_memory(&mut self, text: &str) -> (String, bool) {
        let Some(p) = self
            .table_state
            .selected()
            .and_then(|i| self.view.get(i))
            .and_then(|&i| self.procs.get(i))
            .cloned()
        else {
            self.status = "no process selected".into();
            return (String::new(), false);
        };
        let key = crate::util::identity_key(&p);
        let text = text.trim().to_string();
        self.notes.retain(|e| {
            e.splitn(4, '|').take(3).collect::<Vec<_>>().join("|") != key
        });
        if !text.is_empty() {
            self.notes.push(format!("{key}|{text}"));
        }
        (p.name, text.is_empty())
    }

    /// Selection changed (or never computed): rebuild the details panel.
    fn update_details(&mut self) {
        let Some(pid) = self.selected_pid() else {
            self.detail_lines = vec![Line::from("no selection".fg(MID))];
            self.detail_pid = None;
            return;
        };
        if self.detail_pid == Some(pid) {
            return;
        }
        self.detail_pid = Some(pid);
        self.detail_scroll = 0;
        let mut report = pipeline::run(
            self.platform.as_ref(),
            vec![TargetSpec::Pid { pid }],
            &pipeline::Options::default(),
        )
        .into_iter()
        .next();
        if let Some(r) = report.as_mut() {
            if let Some(mp) = r.matches.first_mut() {
                if let Some(p) = self.procs.iter().find(|p| p.pid == mp.pid) {
                    crate::gpu::copy_fields(p, mp);
                }
            }
        }
        self.detail_lines = match report {
            Some(r) if r.found => {
                let mut lines = detail_lines(&r, &[], &[]);
                push_history_lines(&mut lines, &self.hist, pid);
                lines
            }
            Some(r) => vec![Line::from(
                Span::styled(r.error.unwrap_or_else(|| "unavailable".into()), Style::new().fg(MID)),
            )],
            None => vec![Line::from(Span::styled("unavailable", Style::new().fg(MID)))],
        };
    }

    fn kill_selected(&mut self) {
        let Some(pid) = self.selected_pid() else { return };
        let res = send_signal(pid, "TERM");
        self.status = match res {
            Ok(()) => format!("SIGTERM sent to pid {}", pid),
            Err(e) => format!("kill {}: {}", pid, e),
        };
        self.confirm_kill = None;
    }

    /// Open the full-page detail view: a fresh report is fetched with
    /// `want_env = true` so the Environment pane has data where the
    /// platform allows it.
    fn open_detail_page(&mut self) {
        let Some(pid) = self.selected_pid() else { return };
        self.open_detail_page_for(pid);
    }

    fn open_detail_page_for(&mut self, pid: Pid) {
        let report = pipeline::run(
            self.platform.as_ref(),
            vec![TargetSpec::Pid { pid }],
            // deep_files: the report then carries open files + locks + fd
            // usage from one platform probe (one lsof scan on macOS);
            // deep_binaries: sha256 + code-signature verdict for the page
            &pipeline::Options {
                want_env: true,
                deep_files: true,
                deep_binaries: true,
                ..Default::default()
            },
        )
        .into_iter()
        .next();
        match report {
            Some(mut r) if r.found => {
                // rebuild the pane content for THIS process (detail_lines is
                // shared with the browse side panel, which may still hold the
                // previously selected process); the live socket list is not
                // part of a Pid report, so fetch a full fresh snapshot —
                // every state, so peer attribution can reverse-match
                if let Some(mp) = r.matches.first_mut() {
                    if let Some(p) = self.procs.iter().find(|p| p.pid == mp.pid) {
                        crate::gpu::copy_fields(p, mp);
                    }
                }
                self.detail_socks = self.platform.list_all_sockets().unwrap_or_default();
                self.detail_report = Some(r);
                self.render_detail_page(pid);
                self.detail_pid = Some(pid);
                self.detail_scroll = 0;
                self.env_scroll = 0;
                self.env_search.clear();
                self.env_search_mode = false;
                self.detail_zoom = false;
                self.detail_pane = true;
                self.page = Page::Detail;
            }
            _ => {
                self.status = format!("pid {} is gone — details unavailable", pid);
            }
        }
    }

    /// Rebuild the full detail page content from the report + sockets cached
    /// at open (open_detail_page_for ran the expensive probes once) plus the
    /// live history charts. Called at open and every refresh tick while the
    /// page shows, so the cpu/mem/fd/io sparklines track samples taken since
    /// the page opened instead of freezing at open-time state.
    fn render_detail_page(&mut self, pid: Pid) {
        let Some(r) = self.detail_report.as_ref() else { return };
        let full_socks = std::mem::take(&mut self.detail_socks);
        let socks: Vec<Socket> =
            full_socks.iter().filter(|s| s.pid == Some(pid)).cloned().collect();
        let locks = r.locks.clone();
        let mut lines = detail_lines(r, &socks, &locks);
        // 'N' annotation — identity-keyed, so a restarted process keeps it
        if let Some(p) = r.matches.iter().find(|p| p.pid == pid) {
            if let Some(note) = self.note_of(p) {
                lines.push(Line::from(Span::styled("Note:", Style::new().bold())));
                lines.push(Line::from(Span::styled(
                    format!("  ✎ {note}"),
                    Style::new().fg(Color::Yellow),
                )));
            }
        }
        push_history_lines(&mut lines, &self.hist, pid);
        let names: HashMap<Pid, String> =
            self.procs.iter().map(|p| (p.pid, p.name.clone())).collect();
        push_peer_lines(&mut lines, &full_socks, &names, pid);
        if let Some(b) = &r.binary {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("Binary:", Style::new().bold())));
            match &b.sha256 {
                Some(h) => lines.push(Line::from(format!(
                    "  sha256: {}…{}",
                    &h[..16.min(h.len())],
                    &h[h.len().saturating_sub(8)..]
                ))),
                None => lines.push(Line::from(Span::styled(
                    "  sha256: unreadable (permissions?)",
                    Style::new().fg(MID),
                ))),
            }
            let sig_line = b
                .signature
                .clone()
                .unwrap_or_else(|| "no signature infrastructure on this platform".into());
            let sig_style = if sig_line.starts_with("NOT VALID") {
                Style::new().fg(Color::Red)
            } else if sig_line == "unsigned" {
                Style::new().fg(Color::Yellow)
            } else {
                Style::new().fg(GREEN)
            };
            lines.push(Line::from(Span::styled(
                format!("  signature: {sig_line}"),
                sig_style,
            )));
        }
        self.open_files = r.open_files.clone();
        if let Some(files) = &self.open_files {
            lines.push(Line::from(""));
            if files.is_empty() {
                lines.push(Line::from(styled(
                    Style::new().fg(MID),
                    "open files: none readable (belongs to another user?)",
                )));
            } else {
                lines.push(Line::from(Span::styled(
                    format!("Open Files ({}):", files.len()),
                    Style::new().bold(),
                )));
                for f in files.iter().take(30) {
                    lines.push(Line::from(format!("  {f}")));
                }
                if files.len() > 30 {
                    lines.push(Line::from(format!("  … {} more", files.len() - 30)));
                }
            }
        }
        // provisional count (logical lines); refined to the wrapped
        // count on the next render
        self.detail_line_count = lines.len() as u16;
        self.detail_lines = lines;
        self.detail_socks = full_socks;
    }

    /// Open the Ports-tab detail page: every socket touching the selected
    /// port (LISTEN + the current requests against it) plus the owning
    /// process report.
    fn open_port_detail_page(&mut self) {
        let Some(sel) = self.table_state.selected() else {
            return;
        };
        let Some(&idx) = self.socket_view.get(sel) else {
            return;
        };
        let Some(sock) = self.sockets.get(idx) else {
            return;
        };
        let port = sock.local_port;
        self.port_detail_port = port;
        let mut sockets = self
            .platform
            .port_to_sockets(port)
            .unwrap_or_else(|_| self.sockets.clone());
        // LISTEN first, then ESTABLISHED (the live requests), then the rest
        sockets.sort_by_key(|s| match s.state.as_str() {
            "LISTEN" | "LISTENING" => 0,
            "ESTABLISHED" => 1,
            _ => 2,
        });
        self.port_detail_sockets = sockets;
        let owner_pid = self
            .port_detail_sockets
            .iter()
            .find(|s| matches!(s.state.as_str(), "LISTEN" | "LISTENING"))
            .or_else(|| self.port_detail_sockets.iter().find(|s| s.pid.is_some()))
            .and_then(|s| s.pid);
        self.port_detail_report = owner_pid.and_then(|pid| {
            pipeline::run(
                self.platform.as_ref(),
                vec![TargetSpec::Pid { pid }],
                &pipeline::Options::default(),
            )
            .into_iter()
            .next()
            .filter(|r| r.found)
        });
        self.port_scroll = 0;
        self.port_owner_scroll = 0;
        self.port_pane_conn = true;
        self.page = Page::PortDetail;
    }

    /// Lines for the connections pane of the port detail page.
    fn port_connection_lines(&self) -> Vec<Line<'static>> {
        let names: HashMap<Pid, String> =
            self.procs.iter().map(|p| (p.pid, p.name.clone())).collect();
        let mut out = vec![Line::from(
            Span::styled(
                format!(
                    "{:<5}  {:<34}  {:<30}  {:<13}  {:<7}  {}",
                    "Proto", "Local", "Peer / Request", "State", "PID", "Process"
                ),
                Style::new().fg(ACCENT).bold(),
            ),
        )];
        for s in &self.port_detail_sockets {
            let peer = match (&s.peer_addr, s.peer_port) {
                (Some(a), Some(p)) => format!("{}:{}", a, p),
                _ => "-".to_string(),
            };
            let state_style = match s.state.as_str() {
                "LISTEN" | "LISTENING" => Style::new().fg(ACCENT),
                "ESTABLISHED" => Style::new().fg(GREEN),
                _ => Style::new().fg(MID),
            };
            out.push(Line::from(vec![
                Span::raw(format!("{:<5}  ", s.proto)),
                Span::raw(format!("{:<34}  ", format!("{}:{}", s.local_addr, s.local_port))),
                Span::raw(format!("{:<30}  ", peer)),
                Span::styled(format!("{:<13}  ", s.state), state_style),
                Span::raw(format!(
                    "{:<7}  ",
                    s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
                )),
                Span::raw(
                    s.pid
                        .and_then(|p| names.get(&p).cloned())
                        .unwrap_or_else(|| "-".into()),
                ),
            ]));
        }
        out
    }

    /// Open the Containers-tab detail page for the selected container.
    fn open_container_detail_page(&mut self) {
        let Some(sel) = self.table_state.selected() else {
            return;
        };
        let Some(&idx) = self.container_view.get(sel) else {
            return;
        };
        let Some(c) = self.containers.get(idx) else {
            return;
        };
        let mut c = c.clone();
        // process mapping works on Linux (cgroup match); elsewhere empty
        self.container_procs = self.platform.container_processes(&c.id);
        // restart count is a lazily-fetched inspect (one extra CLI call,
        // fine for a user-opened detail page)
        if c.restarts.is_none() {
            c.restarts = crate::platform::container_restarts(&c.runtime, &c.id);
        }
        self.container_detail = Some(c);
        self.cd_scroll = 0;
        self.cdp_scroll = 0;
        self.cd_pane_info = true;
        self.page = Page::ContainerDetail;
    }

    /// Lines for the container info pane.
    fn container_info_lines(&self) -> Vec<Line<'static>> {
        let Some(c) = &self.container_detail else {
            return vec![Line::from("no container".fg(MID))];
        };
        let kv = |k: &str, v: String| {
            Line::from(vec![
                styled(Style::new().fg(MID), format!("{:<9}", k)),
                Span::raw(v),
            ])
        };
        vec![
            kv("Name", c.name.clone()),
            kv("Runtime", c.runtime.clone()),
            kv("Compose", c.compose.clone().unwrap_or_else(|| "-".into())),
            kv("ID", c.id.clone()),
            kv("Image", c.image.clone()),
            kv("State", c.state.clone()),
            kv("Status", c.status.clone()),
            kv("Ports", if c.ports.is_empty() { "-".into() } else { c.ports.clone() }),
            if let Some(n) = c.restarts {
                let line = Line::from(vec![
                    styled(Style::new().fg(MID), format!("{:<9}", "Restarts")),
                    Span::raw(n.to_string()),
                    if n > 0 {
                        styled(Style::new().fg(Color::Yellow).bold(), "  (restart policy fired)")
                    } else {
                        Span::raw("")
                    },
                ]);
                line
            } else {
                kv("Restarts", "unavailable".into())
            },
            // cgroup pressure (Linux): cumulative oom_kill total + the
            // throttle percentage over the last sweep
            match c.oom_kills {
                Some(n) if n > 0 => Line::from(vec![
                    styled(Style::new().fg(MID), format!("{:<9}", "OOM kills")),
                    Span::raw(n.to_string()),
                    styled(
                        Style::new().fg(Color::Red).bold(),
                        "  (the kernel OOM-killed inside this container)",
                    ),
                ]),
                Some(_) => kv("OOM kills", "0".into()),
                None => kv("OOM kills", "n/a (no cgroup v2)".into()),
            },
            match self
                .throttle_pct
                .get(&c.id.chars().take(12).collect::<String>())
            {
                Some(pct) if *pct > 0.0 => Line::from(vec![
                    styled(Style::new().fg(MID), format!("{:<9}", "Throttled")),
                    Span::raw(format!("{pct:.1}% of the last sweep")),
                    if *pct >= 50.0 {
                        styled(Style::new().fg(Color::Red).bold(), "  (CPU-starved by its quota)")
                    } else {
                        Span::raw("")
                    },
                ]),
            _ => kv("Throttled", "0% of the last sweep".into()),
            },
        ]
    }

    /// Plain text of the focused pane (for the clipboard).
    fn focused_pane_text(&self) -> String {
        let lines: Vec<Line<'static>> = match self.page {
            Page::Detail if self.detail_pane => self.detail_lines.clone(),
            Page::Detail => self.env_lines(),
            Page::PortDetail if self.port_pane_conn => self.port_connection_lines(),
            Page::PortDetail => match &self.port_detail_report {
                Some(r) => {
                    let pid = r.matches[0].pid;
                    let own: Vec<Socket> = r
                        .sockets
                        .iter()
                        .filter(|s| s.pid == Some(pid))
                        .cloned()
                        .collect();
                    detail_lines(r, &own, &[])
                }
                None => vec![Line::from("no owning process visible")],
            },
            Page::ContainerDetail if self.cd_pane_info => self.container_info_lines(),
            Page::ContainerDetail => self.container_proc_lines(),
            Page::Logs => self.logs_lines.iter().map(|l| Line::from(l.clone())).collect(),
            Page::Summary => self
                .summary
                .as_ref()
                .map(|s| s.to_text().lines().map(|l| Line::from(l.to_string())).collect())
                .unwrap_or_default(),
            Page::System => self.system_page_lines(),
            Page::Diff => self.diff_page_lines(),
            Page::Samples => self.samples_page_lines(80),
            Page::Help => help_lines(self.tab),
            Page::Browse => Vec::new(),
        };
        lines.iter().map(line_to_string).collect::<Vec<_>>().join("\n")
    }

    /// Lines for the in-container process pane.
    fn container_proc_lines(&self) -> Vec<Line<'static>> {        if self.container_procs.is_empty() {
            let note = if self.platform.name() == "linux" {
                "no processes matched this container's cgroup"
            } else {
                "process mapping needs Linux (cgroups); on this platform containers run in a VM"
            };
            return vec![Line::from(styled(Style::new().fg(MID), note))];
        }
        let mut out = vec![Line::from(
            Span::styled(
                format!("{:<8} {:<24} {}", "PID", "User", "Name"),
                Style::new().fg(ACCENT).bold(),
            ),
        )];
        let mut procs = self.container_procs.clone();
        procs.sort_by_key(|p| p.pid);
        for p in procs {
            out.push(Line::from(format!(
                "{:<8} {:<24} {}",
                p.pid,
                p.user.as_deref().unwrap_or("-"),
                p.name
            )));
        }
        out
    }

    fn env_lines(&self) -> Vec<Line<'static>> {        let Some(r) = &self.detail_report else {
            return vec![Line::from("no process".fg(MID))];
        };
        let m = &r.matches[0];
        if let Some(env) = &m.env {
            if env.is_empty() {
                return vec![Line::from("(empty environment)".fg(MID))];
            }
            let needle = self.env_search.to_lowercase();
            let vars: Vec<_> = env
                .iter()
                .filter(|(k, v)| {
                    needle.is_empty()
                        || k.to_lowercase().contains(&needle)
                        || v.to_lowercase().contains(&needle)
                })
                .collect();
            if vars.is_empty() {
                return vec![Line::from(styled(
                    Style::new().fg(MID),
                    format!("no environment matches \"{}\"", self.env_search),
                ))];
            }
            return vars
                .into_iter()
                .map(|(k, v)| {
                    Line::from(vec![
                        Span::styled(k.clone(), Style::new().fg(ACCENT)),
                        Span::raw("="),
                        Span::raw(v.clone()),
                    ])
                })
                .collect();
        }
        let note = match self.platform.name() {
            "macos" => "no environment readable for this process (same-user only; SIP restricts the rest)",
            "windows" => "environment is not collected on Windows",
            _ => "no environment readable (belongs to another user?)",
        };
        vec![Line::from(styled(Style::new().fg(MID), note))]
    }

    fn scroll_indicator(scroll: u16, count: u16, height: u16) -> &'static str {
        let at_top = scroll == 0;
        let at_bottom = scroll.saturating_add(height) >= count;
        match (at_top, at_bottom) {
            (false, false) => " ↕",
            (false, true) => " ↑",
            (true, false) => " ↓",
            (true, true) => "",
        }
    }
}

/// Send a POSIX signal via the kill utility (TERM/KILL/STOP/CONT...).
/// Windows only supports graceful (/PID) and forced (/F) taskkill.
/// Failures always carry a non-empty message: spawn errors get the tool
/// name for context, and tools that fail silently (empty stderr) get a
/// plain "failed" note — the status line would otherwise go blank.
pub(crate) fn send_signal(pid: Pid, sig: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let out = std::process::Command::new("kill")
            .args(["-s", sig, &pid.to_string()])
            .output()
            .map_err(|e| std::io::Error::other(format!("kill: {e}")))?;
        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr);
            let msg = msg.trim();
            let msg = if msg.is_empty() { "kill failed" } else { msg };
            return Err(std::io::Error::other(msg.to_string()));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let tool = |args: &[&str]| {
            std::process::Command::new("taskkill")
                .args(args)
                .output()
                .map_err(|e| std::io::Error::other(format!("taskkill: {e}")))
        };
        match sig {
            "TERM" => {
                tool(&["/PID", &pid.to_string()])?;
                Ok(())
            }
            "KILL" => {
                tool(&["/F", "/PID", &pid.to_string()])?;
                Ok(())
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("signal {sig} is not supported on windows"),
            )),
        }
    }
}

/// renice the process (action-bar [n]ice); returns the tool's message.
fn renice_pid(pid: Pid, value: i32) -> std::io::Result<String> {
    #[cfg(unix)]
    {
        let out = std::process::Command::new("renice")
            .args([value.to_string(), "-p".to_string(), pid.to_string()])
            .output()?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if out.status.success() {
            Ok(text.trim().to_string())
        } else {
            Err(std::io::Error::other(text.trim().to_string()))
        }
    }
    #[cfg(windows)]
    {
        let _ = (pid, value);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "renice is not supported on windows",
        ))
    }
}

/// Filter sockets for the Ports tab: substring match over port, pid,
/// process name, address, proto and state.
fn filter_sockets(
    sockets: &[Socket],
    needle: &str,
    name_of: impl Fn(Pid) -> Option<String>,
) -> Vec<usize> {
    if needle.is_empty() {
        return (0..sockets.len()).collect();
    }
    sockets
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            s.local_port.to_string().contains(needle)
                || s.pid.map(|p| p.to_string()).unwrap_or_default().contains(needle)
                || name_of(s.pid.unwrap_or(-1))
                    .unwrap_or_default()
                    .contains(needle)
                || s.local_addr.to_lowercase().contains(needle)
                || s.proto.to_lowercase().contains(needle)
                || s.state.to_lowercase().contains(needle)
        })
        .map(|(i, _)| i)
        .collect()
}

/// One aggregated row of the Ports-tab overview ('o'): every distinct
/// (port, owner) pair among listening tcp + bound udp sockets, with the
/// owning process, its user, the protocols bound there and how many
/// distinct addresses that port is reachable on.
#[derive(Debug, Clone, PartialEq)]
struct PortOverviewRow {
    port: u16,
    pid: Option<Pid>,
    name: String,
    user: String,
    protos: String,
    addrs: usize,
    /// Exposure class from the bind addresses: "internet" (a wildcard
    /// 0.0.0.0/::/* bind), "loopback", "iface", "unknown".
    scope: &'static str,
}

/// Accumulated overview data per (port, owner): protocols seen, and the
/// distinct local bind addresses the port is reachable on.
type PortGroup = (Vec<String>, std::collections::HashSet<String>);

/// Processes-tab 'B' grouping: aggregate the (search-filtered) table into
/// one row per program name / user / container instead of per process —
/// "all Chrome helpers summed up" at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum GroupMode {
    #[default]
    Off,
    Name,
    User,
    Container,
}

impl GroupMode {
    fn next(self) -> Self {
        match self {
            GroupMode::Off => GroupMode::Name,
            GroupMode::Name => GroupMode::User,
            GroupMode::User => GroupMode::Container,
            GroupMode::Container => GroupMode::Off,
        }
    }

    fn label(self) -> &'static str {
        match self {
            GroupMode::Off => "",
            GroupMode::Name => "name",
            GroupMode::User => "user",
            GroupMode::Container => "container",
        }
    }
}

/// One aggregated row of the grouped process table.
#[derive(Debug, Clone, PartialEq)]
struct GroupRow {
    key: String,
    count: usize,
    cpu: f64,
    mem_kb: u64,
    io_bps: f64,
    /// the member to open on Enter — the busiest (cpu, then mem) one
    top_pid: Pid,
}

/// Aggregate the given process indices into group rows. The current sort
/// key picks the group order (cpu/mem sort → summed value descending,
/// anything else → key ascending).
fn group_rows(
    procs: &[Process],
    indices: &[usize],
    mode: GroupMode,
    hist: &crate::history::History,
    sort_key: SortKey,
) -> Vec<GroupRow> {
    let key_of = |p: &Process| -> String {
        match mode {
            GroupMode::Off => p.name.clone(),
            GroupMode::Name => p.name.clone(),
            GroupMode::User => p.user.clone().unwrap_or_else(|| "-".into()),
            GroupMode::Container => p
                .container
                .as_ref()
                .map(|c| {
                    // "docker: web (id abc123) [running]" → "web"
                    c.split_once(": ")
                        .and_then(|(_, rest)| rest.split(" (id").next())
                        .map(|s| s.trim().to_string())
                        .unwrap_or_else(|| c.clone())
                })
                .unwrap_or_else(|| "-".into()),
        }
    };
    let mut order: Vec<String> = Vec::new();
    let mut acc: HashMap<String, GroupRow> = HashMap::new();
    for &i in indices {
        let Some(p) = procs.get(i) else { continue };
        let k = key_of(p);
        let cpu = hist.display_cpu(p).unwrap_or(0.0);
        let io = hist.io_rate_of(p.pid).map(|(r, w)| r + w).unwrap_or(0.0);
        let e = acc.entry(k.clone()).or_insert_with(|| {
            order.push(k.clone());
            GroupRow {
                key: k,
                count: 0,
                cpu: 0.0,
                mem_kb: 0,
                io_bps: 0.0,
                top_pid: p.pid,
            }
        });
        e.count += 1;
        e.cpu += cpu;
        e.mem_kb += p.mem_kb.unwrap_or(0);
        e.io_bps += io;
        let top = procs
            .iter()
            .find(|q| q.pid == e.top_pid)
            .map(|q| (hist.display_cpu(q).unwrap_or(0.0), q.mem_kb.unwrap_or(0)))
            .unwrap_or((0.0, 0));
        if (cpu, p.mem_kb.unwrap_or(0)) > top {
            e.top_pid = p.pid;
        }
    }
    order.sort_by_key(|a| a.to_lowercase());
    let mut rows: Vec<GroupRow> = order
        .into_iter()
        .filter_map(|k| acc.remove(&k))
        .collect();
    match sort_key {
        SortKey::Cpu => rows.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal)),
        SortKey::Mem => rows.sort_by_key(|b| std::cmp::Reverse(b.mem_kb)),
        _ => {}
    }
    rows
}

/// Group sockets into overview rows: listening tcp (any state spelled
/// "LISTEN") plus bound udp (port != 0), keyed by (local_port, pid).
/// Sorted by port, then pid; unknown owners show up as "-".
fn port_overview_rows(sockets: &[Socket], procs: &[Process]) -> Vec<PortOverviewRow> {
    let mut order: Vec<(u16, Option<Pid>)> = Vec::new();
    let mut acc: HashMap<(u16, Option<Pid>), PortGroup> = HashMap::new();
    for s in sockets {
        let keep = s.state.eq_ignore_ascii_case("LISTEN")
            || (s.proto.starts_with("udp") && s.local_port != 0);
        if !keep {
            continue;
        }
        let key = (s.local_port, s.pid);
        let e = acc.entry(key).or_insert_with(|| {
            order.push(key);
            (Vec::new(), std::collections::HashSet::new())
        });
        if !e.0.contains(&s.proto) {
            e.0.push(s.proto.clone());
        }
        e.1.insert(s.local_addr.clone());
    }
    order.sort();
    order
        .into_iter()
        .map(|(port, pid)| {
            let (mut protos, addrs) = acc.remove(&(port, pid)).unwrap_or_default();
            protos.sort();
            let (name, user) = pid
                .and_then(|p| procs.iter().find(|pr| pr.pid == p))
                .map(|pr| {
                    (
                        pr.name.clone(),
                        pr.user.clone().unwrap_or_else(|| "-".into()),
                    )
                })
                .unwrap_or_else(|| ("-".into(), "-".into()));
            let binds: Vec<String> = addrs.iter().cloned().collect();
            PortOverviewRow {
                port,
                pid,
                name,
                user,
                protos: protos.join("/"),
                addrs: binds.len(),
                scope: crate::snapshot::bind_scope(&binds),
            }
        })
        .collect()
}

/// Filter locks: substring match over type, mode, pid, process and path.
fn filter_locks(locks: &[LockEntry], needle: &str) -> Vec<usize> {
    if needle.is_empty() {
        return (0..locks.len()).collect();
    }
    locks
        .iter()
        .enumerate()
        .filter(|(_, l)| {
            l.kind.to_lowercase().contains(needle)
                || l.mode.to_lowercase().contains(needle)
                || l.owner.to_lowercase().contains(needle)
                || l.path.to_lowercase().contains(needle)
                || l.id.to_lowercase().contains(needle)
                || l.pid.map(|p| p.to_string()).unwrap_or_default().contains(needle)
        })
        .map(|(i, _)| i)
        .collect()
}

/// Filter containers: substring match over name, image, id, runtime,
/// state and compose project.
fn filter_containers(containers: &[Container], needle: &str) -> Vec<usize> {
    if needle.is_empty() {
        return (0..containers.len()).collect();
    }
    containers
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            c.name.to_lowercase().contains(needle)
                || c.image.to_lowercase().contains(needle)
                || c.id.to_lowercase().contains(needle)
                || c.runtime.to_lowercase().contains(needle)
                || c.state.to_lowercase().contains(needle)
                || c
                    .compose
                    .as_ref()
                    .is_some_and(|p| p.to_lowercase().contains(needle))
        })
        .map(|(i, _)| i)
        .collect()
}

/// Services-tab filter over every visible column.
fn filter_services(services: &[crate::model::Service], needle: &str) -> Vec<usize> {
    if needle.is_empty() {
        return (0..services.len()).collect();
    }
    services
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            s.name.to_lowercase().contains(needle)
                || s.manager.to_lowercase().contains(needle)
                || s.state.to_lowercase().contains(needle)
                || s.desc.to_lowercase().contains(needle)
                || s.pid.is_some_and(|p| p.to_string().contains(needle))
        })
        .map(|(i, _)| i)
        .collect()
}

fn fmt_mem(kb: Option<u64>) -> String {
    match kb {
        None => "-".into(),
        Some(k) if k >= 1024 * 1024 => format!("{:.1}G", k as f64 / 1024.0 / 1024.0),
        Some(k) if k >= 1024 => format!("{:.0}M", k as f64 / 1024.0),
        Some(k) => format!("{}K", k),
    }
}

/// Byte count with a K/M/G suffix ("45M", "1.2G"); plain bytes below 1K.
fn fmt_age_short(started: Option<i64>) -> String {
    match started {
        None => "-".into(),
        Some(t) => crate::util::fmt_age(crate::util::now_unix() - t),
    }
}

fn styled(kind: Style, s: impl Into<String>) -> Span<'static> {
    Span::styled(s.into(), kind)
}

fn line_to_string(l: &Line<'_>) -> String {
    l.spans.iter().map(|s| s.content.clone()).collect()
}

/// Crash-loop signal appended to detail panes from the sampling history.
/// Who is `pid` talking to right now? Reverse-match its ESTABLISHED
/// sockets' (peer addr, peer port) against every other socket's local end
/// in the same snapshot — listeners on wildcard addresses match too, and
/// on loopback the server-side accepted socket pairs up exactly. Remote
/// peers (no local socket) are reported as such. Returns one label per
/// distinct destination with its connection count.
fn describe_peers(full: &[Socket], names: &HashMap<Pid, String>, pid: Pid) -> Vec<(String, usize)> {
    let mut out: Vec<(String, usize)> = Vec::new();
    for s in full
        .iter()
        .filter(|s| s.pid == Some(pid) && s.state == "ESTABLISHED")
    {
        let (Some(pa), Some(pp)) = (&s.peer_addr, s.peer_port) else {
            continue;
        };
        let peer_pid = full
            .iter()
            .filter(|o| o.pid.is_some() && o.pid != s.pid)
            .find(|o| {
                o.local_port == pp
                    && (o.local_addr == *pa
                        || pa == "127.0.0.1"
                        || pa == "::1"
                        || o.local_addr == "*"
                        || o.local_addr == "0.0.0.0"
                        || o.local_addr == "::")
            })
            .and_then(|o| o.pid);
        let label = match peer_pid.and_then(|p| names.get(&p)) {
            Some(name) => format!("{} (pid {})", name, peer_pid.unwrap_or(0)),
            None => format!("remote {}:{}", pa, pp),
        };
        match out.iter_mut().find(|(l, _)| *l == label) {
            Some((_, n)) => *n += 1,
            None => out.push((label, 1)),
        }
    }
    out
}

/// Append the "talking to" section (detail pages): peer-process attribution
/// for the process's live connections.
fn push_peer_lines(
    lines: &mut Vec<Line<'static>>,
    full: &[Socket],
    names: &HashMap<Pid, String>,
    pid: Pid,
) {
    let peers = describe_peers(full, names, pid);
    if peers.is_empty() {
        return;
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("talking to:", Style::new().bold())));
    for (label, n) in peers.iter().take(6) {
        let conn = if *n == 1 { "connection" } else { "connections" };
        lines.push(Line::from(Span::styled(
            format!("  {label} — {n} {conn}"),
            Style::new().fg(MID),
        )));
    }
    if peers.len() > 6 {
        lines.push(Line::from(format!("  … {} more", peers.len() - 6)));
    }
}

/// Tree-mode ordering for the Processes tab: DFS over the ppid relation,
/// siblings kept in the caller's (sorted) order. Roots are rows whose
/// parent isn't in the table; cycles are cut by visiting each row once.
/// Returns row indices in display order with their depth (0 = root).
fn tree_order(procs: &[Process], sorted: &[usize]) -> (Vec<usize>, Vec<usize>) {
    let pids: std::collections::HashSet<Pid> = sorted.iter().map(|&i| procs[i].pid).collect();
    let mut children: HashMap<Pid, Vec<usize>> = HashMap::new();
    let mut roots: Vec<usize> = Vec::new();
    for &i in sorted {
        match procs[i].ppid {
            Some(pp) if pids.contains(&pp) && pp != procs[i].pid => {
                children.entry(pp).or_default().push(i)
            }
            _ => roots.push(i),
        }
    }
    let mut order = Vec::with_capacity(sorted.len());
    let mut depth = Vec::with_capacity(sorted.len());
    // explicit stack of (index, depth); pushed reversed so the first
    // sibling ends up on top
    let mut stack: Vec<(usize, usize)> = roots.iter().rev().map(|&i| (i, 0)).collect();
    let mut seen: std::collections::HashSet<Pid> = std::collections::HashSet::new();
    while let Some((i, d)) = stack.pop() {
        if !seen.insert(procs[i].pid) {
            continue;
        }
        order.push(i);
        depth.push(d);
        if let Some(kids) = children.get(&procs[i].pid) {
            for &k in kids.iter().rev() {
                stack.push((k, d + 1));
            }
        }
    }
    // ppid cycles (or any row unreachable from a root) would be dropped by
    // the DFS — append them so the table never loses rows
    if order.len() < sorted.len() {
        let placed: std::collections::HashSet<usize> = order.iter().copied().collect();
        for &i in sorted {
            if !placed.contains(&i) {
                order.push(i);
                depth.push(0);
            }
        }
    }
    (order, depth)
}

/// Best-effort log source for a DEAD process: journald matches historical
/// entries by _PID (works after exit within the current boot); the macOS
/// unified log can only be queried by process name. Takes the platform
/// name (not cfg!) so every branch compiles — and tests — on every host.
fn death_log_source(platform_name: &str, pid: Pid, name: &str) -> crate::logs::LogSource {
    match platform_name {
        "macos" => crate::logs::LogSource::UnifiedLog {
            name: name.to_string(),
        },
        "windows" => crate::logs::LogSource::EventLog {
            pid,
            name: name.to_string(),
        },
        _ => crate::logs::LogSource::Journald { pid },
    }
}

/// The desktop-notification command for a given OS — macOS speaks
/// osascript, Linux notify-send, Windows a native WinRT toast via
/// PowerShell (no extra module needed). Split from the fire step so tests
/// can assert the exact argv.
fn notify_command_for(os: &str, title: &str, body: &str) -> Option<(String, Vec<String>)> {
    match os {
        "macos" => Some((
            "osascript".to_string(),
            vec![
                "-e".to_string(),
                format!(
                    "display notification \"{}\" with title \"{}\"",
                    body.replace('"', "'"),
                    title.replace('"', "'")
                ),
            ],
        )),
        "linux" => Some((
            "notify-send".to_string(),
            vec![title.to_string(), body.to_string()],
        )),
        "windows" => {
            // single-quoted PowerShell strings: double the single quotes
            let ps = |s: &str| s.replace('\'', "''");
            Some((
                "powershell".to_string(),
                vec![
                    "-NoProfile".to_string(),
                    "-Command".to_string(),
                    format!(
                        "[Windows.UI.Notifications.ToastNotificationManager, \
                         Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; \
                         $x = [Windows.UI.Notifications.ToastNotificationManager]::\
                         GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::\
                         ToastText02); \
                         $x.GetElementsByTagName('text').Item(0).AppendChild(\
                         $x.CreateTextNode('{}')) > $null; \
                         $x.GetElementsByTagName('text').Item(1).AppendChild(\
                         $x.CreateTextNode('{}')) > $null; \
                         [Windows.UI.Notifications.ToastNotificationManager]::\
                         CreateToastNotifier('{{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}}\
                         \\WindowsPowerShell\\v1.0\\powershell.exe').Show(\
                         [Windows.UI.Notifications.ToastNotification]::new($x))",
                        ps(title),
                        ps(body)
                    ),
                ],
            ))
        }
        _ => None,
    }
}

/// The live-stream command behind the Logs page's 'F' for a source —
/// container `logs -f`, `journalctl -f _PID=`, macOS `log stream
/// --predicate`. None for the Windows event log (no streaming shape).
/// Split from the spawn step so tests can assert the exact argv.
fn follow_command_for(src: &crate::logs::LogSource) -> Option<(String, Vec<String>, String)> {
    match src {
        crate::logs::LogSource::Container { runtime, ref_ } => Some((
            runtime.clone(),
            vec![
                "logs".to_string(),
                "-f".to_string(),
                "--tail".to_string(),
                "100".to_string(),
                ref_.clone(),
            ],
            format!("{runtime} logs"),
        )),
        crate::logs::LogSource::Journald { pid } => Some((
            "journalctl".to_string(),
            vec![
                "--no-pager".to_string(),
                "-f".to_string(),
                "-n".to_string(),
                "100".to_string(),
                format!("_PID={pid}"),
            ],
            format!("journal (_PID={pid})"),
        )),
        crate::logs::LogSource::UnifiedLog { name } => {
            let pred = format!(
                "process == \"{}\"",
                crate::logs::sanitize_predicate(name)
            );
            Some((
                "log".to_string(),
                vec![
                    "stream".to_string(),
                    "--style".to_string(),
                    "compact".to_string(),
                    "--predicate".to_string(),
                    pred,
                ],
                format!("unified log (process {name})"),
            ))
        }
        crate::logs::LogSource::EventLog { .. } => None,
    }
}

/// Fire-and-forget desktop notification for this host — spawned on a
/// throwaway thread so a slow osascript never stalls a refresh tick.
fn send_desktop_notify(title: &str, body: &str) {
    if let Some((prog, args)) = notify_command_for(std::env::consts::OS, title, body) {
        let _ = std::thread::spawn(move || {
            let _ = std::process::Command::new(prog)
                .args(&args)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        });
    }
}

/// Run the `--alert-exec` command for one firing — sh -c / cmd /C, throwaway
/// thread (a webhook POST must never stall a refresh tick). The alert
/// context rides in the child's environment: WITR_ALERT_PID / NAME / DETAIL /
/// KIND ("alert" or "recovered"). Shared with the headless `--watch` loop.
pub fn spawn_alert_exec(cmd: &str, pid: Pid, name: &str, detail: &str, kind: &str) {
    let cmd = cmd.to_string();
    let name = name.to_string();
    let detail = detail.to_string();
    let kind = kind.to_string();
    let _ = std::thread::spawn(move || {
        #[cfg(windows)]
        let mut c = {
            let mut c = std::process::Command::new("cmd");
            c.args(["/C", &cmd]);
            c
        };
        #[cfg(not(windows))]
        let mut c = {
            let mut c = std::process::Command::new("sh");
            c.args(["-c", &cmd]);
            c
        };
        c.env("WITR_ALERT_PID", pid.to_string())
            .env("WITR_ALERT_NAME", &name)
            .env("WITR_ALERT_DETAIL", &detail)
            .env("WITR_ALERT_KIND", &kind)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let _ = c.status();
    });
}

/// POST one alert (or recovery — `kind` is "alert" / "recovered") as JSON
/// to `--alert-webhook` (same payload shape as the --events-log envelope).
/// http:// only — std has no TLS, https:// URLs are refused with a note.
/// Fire-and-forget on a throwaway thread with a 3s timeout: a slow or dead
/// webhook must never stall the sampler; failures print to stderr once per
/// miss.
pub fn send_alert_webhook(url: &str, pid: Pid, name: &str, detail: &str, kind: &str) {
    let Some(rest) = url.strip_prefix("http://") else {
        eprintln!("--alert-webhook: only http:// URLs are supported (no TLS): {url}");
        return;
    };
    let (host_port, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp.to_string(), format!("/{p}")),
        None => (rest.to_string(), "/".to_string()),
    };
    if host_port.is_empty() {
        eprintln!("--alert-webhook: no host in {url}");
        return;
    }
    let url = url.to_string();
    let name = name.to_string();
    let detail = detail.to_string();
    let kind = kind.to_string();
    let _ = std::thread::spawn(move || {
        let body = serde_json::json!({
            "schema_version": crate::SCHEMA_VERSION,
            "kind": kind,
            "at_unix": crate::util::now_unix(),
            "pid": pid,
            "name": name,
            "detail": detail,
        });
        let payload = serde_json::to_string(&body).unwrap_or_default();
        let addrs = match std::net::ToSocketAddrs::to_socket_addrs(&host_port.as_str()) {
            Ok(a) => a.collect::<Vec<_>>(),
            Err(e) => {
                eprintln!("--alert-webhook {url}: {e}");
                return;
            }
        };
        for addr in addrs {
            let Ok(mut stream) =
                std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3))
            else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
            let req = format!(
                "POST {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len(),
            );
            use std::io::Write as _;
            if stream.write_all(req.as_bytes()).is_ok() {
                // drain the response best-effort so the server sees a clean close
                let mut buf = [0u8; 256];
                let _ = std::io::Read::read(&mut stream, &mut buf);
                return;
            }
        }
        eprintln!("--alert-webhook {url}: unreachable");
    });
}

fn push_history_lines(lines: &mut Vec<Line<'static>>, hist: &crate::history::History, pid: Pid) {
    if let Some(n) = hist.recent_restarts(pid) {
        if n >= 2 {
            lines.push(Line::from(styled(
                Style::new().fg(Color::Yellow),
                format!("⚠ restarted {n}× in the last 5 min"),
            )));
        }
    }
    let total = hist.total_restarts(pid);
    if total >= 2 {
        lines.push(Line::from(styled(
            Style::new().fg(MID),
            format!("total {total} restarts since TUI start"),
        )));
    }
    // CPU history over the last ~10 min of TUI samples (needs 2+ samples,
    // so a freshly opened TUI stays quiet until the second refresh)
    if let Some(chart) = hist.cpu_chart(pid, 80) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("CPU history:", Style::new().bold())));
        lines.push(Line::from(Span::styled(
            format!("  {chart}"),
            Style::new().fg(GREEN),
        )));
    }
    // RSS history on the same window, absolute scale; a slow monotonic
    // climb surfaces as a leak suspicion line
    if let Some(chart) = hist.mem_chart(pid, 80) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Memory history:", Style::new().bold())));
        lines.push(Line::from(Span::styled(
            format!("  {chart}"),
            Style::new().fg(GREEN),
        )));
    }
    if let Some(w) = hist.leak_suspicion(pid, REFRESH.as_secs_f64()) {
        lines.push(Line::from(Span::styled(
            format!("  ⚠ {w}"),
            Style::new().fg(Color::Yellow),
        )));
    }
    // Open-descriptor history on the same window; a steady climb surfaces
    // as an fd leak suspicion line (same shape as the memory one)
    if let Some((chart, now)) = hist.fd_chart(pid, 80) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("Open fds ({now}):"),
            Style::new().bold(),
        )));
        lines.push(Line::from(Span::styled(
            format!("  {chart}"),
            Style::new().fg(GREEN),
        )));
    }
    if let Some(w) = hist.fd_suspicion(pid, REFRESH.as_secs_f64()) {
        lines.push(Line::from(Span::styled(
            format!("  ⚠ {w}"),
            Style::new().fg(Color::Yellow),
        )));
    }
    // Kernel thread history (Linux / Windows listings carry it) — the
    // thread-leak twin of the fd chart
    if let Some((chart, now)) = hist.thread_chart(pid, 80) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("Threads ({now}):"),
            Style::new().bold(),
        )));
        lines.push(Line::from(Span::styled(
            format!("  {chart}"),
            Style::new().fg(GREEN),
        )));
    }
    if let Some(w) = hist.thread_suspicion(pid, REFRESH.as_secs_f64()) {
        lines.push(Line::from(Span::styled(
            format!("  ⚠ {w}"),
            Style::new().fg(Color::Yellow),
        )));
    }
    // Disk I/O rates on the same window (read/write sparklines; only the
    // platforms that report per-process I/O have data here)
    if let Some((r, w)) = hist.io_chart(pid, 80) {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("Disk I/O:", Style::new().bold())));
        lines.push(Line::from(Span::styled(format!("  {r}"), Style::new().fg(GREEN))));
        lines.push(Line::from(Span::styled(format!("  {w}"), Style::new().fg(MID))));
    }
}

/// "Key      value" line in the detail panes.
fn push_kv(v: &mut Vec<Line<'static>>, k: &str, val: String) {
    v.push(Line::from(vec![
        styled(Style::new().fg(MID), format!("{:<8}", k)),
        Span::raw(val),
    ]));
}

/// Indented sub-entry under a bold section header ("Virtual 436.5G").
fn push_sub(v: &mut Vec<Line<'static>>, k: &str, val: String) {
    v.push(Line::from(vec![
        styled(Style::new().fg(MID), format!("  {:<9}", format!("{}:", k))),
        Span::raw(val),
    ]));
}

/// "45% SM · 1200 MiB" when the process carries NVIDIA usage; None otherwise.
fn gpu_line(p: &crate::model::Process) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(sm) = p.gpu_sm_pct {
        parts.push(format!("{sm}% SM"));
    }
    if let Some(mb) = p.gpu_mem_mb {
        parts.push(format!("{mb} MiB"));
    }
    (!parts.is_empty()).then(|| parts.join(" · "))
}

/// Right-hand details panel: identity + resources + ancestry tree + warnings.
/// `sockets`/`locks` are the live per-process entries (empty on the browse
/// side panel, which does not pay for the fetch).
fn detail_lines(
    r: &crate::model::TargetReport,
    sockets: &[Socket],
    locks: &[LockEntry],
) -> Vec<Line<'static>> {
    let m = &r.matches[0];
    let mut v: Vec<Line<'static>> = Vec::new();
    push_kv(&mut v, "PID", m.pid.to_string());
    if let Some(u) = &m.user {
        push_kv(&mut v, "User", u.clone());
    }
    if let Some(t) = m.started {
        push_kv(
            &mut v,
            "Started",
            format!("{} ({} ago)", crate::util::fmt_time(t), crate::util::fmt_age(crate::util::now_unix() - t)),
        );
    }
    if let Some(c) = &m.cwd {
        push_kv(&mut v, "Cwd", c.clone());
    }
    if let Some(t) = &m.tty {
        let label = if t == "-" {
            "(detached)".to_string()
        } else {
            t.clone()
        };
        push_kv(&mut v, "Tty", label);
    }
    if m.pgid.is_some() || m.sid.is_some() {
        let mut label = String::new();
        if let Some(g) = m.pgid {
            label.push_str(&format!("pgid {g}"));
        }
        if m.pgid.is_some() && m.sid.is_some() {
            label.push_str(" · ");
        }
        if let Some(s) = m.sid {
            label.push_str(&format!("sid {s}"));
        }
        push_kv(&mut v, "Group", label);
    }
    // cgroup v2 (Linux detail-time): path plus the group's own memory and
    // CPU totals — the container/service view a bare RSS can't give
    if let Some(cg) = &m.cgroup {
        let mut label = cg.clone();
        if let Some(bytes) = m.cgroup_mem_bytes {
            label.push_str(&format!(" · mem {}", crate::util::fmt_bytes(bytes)));
        }
        if let Some(usec) = m.cgroup_cpu_usec {
            label.push_str(&format!(" · cpu {:.1}s", usec as f64 / 1_000_000.0));
        }
        push_kv(&mut v, "Cgroup", label);
    }
    if let Some(e) = &m.exe {
        push_kv(&mut v, "Exe", e.clone());
    }
    if !m.cmdline.is_empty() {
        push_kv(&mut v, "Cmd", m.command_line());
    }

    // resource usage (mirrors the Go witr's CPU/Memory/I/O/Threads block)
    if m.cpu.is_some() || m.cpu_time_ms.is_some() {
        v.push(Line::from(Span::styled("CPU:", Style::new().bold())));
        if let Some(cpu) = m.cpu {
            push_sub(&mut v, "Average", format!("{cpu:.1}% (lifetime avg)"));
        }
        if let Some(ms) = m.cpu_time_ms {
            push_sub(&mut v, "Time", crate::util::fmt_age((ms / 1000) as i64));
        }
    }
    if m.vm_kb.is_some() || m.mem_kb.is_some() || m.private_kb.is_some() {
        v.push(Line::from(Span::styled("Memory:", Style::new().bold())));
        if m.vm_kb.is_some() {
            push_sub(&mut v, "Virtual", fmt_mem(m.vm_kb));
        }
        if m.mem_kb.is_some() {
            push_sub(&mut v, "Resident", fmt_mem(m.mem_kb));
        }
        if m.private_kb.is_some() {
            push_sub(&mut v, "Private", fmt_mem(m.private_kb));
        }
    }
    if m.io_read_bytes.is_some() || m.io_write_bytes.is_some() {
        v.push(Line::from(Span::styled("I/O Statistics:", Style::new().bold())));
        let fbytes = |b: u64| -> String {
            if b >= 1024 * 1024 * 1024 {
                format!("{:.1} GB", b as f64 / 1024.0 / 1024.0 / 1024.0)
            } else if b >= 1024 * 1024 {
                format!("{:.1} MB", b as f64 / 1024.0 / 1024.0)
            } else if b >= 1024 {
                format!("{:.1} KB", b as f64 / 1024.0)
            } else {
                format!("{b} B")
            }
        };
        if let Some(b) = m.io_read_bytes {
            push_sub(
                &mut v,
                "Read",
                match m.io_read_ops {
                    Some(ops) => format!("{} ({} ops)", fbytes(b), ops),
                    None => fbytes(b),
                },
            );
        }
        if let Some(b) = m.io_write_bytes {
            push_sub(
                &mut v,
                "Write",
                match m.io_write_ops {
                    Some(ops) => format!("{} ({} ops)", fbytes(b), ops),
                    None => fbytes(b),
                },
            );
        }
    }
    if let Some(t) = m.threads {
        push_kv(&mut v, "Threads", t.to_string());
    }
    if let Some(g) = gpu_line(m) {
        push_kv(&mut v, "GPU", g);
    }
    if !sockets.is_empty() {
        v.push(Line::from(""));
        v.push(Line::from(Span::styled("Sockets:", Style::new().bold())));
        for s in sockets {
            // "127.0.0.1:18789 (TCP | LISTENING)", with the peer for
            // established connections
            let mut text = format!("  {}:{} ({}", s.local_addr, s.local_port, s.proto.to_uppercase());
            if let (Some(pa), Some(pp)) = (&s.peer_addr, &s.peer_port) {
                text.push_str(&format!(" -> {}:{}", pa, pp));
            }
            text.push_str(&format!(" | {})", s.state));
            v.push(Line::from(text));
        }
    }
    if !locks.is_empty() {
        v.push(Line::from(""));
        v.push(Line::from(Span::styled("Locks:", Style::new().bold())));
        for l in locks {
            v.push(Line::from(format!(
                "  {} {} {} ({})",
                l.kind, l.mode, l.path, l.owner
            )));
        }
    }
    if let Some(s) = &r.source {
        v.push(Line::from(""));
        let mut line = vec![
            styled(Style::new().fg(GREEN), "Started by: "),
            styled(Style::new().fg(GREEN), s.kind.clone()),
        ];
        if let Some(l) = &s.label {
            line.push(styled(Style::new().fg(GREEN), format!(" · {}", l)));
        }
        v.push(Line::from(line));
        if let Some(d) = &s.detail {
            v.push(Line::from(styled(Style::new().fg(MID), format!("  {}", d))));
        }
    }
    if r.ancestry.len() > 1 {
        v.push(Line::from(""));
        v.push(Line::from(Span::styled("Ancestry Tree:", Style::new().bold())));
        let last = r.ancestry.len() - 1;
        for (i, a) in r.ancestry.iter().enumerate() {
            let mut spans = vec![styled(
                Style::new().fg(MID),
                format!("{}{}", "  ".repeat(i), if i == 0 { String::new() } else { "└─ ".into() }),
            )];
            let name = format!("{} ({})", a.name, a.pid);
            if i == last {
                spans.push(styled(Style::new().fg(GREEN).add_modifier(Modifier::BOLD), name));
                spans.push(styled(Style::new().fg(GREEN), " ←"));
            } else {
                spans.push(Span::raw(name));
            }
            v.push(Line::from(spans));
        }
    }
    if let Some(risk) = &r.risk {
        if risk.score > 0 {
            v.push(Line::from(""));
            v.push(Line::from(styled(
                Style::new().fg(Color::Yellow),
                format!("⚠ risk {}/10: {}", risk.score, risk.signals.join("; ")),
            )));
        }
    }
    if !r.warnings.is_empty() {
        v.push(Line::from(""));
        for w in &r.warnings {
            v.push(Line::from(styled(Style::new().fg(Color::Yellow), format!("⚠ {}", w))));
        }
    }
    v
}

// ---------- UI ----------

fn tab_bar(app: &TuiApp) -> Line<'static> {
    let mut spans = vec![
        styled(Style::new().bg(PURPLE).fg(Color::White).bold(), " witr-rs "),
        Span::raw("  "),
    ];
    if let Some(i) = app.replay_pos {
        let (at, _) = &app.replay_ring[i];
        spans.push(styled(
            Style::new().bg(Color::Yellow).fg(Color::Black).bold(),
            format!(
                " REPLAY {} ({}/{}) ",
                crate::util::fmt_time(*at),
                i + 1,
                app.replay_ring.len()
            ),
        ));
        spans.push(Span::raw(" "));
    }
    for t in [
        Tab::Processes,
        Tab::Ports,
        Tab::Containers,
        Tab::Locks,
        Tab::Events,
        Tab::Services,
    ] {
        if app.tab == t {
            spans.push(styled(
                Style::new().bg(GREEN).fg(Color::White).bold(),
                format!(" {} ", t.title()),
            ));
        } else {
            spans.push(styled(
                Style::new().bg(MID).fg(Color::White),
                format!(" {} ", t.title()),
            ));
        }
        spans.push(Span::raw(" "));
    }
    Line::from(spans)
}

fn mode_line(app: &TuiApp) -> Line<'static> {
    if let Some(pid) = app.confirm_kill {
        return Line::from(styled(
            Style::new().fg(Color::Red).bold(),
            format!("  Mode: Confirm — kill pid {}? (y/n)", pid),
        ));
    }
    if let Some((root, tree)) = &app.confirm_tree_kill {
        return Line::from(styled(
            Style::new().fg(Color::Red).bold(),
            format!(
                "  Mode: Confirm — kill pid {root} + {} descendant(s) ({}…)? y/n",
                tree.len(),
                tree.first().map(|p| p.to_string()).unwrap_or_default()
            ),
        ));
    }
    if let Some(input) = &app.note_input {
        let name = app
            .selected_pid()
            .and_then(|pid| app.procs.iter().find(|p| p.pid == pid))
            .map(|p| p.name.clone())
            .unwrap_or_default();
        return Line::from(vec![
            styled(
                Style::new().fg(Color::Yellow).bold(),
                format!("  Mode: Note — annotation for {name}: "),
            ),
            Span::raw(input.clone()),
            styled(Style::new().fg(Color::Yellow), "▏"),
            styled(Style::new().fg(MID), "  (Enter: save — Esc: discard — empty text removes)"),
        ]);
    }
    if let Some(input) = &app.renice_input {
        let pid = app.detail_pid.or_else(|| app.selected_pid()).unwrap_or(0);
        return Line::from(vec![
            styled(
                Style::new().fg(Color::Yellow).bold(),
                format!("  Mode: Renice — nice value for pid {pid} (−20…19): "),
            ),
            Span::raw(input.clone()),
            styled(Style::new().fg(Color::Yellow), "▏"),
            styled(Style::new().fg(MID), "  (Enter: apply — any other key cancels)"),
        ]);
    }
    if app.actions_open {
        return Line::from(styled(
            Style::new().fg(Color::Yellow).bold(),
            format!(
                "  Mode: Actions on pid {} — [k]ill [K]ill tree [t]erm [p]ause [r]esume [n]ice (Esc: cancel)",
                app.detail_pid.or_else(|| app.selected_pid()).unwrap_or(0)
            ),
        ));
    }
    if app.search_mode {
        return Line::from(styled(Style::new().fg(ACCENT), "  Mode: Search (Enter: apply — Esc: cancel)"));
    }
    let (text, style) = match app.focus {
        Focus::Details => (
            "  Mode: Detail (Tab to go back)".to_string(),
            Style::new().fg(ACCENT),
        ),
        Focus::Table => (
            "  Mode: Navigation (Press / to search)".to_string(),
            Style::new().fg(MID),
        ),
    };
    let text = if app.browse_zoom {
        format!("{text} — zoomed (z to restore)")
    } else {
        text
    };
    Line::from(styled(style, text))
}

fn search_line(app: &TuiApp) -> Line<'static> {
    let (val, placeholder) = if app.tab == Tab::Ports {
        (
            app.port_search.clone(),
            "Search Port, PID, Process, Address...",
        )
    } else if app.tab == Tab::Containers {
        (
            app.container_search.clone(),
            "Search Name, Image, ID, State...",
        )
    } else if app.tab == Tab::Locks {
        (
            app.lock_search.clone(),
            "Search Type, Mode, PID, Process, Path...",
        )
    } else if app.tab == Tab::Events {
        (
            app.event_search.clone(),
            "Search Event, PID, Process, Detail...",
        )
    } else if app.tab == Tab::Services {
        (
            app.service_search.clone(),
            "Search Name, Manager, State, PID...",
        )
    } else {
        (app.search.clone(), "Search PID, Name, User...")
    };
    if val.is_empty() && !app.search_mode {
        return Line::from(vec![
            styled(Style::new().fg(ACCENT).bold(), "  > "),
            styled(Style::new().fg(MID), placeholder),
        ]);
    }
    let cursor = if app.search_mode { "▏" } else { "" };
    Line::from(vec![
        styled(Style::new().fg(ACCENT).bold(), "  > "),
        Span::raw(val),
        styled(Style::new().fg(ACCENT), cursor),
    ])
}

fn processes_table(app: &mut TuiApp, area: ratatui::prelude::Rect, f: &mut Frame<'_>) {
    if app.group_mode != GroupMode::Off {
        groups_table(app, area, f);
        return;
    }
    let arrow = |cur: SortKey, key: SortKey, desc: bool| {
        if cur == key {
            if desc { " ↓" } else { " ↑" }
        } else {
            ""
        }
    };
    let (k, d) = (app.sort_key, app.sort_desc);
    // GPU column only when the host actually reports NVIDIA usage — it
    // would be dead width everywhere else. Same idea for IO (Linux fills
    // the cumulative counters; macOS/Windows never do).
    let has_gpu = app.procs.iter().any(crate::gpu::has_gpu_data);
    let has_io = app.procs.iter().any(|p| p.io_read_bytes.is_some() || p.io_write_bytes.is_some());
    let mut header: Vec<Cell> = vec![
        Cell::from(format!("PID{}", arrow(k, SortKey::Pid, d))),
        Cell::from(format!("User{}", arrow(k, SortKey::User, d))),
        Cell::from(format!("Name{}", arrow(k, SortKey::Name, d))),
        Cell::from(format!("CPU%{}", arrow(k, SortKey::Cpu, d))),
        Cell::from("Trend"),
        Cell::from(format!("Mem{}", arrow(k, SortKey::Mem, d))),
    ];
    let mut widths: Vec<Constraint> = vec![
        Constraint::Length(7),
        Constraint::Length(12),
        Constraint::Min(18),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(8),
    ];
    if has_io {
        header.push(Cell::from(format!("IO{}", arrow(k, SortKey::Io, d))));
        widths.push(Constraint::Length(8));
    }
    if has_gpu {
        header.push(Cell::from("GPU"));
        widths.push(Constraint::Length(9));
    }
    header.push(Cell::from("Rst"));
    header.push(Cell::from(format!("Age{}", arrow(k, SortKey::Started, d))));
    widths.push(Constraint::Length(4));
    widths.push(Constraint::Length(9));
    let header = Row::new(header).style(Style::new().fg(ACCENT).bold());

    let tree = app.tree_mode && !app.view_depth.is_empty();
    let rows: Vec<Row> = app
        .view
        .iter()
        .enumerate()
        .filter_map(|(vi, &i)| app.procs.get(i).map(|p| (vi, p)))
        .map(|(vi, p)| {
            let cpu = app.hist.display_cpu(p);
            let rst = app.hist.total_restarts(p.pid);
            // tree mode: nest the name under its parent with a branch glyph
            let name = if tree {
                let d = app.view_depth.get(vi).copied().unwrap_or(0);
                if d == 0 {
                    p.name.clone()
                } else {
                    format!("{}└─ {}", "  ".repeat(d - 1), p.name)
                }
            } else {
                p.name.clone()
            };
            // watchlist ('w'): star prefix — matches the config `watch` key,
            // so the mark survives restarts under a new pid
            let name = if app.is_watched(p) {
                format!("★ {name}")
            } else {
                name
            };
            // annotation ('N'): pencil suffix, same identity-key persistence
            let name = if app.note_of(p).is_some() {
                format!("{name} ✎")
            } else {
                name
            };
            // a pid with an active (un-rearmed) threshold alert glows red
            let name = if app
                .alert_state
                .get(&p.pid)
                .is_some_and(|t| {
                    t.cpu_firing
                        || t.mem_firing
                        || t.fd_firing
                        || t.io_firing
                        || t.conn_firing
                })
            {
                Cell::from(name).style(Style::new().fg(Color::Red).bold())
            } else {
                Cell::from(name)
            };
            let mut cells = vec![
                Cell::from(p.pid.to_string()),
                Cell::from(p.user.clone().unwrap_or_else(|| "-".into())),
                name,
                Cell::from(cpu.map(|c| format!("{:.1}", c)).unwrap_or_else(|| "-".into())),
                Cell::from(app.hist.spark(p.pid).unwrap_or("").to_string()),
                Cell::from(fmt_mem(p.mem_kb)),
            ];
            if has_io {
                let cell = app
                    .hist
                    .io_rate_of(p.pid)
                    .map(|(r, w)| crate::util::fmt_rate(r + w))
                    .unwrap_or_else(|| "-".into());
                cells.push(Cell::from(cell));
            }
            if has_gpu {
                cells.push(Cell::from(crate::gpu::cell(p)));
            }
            cells.push(Cell::from(if rst > 0 { rst.to_string() } else { String::new() }));
            cells.push(Cell::from(fmt_age_short(p.started)));
            Row::new(cells)
        })
        .collect();

    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(2)
        .row_highlight_style(Style::new().bg(PURPLE).fg(Color::White).bold());
    f.render_stateful_widget(table, area, &mut app.table_state);
}

/// The grouped process table ('B'): one row per program/user/container
/// with the members' CPU/mem/IO summed. Enter opens the busiest member.
fn groups_table(app: &mut TuiApp, area: ratatui::prelude::Rect, f: &mut Frame<'_>) {
    let header = Row::new(["Group", "Procs", "CPU%", "Mem", "IO"])
        .style(Style::new().fg(ACCENT).bold());
    let rows: Vec<Row> = app
        .group_view
        .iter()
        .map(|g| {
            Row::new([
                Cell::from(g.key.clone()),
                Cell::from(g.count.to_string()),
                Cell::from(if g.cpu > 0.0 {
                    format!("{:.1}", g.cpu)
                } else {
                    "-".into()
                }),
                Cell::from(fmt_mem(Some(g.mem_kb))),
                Cell::from(if g.io_bps > 0.0 {
                    crate::util::fmt_rate(g.io_bps)
                } else {
                    "-".into()
                }),
            ])
        })
        .collect();
    let widths = [
        Constraint::Min(28),
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Length(9),
        Constraint::Length(9),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(3)
        .row_highlight_style(Style::new().bg(PURPLE).fg(Color::White).bold());
    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn ports_table(app: &mut TuiApp, area: ratatui::prelude::Rect, f: &mut Frame<'_>) {
    if app.ports_overview {
        ports_overview_table(app, area, f);
        return;
    }
    let header = Row::new(["Proto", "Local", "State", "PID", "Process"])
        .style(Style::new().fg(ACCENT).bold());
    let name_by_pid: HashMap<Pid, String> =
        app.procs.iter().map(|p| (p.pid, p.name.clone())).collect();
    let rows: Vec<Row> = app
        .socket_view
        .iter()
        .filter_map(|&i| app.sockets.get(i))
        .map(|s| {
            Row::new([
                Cell::from(s.proto.clone()),
                Cell::from(format!("{}:{}", s.local_addr, s.local_port)),
                Cell::from(s.state.clone()),
                Cell::from(s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())),
                Cell::from(
                    s.pid
                        .and_then(|p| name_by_pid.get(&p).cloned())
                        .unwrap_or_else(|| "-".into()),
                ),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(6),
        Constraint::Length(34),
        Constraint::Length(14),
        Constraint::Length(9),
        Constraint::Min(24),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(3)
        .row_highlight_style(Style::new().bg(PURPLE).fg(Color::White).bold());
    f.render_stateful_widget(table, area, &mut app.table_state);
}

/// The Ports-tab overview ('o'): one row per (port, owner) instead of one
/// row per socket — answers "who is serving what" at a glance. Enter jumps
/// to the owning process's detail page.
fn ports_overview_table(app: &mut TuiApp, area: ratatui::prelude::Rect, f: &mut Frame<'_>) {
    let header = Row::new(["Port", "Proto(s)", "Process", "PID", "User", "Scope", "Addrs"])
        .style(Style::new().fg(ACCENT).bold());
    let rows: Vec<Row> = app
        .port_overview_view
        .iter()
        .map(|r| {
            // internet-reachable bindings shout (yellow); loopback-only
            // ones recede
            let scope_cell = match r.scope {
                "internet" => Cell::from(r.scope).style(Style::new().fg(Color::Yellow).bold()),
                "loopback" => Cell::from(r.scope).style(Style::new().fg(MID)),
                _ => Cell::from(r.scope),
            };
            Row::new([
                Cell::from(r.port.to_string()),
                Cell::from(r.protos.clone()),
                Cell::from(r.name.clone()),
                Cell::from(r.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())),
                Cell::from(r.user.clone()),
                scope_cell,
                Cell::from(r.addrs.to_string()),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(8),
        Constraint::Length(12),
        Constraint::Min(24),
        Constraint::Length(9),
        Constraint::Length(16),
        Constraint::Length(9),
        Constraint::Length(8),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(3)
        .row_highlight_style(Style::new().bg(PURPLE).fg(Color::White).bold());
    f.render_stateful_widget(table, area, &mut app.table_state);
}

/// State-cell color: green for healthy/running, red for unhealthy or dead,
/// yellow for the transient states, muted for everything else.
fn container_state_style(c: &crate::model::Container) -> Style {
    let tag = c.state_tag();
    if tag.contains("unhealthy") {
        Style::new().fg(Color::Red).bold()
    } else if tag == "starting" || tag == "restarting" || tag == "paused" {
        Style::new().fg(Color::Yellow)
    } else if tag == "healthy" || c.state == "running" {
        Style::new().fg(GREEN)
    } else {
        Style::new().fg(MID)
    }
}

/// "12.50%" from the stats sweep; "-" until the first sweep lands.
fn container_cpu_disp(c: &crate::model::Container) -> String {
    c.cpu_pct.map(|p| format!("{p:.2}%")).unwrap_or_else(|| "-".into())
}

/// "12.3Mi/1.9Gi" from the stats sweep; "-" until the first sweep lands.
fn container_mem_disp(c: &crate::model::Container) -> String {
    match (c.mem_used_mb, c.mem_total_mb) {
        (Some(u), Some(t)) if t > 0 => {
            format!("{:.1}Mi/{:.1}Gi", u as f64 / 1024.0, t as f64 / 1024.0)
        }
        (Some(u), _) => format!("{u}Mi"),
        _ => "-".into(),
    }
}

/// Memory brightens as the container crowds its own limit (≥90% red,
/// ≥70% yellow — a container bumping its cap is the usual OOM prologue).
fn container_mem_style(c: &crate::model::Container) -> Style {
    let frac = match (c.mem_used_mb, c.mem_total_mb) {
        (Some(u), Some(t)) if t > 0 => u as f64 / t as f64,
        _ => 0.0,
    };
    if frac >= 0.9 {
        Style::new().fg(Color::Red).bold()
    } else if frac >= 0.7 {
        Style::new().fg(Color::Yellow)
    } else {
        Style::new()
    }
}

fn containers_table(app: &mut TuiApp, area: ratatui::prelude::Rect, f: &mut Frame<'_>) {
    // Pod column only when k8s attribution actually produced something —
    // it's dead width on plain-docker hosts. Same for the CPU%/MEM columns:
    // they appear once the first stats sweep has landed (stats cost ~2s
    // per runtime CLI, so they arrive after the listing). THR%/OOM ride
    // the same pattern — cgroup pressure readings from the first sweep.
    let has_pod = app.containers.iter().any(|c| c.pod.is_some());
    let has_stats = app.containers.iter().any(|c| c.cpu_pct.is_some());
    let has_thr = app.throttle_pct.values().any(|v| *v > 0.0);
    let has_oom = app.containers.iter().any(|c| c.oom_kills.is_some());
    let has_compose = app.containers.iter().any(|c| c.compose.is_some());
    let mut header: Vec<Cell> = vec![
        Cell::from("Runtime"),
        Cell::from("ID"),
        Cell::from("State"),
        Cell::from("Status"),
    ];
    let mut widths: Vec<Constraint> = vec![
        Constraint::Length(8),
        Constraint::Length(13),
        Constraint::Length(10),
        Constraint::Length(24),
    ];
    if has_stats {
        header.push(Cell::from("CPU%"));
        header.push(Cell::from("MEM"));
        widths.push(Constraint::Length(8));
        widths.push(Constraint::Length(15));
    }
    if has_thr {
        header.push(Cell::from("THR%"));
        widths.push(Constraint::Length(7));
    }
    if has_oom {
        header.push(Cell::from("OOM"));
        widths.push(Constraint::Length(5));
    }
    if has_compose {
        header.push(Cell::from("Compose"));
        widths.push(Constraint::Length(16));
    }
    if has_pod {
        header.push(Cell::from("Pod"));
        widths.push(Constraint::Length(24));
    }
    header.push(Cell::from("Image"));
    header.push(Cell::from("Name"));
    widths.push(Constraint::Min(20));
    widths.push(Constraint::Min(18));
    let header = Row::new(header).style(Style::new().fg(ACCENT).bold());
    let rows: Vec<Row> = app
        .container_view
        .iter()
        .filter_map(|&i| app.containers.get(i))
        .map(|c| {
            let mut cells = vec![
                Cell::from(c.runtime.clone()),
                Cell::from(c.id.chars().take(12).collect::<String>()),
                Cell::from(c.state.clone()).style(container_state_style(c)),
                Cell::from(c.status.clone()),
            ];
            if has_stats {
                cells.push(Cell::from(container_cpu_disp(c)));
                cells.push(Cell::from(container_mem_disp(c)).style(container_mem_style(c)));
            }
            let key: String = c.id.chars().take(12).collect();
            if has_thr {
                let cell = match app.throttle_pct.get(&key) {
                    Some(pct) if *pct > 0.0 => {
                        let style = if *pct >= 50.0 {
                            Style::new().fg(Color::Red).bold()
                        } else {
                            Style::new().fg(Color::Yellow)
                        };
                        Cell::from(format!("{pct:.0}%")).style(style)
                    }
                    _ => Cell::from("-"),
                };
                cells.push(cell);
            }
            if has_oom {
                let cell = match c.oom_kills {
                    Some(n) if n > 0 => {
                        Cell::from(format!("{n}")).style(Style::new().fg(Color::Red).bold())
                    }
                    Some(_) => Cell::from("0"),
                    None => Cell::from("-"),
                };
                cells.push(cell);
            }
            if has_compose {
                cells.push(Cell::from(
                    c.compose.clone().unwrap_or_else(|| "-".into()),
                ));
            }
            if has_pod {
                cells.push(Cell::from(c.pod.clone().unwrap_or_else(|| "-".into())));
            }
            cells.push(Cell::from(c.image.clone()));
            cells.push(Cell::from(c.name.clone()));
            Row::new(cells)
        })
        .collect();
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(3)
        .row_highlight_style(Style::new().bg(PURPLE).fg(Color::White).bold());
    f.render_stateful_widget(table, area, &mut app.table_state);
}

/// Green for running units, red for failed, dim elsewhere.
fn service_state_style(s: &crate::model::Service) -> Style {
    let st = s.state.to_ascii_lowercase();
    if st.contains("fail") {
        Style::new().fg(Color::Red).bold()
    } else if st.starts_with("active") || st.starts_with("running") {
        Style::new().fg(Color::Green)
    } else {
        Style::new().fg(MID)
    }
}

/// The Services table: Name | Manager | State | PID | Description, with
/// the sort key shown in each header (n:Name, m:Manager, s:State, p:PID).
fn services_table(app: &mut TuiApp, area: ratatui::prelude::Rect, f: &mut Frame<'_>) {
    let cols = [
        ("n", "Name", ServiceSort::Name),
        ("m", "Manager", ServiceSort::Manager),
        ("s", "State", ServiceSort::State),
        ("p", "PID", ServiceSort::Pid),
    ];
    let header = Row::new(
        cols.iter()
            .map(|(key, name, col)| {
                let mut title = format!("{key}:{name}");
                if app.service_sort == Some(*col) {
                    title.push_str(if app.service_sort_desc { " ↓" } else { " ↑" });
                }
                Cell::from(title)
            })
            .chain(std::iter::once(Cell::from("Description")))
            .collect::<Vec<_>>(),
    )
    .style(Style::new().fg(ACCENT).bold());
    let rows: Vec<Row> = app
        .service_view
        .iter()
        .filter_map(|&i| app.services.get(i))
        .map(|s| {
            Row::new([
                Cell::from(s.name.clone()),
                Cell::from(s.manager.clone()),
                Cell::from(s.state.clone()).style(service_state_style(s)),
                Cell::from(s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())),
                Cell::from(s.desc.clone()),
            ])
        })
        .collect();
    let widths = [
        Constraint::Min(28),
        Constraint::Length(9),
        Constraint::Length(16),
        Constraint::Length(8),
        Constraint::Min(24),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(3)
        .row_highlight_style(Style::new().bg(PURPLE).fg(Color::White).bold());
    f.render_stateful_widget(table, area, &mut app.table_state);
}
/// The Locks table (live selection — j/k moves, Enter jumps to the holder).
/// Column layout mirrors the Go witr: PID | Process | Type | Mode | Path,
/// with the sort key shown in each header (p:PID, n:Process, ...) and a
/// direction arrow on the active sort column.
fn locks_table(app: &mut TuiApp, area: ratatui::prelude::Rect, f: &mut Frame<'_>) {
    let cols = [
        ("p", "PID", LockSort::Pid),
        ("n", "Process", LockSort::Process),
        ("t", "Type", LockSort::Type),
        ("m", "Mode", LockSort::Mode),
        ("f", "Path", LockSort::Path),
    ];
    let header = Row::new(cols.iter().map(|(key, name, col)| {
        let mut title = format!("{key}:{name}");
        if app.lock_sort == *col {
            title.push_str(if app.lock_sort_desc { " ↓" } else { " ↑" });
        }
        Cell::from(title)
    }))
    .style(Style::new().fg(ACCENT).bold());
    let rows: Vec<Row> = app
        .lock_view
        .iter()
        .map(|&i| {
            let l = &app.locks[i];
            Row::new([
                Cell::from(l.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())),
                Cell::from(l.owner.clone()),
                Cell::from(l.kind.clone()),
                Cell::from(l.mode.clone()),
                Cell::from(l.path.clone()),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(8),
        Constraint::Length(18),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Min(30),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(2)
        .row_highlight_style(Style::new().bg(PURPLE).fg(Color::White).bold());
    f.render_stateful_widget(table, area, &mut app.lock_state);
}

/// The Events table: the sampling history's appear/exit/restart ring,
/// newest first. Time | Event | PID | Process | Detail.
fn events_table(app: &mut TuiApp, area: ratatui::prelude::Rect, f: &mut Frame<'_>) {
    let arrow = |name: &str, col: EventSort| {
        if app.event_sort == col {
            format!("{name} {}", if app.event_sort_desc { "↓" } else { "↑" })
        } else {
            name.to_string()
        }
    };
    let header = Row::new([
        arrow("Time", EventSort::Time),
        arrow("Event", EventSort::Kind),
        arrow("PID", EventSort::Pid),
        arrow("Process", EventSort::Process),
        "Detail".to_string(),
    ])
    .style(Style::new().fg(ACCENT).bold());
    let rows: Vec<Row> = app
        .event_view
        .iter()
        .filter_map(|&i| app.hist.events.get(i))
        .map(|e| {
            let kind = match e.kind.as_str() {
                "started" => "started",
                "exited" => "exited",
                "alert" => "ALERT",
                _ => "restarted",
            };
            // alert rows stand out: red kind cell, the detail column
            // carries the metric that tripped
            let kind_cell = if e.kind == "alert" {
                Cell::from(kind).style(Style::new().fg(Color::Red).bold())
            } else {
                Cell::from(kind)
            };
            Row::new([
                Cell::from(fmt_age_short(Some(e.at_unix))),
                kind_cell,
                Cell::from(e.pid.to_string()),
                Cell::from(e.name.clone()),
                Cell::from(e.detail.clone()),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Min(16),
        Constraint::Min(30),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(3)
        .row_highlight_style(Style::new().bg(PURPLE).fg(Color::White).bold());
    f.render_stateful_widget(table, area, &mut app.event_state);
}

/// Full-page process detail (the Go witr's stateDetail): header with the
/// pid, left "Process Detail" pane, right "Environment Variables" pane,
/// focus shown by title/border color, per-pane scroll indicators.
/// Row count after the paragraph wraps long lines at `width` — scroll
/// clamps and indicators must count wrapped rows, not logical lines.
fn wrapped_count(lines: &[Line<'_>], width: u16) -> u16 {
    let w = width.max(1) as usize;
    lines
        .iter()
        .map(|l| {
            let lw = l.width();
            if lw == 0 {
                1
            } else {
                lw.div_ceil(w) as u16
            }
        })
        .sum()
}

/// Approximate inner width of a percentage pane (±1px, good enough for
/// scroll indicators) — percentage splits include a 1px divider gap.
fn pane_inner_width(total: u16, pct: u16) -> u16 {
    let share = total.saturating_sub(1) as usize * pct as usize / 100;
    (share as u16).saturating_sub(2)
}

fn ui_detail_page(app: &mut TuiApp, f: &mut Frame<'_>) {
    let outer = Block::bordered().border_style(Style::new().fg(GRAY));
    f.render_widget(&outer, f.area());
    let inner = outer.inner(f.area());
    let v = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Length(1),
        Constraint::Min(6),    // panes
        Constraint::Length(1), // footer
    ])
    .split(inner);

    // zoom collapses the split to just the focused pane (tmux-style z)
    let (dl, dr) = if app.detail_zoom {
        if app.detail_pane { (100, 0) } else { (0, 100) }
    } else {
        (70, 30)
    };

    // pane content sizes first: indicators need the wrapped row counts
    let env = app.env_lines();
    app.detail_line_count = wrapped_count(&app.detail_lines, pane_inner_width(v[2].width, dl));
    app.env_line_count = wrapped_count(&env, pane_inner_width(v[2].width, dr));

    let header = Line::from(vec![
        styled(Style::new().bg(PURPLE).fg(Color::White).bold(), " witr-rs "),
        Span::raw("  "),
        styled(
            Style::new().fg(ACCENT).bold(),
            format!("PID {}", app.detail_pid.unwrap_or(0)),
        ),
        Span::raw("  "),
        styled(Style::new().fg(MID), "Process Detail"),
    ]);
    f.render_widget(Paragraph::new(header), v[0]);

    // environment search line (occupies the spacer row while active)
    if app.env_search_mode || !app.env_search.is_empty() {
        let shown = app.env_lines().len();
        let total = app
            .detail_report
            .as_ref()
            .and_then(|r| r.matches[0].env.as_ref())
            .map(|e| e.len())
            .unwrap_or(0);
        let mut spans = vec![
            styled(Style::new().fg(ACCENT).bold(), "  / "),
            Span::raw(app.env_search.clone()),
        ];
        if app.env_search_mode {
            spans.push(styled(Style::new().fg(ACCENT), "▏"));
        }
        if !app.env_search.is_empty() {
            spans.push(styled(
                Style::new().fg(MID),
                format!("  {} of {} vars", shown, total),
            ));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), v[1]);
    }

    let cols = Layout::horizontal([Constraint::Percentage(dl), Constraint::Percentage(dr)])
        .split(v[2]);

    // mouse mapping: left pane = process detail, right = environment
    app.tab_rect = None;
    app.table_rect = Some(cols[0]);
    app.detail_rect = Some(cols[1]);

    // left: process detail
    let d_active = app.detail_pane;
    let d_title = format!(
        "Process Detail{}{}",
        if app.detail_zoom && d_active { " [zoom]" } else { "" },
        TuiApp::scroll_indicator(app.detail_scroll, app.detail_line_count, app.detail_height)
    );
    let d_block = Block::bordered()
        .title(Line::from(styled(
            if d_active {
                Style::new().fg(ACCENT).bold()
            } else {
                Style::new().fg(MID)
            },
            d_title,
        )))
        .border_style(if d_active {
            Style::new().fg(ACCENT)
        } else {
            Style::new().fg(GRAY)
        });
    let d_inner = d_block.inner(cols[0]);
    app.detail_height = d_inner.height;
    f.render_widget(d_block, cols[0]);
    let d_scroll = app.detail_scroll.min(app.detail_line_count.saturating_sub(1));
    f.render_widget(
        Paragraph::new(app.detail_lines.clone())
            .wrap(Wrap { trim: false })
            .scroll((d_scroll, 0)),
        d_inner,
    );

    // right: environment variables
    let e_title = format!(
        "Environment Variables{}{}",
        if app.detail_zoom && !d_active { " [zoom]" } else { "" },
        TuiApp::scroll_indicator(app.env_scroll, app.env_line_count, app.detail_height)
    );
    let e_block = Block::bordered()
        .title(Line::from(styled(
            if !d_active {
                Style::new().fg(ACCENT).bold()
            } else {
                Style::new().fg(MID)
            },
            e_title,
        )))
        .border_style(if !d_active {
            Style::new().fg(ACCENT)
        } else {
            Style::new().fg(GRAY)
        });
    let e_inner = e_block.inner(cols[1]);
    f.render_widget(e_block, cols[1]);
    f.render_widget(
        Paragraph::new(env)
            .wrap(Wrap { trim: false })
            .scroll((app.env_scroll.min(app.env_line_count.saturating_sub(1)), 0)),
        e_inner,
    );

    let mut footer = if app.actions_open {
        "Esc/q: cancel | Actions: [k]ill [t]erm [p]ause [r]esume [n]ice".to_string()
    } else if app.env_search_mode {
        "Search env: Enter: apply — Esc: cancel".to_string()
    } else {
        "j/k/d/u/g/G/b-f: Scroll | Tab: Focus | z: Zoom | /: Search Env | a: Actions | l: Logs | Esc/q: Back | c: Copy"
            .to_string()
    };
    if !app.status.is_empty() {
        footer.push_str(&format!("  ·  {}", app.status));
    }
    f.render_widget(
        Paragraph::new(Line::from(styled(Style::new().fg(MID), footer))),
        v[3],
    );
}

/// Full-page port detail (Ports tab, Enter): every socket touching the
/// port — the LISTEN entry plus the current requests — and the owner.
fn ui_port_detail_page(app: &mut TuiApp, f: &mut Frame<'_>) {
    let outer = Block::bordered().border_style(Style::new().fg(GRAY));
    f.render_widget(&outer, f.area());
    let inner = outer.inner(f.area());
    let v = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Length(1),
        Constraint::Min(8),    // connections
        Constraint::Min(5),    // owner
        Constraint::Length(1), // footer
    ])
    .split(inner);

    // mouse mapping: connections pane above, owner pane below
    app.tab_rect = None;
    app.table_rect = Some(v[2]);
    app.detail_rect = Some(v[3]);

    let n = app.port_detail_sockets.len();
    let established = app
        .port_detail_sockets
        .iter()
        .filter(|s| s.state == "ESTABLISHED")
        .count();
    let header = Line::from(vec![
        styled(Style::new().bg(PURPLE).fg(Color::White).bold(), " witr-rs "),
        Span::raw("  "),
        styled(
            Style::new().fg(ACCENT).bold(),
            format!("Port {}", app.port_detail_port),
        ),
        Span::raw("  "),
        styled(
            Style::new().fg(MID),
            format!("{} socket(s), {} established request(s)", n, established),
        ),
    ]);
    f.render_widget(Paragraph::new(header), v[0]);

    // connections pane
    let conn_lines = app.port_connection_lines();
    let c_title = format!(
        "Connections{}",
        TuiApp::scroll_indicator(app.port_scroll, conn_lines.len() as u16, app.port_pane_height)
    );
    let c_block = Block::bordered()
        .title(Line::from(styled(
            if app.port_pane_conn {
                Style::new().fg(ACCENT).bold()
            } else {
                Style::new().fg(MID)
            },
            c_title,
        )))
        .border_style(if app.port_pane_conn {
            Style::new().fg(ACCENT)
        } else {
            Style::new().fg(GRAY)
        });
    let c_inner = c_block.inner(v[2]);
    app.port_pane_height = c_inner.height;
    f.render_widget(c_block, v[2]);
    let c_scroll = app
        .port_scroll
        .min(conn_lines.len().saturating_sub(1) as u16);
    f.render_widget(
        Paragraph::new(conn_lines).scroll((c_scroll, 0)),
        c_inner,
    );

    // owner pane
    let owner_lines = match &app.port_detail_report {
        Some(r) => {
            let pid = r.matches[0].pid;
            let own: Vec<Socket> = r
                .sockets
                .iter()
                .filter(|s| s.pid == Some(pid))
                .cloned()
                .collect();
            detail_lines(r, &own, &[])
        }
        None => vec![Line::from(styled(
            Style::new().fg(MID),
            "no owning process visible (kernel-held socket, or permission needed — try sudo)",
        ))],
    };
    let owner_count = wrapped_count(&owner_lines, v[3].width.saturating_sub(2));
    let o_title = format!(
        "Owner{}",
        TuiApp::scroll_indicator(app.port_owner_scroll, owner_count, app.detail_height)
    );
    let o_block = Block::bordered()
        .title(Line::from(styled(
            if !app.port_pane_conn {
                Style::new().fg(ACCENT).bold()
            } else {
                Style::new().fg(MID)
            },
            o_title,
        )))
        .border_style(if !app.port_pane_conn {
            Style::new().fg(ACCENT)
        } else {
            Style::new().fg(GRAY)
        });
    let o_inner = o_block.inner(v[3]);
    f.render_widget(o_block, v[3]);
    let o_scroll = app.port_owner_scroll.min(owner_count.saturating_sub(1));
    f.render_widget(
        Paragraph::new(owner_lines)
            .wrap(Wrap { trim: false })
            .scroll((o_scroll, 0)),
        o_inner,
    );

    let mut footer = "j/k/d/u/g/G/b-f: Scroll | Tab: Focus | Esc/q: Back | c: Copy".to_string();
    if !app.status.is_empty() {
        footer.push_str(&format!("  ·  {}", app.status));
    }
    f.render_widget(
        Paragraph::new(Line::from(styled(Style::new().fg(MID), footer))),
        v[4],
    );
}

/// Full-page container detail (Containers tab, Enter): container attributes
/// plus the in-container process list (Linux; other platforms show a note).
fn ui_container_detail_page(app: &mut TuiApp, f: &mut Frame<'_>) {
    let outer = Block::bordered().border_style(Style::new().fg(GRAY));
    f.render_widget(&outer, f.area());
    let inner = outer.inner(f.area());
    let v = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Length(1),
        Constraint::Min(6),    // panes
        Constraint::Length(1), // footer
    ])
    .split(inner);

    let (name, state, status) = match &app.container_detail {
        Some(c) => (c.name.clone(), c.state.clone(), c.status.clone()),
        None => ("-".into(), "-".into(), String::new()),
    };
    let state_style = if status.contains("unhealthy") {
        Style::new().fg(Color::Red).bold()
    } else if state == "running" {
        Style::new().fg(GREEN).bold()
    } else {
        Style::new().fg(MID)
    };
    let header = Line::from(vec![
        styled(Style::new().bg(PURPLE).fg(Color::White).bold(), " witr-rs "),
        Span::raw("  "),
        styled(Style::new().fg(ACCENT).bold(), format!("Container {name}")),
        Span::raw("  "),
        Span::styled(state.clone(), state_style),
    ]);
    f.render_widget(Paragraph::new(header), v[0]);

    let cols = Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(v[2]);

    // mouse mapping: info pane left, in-container processes right
    app.tab_rect = None;
    app.table_rect = Some(cols[0]);
    app.detail_rect = Some(cols[1]);

    // left: container attributes
    let info = app.container_info_lines();
    app.detail_line_count = wrapped_count(&info, cols[0].width.saturating_sub(2));
    let i_title = format!(
        "Container{}",
        TuiApp::scroll_indicator(app.cd_scroll, app.detail_line_count, app.detail_height)
    );
    let i_block = Block::bordered()
        .title(Line::from(styled(
            if app.cd_pane_info {
                Style::new().fg(ACCENT).bold()
            } else {
                Style::new().fg(MID)
            },
            i_title,
        )))
        .border_style(if app.cd_pane_info {
            Style::new().fg(ACCENT)
        } else {
            Style::new().fg(GRAY)
        });
    let i_inner = i_block.inner(cols[0]);
    app.detail_height = i_inner.height;
    f.render_widget(i_block, cols[0]);
    let i_scroll = app.cd_scroll.min(app.detail_line_count.saturating_sub(1));
    f.render_widget(
        Paragraph::new(info)
            .wrap(Wrap { trim: false })
            .scroll((i_scroll, 0)),
        i_inner,
    );

    // right: in-container processes
    let procs = app.container_proc_lines();
    app.env_line_count = wrapped_count(&procs, cols[1].width.saturating_sub(2));
    let p_title = format!(
        "Processes{}",
        TuiApp::scroll_indicator(app.cdp_scroll, app.env_line_count, app.detail_height)
    );
    let p_block = Block::bordered()
        .title(Line::from(styled(
            if !app.cd_pane_info {
                Style::new().fg(ACCENT).bold()
            } else {
                Style::new().fg(MID)
            },
            p_title,
        )))
        .border_style(if !app.cd_pane_info {
            Style::new().fg(ACCENT)
        } else {
            Style::new().fg(GRAY)
        });
    let p_inner = p_block.inner(cols[1]);
    f.render_widget(p_block, cols[1]);
    let p_scroll = app.cdp_scroll.min(app.env_line_count.saturating_sub(1));
    f.render_widget(
        Paragraph::new(procs)
            .wrap(Wrap { trim: false })
            .scroll((p_scroll, 0)),
        p_inner,
    );

    let mut footer = "j/k/d/u/g/G/b-f: Scroll | Tab: Focus | l: Logs | Esc/q: Back | c: Copy".to_string();
    if !app.status.is_empty() {
        footer.push_str(&format!("  ·  {}", app.status));
    }
    f.render_widget(
        Paragraph::new(Line::from(styled(Style::new().fg(MID), footer))),
        v[3],
    );
}

/// Full-page recent-logs view ('l' from the detail / events pages): header
/// naming the source, the fetched lines (or a loading note), key hints.
fn ui_logs_page(app: &mut TuiApp, f: &mut Frame<'_>) {
    let outer = Block::bordered().border_style(Style::new().fg(GRAY));
    f.render_widget(&outer, f.area());
    let inner = outer.inner(f.area());
    let v = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Length(1),
        Constraint::Min(6),    // log lines
        Constraint::Length(1), // footer
    ])
    .split(inner);

    let title = app.logs_for.clone().unwrap_or_else(|| "Logs".into());
    let header = Line::from(vec![
        styled(Style::new().bg(PURPLE).fg(Color::White).bold(), " witr-rs "),
        Span::raw("  "),
        styled(Style::new().fg(ACCENT).bold(), format!("Recent Logs — {title}")),
    ]);
    f.render_widget(Paragraph::new(header), v[0]);

    app.tab_rect = None;
    app.table_rect = Some(v[2]);
    app.detail_rect = Some(v[2]);
    app.logs_pane_h = v[2].height;

    if app.logs_rx.is_some() {
        placeholder(v[2], f, "  fetching logs… (journalctl / log show can take several seconds)");
    } else {
        let lines: Vec<Line<'static>> = app
            .logs_lines
            .iter()
            .map(|l| {
                if l.starts_with('⚠') {
                    Line::from(styled(Style::new().fg(Color::Yellow), l.clone()))
                } else {
                    Line::from(l.clone())
                }
            })
            .collect();
        let count = lines.len() as u16;
        let block = Block::bordered()
            .title(Line::from(styled(
                Style::new().fg(ACCENT).bold(),
                format!("Logs{}", TuiApp::scroll_indicator(app.logs_scroll, count, v[2].height)),
            )))
            .border_style(Style::new().fg(GRAY));
        let area = block.inner(v[2]);
        f.render_widget(block, v[2]);
        let scroll = app.logs_scroll.min(count.saturating_sub(1));
        f.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }).scroll((scroll, 0)),
            area,
        );
    }

    // follow streams container logs, journald and the unified log (the
    // Windows event log has no streaming equivalent)
    let followable = matches!(
        app.logs_src,
        Some(
            crate::logs::LogSource::Container { .. }
                | crate::logs::LogSource::Journald { .. }
                | crate::logs::LogSource::UnifiedLog { .. }
        )
    );
    let mut footer = if followable && app.follow_child.is_some() {
        "F: Stop Follow | j/k/d/u/g/G/b-f: Scroll | Esc/q: Back | c: Copy".to_string()
    } else if followable {
        "F: Follow Stream | j/k/d/u/g/G/b-f: Scroll | Esc/q: Back | c: Copy".to_string()
    } else {
        "j/k/d/u/g/G/b-f: Scroll | Esc/q: Back | c: Copy".to_string()
    };
    if !app.status.is_empty() {
        footer.push_str(&format!("  ·  {}", app.status));
    }
    f.render_widget(
        Paragraph::new(Line::from(styled(Style::new().fg(MID), footer))),
        v[3],
    );
}

fn placeholder(area: ratatui::prelude::Rect, f: &mut Frame<'_>, msg: &str) {
    f.render_widget(
        Paragraph::new(vec![Line::from(""), Line::from(styled(Style::new().fg(MID), msg))]),
        area,
    );
}

/// `82944` → `81.0 GB` (system-page memory/swap lines).
fn human_mb(mb: u64) -> String {
    if mb >= 1024 {
        format!("{:.1} GB", mb as f64 / 1024.0)
    } else {
        format!("{mb} MB")
    }
}

/// Full-page system resources ('y'): machine-wide CPU/memory history
/// charts, load average, swap and the per-core grid. Sampled in refresh()
/// — Linux every cycle (a few /proc reads), the subprocess platforms only
/// while this page is open.
fn ui_system_page(app: &mut TuiApp, f: &mut Frame<'_>) {
    let outer = Block::bordered().border_style(Style::new().fg(GRAY));
    f.render_widget(&outer, f.area());
    let inner = outer.inner(f.area());
    let v = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Length(1),
        Constraint::Min(6),    // meters
        Constraint::Length(1), // footer
    ])
    .split(inner);

    let header = Line::from(vec![
        styled(Style::new().bg(PURPLE).fg(Color::White).bold(), " witr-rs "),
        Span::raw("  "),
        styled(Style::new().fg(ACCENT).bold(), "System Resources"),
    ]);
    f.render_widget(Paragraph::new(header), v[0]);

    app.tab_rect = None;
    app.table_rect = Some(v[2]);
    app.detail_rect = Some(v[2]);

    let lines = app.system_page_lines();
    app.detail_height = lines.len() as u16;
    let count = lines.len() as u16;
    let block = Block::bordered()
        .title(Line::from(styled(
            Style::new().fg(ACCENT).bold(),
            format!("Meters{}", TuiApp::scroll_indicator(app.logs_scroll, count, v[2].height)),
        )))
        .border_style(Style::new().fg(GRAY));
    let area = block.inner(v[2]);
    f.render_widget(block, v[2]);
    let scroll = app.logs_scroll.min(count.saturating_sub(1));
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).scroll((scroll, 0)),
        area,
    );

    let mut footer = "r: Refresh | j/k/d/u/g-G/b-f: Scroll | Esc/q: Back | c: Copy".to_string();
    if !app.status.is_empty() {
        footer.push_str(&format!("  ·  {}", app.status));
    }
    f.render_widget(
        Paragraph::new(Line::from(styled(Style::new().fg(MID), footer))),
        v[3],
    );
}

/// Full-page "what happened" digest ('S'): windowed activity counts,
/// restart chains, the CPU-spike board and the memory climbers. Computed
/// when the page opens; 'r' re-computes from the live history.
fn ui_summary_page(app: &mut TuiApp, f: &mut Frame<'_>) {
    let outer = Block::bordered().border_style(Style::new().fg(GRAY));
    f.render_widget(&outer, f.area());
    let inner = outer.inner(f.area());
    let v = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Length(1),
        Constraint::Min(6),    // digest
        Constraint::Length(1), // footer
    ])
    .split(inner);

    let window = if app.summary_window >= i64::MAX as u64 {
        "whole session".to_string()
    } else {
        format!("last {}", crate::history::human_secs(app.summary_window))
    };
    let header = Line::from(vec![
        styled(Style::new().bg(PURPLE).fg(Color::White).bold(), " witr-rs "),
        Span::raw("  "),
        styled(Style::new().fg(ACCENT).bold(), format!("Session Summary — {window}")),
    ]);
    f.render_widget(Paragraph::new(header), v[0]);

    app.tab_rect = None;
    app.table_rect = Some(v[2]);
    app.detail_rect = Some(v[2]);

    let mut lines: Vec<Line<'static>> = Vec::new();
    match &app.summary {
        None => lines.push(Line::from(styled(
            Style::new().fg(MID),
            "no digest yet — press r to compute",
        ))),
        Some(s) => {
            lines.push(Line::from(vec![
                Span::styled("activity  ", Style::new().bold()),
                Span::raw(format!(
                    "started {} · exited {} · restarted {}",
                    s.started, s.exited, s.restarted
                )),
            ]));
            if s.chains.is_empty()
                && s.spikes.is_empty()
                && s.climbers.is_empty()
                && s.started + s.exited + s.restarted == 0
            {
                lines.push(Line::from(styled(
                    Style::new().fg(MID),
                    "nothing recorded in this window yet — the sampler needs a few refreshes",
                )));
            }
            if !s.chains.is_empty() {
                lines.push(Line::from(Span::styled("restart chains", Style::new().bold())));
                for c in &s.chains {
                    lines.push(Line::from(styled(
                        Style::new().fg(Color::Yellow),
                        format!("  {} ×{}", c.name, c.count),
                    )));
                }
            }
            if !s.spikes.is_empty() {
                lines.push(Line::from(Span::styled(
                    "CPU spikes (while watched)",
                    Style::new().bold(),
                )));
                for sp in &s.spikes {
                    lines.push(Line::from(format!(
                        "  {} (pid {}) peak {:.0}%",
                        sp.name, sp.pid, sp.peak
                    )));
                }
            }
            if !s.climbers.is_empty() {
                lines.push(Line::from(Span::styled("memory climbers", Style::new().bold())));
                for c in &s.climbers {
                    lines.push(Line::from(styled(
                        Style::new().fg(Color::Yellow),
                        format!("  {} (pid {}) +{:.1} MB", c.name, c.pid, c.grew_mb),
                    )));
                }
            }
        }
    }
    app.detail_height = lines.len() as u16;
    let count = lines.len() as u16;
    let block = Block::bordered()
        .title(Line::from(styled(
            Style::new().fg(ACCENT).bold(),
            format!("Digest{}", TuiApp::scroll_indicator(app.logs_scroll, count, v[2].height)),
        )))
        .border_style(Style::new().fg(GRAY));
    let area = block.inner(v[2]);
    f.render_widget(block, v[2]);
    let scroll = app.logs_scroll.min(count.saturating_sub(1));
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).scroll((scroll, 0)),
        area,
    );

    let mut footer = "r: Recompute | j/k/d/u/g/G/b-f: Scroll | Esc/q: Back | c: Copy".to_string();
    if !app.status.is_empty() {
        footer.push_str(&format!("  ·  {}", app.status));
    }
    f.render_widget(
        Paragraph::new(Line::from(styled(Style::new().fg(MID), footer))),
        v[3],
    );
}

/// Full-page snapshot diff ('D'): the newest auto snapshot vs the live
/// table. Computed when the page opens; 'r' re-diffs. j/k move the
/// selection, Enter opens the entry's process detail page.
/// --samples page: the record file's machine samples as a sparkline with
/// a movable cursor (←/→), one of five series charted (↑/↓).
fn ui_samples_page(app: &mut TuiApp, f: &mut Frame<'_>) {
    let outer = Block::bordered().border_style(Style::new().fg(GRAY));
    f.render_widget(&outer, f.area());
    let inner = outer.inner(f.area());
    let v = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Min(4),    // chart + readout
        Constraint::Length(1), // footer
    ])
    .split(inner);

    let header = Line::from(vec![
        styled(Style::new().bg(PURPLE).fg(Color::White).bold(), " witr-rs "),
        Span::raw("  "),
        styled(Style::new().fg(ACCENT).bold(), "Samples"),
    ]);
    f.render_widget(Paragraph::new(header), v[0]);

    app.tab_rect = None;
    app.table_rect = Some(v[1]);
    app.detail_rect = Some(v[1]);

    let lines = app.samples_page_lines(v[1].width as usize);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        v[1],
    );

    let mut footer = "←/→: Move | ↑/↓: Series | g/G: Ends | Esc: Back | c: Copy".to_string();
    if !app.status.is_empty() {
        footer.push_str(&format!("  ·  {}", app.status));
    }
    f.render_widget(
        Paragraph::new(Line::from(styled(Style::new().fg(MID), footer))),
        v[2],
    );
}

fn ui_diff_page(app: &mut TuiApp, f: &mut Frame<'_>) {
    let outer = Block::bordered().border_style(Style::new().fg(GRAY));
    f.render_widget(&outer, f.area());
    let inner = outer.inner(f.area());
    let v = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Length(1),
        Constraint::Min(6),    // entries
        Constraint::Length(1), // footer
    ])
    .split(inner);

    let header = Line::from(vec![
        styled(Style::new().bg(PURPLE).fg(Color::White).bold(), " witr-rs "),
        Span::raw("  "),
        styled(Style::new().fg(ACCENT).bold(), "Snapshot Diff"),
    ]);
    f.render_widget(Paragraph::new(header), v[0]);

    app.tab_rect = None;
    app.table_rect = Some(v[2]);
    app.detail_rect = Some(v[2]);

    let lines = app.diff_page_lines();
    // entries start at line 3 (vs / summary / column header) — keep the
    // selected row in view
    let count = lines.len() as u16;
    let height = v[2].height.saturating_sub(2);
    let sel = app.diff_sel as u16 + 3;
    let mut scroll = app.logs_scroll.min(count.saturating_sub(1));
    if sel < scroll {
        scroll = sel;
    } else if height > 0 && sel >= scroll + height {
        scroll = sel + 1 - height;
    }
    app.logs_scroll = scroll;

    let block = Block::bordered()
        .title(Line::from(styled(
            Style::new().fg(ACCENT).bold(),
            format!("Diff{}", TuiApp::scroll_indicator(app.logs_scroll, count, v[2].height)),
        )))
        .border_style(Style::new().fg(GRAY));
    let area = block.inner(v[2]);
    f.render_widget(block, v[2]);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).scroll((scroll, 0)),
        area,
    );

    let mut footer =
        "j/k: Select | Enter: Inspect | r: Re-diff | Esc/q: Back | c: Copy".to_string();
    if !app.status.is_empty() {
        footer.push_str(&format!("  ·  {}", app.status));
    }
    f.render_widget(
        Paragraph::new(Line::from(styled(Style::new().fg(MID), footer))),
        v[3],
    );
}

fn ui(app: &mut TuiApp, f: &mut Frame<'_>) {
    match app.page {
        Page::Detail => ui_detail_page(app, f),
        Page::PortDetail => ui_port_detail_page(app, f),
        Page::ContainerDetail => ui_container_detail_page(app, f),
        Page::Logs => ui_logs_page(app, f),
        Page::Summary => ui_summary_page(app, f),
        Page::System => ui_system_page(app, f),
        Page::Diff => ui_diff_page(app, f),
        Page::Samples => ui_samples_page(app, f),
        Page::Help => ui_help_page(app, f),
        Page::Browse => {}
    }
    if app.page != Page::Browse {
        return;
    }
    let outer = Block::bordered().border_style(Style::new().fg(GRAY));
    f.render_widget(&outer, f.area());
    let inner = outer.inner(f.area());

    let v = Layout::vertical([
        Constraint::Length(1), // tabs
        Constraint::Length(1),
        Constraint::Length(1), // mode
        Constraint::Length(1),
        Constraint::Length(1), // search
        Constraint::Length(1),
        Constraint::Min(6),    // content
        Constraint::Length(1), // separator
        Constraint::Length(1), // footer
    ])
    .split(inner);

    f.render_widget(Paragraph::new(tab_bar(app)), v[0]);
    f.render_widget(Paragraph::new(mode_line(app)), v[2]);
    f.render_widget(Paragraph::new(search_line(app)), v[4]);

    // mouse mapping: full-width table by default; the Processes tab narrows
    // it and adds the details pane
    app.tab_rect = Some(v[0]);
    app.table_rect = Some(v[6]);
    app.detail_rect = None;

    match app.tab {
        Tab::Processes => {
            // tmux-style zoom (z): the focused pane temporarily takes the row
            let (tw, dw) = if app.browse_zoom {
                if app.focus == Focus::Table { (100, 0) } else { (0, 100) }
            } else {
                (58, 42)
            };
            let cols = Layout::horizontal([
                Constraint::Percentage(tw),
                Constraint::Length(1),
                Constraint::Percentage(dw),
            ])
            .split(v[6]);
            app.table_rect = (tw > 0).then_some(cols[0]);
            app.detail_rect = (dw > 0).then_some(cols[2]);
            if tw > 0 {
                processes_table(app, cols[0], f);
            }
            if dw > 0 {
                let divider = Block::bordered().border_set(border::Set {
                    top_left: "│",
                    top_right: "│",
                    bottom_left: "│",
                    bottom_right: "│",
                    vertical_left: "│",
                    vertical_right: "│",
                    horizontal_top: " ",
                    horizontal_bottom: " ",
                });
                f.render_widget(divider, cols[1]);

                let block = Block::bordered()
                    .title(Line::from(styled(
                        Style::new().fg(MID).bold(),
                        if app.browse_zoom { " Details [zoom] " } else { " Details " },
                    )))
                    .border_style(Style::new().fg(GRAY));
                let inner = block.inner(cols[2]);
                app.detail_height = inner.height;
                f.render_widget(block, cols[2]);
                f.render_widget(
                    Paragraph::new(app.detail_lines.clone())
                        .wrap(Wrap { trim: false })
                        .scroll((app.detail_scroll, 0)),
                    inner,
                );
            }
        }
        // Ports tab: no detail pane — the table gets the full width
        Tab::Ports => ports_table(app, v[6], f),
        Tab::Containers => {
            if app.containers_loading && !app.containers_loaded {
                placeholder(v[6], f, "  loading containers… (querying docker / podman / nerdctl)");
            } else if app.containers.is_empty() {
                placeholder(
                    v[6],
                    f,
                    "  no containers found — needs docker / podman / nerdctl on PATH with a running daemon",
                );
            } else {
                containers_table(app, v[6], f);
            }
        }
        Tab::Locks => {
            if app.locks_supported {
                locks_table(app, v[6], f);
            } else {
                placeholder(v[6], f, "  file locks are not collected on this platform");
            }
        }
        Tab::Events => {
            if app.hist.events.is_empty() {
                placeholder(
                    v[6],
                    f,
                    "  no events yet — appear / exit / restart deltas land here as the TUI samples (every 3s)",
                );
            } else {
                events_table(app, v[6], f);
            }
        }
        Tab::Services => {
            if app.services_loading && app.services.is_empty() {
                placeholder(
                    v[6],
                    f,
                    "  loading services… (systemctl / launchctl / Get-CimInstance can take a second)",
                );
            } else if app.services.is_empty() {
                placeholder(
                    v[6],
                    f,
                    "  no services found — needs systemd (Linux), launchd (macOS) or the SCM (Windows)",
                );
            } else {
                services_table(app, v[6], f);
            }
        }
    }

    let sep = Line::from(styled(
        Style::new().fg(GRAY),
        format!(" {}", "─".repeat(v[8].width.saturating_sub(2) as usize)),
    ));
    f.render_widget(Paragraph::new(sep), v[7]);

    let total = match app.tab {
        Tab::Processes => {
            if app.group_mode != GroupMode::Off {
                format!("{}/{}", app.group_view.len(), app.view.len())
            } else {
                app.view.len().to_string()
            }
        }
        Tab::Ports => {
            if app.ports_overview {
                app.port_overview_view.len().to_string()
            } else if app.port_search.is_empty() {
                app.sockets.len().to_string()
            } else {
                format!("{}/{}", app.socket_view.len(), app.sockets.len())
            }
        }
        Tab::Containers => {
            if app.container_search.is_empty() {
                app.containers.len().to_string()
            } else {
                format!("{}/{}", app.container_view.len(), app.containers.len())
            }
        }
        Tab::Locks => {
            if !app.lock_search.is_empty() {
                format!("{}/{}", app.lock_view.len(), app.locks.len())
            } else if app.locks_total > app.lock_view.len() {
                // OPEN mode display cap is active
                format!("{} of {}", app.lock_view.len(), app.locks_total)
            } else {
                app.locks.len().to_string()
            }
        }
        Tab::Events => {
            if app.event_search.is_empty() {
                app.hist.events.len().to_string()
            } else {
                format!("{}/{}", app.event_view.len(), app.hist.events.len())
            }
        }
        Tab::Services => {
            if app.service_search.is_empty() {
                app.services.len().to_string()
            } else {
                format!("{}/{}", app.service_view.len(), app.services.len())
            }
        }
    };
    let mut footer = match app.tab {
        Tab::Processes => format!(
            "Total: {} | Enter: Detail | w: Watch{} | N: Note | a: Actions (K: tree-kill) | /: Search | z: Zoom | T: Tree{} | B: Group{} | S: Summary | Y: System | !: Notify{} | P: Pause | M: Mute{} | p/n/u/c/m/i/t: Sort | j-k/g-G: Move | h-l: Tab | x: Kill | ?: Help | r: Refresh | q: Quit",
            total,
            if app.watch.is_empty() {
                String::new()
            } else {
                format!(" ({})", app.watch.len())
            },
            if app.tree_mode { " (on)" } else { "" },
            if app.group_mode != GroupMode::Off {
                format!(" ({})", app.group_mode.label())
            } else {
                String::new()
            },
            if app.notify { " (on)" } else { "" },
            if app.muted { " (on)" } else { "" }
        ),
        Tab::Ports => format!(
            "Total: {} | Enter: Detail | o: Overview{} | a: All States | p/t/n/s: Sort | /: Search | h-l: Tab | r: Refresh | q: Quit",
            total,
            if app.ports_overview { " (on)" } else { "" }
        ),
        Tab::Containers => format!(
            "Total: {} | Enter: Detail | i/n/r/g/s/p: Sort | /: Search | h-l: Tab | r: Refresh | q: Quit",
            total
        ),
        Tab::Locks => {
            let mode = if app.locks_show_all { "OPEN" } else { "LOCKED" };
            format!(
                "Total: {} [{}] | a: All Files | p/n/t/m/f: Sort | Enter: Detail | /: Search | j-k/g-G: Move | h-l: Tab | q: Quit",
                total, mode
            )
        }
        Tab::Events => format!(
            "Total: {} | Enter: Open Process | l: Logs | S: Summary | t/e/p/n: Sort | /: Search | j-k/g-G: Move | h-l: Tab | r: Refresh | q: Quit",
            total
        ),
        Tab::Services => format!(
            "Total: {} | Enter: Open Process | n/m/s/p: Sort | /: Search | j-k/g-G: Move | h-l: Tab | r: Refresh | q: Quit",
            total
        ),
    };
    footer = format!("witr-rs v{} · {}", env!("CARGO_PKG_VERSION"), footer);
    if app.paused {
        footer.push_str("  ·  ⏸ paused");
    }
    if !app.status.is_empty() {
        footer.push_str(&format!("  ·  {}", app.status));
    }
    f.render_widget(Paragraph::new(Line::from(styled(Style::new().fg(MID), footer))), v[8]);
}

fn move_selection(app: &mut TuiApp, delta: i32) {
    if app.tab == Tab::Ports {
        // the Ports table's cursor sits over socket_view — or the overview
        // rows when the 'o' aggregate view is active
        let len = if app.ports_overview {
            app.port_overview_view.len()
        } else {
            app.socket_view.len()
        };
        if len == 0 {
            return;
        }
        let len = len as i32;
        let cur = app.table_state.selected().unwrap_or(0) as i32;
        let next = (cur + delta).clamp(0, len - 1);
        if next != cur {
            app.table_state.select(Some(next as usize));
        }
        return;
    }
    if app.tab == Tab::Locks {
        // the Locks table keeps its own cursor over lock_view
        if app.lock_view.is_empty() {
            return;
        }
        let len = app.lock_view.len() as i32;
        let cur = app.lock_state.selected().unwrap_or(0) as i32;
        let next = (cur + delta).clamp(0, len - 1);
        if next != cur {
            app.lock_state.select(Some(next as usize));
        }
        return;
    }
    if app.tab == Tab::Events {
        // same pattern for the Events feed
        if app.event_view.is_empty() {
            return;
        }
        let len = app.event_view.len() as i32;
        let cur = app.event_state.selected().unwrap_or(0) as i32;
        let next = (cur + delta).clamp(0, len - 1);
        if next != cur {
            app.event_state.select(Some(next as usize));
        }
        return;
    }
    if app.tab == Tab::Services {
        // and for the Services table (shared table_state over service_view)
        if app.service_view.is_empty() {
            return;
        }
        let len = app.service_view.len() as i32;
        let cur = app.table_state.selected().unwrap_or(0) as i32;
        let next = (cur + delta).clamp(0, len - 1);
        if next != cur {
            app.table_state.select(Some(next as usize));
        }
        return;
    }
    if app.view.is_empty() {
        return;
    }
    // grouped mode ('B'): the cursor walks the aggregate rows
    let len = if app.tab == Tab::Processes && app.group_mode != GroupMode::Off {
        app.group_view.len()
    } else {
        app.view.len()
    };
    let len = len as i32;
    let cur = app.table_state.selected().unwrap_or(0) as i32;
    let next = (cur + delta).clamp(0, len - 1);
    if next != cur {
        app.table_state.select(Some(next as usize));
        app.detail_pid = None; // force detail refresh (debounced)
        app.detail_scroll = 0;
        app.detail_pending_since = Some(Instant::now());
    }
}

fn select_edge(app: &mut TuiApp, first: bool) {
    if app.tab == Tab::Ports {
        // g/G over the Ports table: bound by the active view's length
        let len = if app.ports_overview {
            app.port_overview_view.len()
        } else {
            app.socket_view.len()
        };
        if len == 0 {
            return;
        }
        let next = if first { 0 } else { len - 1 };
        app.table_state.select(Some(next));
        return;
    }
    if app.tab == Tab::Locks {
        if app.lock_view.is_empty() {
            return;
        }
        let next = if first { 0 } else { app.lock_view.len() - 1 };
        app.lock_state.select(Some(next));
        return;
    }
    if app.tab == Tab::Events {
        if app.event_view.is_empty() {
            return;
        }
        let next = if first { 0 } else { app.event_view.len() - 1 };
        app.event_state.select(Some(next));
        return;
    }
    if app.tab == Tab::Services {
        if app.service_view.is_empty() {
            return;
        }
        let next = if first { 0 } else { app.service_view.len() - 1 };
        app.table_state.select(Some(next));
        return;
    }
    if app.view.is_empty() {
        return;
    }
    let len = if app.tab == Tab::Processes && app.group_mode != GroupMode::Off {
        app.group_view.len()
    } else {
        app.view.len()
    };
    if len == 0 {
        return;
    }
    let next = if first { 0 } else { len - 1 };
    app.table_state.select(Some(next));
    app.detail_pid = None;
    app.detail_scroll = 0;
    app.detail_pending_since = Some(Instant::now());
}

/// Mutably borrow the scroll offset of the pane that has focus on the
/// current full-page view (shared by the keymap and the mouse wheel).
fn focused_scroll_mut(app: &mut TuiApp) -> Option<&mut u16> {
    match (app.page, app.detail_pane, app.port_pane_conn, app.cd_pane_info) {
        (Page::Detail, true, _, _) => Some(&mut app.detail_scroll),
        (Page::Detail, false, _, _) => Some(&mut app.env_scroll),
        (Page::PortDetail, _, true, _) => Some(&mut app.port_scroll),
        (Page::PortDetail, _, false, _) => Some(&mut app.port_owner_scroll),
        (Page::ContainerDetail, _, _, true) => Some(&mut app.cd_scroll),
        (Page::ContainerDetail, _, _, false) => Some(&mut app.cdp_scroll),
        (Page::Logs, _, _, _) => Some(&mut app.logs_scroll),
        (Page::Summary, _, _, _) => Some(&mut app.logs_scroll),
        (Page::System, _, _, _) => Some(&mut app.logs_scroll),
        (Page::Diff, _, _, _) => Some(&mut app.logs_scroll),
        (Page::Samples, _, _, _) => Some(&mut app.logs_scroll),
        (Page::Help, _, _, _) => Some(&mut app.logs_scroll),
        (Page::Browse, _, _, _) => None,
    }
}

/// The '?' overlay: the full keymap, headed by the current tab's own keys.
/// Pure (no app state) so tests can assert on it.
fn help_lines(tab: Tab) -> Vec<Line<'static>> {
    let mut out: Vec<Line<'static>> = Vec::new();
    let mut section = |title: &str, rows: &[(&str, &str)]| {
        out.push(Line::from(Span::styled(
            title.to_string(),
            Style::new().bold(),
        )));
        for (k, v) in rows {
            out.push(Line::from(Span::styled(
                format!("  {k:<22} {v}"),
                Style::new().fg(ACCENT),
            )));
        }
        out.push(Line::from(""));
    };
    section(
        "Global",
        &[
            ("h / l (or ←→)", "switch tab"),
            ("1-9", "jump to tab by number"),
            ("?", "this help"),
            ("q", "quit"),
            ("P", "pause sampling"),
            ("!", "toggle desktop notifications"),
            ("c", "copy the focused pane"),
            ("r", "refresh now"),
        ],
    );
    match tab {
        Tab::Processes => section(
            "Processes",
            &[
                ("j/k, arrows", "move selection"),
                ("g/G", "top / bottom"),
                ("Enter", "full detail page"),
                (
                    "/",
                    "search, or a numeric filter: cpu>50 · mem>500 (MB) · fd>=100 · age>1h · io<10m",
                ),
                ("a", "actions: kill/term/pause/resume/nice"),
                ("K", "kill tree (process + descendants, y confirms)"),
                ("x", "kill selection (y confirms)"),
                ("w", "watchlist: star + pin (survives restarts)"),
                ("N", "annotate: attach a note (survives restarts)"),
                ("B", "group by user/command"),
                ("T", "tree mode"),
                ("z", "zoom the focused pane"),
                ("p/n/u/c/m/i/t", "sort: pid/name/user/cpu/mem/io/time"),
                ("S", "session summary"),
                ("y", "system resources"),
                ("D", "snapshot diff vs the newest auto snapshot"),
            ],
        ),
        Tab::Ports => section(
            "Ports",
            &[
                ("j/k", "move selection"),
                ("Enter", "port detail page"),
                ("o", "overview: one row per (port, owner)"),
                ("a", "show all states (not just LISTEN)"),
                ("p/t/n/s", "sort: port/proto/addr/state"),
                ("/", "search"),
            ],
        ),
        Tab::Containers => section(
            "Containers",
            &[
                ("j/k", "move selection"),
                ("Enter", "container detail + its processes"),
                ("l", "container logs"),
                ("i/n/r/g/s/p", "sort: id/name/runtime/image/status/compose"),
                ("/", "search"),
                ("CPU%/MEM", "live stats sweep, ~10s cadence"),
            ],
        ),
        Tab::Locks => section(
            "Locks",
            &[
                ("j/k", "move selection"),
                ("Enter", "jump to the holding process"),
                ("a", "merge every open file (kind OPEN)"),
                ("p/n/t/m/f", "sort: pid/process/type/mode/path"),
                ("/", "search"),
            ],
        ),
        Tab::Services => section(
            "Services",
            &[
                ("j/k", "move selection"),
                ("Enter", "jump to the unit's main process"),
                ("n/m/s/p", "sort: name/manager/state/pid"),
                ("/", "search"),
            ],
        ),
        Tab::Events => section(
            "Events",
            &[
                ("j/k", "move selection"),
                ("l", "logs (crash forensics first, live fetch second)"),
                ("t/e/p/n", "sort: time/event/pid/process"),
                ("/", "search"),
            ],
        ),
    }
    out.push(Line::from(Span::styled(
        "Esc / q: back to where you were",
        Style::new().fg(MID),
    )));
    out
}

/// The Help overlay: a bordered, scrollable keymap sheet.
fn ui_help_page(app: &mut TuiApp, f: &mut Frame<'_>) {
    let lines = help_lines(app.tab);
    let title = match app.tab {
        Tab::Processes => "Processes",
        Tab::Ports => "Ports",
        Tab::Containers => "Containers",
        Tab::Locks => "Locks",
        Tab::Services => "Services",
        Tab::Events => "Events",
    };
    let block = Block::bordered()
        .title(Span::styled(
            format!(" Keymap — {title} tab "),
            Style::new().bold(),
        ))
        .border_style(Style::new().fg(GRAY));
    let area = block.inner(f.area());
    f.render_widget(block, f.area());
    let count = lines.len() as u16;
    let scroll = app.logs_scroll.min(count.saturating_sub(1));
    let para = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    f.render_widget(para, area);
}

/// Open the detail view for whatever the current tab's cursor is on — the
/// Enter key and a table double-click share this.
fn open_selection(app: &mut TuiApp) {
    match app.tab {
        Tab::Processes => app.open_detail_page(),
        Tab::Ports => {
            // overview rows point at an owning process, not a socket
            if app.ports_overview {
                if let Some(row) = app
                    .table_state
                    .selected()
                    .and_then(|i| app.port_overview_view.get(i))
                {
                    match row.pid {
                        Some(pid) if app.procs.iter().any(|p| p.pid == pid) => {
                            app.open_detail_page_for(pid);
                        }
                        Some(pid) => {
                            app.status = format!("pid {pid} has exited — details unavailable");
                        }
                        None => app.status = "no owning process for this port".into(),
                    }
                }
            } else {
                app.open_port_detail_page();
            }
        }
        Tab::Containers => app.open_container_detail_page(),
        // "from the lock back to the process": jump straight into the
        // holder's detail page
        Tab::Locks => {
            if let Some(pid) = app.selected_lock_pid() {
                app.open_detail_page_for(pid);
            }
        }
        // same idea from the Events feed — but the pid may already be gone;
        // only jump when it's still alive, otherwise say so
        Tab::Events => {
            if let Some(pid) = app.selected_event_pid() {
                if app.procs.iter().any(|p| p.pid == pid) {
                    app.open_detail_page_for(pid);
                } else {
                    app.status = format!("pid {pid} has exited — details unavailable");
                }
            }
        }
        // "from the service back to its process": launchd/SCM list pids
        // inline; systemd resolves MainPID on demand
        Tab::Services => app.open_service_detail(),
    }
}

/// Move the tab's table cursor to an absolute row (used by mouse clicks).
fn select_row(app: &mut TuiApp, row: usize) {
    if app.tab == Tab::Ports {
        // clicks map onto the active Ports view (sockets or overview rows)
        let len = if app.ports_overview {
            app.port_overview_view.len()
        } else {
            app.socket_view.len()
        };
        if row < len {
            app.table_state.select(Some(row));
        }
        return;
    }
    if app.tab == Tab::Locks {
        if row < app.lock_view.len() {
            app.lock_state.select(Some(row));
        }
        return;
    }
    if app.tab == Tab::Events {
        if row < app.event_view.len() {
            app.event_state.select(Some(row));
        }
        return;
    }
    if app.tab == Tab::Services {
        if row < app.service_view.len() {
            app.table_state.select(Some(row));
        }
        return;
    }
    let len = if app.tab == Tab::Processes && app.group_mode != GroupMode::Off {
        app.group_view.len()
    } else {
        app.view.len()
    };
    if row < len {
        app.table_state.select(Some(row));
        app.detail_pid = None;
        app.detail_scroll = 0;
        app.detail_pending_since = Some(Instant::now());
    }
}

/// Scroll offset of whichever table the current tab drives.
fn table_offset(app: &TuiApp) -> usize {
    match app.tab {
        Tab::Locks => app.lock_state.offset(),
        Tab::Events => app.event_state.offset(),
        _ => app.table_state.offset(),
    }
}

/// Position inside a rect (rects have zero-size guard for free: a zero
/// width/height rect contains nothing).
fn in_rect(r: Rect, x: u16, y: u16) -> bool {
    x >= r.x && x < r.x + r.width && y >= r.y && y < r.y + r.height
}

/// Which tab a click in the tab bar lands on — recomputed from the same
/// span widths tab_bar() renders (" witr-rs " + gap, then " title " + gap).
fn tab_at_x(x: u16) -> Option<Tab> {
    let mut cx = 9 + 2; // " witr-rs " + "  "
    for t in [
        Tab::Processes,
        Tab::Ports,
        Tab::Containers,
        Tab::Locks,
        Tab::Events,
        Tab::Services,
    ] {
        let w = t.title().chars().count() as u16 + 2;
        if x >= cx && x < cx + w {
            return Some(t);
        }
        cx += w + 1;
    }
    None
}

/// Mouse handling: wheel scrolls (table cursor / focused detail pane),
/// left click selects tabs, rows and panes; a double-click on a table row
/// opens its detail view.
fn on_mouse(app: &mut TuiApp, m: MouseEvent) {
    match m.kind {
        MouseEventKind::ScrollDown => on_wheel(app, 1, m.column, m.row),
        MouseEventKind::ScrollUp => on_wheel(app, -1, m.column, m.row),
        MouseEventKind::Down(MouseButton::Left) => on_click(app, m.column, m.row),
        _ => {}
    }
}

fn on_wheel(app: &mut TuiApp, delta: i32, x: u16, y: u16) {
    if app.page != Page::Browse {
        if let Some(pane) = focused_scroll_mut(app) {
            if delta > 0 {
                *pane = pane.saturating_add(delta as u16);
            } else {
                *pane = pane.saturating_sub(delta.unsigned_abs() as u16);
            }
        }
        return;
    }
    // over the details panel: scroll its content instead of the table
    if app.tab == Tab::Processes && app.focus == Focus::Details {
        if let Some(r) = app.detail_rect {
            if in_rect(r, x, y) {
                if delta > 0 {
                    app.detail_scroll = app.detail_scroll.saturating_add(delta as u16);
                } else {
                    app.detail_scroll = app.detail_scroll.saturating_sub(delta.unsigned_abs() as u16);
                }
                return;
            }
        }
    }
    move_selection(app, delta);
}

fn on_click(app: &mut TuiApp, x: u16, y: u16) {
    // full-page views: click a pane to focus it
    if app.page != Page::Browse {
        if let Some(r) = app.detail_rect {
            if in_rect(r, x, y) {
                match app.page {
                    Page::Detail => app.detail_pane = false,
                    Page::PortDetail => app.port_pane_conn = false,
                    Page::ContainerDetail => app.cd_pane_info = false,
                    _ => {}
                }
                return;
            }
        }
        if let Some(r) = app.table_rect {
            if in_rect(r, x, y) {
                match app.page {
                    Page::Detail => app.detail_pane = true,
                    Page::PortDetail => app.port_pane_conn = true,
                    Page::ContainerDetail => app.cd_pane_info = true,
                    _ => {}
                }
            }
        }
        return;
    }

    // tab bar
    if let Some(r) = app.tab_rect {
        if in_rect(r, x, y) {
            if let Some(t) = tab_at_x(x) {
                app.switch_tab(t);
            }
            return;
        }
    }
    // details panel (Processes tab): click focuses it
    if let Some(r) = app.detail_rect {
        if in_rect(r, x, y) {
            app.focus = Focus::Details;
            return;
        }
    }
    // table rows: the header row is y == r.y, data starts below it
    let Some(r) = app.table_rect else { return };
    if !in_rect(r, x, y) || y == r.y {
        return;
    }
    let vis = (y - r.y - 1) as usize;
    let abs = table_offset(app) + vis;
    let len = match app.tab {
        Tab::Locks => app.lock_view.len(),
        Tab::Events => app.event_view.len(),
        _ => app.view.len(),
    };
    if abs >= len {
        return;
    }
    select_row(app, abs);
    app.focus = Focus::Table;
    // double-click on the same cell opens the detail view
    let dbl = app
        .last_click
        .take()
        .is_some_and(|(t, lx, ly)| t.elapsed() <= DOUBLE_CLICK && lx == x && ly == y);
    if dbl {
        open_selection(app);
    } else {
        app.last_click = Some((Instant::now(), x, y));
    }
}

/// Every pid in `procs` that descends from `root` via ppid links (BFS, so
/// grandchildren are covered even when the direct parent is reaped mid-walk).
pub(crate) fn descendants_of(root: Pid, procs: &[Process]) -> Vec<Pid> {
    let mut out = Vec::new();
    let mut frontier = vec![root];
    let mut seen: std::collections::HashSet<Pid> = std::collections::HashSet::new();
    seen.insert(root);
    while let Some(pid) = frontier.pop() {
        for p in procs {
            if p.ppid == Some(pid) && seen.insert(p.pid) {
                out.push(p.pid);
                frontier.push(p.pid);
            }
        }
    }
    out.sort_unstable();
    out
}

/// Established-connection count per owning pid — the sample behind
/// `--alert-conn` (sockets without an owner simply don't count). Shared
/// with the headless `--watch` alert loop.
pub fn established_per_pid(sockets: &[Socket]) -> HashMap<Pid, u64> {
    let mut out: HashMap<Pid, u64> = HashMap::new();
    for s in sockets {
        if s.state == "ESTABLISHED" {
            if let Some(pid) = s.pid {
                *out.entry(pid).or_insert(0) += 1;
            }
        }
    }
    out
}

/// Returns false when the app should quit.
fn on_key(app: &mut TuiApp, key: KeyCode) -> bool {
    if app.confirm_kill.is_some() {
        if matches!(key, KeyCode::Char('y') | KeyCode::Char('Y')) {
            app.kill_selected();
        } else {
            app.confirm_kill = None;
        }
        return true;
    }

    // tree-kill confirmation: y fires TERM at the root and every descendant
    // (best-effort — pids may exit on their own between arm and confirm)
    if let Some((root, tree)) = app.confirm_tree_kill.clone() {
        app.confirm_tree_kill = None;
        if matches!(key, KeyCode::Char('y') | KeyCode::Char('Y')) {
            let mut sent = 0usize;
            for pid in std::iter::once(root).chain(tree) {
                if send_signal(pid, "TERM").is_ok() {
                    sent += 1;
                }
            }
            app.status = format!("SIGTERM sent to {sent} process(es) in {root}'s tree");
        } else {
            app.status = "tree kill cancelled".into();
        }
        return true;
    }

    // Note input ('N' on the Processes table): free text; Enter commits,
    // Esc cancels
    if app.note_input.is_some() {
        let mut input = app.note_input.take().unwrap();
        match key {
            KeyCode::Char(c) => {
                if input.chars().count() < 200 {
                    input.push(c);
                }
                app.note_input = Some(input);
            }
            KeyCode::Backspace => {
                input.pop();
                app.note_input = Some(input);
            }
            KeyCode::Enter => app.save_note(&input),
            KeyCode::Esc => app.status = "note discarded".into(),
            _ => app.note_input = Some(input), // arrows etc. keep typing state
        }
        return true;
    }

    // Renice value input ('n' in the actions bar): free-form −20…19
    if app.renice_input.is_some() {        let pid = app.detail_pid.or_else(|| app.selected_pid());
        let mut input = app.renice_input.take().unwrap();
        match key {
            KeyCode::Char(c) if c.is_ascii_digit() || (c == '-' && input.is_empty()) => {
                if input.len() < 4 {
                    input.push(c);
                }
                app.renice_input = Some(input);
            }
            KeyCode::Backspace => {
                input.pop();
                app.renice_input = Some(input);
            }
            KeyCode::Enter => match input.parse::<i32>() {
                Ok(v) if (-20..=19).contains(&v) => {
                    if let Some(pid) = pid {
                        app.status = match renice_pid(pid, v) {
                            Ok(msg) => format!("renice pid {pid}: {msg}"),
                            Err(e) => e.to_string(),
                        };
                    }
                }
                _ => app.status = "nice value must be between -20 and 19".into(),
            },
            _ => {} // any other key cancels
        }
        return true;
    }

    // Actions bar: one-key signals on the selected process (Go witr parity)
    // — openable from the detail page ('a') and straight from the browse
    // table ('a' on Processes).
    if app.actions_open {
        let Some(pid) = app.detail_pid.or_else(|| app.selected_pid()) else {
            app.actions_open = false;
            return true;
        };
        app.actions_open = false;
        match key {
            KeyCode::Char('k') => app.status = match send_signal(pid, "KILL") {
                Ok(()) => format!("SIGKILL sent to pid {pid}"),
                Err(e) => e.to_string(),
            },
            KeyCode::Char('K') => {
                let tree = descendants_of(pid, &app.procs);
                if tree.is_empty() {
                    app.status = format!("pid {pid} has no descendants — use k to kill it alone");
                } else {
                    app.status = format!(
                        "kill pid {pid} + {} descendant(s)? y to confirm, any other key cancels",
                        tree.len()
                    );
                    app.confirm_tree_kill = Some((pid, tree));
                    // the bar stays conceptually closed either way; the
                    // confirmation prompt takes over
                }
            }
            KeyCode::Char('t') => app.status = match send_signal(pid, "TERM") {
                Ok(()) => format!("SIGTERM sent to pid {pid}"),
                Err(e) => e.to_string(),
            },
            KeyCode::Char('p') => app.status = match send_signal(pid, "STOP") {
                Ok(()) => format!("SIGSTOP sent to pid {pid} (paused)"),
                Err(e) => e.to_string(),
            },
            KeyCode::Char('r') => app.status = match send_signal(pid, "CONT") {
                Ok(()) => format!("SIGCONT sent to pid {pid} (resumed)"),
                Err(e) => e.to_string(),
            },
            KeyCode::Char('n') => app.renice_input = Some(String::new()),
            _ => return true, // any other key just closes the bar
        }
        return true;
    }

    // '?' toggles the keymap overlay from anywhere outside an input mode
    // (search typing stays search — it handles its own chars below)
    if key == KeyCode::Char('?') && !app.search_mode {
        if app.page == Page::Help {
            app.page = app.help_prev;
        } else {
            app.help_prev = app.page;
            app.page = Page::Help;
            app.logs_scroll = 0;
        }
        return true;
    }
    // on the overlay itself, close keys restore where '?' was pressed
    // (the generic full-page Esc below would always land on Browse)
    if app.page == Page::Help
        && matches!(key, KeyCode::Esc | KeyCode::Char('q') | KeyCode::Backspace)
    {
        app.page = app.help_prev;
        return true;
    }

    // Full-page views (process detail / port detail) share a keymap that
    // mirrors handleDetailKey in the Go witr: Esc/q/Backspace back, Tab
    // focus, vim scroll on the focused pane, c copy.
    if app.page != Page::Browse {
        // Environment-pane search on the process detail page (/ to enter)
        if app.env_search_mode {
            match key {
                KeyCode::Char(c) => {
                    app.env_search.push(c);
                    app.env_scroll = 0;
                }
                KeyCode::Backspace => {
                    app.env_search.pop();
                    app.env_scroll = 0;
                }
                KeyCode::Enter | KeyCode::Esc => app.env_search_mode = false,
                _ => {}
            }
            return true;
        }
        if matches!(key, KeyCode::Esc | KeyCode::Char('q') | KeyCode::Backspace) {
            // first Esc clears the env filter, only then does it leave the page
            if !app.env_search.is_empty() {
                app.env_search.clear();
                app.env_scroll = 0;
                return true;
            }
            // leaving the Logs page stops a live `logs -f` stream
            if app.page == Page::Logs {
                app.stop_logs_follow();
            }
            app.page = Page::Browse;
            app.actions_open = false;
            return true;
        }
        // 'F' on the Logs page: toggle the live container-log stream
        // (uppercase — lowercase f scrolls down)
        if key == KeyCode::Char('F') && app.page == Page::Logs {
            app.toggle_logs_follow();
            return true;
        }
        // 'r' on the summary page: recompute from the live history
        if key == KeyCode::Char('r') && app.page == Page::Summary {
            app.open_summary();
            return true;
        }
        // 'r' on the system page: sample now instead of waiting for the tick
        if key == KeyCode::Char('r') && app.page == Page::System {
            app.refresh();
            return true;
        }
        // 'r' on the diff page: re-diff against the newest auto snapshot
        if key == KeyCode::Char('r') && app.page == Page::Diff {
            app.open_diff_page();
            return true;
        }
        // D page: j/k/g/G move the selection, Enter inspects the entry's
        // process (d/u/f/b keep their generic scroll meaning below)
        if app.page == Page::Diff {
            let count = app.diff_entries.len();
            match key {
                KeyCode::Char('j') | KeyCode::Down => {
                    app.diff_sel = (app.diff_sel + 1).min(count.saturating_sub(1));
                    return true;
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    app.diff_sel = app.diff_sel.saturating_sub(1);
                    return true;
                }
                KeyCode::Char('g') => {
                    app.diff_sel = 0;
                    return true;
                }
                KeyCode::Char('G') => {
                    app.diff_sel = count.saturating_sub(1);
                    return true;
                }
                KeyCode::Enter => {
                    if let Some(e) = app.diff_entries.get(app.diff_sel).map(|e| e.pid) {
                        if app.procs.iter().any(|p| p.pid == e) {
                            app.open_detail_page_for(e);
                        } else {
                            app.status =
                                format!("pid {e} is gone — it only exists in the snapshot");
                        }
                    }
                    return true;
                }
                _ => {}
            }
        }
        // samples page: ←/→ (h/l) walk the cursor, ↑/↓ (j/k) switch the
        // charted series, g/G jump to the ends
        if app.page == Page::Samples && !app.samples.is_empty() {
            let last = app.samples.len() - 1;
            let move_cursor = |app: &mut TuiApp, d: isize| {
                app.samples_cursor = (app.samples_cursor as isize + d).clamp(0, last as isize)
                    as usize;
            };
            match key {
                KeyCode::Left | KeyCode::Char('h') => {
                    move_cursor(app, -1);
                    return true;
                }
                KeyCode::Right | KeyCode::Char('l') => {
                    move_cursor(app, 1);
                    return true;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    app.samples_series =
                        (app.samples_series + SAMPLE_SERIES - 1) % SAMPLE_SERIES;
                    return true;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    app.samples_series = (app.samples_series + 1) % SAMPLE_SERIES;
                    return true;
                }
                KeyCode::Char('g') => {
                    app.samples_cursor = 0;
                    return true;
                }
                KeyCode::Char('G') => {
                    app.samples_cursor = last;
                    return true;
                }
                _ => {}
            }
        }
        if key == KeyCode::Char('c') {
            let text = app.focused_pane_text();
            app.status = match crate::util::clipboard_copy(&text) {
                Ok(n) => format!("copied {n} chars to clipboard"),
                Err(e) => format!("clipboard: {e}"),
            };
            return true;
        }
        if key == KeyCode::Tab {
            match app.page {
                Page::Detail => app.detail_pane = !app.detail_pane,
                Page::PortDetail => app.port_pane_conn = !app.port_pane_conn,
                Page::ContainerDetail => app.cd_pane_info = !app.cd_pane_info,
                _ => {}
            }
            return true;
        }
        // 'l': recent logs of the traced process (detail page / port owner)
        if key == KeyCode::Char('l') && app.page == Page::Detail {
            app.open_logs_for_detail();
            return true;
        }
        if key == KeyCode::Char('l') && app.page == Page::ContainerDetail {
            if let Some(c) = &app.container_detail {
                let src = crate::logs::LogSource::Container {
                    runtime: c.runtime.clone(),
                    ref_: c.id.clone(),
                };
                app.open_logs(src);
            }
            return true;
        }
        if key == KeyCode::Char('/') && app.page == Page::Detail {
            app.env_search_mode = true;
            return true;
        }
        if key == KeyCode::Char('a') && app.page == Page::Detail {
            app.actions_open = true;
            return true;
        }
        // tmux-style zoom: the focused pane takes the whole row until z again
        if key == KeyCode::Char('z') && app.page == Page::Detail {
            app.detail_zoom = !app.detail_zoom;
            return true;
        }
        let h = app.detail_height.max(app.port_pane_height);
        let half = (h / 2).max(1);
        let delta: i32 = match key {
            KeyCode::Char('j') | KeyCode::Down => 1,
            KeyCode::Char('k') | KeyCode::Up => -1,
            KeyCode::Char('d') => half as i32,
            KeyCode::Char('u') => -(half as i32),
            KeyCode::Char('g') => -(u16::MAX as i32),
            KeyCode::Char('G') => u16::MAX as i32,
            KeyCode::Char('f') | KeyCode::Char(' ') | KeyCode::PageDown => h as i32,
            KeyCode::Char('b') | KeyCode::PageUp => -(h as i32),
            _ => 0,
        };
        if delta != 0 {
            if let Some(pane) = focused_scroll_mut(app) {
                if delta > 0 {
                    *pane = pane.saturating_add(delta as u16);
                } else {
                    *pane = pane.saturating_sub(delta.unsigned_abs() as u16);
                }
            }
        }
        return true;
    }

    if app.search_mode {
        match key {
            KeyCode::Char(c) => {
                match app.tab {
                    Tab::Ports => {
                        app.port_search.push(c);
                        app.rebuild_socket_view();
                    }
                    Tab::Containers => {
                        app.container_search.push(c);
                        app.rebuild_container_view();
                    }
                    Tab::Locks => {
                        app.lock_search.push(c);
                        app.rebuild_lock_view();
                    }
                    Tab::Events => {
                        app.event_search.push(c);
                        app.rebuild_event_view();
                    }
                    Tab::Services => {
                        app.service_search.push(c);
                        app.rebuild_service_view();
                    }
                    _ => {
                        app.search.push(c);
                        app.rebuild_view();
                    }
                }
            }
            KeyCode::Backspace => {
                match app.tab {
                    Tab::Ports => {
                        app.port_search.pop();
                        app.rebuild_socket_view();
                    }
                    Tab::Containers => {
                        app.container_search.pop();
                        app.rebuild_container_view();
                    }
                    Tab::Locks => {
                        app.lock_search.pop();
                        app.rebuild_lock_view();
                    }
                    Tab::Events => {
                        app.event_search.pop();
                        app.rebuild_event_view();
                    }
                    Tab::Services => {
                        app.service_search.pop();
                        app.rebuild_service_view();
                    }
                    _ => {
                        app.search.pop();
                        app.rebuild_view();
                    }
                }
            }
            KeyCode::Enter | KeyCode::Esc => {
                app.search_mode = false;
                app.focus = Focus::Table;
            }
            // keep the list navigable while the search box has focus
            KeyCode::Up => move_selection(app, -1),
            KeyCode::Down => move_selection(app, 1),
            _ => {}
        }
        return true;
    }

    // Vim-style, mirroring the Go witr (bubbles table keymap): j/k move,
    // g/G first/last row, b/f (space) page, h/l switch tabs, d/u half-page
    // in the details pane. 'u'/'t' etc. stay sort keys in table focus.
    match key {
        KeyCode::Char('q') => return false,
        KeyCode::Esc => {
            if app.focus == Focus::Details {
                app.focus = Focus::Table;
            } else if app.browse_zoom {
                app.browse_zoom = false;
            } else if app.tab == Tab::Ports && !app.port_search.is_empty() {
                app.port_search.clear();
                app.rebuild_socket_view();
            } else if app.tab == Tab::Containers && !app.container_search.is_empty() {
                app.container_search.clear();
                app.rebuild_container_view();
            } else if app.tab == Tab::Locks && !app.lock_search.is_empty() {
                app.lock_search.clear();
                app.rebuild_lock_view();
            } else if app.tab == Tab::Events && !app.event_search.is_empty() {
                app.event_search.clear();
                app.rebuild_event_view();
            } else if app.tab == Tab::Services && !app.service_search.is_empty() {
                app.service_search.clear();
                app.rebuild_service_view();
            } else if !app.search.is_empty() {
                app.search.clear();
                app.rebuild_view();
            } else {
                return false;
            }
        }
        KeyCode::Tab => {
            app.focus = match app.focus {
                Focus::Table => Focus::Details,
                Focus::Details => Focus::Table,
            };
        }
        KeyCode::Char('/') => {
            app.search_mode = true;
        }
        // tmux-style zoom on the Processes tab: focused pane takes the row
        KeyCode::Char('z') if app.tab == Tab::Processes => {
            app.browse_zoom = !app.browse_zoom;
        }
        // Processes tab 'B': cycle grouping off → name → user → container
        // (mutually exclusive with the tree view)
        KeyCode::Char('B') if app.tab == Tab::Processes && app.focus == Focus::Table => {
            app.tree_mode = false;
            app.group_mode = app.group_mode.next();
            app.rebuild_view();
            app.status = match app.group_mode {
                GroupMode::Off => "grouping off".into(),
                m => format!("grouped by {} — Enter opens the busiest member", m.label()),
            };
        }
        // desktop notifications on/off (--notify seeds it)
        KeyCode::Char('!') => {
            app.notify = !app.notify;
            app.status = if app.notify {
                "desktop notifications on".into()
            } else {
                "desktop notifications off".into()
            };
        }
        // freeze/unfreeze sampling ('P'; Events' pid-sort-desc is still
        // reachable as p-p there)
        KeyCode::Char('P') => {
            app.paused = !app.paused;
            app.status = if app.paused {
                "sampling paused — data frozen".into()
            } else {
                "sampling resumed".into()
            };
        }
        // 'M': mute/unmute every alert firing for this session — firings
        // still land in the Events ring as "silenced", side-effect free
        KeyCode::Char('M') => {
            app.muted = !app.muted;
            app.status = if app.muted {
                "alerts muted — 'M' unmutes".into()
            } else {
                "alerts unmuted".into()
            };
        }
        // '<' / '>': scrub the time-replay ring on the Processes tab —
        // '<' steps one sampled frame into the past, '>' forward; the
        // newest frame's '>' returns to live
        KeyCode::Char('<') if app.tab == Tab::Processes && app.focus == Focus::Table => {
            if app.replay_ring.is_empty() {
                app.status = "no replay history yet — give it a few samples".into();
            } else {
                let pos = match app.replay_pos {
                    None => app.replay_ring.len() - 1,
                    Some(i) => i.saturating_sub(1),
                };
                if Some(pos) != app.replay_pos {
                    let (at, frame) = {
                        let (at, frame) = &app.replay_ring[pos];
                        (at.to_string(), frame.clone())
                    };
                    app.replay_pos = Some(pos);
                    app.procs = frame;
                    app.rebuild_view();
                    app.status = format!(
                        "replay {} ({}/{}) — '>' forward, newest '>' returns to live",
                        at,
                        pos + 1,
                        app.replay_ring.len()
                    );
                }
            }
        }
        KeyCode::Char('>') if app.tab == Tab::Processes && app.focus == Focus::Table => {
            match app.replay_pos {
                None => app.status = "already live — '<' steps into the past".into(),
                Some(i) => {
                    if i + 1 >= app.replay_ring.len() {
                        app.replay_pos = None;
                        app.status = "back to live".into();
                    } else {
                        let (at, frame) = {
                            let (at, frame) = &app.replay_ring[i + 1];
                            (at.to_string(), frame.clone())
                        };
                        app.replay_pos = Some(i + 1);
                        app.procs = frame;
                        app.rebuild_view();
                        app.status = format!(
                            "replay {} ({}/{}) — '>' forward, newest '>' returns to live",
                            at,
                            i + 2,
                            app.replay_ring.len()
                        );
                    }
                }
            }
        }
        // 'S': session summary — what happened in the watched window
        KeyCode::Char('S') => {
            app.open_summary();
        }
        // 'y': system resources — machine-wide cpu/memory/load meters
        KeyCode::Char('y') => {
            app.open_system();
        }
        // 'D': snapshot diff — newest auto snapshot vs the live table
        KeyCode::Char('D') => {
            app.open_diff_page();
        }

        // ---- cursor movement ----
        KeyCode::Down if app.focus == Focus::Table => move_selection(app, 1),
        KeyCode::Up if app.focus == Focus::Table => move_selection(app, -1),
        KeyCode::Char('j') if app.focus == Focus::Table => move_selection(app, 1),
        KeyCode::Char('k') if app.focus == Focus::Table => move_selection(app, -1),
        KeyCode::Char('g') if app.focus == Focus::Table => select_edge(app, true),
        KeyCode::Char('G') if app.focus == Focus::Table => select_edge(app, false),
        // ---- Ports tab: 'a' widens to every socket state, 'o' flips to
        // the per-port overview, p/t/n/s sort (Go witr parity) ----
        KeyCode::Char('a') if app.tab == Tab::Ports && app.focus == Focus::Table => {
            app.ports_show_all = !app.ports_show_all;
            app.rebuild_socket_view();
        }
        KeyCode::Char('o') if app.tab == Tab::Ports && app.focus == Focus::Table => {
            app.ports_overview = !app.ports_overview;
            app.rebuild_socket_view();
        }
        KeyCode::Char(c)
            if app.tab == Tab::Ports
                && app.focus == Focus::Table
                && matches!(c.to_ascii_lowercase(), 'p' | 't' | 'n' | 's') =>
        {
            let col = match c.to_ascii_lowercase() {
                'p' => PortSort::Port,
                't' => PortSort::Proto,
                'n' => PortSort::Addr,
                _ => PortSort::State,
            };
            if app.port_sort == col {
                app.port_sort_desc = !app.port_sort_desc;
            } else {
                app.port_sort = col;
                app.port_sort_desc = false;
            }
            app.rebuild_socket_view();
        }
        // ---- Containers tab: i/n/r/g/s sort (Go witr parity) ----
        KeyCode::Char(c)
            if app.tab == Tab::Containers
                && app.focus == Focus::Table
                && matches!(c.to_ascii_lowercase(), 'i' | 'n' | 'r' | 'g' | 's' | 'p') =>
        {
            let col = match c.to_ascii_lowercase() {
                'i' => ContainerSort::Id,
                'n' => ContainerSort::Name,
                'r' => ContainerSort::Runtime,
                'g' => ContainerSort::Image,
                'p' => ContainerSort::Project,
                _ => ContainerSort::Status,
            };
            if app.container_sort == Some(col) {
                app.container_sort_desc = !app.container_sort_desc;
            } else {
                app.container_sort = Some(col);
                app.container_sort_desc = false;
            }
            app.rebuild_container_view();
        }
        // ---- Services tab: n/m/s/p sort ----
        KeyCode::Char(c)
            if app.tab == Tab::Services
                && app.focus == Focus::Table
                && matches!(c.to_ascii_lowercase(), 'n' | 'm' | 's' | 'p') =>
        {
            let col = match c.to_ascii_lowercase() {
                'n' => ServiceSort::Name,
                'm' => ServiceSort::Manager,
                's' => ServiceSort::State,
                _ => ServiceSort::Pid,
            };
            if app.service_sort == Some(col) {
                app.service_sort_desc = !app.service_sort_desc;
            } else {
                app.service_sort = Some(col);
                app.service_sort_desc = false;
            }
            app.rebuild_service_view();
        }
        // ---- Processes tab: 'a' opens the actions bar on the selection ----
        KeyCode::Char('a') if app.tab == Tab::Processes && app.focus == Focus::Table => {
            if app.selected_pid().is_some() {
                app.actions_open = true;
            }
        }
        // ---- Processes tab: 'w' toggles the watchlist entry (pinned + ★,
        // identity-matched so it survives restarts); persisted to the config ----
        KeyCode::Char('w') if app.tab == Tab::Processes && app.focus == Focus::Table => {
            app.toggle_watch();
        }
        // ---- Processes tab: 'N' annotates the selection (identity-keyed,
        // persisted to the config; Enter commits, any other input key types) ----
        KeyCode::Char('N') if app.tab == Tab::Processes && app.focus == Focus::Table => {
            if app.selected_pid().is_some() {
                app.note_input = Some(String::new());
            }
        }
        // ---- Locks tab: 'a' toggles the all-open-files view, p/n/t/m/f
        // sort (Go witr parity; there 'f' shadows page-down — use Space) ----
        KeyCode::Char(c)
            if app.tab == Tab::Locks
                && app.focus == Focus::Table
                && matches!(c.to_ascii_lowercase(), 'a' | 'p' | 'n' | 't' | 'm' | 'f') =>
        {
            match c.to_ascii_lowercase() {
                'a' => {
                    app.locks_show_all = !app.locks_show_all;
                    app.lock_state.select(Some(0));
                    app.load_locks();
                }
                col => {
                    let col = match col {
                        'p' => LockSort::Pid,
                        'n' => LockSort::Process,
                        't' => LockSort::Type,
                        'm' => LockSort::Mode,
                        _ => LockSort::Path,
                    };
                    if app.lock_sort == col {
                        app.lock_sort_desc = !app.lock_sort_desc;
                    } else {
                        app.lock_sort = col;
                        app.lock_sort_desc = false;
                    }
                    app.rebuild_lock_view();
                }
            }
        }
        // ---- Events tab: t/e/p/n sort columns ----
        KeyCode::Char(c)
            if app.tab == Tab::Events
                && app.focus == Focus::Table
                && matches!(c.to_ascii_lowercase(), 't' | 'e' | 'p' | 'n') =>
        {
            let col = match c.to_ascii_lowercase() {
                'e' => EventSort::Kind,
                'p' => EventSort::Pid,
                'n' => EventSort::Process,
                _ => EventSort::Time,
            };
            if app.event_sort == col {
                app.event_sort_desc = !app.event_sort_desc;
            } else {
                app.event_sort = col;
                // Time reads best newest-first; the rest ascending.
                app.event_sort_desc = col == EventSort::Time;
            }
            app.rebuild_event_view();
        }
        KeyCode::PageDown if app.focus == Focus::Table => move_selection(app, 20),
        KeyCode::PageUp if app.focus == Focus::Table => move_selection(app, -20),
        KeyCode::Char('f') if app.focus == Focus::Table => move_selection(app, 20),
        KeyCode::Char(' ') if app.focus == Focus::Table => move_selection(app, 20),
        KeyCode::Char('b') if app.focus == Focus::Table => move_selection(app, -20),

        // Events rows: 'l' pulls recent logs for the event's process — the
        // natural follow-up when the row says "restarted". Must precede the
        // generic 'l' tab-switch below. Exited/restarted rows hit the crash
        // forensics cache first ("last words" captured at exit time).
        KeyCode::Char('l') if app.tab == Tab::Events && app.focus == Focus::Table => {
            let ev = app
                .event_state
                .selected()
                .and_then(|i| app.event_view.get(i))
                .and_then(|&ei| app.hist.events.get(ei))
                .cloned();
            if let Some(ev) = ev {
                if ev.kind == "exited" || ev.kind == "restarted" {
                    app.open_death_logs(&ev);
                } else if let Some(p) = app.procs.iter().find(|p| p.pid == ev.pid) {
                    app.open_logs(crate::logs::LogSource::for_process(p));
                }
            }
        }

        // ---- tabs: h/l (and left/right) ----
        KeyCode::Char('h') if app.focus == Focus::Table => {
            let t = app.tab.prev();
            app.switch_tab(t);
        }
        KeyCode::Char('l') if app.focus == Focus::Table => {
            let t = app.tab.next();
            app.switch_tab(t);
        }
        KeyCode::Left if app.focus == Focus::Table => {
            let t = app.tab.prev();
            app.switch_tab(t);
        }
        KeyCode::Right if app.focus == Focus::Table => {
            let t = app.tab.next();
            app.switch_tab(t);
        }

        // ---- details pane scrolling ----
        KeyCode::Up if app.focus == Focus::Details => {
            app.detail_scroll = app.detail_scroll.saturating_sub(1)
        }
        KeyCode::Down if app.focus == Focus::Details => app.detail_scroll += 1,
        KeyCode::Char('j') if app.focus == Focus::Details => app.detail_scroll += 1,
        KeyCode::Char('k') if app.focus == Focus::Details => {
            app.detail_scroll = app.detail_scroll.saturating_sub(1)
        }
        KeyCode::Char('d') if app.focus == Focus::Details => {
            app.detail_scroll = app.detail_scroll.saturating_add(app.detail_height / 2)
        }
        KeyCode::Char('u') if app.focus == Focus::Details => {
            app.detail_scroll = app.detail_scroll.saturating_sub(app.detail_height / 2)
        }
        KeyCode::Char('g') if app.focus == Focus::Details => app.detail_scroll = 0,
        KeyCode::Char('G') if app.focus == Focus::Details => app.detail_scroll = u16::MAX / 2,
        KeyCode::PageDown if app.focus == Focus::Details => {
            app.detail_scroll = app.detail_scroll.saturating_add(app.detail_height)
        }
        KeyCode::PageUp if app.focus == Focus::Details => {
            app.detail_scroll = app.detail_scroll.saturating_sub(app.detail_height)
        }
        KeyCode::Char('f') if app.focus == Focus::Details => {
            app.detail_scroll = app.detail_scroll.saturating_add(app.detail_height)
        }
        KeyCode::Char('b') if app.focus == Focus::Details => {
            app.detail_scroll = app.detail_scroll.saturating_sub(app.detail_height)
        }

        KeyCode::Enter => open_selection(app),
        KeyCode::Char('r') => app.refresh(),
        KeyCode::Char('x') => {
            if let Some(pid) = app.selected_pid() {
                app.confirm_kill = Some(pid);
            }
        }
        KeyCode::Char(c) => {
            if let Some(t) = Tab::from_digit(c) {
                let tab = t;
                app.switch_tab(tab);
            } else if app.tab == Tab::Processes {
                // uppercase 'T' (lowercase 't' sorts by start time) flips
                // the Processes tab between the flat table and the
                // parent→child tree; a live search falls back to flat
                if c == 'T' {
                    app.tree_mode = !app.tree_mode;
                    if app.tree_mode {
                        app.group_mode = GroupMode::Off;
                    }
                    app.status = if app.tree_mode {
                        "tree view on (children nest under their parent; a search shows flat)".into()
                    } else {
                        "tree view off".into()
                    };
                    app.rebuild_view();
                    return true;
                }
                let k = match c {
                    'p' => Some(SortKey::Pid),
                    'n' => Some(SortKey::Name),
                    'u' => Some(SortKey::User),
                    'c' => Some(SortKey::Cpu),
                    'm' => Some(SortKey::Mem),
                    'i' => Some(SortKey::Io),
                    't' => Some(SortKey::Started),
                    _ => None,
                };
                if let Some(k) = k {
                    if app.sort_key == k {
                        app.sort_desc = !app.sort_desc;
                    } else {
                        app.sort_key = k;
                        app.sort_desc = true;
                    }
                    app.rebuild_view();
                }
            }
        }
        _ => {}
    }
    true
}

/// One sampling tick when due — a no-op while paused ('P'): no refresh,
/// no new events, no notifications.
fn tick_refresh(app: &mut TuiApp) {
    if !app.paused && app.last_refresh.elapsed() >= app.refresh {
        app.refresh();
    }
}

/// Config `sort = "..."` → a sort column; unknown names are ignored.
fn sort_key_from_str(s: &str) -> Option<SortKey> {
    match s.to_ascii_lowercase().as_str() {
        "pid" => Some(SortKey::Pid),
        "name" => Some(SortKey::Name),
        "user" => Some(SortKey::User),
        "cpu" => Some(SortKey::Cpu),
        "mem" => Some(SortKey::Mem),
        "io" => Some(SortKey::Io),
        "started" | "age" | "time" => Some(SortKey::Started),
        _ => None,
    }
}

/// One numeric `/` filter on the Processes tab (`cpu>50`, `mem<=2g`,
/// `fd>=100`, `age>1h`, `io<10m`).
#[derive(Debug, Clone, Copy, PartialEq)]
struct MetricFilter {
    metric: FilterMetric,
    /// true = `>`, false = `<`; the parser normalizes >=/> and <=/< onto
    /// the same comparison (equal values are edge noise, not a mode)
    gt: bool,
    /// comparison value in the metric's unit: cpu percent, mem KiB,
    /// fd count, age seconds, io bytes/s
    value: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum FilterMetric {
    Cpu,
    Mem,
    Fd,
    Age,
    Io,
    Threads,
}

/// `1.5g` → 1.5 × 10⁹ (k/m/g suffixes, case-insensitive; bare = plain).
fn parse_scaled(s: &str) -> Option<f64> {
    let s = s.trim();
    let (num, mult) = if let Some(v) = s.strip_suffix(['k', 'K']) {
        (v, 1e3)
    } else if let Some(v) = s.strip_suffix(['m', 'M']) {
        (v, 1e6)
    } else if let Some(v) = s.strip_suffix(['g', 'G']) {
        (v, 1e9)
    } else {
        (s, 1.0)
    };
    num.trim().parse::<f64>().ok().map(|n| n * mult)
}

/// Age suffixes: `30` seconds, `10m`, `2h`, `1d`.
fn parse_age_secs(s: &str) -> Option<f64> {
    let s = s.trim();
    let (num, mult) = if let Some(v) = s.strip_suffix(['s', 'S']) {
        (v, 1.0)
    } else if let Some(v) = s.strip_suffix(['m', 'M']) {
        (v, 60.0)
    } else if let Some(v) = s.strip_suffix(['h', 'H']) {
        (v, 3600.0)
    } else if let Some(v) = s.strip_suffix(['d', 'D']) {
        (v, 86400.0)
    } else {
        (s, 1.0)
    };
    num.trim().parse::<f64>().ok().map(|n| n * mult)
}

/// `cpu>50` / `mem<=2g` / `fd>=100` / `age>1h` / `io<10m` → a numeric
/// filter; `None` means "not an expression" and the search falls back to
/// substring. Bare `mem` is MB, bare `age` seconds, bare `io` bytes/s.
fn parse_metric_filter(s: &str) -> Option<MetricFilter> {
    let s = s.trim();
    // longest operator first so >= wins over >
    let (op_len, gt) = if s.contains(">=") {
        (2, true)
    } else if s.contains("<=") {
        (2, false)
    } else if s.contains('>') {
        (1, true)
    } else if s.contains('<') {
        (1, false)
    } else if s.contains('=') {
        // `=` alone compares as ≥ (a name filter's job is substring)
        (1, true)
    } else {
        return None;
    };
    let pos = s.find(['>', '<', '='])?;
    let metric = s[..pos].trim().to_ascii_lowercase();
    let raw = s[pos + op_len..].trim();
    let fm = match metric.as_str() {
        "cpu" => FilterMetric::Cpu,
        "mem" => FilterMetric::Mem,
        "fd" => FilterMetric::Fd,
        "age" => FilterMetric::Age,
        "io" => FilterMetric::Io,
        "threads" | "thr" => FilterMetric::Threads,
        _ => return None,
    };
    let value = match fm {
        FilterMetric::Cpu | FilterMetric::Fd | FilterMetric::Threads => raw.parse::<f64>().ok()?,
        FilterMetric::Age => parse_age_secs(raw)?,
        // bare mem is MB (stored as KiB), bare io is bytes/s
        FilterMetric::Mem => parse_scaled(raw)? * 1024.0,
        FilterMetric::Io => parse_scaled(raw)?,
    };
    (!raw.is_empty()).then_some(MetricFilter { metric: fm, gt, value })
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, seed: Seed) -> Result<()> {
    let mut app = TuiApp::new(crate::platform::get(), seed);
    // brief-process poller: spawns and dies between the regular ticks
    // would be invisible otherwise (not on Windows — no cheap pid sweep)
    if crate::platform::quick_pids().is_some() {
        let (rx, stop) = crate::history::spawn_brief_poller(250);
        app.brief_rx = Some(rx);
        app.brief_stop = Some(stop);
    }
    loop {
        terminal.draw(|f| ui(&mut app, f))?;
        if event::poll(Duration::from_millis(200))? {
            match event::read()? {
                CEvent::Key(key) => {
                    if key.kind == KeyEventKind::Press && !on_key(&mut app, key.code) {
                        return Ok(());
                    }
                }
                CEvent::Mouse(m) => on_mouse(&mut app, m),
                _ => {}
            }
        }
        tick_refresh(&mut app);
        app.poll_containers();
        app.poll_container_events();
        app.poll_container_stats();
        app.poll_services();
        app.poll_logs();
        app.poll_death_logs();
        app.poll_follow_logs();
        // selection debounce: recompute details 500ms after the cursor
        // stopped moving (mirrors selectionDebounce in the Go witr)
        if let Some(since) = app.detail_pending_since {
            if since.elapsed() >= DEBOUNCE {
                app.detail_pending_since = None;
                app.update_details();
            }
        }
    }
}

/// Entry point: alternate screen + raw mode + mouse capture, restored on
/// every exit path. `seed` pre-selects the CLI target (Go witr parity).
pub fn run(seed: Seed) -> Result<()> {
    let mut terminal = ratatui::init();
    let _ = execute!(std::io::stdout(), event::EnableMouseCapture);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        event_loop(&mut terminal, seed)
    }));
    let out = match res {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::other("tui panicked")),
    };
    let _ = execute!(std::io::stdout(), event::DisableMouseCapture);
    ratatui::restore();
    out
}

/// Reproduce the event-loop's debounced detail refresh (test helper).
#[cfg_attr(not(test), allow(dead_code))]
fn settle_details(app: &mut TuiApp) {
    if let Some(since) = app.detail_pending_since {
        if since.elapsed() >= DEBOUNCE {
            app.detail_pending_since = None;
            app.update_details();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::TargetReport;

    #[test]
    fn refresh_produces_alert_events_when_seeded() {
        // live-platform loop: with a 0 MB floor every process is over, so
        // five refreshes must land alert events in the ring
        let mut app = TuiApp::new(
            crate::platform::get(),
            Seed {
                alert_mem: Some(0),
                ..Seed::default()
            },
        );
        assert_eq!(app.alert_mem, Some(0), "seed propagates");
        // a listing pass that transiently misses a pid resets its streak
        // (alert_state prunes to the seen set), so keep cycling until an
        // alert lands instead of betting on an exact refresh count
        let mut alerts: Vec<&crate::history::TuiEvent> = Vec::new();
        for _ in 0..30 {
            app.refresh();
            alerts = app
                .hist
                .events
                .iter()
                .filter(|e| e.kind == "alert")
                .collect();
            if !alerts.is_empty() {
                break;
            }
        }
        assert!(!alerts.is_empty(), "expected alerts within 30 refreshes");
    }

    #[test]
    fn wrapped_count_ceil() {
        let mk = |s: &str| Line::from(s.to_string());
        let lines = vec![mk("short"), mk(""), mk(&"a".repeat(25))];
        // 25-char line at width 10 → 3 rows; others 1 each
        assert_eq!(wrapped_count(&lines, 10), 5);
        // exact multiples don't spill an extra row
        let exact = vec![mk(&"x".repeat(10))];
        assert_eq!(wrapped_count(&exact, 10), 1);
        // zero width degrades to 1 char per row
        assert_eq!(wrapped_count(&lines, 0), 31);
    }

    #[test]
    fn port_overview_groups_listeners() {
        let mk = |proto: &str, addr: &str, port: u16, state: &str, pid: Option<Pid>| Socket {
            proto: proto.into(),
            local_addr: addr.into(),
            local_port: port,
            peer_addr: None,
            peer_port: None,
            state: state.into(),
            pid,
        };
        let procs = vec![Process {
            pid: 100,
            name: "nginx".into(),
            user: Some("root".into()),
            ..Default::default()
        }];
        let sockets = vec![
            mk("tcp", "0.0.0.0", 8080, "LISTEN", Some(100)),
            mk("tcp6", "::", 8080, "LISTEN", Some(100)), // same port+pid → one row
            mk("tcp", "127.0.0.1", 9000, "ESTABLISHED", Some(100)), // dropped: not serving
            mk("udp", "0.0.0.0", 5353, "UNCONNECTED", Some(100)), // bound udp kept
            mk("udp", "0.0.0.0", 0, "UNCONNECTED", None), // ephemeral udp dropped
            mk("tcp", "0.0.0.0", 22, "LISTEN", None),     // unknown owner
        ];
        let rows = port_overview_rows(&sockets, &procs);
        assert_eq!(rows.len(), 3, "8080 merges, 9000/udp0 drop, 22+5353 stay");
        assert_eq!(rows[0].port, 22);
        assert_eq!(rows[0].pid, None);
        assert_eq!(rows[0].name, "-");
        assert_eq!(rows[0].user, "-");
        assert_eq!(rows[1].port, 5353);
        assert_eq!(rows[1].protos, "udp");
        assert_eq!(rows[2].port, 8080);
        assert_eq!(rows[2].protos, "tcp/tcp6");
        assert_eq!(rows[2].name, "nginx");
        assert_eq!(rows[2].user, "root");
        assert_eq!(rows[2].addrs, 2, "v4 + v6 listener both counted");
        // exposure scope comes from the bind addresses: the wildcard
        // 0.0.0.0/:: listeners read as internet-reachable even merged
        assert_eq!(rows[2].scope, "internet");
        assert_eq!(
            rows[0].scope, "internet",
            "ownerless still has a wildcard bind"
        );
    }

    #[test]
    fn ports_overview_toggle_and_enter_opens_owner() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        on_key(&mut app, KeyCode::Char('2')); // Ports tab
        // inject a controlled socket table (switch_tab already refetched
        // the real one) — pid 1 is always alive, 999_999 never is
        app.sockets = vec![
            Socket {
                proto: "tcp".into(),
                local_addr: "127.0.0.1".into(),
                local_port: 8080,
                peer_addr: None,
                peer_port: None,
                state: "LISTEN".into(),
                pid: Some(1),
            },
            Socket {
                proto: "tcp".into(),
                local_addr: "127.0.0.1".into(),
                local_port: 9999,
                peer_addr: None,
                peer_port: None,
                state: "LISTEN".into(),
                pid: Some(999_999),
            },
        ];
        app.rebuild_socket_view();
        assert!(!app.ports_overview);
        on_key(&mut app, KeyCode::Char('o'));
        assert!(app.ports_overview);
        assert_eq!(app.port_overview_view.len(), 2);
        assert_eq!(app.port_overview_view[0].port, 8080);
        // Enter on the live owner jumps to its process detail page
        on_key(&mut app, KeyCode::Enter);
        assert_eq!(app.page, Page::Detail);
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Browse);
        // dead owner: stays put and says why
        on_key(&mut app, KeyCode::Char('j'));
        on_key(&mut app, KeyCode::Enter);
        assert_eq!(app.page, Page::Browse);
        assert!(app.status.contains("999999 has exited"));
        // toggle off returns to the raw per-socket list
        on_key(&mut app, KeyCode::Char('o'));
        assert!(!app.ports_overview);
        assert!(!app.socket_view.is_empty());
    }

    #[test]
    fn pause_freezes_the_sampling_tick() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        assert!(!app.paused);
        on_key(&mut app, KeyCode::Char('P'));
        assert!(app.paused);
        assert!(app.status.contains("paused"));
        // a due tick while paused is skipped: last_refresh untouched
        app.last_refresh = Instant::now() - REFRESH;
        tick_refresh(&mut app);
        assert!(app.last_refresh.elapsed() >= REFRESH, "paused tick skipped");
        // resume ('P' again): the next due tick fires a real refresh
        on_key(&mut app, KeyCode::Char('P'));
        assert!(!app.paused);
        assert!(app.status.contains("resumed"));
        tick_refresh(&mut app);
        assert!(app.last_refresh.elapsed() < REFRESH, "resumed tick refreshed");
    }

    #[test]
    fn group_rows_aggregate_and_sort() {
        use crate::history::History;
        let mk = |pid: Pid, name: &str, user: Option<&str>, mem_mb: u64| Process {
            pid,
            name: name.into(),
            user: user.map(String::from),
            mem_kb: Some(mem_mb * 1024),
            ..Default::default()
        };
        let mut hist = History::new();
        let procs = vec![
            mk(1, "Chrome Helper", Some("yao"), 100),
            mk(2, "Chrome Helper", Some("yao"), 300),
            mk(3, "nginx", Some("root"), 50),
        ];
        let all = vec![0, 1, 2];
        // name mode merges the two Chrome Helpers; order by name asc
        let rows = group_rows(&procs, &all, GroupMode::Name, &hist, SortKey::Name);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].key, "Chrome Helper");
        assert_eq!(rows[0].count, 2);
        assert_eq!(rows[0].mem_kb, 400 * 1024);
        assert_eq!(rows[0].top_pid, 2, "cpu tie → the bigger member wins");
        assert_eq!(rows[1].key, "nginx");
        // user mode
        let rows = group_rows(&procs, &all, GroupMode::User, &hist, SortKey::Name);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].key, "root");
        assert_eq!(rows[0].count, 1);
        assert_eq!(rows[1].key, "yao");
        assert_eq!(rows[1].count, 2);
        // mem sort key → biggest group first
        let rows = group_rows(&procs, &all, GroupMode::Name, &hist, SortKey::Mem);
        assert_eq!(rows[0].key, "Chrome Helper");
        // empty selection → no rows
        assert!(group_rows(&procs, &[], GroupMode::Name, &hist, SortKey::Name).is_empty());
        let _ = &mut hist;
    }

    #[test]
    fn group_mode_cycles_selection_and_gone_status() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        assert_eq!(app.group_mode, GroupMode::Off);
        // inject a controlled table (two same-name processes + a stranger)
        let mk = |pid: Pid, name: &str, mem_mb: u64| Process {
            pid,
            name: name.into(),
            mem_kb: Some(mem_mb * 1024),
            ..Default::default()
        };
        app.procs = vec![
            mk(910, "zz-test-a", 100),
            mk(911, "zz-test-a", 300),
            mk(912, "zz-test-b", 50),
        ];
        app.rebuild_view();
        on_key(&mut app, KeyCode::Char('B'));
        assert_eq!(app.group_mode, GroupMode::Name);
        assert_eq!(app.group_view.len(), 2);
        assert_eq!(app.group_view[0].key, "zz-test-a");
        assert_eq!(app.group_view[0].count, 2);
        // the selection maps to the group's busiest member (mem tiebreak)
        assert_eq!(app.selected_pid(), Some(911));
        // Enter opens that member — with the busiest member's pid swapped for
        // one no kernel can ever allocate (Linux pid_max ≤ 4 194 304, macOS
        // ≤ 99 998) so "gone" is deterministic instead of racing with whatever
        // happens to run on the test machine (pid 911 was taken once).
        const GONE_PID: Pid = 4_194_305;
        app.procs[1].pid = GONE_PID;
        app.rebuild_view();
        assert_eq!(app.selected_pid(), Some(GONE_PID));
        on_key(&mut app, KeyCode::Enter);
        assert_eq!(app.page, Page::Browse);
        assert!(app.status.contains("is gone"));
        // cycle: user → container → off (un-attributed procs group under "-")
        on_key(&mut app, KeyCode::Char('B'));
        assert_eq!(app.group_mode, GroupMode::User);
        on_key(&mut app, KeyCode::Char('B'));
        assert_eq!(app.group_mode, GroupMode::Container);
        assert!(app.group_view.iter().any(|g| g.key == "-"));
        on_key(&mut app, KeyCode::Char('B'));
        assert_eq!(app.group_mode, GroupMode::Off);
        assert!(app.group_view.is_empty());
        // tree and grouping are mutually exclusive
        on_key(&mut app, KeyCode::Char('B'));
        assert_eq!(app.group_mode, GroupMode::Name);
        on_key(&mut app, KeyCode::Char('T'));
        assert!(app.tree_mode);
        assert_eq!(app.group_mode, GroupMode::Off);
    }

    #[test]
    fn summary_page_opens_counts_and_closes() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        assert_eq!(app.page, Page::Browse);
        // default window covers the whole session
        assert_eq!(app.summary_window, u64::MAX);
        // synthetic event ring (TuiApp::new's live seeding would flood the
        // 500-cap ring with table churn — inject, don't update)
        let ev = |kind: &str, pid: Pid| crate::history::TuiEvent {
            at_unix: crate::util::now_unix(),
            kind: kind.into(),
            pid,
            name: "zz-summary".into(),
            detail: String::new(),
        };
        app.hist.events = vec![ev("restarted", 881), ev("exited", 880), ev("started", 880)];
        on_key(&mut app, KeyCode::Char('S'));
        assert_eq!(app.page, Page::Summary);
        let s = app.summary.as_ref().expect("digest computed on open");
        assert_eq!((s.started, s.exited, s.restarted), (1, 1, 1));
        assert_eq!(
            s.chains,
            vec![crate::history::ChainRow { name: "zz-summary".into(), count: 1 }]
        );
        // 'r' recomputes in place; Esc returns to browse
        on_key(&mut app, KeyCode::Char('r'));
        assert_eq!(app.page, Page::Summary);
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Browse);
        // --since seeds a narrower window
        let app = TuiApp::new(
            crate::platform::get(),
            Seed {
                since: Some(300),
                ..Seed::default()
            },
        );
        assert_eq!(app.summary_window, 300);
    }

    #[test]
    fn system_page_opens_samples_and_closes() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        assert_eq!(app.page, Page::Browse);
        on_key(&mut app, KeyCode::Char('y'));
        assert_eq!(app.page, Page::System);
        // opening took one sample — the "now" snapshot is there even on a
        // platform whose first CPU delta is still empty
        let stats = app.sys_stats.as_ref().expect("sampled on open");
        let _ = stats;
        // the copy text is non-empty (memory/load section renders from the
        // snapshot alone)
        assert!(!app.focused_pane_text().is_empty(), "page has meters");
        // 'r' refreshes in place; Esc returns to browse
        on_key(&mut app, KeyCode::Char('r'));
        assert_eq!(app.page, Page::System);
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Browse);
    }

    #[test]
    fn system_page_net_section_arms_then_shows_rates() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        on_key(&mut app, KeyCode::Char('y'));
        if app.sys_net_prev.is_empty() {
            // platform with no net counters (hermetic CI): the section
            // stays hidden rather than showing an empty shell
            assert!(app.sys_net_rows.is_empty());
            return;
        }
        // new()'s initial refresh armed the counters at an unknown
        // wall-clock instant — on a slow host the sweep behind on_key('y')
        // is already past the rate window, so rows can exist here (same
        // startup race 624df02 fixed for the pid table). No "rows must be
        // empty yet" assertion; only the timing-free rows⇔history
        // invariant. Advance two refreshes and check it holds throughout.
        for _ in 0..2 {
            on_key(&mut app, KeyCode::Char('r'));
            if !app.sys_net_rows.is_empty() {
                assert!(!app.sys_net_hist.is_empty());
                let total: f64 = app.sys_net_rows.iter().map(|(_, rx, tx)| rx + tx).sum();
                let last = app.sys_net_hist.last().copied().unwrap();
                assert!((last - total).abs() < 1e-6, "{last} vs {total}");
                for (_, rx, tx) in &app.sys_net_rows {
                    assert!(*rx >= 0.0 && *tx >= 0.0, "rates never negative");
                }
            }
        }
    }

    #[test]
    fn config_seed_applies_sort_pause_and_interval() {
        let app = TuiApp::new(
            crate::platform::get(),
            Seed {
                refresh_secs: Some(7),
                sort: Some("cpu".into()),
                paused: true,
                ..Seed::default()
            },
        );
        assert_eq!(app.refresh, Duration::from_secs(7));
        assert_eq!(app.sort_key, SortKey::Cpu);
        assert!(app.paused, "config paused starts frozen");
        // unknown sort names fall back to the built-in default
        let app = TuiApp::new(
            crate::platform::get(),
            Seed {
                sort: Some("bogus".into()),
                ..Seed::default()
            },
        );
        assert_eq!(app.sort_key, SortKey::Mem);
        assert_eq!(app.refresh, REFRESH);
        // sort_key_from_str accepts every documented name
        for (name, key) in [
            ("pid", SortKey::Pid),
            ("name", SortKey::Name),
            ("user", SortKey::User),
            ("cpu", SortKey::Cpu),
            ("mem", SortKey::Mem),
            ("io", SortKey::Io),
            ("started", SortKey::Started),
        ] {
            assert_eq!(sort_key_from_str(name), Some(key), "{name}");
        }
        assert_eq!(sort_key_from_str("wat"), None);
    }

    #[test]
    fn io_sort_orders_by_sampled_rate() {
        let mk = |pid: Pid, name: &str, rb: u64, wb: u64| Process {
            pid,
            name: name.into(),
            io_read_bytes: Some(rb),
            io_write_bytes: Some(wb),
            ..Default::default()
        };
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        app.procs = vec![
            mk(1, "idle", 0, 0),
            mk(2, "writer", 1000, 1000),
            mk(3, "reader", 1000, 1000),
        ];
        app.search.clear();
        // baseline sample seeds the counters; the second tick gives reader
        // ~3 MB/s read vs writer ~1.5 MB/s write (real sleeps: the rate
        // needs ≥50 ms between samples)
        let baseline = app.procs.clone();
        app.hist.update(&baseline);
        std::thread::sleep(std::time::Duration::from_millis(60));
        let tick = vec![
            mk(1, "idle", 0, 0),
            mk(2, "writer", 1000, 1_500_000),
            mk(3, "reader", 3_000_000, 1000),
        ];
        app.hist.update(&tick);
        app.procs = tick;
        app.sort_key = SortKey::Io;
        app.sort_desc = true;
        app.rebuild_view();
        let names: Vec<&str> = app.view.iter().map(|&i| app.procs[i].name.as_str()).collect();
        assert_eq!(names, vec!["reader", "writer", "idle"]);
        // flipping direction puts the quiet first
        app.sort_desc = false;
        app.rebuild_view();
        let names: Vec<&str> = app.view.iter().map(|&i| app.procs[i].name.as_str()).collect();
        assert_eq!(names, vec!["idle", "writer", "reader"]);
    }

    #[test]
    fn metric_filter_parses_expressions_and_falls_back() {
        // substring searches stay the default
        assert_eq!(parse_metric_filter("nginx"), None);
        assert_eq!(parse_metric_filter(""), None);
        assert_eq!(parse_metric_filter("cpu"), None, "bare metric isn't an expression");
        assert_eq!(parse_metric_filter("cpu>"), None, "no value");
        assert_eq!(parse_metric_filter("ram>50"), None, "unknown metric");
        let f = |s: &str| parse_metric_filter(s).unwrap();
        // cpu/fd compare plain numbers; >=/<= collapse onto >/<
        assert_eq!(f("cpu>50"), MetricFilter { metric: FilterMetric::Cpu, gt: true, value: 50.0 });
        assert_eq!(f("cpu >= 90.5"), MetricFilter { metric: FilterMetric::Cpu, gt: true, value: 90.5 });
        assert_eq!(f("fd<10"), MetricFilter { metric: FilterMetric::Fd, gt: false, value: 10.0 });
        // bare mem is MB (stored KiB), suffixes scale: 2g → 2 GiB in KiB
        assert_eq!(f("mem>500"), MetricFilter { metric: FilterMetric::Mem, gt: true, value: 500.0 * 1024.0 });
        assert_eq!(f("mem<=2g"), MetricFilter { metric: FilterMetric::Mem, gt: false, value: 2e9 * 1024.0 });
        // age: bare seconds, m/h/d suffixes
        assert_eq!(f("age>3600"), MetricFilter { metric: FilterMetric::Age, gt: true, value: 3600.0 });
        assert_eq!(f("age>1h"), MetricFilter { metric: FilterMetric::Age, gt: true, value: 3600.0 });
        assert_eq!(f("age<30m"), MetricFilter { metric: FilterMetric::Age, gt: false, value: 1800.0 });
        // io: bare bytes/s, k/m/g scale — and "10m" means megabytes here,
        // not minutes (the metric disambiguates the suffix)
        assert_eq!(f("io>1048576"), MetricFilter { metric: FilterMetric::Io, gt: true, value: 1_048_576.0 });
        assert_eq!(f("io>10m"), MetricFilter { metric: FilterMetric::Io, gt: true, value: 1e7 });
    }

    #[test]
    fn metric_filter_narrows_the_table() {
        let mk = |pid: Pid, name: &str, kb: Option<u64>| Process {
            pid,
            name: name.into(),
            mem_kb: kb,
            ..Default::default()
        };
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        app.procs = vec![
            mk(1, "small", Some(100 * 1024)),   // 100 MB
            mk(2, "big", Some(600 * 1024)),     // 600 MB
            mk(3, "unknown", None),
        ];
        app.search = "mem>500".into();
        app.rebuild_view();
        let names: Vec<&str> = app.view.iter().map(|&i| app.procs[i].name.as_str()).collect();
        assert_eq!(names, vec!["big"], "only the >500 MB process survives");
        // mem<500 keeps the small one and the unmeasured (unknown sorts low)
        app.search = "mem<500".into();
        app.rebuild_view();
        let mut names: Vec<&str> = app.view.iter().map(|&i| app.procs[i].name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["small", "unknown"]);
        // cpu>… uses the display cpu (unmeasured = -1.0, excluded)
        app.search = "cpu>0".into();
        app.rebuild_view();
        assert!(app.view.is_empty(), "no samples yet → nothing measures above 0");
        // non-expressions keep substring semantics
        app.search = "big".into();
        app.rebuild_view();
        let names: Vec<&str> = app.view.iter().map(|&i| app.procs[i].name.as_str()).collect();
        assert_eq!(names, vec!["big"]);
    }

    #[test]
    fn vim_navigation() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        if app.view.len() < 3 {
            panic!("need a few processes for the test");
        }
        let n = app.view.len();
        assert_eq!(app.table_state.selected(), Some(0));

        on_key(&mut app, KeyCode::Char('j'));
        assert_eq!(app.table_state.selected(), Some(1));
        on_key(&mut app, KeyCode::Char('k'));
        assert_eq!(app.table_state.selected(), Some(0));
        on_key(&mut app, KeyCode::Char('G'));
        assert_eq!(app.table_state.selected(), Some(n - 1));
        on_key(&mut app, KeyCode::Char('g'));
        assert_eq!(app.table_state.selected(), Some(0));
        on_key(&mut app, KeyCode::Char('k')); // clamp at top
        assert_eq!(app.table_state.selected(), Some(0));
        on_key(&mut app, KeyCode::Char('f'));
        assert_eq!(app.table_state.selected(), Some(20.min(n - 1)));
        on_key(&mut app, KeyCode::Char('b'));
        assert_eq!(app.table_state.selected(), Some(0));
    }

    #[test]
    fn tree_order_nests_children_under_parents() {
        // family: 1 → (2 → 4), 1 → 3; a stray root 9 whose parent is absent
        let mk = |pid: Pid, ppid: Option<Pid>| Process {
            pid,
            ppid,
            name: format!("p{pid}"),
            ..Default::default()
        };
        let procs = vec![mk(1, None), mk(2, Some(1)), mk(3, Some(1)), mk(4, Some(2)), mk(9, Some(7))];
        let sorted: Vec<usize> = (0..procs.len()).collect();
        let (order, depth) = tree_order(&procs, &sorted);
        let pids: Vec<Pid> = order.iter().map(|&i| procs[i].pid).collect();
        assert_eq!(pids, vec![1, 2, 4, 3, 9], "DFS: children directly under parent");
        assert_eq!(depth, vec![0, 1, 2, 1, 0]);
        // cycle guard: ppid pointing back at a visited pid doesn't loop
        let cyc = vec![mk(5, Some(6)), mk(6, Some(5))];
        let (o2, _) = tree_order(&cyc, &[0, 1]);
        assert_eq!(o2.len(), 2, "cycle terminates with every row present");
    }

    /// A deterministic synthetic table (live refresh would race a proc
    /// vanishing): big/mid/watched where the watched one sorts last by the
    /// default Mem-desc key.
    fn watch_test_app() -> TuiApp {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        let mk = |pid: Pid, mem_kb: u64, exe: &str| Process {
            pid,
            name: format!("p{pid}"),
            mem_kb: Some(mem_kb),
            user: Some("u".into()),
            exe: Some(exe.into()),
            ..Default::default()
        };
        app.procs = vec![mk(1, 999, "/bin/p1"), mk(2, 500, "/bin/p2"), mk(3, 1, "/bin/p3")];
        app.rebuild_view();
        app
    }

    #[test]
    fn watch_toggle_pins_and_survives_pid_change() {
        let mut app = watch_test_app();
        // default sort is Mem desc → pid 3 (1 KiB) is the bottom row
        let n = app.view.len();
        app.table_state.select(Some(n - 1));
        assert_eq!(app.procs[app.view[n - 1]].pid, 3);
        assert!(!app.is_watched(&app.procs[app.view[n - 1]]));

        let (added, name) = app.toggle_watch_in_memory();
        assert!(added, "first 'w' watches");
        assert_eq!(name, "p3");
        assert_eq!(app.watch, vec!["p3|p3|u".to_string()]);
        // pinned: the watched process now sits at the top of the view
        assert_eq!(app.procs[app.view[0]].pid, 3, "watched process pins to top");

        // restart under a new pid: the identity key ignores the pid
        let top = app.view[0];
        app.procs[top].pid = 424242;
        assert!(app.is_watched(&app.procs[top]), "star follows the program, not the pid");

        // toggle again on the (re-selected) top row → unwatched
        app.table_state.select(Some(0));
        app.rebuild_view();
        app.table_state.select(Some(0));
        let (added, _) = app.toggle_watch_in_memory();
        assert!(!added, "second 'w' unwatches");
        assert!(app.watch.is_empty());
        assert_eq!(app.procs[app.view[0]].pid, 1, "pin released, Mem-desc order restored");
    }

    #[test]
    fn seeded_watch_pins_from_config() {
        let mut app = watch_test_app();
        app.watch = vec![crate::util::identity_key(&app.procs[2])];
        app.rebuild_view();
        assert_eq!(app.procs[app.view[0]].pid, 3, "config-seeded watch pins at startup");

        // search filters fine alongside the pin; tree mode skips pinning
        app.search = "p".into();
        app.rebuild_view();
        assert_eq!(app.procs[app.view[0]].pid, 3, "pin survives filtering");
        app.search.clear();
        app.tree_mode = true;
        app.rebuild_view();
        assert_eq!(app.procs[app.view[0]].pid, 1, "tree mode keeps parent/child shape");
    }

    #[test]
    fn tree_mode_toggle_orders_and_search_falls_back_to_flat() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        on_key(&mut app, KeyCode::Char('T'));
        assert!(app.tree_mode);
        assert!(!app.view_depth.is_empty(), "tree mode fills the depth column");
        // depth-0 rows exist and children follow parents (pid adjacency)
        let first_root = app.view_depth[0];
        assert_eq!(first_root, 0);
        // 'T' again → back to flat
        on_key(&mut app, KeyCode::Char('T'));
        assert!(!app.tree_mode);
        assert!(app.view_depth.is_empty());
        // lowercase 't' still sorts by start time (not the tree toggle)
        on_key(&mut app, KeyCode::Char('t'));
        assert!(!app.tree_mode);
        assert_eq!(app.sort_key, SortKey::Started);
    }

    #[test]
    fn logs_follow_state_transitions() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        // Windows event log: F explains itself and spawns nothing
        app.logs_src = Some(crate::logs::LogSource::EventLog {
            pid: 1,
            name: "nginx".into(),
        });
        app.toggle_logs_follow();
        assert!(app.follow_child.is_none());
        assert!(app.status.contains("no Windows event-log equivalent"));
        // no source at all
        app.logs_src = None;
        app.toggle_logs_follow();
        assert!(app.follow_child.is_none());
        assert!(app.status.contains("no log source"));
        // stop without a running stream is a safe no-op
        app.stop_logs_follow();
        assert!(app.follow_rx.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn logs_follow_follows_journald_and_unified_sources() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        // journald: journalctl -f exists on Linux; on macOS the spawn fails
        // but the code path is identical — assert on the attempt, not the
        // result
        app.logs_src = Some(crate::logs::LogSource::Journald { pid: 1 });
        app.toggle_logs_follow();
        if app.follow_child.is_some() {
            app.stop_logs_follow();
            assert!(app.follow_rx.is_none());
            assert!(app.status.contains("follow stopped"));
        } else {
            assert!(app.status.starts_with("follow:"));
        }
        // unified log source routes to `log stream` (same attempt pattern)
        app.logs_src = Some(crate::logs::LogSource::UnifiedLog { name: "launchd".into() });
        app.toggle_logs_follow();
        if app.follow_child.is_some() {
            app.stop_logs_follow();
        } else {
            assert!(app.status.starts_with("follow:"));
        }
        // toggling twice never stacks two children
        assert!(app.follow_child.is_none());
    }

    #[test]
    fn h_l_switch_tabs() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        on_key(&mut app, KeyCode::Char('h'));
        assert_eq!(app.tab, Tab::Services);
        on_key(&mut app, KeyCode::Char('h'));
        assert_eq!(app.tab, Tab::Events);
        on_key(&mut app, KeyCode::Char('h'));
        assert_eq!(app.tab, Tab::Locks);
        on_key(&mut app, KeyCode::Char('l'));
        assert_eq!(app.tab, Tab::Events);
        // 'l' on the Events tab is the logs key now (previously a dead arm —
        // the generic tab-switch shadowed it): the seeded "started" event's
        // process is alive, so logs open for it instead of switching tabs
        on_key(&mut app, KeyCode::Char('l'));
        assert_eq!(app.page, Page::Logs);
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Browse);
        // digit jump still lands on Events, and '6' reaches Services
        on_key(&mut app, KeyCode::Char('5'));
        assert_eq!(app.tab, Tab::Events);
        on_key(&mut app, KeyCode::Char('6'));
        assert_eq!(app.tab, Tab::Services);
    }

    #[test]
    fn death_log_source_branches() {
        assert_eq!(
            death_log_source("macos", 9, "nginx"),
            crate::logs::LogSource::UnifiedLog { name: "nginx".into() }
        );
        assert_eq!(
            death_log_source("linux", 9, "nginx"),
            crate::logs::LogSource::Journald { pid: 9 }
        );
        assert_eq!(
            death_log_source("windows", 9, "nginx"),
            crate::logs::LogSource::EventLog { pid: 9, name: "nginx".into() }
        );
    }

    #[test]
    fn notify_command_platform_shapes() {
        // macOS: quoted AppleScript, embedded quotes neutralized
        let (prog, args) = notify_command_for("macos", "witr-rs", "nginx said \"hi\"").unwrap();
        assert_eq!(prog, "osascript");
        assert_eq!(args[0], "-e");
        assert_eq!(
            args[1],
            "display notification \"nginx said 'hi'\" with title \"witr-rs\""
        );
        // Linux: plain notify-send title body
        let (prog, args) = notify_command_for("linux", "witr-rs", "nginx restarted").unwrap();
        assert_eq!(prog, "notify-send");
        assert_eq!(args, vec!["witr-rs", "nginx restarted"]);
        // Windows: one PowerShell -Command element with the toast script;
        // single quotes are doubled, not stripped
        let (prog, args) =
            notify_command_for("windows", "witr-rs", "nginx exited; it's gone").unwrap();
        assert_eq!(prog, "powershell");
        assert_eq!(args[0], "-NoProfile");
        assert_eq!(args[1], "-Command");
        let script = &args[2];
        assert!(script.contains("ToastNotificationManager"), "{script}");
        assert!(script.contains("ToastText02"), "{script}");
        assert!(script.contains("nginx exited; it''s gone"), "quotes doubled: {script}");
        let evil = notify_command_for("windows", "witr-rs", "bad'); x").unwrap().1[2].clone();
        assert!(evil.contains("bad''); x"), "hostile quotes doubled: {evil}");
        // elsewhere: nothing to call
        assert!(notify_command_for("plan9", "witr-rs", "x").is_none());
    }

    #[test]
    fn alert_webhook_posts_the_envelope() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        send_alert_webhook(
            &format!("http://127.0.0.1:{port}/hook"),
            42,
            "nginx",
            "cpu 95% over line",
            "alert",
        );
        listener
            .set_nonblocking(true)
            .expect("nonblocking accept loop");
        let deadline = Instant::now() + Duration::from_secs(3);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(x) => break x,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(e) => panic!("no webhook connection arrived: {e}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 512];
        loop {
            match std::io::Read::read(&mut stream, &mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        }
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("POST /hook HTTP/1.1"), "{text}");
        assert!(text.contains("Content-Type: application/json"), "{text}");
        assert!(text.contains("\"pid\":42"), "{text}");
        assert!(text.contains("\"name\":\"nginx\""), "{text}");
        assert!(text.contains("cpu 95% over line"), "{text}");
    }

    #[test]
    fn follow_command_shapes_per_source() {
        use crate::logs::LogSource;
        // container: runtime CLI with -f and a tail seed
        let (prog, args, label) = follow_command_for(&LogSource::Container {
            runtime: "podman".into(),
            ref_: "abc123".into(),
        })
        .unwrap();
        assert_eq!(prog, "podman");
        assert_eq!(args[..3], ["logs", "-f", "--tail"]);
        assert_eq!(args[4], "abc123");
        assert_eq!(label, "podman logs");
        // journald: follow filtered by the pid
        let (prog, args, _) = follow_command_for(&LogSource::Journald { pid: 42 }).unwrap();
        assert_eq!(prog, "journalctl");
        assert!(args.contains(&"-f".to_string()));
        assert!(args.contains(&"_PID=42".to_string()));
        // macOS unified log: log stream with the sanitized process predicate
        let (prog, args, _) =
            follow_command_for(&LogSource::UnifiedLog { name: "nginx-worker".into() }).unwrap();
        assert_eq!(prog, "log");
        assert_eq!(args[0], "stream");
        assert!(args.contains(&"process == \"nginx-worker\"".to_string()));
        // hostile names never reach the predicate raw
        let (_, args, _) =
            follow_command_for(&LogSource::UnifiedLog { name: "bad\"name;x".into() }).unwrap();
        assert!(args.contains(&"process == \"badnamex\"".to_string()));
        // Windows event log has no streaming shape
        assert!(follow_command_for(&LogSource::EventLog {
            pid: 1,
            name: "x".into()
        })
        .is_none());
    }

    #[test]
    fn notify_picks_restarts_and_crash_loops() {
        let ev = |kind: &str, pid: Pid, name: &str| crate::history::TuiEvent {
            at_unix: crate::util::now_unix(),
            kind: kind.into(),
            pid,
            name: name.into(),
            detail: String::new(),
        };
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        // toggle off: nothing fires, tally still not touched
        let fresh = [ev("restarted", 5, "nginx"), ev("exited", 6, "nginx")];
        assert!(app.notify_picks(&fresh).is_empty());
        app.notify = true;
        // first cycle: restart notifies, plain exit does not
        let fresh = [ev("started", 1, "nginx"), ev("restarted", 2, "nginx")];
        assert_eq!(app.notify_picks(&fresh).len(), 1);
        // second restart of the same name → tally 2, its exit now notifies
        let fresh = [ev("restarted", 3, "nginx")];
        assert_eq!(app.notify_picks(&fresh).len(), 1);
        let fresh = [ev("exited", 3, "nginx")];
        let picks = app.notify_picks(&fresh);
        assert_eq!(picks.len(), 1);
        assert!(picks[0].contains("nginx (pid 3) exited again — crash loop?"));
        // a different name's first exit stays quiet
        let fresh = [ev("exited", 9, "busybox")];
        assert!(app.notify_picks(&fresh).is_empty());
    }

    #[test]
    fn alert_cycle_fires_once_per_excursion() {
        use crate::history::AlertEdge;
        let mut streak = 0u32;
        let mut firing = false;
        // four hot samples: quiet; the fifth fires exactly once
        for _ in 0..4 {
            assert_eq!(alert_cycle(&mut streak, &mut firing, true), AlertEdge::None);
        }
        assert_eq!(alert_cycle(&mut streak, &mut firing, true), AlertEdge::Fire);
        assert_eq!(streak, 5);
        // still hot: stays quiet (already fired for this excursion)
        assert_eq!(alert_cycle(&mut streak, &mut firing, true), AlertEdge::None);
        // drops under: re-arms, and the recovery is reported exactly once
        assert_eq!(alert_cycle(&mut streak, &mut firing, false), AlertEdge::Recover);
        assert_eq!(alert_cycle(&mut streak, &mut firing, false), AlertEdge::None);
        assert_eq!(streak, 0);
        // a fresh excursion needs the full run again
        for _ in 0..4 {
            assert_eq!(alert_cycle(&mut streak, &mut firing, true), AlertEdge::None);
        }
        assert_eq!(alert_cycle(&mut streak, &mut firing, true), AlertEdge::Fire);
    }

    #[test]
    fn replay_ring_scrubs_back_then_returns_live() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        app.refresh();
        app.refresh(); // two samples → two frames
        assert!(app.replay_ring.len() >= 2, "refresh fills the ring");
        assert!(app.replay_pos.is_none(), "starts live");
        // '<' steps to the newest past frame, then further back
        on_key(&mut app, KeyCode::Char('<'));
        assert!(app.replay_pos.is_some());
        let back = app.replay_pos.unwrap();
        on_key(&mut app, KeyCode::Char('<'));
        assert_eq!(app.replay_pos, Some(back.saturating_sub(1)));
        // '>' forward: reaches the newest frame, then returns to live
        on_key(&mut app, KeyCode::Char('>'));
        on_key(&mut app, KeyCode::Char('>'));
        assert!(app.replay_pos.is_none(), "newest '>' returns to live");
        // '>' while live is a no-op with a hint
        on_key(&mut app, KeyCode::Char('>'));
        assert!(app.replay_pos.is_none());
        assert!(app.status.contains("already live"));
        // replaying freezes the table: a refresh keeps the scrubbed frame
        on_key(&mut app, KeyCode::Char('<'));
        let frozen = app.procs.clone();
        app.refresh();
        assert_eq!(app.procs.len(), frozen.len(), "refresh leaves a replayed frame put");
    }

    #[test]
    fn alert_picks_fire_after_sustained_over_and_rearm() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        app.alert_cpu = Some(50.0);
        app.alert_mem = Some(100);
        let mk = |pid: Pid, kb: Option<u64>| crate::model::Process {
            pid,
            name: format!("p{pid}"),
            mem_kb: kb,
            ..Default::default()
        };
        // pid 1: cpu hot; pid 2: huge RSS; pid 3: quiet
        app.procs = vec![mk(1, Some(10 * 1024)), mk(2, Some(500 * 1024)), mk(3, None)];
        app.hist.cpu_now.insert(1, 90.0);
        app.hist.cpu_now.insert(3, 5.0);
        // cycles 1-4: nothing yet
        for _ in 0..4 {
            assert!(app.alert_picks().is_empty(), "below cycle threshold");
        }
        // cycle 5: both fire, each with its metric named
        let picks = app.alert_picks();
        assert_eq!(picks.len(), 2);
        assert!(picks.iter().any(|(pid, _, d, _)| *pid == 1 && d.contains("CPU")));
        assert!(picks.iter().any(|(pid, _, d, _)| *pid == 2 && d.contains("RSS")));
        // cycle 6: still over but already fired → quiet
        assert!(app.alert_picks().is_empty());
        // both drop under → one recovery edge each, then quiet (re-armed)
        app.hist.cpu_now.insert(1, 1.0);
        app.procs[1].mem_kb = Some(10 * 1024);
        let recs = app.alert_picks();
        assert_eq!(recs.len(), 2, "{recs:?}");
        assert!(recs.iter().all(|(.., rec)| *rec));
        assert!(recs.iter().any(|(pid, _, d, _)| *pid == 1 && d.contains("back under")));
        assert!(app.alert_picks().is_empty());
        app.hist.cpu_now.insert(1, 99.0);
        app.procs[1].mem_kb = Some(900 * 1024);
        for _ in 0..4 {
            assert!(app.alert_picks().is_empty());
        }
        assert_eq!(app.alert_picks().len(), 2);
        // bookkeeping for a vanished pid is pruned
        app.procs = vec![mk(3, None)];
        app.alert_picks();
        assert!(!app.alert_state.contains_key(&1));
    }

    #[test]
    fn alert_exec_runs_with_alert_context_in_env() {
        // real command, real env — the fastest hermetic check of the whole
        // fire path (spawn_alert_exec is sync-equivalent from the test's
        // view: the file appears within the wait loop or it didn't happen)
        let dir = std::env::temp_dir().join(format!("witr-alert-exec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("fired.txt");
        let _ = std::fs::remove_file(&out);
        let cmd = format!(
            "echo \"$WITR_ALERT_PID|$WITR_ALERT_NAME|$WITR_ALERT_DETAIL\" > {}",
            out.display()
        );
        spawn_alert_exec(&cmd, 42, "nginx", "CPU 90% above 50% for 15s", "alert");
        let mut content = String::new();
        for _ in 0..100 {
            if let Ok(s) = std::fs::read_to_string(&out) {
                content = s;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        std::fs::remove_dir_all(dir).ok();
        let line = content.trim();
        assert_eq!(
            line,
            "42|nginx|CPU 90% above 50% for 15s",
            "env vars carry the alert context"
        );
    }

    #[test]
    fn death_logs_cache_round_trip() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        // a finished fetch lands in the cache and frees the in-flight slot
        let (tx, rx) = std::sync::mpsc::channel();
        app.death_rx = Some(rx);
        tx.send((5, Ok(vec!["panic: boom".into()]))).unwrap();
        app.poll_death_logs();
        assert!(app.death_rx.is_none());
        assert!(app.death_fetch_needed(9), "another pid can fetch");
        assert!(!app.death_fetch_needed(5), "captured pid is not re-fetched");
        assert_eq!(
            app.death_logs.front().map(|(p, l)| (p, l.as_slice())),
            Some((&5, &["panic: boom".to_string()][..]))
        );
        // empty and error results are not cached
        let (tx, rx) = std::sync::mpsc::channel();
        app.death_rx = Some(rx);
        tx.send((6, Ok(vec![]))).unwrap();
        app.poll_death_logs();
        let (tx, rx) = std::sync::mpsc::channel();
        app.death_rx = Some(rx);
        tx.send((8, Err("log show: timed out".into()))).unwrap();
        app.poll_death_logs();
        assert!(!app.death_logs.iter().any(|(p, _)| *p == 6 || *p == 8));
        // the cache is bounded: oldest entries evict first
        for i in 0..(DEATH_CAP as Pid + 3) {
            let (tx, rx) = std::sync::mpsc::channel();
            app.death_rx = Some(rx);
            tx.send((1000 + i, Ok(vec!["x".into()]))).unwrap();
            app.poll_death_logs();
        }
        assert_eq!(app.death_logs.len(), DEATH_CAP);
        assert_eq!(app.death_logs.front().map(|(p, _)| *p), Some(1003));
    }

    #[test]
    fn events_l_shows_cached_death_logs() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        app.hist.events.insert(
            0,
            crate::history::TuiEvent {
                at_unix: crate::util::now_unix(),
                kind: "exited".into(),
                pid: 42,
                name: "worker".into(),
                detail: String::new(),
            },
        );
        app.death_logs.push_back((42, vec!["panic: nil map".into()]));
        app.rebuild_event_view();
        app.event_state.select(Some(0));
        app.tab = Tab::Events;
        on_key(&mut app, KeyCode::Char('l'));
        assert_eq!(app.page, Page::Logs, "cached death logs open instantly");
        assert!(app.logs_for.as_deref().is_some_and(|h| h.contains("last words")));
        assert_eq!(app.logs_lines, vec!["panic: nil map".to_string()]);
        // a started event goes through the live path instead (no cached logs)
        app.hist.events.insert(
            0,
            crate::history::TuiEvent {
                at_unix: crate::util::now_unix(),
                kind: "started".into(),
                pid: 1,
                name: "init-ish".into(),
                detail: String::new(),
            },
        );
        app.page = Page::Browse;
        app.rebuild_event_view();
        app.event_state.select(Some(0));
        on_key(&mut app, KeyCode::Char('l'));
        assert_ne!(app.logs_lines, vec!["panic: nil map".to_string()]);
    }

    #[test]
    fn describe_peers_matches_local_and_remote() {
        let mk = |proto: &str, la: &str, lp: u16, pa: Option<&str>, pp: Option<u16>, st: &str, pid: Option<Pid>| Socket {
            proto: proto.into(),
            local_addr: la.into(),
            local_port: lp,
            peer_addr: pa.map(|s| s.into()),
            peer_port: pp,
            state: st.into(),
            pid,
        };
        let socks = vec![
            mk("tcp6", "*", 8921, None, None, "LISTEN", Some(1)),
            // server-side accepted socket: proves the exact loopback pairing
            mk("tcp", "127.0.0.1", 8921, Some("127.0.0.1"), Some(5001), "ESTABLISHED", Some(1)),
            // client side owned by pid 2
            mk("tcp", "127.0.0.1", 5001, Some("127.0.0.1"), Some(8921), "ESTABLISHED", Some(2)),
            // pid 3 talks to the internet — no local owner for the peer
            mk("tcp", "10.0.0.2", 51000, Some("93.184.216.34"), Some(443), "ESTABLISHED", Some(3)),
            // listeners don't count as "talking"
            mk("tcp", "*", 22, None, None, "LISTEN", Some(4)),
        ];
        let names: HashMap<Pid, String> =
            [(1, "server".to_string()), (2, "client".to_string()), (3, "curl".to_string())]
                .into_iter()
                .collect();
        // server (pid 1): peer is the client via the accepted socket
        let peers = describe_peers(&socks, &names, 1);
        assert_eq!(peers, vec![("client (pid 2)".to_string(), 1)]);
        // client (pid 2): peer is the listener's owner via wildcard match
        let peers = describe_peers(&socks, &names, 2);
        assert_eq!(peers, vec![("server (pid 1)".to_string(), 1)]);
        // outbound-only process: peer unresolved → remote label
        let peers = describe_peers(&socks, &names, 3);
        assert_eq!(peers, vec![("remote 93.184.216.34:443".to_string(), 1)]);
        // a pure listener has no established connections at all
        let peers = describe_peers(&socks, &names, 4);
        assert!(peers.is_empty());
    }

    #[test]
    fn events_tab_filter_and_selection() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        on_key(&mut app, KeyCode::Char('5'));
        assert_eq!(app.tab, Tab::Events);
        // macOS/CI boxes always churn some short-lived helpers; if the TUI
        // saw no events at all there is nothing to assert
        if app.hist.events.is_empty() {
            return;
        }
        assert!(!app.event_view.is_empty());
        // filter narrows to matches only
        app.event_search = "exited".into();
        app.rebuild_event_view();
        assert!(app
            .event_view
            .iter()
            .all(|&i| app.hist.events[i].kind == "exited"));
        app.event_search.clear();
        app.rebuild_event_view();
        // selection moves inside the event view without touching the
        // process table cursor
        let before = app.table_state.selected();
        on_key(&mut app, KeyCode::Char('j'));
        on_key(&mut app, KeyCode::Char('G'));
        assert_eq!(
            app.event_state.selected(),
            Some(app.event_view.len() - 1)
        );
        assert_eq!(app.table_state.selected(), before);
    }

    #[test]
    fn events_tab_sort_keys() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        on_key(&mut app, KeyCode::Char('5'));
        assert_eq!(app.tab, Tab::Events);
        let ev = |at: i64, kind: &str, pid: i32, name: &str| crate::history::TuiEvent {
            at_unix: at,
            kind: kind.into(),
            pid,
            name: name.into(),
            detail: String::new(),
        };
        app.hist.events = vec![
            ev(100, "started", 3, "zsh"),
            ev(200, "exited", 1, "nginx"),
            ev(150, "started", 2, "node"),
        ];
        // default: Time newest-first
        app.rebuild_event_view();
        assert_eq!(app.event_view, vec![1, 2, 0]);
        // same key again → oldest first
        on_key(&mut app, KeyCode::Char('t'));
        assert!(!app.event_sort_desc);
        assert_eq!(app.event_view, vec![0, 2, 1]);
        // pid ascending / descending ('P' is the global pause now, so the
        // desc direction comes from pressing the same key twice)
        on_key(&mut app, KeyCode::Char('p'));
        assert_eq!(app.event_sort, EventSort::Pid);
        assert!(!app.event_sort_desc);
        assert_eq!(app.event_view, vec![1, 2, 0]);
        on_key(&mut app, KeyCode::Char('p'));
        assert!(app.event_sort_desc);
        assert_eq!(app.event_view, vec![0, 2, 1]);
        // process name ascending: nginx < node < zsh
        on_key(&mut app, KeyCode::Char('n'));
        assert_eq!(app.event_view, vec![1, 2, 0]);
        // event kind ascending: exited < started (stable among equals)
        on_key(&mut app, KeyCode::Char('e'));
        assert_eq!(app.event_sort, EventSort::Kind);
        assert_eq!(app.event_view, vec![1, 0, 2]);
    }

    #[test]
    fn locks_tab_selection_and_enter_opens_detail() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        on_key(&mut app, KeyCode::Char('4'));
        assert_eq!(app.tab, Tab::Locks);
        if !app.locks_supported {
            return; // nothing to navigate on platforms without lock data
        }
        // anchor the jumps to a process that definitely exists
        let pid = app.procs[0].pid;
        app.locks = vec![
            LockEntry {
                id: "1".into(),
                kind: "POSIX".into(),
                mode: "WRITE".into(),
                pid: Some(42),
                owner: "node".into(),
                path: "/tmp/data.lock".into(),
            },
            LockEntry {
                id: "2".into(),
                kind: "FLOCK".into(),
                mode: "READ".into(),
                pid: Some(pid),
                owner: "nginx".into(),
                path: "/var/run/nginx.pid".into(),
            },
        ];
        // pin the order (path sort keeps insertion order here) so the
        // navigation assertions don't depend on the default pid sort
        app.lock_sort = LockSort::Path;
        app.rebuild_lock_view();
        assert_eq!(app.lock_state.selected(), Some(0));
        on_key(&mut app, KeyCode::Char('j'));
        assert_eq!(app.lock_state.selected(), Some(1));
        on_key(&mut app, KeyCode::Char('k'));
        assert_eq!(app.lock_state.selected(), Some(0));
        on_key(&mut app, KeyCode::Char('G'));
        assert_eq!(app.lock_state.selected(), Some(1));
        on_key(&mut app, KeyCode::Char('g'));
        assert_eq!(app.lock_state.selected(), Some(0));
        // Enter opens the holding process's detail page
        on_key(&mut app, KeyCode::Char('G'));
        on_key(&mut app, KeyCode::Enter);
        assert_eq!(app.page, Page::Detail);
        assert_eq!(app.detail_pid, Some(pid));
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Browse);
    }

    #[test]
    fn locks_tab_search_filters_and_esc_clears() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        on_key(&mut app, KeyCode::Char('4'));
        assert_eq!(app.tab, Tab::Locks);
        if !app.locks_supported {
            return; // nothing to search on platforms without lock data
        }
        // synthetic entries so the filter outcome is deterministic
        app.locks = vec![
            LockEntry {
                id: "1".into(),
                kind: "POSIX".into(),
                mode: "WRITE".into(),
                pid: Some(42),
                owner: "node".into(),
                path: "/tmp/data.lock".into(),
            },
            LockEntry {
                id: "2".into(),
                kind: "FLOCK".into(),
                mode: "READ".into(),
                pid: Some(7),
                owner: "nginx".into(),
                path: "/var/run/nginx.pid".into(),
            },
        ];
        app.rebuild_lock_view();
        on_key(&mut app, KeyCode::Char('/'));
        assert!(app.search_mode);
        for c in "nginx".chars() {
            on_key(&mut app, KeyCode::Char(c));
        }
        assert_eq!(app.lock_search, "nginx");
        assert_eq!(app.lock_view, vec![1]);
        // the process search is untouched on this tab
        assert!(app.search.is_empty());
        on_key(&mut app, KeyCode::Esc); // exits search mode
        on_key(&mut app, KeyCode::Esc); // clears the filter
        assert!(!app.search_mode);
        assert!(app.lock_search.is_empty());
        // default sort is pid ascending: 7 before 42
        assert_eq!(app.lock_view, vec![1, 0]);
    }

    #[test]
    fn locks_tab_sort_keys() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        on_key(&mut app, KeyCode::Char('4'));
        if !app.locks_supported {
            return;
        }
        app.locks = vec![
            LockEntry {
                id: "1".into(),
                kind: "POSIX".into(),
                mode: "WRITE".into(),
                pid: Some(42),
                owner: "node".into(),
                path: "/tmp/data.lock".into(),
            },
            LockEntry {
                id: "2".into(),
                kind: "FLOCK".into(),
                mode: "READ".into(),
                pid: Some(7),
                owner: "nginx".into(),
                path: "/var/run/nginx.pid".into(),
            },
        ];
        // default: pid ascending
        app.rebuild_lock_view();
        assert_eq!(app.lock_view, vec![1, 0]);
        // same key again → descending
        on_key(&mut app, KeyCode::Char('p'));
        assert_eq!(app.lock_view, vec![0, 1]);
        // path sort: /tmp < /var
        on_key(&mut app, KeyCode::Char('f'));
        assert_eq!(app.lock_sort, LockSort::Path);
        assert!(!app.lock_sort_desc);
        assert_eq!(app.lock_view, vec![0, 1]);
        on_key(&mut app, KeyCode::Char('F'));
        assert!(app.lock_sort_desc);
        assert_eq!(app.lock_view, vec![1, 0]);
        // process sort: nginx < node
        on_key(&mut app, KeyCode::Char('n'));
        assert_eq!(app.lock_view, vec![1, 0]);
    }

    #[test]
    fn locks_tab_open_files_cap_lifts_on_search() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        on_key(&mut app, KeyCode::Char('4'));
        if !app.locks_supported {
            return;
        }
        app.locks = (0..101)
            .map(|i| LockEntry {
                id: i.to_string(),
                kind: "OPEN".into(),
                mode: "R".into(),
                pid: Some(i),
                owner: format!("p{i}"),
                path: format!("/tmp/f{i}"),
            })
            .collect();
        app.locks_show_all = true;
        app.rebuild_lock_view();
        // OPEN mode caps the display at 100 until the user searches
        assert_eq!(app.lock_view.len(), 100);
        assert_eq!(app.locks_total, 101);
        app.lock_search = "p100".into();
        app.rebuild_lock_view();
        assert_eq!(app.lock_view, vec![100]);
        app.lock_search.clear();
        app.locks_show_all = false;
        app.rebuild_lock_view();
        assert_eq!(app.lock_view.len(), 101);
    }

    #[test]
    fn selection_debounce_refreshes_details() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        let first_pid = app.detail_pid;
        on_key(&mut app, KeyCode::Char('j'));
        // pending refresh is armed and the "computed for" marker is cleared
        assert!(app.detail_pending_since.is_some());
        assert_eq!(app.detail_pid, None);
        std::thread::sleep(DEBOUNCE + Duration::from_millis(80));
        settle_details(&mut app);
        assert_eq!(app.detail_pid, app.selected_pid());
        assert_ne!(app.detail_pid, first_pid);
        // the panel body actually names the new pid
        let body = app
            .detail_lines
            .iter()
            .map(|l| l.to_string())
            .collect::<String>();
        assert!(body.contains(&app.selected_pid().unwrap().to_string()));
    }

    #[test]
    fn socket_filter_matches_port_pid_name() {
        let sockets = vec![
            Socket { proto: "tcp".into(), local_addr: "127.0.0.1".into(), local_port: 8080, peer_addr: None, peer_port: None, state: "LISTEN".into(), pid: Some(100) },
            Socket { proto: "tcp6".into(), local_addr: "*".into(), local_port: 443, peer_addr: None, peer_port: None, state: "LISTEN".into(), pid: Some(200) },
            Socket { proto: "udp".into(), local_addr: "0.0.0.0".into(), local_port: 5353, peer_addr: None, peer_port: None, state: "UNCONNECTED".into(), pid: None },
        ];
        let names = |p: Pid| {
            match p {
                100 => Some("nginx".to_string()),
                200 => Some("envoy".to_string()),
                _ => None,
            }
            .map(|s| s.to_lowercase())
        };
        // by port
        assert_eq!(filter_sockets(&sockets, "8080", names).len(), 1);
        assert_eq!(filter_sockets(&sockets, "8080", names)[0], 0);
        // by pid
        assert_eq!(filter_sockets(&sockets, "200", names)[0], 1);
        // by process name
        assert_eq!(filter_sockets(&sockets, "nginx", names)[0], 0);
        // by proto / state
        assert_eq!(filter_sockets(&sockets, "udp", names).len(), 1);
        assert_eq!(filter_sockets(&sockets, "listen", names).len(), 2);
        // no filter → everything
        assert_eq!(filter_sockets(&sockets, "", names).len(), 3);
        // no match
        assert!(filter_sockets(&sockets, "99999", names).is_empty());
    }

    #[test]
    fn kill_moves_to_x_and_confirm_cancels() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        let pid = app.selected_pid().unwrap();
        on_key(&mut app, KeyCode::Char('x'));
        assert_eq!(app.confirm_kill, Some(pid));
        on_key(&mut app, KeyCode::Char('n'));
        assert_eq!(app.confirm_kill, None);
    }

    #[test]
    fn port_detail_page_opens_and_closes() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        app.tab = Tab::Ports;
        app.sockets = app.platform.list_sockets().unwrap_or_default();
        app.socket_view = (0..app.sockets.len()).collect();
        if app.sockets.is_empty() {
            return; // minimal environments (a bare container) have no sockets
        }
        // pick a socket with a known owning process if any, else the first
        let sel = app
            .sockets
            .iter()
            .position(|s| s.pid.is_some())
            .unwrap_or(0);
        app.table_state.select(Some(sel));
        let want_port = app.sockets[sel].local_port;

        on_key(&mut app, KeyCode::Enter);
        assert_eq!(app.page, Page::PortDetail);
        assert_eq!(app.port_detail_port, want_port);
        assert!(app
            .port_detail_sockets
            .iter()
            .all(|s| s.local_port == want_port));

        // connections pane: header row + one line per socket
        let lines = app.port_connection_lines();
        assert!(!lines.is_empty());

        // Tab toggles focus between connections and owner
        assert!(app.port_pane_conn);
        on_key(&mut app, KeyCode::Tab);
        assert!(!app.port_pane_conn);

        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Browse);
        assert_eq!(app.tab, Tab::Ports);
    }

    #[test]
    fn container_parse_and_filter() {
        let line = r#"{"Command":"\"pwsh\"","ID":"98974e0e63d6","Image":"mcr.microsoft.com/dotnet/sdk:9.0","Names":"powershell","State":"running","Status":"Up 2 weeks"}"#;
        let c = crate::platform::parse_container_line(line, "docker").unwrap();
        assert_eq!(c.id, "98974e0e63d6");
        assert_eq!(c.name, "powershell");
        assert_eq!(c.state, "running");
        assert_eq!(c.runtime, "docker");

        // Names as array (older docker versions)
        let arr = r#"{"ID":"abc","Names":["web1","web1Alias"],"Image":"nginx","State":"exited","Status":"Exited (0)"}"#;
        let c2 = crate::platform::parse_container_line(arr, "docker").unwrap();
        assert_eq!(c2.name, "web1");
        assert_eq!(c2.state, "exited");

        // garbage line is skipped
        assert!(crate::platform::parse_container_line("not json", "docker").is_none());

        let containers = vec![c, c2];
        assert_eq!(filter_containers(&containers, "powershell"), vec![0]);
        assert_eq!(filter_containers(&containers, "nginx"), vec![1]);
        assert_eq!(filter_containers(&containers, "run"), vec![0]);
        assert_eq!(filter_containers(&containers, ""), vec![0, 1]);
        assert!(filter_containers(&containers, "k8s").is_empty());
    }

    #[test]
    fn container_state_colors() {
        let mk = |state: &str, status: &str| Container {
            runtime: "docker".into(),
            id: "x".into(),
            name: "n".into(),
            image: String::new(),
            command: String::new(),
            state: state.into(),
            status: status.into(),
            ports: String::new(),
            pod: None,
            restarts: None,
            cpu_pct: None,
            mem_used_mb: None,
            mem_total_mb: None,
    throttled_usec: None,
    oom_kills: None,
    compose: None,
        };
        assert_eq!(
            container_state_style(&mk("running", "Up 2 weeks (healthy)")).fg,
            Some(GREEN)
        );
        // plain "Up N" running with no health check: green
        assert_eq!(container_state_style(&mk("running", "Up 3 days")).fg, Some(GREEN));
        // unhealthy wins over running's green
        assert_eq!(
            container_state_style(&mk("running", "Up 2 weeks (unhealthy)")).fg,
            Some(Color::Red)
        );
        assert_eq!(
            container_state_style(&mk("restarting", "Restarting")).fg,
            Some(Color::Yellow)
        );
        assert_eq!(
            container_state_style(&mk("exited", "Exited (0) 2 hours ago")).fg,
            Some(MID)
        );
    }

    #[test]
    fn container_search_filters_view() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        app.tab = Tab::Containers;
        app.containers = vec![
            Container {
                runtime: "docker".into(),
                id: "98974e0e63d6".into(),
                name: "powershell".into(),
                image: "dotnet/sdk:9.0".into(),
                command: String::new(),
                state: "running".into(),
                status: "Up 2 weeks".into(),
                ports: "".into(),
                pod: None,
                restarts: None,
                cpu_pct: None,
                mem_used_mb: None,
                mem_total_mb: None,
        throttled_usec: None,
        oom_kills: None,
        compose: None,
            },
            Container {
                runtime: "docker".into(),
                id: "1daeb5281349".into(),
                name: "stack-akhq-1".into(),
                image: "tchiotludo/akhq".into(),
                command: String::new(),
                state: "running".into(),
                status: "Up 2 weeks".into(),
                ports: "".into(),
                pod: None,
                restarts: None,
                cpu_pct: None,
                mem_used_mb: None,
                mem_total_mb: None,
        throttled_usec: None,
        oom_kills: None,
        compose: None,
            },
        ];
        app.rebuild_container_view();
        assert_eq!(app.container_view.len(), 2);
        app.container_search = "akhq".into();
        app.rebuild_container_view();
        assert_eq!(app.container_view.len(), 1);
        assert_eq!(app.container_view[0], 1);
        app.container_search.clear();
        app.rebuild_container_view();
        assert_eq!(app.container_view.len(), 2);
    }

    #[test]
    fn container_alert_edges_fire_on_death_and_restart_climb() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        let mk = |id: &str, name: &str, state: &str, restarts: Option<u32>| Container {
            runtime: "docker".into(),
            id: id.into(),
            name: name.into(),
            image: String::new(),
            command: String::new(),
            state: state.into(),
            status: "Up".into(),
            ports: String::new(),
            pod: Some("prod/web".into()),
            restarts,
            cpu_pct: None,
            mem_used_mb: None,
            mem_total_mb: None,
    throttled_usec: None,
    oom_kills: None,
    compose: None,
        };
        // first sighting arms quietly — no alerts
        app.container_alert_edges(&[mk("a1", "web", "running", Some(0))], &[]);
        assert!(app.pending_alerts.is_empty());
        assert!(app.container_edges.tracks_container("docker/a1"));

        // restart count climbs: crash-loop alert, latched until the next climb
        app.container_alert_edges(&[mk("a1", "web", "running", Some(3))], &[]);
        assert_eq!(app.pending_alerts.len(), 1, "{:?}", app.pending_alerts);
        assert!(
            app.pending_alerts[0].2.contains("restart count 0 → 3 (crash loop?)")
                && app.pending_alerts[0].2.contains("· pod prod/web"),
            "{:?}",
            app.pending_alerts
        );
        app.pending_alerts.clear();
        app.container_alert_edges(&[mk("a1", "web", "running", Some(3))], &[]);
        assert!(app.pending_alerts.is_empty(), "same count → no re-fire");

        // running → exited: death edge (the inspect fetch here hits no
        // daemon for the fixture id and falls back to the status line)
        app.container_alert_edges(&[mk("a1", "web", "exited", Some(3))], &[]);
        assert_eq!(app.pending_alerts.len(), 1, "{:?}", app.pending_alerts);
        assert!(
            app.pending_alerts[0].1 == "container web"
                && app.pending_alerts[0].2.starts_with("exited — "),
            "{:?}",
            app.pending_alerts
        );
        app.pending_alerts.clear();
        app.container_alert_edges(&[mk("a1", "web", "exited", Some(3))], &[]);
        assert!(app.pending_alerts.is_empty(), "still dead → no re-fire");

        // a removed container leaves the edge detector's memory
        app.container_alert_edges(&[], &[]);
        assert_eq!(app.container_edges.containers_tracked(), 0);
    }

    #[test]
    fn pod_alert_edges_fire_on_waiting_pending_failed_and_climbs() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        let mk = |restarts: u32, phase: &str, waiting: Option<&str>| crate::k8s::Pod {
            key: "prod/web".into(),
            container_ids: Vec::new(),
            phase: Some(phase.into()),
            restarts,
            waiting: waiting.map(str::to_string),
        };
        // first sighting arms quietly
        app.container_alert_edges(&[], &[mk(0, "Running", None)]);
        assert!(app.pending_alerts.is_empty());
        // CrashLoopBackOff appears
        app.container_alert_edges(&[], &[mk(2, "Running", Some("CrashLoopBackOff"))]);
        assert!(app.pending_alerts[0]
            .2
            .contains("containers waiting: CrashLoopBackOff (phase Running)"));
        app.pending_alerts.clear();
        // same waiting reason → latched; restart climb fires independently
        app.container_alert_edges(&[], &[mk(5, "Running", Some("CrashLoopBackOff"))]);
        assert_eq!(app.pending_alerts.len(), 1);
        assert!(app.pending_alerts[0].2.contains("restart count 2 → 5"));
        app.pending_alerts.clear();
        // Running → Pending (rescheduled) fires; the reason gone clears the latch
        app.container_alert_edges(&[], &[mk(5, "Pending", None)]);
        assert_eq!(app.pending_alerts.len(), 1);
        assert!(app.pending_alerts[0].2.contains("went Pending again"));
        app.pending_alerts.clear();
        // Pending → Failed fires once
        app.container_alert_edges(&[], &[mk(5, "Failed", None)]);
        assert_eq!(app.pending_alerts.len(), 1);
        assert!(app.pending_alerts[0].2.contains("phase Failed"));
        app.pending_alerts.clear();
        app.container_alert_edges(&[], &[mk(5, "Failed", None)]);
        assert!(app.pending_alerts.is_empty(), "Failed latches");
        // vanished pods leave the memory
        app.container_alert_edges(&[], &[]);
        assert_eq!(app.container_edges.pods_tracked(), 0);
    }

    #[test]
    fn detail_page_opens_and_closes() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        let pid = app.selected_pid().unwrap();
        on_key(&mut app, KeyCode::Enter);
        assert_eq!(app.page, Page::Detail);
        let r = app.detail_report.as_ref().expect("report fetched");
        assert_eq!(r.matches[0].pid, pid);
        assert!(app.detail_line_count > 1);
        // env pane has either variables or a platform note — never empty
        assert!(!app.env_lines().is_empty());

        // scroll the detail pane, switch to env, scroll it independently
        on_key(&mut app, KeyCode::Char('j'));
        on_key(&mut app, KeyCode::Char('j'));
        assert_eq!(app.detail_scroll, 2);
        on_key(&mut app, KeyCode::Tab);
        assert!(!app.detail_pane);
        on_key(&mut app, KeyCode::Char('j'));
        assert_eq!(app.env_scroll, 1);
        assert_eq!(app.detail_scroll, 2);

        // back to browse
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Browse);
        assert_eq!(app.table_state.selected(), Some(0));
    }

    #[test]
    fn detail_actions_bar_keymap() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        on_key(&mut app, KeyCode::Enter);
        assert_eq!(app.page, Page::Detail);
        assert!(!app.actions_open);

        // a opens the bar; Esc cancels without leaving the page
        on_key(&mut app, KeyCode::Char('a'));
        assert!(app.actions_open);
        on_key(&mut app, KeyCode::Esc);
        assert!(!app.actions_open);
        assert_eq!(app.page, Page::Detail);

        // an action key on a dead pid reports the failure and closes the bar
        // (the report quotes the tool's own stderr, which differs by platform
        // — `kill: (4000000) - No such process`, a bare NotFound when kill
        // isn't installed, taskkill text on Windows — so assert non-empty)
        app.detail_pid = Some(4_000_000); // nothing there
        on_key(&mut app, KeyCode::Char('a'));
        on_key(&mut app, KeyCode::Char('t'));
        assert!(!app.actions_open);
        assert!(!app.status.is_empty(), "no failure report for dead pid");

        // other keys inside the bar just close it without acting
        on_key(&mut app, KeyCode::Char('a'));
        on_key(&mut app, KeyCode::Char('x'));
        assert!(!app.actions_open);

        // q inside the bar cancels instead of leaving the page
        on_key(&mut app, KeyCode::Char('a'));
        on_key(&mut app, KeyCode::Char('q'));
        assert!(!app.actions_open);
        assert_eq!(app.page, Page::Detail);

        // leaving the page resets the bar
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Browse);
        assert!(!app.actions_open);
    }

    #[test]
    fn detail_lines_show_resources_sockets_locks() {
        let mut r = TargetReport::not_found(TargetSpec::Pid { pid: 42 }, String::new());
        r.found = true;
        r.matches = vec![Process {
            pid: 42,
            name: "node".into(),
            cpu: Some(0.1),
            cpu_time_ms: Some(3_723_400),
            mem_kb: Some(1_153_433),
            vm_kb: Some(457_703_424),
            private_kb: Some(1_153_433),
            threads: Some(13),
            io_read_bytes: Some(56_275_619_676),
            io_read_ops: Some(0),
            io_write_bytes: Some(53_164_675_379),
            io_write_ops: Some(1_234),
            gpu_sm_pct: Some(45),
            gpu_mem_mb: Some(1200),
            ..Default::default()
        }];
        let sockets = vec![Socket {
            proto: "tcp".into(),
            local_addr: "127.0.0.1".into(),
            local_port: 18789,
            peer_addr: None,
            peer_port: None,
            state: "LISTEN".into(),
            pid: Some(42),
        }];
        let locks = vec![LockEntry {
            id: "1".into(),
            kind: "POSIX".into(),
            mode: "WRITE".into(),
            pid: Some(42),
            owner: "node".into(),
            path: "/tmp/data.lock".into(),
        }];
        let text: Vec<String> = detail_lines(&r, &sockets, &locks)
            .iter()
            .map(line_to_string)
            .collect();
        assert!(text.iter().any(|l| l == "CPU:"));
        assert!(text.iter().any(|l| l.contains("Average") && l.contains("0.1%")));
        assert!(text.iter().any(|l| l.contains("Time") && l.ends_with("1h 2m")));
        assert!(text.iter().any(|l| l == "Memory:"));
        assert!(text.iter().any(|l| l.contains("Virtual") && l.ends_with("436.5G")));
        assert!(text.iter().any(|l| l.contains("Resident") && l.ends_with("1.1G")));
        assert!(text.iter().any(|l| l.contains("Private") && l.ends_with("1.1G")));
        assert!(text.iter().any(|l| l == "I/O Statistics:"));
        assert!(text.iter().any(|l| l.contains("Read") && l.contains("52.4 GB")));
        assert!(text.iter().any(|l| l.contains("Write") && l.contains("(1234 ops)")));
        assert!(text.iter().any(|l| l.starts_with("Threads") && l.ends_with("13")));
        assert!(text
            .iter()
            .any(|l| l.starts_with("GPU") && l.ends_with("45% SM · 1200 MiB")));
        assert!(text.iter().any(|l| l.contains("127.0.0.1:18789 (TCP | LISTEN)")));
        assert!(text
            .iter()
            .any(|l| l.contains("POSIX WRITE /tmp/data.lock (node)")));

        // established socket renders the peer
        let with_peer = vec![Socket {
            peer_addr: Some("10.0.0.5".into()),
            peer_port: Some(5000),
            ..sockets[0].clone()
        }];
        let text2: Vec<String> = detail_lines(&r, &with_peer, &[])
            .iter()
            .map(line_to_string)
            .collect();
        assert!(text2.iter().any(|l| l.contains("-> 10.0.0.5:5000")));

        // no sockets/locks -> no sections
        let text3: Vec<String> = detail_lines(&r, &[], &[])
            .iter()
            .map(line_to_string)
            .collect();
        assert!(!text3.iter().any(|l| l.starts_with("Sockets:")));
        assert!(!text3.iter().any(|l| l.starts_with("Locks:")));
    }

    #[test]
    fn browse_zoom_toggles_and_esc_unzooms() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        assert_eq!(app.page, Page::Browse);
        assert!(!app.browse_zoom);

        // table focused: z zooms the table over the details panel
        on_key(&mut app, KeyCode::Char('z'));
        assert!(app.browse_zoom);
        assert_eq!(app.focus, Focus::Table);

        // Tab moves focus; the zoom follows it (details pane becomes zoomed)
        on_key(&mut app, KeyCode::Tab);
        assert_eq!(app.focus, Focus::Details);
        assert!(app.browse_zoom);

        // z again unzooms
        on_key(&mut app, KeyCode::Char('z'));
        assert!(!app.browse_zoom);

        // Esc from the zoomed details pane returns to the table first,
        // zoom stays on (focus went to Details after the unzoom above)
        on_key(&mut app, KeyCode::Tab);
        on_key(&mut app, KeyCode::Char('z'));
        on_key(&mut app, KeyCode::Tab);
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.focus, Focus::Table);
        assert!(app.browse_zoom);

        // …then Esc unzooms instead of quitting…
        on_key(&mut app, KeyCode::Esc);
        assert!(!app.browse_zoom);

        // …and the next Esc finally quits
        assert!(!on_key(&mut app, KeyCode::Esc));
    }

    #[test]
    fn detail_zoom_toggles_and_resets() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        on_key(&mut app, KeyCode::Enter);
        assert_eq!(app.page, Page::Detail);
        assert!(!app.detail_zoom);

        // z toggles zoom on and off
        on_key(&mut app, KeyCode::Char('z'));
        assert!(app.detail_zoom);
        on_key(&mut app, KeyCode::Char('z'));
        assert!(!app.detail_zoom);

        // zoomed: Tab moves focus and the env pane becomes the zoomed one
        on_key(&mut app, KeyCode::Char('z'));
        on_key(&mut app, KeyCode::Tab);
        assert!(app.detail_zoom);
        assert!(!app.detail_pane);

        // scrolling still works while zoomed (env pane)
        on_key(&mut app, KeyCode::Char('j'));
        assert_eq!(app.env_scroll, 1);

        // leaving the page works from the zoomed state…
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Browse);

        // …and reopening starts unzoomed
        on_key(&mut app, KeyCode::Enter);
        assert_eq!(app.page, Page::Detail);
        assert!(!app.detail_zoom);
        assert!(app.detail_pane);
    }

    #[test]
    fn detail_env_search_filters_and_esc_clears() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        let pid = app.selected_pid().unwrap();
        on_key(&mut app, KeyCode::Enter);
        assert_eq!(app.page, Page::Detail);

        // only test filtering on platforms that actually collect env
        if app.detail_report.as_ref().unwrap().matches[0].env.is_none() {
            return;
        }

        // '/' enters env search mode
        on_key(&mut app, KeyCode::Char('/'));
        assert!(app.env_search_mode);

        // typing filters the env pane
        on_key(&mut app, KeyCode::Char('Z'));
        on_key(&mut app, KeyCode::Char('Z'));
        assert_eq!(app.env_search, "ZZ");
        let total = app.detail_report.as_ref().unwrap().matches[0]
            .env
            .as_ref()
            .unwrap()
            .len();
        // an env var containing "zz" is unlikely; the pane shows a no-match note
        assert!(app.env_lines().len() <= 1);

        // Enter applies (leaves search mode, keeps the filter)
        on_key(&mut app, KeyCode::Enter);
        assert!(!app.env_search_mode);
        assert_eq!(app.env_search, "ZZ");
        assert!(app.env_lines().len() <= 1);

        // first Esc clears the filter instead of leaving the page
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Detail);
        assert!(app.env_search.is_empty());
        assert_eq!(app.env_lines().len(), total);

        // now Esc leaves the page
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Browse);
        assert_eq!(app.detail_report.as_ref().unwrap().matches[0].pid, pid);
    }

    #[test]
    fn seed_applies_filters_tabs_and_skip_note() {
        let app = TuiApp::new(
            crate::platform::get(),
            Seed {
                name: Some("definitely-not-a-process-name-zz".into()),
                pid: None,
                port: Some(8080),
                container: None,
                file: None,
                skipped: vec!["pid 99".into()],
                events_log: None,
                replayed: Vec::new(),
                notify: false,
                watch: Vec::new(),
                alert_exec: None,
                since: None,
                refresh_secs: None,
                sort: None,
                paused: false,
                alert_cpu: None,
                alert_mem: None,
                alert_fd: None,
                alert_io: None,
                alert_conn: None,
                alert_threads: None,
                alert_net_per_proc: None,
                alert_deviation: None,
                alert_port: Vec::new(),
                alert_repeat: None,
                alert_load: None,
                alert_mem_pct: None,
                alert_count: None,
                alert_disk: None,
                alert_net: None,
                alert_psi: None,
                alert_mem_avail_mb: None,
                alert_swap_pct: None,
                alert_retrans: None,
                alert_nic_drop: None,
                alert_webhook: None,
                alert_silence: Vec::new(),
                alert_new_proc: Vec::new(),
                samples: Vec::new(),
                samples_source: String::new(),
                replay_follow: None,
                notes: Vec::new(),
                reseed: None,
            },
        );
        // port seed wins the tab, filter prefilled, extras reported
        assert_eq!(app.tab, Tab::Ports);
        assert_eq!(app.port_search, "8080");
        assert!(app.status.contains("not shown: pid 99"));
        // the name seed went to the process search untouched by the port tab
        assert_eq!(app.search, "definitely-not-a-process-name-zz");
    }

    #[test]
    fn seed_from_targets_first_of_each_type_wins() {
        let s = Seed::from_targets(
            &["nginx".into(), "redis".into()],
            &[1, 2],
            &[80],
            &[],
            &["web".into()],
        );
        assert_eq!(s.name.as_deref(), Some("nginx"));
        assert_eq!(s.pid, Some(1));
        assert_eq!(s.port, Some(80));
        assert_eq!(s.container.as_deref(), Some("web"));
        assert_eq!(s.skipped, vec!["name redis".to_string(), "pid 2".to_string()]);
    }

    #[test]
    fn mouse_click_tab_row_and_double_click() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        app.tab_rect = Some(Rect { x: 0, y: 0, width: 80, height: 1 });
        app.table_rect = Some(Rect { x: 0, y: 2, width: 80, height: 12 });
        app.detail_rect = None;

        // click in the tab bar: x=12 is inside " 1. Processes "
        on_click(&mut app, 12, 0);
        assert_eq!(app.tab, Tab::Processes);

        // click the first data row (header occupies y == r.y)
        on_click(&mut app, 3, 3);
        assert_eq!(app.focus, Focus::Table);
        assert_eq!(app.table_state.selected(), Some(0));

        // same cell again within the double-click window → detail page
        on_click(&mut app, 3, 3);
        assert_eq!(app.page, Page::Detail);

        // wheel scrolls the focused pane, click on pane B focuses it
        on_wheel(&mut app, 1, 40, 5);
        assert_eq!(app.detail_scroll, 1);
        app.detail_rect = Some(Rect { x: 60, y: 2, width: 20, height: 20 });
        app.table_rect = Some(Rect { x: 0, y: 2, width: 58, height: 20 });
        on_click(&mut app, 65, 5);
        assert!(!app.detail_pane);
        on_click(&mut app, 10, 5);
        assert!(app.detail_pane);

        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Browse);
    }

    #[test]
    fn detail_page_scroll_indicator() {
        assert_eq!(TuiApp::scroll_indicator(0, 5, 12), "");
        assert_eq!(TuiApp::scroll_indicator(0, 30, 12), " ↓");
        assert_eq!(TuiApp::scroll_indicator(10, 30, 12), " ↕");
        assert_eq!(TuiApp::scroll_indicator(25, 30, 12), " ↑");
    }

    #[test]
    fn descendants_of_walks_ppid_links_breadth_first() {
        let mk = |pid: Pid, ppid: Option<Pid>| Process {
            pid,
            ppid,
            name: "p".into(),
            ..Default::default()
        };
        // 1 → 10 → 100 → 1000 → 7 chain, plus an orphan under a dead parent
        let procs = vec![
            mk(7, Some(1_000)),
            mk(10, Some(1)),
            mk(100, Some(10)),
            mk(1000, Some(100)),
            mk(20, Some(999_999)), // orphan: parent not in the set
        ];
        let tree = descendants_of(1, &procs);
        assert_eq!(tree, vec![7, 10, 100, 1000], "BFS covers grandchildren, sorted");
        // root with no children → empty (the "use k instead" case)
        assert!(descendants_of(20, &procs).is_empty());
        // self-parent cycle can't loop forever (seen-set)
        let cyclic = vec![mk(5, Some(5))];
        assert!(descendants_of(5, &cyclic).is_empty());
    }

    #[test]
    fn note_input_flow_discards_on_esc_and_never_touches_config() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        on_key(&mut app, KeyCode::Char('N'));
        assert!(app.note_input.is_some(), "'N' opens the note input");
        for c in "reverse proxy".chars() {
            on_key(&mut app, KeyCode::Char(c));
        }
        assert_eq!(
            app.note_input.as_deref(),
            Some("reverse proxy"),
            "chars land in the input"
        );
        on_key(&mut app, KeyCode::Backspace);
        assert_eq!(app.note_input.as_deref(), Some("reverse prox"));
        on_key(&mut app, KeyCode::Esc);
        assert!(app.note_input.is_none());
        assert_eq!(app.status, "note discarded");
        assert!(app.notes.is_empty(), "Esc never persists");
    }

    #[test]
    fn apply_note_upserts_removes_and_matches_by_identity() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        app.table_state.select(Some(0));
        // clone the selected process so later &mut calls don't fight the borrow
        let sel = app
            .selected_pid()
            .and_then(|pid| app.procs.iter().find(|p| p.pid == pid).cloned())
            .expect("a live selection to annotate");
        let (name, removed) = app.apply_note_in_memory("the init");
        assert!(!removed);
        assert_eq!(name, sel.name);
        assert_eq!(app.notes.len(), 1);
        let key = crate::util::identity_key(&sel);
        assert_eq!(
            app.notes[0],
            format!("{key}|the init"),
            "entry is identity-key|text"
        );
        assert_eq!(app.note_of(&sel).as_deref(), Some("the init"));

        // upsert on the same identity replaces instead of duplicating
        let (_, removed) = app.apply_note_in_memory("rewritten");
        assert!(!removed);
        assert_eq!(app.notes.len(), 1, "same identity → one entry");
        assert_eq!(app.note_of(&sel).as_deref(), Some("rewritten"));
        // note text may itself contain pipes (splitn(4) keeps them)
        app.apply_note_in_memory("a|b|c");
        assert_eq!(app.note_of(&sel).as_deref(), Some("a|b|c"));

        // empty text removes the entry
        let (name, removed) = app.apply_note_in_memory("   ");
        assert!(removed);
        assert_eq!(app.notes.len(), 0, "empty (whitespace) text removes");
        assert_eq!(app.note_of(&sel), None);
        assert!(!name.is_empty());
    }

    #[test]
    fn help_overlay_returns_to_where_it_was_opened() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        on_key(&mut app, KeyCode::Enter); // Detail page
        assert_eq!(app.page, Page::Detail);
        on_key(&mut app, KeyCode::Char('?'));
        assert_eq!(app.page, Page::Help);
        // Esc restores Detail, not Browse (the generic Esc would land there)
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Detail);
        // q closes back to Detail too (same help_prev), then Esc leaves for
        // real and '?' re-opens from Browse
        on_key(&mut app, KeyCode::Char('?'));
        assert_eq!(app.page, Page::Help);
        on_key(&mut app, KeyCode::Char('q'));
        assert_eq!(app.page, Page::Detail);
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Browse);
        on_key(&mut app, KeyCode::Char('?'));
        assert_eq!(app.page, Page::Help);
        on_key(&mut app, KeyCode::Backspace);
        assert_eq!(app.page, Page::Browse);
        // '?' while typing a search stays search ('?' is a legal char there)
        on_key(&mut app, KeyCode::Char('/'));
        on_key(&mut app, KeyCode::Char('?'));
        assert!(app.search_mode);
        assert_eq!(app.page, Page::Browse);
    }

    #[test]
    fn tree_kill_arms_confirms_and_cancels() {
        // inject a fake family so the arm path is deterministic: 99901 →
        // 99902 → 99903, all dead in reality (macOS recycles low pids
        // constantly — pids near the 99999 ceiling almost never come into
        // existence, so confirming signals nothing for real
        let mk = |pid: Pid, ppid: Option<Pid>| Process {
            pid,
            ppid,
            name: "fake".into(),
            ..Default::default()
        };
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        app.procs = vec![mk(99901, None), mk(99902, Some(99901)), mk(99903, Some(99902))];
        app.view = vec![0, 1, 2];
        app.table_state.select(Some(0));
        app.detail_pid = None; // else startup's real selection wins over ours

        on_key(&mut app, KeyCode::Char('a')); // actions bar on the selection
        on_key(&mut app, KeyCode::Char('K'));
        let (root, tree) = app
            .confirm_tree_kill
            .clone()
            .expect("'K' on a process with kin arms the confirmation");
        assert_eq!(root, 99901);
        assert_eq!(tree, vec![99902, 99903], "descendants, root excluded");
        assert!(
            app.status.contains("kill pid 99901 + 2 descendant(s)?"),
            "prompt names root and count: {}",
            app.status
        );

        // any non-y key cancels without signalling
        on_key(&mut app, KeyCode::Char('n'));
        assert!(app.confirm_tree_kill.is_none());
        assert_eq!(app.status, "tree kill cancelled");

        // re-arm and confirm: every pid is dead, so the report counts 0
        on_key(&mut app, KeyCode::Char('a'));
        on_key(&mut app, KeyCode::Char('K'));
        on_key(&mut app, KeyCode::Char('y'));
        assert!(app.confirm_tree_kill.is_none());
        assert_eq!(
            app.status,
            "SIGTERM sent to 0 process(es) in 99901's tree",
            "confirm reports the honest count: {}",
            app.status
        );
    }

    #[test]
    fn alert_fd_fires_after_steady_samples() {
        let mut app = TuiApp::new(
            crate::platform::get(),
            Seed {
                alert_fd: Some(0), // any pid with fds is over a 0 floor
                ..Seed::default()
            },
        );
        app.refresh(); // populate self.procs
        assert!(!app.procs.is_empty());
        // pretend the sweep saw fds on every listed pid
        let pids: Vec<Pid> = app.procs.iter().map(|p| p.pid).collect();
        for pid in &pids {
            app.fd_counts.insert(*pid, 42);
        }
        // ALERT_CYCLES consecutive over samples re-arm → fires on the 5th
        let mut fired = Vec::new();
        for _ in 0..ALERT_CYCLES {
            fired = app
                .alert_picks()
                .into_iter()
                .map(|(pid, _, msg, _)| (pid, msg))
                .collect();
        }
        assert!(
            fired.iter().any(|(_, msg)| msg.contains("open fds above 0")),
            "fd alert fired after {ALERT_CYCLES} cycles: {fired:?}"
        );
        // and the event ring got it via refresh-driven picks? (alert_picks is
        // the shared funnel — the caller routes to events) — just check the
        // streak re-arms: a subsequent cycle stays quiet
        assert!(app.alert_picks().is_empty(), "firing latches until re-arm");
    }

    #[test]
    fn diff_page_selects_jumps_and_reports_gone() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        let Some(live) = app.procs.first().cloned() else {
            return; // empty machine table — nothing to jump to
        };
        app.diff_entries = vec![
            crate::snapshot::DiffEntry {
                kind: "new",
                pid: live.pid,
                name: live.name.clone(),
                detail: "started".into(),
            },
            crate::snapshot::DiffEntry {
                kind: "gone",
                pid: -1,
                name: "ghost".into(),
                detail: "exited".into(),
            },
        ];
        app.diff_source = "/tmp/snap.json".into();
        app.page = Page::Diff;
        app.diff_sel = 0;

        // selection movement, clamped at both ends
        on_key(&mut app, KeyCode::Char('j'));
        assert_eq!(app.diff_sel, 1);
        on_key(&mut app, KeyCode::Char('j'));
        assert_eq!(app.diff_sel, 1, "clamped at the last entry");
        on_key(&mut app, KeyCode::Char('G'));
        assert_eq!(app.diff_sel, 1);
        on_key(&mut app, KeyCode::Char('g'));
        assert_eq!(app.diff_sel, 0);

        // the page text carries the counts and the compared snapshot
        let text = app
            .diff_page_lines()
            .iter()
            .map(line_to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("1 new"), "{text}");
        assert!(text.contains("1 gone"), "{text}");
        assert!(text.contains("/tmp/snap.json"), "{text}");

        // Enter on a live pid opens its detail page
        on_key(&mut app, KeyCode::Enter);
        assert_eq!(app.page, Page::Detail);
        assert_eq!(app.detail_pid, Some(live.pid));

        // back out, then Enter on the snapshot-only pid reports and stays
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Browse);
        app.page = Page::Diff;
        app.diff_sel = 1;
        on_key(&mut app, KeyCode::Enter);
        assert_eq!(app.page, Page::Diff);
        assert!(
            app.status.contains("only exists in the snapshot"),
            "{}",
            app.status
        );

        // Esc leaves the diff page
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Browse);
    }

    #[test]
    fn samples_page_browses_cursor_series_and_series_wrap() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        let pt = |at: i64, cpu: Option<f64>| crate::SysPoint {
            at,
            cpu,
            mem_pct: Some(40.0),
            load1: Some(1.0),
            procs: 200,
            net_bps: Some(1_048_576.0),
        };
        app.samples = vec![pt(1_700_000_100, Some(10.0)), pt(1_700_000_160, Some(20.0))];
        app.samples_source = "/tmp/rec.csv".into();
        app.samples_cursor = 1;
        app.page = Page::Samples;

        // cursor movement with both key sets, clamped
        on_key(&mut app, KeyCode::Left);
        assert_eq!(app.samples_cursor, 0);
        on_key(&mut app, KeyCode::Left);
        assert_eq!(app.samples_cursor, 0, "clamped at the first sample");
        on_key(&mut app, KeyCode::Right);
        on_key(&mut app, KeyCode::Right);
        assert_eq!(app.samples_cursor, 1, "clamped at the last sample");
        on_key(&mut app, KeyCode::Char('g'));
        assert_eq!(app.samples_cursor, 0);
        on_key(&mut app, KeyCode::Char('G'));
        assert_eq!(app.samples_cursor, 1);

        // series cycling wraps over the five chartable series
        app.samples_series = 4;
        on_key(&mut app, KeyCode::Down);
        assert_eq!(app.samples_series % SAMPLE_SERIES, 0);
        on_key(&mut app, KeyCode::Char('k'));
        assert_eq!(app.samples_series % SAMPLE_SERIES, 4);

        // the page text: source, count, series label and the cursor readout
        let text = app
            .samples_page_lines(80)
            .iter()
            .map(line_to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("/tmp/rec.csv"), "{text}");
        assert!(text.contains("2 samples"), "{text}");
        assert!(text.contains("processes"), "series 4 % 5 is the process count: {text}");
        assert!(text.contains("procs 200"), "{text}");

        // switching to the cpu series shows its label and cursor value
        app.samples_series = 0;
        let text = app
            .samples_page_lines(80)
            .iter()
            .map(line_to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("cpu %"), "{text}");
        assert!(text.contains("20.0%"), "cursor sits on the 2nd sample: {text}");

        // the sparkline row: peaks survive downsampling, cursor maps in
        let values: Vec<Option<f64>> = (0..100).map(|i| Some(i as f64)).collect();
        let (cells, cur) = spark_row(&values, 20, 99);
        assert_eq!(cells.len(), 20);
        assert_eq!(cur, Some(19), "cursor at the last sample → last cell");
        assert_eq!(cells.iter().rfind(|c| **c == '█'), Some(&'█'), "the max lands at the top block");
        let (cells, _) = spark_row(&[None, None], 10, 0);
        assert!(cells.iter().all(|c| *c == ' '), "gaps render as spaces");

        // empty page says how to load a file
        app.samples.clear();
        let text = app
            .samples_page_lines(80)
            .iter()
            .map(line_to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("--samples FILE"), "{text}");

        // Esc leaves the samples page
        on_key(&mut app, KeyCode::Esc);
        assert_eq!(app.page, Page::Browse);
    }

    #[test]
    fn conn_alerts_count_established_sockets_per_pid() {
        let sock = |pid: Option<i32>, state: &str| crate::model::Socket {
            proto: "tcp".into(),
            local_addr: "127.0.0.1".into(),
            local_port: 0,
            peer_addr: None,
            peer_port: None,
            state: state.into(),
            pid,
        };
        let sockets = vec![
            sock(Some(9), "ESTABLISHED"),
            sock(Some(9), "ESTABLISHED"),
            sock(Some(9), "ESTABLISHED"),
            sock(Some(9), "LISTEN"), // not established
            sock(None, "ESTABLISHED"), // no owner → uncounted
            sock(Some(8), "ESTABLISHED"),
        ];
        let counts = established_per_pid(&sockets);
        assert_eq!(counts.get(&9), Some(&3));
        assert_eq!(counts.get(&8), Some(&1));
        assert!(!counts.contains_key(&7));

        // new() runs an initial refresh(), so on a low-pid host the table
        // already holds a real pid 9 (e.g. kworker) — clear it or the
        // pushed row below shares pid 9's alert track and doubles every
        // streak increment
        let mut app = TuiApp::new(
            crate::platform::get(),
            Seed {
                alert_conn: Some(2),
                ..Seed::default()
            },
        );
        app.procs.clear();
        app.procs.push(crate::model::Process {
            pid: 9,
            name: "chatty".into(),
            ..Default::default()
        });
        app.conn_counts = counts;
        for _ in 0..ALERT_CYCLES - 1 {
            let picks = app.alert_picks();
            assert!(
                picks.is_empty(),
                "no fire before the streak (cycles={ALERT_CYCLES}): {picks:?}"
            );
        }
        let fired = app.alert_picks();
        assert_eq!(fired.len(), 1, "{fired:?}");
        assert_eq!(fired[0].0, 9);
        assert!(
            fired[0].2.contains("3 established connection(s) above 2"),
            "{}",
            fired[0].2
        );
        assert!(app.alert_picks().is_empty(), "latches until re-arm");
    }
}
