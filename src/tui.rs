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

#[derive(Clone, Copy, PartialEq, Debug)]
enum Tab {
    Processes,
    Ports,
    Containers,
    Locks,
    Events,
}

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Processes => "1. Processes",
            Tab::Ports => "2. Ports",
            Tab::Containers => "3. Containers",
            Tab::Locks => "4. Locks",
            Tab::Events => "5. Events",
        }
    }
    fn from_digit(c: char) -> Option<Self> {
        match c {
            '1' => Some(Tab::Processes),
            '2' => Some(Tab::Ports),
            '3' => Some(Tab::Containers),
            '4' => Some(Tab::Locks),
            '5' => Some(Tab::Events),
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
    Started,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Focus {
    Table,
    Details,
}

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
    /// Containers-tab sort column ('i/n/r/g/s', Go witr parity); None =
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
    death_rx: Option<std::sync::mpsc::Receiver<(Pid, std::result::Result<Vec<String>, String>)>>,
    /// --events-log sink: every event the sampler generates is appended as
    /// one JSON line (single writer — the event loop thread)
    events_log: Option<std::fs::File>,
    /// desktop notifications enabled (--notify, '!' toggles)
    notify: bool,
    /// process name → restart count seen this session; a name that has
    /// restarted ≥2 times is a crash looper — its plain exits notify too
    restart_tally: HashMap<String, u32>,
    /// container enumeration runs on a background thread (a hung runtime
    /// CLI must not freeze the UI); results arrive via this channel
    containers_loading: bool,
    /// first enumeration finished — afterwards refreshes keep the stale
    /// table visible instead of flashing the loading placeholder
    containers_loaded: bool,
    containers_rx: Option<std::sync::mpsc::Receiver<Vec<Container>>>,
    /// sampling history: instantaneous cpu, sparklines, restart detection
    hist: crate::history::History,
    /// open files fetched when the full detail page opens
    open_files: Option<Vec<String>>,
    last_refresh: Instant,
    /// 'P' freezes sampling: no refresh, no event deltas, no pings
    paused: bool,
    status: String,
    confirm_kill: Option<Pid>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Page {
    Browse,
    Detail,
    PortDetail,
    ContainerDetail,
    Logs,
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

/// Containers-tab sort columns — keys i/n/r/g/s, matching the Go witr.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ContainerSort {
    Id,
    Name,
    Runtime,
    Image,
    Status,
}

/// Events-tab sort columns — keys t/e/p/n (Time defaults newest-first).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EventSort {
    Time,
    Kind,
    Pid,
    Process,
}

const DEBOUNCE: Duration = Duration::from_millis(500);
const DOUBLE_CLICK: Duration = Duration::from_millis(400);

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
    /// --notify: desktop notifications on restarts / repeated exits
    /// ('!' toggles live inside the TUI)
    pub notify: bool,
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
}

impl Tab {
    fn next(self) -> Self {
        match self {
            Tab::Processes => Tab::Ports,
            Tab::Ports => Tab::Containers,
            Tab::Containers => Tab::Locks,
            Tab::Locks => Tab::Events,
            Tab::Events => Tab::Processes,
        }
    }
    fn prev(self) -> Self {
        match self {
            Tab::Processes => Tab::Events,
            Tab::Ports => Tab::Processes,
            Tab::Containers => Tab::Ports,
            Tab::Locks => Tab::Containers,
            Tab::Events => Tab::Locks,
        }
    }
}

/// Quitting the TUI kills a running `logs -f` child so the runtime CLI
/// doesn't outlive the UI.
impl Drop for TuiApp {
    fn drop(&mut self) {
        self.stop_logs_follow();
    }
}

impl TuiApp {
    fn new(platform: Box<dyn Platform>, seed: Seed) -> Self {
        let locks_supported = matches!(platform.name(), "linux" | "macos");
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
            notify: false,
            restart_tally: HashMap::new(),
            containers_loading: false,
            containers_loaded: false,
            containers_rx: None,
            hist: crate::history::History::new(),
            open_files: None,
            last_refresh: Instant::now() - REFRESH, // force first refresh
            paused: false,
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
        app.notify = seed.notify;
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

    fn refresh(&mut self) {
        if let Ok(mut p) = self.platform.list_processes() {
            crate::gpu::enrich(&mut p);
            self.platform.enrich_listing(&mut p);
            self.procs = p;
            let fresh = self.hist.update(&self.procs);
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
        }
        if self.tab == Tab::Ports {
            self.load_sockets();
            self.rebuild_socket_view();
        }
        if self.tab == Tab::Containers {
            self.request_containers();
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
            // adds ~1s when a cluster is reachable)
            crate::k8s::annotate(&mut cs);
            let _ = tx.send(cs);
        });
        self.containers_rx = Some(rx);
    }

    /// Pick up finished background enumeration, if any.
    fn poll_containers(&mut self) {
        if !self.containers_loading {
            return;
        }
        let arrived = self.containers_rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some(cs) = arrived {
            self.containers = cs;
            self.containers_loading = false;
            self.containers_loaded = true;
            self.containers_rx = None;
            self.rebuild_container_view();
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

    /// 'F' on the Logs page: stream the container's logs live (`runtime
    /// logs -f`). Toggles — pressing F again (or leaving the page) stops
    /// the stream and kills the child runtime CLI.
    fn toggle_logs_follow(&mut self) {
        if self.follow_child.is_some() {
            self.stop_logs_follow();
            self.status = "follow stopped".into();
            return;
        }
        let Some(src) = self.logs_src.clone() else {
            self.status = "no log source for this view".into();
            return;
        };
        // only container sources stream; journald/unified log have no -f
        // equivalent wired up here
        let crate::logs::LogSource::Container { runtime, ref_ } = src else {
            self.status = "live follow works for container logs only".into();
            return;
        };
        if self.logs_rx.is_some() {
            self.status = "still fetching the initial tail… try again in a moment".into();
            return;
        }
        match std::process::Command::new(&runtime)
            .args(["logs", "-f", "--tail", "100", &ref_])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                self.logs_lines.clear();
                self.logs_scroll = 0;
                self.follow_prev_len = 0;
                let (tx, rx) = std::sync::mpsc::channel();
                // both pipes carry container output (the runtime CLI writes
                // the container's stderr down its own)
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
                self.status = format!("following {runtime} logs — F/Esc to stop");
            }
            Err(e) => self.status = format!("follow: {e}"),
        }
    }

    /// Kill the streaming child (page exit, toggle off, TUI shutdown).
    fn stop_logs_follow(&mut self) {
        if let Some(mut child) = self.follow_child.take() {
            let _ = child.kill();
            let _ = child.wait();
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
        let procs = &self.procs;
        let mut idx: Vec<usize> = procs
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                needle.is_empty()
                    || p.name.to_lowercase().contains(&needle)
                    || p.user.as_deref().unwrap_or("").to_lowercase().contains(&needle)
                    || p.pid.to_string().contains(&needle)
            })
            .map(|(i, _)| i)
            .collect();

        let key = self.sort_key;
        let desc = self.sort_desc;
        // snapshot the display-cpu (instantaneous with lifetime fallback)
        // so the sort comparator doesn't fight the borrow checker
        let cpu_disp: HashMap<Pid, f64> = procs
            .iter()
            .map(|p| (p.pid, self.hist.display_cpu(p).unwrap_or(-1.0)))
            .collect();
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
                SortKey::Started => x
                    .started
                    .unwrap_or(i64::MAX)
                    .cmp(&y.started.unwrap_or(i64::MAX)),
            };
            if desc { ord.reverse() } else { ord }
        });
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
    }

    fn selected_pid(&self) -> Option<Pid> {
        self.table_state
            .selected()
            .and_then(|i| self.view.get(i))
            .and_then(|&i| self.procs.get(i))
            .map(|p| p.pid)
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
                let full_socks = self.platform.list_all_sockets().unwrap_or_default();
                let socks: Vec<Socket> =
                    full_socks.iter().filter(|s| s.pid == Some(pid)).cloned().collect();
                let locks = r.locks.clone();
                let mut lines = detail_lines(&r, &socks, &locks);
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
                    let sig_line = b.signature.clone().unwrap_or_else(|| {
                        "no signature infrastructure on this platform".into()
                    });
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
                self.detail_report = Some(r);
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
fn send_signal(pid: Pid, sig: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let out = std::process::Command::new("kill")
            .args(["-s", sig, &pid.to_string()])
            .output()?;
        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                msg.trim().to_string(),
            ));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        match sig {
            "TERM" => {
                std::process::Command::new("taskkill")
                    .args(["/PID", &pid.to_string()])
                    .output()?;
                Ok(())
            }
            "KILL" => {
                std::process::Command::new("taskkill")
                    .args(["/F", "/PID", &pid.to_string()])
                    .output()?;
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
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                text.trim().to_string(),
            ))
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
                    .contains(&needle)
                || s.local_addr.to_lowercase().contains(&needle)
                || s.proto.to_lowercase().contains(&needle)
                || s.state.to_lowercase().contains(&needle)
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
}

/// Accumulated overview data per (port, owner): protocols seen, and the
/// distinct local addr:port endpoints the port is reachable on.
type PortGroup = (Vec<String>, std::collections::HashSet<String>);

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
        e.1.insert(format!("{}:{}", s.local_addr, s.local_port));
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
            PortOverviewRow {
                port,
                pid,
                name,
                user,
                protos: protos.join("/"),
                addrs: addrs.len(),
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

/// Filter containers: substring match over name, image, id, runtime, state.
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
fn fmt_bytes(b: u64) -> String {
    if b >= 1024 * 1024 * 1024 {
        format!("{:.1}G", b as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if b >= 1024 * 1024 {
        format!("{:.1}M", b as f64 / 1024.0 / 1024.0)
    } else if b >= 1024 {
        format!("{:.0}K", b as f64 / 1024.0)
    } else {
        format!("{b}B")
    }
}

/// Per-second rate ("12K/s") for the IO column (read+write combined).
fn fmt_rate(bps: f64) -> String {
    if bps < 0.5 {
        return "0B/s".into();
    }
    format!("{}/s", fmt_bytes(bps as u64))
}

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
    if platform_name == "macos" {
        crate::logs::LogSource::UnifiedLog {
            name: name.to_string(),
        }
    } else {
        crate::logs::LogSource::Journald { pid }
    }
}

/// The desktop-notification command for a given OS — macOS speaks
/// osascript, Linux notify-send, everything else has no story yet.
/// Split from the fire step so tests can assert the exact argv.
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
        _ => None,
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
    for t in [Tab::Processes, Tab::Ports, Tab::Containers, Tab::Locks, Tab::Events] {
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
                "  Mode: Actions on pid {} — [k]ill [t]erm [p]ause [r]esume [n]ice (Esc: cancel)",
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
        header.push(Cell::from("IO"));
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
            let mut cells = vec![
                Cell::from(p.pid.to_string()),
                Cell::from(p.user.clone().unwrap_or_else(|| "-".into())),
                Cell::from(name),
                Cell::from(cpu.map(|c| format!("{:.1}", c)).unwrap_or_else(|| "-".into())),
                Cell::from(app.hist.spark(p.pid).unwrap_or("").to_string()),
                Cell::from(fmt_mem(p.mem_kb)),
            ];
            if has_io {
                let cell = app
                    .hist
                    .io_rate_of(p.pid)
                    .map(|(r, w)| fmt_rate(r + w))
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
    let header = Row::new(["Port", "Proto(s)", "Process", "PID", "User", "Addrs"])
        .style(Style::new().fg(ACCENT).bold());
    let rows: Vec<Row> = app
        .port_overview_view
        .iter()
        .map(|r| {
            Row::new([
                Cell::from(r.port.to_string()),
                Cell::from(r.protos.clone()),
                Cell::from(r.name.clone()),
                Cell::from(r.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into())),
                Cell::from(r.user.clone()),
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

fn containers_table(app: &mut TuiApp, area: ratatui::prelude::Rect, f: &mut Frame<'_>) {
    // Pod column only when k8s attribution actually produced something —
    // it's dead width on plain-docker hosts.
    let has_pod = app.containers.iter().any(|c| c.pod.is_some());
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
                _ => "restarted",
            };
            Row::new([
                Cell::from(fmt_age_short(Some(e.at_unix))),
                Cell::from(kind.to_string()),
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

    let container_src = matches!(
        app.logs_src,
        Some(crate::logs::LogSource::Container { .. })
    );
    let mut footer = if container_src && app.follow_child.is_some() {
        "F: Stop Follow | j/k/d/u/g/G/b-f: Scroll | Esc/q: Back | c: Copy".to_string()
    } else if container_src {
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

fn ui(app: &mut TuiApp, f: &mut Frame<'_>) {
    match app.page {
        Page::Detail => ui_detail_page(app, f),
        Page::PortDetail => ui_port_detail_page(app, f),
        Page::ContainerDetail => ui_container_detail_page(app, f),
        Page::Logs => ui_logs_page(app, f),
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
                    ..border::PLAIN
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
    }

    let sep = Line::from(styled(
        Style::new().fg(GRAY),
        format!(" {}", "─".repeat(v[8].width.saturating_sub(2) as usize)),
    ));
    f.render_widget(Paragraph::new(sep), v[7]);

    let total = match app.tab {
        Tab::Processes => app.view.len().to_string(),
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
    };
    let mut footer = match app.tab {
        Tab::Processes => format!(
            "Total: {} | Enter: Detail | a: Actions | /: Search | z: Zoom | T: Tree{} | !: Notify{} | P: Pause | p/n/u/c/m/t: Sort | j-k/g-G: Move | h-l: Tab | x: Kill | r: Refresh | q: Quit",
            total,
            if app.tree_mode { " (on)" } else { "" },
            if app.notify { " (on)" } else { "" }
        ),
        Tab::Ports => format!(
            "Total: {} | Enter: Detail | o: Overview{} | a: All States | p/t/n/s: Sort | /: Search | h-l: Tab | r: Refresh | q: Quit",
            total,
            if app.ports_overview { " (on)" } else { "" }
        ),
        Tab::Containers => format!(
            "Total: {} | Enter: Detail | i/n/r/g/s: Sort | /: Search | h-l: Tab | r: Refresh | q: Quit",
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
            "Total: {} | Enter: Open Process | l: Logs | t/e/p/n: Sort | /: Search | j-k/g-G: Move | h-l: Tab | r: Refresh | q: Quit",
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
    if app.view.is_empty() {
        return;
    }
    let len = app.view.len() as i32;
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
    if app.view.is_empty() {
        return;
    }
    let next = if first { 0 } else { app.view.len() - 1 };
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
        (Page::Browse, _, _, _) => None,
    }
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
    if row < app.view.len() {
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
    for t in [Tab::Processes, Tab::Ports, Tab::Containers, Tab::Locks, Tab::Events] {
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

    // Renice value input ('n' in the actions bar): free-form −20…19
    if app.renice_input.is_some() {
        let pid = app.detail_pid.or_else(|| app.selected_pid());
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
                && matches!(c.to_ascii_lowercase(), 'i' | 'n' | 'r' | 'g' | 's') =>
        {
            let col = match c.to_ascii_lowercase() {
                'i' => ContainerSort::Id,
                'n' => ContainerSort::Name,
                'r' => ContainerSort::Runtime,
                'g' => ContainerSort::Image,
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
        // ---- Processes tab: 'a' opens the actions bar on the selection ----
        KeyCode::Char('a') if app.tab == Tab::Processes && app.focus == Focus::Table => {
            if app.selected_pid().is_some() {
                app.actions_open = true;
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
    if !app.paused && app.last_refresh.elapsed() >= REFRESH {
        app.refresh();
    }
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal, seed: Seed) -> Result<()> {
    let mut app = TuiApp::new(crate::platform::get(), seed);
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
        let (o2, _) = tree_order(&cyc, &vec![0, 1]);
        assert_eq!(o2.len(), 2, "cycle terminates with every row present");
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
        // non-container source: F explains itself and spawns nothing
        app.logs_src = Some(crate::logs::LogSource::Journald { pid: 1 });
        app.toggle_logs_follow();
        assert!(app.follow_child.is_none());
        assert!(app.status.contains("container logs only"));
        // no source at all
        app.logs_src = None;
        app.toggle_logs_follow();
        assert!(app.follow_child.is_none());
        assert!(app.status.contains("no log source"));
        // stop without a running stream is a safe no-op
        app.stop_logs_follow();
        assert!(app.follow_rx.is_none());
    }

    #[test]
    fn h_l_switch_tabs() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
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
        // digit jump still lands on Events
        on_key(&mut app, KeyCode::Char('5'));
        assert_eq!(app.tab, Tab::Events);
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
        // elsewhere: nothing to call
        assert!(notify_command_for("windows", "witr-rs", "x").is_none());
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
        assert!(lines.len() >= 1);

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
    fn detail_page_opens_and_closes() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        let pid = app.selected_pid().unwrap();
        on_key(&mut app, KeyCode::Enter);
        assert_eq!(app.page, Page::Detail);
        let r = app.detail_report.as_ref().expect("report fetched");
        assert_eq!(r.matches[0].pid, pid);
        assert!(app.detail_line_count > 1);
        // env pane has either variables or a platform note — never empty
        assert!(app.env_lines().len() >= 1);

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
        app.detail_pid = Some(4_000_000); // nothing there
        on_key(&mut app, KeyCode::Char('a'));
        on_key(&mut app, KeyCode::Char('t'));
        assert!(!app.actions_open);
        assert!(app.status.contains("4000000"), "status: {}", app.status);

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
}
