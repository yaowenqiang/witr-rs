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
}

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Processes => "1. Processes",
            Tab::Ports => "2. Ports",
            Tab::Containers => "3. Containers",
            Tab::Locks => "4. Locks",
        }
    }
    fn from_digit(c: char) -> Option<Self> {
        match c {
            '1' => Some(Tab::Processes),
            '2' => Some(Tab::Ports),
            '3' => Some(Tab::Containers),
            '4' => Some(Tab::Locks),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
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
    status: String,
    confirm_kill: Option<Pid>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Page {
    Browse,
    Detail,
    PortDetail,
    ContainerDetail,
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
            Tab::Locks => Tab::Processes,
        }
    }
    fn prev(self) -> Self {
        match self {
            Tab::Processes => Tab::Locks,
            Tab::Ports => Tab::Processes,
            Tab::Containers => Tab::Ports,
            Tab::Locks => Tab::Containers,
        }
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
            containers_loading: false,
            containers_loaded: false,
            containers_rx: None,
            hist: crate::history::History::new(),
            open_files: None,
            last_refresh: Instant::now() - REFRESH, // force first refresh
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
        if let Ok(p) = self.platform.list_processes() {
            self.procs = p;
            self.hist.update(&self.procs);
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
            let cs = crate::platform::enumerate_containers();
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
        self.view = idx;
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
        let report = pipeline::run(
            self.platform.as_ref(),
            vec![TargetSpec::Pid { pid }],
            &pipeline::Options::default(),
        )
        .into_iter()
        .next();
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
            // usage from one platform probe (one lsof scan on macOS)
            &pipeline::Options { want_env: true, deep_files: true, ..Default::default() },
        )
        .into_iter()
        .next();
        match report {
            Some(r) if r.found => {
                // rebuild the pane content for THIS process (detail_lines is
                // shared with the browse side panel, which may still hold the
                // previously selected process); the live socket list is not
                // part of a Pid report, so filter a fresh snapshot
                let socks: Vec<Socket> = self
                    .platform
                    .list_sockets()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|s| s.pid == Some(pid))
                    .collect();
                let locks = r.locks.clone();
                let mut lines = detail_lines(&r, &socks, &locks);
                push_history_lines(&mut lines, &self.hist, pid);
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
        let c = c.clone();
        // process mapping works on Linux (cgroup match); elsewhere empty
        self.container_procs = self.platform.container_processes(&c.id);
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
    for t in [Tab::Processes, Tab::Ports, Tab::Containers, Tab::Locks] {
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
    let header = Row::new([
        Cell::from(format!("PID{}", arrow(k, SortKey::Pid, d))),
        Cell::from(format!("User{}", arrow(k, SortKey::User, d))),
        Cell::from(format!("Name{}", arrow(k, SortKey::Name, d))),
        Cell::from(format!("CPU%{}", arrow(k, SortKey::Cpu, d))),
        Cell::from("Trend"),
        Cell::from(format!("Mem{}", arrow(k, SortKey::Mem, d))),
        Cell::from("Rst"),
        Cell::from(format!("Age{}", arrow(k, SortKey::Started, d))),
    ])
    .style(Style::new().fg(ACCENT).bold());

    let rows: Vec<Row> = app
        .view
        .iter()
        .filter_map(|&i| app.procs.get(i))
        .map(|p| {
            let cpu = app.hist.display_cpu(p);
            let rst = app.hist.total_restarts(p.pid);
            Row::new([
                Cell::from(p.pid.to_string()),
                Cell::from(p.user.clone().unwrap_or_else(|| "-".into())),
                Cell::from(p.name.clone()),
                Cell::from(cpu.map(|c| format!("{:.1}", c)).unwrap_or_else(|| "-".into())),
                Cell::from(app.hist.spark(p.pid).unwrap_or("").to_string()),
                Cell::from(fmt_mem(p.mem_kb)),
                Cell::from(if rst > 0 { rst.to_string() } else { String::new() }),
                Cell::from(fmt_age_short(p.started)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(7),
        Constraint::Length(12),
        Constraint::Min(18),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(4),
        Constraint::Length(9),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(2)
        .row_highlight_style(Style::new().bg(PURPLE).fg(Color::White).bold());
    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn ports_table(app: &mut TuiApp, area: ratatui::prelude::Rect, f: &mut Frame<'_>) {
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

fn containers_table(app: &mut TuiApp, area: ratatui::prelude::Rect, f: &mut Frame<'_>) {
    let header = Row::new(["Runtime", "ID", "State", "Status", "Image", "Name"])
        .style(Style::new().fg(ACCENT).bold());
    let rows: Vec<Row> = app
        .container_view
        .iter()
        .filter_map(|&i| app.containers.get(i))
        .map(|c| {
            Row::new([
                Cell::from(c.runtime.clone()),
                Cell::from(c.id.chars().take(12).collect::<String>()),
                Cell::from(c.state.clone()),
                Cell::from(c.status.clone()),
                Cell::from(c.image.clone()),
                Cell::from(c.name.clone()),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(8),
        Constraint::Length(13),
        Constraint::Length(10),
        Constraint::Length(24),
        Constraint::Min(20),
        Constraint::Min(18),
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
        "j/k/d/u/g/G/b-f: Scroll | Tab: Focus | z: Zoom | /: Search Env | a: Actions | Esc/q: Back | c: Copy"
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

    let (name, state) = match &app.container_detail {
        Some(c) => (c.name.clone(), c.state.clone()),
        None => ("-".into(), "-".into()),
    };
    let state_style = if state == "running" {
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

    let mut footer = "j/k/d/u/g/G/b-f: Scroll | Tab: Focus | Esc/q: Back | c: Copy".to_string();
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
    }

    let sep = Line::from(styled(
        Style::new().fg(GRAY),
        format!(" {}", "─".repeat(v[8].width.saturating_sub(2) as usize)),
    ));
    f.render_widget(Paragraph::new(sep), v[7]);

    let total = match app.tab {
        Tab::Processes => app.view.len().to_string(),
        Tab::Ports => {
            if app.port_search.is_empty() {
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
    };
    let mut footer = match app.tab {
        Tab::Processes => format!(
            "Total: {} | Enter: Detail | a: Actions | /: Search | z: Zoom | p/n/u/c/m/t: Sort | j-k/g-G: Move | h-l: Tab | x: Kill | r: Refresh | q: Quit",
            total
        ),
        Tab::Ports => format!(
            "Total: {} | Enter: Detail | a: All States | p/t/n/s: Sort | /: Search | h-l: Tab | r: Refresh | q: Quit",
            total
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
    };
    footer = format!("witr-rs v{} · {}", env!("CARGO_PKG_VERSION"), footer);
    if !app.status.is_empty() {
        footer.push_str(&format!("  ·  {}", app.status));
    }
    f.render_widget(Paragraph::new(Line::from(styled(Style::new().fg(MID), footer))), v[8]);
}

fn move_selection(app: &mut TuiApp, delta: i32) {
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
    if app.tab == Tab::Locks {
        if app.lock_view.is_empty() {
            return;
        }
        let next = if first { 0 } else { app.lock_view.len() - 1 };
        app.lock_state.select(Some(next));
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
        (Page::Browse, _, _, _) => None,
    }
}

/// Open the detail view for whatever the current tab's cursor is on — the
/// Enter key and a table double-click share this.
fn open_selection(app: &mut TuiApp) {
    match app.tab {
        Tab::Processes => app.open_detail_page(),
        Tab::Ports => app.open_port_detail_page(),
        Tab::Containers => app.open_container_detail_page(),
        // "from the lock back to the process": jump straight into the
        // holder's detail page
        Tab::Locks => {
            if let Some(pid) = app.selected_lock_pid() {
                app.open_detail_page_for(pid);
            }
        }
    }
}

/// Move the tab's table cursor to an absolute row (used by mouse clicks).
fn select_row(app: &mut TuiApp, row: usize) {
    if app.tab == Tab::Locks {
        if row < app.lock_view.len() {
            app.lock_state.select(Some(row));
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
    if app.tab == Tab::Locks {
        app.lock_state.offset()
    } else {
        app.table_state.offset()
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
    for t in [Tab::Processes, Tab::Ports, Tab::Containers, Tab::Locks] {
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
                    Page::Browse => {}
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
                    Page::Browse => {}
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
    let len = if app.tab == Tab::Locks {
        app.lock_view.len()
    } else {
        app.view.len()
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
            app.page = Page::Browse;
            app.actions_open = false;
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
                Page::Browse => {}
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

        // ---- cursor movement ----
        KeyCode::Down if app.focus == Focus::Table => move_selection(app, 1),
        KeyCode::Up if app.focus == Focus::Table => move_selection(app, -1),
        KeyCode::Char('j') if app.focus == Focus::Table => move_selection(app, 1),
        KeyCode::Char('k') if app.focus == Focus::Table => move_selection(app, -1),
        KeyCode::Char('g') if app.focus == Focus::Table => select_edge(app, true),
        KeyCode::Char('G') if app.focus == Focus::Table => select_edge(app, false),
        // ---- Ports tab: 'a' widens to every socket state, p/t/n/s sort
        // (Go witr parity) ----
        KeyCode::Char('a') if app.tab == Tab::Ports && app.focus == Focus::Table => {
            app.ports_show_all = !app.ports_show_all;
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
        KeyCode::PageDown if app.focus == Focus::Table => move_selection(app, 20),
        KeyCode::PageUp if app.focus == Focus::Table => move_selection(app, -20),
        KeyCode::Char('f') if app.focus == Focus::Table => move_selection(app, 20),
        KeyCode::Char(' ') if app.focus == Focus::Table => move_selection(app, 20),
        KeyCode::Char('b') if app.focus == Focus::Table => move_selection(app, -20),

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
            } else {
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
        if app.last_refresh.elapsed() >= REFRESH {
            app.refresh();
        }
        app.poll_containers();
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
    fn h_l_switch_tabs() {
        let mut app = TuiApp::new(crate::platform::get(), Seed::default());
        on_key(&mut app, KeyCode::Char('h'));
        assert_eq!(app.tab, Tab::Locks);
        on_key(&mut app, KeyCode::Char('l'));
        assert_eq!(app.tab, Tab::Processes);
        on_key(&mut app, KeyCode::Char('l'));
        assert_eq!(app.tab, Tab::Ports);
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
