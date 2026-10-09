use serde::Serialize;

pub type Pid = i32;

/// Everything we know about one process. Fields are optional because
/// each platform fills in a different subset (and permissions limit more).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Process {
    pub pid: Pid,
    pub ppid: Option<Pid>,
    pub name: String,
    pub exe: Option<String>,
    pub exe_deleted: bool,
    pub cmdline: Vec<String>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub uid: Option<u32>,
    /// Unix timestamp (seconds) the process started, when resolvable.
    pub started: Option<i64>,
    /// Only collected when the user asks for it; None = unavailable
    /// (other user's process, SIP, unsupported platform...).
    pub env: Option<Vec<(String, String)>>,
    pub kernel_thread: bool,
    /// Average CPU percent over the process lifetime (what ps pcpu reports).
    pub cpu: Option<f64>,
    /// Resident set size in KiB.
    pub mem_kb: Option<u64>,
    /// Virtual memory size in KiB (macOS ps vsz / Linux VmSize).
    pub vm_kb: Option<u64>,
    /// Anonymous (private) resident memory in KiB (Linux RssAnon).
    pub private_kb: Option<u64>,
    /// OS thread count, when the platform exposes it.
    pub threads: Option<u32>,
    /// Cumulative disk I/O: bytes + syscall ops (Linux /proc/<pid>/io).
    pub io_read_bytes: Option<u64>,
    pub io_read_ops: Option<u64>,
    pub io_write_bytes: Option<u64>,
    pub io_write_ops: Option<u64>,
    /// Cumulative CPU time in milliseconds — the sampling history uses the
    /// delta between refreshes for a true instantaneous percent.
    pub cpu_time_ms: Option<u64>,
    /// Kernel process state letter when the platform exposes it (Linux stat,
    /// macOS ps state=): R/S/D/Z/T. Z (zombie) and T (stopped) feed warnings.
    pub state: Option<String>,
    /// True when the process was forked from a non-init parent (Go witr's
    /// `{forked}` tag): ppid != 1 and the parent isn't the init system.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub forked: bool,
    /// Repository name when the process's working directory sits inside a git
    /// work tree, and the checked-out branch ("" when HEAD is detached).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    /// Container identity line for `-c` targets whose main process is visible
    /// on the host: "docker: web (id abc123def456) [running]".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// Effective Linux capability names (from /proc/<pid>/status CapEff).
    /// Empty on other platforms or when unreadable.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

impl Process {
    /// One-line command representation for display.
    pub fn command_line(&self) -> String {
        if self.cmdline.is_empty() {
            self.name.clone()
        } else {
            self.cmdline.join(" ")
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Child {
    pub pid: Pid,
    pub name: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Socket {
    pub proto: String, // tcp / tcp6 / udp / udp6
    pub local_addr: String,
    pub local_port: u16,
    pub peer_addr: Option<String>,
    pub peer_port: Option<u16>,
    pub state: String, // LISTEN / ESTABLISHED / UNCONNECTED ...
    pub pid: Option<Pid>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Container {
    pub runtime: String, // docker / podman / nerdctl
    pub id: String,
    pub name: String,
    pub image: String,
    pub command: String, // truncated command from the runtime listing
    pub state: String,
    pub status: String, // human readable, e.g. "Up 2 weeks (healthy)"
    pub ports: String,  // published ports, e.g. "0.0.0.0:8088->8088/tcp"
}

impl Container {
    /// The bracketed state/health tag: healthy when reported healthy, the
    /// health verdict otherwise, else the state when it isn't "running".
    pub fn state_tag(&self) -> String {
        let health = self.status.rsplit(['(', ')']).find(|s| {
            matches!(
                s.trim(),
                "healthy" | "unhealthy" | "starting" | "restarting"
            )
        });
        if let Some(h) = health {
            return h.trim().to_string();
        }
        if self.state != "running" && !self.state.is_empty() {
            return self.state.clone();
        }
        String::new()
    }

    /// "docker: web (id abc123def456) [running]" — the identity line shown
    /// for `-c` targets, mirroring Go witr's FormatContainerLine.
    pub fn format_line(&self) -> String {
        let mut parts = if self.runtime.is_empty() {
            self.name.clone()
        } else {
            format!("{}: {}", self.runtime, self.name)
        };
        let short: String = self.id.chars().take(12).collect();
        if !short.is_empty() {
            parts.push_str(&format!(" (id {short})"));
        }
        let tag = self.state_tag();
        if !tag.is_empty() {
            parts.push_str(&format!(" [{tag}]"));
        }
        parts
    }

    /// Substring/exact match across name, image, command, ports and ID
    /// prefix (≥ 4 hex chars, like docker accepts).
    pub fn matches_query(&self, query: &str, exact: bool) -> bool {
        let q = query.to_lowercase();
        let hex_ok = q.len() >= 4 && !q.is_empty() && q.chars().all(|c| c.is_ascii_hexdigit());
        if hex_ok {
            let id = self.id.to_lowercase();
            if if exact {
                id == q || (id.len() > 12 && id[..12] == *q)
            } else {
                id.starts_with(&q)
            } {
                return true;
            }
        }
        let fields = [
            self.name.to_lowercase(),
            self.image.to_lowercase(),
            self.command.to_lowercase(),
            self.ports.to_lowercase(),
        ];
        for f in fields {
            if f.is_empty() {
                continue;
            }
            if exact {
                if f == q {
                    return true;
                }
            } else if f.contains(&q) {
                return true;
            }
        }
        false
    }
}

/// One file lock, for the Locks tab and the detail page's Locks section.
/// On Linux this comes from /proc/locks (paths resolved through the
/// holder's fd table); on macOS from `lsof` lock flags plus a
/// `.lock`/`.pid` filename heuristic (the kernel doesn't export lock
/// tables there — see platform::macos::list_locks).
#[derive(Debug, Clone, Serialize)]
pub struct LockEntry {
    /// /proc/locks id, or the lsof fd token (e.g. "3uW") on macOS.
    pub id: String,
    /// POSIX / FLOCK / MAND (Linux); always "FLOCK" on macOS. Serialized as
    /// "type" to match the Go witr's LockedFile field name.
    #[serde(rename = "type")]
    pub kind: String,
    /// READ / WRITE / RW.
    pub mode: String,
    pub pid: Option<Pid>,
    /// Holder's process name.
    pub owner: String,
    /// Resolved file path; falls back to the device:inode literal on Linux
    /// when the holder's fd table isn't readable.
    pub path: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Source {
    /// systemd | launchd | windows-service | cron | container | supervisor | ssh | shell | init
    pub kind: String,
    pub label: Option<String>,
    pub detail: Option<String>,
    /// Restart count reported by the service manager (systemd NRestarts).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restarts: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum TargetSpec {
    Name { pattern: String, exact: bool },
    Pid { pid: Pid },
    Port { port: u16 },
    File { path: String },
    Container { query: String, exact: bool },
}

impl TargetSpec {
    pub fn describe(&self) -> String {
        match self {
            TargetSpec::Name { pattern, exact } => {
                if *exact {
                    format!("process named \"{}\" (exact)", pattern)
                } else {
                    format!("process matching \"{}\"", pattern)
                }
            }
            TargetSpec::Pid { pid } => format!("pid {}", pid),
            TargetSpec::Port { port } => format!("port {}", port),
            TargetSpec::File { path } => format!("file {}", path),
            TargetSpec::Container { query, exact } => {
                if *exact {
                    format!("container named \"{}\" (exact)", query)
                } else {
                    format!("container matching \"{}\"", query)
                }
            }
        }
    }

    /// Short label for the multi-target divider: `----- [pid: 12] -----`.
    pub fn divider_label(&self) -> String {
        match self {
            TargetSpec::Name { pattern, .. } => format!("name: {pattern}"),
            TargetSpec::Pid { pid } => format!("pid: {pid}"),
            TargetSpec::Port { port } => format!("port: {port}"),
            TargetSpec::File { path } => format!("file: {path}"),
            TargetSpec::Container { query, .. } => format!("container: {query}"),
        }
    }
}

/// What one `file_overview` probe yields for a process: open-file display
/// lines, file locks, and fd-table usage when the platform can read it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FileOverview {
    pub files: Vec<String>,
    pub locks: Vec<LockEntry>,
    /// (open fds, soft "Max open files" limit). None when either side is
    /// unreadable or unlimited.
    pub fd_usage: Option<(u64, u64)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetReport {
    pub target: TargetSpec,
    /// false = nothing matched (report carries the reason in `error`)
    pub found: bool,
    pub error: Option<String>,
    /// The process(es) the target resolved to. Multiple when a name
    /// matches several processes.
    pub matches: Vec<Process>,
    /// Ancestor chain, root first, the matched process last.
    pub ancestry: Vec<Process>,
    /// Direct children of each matched process.
    pub children: Vec<Child>,
    pub source: Option<Source>,
    pub sockets: Vec<Socket>,
    pub warnings: Vec<String>,
    /// File locks held by the matched process. Only collected when the
    /// caller asks for deep file data (CLI / TUI detail page).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub locks: Vec<LockEntry>,
    /// Open-file display lines, same collection gate as `locks`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_files: Option<Vec<String>>,
    /// (open fds, soft limit) for the matched process, when readable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fd_usage: Option<(u64, u64)>,
    /// Aggregated risk signals for the (first) matched process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<crate::risk::Risk>,
    /// The lookup hit a permission wall (socket owners / file holders hidden
    /// to this user). Drives exit code 3.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub permission_denied: bool,
    /// For `-c` targets whose main process is NOT visible on this host
    /// (Docker Desktop, podman machine): the runtime-side view of the
    /// container, rendered as a fallback report. `found` is false then.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<Container>,
}

impl TargetReport {
    #[allow(clippy::too_many_arguments)]
    pub fn not_found(target: TargetSpec, error: String) -> Self {
        TargetReport {
            target,
            found: false,
            error: Some(error),
            matches: Vec::new(),
            ancestry: Vec::new(),
            children: Vec::new(),
            source: None,
            sockets: Vec::new(),
            warnings: Vec::new(),
            locks: Vec::new(),
            open_files: None,
            fd_usage: None,
            risk: None,
            permission_denied: false,
            container: None,
        }
    }
}
