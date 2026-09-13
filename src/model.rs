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
    pub state: String,
    pub status: String, // human readable, e.g. "Up 2 weeks (healthy)"
    pub ports: String,  // published ports, e.g. "0.0.0.0:8088->8088/tcp"
}

#[derive(Debug, Clone, Serialize)]
pub struct Source {
    /// systemd | launchd | windows-service | cron | container | tmux | screen | ssh | shell | init
    pub kind: String,
    pub label: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum TargetSpec {
    Name { pattern: String, exact: bool },
    Pid { pid: Pid },
    Port { port: u16 },
    File { path: String },
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
        }
    }
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
}

impl TargetReport {
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
        }
    }
}
