// All three platform modules compile on every host so `cargo check`
// type-validates the whole tree anywhere; dead-code allows cover the
// implementations that aren't wired in on the current OS.
#[allow(dead_code)]
pub mod linux;
#[allow(dead_code)]
pub mod macos;
#[allow(dead_code)]
pub mod windows;

use crate::model::{Container, Pid, Process, Socket, Source};
use crate::util::Users;

#[derive(Debug)]
pub enum PlatError {
    /// The platform genuinely can't answer this (no API without root, etc).
    Unsupported(String),
    /// Answering requires privileges the current user doesn't have.
    Permission(String),
    Failed(String),
}

impl std::fmt::Display for PlatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlatError::Unsupported(m) => write!(f, "not supported on this platform: {}", m),
            PlatError::Permission(m) => write!(f, "permission denied: {}", m),
            PlatError::Failed(m) => write!(f, "{}", m),
        }
    }
}

pub type PlatResult<T> = Result<T, PlatError>;

/// Enumerate containers from every runtime CLI on PATH. Uses
/// `ps --all --format '{{json .}}'` (one JSON object per line); runtimes
/// that are missing or whose daemon is down are silently skipped.
pub fn enumerate_containers() -> Vec<Container> {
    let mut out = Vec::new();
    for rt in ["docker", "podman", "nerdctl"] {
        let Ok(text) = crate::util::run(
            rt,
            &["ps", "--all", "--format", "{{json .}}"],
            std::time::Duration::from_secs(6),
        ) else {
            continue;
        };
        for line in text.lines() {
            let Some(c) = parse_container_line(line, rt) else {
                continue;
            };
            out.push(c);
        }
    }
    // running first, then by runtime and name
    out.sort_by(|a, b| {
        let ar = a.state != "running";
        let br = b.state != "running";
        ar.cmp(&br)
            .then(a.runtime.cmp(&b.runtime))
            .then(a.name.cmp(&b.name))
    });
    out
}

/// Parse one `{{json .}}` line from docker/podman/nerdctl.
pub fn parse_container_line(line: &str, runtime: &str) -> Option<Container> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let get = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default();
    let id = get("ID").to_string();
    let name = match v.get("Names") {
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str())
            .next()
            .unwrap_or_default()
            .to_string(),
        _ => get("Names").to_string(),
    };
    if id.is_empty() && name.is_empty() {
        return None;
    }
    Some(Container {
        runtime: runtime.to_string(),
        id,
        name,
        image: get("Image").to_string(),
        state: get("State").to_string(),
        status: get("Status").to_string(),
        ports: get("Ports").to_string(),
    })
}

/// Which optional capabilities the current platform/target has, so the
/// pipeline can warn instead of silently returning nothing.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    pub file_lookup: bool,
    /// Env vars readable for same-user processes at least.
    pub env: bool,
}

/// The single seam between pipeline logic and OS specifics.
pub trait Platform {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> Capabilities;

    /// One sweep over all processes (brief info only). Ancestry walking is
    /// built on top of this snapshot, so it should be a single pass.
    fn list_processes(&self) -> PlatResult<Vec<Process>>;

    /// Enrich one process with cmdline/cwd/exe/env. `brief` is the entry
    /// from [`list_processes`] for the same pid.
    fn detail(&self, brief: &Process, want_env: bool) -> Process;

    /// All sockets whose local port equals `port` (any proto), with owning
    /// pid where resolvable.
    fn port_to_sockets(&self, port: u16) -> PlatResult<Vec<Socket>>;

    /// Snapshot for the TUI Ports tab: tcp LISTEN + bound udp sockets.
    fn list_sockets(&self) -> PlatResult<Vec<Socket>>;

    /// Processes running inside container `id` (Linux via cgroup matching;
    /// on macOS the VM's processes aren't visible — default: none).
    fn container_processes(&self, id: &str) -> Vec<Process> {
        let _ = id;
        Vec::new()
    }

    /// Files (and a socket/pipe summary) the process currently has open,
    /// as display lines. Empty when not readable (other user, unsupported).
    fn open_files(&self, pid: Pid) -> Vec<String> {
        let _ = pid;
        Vec::new()
    }

    /// PIDs holding `path` open.
    fn file_to_pids(&self, path: &str) -> PlatResult<Vec<Pid>>;

    /// If this pid runs inside a container, attribute it.
    fn container_of(&self, pid: Pid) -> Option<Source>;

    /// Service-manager attribution (systemd / launchd / SCM) for a process
    /// whose ancestry is `chain` (root first, the process itself last).
    fn service_source(&self, chain: &[Process]) -> Option<Source>;
}

pub fn get() -> Box<dyn Platform> {
    let users = Users::load();
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::Linux::new(users))
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOs::new(users))
    }
    #[cfg(windows)]
    {
        Box::new(windows::Windows::new(users))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        compile_error!("witr-rs supports linux, macOS and Windows only")
    }
}
