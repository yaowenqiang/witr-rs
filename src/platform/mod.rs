// All three platform modules compile on every host so `cargo check`
// type-validates the whole tree anywhere; dead-code allows cover the
// implementations that aren't wired in on the current OS.
#[allow(dead_code)]
pub mod linux;
#[allow(dead_code)]
pub mod macos;
#[allow(dead_code)]
pub mod windows;

use crate::model::{Container, FileOverview, LockEntry, Pid, Process, Service, Socket, Source};
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
        command: get("Command").to_string(),
        state: get("State").to_string(),
        status: get("Status").to_string(),
        ports: get("Ports").to_string(),
        pod: None,
        restarts: None,
    })
}

/// The host pid of a container's main process, via the runtime's `inspect`.
/// Inside a VM-backed setup (Docker Desktop, podman machine) this is the pid
/// inside the VM, so callers must verify it against the host snapshot.
pub fn container_host_pid(runtime: &str, id: &str) -> Option<Pid> {
    let out = crate::util::run(
        runtime,
        &["inspect", "--format", "{{.State.Pid}}", id],
        std::time::Duration::from_secs(6),
    )
    .ok()?;
    let pid: i32 = out.trim().parse().ok()?;
    (pid > 0).then_some(pid)
}

/// How often the runtime's restart policy has restarted this container
/// (`inspect .RestartCount`). None when the runtime/daemon is unavailable.
pub fn container_restarts(runtime: &str, id: &str) -> Option<u32> {
    let out = crate::util::run(
        runtime,
        &["inspect", "--format", "{{.RestartCount}}", id],
        std::time::Duration::from_secs(6),
    )
    .ok()?;
    out.trim().parse().ok()
}

/// The container that publishes `port` on the host, found by matching the
/// runtime's port mapping strings ("0.0.0.0:8088->8088/tcp"). This is how a
/// Docker Desktop / podman-machine port is explained when no host process
/// owns the socket.
pub fn container_by_port(port: u16) -> Option<Container> {
    enumerate_containers().into_iter().find(|c| {
        c.ports.split(',').any(|entry| {
            let entry = entry.trim();
            entry
                .split("->")
                .next()
                .and_then(|host| host.rsplit(':').next())
                .is_some_and(|hp| hp == port.to_string())
        })
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

/// Enumerate services from the platform's service manager in one CLI call:
/// systemd (Linux), launchctl (macOS), SCM via PowerShell (Windows). A
/// missing or failing manager yields an empty list — the tab shows its
/// "not available" note.
pub fn enumerate_services() -> Vec<Service> {
    #[cfg(target_os = "linux")]
    return systemd_services();
    #[cfg(target_os = "macos")]
    return launchd_services();
    #[cfg(windows)]
    return scm_services();
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    return Vec::new();
}

/// Main pid of a service whose listing didn't carry one (systemd resolves
/// `MainPID` on demand — one fast call when Enter is pressed).
pub fn service_pid_of(svc: &Service) -> Option<Pid> {
    if svc.manager != "systemd" {
        return None;
    }
    #[cfg(target_os = "linux")]
    return systemd_unit_pid(&svc.name);
    #[cfg(not(target_os = "linux"))]
    return None;
}

#[cfg(target_os = "linux")]
fn systemd_services() -> Vec<Service> {
    let Ok(text) = crate::util::run(
        "systemctl",
        &[
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--no-pager",
            "--plain",
        ],
        std::time::Duration::from_secs(8),
    ) else {
        return Vec::new();
    };
    parse_systemctl_units(&text)
}

/// `ssh.service  loaded active running  OpenBSD Secure Shell server` — the
/// no-legend `list-units` row: UNIT LOAD ACTIVE SUB DESCRIPTION (a leading
/// `●` marks units with queued jobs; DESCRIPTION may be absent).
#[allow(dead_code)] // every parse fn is unit-tested on all platforms
pub fn parse_systemctl_units(text: &str) -> Vec<Service> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| {
            let mut parts = l.trim_start_matches('●').split_whitespace();
            let unit = parts.next()?.to_string();
            let _load = parts.next()?;
            let active = parts.next()?;
            let sub = parts.next()?;
            let desc = parts.collect::<Vec<_>>().join(" ");
            (unit.ends_with(".service")).then(|| Service {
                manager: "systemd".into(),
                name: unit,
                state: if active == "active" {
                    format!("active/{sub}")
                } else {
                    active.to_string()
                },
                desc,
                pid: None,
            })
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn systemd_unit_pid(unit: &str) -> Option<Pid> {
    let out = crate::util::run(
        "systemctl",
        &["show", "-p", "MainPID", "--value", unit],
        std::time::Duration::from_secs(5),
    )
    .ok()?;
    out.trim().parse().ok().filter(|p| *p > 0)
}

#[cfg(target_os = "macos")]
fn launchd_services() -> Vec<Service> {
    let Ok(text) = crate::util::run(
        "launchctl",
        &["list"],
        std::time::Duration::from_secs(8),
    ) else {
        return Vec::new();
    };
    parse_launchctl_list(&text)
}

/// `launchctl list` rows: `PID\tStatus\tLabel`, PID "-" when the job isn't
/// running; the header line ("PID\tStatus\tLabel") fails the pid parse and
/// drops out naturally.
#[allow(dead_code)]
pub fn parse_launchctl_list(text: &str) -> Vec<Service> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| {
            let mut parts = l.split('\t').map(str::trim);
            let pid = match parts.next()? {
                "-" | "" => None,
                s => {
                    let p: Pid = s.parse().ok()?;
                    (p > 0).then_some(p)
                }
            };
            let _status = parts.next()?;
            let label = parts.next()?;
            (!label.is_empty()).then(|| Service {
                manager: "launchd".into(),
                name: label.to_string(),
                state: if pid.is_some() {
                    "running".into()
                } else {
                    "not running".into()
                },
                desc: String::new(),
                pid,
            })
        })
        .collect()
}

#[cfg(windows)]
fn scm_services() -> Vec<Service> {
    let script = "$ErrorActionPreference='SilentlyContinue'; \
                  Get-CimInstance Win32_Service | \
                  Select-Object Name,State,DisplayName,ProcessId | \
                  ConvertTo-Json -Compress";
    let Ok(text) = crate::util::run(
        "powershell",
        &["-NoProfile", "-Command", script],
        std::time::Duration::from_secs(15),
    ) else {
        return Vec::new();
    };
    parse_scm_services(&text)
}

/// Win32_Service JSON — `ConvertTo-Json` emits a bare object for one
/// service and an array otherwise, so both shapes normalize here.
#[allow(dead_code)]
pub fn parse_scm_services(text: &str) -> Vec<Service> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text.trim()) else {
        return Vec::new();
    };
    let items = match v {
        serde_json::Value::Array(a) => a,
        obj @ serde_json::Value::Object(_) => vec![obj],
        _ => return Vec::new(),
    };
    items
        .iter()
        .filter_map(|s| {
            let get = |k: &str| s.get(k).and_then(|x| x.as_str()).unwrap_or_default();
            let name = get("Name").to_string();
            (!name.is_empty()).then(|| Service {
                manager: "scm".into(),
                state: get("State").to_string(),
                name,
                desc: get("DisplayName").to_string(),
                pid: s
                    .get("ProcessId")
                    .and_then(|x| x.as_i64())
                    .filter(|p| *p > 0)
                    .map(|p| p as Pid),
            })
        })
        .collect()
}

/// Parse POSIX `df -P -k` output into device-backed mounts: rows whose
/// filesystem starts with `/dev/` (drops network mounts, `map auto_home`,
/// tmpfs and friends), deduped by mount point, zero-size rows skipped.
/// Shared by the unix platforms — both GNU and BSD df speak `-P -k`.
pub(crate) fn parse_df(out: &str) -> Vec<MountUsage> {
    let mut out_rows: Vec<MountUsage> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in out.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // "Filesystem 1024-blocks Used Available Capacity Mounted on..."
        if fields.len() < 6 {
            continue;
        }
        if !fields[0].starts_with("/dev/") {
            continue;
        }
        let Ok(total_kb) = fields[1].parse::<u64>() else {
            continue;
        };
        let Ok(used_kb) = fields[2].parse::<u64>() else {
            continue;
        };
        let target = fields[5].to_string();
        if total_kb == 0 || !seen.insert(target.clone()) {
            continue;
        }
        out_rows.push(MountUsage {
            target,
            total_mb: total_kb / 1024,
            used_mb: used_kb / 1024,
        });
    }
    out_rows
}

/// One whole-machine resource snapshot for the system page ('y'). Every
/// field is best-effort: platforms without a cheap source leave it `None`
/// (or `cores` empty) and the page hides that section. CPU percents are
/// delta-based, so a platform's very first call may report none.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SystemStats {
    /// Total CPU busy percent across all cores (user+sys+nice).
    pub cpu_percent: Option<f64>,
    /// Per-core busy percent; empty when the platform has no per-core
    /// source (the page hides the grid rather than showing blanks).
    pub cores: Vec<f64>,
    pub mem_used_mb: Option<u64>,
    pub mem_total_mb: Option<u64>,
    pub swap_used_mb: Option<u64>,
    pub swap_total_mb: Option<u64>,
    pub load1: Option<f64>,
    pub load5: Option<f64>,
    pub load15: Option<f64>,
}

/// One device-backed mounted filesystem for the system page's disk
/// section. Pseudo filesystems (tmpfs, overlay, proc...) never appear.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MountUsage {
    /// Mount point ("/", "/home", "C:\"...).
    pub target: String,
    pub total_mb: u64,
    pub used_mb: u64,
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

    /// Optional second pass over a fresh listing that fills per-process
    /// cumulative disk-I/O counters (`io_read_bytes`/`io_write_bytes`).
    /// The TUI calls this once per refresh so the sampling history can
    /// diff the counters into read/write rates for the IO column.
    /// Best-effort: entries the platform can't measure stay `None` and
    /// the column hides itself. Default: not measured.
    fn enrich_listing(&self, procs: &mut [Process]) {
        let _ = procs;
    }

    /// Whole-machine resources for the system page ('y'): total + per-core
    /// CPU, memory/swap usage, load average. Best-effort — anything the
    /// platform can't measure cheaply stays `None`. Default: unsupported.
    fn system_stats(&self) -> Option<SystemStats> {
        None
    }

    /// Device-backed mounted filesystems for the system page's disk
    /// section. One `df -P -k` sweep on unix (network/loopback mounts and
    /// pseudo filesystems drop out because only `/dev/...` devices are
    /// kept), a PowerShell CIM query on Windows. Callers run it only while
    /// the page is open — it is a process spawn, not a file read.
    fn mount_usage(&self) -> Vec<MountUsage> {
        #[cfg(unix)]
        {
            let out = crate::util::run_ok("df", &["-P", "-k"], std::time::Duration::from_secs(5))
                .unwrap_or_default();
            parse_df(&out)
        }
        #[cfg(not(unix))]
        {
            Vec::new()
        }
    }

    /// All sockets whose local port equals `port` (any proto), with owning
    /// pid where resolvable.
    fn port_to_sockets(&self, port: u16) -> PlatResult<Vec<Socket>>;

    /// Snapshot for the TUI Ports tab: tcp LISTEN + bound udp sockets.
    fn list_sockets(&self) -> PlatResult<Vec<Socket>>;

    /// Every socket (tcp in any state + udp). The Ports tab's 'a' toggle
    /// switches between this and the LISTEN-only [`Platform::list_sockets`].
    fn list_all_sockets(&self) -> PlatResult<Vec<Socket>> {
        self.list_sockets()
    }

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

    /// Open-descriptor count for one pid, or None when the platform has no
    /// cheap probe (Windows) or the process is unreadable. Called once per
    /// refresh while the detail page shows this pid — Linux counts
    /// /proc/<pid>/fd (µs-cheap), macOS runs one `lsof -p`, so callers
    /// gate it the same way as the system page ("only while the page is
    /// open").
    fn fd_count(&self, pid: Pid) -> Option<u64> {
        let _ = pid;
        None
    }

    /// Open files + file locks + fd usage in one pass. Platforms whose
    /// probes are expensive (macOS: every lookup is an lsof scan) override
    /// this so the detail page costs one scan instead of two. Default: the
    /// two individual methods, no fd usage.
    fn file_overview(&self, pid: Pid) -> FileOverview {
        FileOverview {
            files: self.open_files(pid),
            locks: self.list_locks(Some(pid)),
            fd_usage: None,
        }
    }

    /// File locks: system-wide when `pid` is None, else one process's.
    /// Linux parses /proc/locks; macOS reads lock flags out of `lsof`
    /// (plus a lock-file name heuristic — the kernel exports no lock
    /// table there). Default: none.
    fn list_locks(&self, pid: Option<Pid>) -> Vec<LockEntry> {
        let _ = pid;
        Vec::new()
    }

    /// Every open file on the system as lock-tab entries (kind "OPEN",
    /// mode = fd access) — the Locks tab's "all open files" view merges
    /// these underneath the real locks. Default: none.
    fn list_all_open_files(&self) -> Vec<LockEntry> {
        Vec::new()
    }

    /// PIDs holding `path` open.
    fn file_to_pids(&self, path: &str) -> PlatResult<Vec<Pid>>;

    /// If this pid runs inside a container, attribute it.
    fn container_of(&self, pid: Pid) -> Option<Source>;

    /// Effective Linux capability names for the pid (CapEff); empty
    /// elsewhere or when unreadable.
    fn process_capabilities(&self, pid: Pid) -> Vec<String> {
        let _ = pid;
        Vec::new()
    }

    /// Service-manager attribution (systemd / launchd / SCM) for a process
    /// whose ancestry is `chain` (root first, the process itself last).
    fn service_source(&self, chain: &[Process]) -> Option<Source>;

    /// Reverse lookup: the main pid of the service manager unit whose name
    /// matches `name` (systemd unit / launchd label). None when no unit or
    /// the platform has no service manager. Lets a name target that matches
    /// no process still resolve through its unit.
    fn service_pid(&self, name: &str) -> Option<Pid> {
        let _ = name;
        None
    }
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

#[cfg(test)]
mod service_tests {
    use super::*;

    #[test]
    fn systemctl_units_parse() {
        let text = "\
sys-devices-loaded.device loaded active plugged stub\
\nssh.service               loaded active running OpenBSD Secure Shell server\
\n● docker.service          loaded activating start-pre Docker Application Container Engine\
\nnginx.service             loaded failed failed  web server\
\nuser@1000.service         loaded active running User Manager for UID 1000\
\n";
        let ss = parse_systemctl_units(text);
        let names: Vec<&str> = ss.iter().map(|s| s.name.as_str()).collect();
        // non-.service rows (devices) drop out
        assert_eq!(names, vec!["ssh.service", "docker.service", "nginx.service", "user@1000.service"]);
        assert_eq!(ss[0].manager, "systemd");
        assert_eq!(ss[0].state, "active/running");
        assert_eq!(ss[0].desc, "OpenBSD Secure Shell server");
        // activating shows the raw state, description still parsed
        assert_eq!(ss[1].state, "activating");
        // failed stands out (the tab paints it red)
        assert_eq!(ss[2].state, "failed");
        assert!(ss.iter().all(|s| s.pid.is_none()), "systemd resolves pids lazily");
    }

    #[test]
    fn launchctl_list_parses() {
        let text = "PID\tStatus\tLabel\n\
                    501\t0\tcom.apple.Finder\n\
                    -\t0\tcom.apple.coreservices.appleid.authentication\n\
                    1234\t127\tbroken.job\n";
        let ss = parse_launchctl_list(text);
        assert_eq!(ss.len(), 3, "header drops out");
        assert_eq!(ss[0].name, "com.apple.Finder");
        assert_eq!(ss[0].manager, "launchd");
        assert_eq!(ss[0].pid, Some(501));
        assert_eq!(ss[0].state, "running");
        assert_eq!(ss[1].pid, None);
        assert_eq!(ss[1].state, "not running");
        assert_eq!(ss[2].pid, Some(1234));
    }

    #[test]
    fn scm_services_parse() {
        let one = r#"{"Name":"wuauserv","State":"Running","DisplayName":"Windows Update","ProcessId":1234}"#;
        assert_eq!(parse_scm_services(one)[0].pid, Some(1234));
        let many = r#"[
            {"Name":"Docker Desktop Service","State":"Running","DisplayName":"Docker Desktop Service","ProcessId":4321},
            {"Name":"Spooler","State":"Stopped","DisplayName":"Print Spooler","ProcessId":0}
        ]"#;
        let ss = parse_scm_services(many);
        assert_eq!(ss.len(), 2);
        assert_eq!(ss[0].manager, "scm");
        assert_eq!(ss[0].pid, Some(4321));
        // pid 0 = stopped service → None
        assert_eq!(ss[1].pid, None);
        assert_eq!(ss[1].state, "Stopped");
        // garbage in → empty out
        assert!(parse_scm_services("not json").is_empty());
    }

    #[test]
    fn df_parse_keeps_device_rows_only() {
        let out = "\
Filesystem 1024-blocks      Used Available Capacity  Mounted on
/dev/disk1s1s1  482949120 38123456 444825664     8%    /
/dev/disk1s5    482949120 38123456 444825664     8%    /System/Volumes/Data
map auto_home           0        0          0     0%    /System/Volumes/Data/home
//server/share   1000000   500000     500000    50%    /Volumes/share
tmpfs             131072    65536     65536    50%    /run
/dev/loop0             0        0          0     0%    /snap/empty
";
        let m = parse_df(out);
        let targets: Vec<_> = m.iter().map(|x| x.target.as_str()).collect();
        assert_eq!(targets, vec!["/", "/System/Volumes/Data"]);
        let root = &m[0];
        // 482949120 KB → MB (integer division)
        assert_eq!(root.total_mb, 482949120 / 1024);
        assert_eq!(root.used_mb, 38123456 / 1024);
        // zero-size device rows drop out too
        assert!(!targets.contains(&"/snap/empty"));
        // header / malformed lines are silently skipped
        assert!(parse_df("").is_empty());
        assert!(parse_df("garbage line\nanother\n").is_empty());
    }
}
