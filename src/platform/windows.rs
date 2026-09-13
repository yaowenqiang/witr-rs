//! Windows: ToolHelp32 snapshot for the process table; PowerShell
//! (Get-CimInstance) batched per-target for cmdline/user/start time;
//! netstat -ano for port ownership; tasklist /svc for service names.

use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;

use crate::model::{Pid, Process, Socket, Source};
use crate::platform::{Capabilities, PlatError, PlatResult, Platform, Users};
use crate::util::{basename, run, split_host_port};

const PS_TIMEOUT: Duration = Duration::from_secs(20);
const NETSTAT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Windows {
    users: Users,
}

impl Windows {
    pub fn new(users: Users) -> Self {
        Windows { users }
    }
}

// ---------- ToolHelp32 process snapshot ----------

#[derive(Debug, Clone)]
struct SnapProc {
    pid: Pid,
    ppid: Pid,
    exe: String,
}

fn toolhelp_snapshot() -> PlatResult<Vec<SnapProc>> {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                .map_err(|e| PlatError::Failed(format!("CreateToolhelp32Snapshot: {}", e)))?;
            let mut out = Vec::new();
            let mut entry = PROCESSENTRY32W::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snap, &mut entry).is_ok() {
                loop {
                    let exe = String::from_utf16_lossy(
                        &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)],
                    );
                    out.push(SnapProc {
                        pid: entry.th32ProcessID as Pid,
                        ppid: entry.th32ParentProcessID as Pid,
                        exe,
                    });
                    if Process32NextW(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
            Ok(out)
        }
    }
    #[cfg(not(windows))]
    {
        Err(PlatError::Unsupported("windows-only snapshot".into()))
    }
}

// ---------- PowerShell helpers ----------

/// Minimal base64 (standard alphabet, padding) for -EncodedCommand.
fn base64_utf16le(s: &str) -> String {
    let mut bytes = Vec::with_capacity(s.len() * 2);
    for unit in s.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

fn run_powershell(script: &str) -> PlatResult<String> {
    let encoded = base64_utf16le(script);
    run(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded,
        ],
        PS_TIMEOUT,
    )
    .map_err(|e| PlatError::Failed(format!("powershell: {}", e)))
}

#[derive(Debug, Deserialize)]
struct PsProc {
    pid: i64,
    #[serde(default)]
    ppid: Option<i64>,
    #[serde(default)]
    exe: Option<String>,
    #[serde(default)]
    cmd: Option<String>,
    #[serde(default)]
    started: Option<serde_json::Value>,
    #[serde(default)]
    user: Option<String>,
}

/// Parse the DateTime shapes PowerShell produces for CIM values:
/// PS 5.1 → "/Date(1694499200123)/" (UTC ms), PS 7 → ISO 8601 string.
fn ps_datetime_to_unix(v: &serde_json::Value) -> Option<i64> {
    let s = v.as_str()?;
    if let Some(rest) = s.strip_prefix("/Date(") {
        let ms: i64 = rest.trim_end_matches(")/").parse().ok()?;
        return Some(ms / 1000);
    }
    // ISO: 2026-09-12T08:31:05[.123][Z]
    let (date, rest) = s.split_once('T')?;
    let d: Vec<i64> = date.split('-').filter_map(|x| x.parse().ok()).collect();
    if d.len() != 3 {
        return None;
    }
    let time_part = rest.trim_end_matches('Z');
    let t: Vec<f64> = time_part
        .split(':')
        .filter_map(|x| x.parse().ok())
        .collect();
    if t.len() < 2 {
        return None;
    }
    let days = days_from_civil(d[0], d[1] as u32, d[2] as u32);
    Some(days * 86_400 + t[0] as i64 * 3600 + t[1] as i64 * 60 + (t.get(2).cloned().unwrap_or(0.0) as i64))
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Query cmdline/exe/started/user for a batch of pids in one PowerShell call.
fn cim_details(pids: &[Pid]) -> Vec<PsProc> {
    if pids.is_empty() {
        return Vec::new();
    }
    let filter = pids
        .iter()
        .map(|p| format!("ProcessId={}", p))
        .collect::<Vec<_>>()
        .join(" OR ");
    let script = format!(
        "Get-CimInstance Win32_Process -Filter '{0}' | ForEach-Object {{ \
         $o = $_ | Invoke-CimMethod -MethodName GetOwner; \
         [PSCustomObject]@{{ pid = $_.ProcessId; ppid = $_.ParentProcessId; \
         exe = $_.ExecutablePath; cmd = $_.CommandLine; started = $_.CreationDate; \
         user = if ($o -and $o.User) {{ '{1}' + $o.Domain + '{1}' + $o.User }} else {{ $null }} }} }} \
         | ConvertTo-Json -Compress -Depth 3",
        filter, "\\"
    );
    let Ok(out) = run_powershell(&script) else {
        return Vec::new();
    };
    let text = out.trim();
    if text.is_empty() {
        return Vec::new();
    }
    match serde_json::from_str::<PsProc>(text) {
        Ok(one) => vec![one],
        Err(_) => serde_json::from_str::<Vec<PsProc>>(text).unwrap_or_default(),
    }
}

// ---------- netstat ----------

fn parse_netstat(text: &str, proto_hint: &str) -> Vec<Socket> {
    let _ = proto_hint;
    let mut out = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4
            || !(cols[0].eq_ignore_ascii_case("tcp") || cols[0].eq_ignore_ascii_case("udp"))
        {
            continue;
        }
        let pid: Pid = match cols.last().and_then(|c| c.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        let state = if cols.len() >= 5 {
            cols[3].to_string()
        } else {
            "UNCONNECTED".into()
        };
        let (Some((laddr, lport)), foreign) = (split_host_port(cols[1]), cols[2]) else {
            continue;
        };
        let (faddr, fport) = split_host_port(foreign)
            .filter(|(_, p)| *p != 0)
            .unwrap_or((String::new(), 0));
        let mut proto = cols[0].to_ascii_lowercase();
        // netstat prints IPv6 locals bracketed: [::]:445
        if cols[1].starts_with('[') {
            proto.push('6');
        }
        out.push(Socket {
            proto,
            local_addr: laddr,
            local_port: lport,
            peer_addr: if faddr.is_empty() { None } else { Some(faddr) },
            peer_port: if fport != 0 { Some(fport) } else { None },
            state,
            pid: Some(pid),
        });
    }
    out
}

fn netstat_sockets(port: u16) -> PlatResult<Vec<Socket>> {
    let mut out = Vec::new();
    for proto in ["tcp", "udp"] {
        let out_text = std::process::Command::new("netstat")
            .args(["-ano", "-p", proto])
            .output()
            .map_err(|e| PlatError::Failed(format!("netstat: {}", e)))?;
        let text = String::from_utf8_lossy(&out_text.stdout);
        out.extend(
            parse_netstat(&text, proto)
                .into_iter()
                .filter(|s| s.local_port == port),
        );
    }
    Ok(out)
}

// ---------- tasklist /svc ----------

/// CSV row `"name","pid","SvcA, Svc B"` → fields via quote-splitting.
fn parse_tasklist_csv(text: &str) -> Vec<(String, Pid, Vec<String>)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('"').enumerate().filter(|(i, _)| i % 2 == 1).map(|(_, f)| f).collect();
        if fields.len() < 3 {
            continue;
        }
        let Ok(pid) = fields[1].trim().parse() else { continue };
        let svcs = fields[2]
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("n/a"))
            .collect();
        out.push((fields[0].to_string(), pid, svcs));
    }
    out
}

fn service_names(pid: Pid) -> Vec<String> {
    let Ok(out) = std::process::Command::new("tasklist")
        .args(["/svc", "/fo", "csv", "/nh", "/fi", &format!("PID eq {}", pid)])
        .output()
    else {
        return Vec::new();
    };
    parse_tasklist_csv(&String::from_utf8_lossy(&out.stdout))
        .into_iter()
        .flat_map(|(_, _, svcs)| svcs)
        .collect()
}

/// tasklist /fo csv /nh row: `"name","pid","Console","1","123,456 K"` → (pid, mem_kb)
fn parse_tasklist_mem(text: &str) -> HashMap<Pid, u64> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line
            .split('"')
            .enumerate()
            .filter(|(i, _)| i % 2 == 1)
            .map(|(_, f)| f)
            .collect();
        if fields.len() < 5 {
            continue;
        }
        let Ok(pid) = fields[1].trim().parse() else { continue };
        let mem: String = fields[4]
            .trim()
            .trim_end_matches(['K', 'k'])
            .trim()
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        if let Ok(kb) = mem.parse() {
            map.insert(pid, kb);
        }
    }
    map
}

impl Platform for Windows {
    fn name(&self) -> &'static str {
        "windows"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            file_lookup: false, // needs Sysinternals handle.exe; warn instead
            env: false,
        }
    }

    fn list_processes(&self) -> PlatResult<Vec<Process>> {
        let snap = toolhelp_snapshot()?;
        let mem = std::process::Command::new("tasklist")
            .args(["/fo", "csv", "/nh"])
            .output()
            .map(|o| parse_tasklist_mem(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default();
        Ok(snap
            .into_iter()
            .map(|s| Process {
                pid: s.pid,
                ppid: Some(s.ppid),
                name: basename(&s.exe),
                mem_kb: mem.get(&s.pid).copied(),
                ..Default::default()
            })
            .collect())
    }

    fn detail(&self, brief: &Process, _want_env: bool) -> Process {
        let mut p = brief.clone();
        let details = cim_details(&[brief.pid]);
        if let Some(d) = details.first() {
            if let Some(ppid) = d.ppid {
                p.ppid = Some(ppid as Pid);
            }
            p.exe = d.exe.clone();
            if let Some(cmd) = &d.cmd {
                p.cmdline = vec![cmd.clone()];
            }
            p.started = d.started.as_ref().and_then(ps_datetime_to_unix);
            p.user = d.user.clone();
        }
        p
    }

    fn port_to_sockets(&self, port: u16) -> PlatResult<Vec<Socket>> {
        netstat_sockets(port)
    }

    fn list_sockets(&self) -> PlatResult<Vec<Socket>> {
        let mut out = Vec::new();
        for proto in ["tcp", "udp"] {
            let out_text = std::process::Command::new("netstat")
                .args(["-ano", "-p", proto])
                .output()
                .map_err(|e| PlatError::Failed(format!("netstat: {}", e)))?;
            let text = String::from_utf8_lossy(&out_text.stdout);
            for s in parse_netstat(&text, proto) {
                let keep = if proto == "tcp" {
                    s.state.eq_ignore_ascii_case("LISTENING")
                } else {
                    true
                };
                if keep {
                    out.push(s);
                }
            }
        }
        out.sort_by(|a, b| (a.proto.clone(), a.local_port).cmp(&(b.proto.clone(), b.local_port)));
        Ok(out)
    }

    fn file_to_pids(&self, _path: &str) -> PlatResult<Vec<Pid>> {
        Err(PlatError::Unsupported(
            "file holders need Sysinternals handle.exe; not supported by witr-rs".into(),
        ))
    }

    fn container_of(&self, _pid: Pid) -> Option<Source> {
        None
    }

    fn service_source(&self, chain: &[Process]) -> Option<Source> {
        let under_scm = chain.iter().any(|p| p.name.eq_ignore_ascii_case("services.exe"));
        if !under_scm {
            return None;
        }
        let target = chain.last()?;
        let svcs = service_names(target.pid);
        if !svcs.is_empty() {
            return Some(Source {
                kind: "windows-service".into(),
                label: Some(svcs.join(", ")),
                detail: Some("registered Windows service(s) (Service Control Manager)".into()),
            });
        }
        Some(Source {
            kind: "windows-service".into(),
            label: None,
            detail: Some(format!(
                "descendant of the Service Control Manager (services.exe), but pid {} is itself not a registered service",
                target.pid
            )),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        // UTF-16LE of "hi" = 68 00 69 00
        assert_eq!(base64_utf16le("hi"), "aABpAA==");
        assert_eq!(base64_utf16le(""), "");
    }

    #[test]
    fn netstat_lines() {
        let text = "\n\n\n  Proto  Local Address          Foreign Address        State           PID\n  \
                    TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234\n  \
                    UDP    0.0.0.0:5353           *:*                                    5678\n  \
                    TCP    [::]:445               [::]:0                 LISTENING       7777\n";
        let socks = parse_netstat(text, "tcp");
        assert_eq!(socks.len(), 3);
        assert_eq!(socks[0].local_port, 135);
        assert_eq!(socks[0].state, "LISTENING");
        assert_eq!(socks[0].pid, Some(1234));
        assert_eq!(socks[1].state, "UNCONNECTED");
        assert_eq!(socks[1].proto, "udp");
        assert_eq!(socks[2].local_addr, "::");
        assert_eq!(socks[2].proto, "tcp6");
    }

    #[test]
    fn tasklist_csv_row() {
        let rows = parse_tasklist_csv("\"nginx.exe\",\"1234\",\"SvcA, SvcB\"\r\n\"idle\",\"0\",\"N/A\"\r\n");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "nginx.exe");
        assert_eq!(rows[0].1, 1234);
        assert_eq!(rows[0].2, vec!["SvcA", "SvcB"]);
        assert!(rows[1].2.is_empty());
    }

    #[test]
    fn ps_datetime() {
        // 2023-09-12T04:53:20.123Z = 1694494400.123 unix
        assert_eq!(
            ps_datetime_to_unix(&serde_json::json!("/Date(1694494400123)/")),
            Some(1694494400)
        );
        assert_eq!(
            ps_datetime_to_unix(&serde_json::json!("2023-09-12T04:53:20.123")),
            ps_datetime_to_unix(&serde_json::json!("/Date(1694494400123)/"))
        );
        assert_eq!(ps_datetime_to_unix(&serde_json::json!(null)), None);
    }
}
