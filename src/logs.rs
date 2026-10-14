//! Recent log lines for a traced process or container — the "why does it
//! keep restarting" follow-up after the Events tab flags a crash loop.
//!
//! Sources, in priority order: a container identity (runtime CLI `logs`)
//! when the process is attributed to one, then the platform log system
//! (journald filtered by `_PID=` on Linux, the unified log filtered by
//! process name on macOS, the Application+System event logs filtered by
//! pid/name on Windows).

use std::time::Duration;

use crate::model::{Pid, Process};
use crate::util::run;

const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
const LOG_SHOW_TIMEOUT: Duration = Duration::from_secs(25);

/// Where to pull recent log lines from.
#[derive(Debug, Clone, PartialEq)]
pub enum LogSource {
    /// `docker/podman/nerdctl logs` — `ref_` is a container id or name.
    Container { runtime: String, ref_: String },
    /// `journalctl _PID=<pid>` — covers every process that logs to the
    /// journal (system services need privileges to see).
    Journald { pid: Pid },
    /// macOS unified log, filtered by process name (log show is slow —
    /// 2–10 s wall time, hence the longer timeout).
    UnifiedLog { name: String },
    /// Windows Application+System event logs (warnings and errors of the
    /// last 30 minutes mentioning the pid or the process name).
    EventLog { pid: Pid, name: String },
}

impl LogSource {
    /// Best source for a process: a container identity line beats the
    /// platform log system (container stdout is the actual application log).
    pub fn for_process(p: &Process) -> LogSource {
        if let Some((runtime, id)) = parse_container_identity(p.container.as_deref()) {
            return LogSource::Container { runtime, ref_: id };
        }
        #[cfg(target_os = "macos")]
        return LogSource::UnifiedLog { name: p.name.clone() };
        #[cfg(target_os = "windows")]
        return LogSource::EventLog { pid: p.pid, name: p.name.clone() };
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        return LogSource::Journald { pid: p.pid };
    }

    /// Human label for page headers and CLI output.
    pub fn describe(&self) -> String {
        match self {
            LogSource::Container { runtime, ref_ } => {
                format!("{runtime} logs · {}", short_id(ref_))
            }
            LogSource::Journald { pid } => format!("journalctl (_PID={pid})"),
            LogSource::UnifiedLog { name } => format!("unified log (process {name})"),
            LogSource::EventLog { pid, name } => {
                format!("event log (pid {pid} / {name})")
            }
        }
    }
}

/// "docker: web (id abc123def456) [running]" → ("docker", "abc123def456").
/// Same shape [`crate::model::Container::format_line`] emits.
fn parse_container_identity(line: Option<&str>) -> Option<(String, String)> {
    let line = line?;
    let (runtime, rest) = line.split_once(": ")?;
    let id = rest.split("(id ").nth(1)?.split(')').next()?;
    (!runtime.is_empty() && !id.is_empty())
        .then(|| (runtime.to_string(), id.to_string()))
}

fn short_id(s: &str) -> String {
    s.chars().take(12).collect()
}

/// Strip characters that would break the `log show` predicate string
/// (names come from the process table, but be defensive anyway).
pub(crate) fn sanitize_predicate(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect()
}

/// PowerShell one-liner behind [`LogSource::EventLog`]: the last 30
/// minutes of Application+System warnings/errors that mention the pid or
/// the process name, rendered as `HH:mm:ss [level] one-line message`.
/// Built here (not inline) so tests can pin the exact command.
fn event_log_script(pid: Pid, name: &str) -> String {
    let name = sanitize_predicate(name);
    format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         Get-WinEvent -FilterHashtable @{{LogName=@('Application','System'); \
         Level=@(1,2,3); StartTime=(Get-Date).AddMinutes(-30)}} -MaxEvents 300 | \
         Where-Object {{ $_.Message -match '\\b{pid}\\b' -or $_.Message -like '*{name}*' }} | \
         Select-Object -First 25 | \
         ForEach-Object {{ '{{0:HH:mm:ss}} [{{1}}] {{2}}' -f $_.TimeCreated, \
         $_.LevelDisplayName, ($_.Message -replace '\\s+',' ') }}"
    )
}

/// Last `n` non-empty lines of `out`.
fn tail_lines(out: &str, n: usize) -> Vec<String> {
    let lines: Vec<String> = out.lines().filter(|l| !l.trim().is_empty()).map(String::from).collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].to_vec()
}

/// Fetch the last `n` log lines. Errors carry a human message suitable for
/// display as-is (the CLI prints it, the TUI shows it in the page).
pub fn fetch(src: &LogSource, n: usize) -> Result<Vec<String>, String> {
    match src {
        LogSource::Container { runtime, ref_ } => {
            let tail = format!("--tail={n}");
            let out = run(runtime, &["logs", &tail, ref_], FETCH_TIMEOUT)
                .map_err(|e| format!("{} logs: {e}", runtime))?;
            Ok(tail_lines(&out, n))
        }
        LogSource::Journald { pid } => {
            let filter = format!("_PID={pid}");
            let count = n.to_string();
            match run(
                "journalctl",
                &["--no-pager", "-n", &count, &filter],
                FETCH_TIMEOUT,
            ) {
                Ok(out) => Ok(tail_lines(&out, n)),
                // journalctl exits 1 when nothing matches — that's "no logs",
                // not a failure
                Err(e) if e.to_string().contains("exited with 1") => Ok(Vec::new()),
                Err(e) => Err(format!("journalctl: {e}")),
            }
        }
        LogSource::UnifiedLog { name } => {
            let pred = format!("process == \"{}\"", sanitize_predicate(name));
            let out = run(
                "log",
                &["show", "--last", "10m", "--predicate", &pred, "--style", "compact"],
                LOG_SHOW_TIMEOUT,
            )
            .map_err(|e| format!("log show: {e}"))?;
            // drop the "Filtering the log data using ..." preamble
            let lines: Vec<String> = out
                .lines()
                .filter(|l| !l.starts_with("Filtering") && !l.starts_with("Timestamp"))
                .map(String::from)
                .collect();
            let start = lines.len().saturating_sub(n);
            Ok(lines[start..]
                .iter()
                .filter(|l| !l.trim().is_empty())
                .cloned()
                .collect())
        }
        LogSource::EventLog { pid, name } => {
            let script = event_log_script(*pid, name);
            let out = run(
                "powershell",
                &["-NoProfile", "-Command", &script],
                FETCH_TIMEOUT,
            )
            .map_err(|e| format!("Get-WinEvent: {e}"))?;
            Ok(tail_lines(&out, n))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(container: Option<&str>, name: &str, pid: Pid) -> Process {
        Process {
            pid,
            name: name.into(),
            container: container.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn container_identity_parses() {
        let line = "docker: web (id abc123def456) [running]";
        assert_eq!(
            parse_container_identity(Some(line)),
            Some(("docker".into(), "abc123def456".into()))
        );
        assert_eq!(parse_container_identity(Some("no colon here")), None);
        assert_eq!(parse_container_identity(None), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn source_prefers_container_then_unified_log() {
        let p = proc(Some("podman: db (id deadbeef1234)"), "postgres", 7);
        assert_eq!(
            LogSource::for_process(&p),
            LogSource::Container { runtime: "podman".into(), ref_: "deadbeef1234".into() }
        );
        let bare = proc(None, "nginx", 9);
        assert_eq!(
            LogSource::for_process(&bare),
            LogSource::UnifiedLog { name: "nginx".into() }
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    #[test]
    fn source_prefers_container_then_journal() {
        let p = proc(Some("podman: db (id deadbeef1234)"), "postgres", 7);
        assert_eq!(
            LogSource::for_process(&p),
            LogSource::Container { runtime: "podman".into(), ref_: "deadbeef1234".into() }
        );
        let bare = proc(None, "nginx", 9);
        assert_eq!(LogSource::for_process(&bare), LogSource::Journald { pid: 9 });
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn source_prefers_container_then_event_log() {
        let p = proc(Some("docker: web (id deadbeef1234)"), "nginx", 7);
        assert_eq!(
            LogSource::for_process(&p),
            LogSource::Container { runtime: "docker".into(), ref_: "deadbeef1234".into() }
        );
        let bare = proc(None, "nginx", 9);
        assert_eq!(
            LogSource::for_process(&bare),
            LogSource::EventLog { pid: 9, name: "nginx".into() }
        );
    }

    #[test]
    fn event_log_script_shape() {
        let s = event_log_script(1234, "nginx-worker");
        assert!(s.starts_with("$ErrorActionPreference='SilentlyContinue';"));
        assert!(s.contains("LogName=@('Application','System')"));
        assert!(s.contains("\\b1234\\b"));
        assert!(s.contains("-like '*nginx-worker*'"));
        assert!(s.contains("AddMinutes(-30)"));
        // hostile names are neutralized before entering the query string
        let evil = event_log_script(1, "bad\"name;x'");
        assert!(evil.contains("-like '*badnamex*'"));
        assert!(!evil.contains("bad\"name"));
    }

    #[test]
    fn event_log_describe() {
        assert_eq!(
            LogSource::EventLog { pid: 42, name: "nginx".into() }.describe(),
            "event log (pid 42 / nginx)"
        );
    }

    #[test]
    fn tail_keeps_last_n_and_skips_blank() {
        let out = "a\n\nb\nc\nd";
        assert_eq!(tail_lines(out, 2), vec!["c".to_string(), "d".to_string()]);
        assert_eq!(tail_lines(out, 10).len(), 4);
        assert!(tail_lines("", 5).is_empty());
    }

    #[test]
    fn predicate_is_sanitized() {
        assert_eq!(sanitize_predicate("nginx-worker"), "nginx-worker");
        assert_eq!(sanitize_predicate("bad\"name\\x"), "badnamex");
    }

    #[test]
    fn describe_labels() {
        assert_eq!(
            LogSource::Container { runtime: "docker".into(), ref_: "abc123def456fff".into() }
                .describe(),
            "docker logs · abc123def456"
        );
        assert_eq!(
            LogSource::Journald { pid: 42 }.describe(),
            "journalctl (_PID=42)"
        );
    }
}
