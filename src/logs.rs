//! Recent log lines for a traced process or container — the "why does it
//! keep restarting" follow-up after the Events tab flags a crash loop.
//!
//! Sources, in priority order: a container identity (runtime CLI `logs`)
//! when the process is attributed to one, then the platform log system
//! (journald filtered by `_PID=` on Linux, the unified log filtered by
//! process name on macOS). Windows has no equivalent single source yet.

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
        #[cfg(not(target_os = "macos"))]
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
fn sanitize_predicate(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .collect()
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

    #[cfg(not(target_os = "macos"))]
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
