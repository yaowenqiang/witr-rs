//! `--doctor`: the environment self-check. Every optional capability the
//! tool can use — probed live, reported with the reason it's missing and
//! the flags that go silent without it. The "honest absence" philosophy
//! made visible: absence is fine, but it should be findable in one
//! command instead of documented-and-guessed.

use serde::Serialize;

/// One capability's verdict.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    /// Short capability name ("systemd", "nvidia-smi", "containers"...).
    pub name: String,
    pub ok: bool,
    /// The human reason — what was probed and what answered (or didn't).
    pub detail: String,
    /// The flags/surfaces that go quiet without this capability.
    pub silent: String,
}

fn check(name: &str, ok: bool, detail: String, silent: &str) -> DoctorCheck {
    DoctorCheck {
        name: name.to_string(),
        ok,
        detail,
        silent: silent.to_string(),
    }
}

/// Probe one external command: ok when it runs and exits successfully.
#[cfg(any(unix, windows, test))]
fn probe_cmd(cmd: &str, args: &[&str]) -> (bool, String) {
    match crate::util::run_ok(cmd, args, std::time::Duration::from_secs(8)) {
        Some(_) => (true, format!("{cmd} answered")),
        None => (false, format!("{cmd} not found or failed")),
    }
}

/// The whole check list for this platform. Every entry is best-effort —
/// a probe failure IS the report, never an error.
pub fn run_checks() -> Vec<DoctorCheck> {
    let mut out = Vec::new();

    // privileges first: they color everything else
    #[cfg(unix)]
    {
        let root = crate::util::run_ok("id", &["-u"], std::time::Duration::from_secs(3))
            .map(|o| o.trim() == "0")
            .unwrap_or(false);
        out.push(if root {
            check("root", true, "running as root — every /proc field visible".into(),
                "not root hides other users' fds/envs (affects --env, fd counts)")
        } else {
            check("root", false, "not running as root — some processes hide".into(),
                "other users' fds/envs stay hidden (affects --env, fd counts)")
        });
    }

    #[cfg(target_os = "linux")]
    {
        // systemd: presence and state are two separate questions —
        // is-system-running exits nonzero on a degraded boot (this very
        // box!), which once read as "systemctl not found"
        let (ok, detail) = match crate::util::run_ok(
            "systemctl",
            &["--version"],
            std::time::Duration::from_secs(5),
        ) {
            None => (false, "systemctl not found".into()),
            Some(version) => {
                let v = version.lines().next().unwrap_or("systemd").trim().to_string();
                // show -p exits 0 even on a degraded boot (unlike
                // is-system-running, which fails exactly when the news
                // is bad)
                let state = crate::util::run_ok(
                    "systemctl",
                    &["show", "-p", "SystemState", "--value", "--no-pager"],
                    std::time::Duration::from_secs(5),
                );
                let state = state.as_deref().map(str::trim).unwrap_or_default();
                let detail = match state {
                    "running" => format!("{v} — running"),
                    "degraded" => format!("{v} — running (degraded: some units failed)"),
                    other if !other.is_empty() => format!("{v} — {other}"),
                    _ => format!("{v} — state unreadable (booting or offline)"),
                };
                (true, detail)
            }
        };
        out.push(check(
            "systemd",
            ok,
            detail,
            "--services, --alert-failed-units, -u reports, failed-units gauge & fleet list",
        ));

        // journalctl readability: permissions decide, not presence
        let (ok, detail) = match crate::util::run_ok(
            "journalctl",
            &["-n", "1", "--no-pager"],
            std::time::Duration::from_secs(5),
        ) {
            Some(_) => (true, "journal readable".into()),
            None => (
                false,
                "journal not readable (permissions — try the systemd-journal group or root)".into(),
            ),
        };
        out.push(check(
            "journalctl",
            ok,
            detail,
            "--logs (journald), --alert-oom victim naming, -u journal tails, follow",
        ));

        // ss: per-pid network rates
        let (ok, detail) = probe_cmd("ss", &["-V"]);
        out.push(check("ss", ok, detail, "--top net, --alert-net-per-proc, per-pid net rates"));

        // cgroup v2: container pressure reads
        let cgv2 = std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
        out.push(check(
            "cgroup v2",
            cgv2,
            if cgv2 {
                "unified hierarchy mounted".into()
            } else {
                "no unified hierarchy (cgroup v1 or none) — container pressure unreadable".into()
            },
            "container THR%/OOM/io attribution, witr_container_* pressure series",
        ));
    }

    #[cfg(target_os = "macos")]
    {
        let (ok, detail) = probe_cmd("launchctl", &["list"]);
        out.push(check(
            "launchctl",
            ok,
            detail,
            "Services tab, --services, -u reports, --alert-failed-units, --services --failed",
        ));
        let (ok, detail) = probe_cmd("log", &["show", "--last", "1m"]);
        out.push(check(
            "unified log",
            ok,
            detail,
            "--logs (unified log view + follow)",
        ));
    }

    #[cfg(windows)]
    {
        let (ok, detail) = probe_cmd(
            "powershell",
            &["-NoProfile", "-Command", "Get-CimInstance Win32_Service | Select-Object -First 1 Name"],
        );
        out.push(check(
            "SCM (services)",
            ok,
            detail,
            "Services tab, --services, -u reports, --alert-failed-units",
        ));
    }

    // cross-platform optional machinery
    let (ok, detail) = probe_cmd("nvidia-smi", &["-L"]);
    out.push(check(
        "nvidia-smi",
        ok,
        detail,
        "GPU columns, --top gpu/gpu-mem, --alert-gpu-mem-pct, GPU metrics & panel",
    ));

    let mut runtime_found = None;
    for rt in ["docker", "podman", "nerdctl"] {
        let (ok, _) = probe_cmd(rt, &["ps"]);
        if ok {
            runtime_found = Some(rt);
            break;
        }
    }
    out.push(match runtime_found {
        Some(rt) => check("containers", true, format!("{rt} answered"), ""),
        None => check(
            "containers",
            false,
            "no runtime answering on PATH (tried docker / podman / nerdctl)".into(),
            "Containers tab, -c targets, --alert-container family, per-device container IO",
        ),
    });

    let (ok, detail) = probe_cmd("kubectl", &["version", "--client"]);
    out.push(check(
        "kubectl",
        ok,
        detail,
        "k8s pod attribution on container rows (namespace/name, crash-loop reasons)",
    ));

    let (ok, detail) = probe_cmd("git", &["--version"]);
    out.push(check(
        "git",
        ok,
        detail,
        "git repo/branch attribution in the process table",
    ));

    out
}

/// The `--doctor` text report: one line per check, ✔/✗-marked, with the
/// silent-flags column rendered dim.
pub fn render_checks(checks: &[DoctorCheck], p: &crate::render::Painter) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let name_w = checks
        .iter()
        .map(|c| c.name.len())
        .max()
        .unwrap_or(4)
        .clamp(4, 24);
    let ok_n = checks.iter().filter(|c| c.ok).count();
    let _ = writeln!(
        out,
        "{} capability check · {} available · {} silent",
        p.bold("witr-rs doctor"),
        ok_n,
        checks.len() - ok_n
    );
    for c in checks {
        let mark = if c.ok { p.green("✔") } else { p.red("✗") };
        let _ = writeln!(
            out,
            "{} {:<name_w$}  {}",
            mark,
            p.bold(&c.name),
            c.detail
        );
        if !c.ok && !c.silent.is_empty() {
            let _ = writeln!(out, "      {} {}", p.yellow("silent:"), c.silent);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_marks_missing_and_names_the_silent_flags() {
        let checks = vec![
            check("systemd", true, "systemd running".into(),
                "--services, --alert-failed-units, -u reports"),
            check("nvidia-smi", false, "nvidia-smi not found or failed".into(),
                "GPU columns, --top gpu/gpu-mem, --alert-gpu-mem-pct"),
        ];
        let p = crate::render::Painter::new(false);
        let text = render_checks(&checks, &p);
        // available: ticked, no silent note
        assert!(text.contains("✔ systemd"), "{text}");
        assert!(text.contains("systemd running"), "{text}");
        // missing: crossed, the reason, and what goes quiet
        assert!(text.contains("✗ nvidia-smi"), "{text}");
        assert!(text.contains("silent:"), "{text}");
        assert!(text.contains("--alert-gpu-mem-pct"), "{text}");
        // the summary counts
        assert!(text.contains("1 available · 1 silent"), "{text}");
        // json shape: serializes with the four keys
        let json = serde_json::to_string(&checks).unwrap();
        assert!(json.contains("\"ok\":false") && json.contains("\"silent\""), "{json}");
    }
}
