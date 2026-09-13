use std::fmt::Write as _;

use crate::model::{Process, TargetReport};
use crate::util::{fmt_age, fmt_time};

/// Render the "no target" default view: every process in a table.
pub fn render_process_table(procs: &[Process], p: &Painter) -> String {
    let mut sorted: Vec<&Process> = procs.iter().collect();
    sorted.sort_by_key(|x| x.pid);
    let now = crate::util::now_unix();

    let mut rows: Vec<(String, String, String, String, String)> = Vec::with_capacity(sorted.len() + 1);
    rows.push((
        "PID".into(),
        "PPID".into(),
        "USER".into(),
        "AGE".into(),
        "NAME".into(),
    ));
    for pr in &sorted {
        rows.push((
            pr.pid.to_string(),
            pr.ppid.map(|x| x.to_string()).unwrap_or_else(|| "-".into()),
            pr.user.clone().unwrap_or_else(|| "-".into()),
            pr.started.map(|t| fmt_age(now - t)).unwrap_or_else(|| "-".into()),
            pr.name.clone(),
        ));
    }
    let w = [
        rows.iter().map(|r| r.0.chars().count()).max().unwrap_or(3),
        rows.iter().map(|r| r.1.chars().count()).max().unwrap_or(4),
        rows.iter().map(|r| r.2.chars().count()).max().unwrap_or(4),
        rows.iter().map(|r| r.3.chars().count()).max().unwrap_or(3),
    ];
    let mut out = String::new();
    let header = &rows[0];
    let _ = writeln!(
        out,
        "{:>w0$}  {:>w1$}  {:<w2$}  {:>w3$}  {}",
        p.bold(&header.0),
        p.bold(&header.1),
        p.bold(&header.2),
        p.bold(&header.3),
        p.bold(&header.4),
        w0 = w[0],
        w1 = w[1],
        w2 = w[2],
        w3 = w[3]
    );
    for r in rows.iter().skip(1) {
        let _ = writeln!(
            out,
            "{:>w0$}  {:>w1$}  {:<w2$}  {:>w3$}  {}",
            r.0,
            r.1,
            r.2,
            r.3,
            r.4,
            w0 = w[0],
            w1 = w[1],
            w2 = w[2],
            w3 = w[3]
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "{} process(es)", sorted.len());
    out
}

/// Render the "no target" `--tree` view: the full process forest.
pub fn render_process_forest(procs: &[Process], p: &Painter) -> String {
    use std::collections::HashMap;
    let by_pid: HashMap<i32, &Process> = procs.iter().map(|x| (x.pid, x)).collect();
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    let mut roots: Vec<i32> = Vec::new();
    for x in procs {
        match x.ppid {
            Some(ppid) if by_pid.contains_key(&ppid) && ppid != x.pid => {
                children.entry(ppid).or_default().push(x.pid);
            }
            _ => roots.push(x.pid),
        }
    }
    for list in children.values_mut() {
        list.sort_unstable();
    }
    roots.sort_unstable();

    let mut out = String::new();
    let label = |pid: i32| -> String {
        match by_pid.get(&pid) {
            Some(x) => {
                let user = x.user.as_deref().unwrap_or("-");
                format!("{} (pid {}, {})", x.name, x.pid, user)
            }
            None => format!("pid {}", pid),
        }
    };
    fn walk(
        pid: i32,
        prefix: &str,
        is_root: bool,
        is_last: bool,
        children: &HashMap<i32, Vec<i32>>,
        p: &Painter,
        out: &mut String,
        label: &dyn Fn(i32) -> String,
    ) {
        let branch = if is_root {
            String::new()
        } else if is_last {
            "└─ ".to_string()
        } else {
            "├─ ".to_string()
        };
        let _ = writeln!(out, "{}{}{}", p.dim(prefix), p.bold(&branch), label(pid));
        let kids = children.get(&pid).cloned().unwrap_or_default();
        let child_prefix = if is_root {
            String::new()
        } else if is_last {
            format!("{}   ", prefix)
        } else {
            format!("{}│  ", prefix)
        };
        for (i, kid) in kids.iter().enumerate() {
            walk(
                *kid,
                &child_prefix,
                false,
                i + 1 == kids.len(),
                children,
                p,
                out,
                label,
            );
        }
    }
    for r in roots.iter() {
        walk(*r, "", true, true, &children, p, &mut out, &label);
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "{} process(es)", procs.len());
    out
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Format {
    Standard,
    Tree,
    Short,
    Json,
}

/// Minimal ANSI painter; every method degrades to plain text when disabled.
pub struct Painter {
    enabled: bool,
}

impl Painter {
    pub fn new(enabled: bool) -> Self {
        Painter { enabled }
    }
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.enabled {
            format!("\x1b[{}m{}\x1b[0m", code, s)
        } else {
            s.to_string()
        }
    }
    pub fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    pub fn yellow(&self, s: &str) -> String {
        self.wrap("33", s)
    }
    pub fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }
}

pub fn render(reports: &[TargetReport], format: Format, color: bool) -> String {
    let p = Painter::new(color);
    match format {
        Format::Json => serde_json::to_string_pretty(reports).unwrap_or_else(|_| "[]".into()),
        Format::Short => reports
            .iter()
            .map(|r| render_short(r, &p))
            .collect::<Vec<_>>()
            .join("\n"),
        Format::Tree => reports
            .iter()
            .map(|r| render_tree(r, &p))
            .collect::<Vec<_>>()
            .join("\n\n"),
        Format::Standard => reports
            .iter()
            .map(|r| render_standard(r, &p))
            .collect::<Vec<_>>()
            .join("\n\n"),
    }
}

fn header(r: &TargetReport, p: &Painter) -> String {
    p.bold(&format!("== {} ==", r.target.describe()))
}

fn render_short(r: &TargetReport, p: &Painter) -> String {
    if !r.found {
        return format!(
            "{} {}",
            header(r, p),
            p.yellow(r.error.as_deref().unwrap_or("no match"))
        );
    }
    let mut lines = Vec::new();
    for m in &r.matches {
        let mut parts = vec![format!("{} (pid {})", m.name, m.pid)];
        if let Some(u) = &m.user {
            parts.push(format!("user {}", u));
        }
        let chain: Vec<String> = r
            .ancestry
            .iter()
            .map(|a| format!("{}({})", a.name, a.pid))
            .collect();
        parts.push(format!("chain: {}", chain.join(" ← ")));
        if let Some(s) = &r.source {
            let mut src = format!("source: {}", s.kind);
            if let Some(l) = &s.label {
                src.push_str(&format!("/{}", l));
            }
            parts.push(src);
        }
        if let Some(t) = m.started {
            parts.push(format!("started {} ago", fmt_age(crate::util::now_unix() - t)));
        }
        lines.push(parts.join(" · "));
    }
    let warn = if r.warnings.is_empty() {
        String::new()
    } else {
        format!(" {}", p.yellow(&format!("⚠ {} warning(s)", r.warnings.len())))
    };
    lines.iter().map(|l| format!("{}{}{}{}", header(r, p), " ", l, warn)).collect::<Vec<_>>().join("\n")
}

fn render_standard(r: &TargetReport, p: &Painter) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}", header(r, p));
    if !r.found {
        let _ = writeln!(
            out,
            "  {}",
            p.yellow(r.error.as_deref().unwrap_or("no process matched"))
        );
        return out;
    }

    for (i, m) in r.matches.iter().enumerate() {
        if i > 0 {
            let _ = writeln!(out);
        }
        let mut title = format!("{} — pid {}", m.name, m.pid);
        if let Some(u) = &m.user {
            title.push_str(&format!(" (user {})", u));
        }
        let _ = writeln!(out, "{}", p.bold(&title));
        if let Some(t) = m.started {
            let _ = writeln!(
                out,
                "  started {}",
                fmt_started_line(t)
            );
        }
        if let Some(cwd) = &m.cwd {
            let _ = writeln!(out, "  cwd {}", cwd);
        }
        if let Some(exe) = &m.exe {
            let mut exe_line = format!("  exe {}", exe);
            if m.exe_deleted {
                exe_line.push_str(&p.yellow("  [deleted from disk]"));
            }
            let _ = writeln!(out, "{}", exe_line);
        }
        if !m.cmdline.is_empty() {
            let _ = writeln!(out, "  cmd {}", m.command_line());
        }
        if let Some(env) = &m.env {
            let _ = writeln!(out, "  env {} variables (use --json for values)", env.len());
        }

        if let Some(s) = &r.source {
            let _ = writeln!(out);
            let _ = writeln!(out, "  {}", p.green("started by:"));
            let mut line = format!("    {} {}", s.kind, s.label.clone().unwrap_or_default());
            if let Some(d) = &s.detail {
                line.push_str(&format!(" — {}", d));
            }
            let _ = writeln!(out, "{}", line.trim_end());
        }

        if r.ancestry.len() > 1 || r.matches.len() != r.ancestry.len() {
            let _ = writeln!(out);
            let _ = writeln!(out, "  {}", p.dim("chain (root → this):"));
            let last = r.ancestry.len().saturating_sub(1);
            for (depth, a) in r.ancestry.iter().enumerate() {
                let branch = if depth == 0 {
                    String::new()
                } else {
                    format!("{}└─ ", "   ".repeat(depth - 1))
                };
                let marker = if depth == last { "  ← this" } else { "" };
                let user = a.user.clone().unwrap_or_default();
                let _ = writeln!(
                    out,
                    "    {}{} {}{}",
                    p.dim(&branch),
                    p.bold(&format!("{:<18}", a.name)),
                    p.dim(&format!("pid {:<7}", a.pid)),
                    if marker.is_empty() {
                        p.dim(&user)
                    } else {
                        format!("{} {}", user, p.green(marker))
                    }
                );
            }
        }

        if !r.sockets.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "  {}", p.dim("sockets:"));
            for s in &r.sockets {
                let mut line = format!("    {:<5} {}:{}", s.proto, s.local_addr, s.local_port);
                if let (Some(pa), Some(pp)) = (&s.peer_addr, s.peer_port) {
                    line.push_str(&format!(" → {}:{}", pa, pp));
                }
                line.push_str(&format!(" {}", s.state));
                let _ = writeln!(out, "{}", line);
            }
        }

        if !r.children.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "  {} ({}):", p.dim("children"), r.children.len());
            for c in &r.children {
                let _ = writeln!(out, "    pid {:<7} {}", c.pid, c.name);
            }
        }
    }

    if let Some(risk) = &r.risk {
        if risk.score > 0 {
            let _ = writeln!(
                out,
                "  {} risk {}/10: {}",
                p.yellow("⚠"),
                risk.score,
                risk.signals.join("; ")
            );
        }
    }

    if !r.warnings.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "  {}", p.yellow("warnings:"));
        for w in &r.warnings {
            let _ = writeln!(out, "  {} {}", p.yellow("⚠"), w);
        }
    }
    out.trim_end().to_string() + "\n"
}

/// Plain-text diagnostic report (the `--export` flag): everything the TUI
/// detail page shows, including env values and open files, for pasting
/// into issues.
pub fn render_export(reports: &[TargetReport], files: &[(crate::model::Pid, Vec<String>)]) -> String {
    let mut out = String::new();
    for r in reports {
        let _ = writeln!(out, "== witr-rs report: {} ==", r.target.describe());
        if !r.found {
            let _ = writeln!(
                out,
                "  {}",
                r.error.as_deref().unwrap_or("no process matched")
            );
            out.push('\n');
            continue;
        }
        let m = &r.matches[0];
        fn kv(out: &mut String, k: &str, v: String) {
            let _ = writeln!(out, "{:<10}{}", format!("{k}:"), v);
        }
        kv(&mut out, "pid", m.pid.to_string());
        if let Some(pp) = m.ppid {
            kv(&mut out, "ppid", pp.to_string());
        }
        if let Some(u) = &m.user {
            kv(&mut out, "user", u.clone());
        }
        if let Some(t) = m.started {
            kv(&mut out, "started", fmt_started_line(t));
        }
        if let Some(cwd) = &m.cwd {
            kv(&mut out, "cwd", cwd.clone());
        }
        if let Some(exe) = &m.exe {
            let mut line = exe.clone();
            if m.exe_deleted {
                line.push_str("  [deleted from disk]");
            }
            kv(&mut out, "exe", line);
        }
        if !m.cmdline.is_empty() {
            kv(&mut out, "cmd", m.command_line());
        }
        if let Some(s) = &r.source {
            let mut line = format!("{} {}", s.kind, s.label.clone().unwrap_or_default());
            if let Some(d) = &s.detail {
                line.push_str(&format!(" — {d}"));
            }
            kv(&mut out, "started by", line.trim_end().to_string());
        }
        if r.ancestry.len() > 1 {
            kv(&mut out, "chain", "root → this".to_string());
            let last = r.ancestry.len() - 1;
            for (i, a) in r.ancestry.iter().enumerate() {
                let branch = if i == 0 {
                    String::new()
                } else {
                    format!("{}└─ ", "   ".repeat(i - 1))
                };
                let marker = if i == last { "  ← this" } else { "" };
                let _ = writeln!(
                    out,
                    "  {}{} (pid {}){}",
                    branch,
                    a.name,
                    a.pid,
                    marker
                );
            }
        }
        if !r.sockets.is_empty() {
            kv(&mut out, "sockets", format!("{} (see below)", r.sockets.len()));
        }
        if let Some(risk) = &r.risk {
            if risk.score > 0 {
                kv(
                    &mut out,
                    "risk",
                    format!("{}/10 — {}", risk.score, risk.signals.join("; ")),
                );
            }
        }
        if !r.warnings.is_empty() {
            kv(&mut out, "warnings", String::new());
            for w in &r.warnings {
                let _ = writeln!(out, "  ⚠ {w}");
            }
        }
        if let Some(env) = &m.env {
            if !env.is_empty() {
                kv(&mut out, "environment", format!("{} variables", env.len()));
                for (k, v) in env.iter().take(60) {
                    let _ = writeln!(out, "  {k}={v}");
                }
                if env.len() > 60 {
                    let _ = writeln!(out, "  … {} more", env.len() - 60);
                }
            }
        }
        if let Some((_, fs)) = files.iter().find(|(pid, _)| Some(*pid) == Some(m.pid)) {
            if !fs.is_empty() {
                kv(&mut out, "open files", format!("{}", fs.len()));
                for f in fs.iter().take(50) {
                    let _ = writeln!(out, "  {f}");
                }
                if fs.len() > 50 {
                    let _ = writeln!(out, "  … {} more", fs.len() - 50);
                }
            }
        }
        out.push('\n');
    }
    out
}

fn fmt_started_line(t: i64) -> String {
    let now = crate::util::now_unix();
    format!("{} ({} ago)", fmt_time(t), fmt_age(now - t))
}

fn render_tree(r: &TargetReport, p: &Painter) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}", header(r, p));
    if !r.found {
        let _ = writeln!(
            out,
            "  {}",
            p.yellow(r.error.as_deref().unwrap_or("no process matched"))
        );
        return out;
    }
    let matched_pids: Vec<i32> = r.matches.iter().map(|m| m.pid).collect();
    let last = r.ancestry.len().saturating_sub(1);
    for (depth, a) in r.ancestry.iter().enumerate() {
        let is_match = matched_pids.contains(&a.pid);
        let prefix = if depth == 0 {
            String::new()
        } else {
            format!("{}└─ ", "  ".repeat(depth - 1))
        };
        let star = if is_match { p.green(" ★") } else { String::new() };
        let user = a.user.as_deref().unwrap_or("?");
        let _ = writeln!(
            out,
            "  {}{}{} (pid {}, {})",
            p.dim(&prefix),
            p.bold(&a.name),
            star,
            a.pid,
            user
        );
        let _ = last;
    }
    // children of the matched process(es)
    if !r.children.is_empty() {
        let indent = "  ".repeat(r.ancestry.len()) + "  ";
        for (i, c) in r.children.iter().enumerate() {
            let branch = if i + 1 == r.children.len() { "└─ " } else { "├─ " };
            let _ = writeln!(out, "{}{}{} (pid {})", indent, p.dim(branch), c.name, c.pid);
        }
    }
    if !r.warnings.is_empty() {
        let _ = writeln!(out);
        for w in &r.warnings {
            let _ = writeln!(out, "  {} {}", p.yellow("⚠"), w);
        }
    }
    out
}
