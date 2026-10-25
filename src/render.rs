use std::collections::HashMap;
use std::fmt::Write as _;

use crate::model::{Pid, Process, TargetReport};
use crate::util::{fmt_age, fmt_time};

/// One-line explanation for a socket state, shown for `--port` targets
/// where the state itself is the interesting part.
pub fn socket_explanation(state: &str) -> Option<&'static str> {
    match state {
        "LISTEN" => Some("listening for connections"),
        "ESTABLISHED" => Some("active connection"),
        "TIME_WAIT" => Some("connection closed, waiting for delayed packets"),
        "CLOSE_WAIT" => Some("remote side closed; the app has not close()d yet"),
        "FIN_WAIT_1" | "FIN_WAIT_2" | "FIN_WAIT" => {
            Some("local close in progress, waiting for the remote end")
        }
        "SYN_SENT" => Some("connecting (no response yet)"),
        "SYN_RECV" => Some("connection attempt received"),
        "LAST_ACK" => Some("closing, waiting for the final acknowledgment"),
        _ => None,
    }
}

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
    #[allow(clippy::too_many_arguments)]
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
    Warnings,
    EnvOnly,
    Json,
}

/// Escape one RFC-4180 CSV field: quotes double, anything containing a
/// comma, quote or newline gets wrapped in quotes.
pub fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// `--ports`: the listener table — one row per (proto, port), owners
/// comma-joined, plus the exposure SCOPE (internet / loopback / iface /
/// unknown). Empty input prints the nothing-to-see note.
pub fn render_listeners(
    listeners: &[crate::snapshot::Listener],
    p: &Painter,
) -> String {
    if listeners.is_empty() {
        return "(no listening sockets with a visible owner)\n".to_string();
    }
    let port_w = listeners.iter().map(|l| l.port.to_string().len()).max().unwrap_or(4);
    let proto_w = listeners.iter().map(|l| l.proto.len()).max().unwrap_or(5).max(5);
    let scope_w = listeners
        .iter()
        .map(|l| l.scope().len())
        .max()
        .unwrap_or(4)
        .max(5);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:>port_w$}  {:proto_w$}  {:scope_w$}  OWNER(S)",
        "PORT", "PROTO", "SCOPE"
    );
    for l in listeners {
        let scope = l.scope();
        let scope_cell = match scope {
            "internet" => p.yellow(scope),
            "loopback" => p.dim(scope),
            _ => scope.to_string(),
        };
        let _ = writeln!(
            out,
            "{:>port_w$}  {:proto_w$}  {scope_cell:scope_w$}  {}",
            p.bold(&l.port.to_string()),
            p.dim(&l.proto),
            l.who.join(", "),
        );
    }
    out
}

/// `--ports --csv`: the same rows as RFC-4180 (owners are "; "-joined so
/// the comma stays a field separator; scope rides as the last column).
pub fn render_listeners_csv(listeners: &[crate::snapshot::Listener]) -> String {
    let mut out = String::from("port,proto,owners,scope\n");
    for l in listeners {
        out.push_str(&format!(
            "{},{},{},{}\n",
            l.port,
            csv_field(&l.proto),
            csv_field(&l.who.join("; ")),
            l.scope(),
        ));
    }
    out
}

/// One `--by-name` aggregate row: every visible process sharing a
/// (name, user) identity folded into totals.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NameGroup {
    pub name: String,
    pub user: String,
    /// How many processes share this identity.
    pub count: usize,
    /// Σ of the platform-reported (lifetime-average) CPU percent.
    pub cpu_pct: f64,
    /// Σ resident memory, MiB.
    pub rss_mb: u64,
    /// Σ cumulative CPU time, milliseconds — the honest "total cost".
    pub cpu_time_ms: u64,
    /// Age in seconds of the oldest instance in the group.
    pub oldest_secs: Option<i64>,
}

/// Fold the visible table into `--by-name` groups, busiest (by total RSS)
/// first.
pub fn aggregate_by_name(procs: &[Process]) -> Vec<NameGroup> {
    let now = crate::util::now_unix();
    let mut map: std::collections::HashMap<(String, String), NameGroup> =
        std::collections::HashMap::new();
    for p in procs {
        let key = (
            p.name.clone(),
            p.user.clone().unwrap_or_else(|| "-".into()),
        );
        let g = map.entry(key).or_insert(NameGroup {
            name: p.name.clone(),
            user: p.user.clone().unwrap_or_else(|| "-".into()),
            count: 0,
            cpu_pct: 0.0,
            rss_mb: 0,
            cpu_time_ms: 0,
            oldest_secs: None,
        });
        g.count += 1;
        g.cpu_pct += p.cpu.unwrap_or(0.0);
        g.rss_mb += p.mem_kb.unwrap_or(0) / 1024;
        g.cpu_time_ms += p.cpu_time_ms.unwrap_or(0);
        if let Some(s) = p.started {
            let age = now - s;
            g.oldest_secs = Some(g.oldest_secs.map_or(age, |o: i64| o.max(age)));
        }
    }
    let mut out: Vec<NameGroup> = map.into_values().collect();
    out.sort_by(|a, b| {
        b.rss_mb
            .cmp(&a.rss_mb)
            .then_with(|| {
                b.cpu_pct
                    .partial_cmp(&a.cpu_pct)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.user.cmp(&b.user))
    });
    out
}

/// `--by-name`: one row per (name, user) identity with folded totals.
pub fn render_by_name(groups: &[NameGroup], p: &Painter) -> String {
    if groups.is_empty() {
        return "(no processes)\n".to_string();
    }
    // column widths from the data, capped so one absurd process name (some
    // comm fields are whole command lines) doesn't stretch every row
    let name_w = groups
        .iter()
        .map(|g| g.name.len())
        .max()
        .unwrap_or(4)
        .clamp(4, 48);
    let user_w = groups
        .iter()
        .map(|g| g.user.len())
        .max()
        .unwrap_or(4)
        .clamp(4, 24);
    let n_w = groups
        .iter()
        .map(|g| g.count.to_string().len())
        .max()
        .unwrap_or(1)
        .max(1);
    let trunc = |s: &str, w: usize| -> String {
        if s.len() > w {
            let mut t: String = s.chars().take(w.saturating_sub(1)).collect();
            t.push('…');
            t
        } else {
            s.to_string()
        }
    };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<name_w$}  {:<user_w$}  {:>n_w$}  {:>7}  {:>8}  {:>9}  AGE(OLDEST)",
        "NAME", "USER", "N", "ΣCPU%", "ΣRSS MB", "ΣCPUTIME"
    );
    for g in groups {
        let _ = writeln!(
            out,
            "{:<name_w$}  {:<user_w$}  {:>n_w$}  {:>7.1}  {:>8}  {:>9}  {}",
            p.bold(&trunc(&g.name, name_w)),
            p.dim(&trunc(&g.user, user_w)),
            g.count,
            g.cpu_pct,
            g.rss_mb,
            fmt_age((g.cpu_time_ms / 1000) as i64),
            g.oldest_secs.map(fmt_age).unwrap_or_default(),
        );
    }
    out
}

/// `--by-name --csv`: the same folded rows, RFC-4180.
pub fn render_by_name_csv(groups: &[NameGroup]) -> String {
    let mut out = String::from(
        "name,user,count,cpu_pct,rss_mb,cpu_time_ms,oldest_age_secs\n",
    );
    for g in groups {
        out.push_str(&format!(
            "{},{},{},{:.1},{},{},{}\n",
            csv_field(&g.name),
            csv_field(&g.user),
            g.count,
            g.cpu_pct,
            g.rss_mb,
            g.cpu_time_ms,
            g.oldest_secs
                .map(|s| s.to_string())
                .unwrap_or_default(),
        ));
    }
    out
}

/// `--by-name --markdown`: the folded rows as a paste-ready pipe table.
pub fn render_by_name_markdown(groups: &[NameGroup]) -> String {
    let mut out = String::from(
        "| NAME | USER | N | ΣCPU% | ΣRSS MB | ΣCPUTIME | AGE(OLDEST) |\n\
         |---|---|---:|---:|---:|---:|---|\n",
    );
    for g in groups {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {:.1} | {} | {} | {} |",
            g.name,
            g.user,
            g.count,
            g.cpu_pct,
            g.rss_mb,
            fmt_age((g.cpu_time_ms / 1000) as i64),
            g.oldest_secs.map(fmt_age).unwrap_or_default(),
        );
    }
    out
}

/// One `--zombies` row: a dead-but-unreaped process plus its parent (the
/// process whose job it is to reap it — the fix is almost always there).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ZombieRow {
    pub pid: Pid,
    pub name: String,
    pub ppid: Option<Pid>,
    /// Parent's process name; None when the parent isn't in the table
    /// (already exited — its zombie should have been reparented and reaped,
    /// so a lingering one here is the interesting case).
    pub parent: Option<String>,
    pub age_secs: Option<i64>,
}

/// Filter the table to zombies (state Z) and resolve each one's parent
/// name. Oldest first — the three-day-old zombie is the interesting one.
pub fn collect_zombies(procs: &[Process]) -> Vec<ZombieRow> {
    let names: HashMap<Pid, String> = procs.iter().map(|p| (p.pid, p.name.clone())).collect();
    let mut rows: Vec<ZombieRow> = procs
        .iter()
        .filter(|p| p.state.as_deref() == Some("Z"))
        .map(|p| ZombieRow {
            pid: p.pid,
            name: p.name.clone(),
            ppid: p.ppid,
            parent: p.ppid.and_then(|pp| names.get(&pp).cloned()),
            age_secs: p.started.map(|t| crate::util::now_unix() - t),
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.age_secs));
    rows
}

/// `--zombies` text table: PID / NAME / PARENT / AGE, oldest first.
pub fn render_zombies(rows: &[ZombieRow], p: &Painter) -> String {
    if rows.is_empty() {
        return "no zombie processes — clean\n".to_string();
    }
    let pid_w = rows.iter().map(|r| r.pid.to_string().len()).max().unwrap_or(3).max(3);
    let name_w = rows.iter().map(|r| r.name.len()).max().unwrap_or(4).clamp(4, 48);
    let parent_w = rows
        .iter()
        .map(|r| {
            r.parent
                .as_ref()
                .map(|n| n.len() + 8)
                .unwrap_or_else(|| "(gone)".len())
        })
        .max()
        .unwrap_or(6)
        .clamp(6, 48);
    let mut out = String::new();
    let pid_h = "PID";
    let name_h = "NAME";
    let parent_h = "PARENT";
    let age_h = "AGE";
    let _ = writeln!(
        out,
        "{pid_h:>pid_w$}  {name_h:<name_w$}  {parent_h:<parent_w$}  {age_h}"
    );
    for r in rows {
        let parent = match (&r.parent, r.ppid) {
            (Some(n), Some(pp)) => format!("{n} (pid {pp})"),
            (Some(n), None) => n.clone(),
            (None, Some(pp)) => format!("(pid {pp})"),
            (None, None) => "(gone)".to_string(),
        };
        let _ = writeln!(
            out,
            "{:>pid_w$}  {:<name_w$}  {}  {}",
            r.pid,
            r.name,
            p.yellow(&parent),
            r.age_secs.map(fmt_age).unwrap_or_default(),
        );
    }
    out
}

/// `--zombies --csv`: age as raw seconds (scripts diff it, not read it);
/// the parent stays split into pid + name so jq can group by either.
pub fn render_zombies_csv(rows: &[ZombieRow]) -> String {
    let mut out = String::from("pid,name,parent_pid,parent,age_secs\n");
    for r in rows {
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            r.pid,
            csv_field(&r.name),
            r.ppid.map(|p| p.to_string()).unwrap_or_default(),
            csv_field(r.parent.as_deref().unwrap_or("")),
            r.age_secs.map(|a| a.to_string()).unwrap_or_default(),
        ));
    }
    out
}

/// `--zombies --markdown`: the same rows, human-format ages.
pub fn render_zombies_markdown(rows: &[ZombieRow]) -> String {
    let mut out = String::from("| PID | NAME | PARENT | AGE |\n|---|---|---|---|\n");
    for r in rows {
        let parent = match (&r.parent, r.ppid) {
            (Some(n), Some(pp)) => format!("{n} (pid {pp})"),
            (Some(n), None) => n.clone(),
            (None, Some(pp)) => format!("(pid {pp})"),
            (None, None) => "(gone)".to_string(),
        };
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            r.pid,
            r.name,
            parent,
            r.age_secs.map(fmt_age).unwrap_or_default(),
        );
    }
    out
}

/// `--locks` text table: PID / OWNER / MODE / TYPE / PATH, pid then path.
pub fn render_locks_table(entries: &[crate::model::LockEntry], p: &Painter) -> String {
    if entries.is_empty() {
        return "no file locks found\n".to_string();
    }
    let mut sorted: Vec<&crate::model::LockEntry> = entries.iter().collect();
    sorted.sort_by_key(|l| (l.pid.unwrap_or(0), l.path.clone()));
    let pid_w = sorted
        .iter()
        .map(|l| l.pid.map(|p| p.to_string().len()).unwrap_or(1))
        .max()
        .unwrap_or(3)
        .max(3);
    let owner_w = sorted
        .iter()
        .map(|l| l.owner.len())
        .max()
        .unwrap_or(5)
        .clamp(5, 32);
    let mode_w = sorted.iter().map(|l| l.mode.len()).max().unwrap_or(4).max(4);
    let kind_w = sorted.iter().map(|l| l.kind.len()).max().unwrap_or(5).max(5);
    let mut out = String::new();
    let pid_h = "PID";
    let owner_h = "OWNER";
    let mode_h = "MODE";
    let kind_h = "TYPE";
    let path_h = "PATH";
    let _ = writeln!(
        out,
        "{pid_h:>pid_w$}  {owner_h:<owner_w$}  {mode_h:<mode_w$}  {kind_h:<kind_w$}  {path_h}"
    );
    for l in sorted {
        let _ = writeln!(
            out,
            "{:>pid_w$}  {:<owner_w$}  {:<mode_w$}  {:<kind_w$}  {}",
            l.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
            p.dim(&l.owner),
            l.mode,
            l.kind,
            l.path,
        );
    }
    out
}

/// `--locks --csv` / `--locks --markdown`: the same (pid, path)-sorted rows
/// as the text table, machine-readable. Locks with no resolvable pid keep
/// the empty field.
fn sorted_locks(entries: &[crate::model::LockEntry]) -> Vec<&crate::model::LockEntry> {
    let mut sorted: Vec<&crate::model::LockEntry> = entries.iter().collect();
    sorted.sort_by_key(|l| (l.pid.unwrap_or(0), l.path.clone()));
    sorted
}

pub fn render_locks_csv(entries: &[crate::model::LockEntry]) -> String {
    let mut out = String::from("pid,owner,mode,type,path\n");
    for l in sorted_locks(entries) {
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            l.pid.map(|p| p.to_string()).unwrap_or_default(),
            csv_field(&l.owner),
            csv_field(&l.mode),
            csv_field(&l.kind),
            csv_field(&l.path),
        ));
    }
    out
}

pub fn render_locks_markdown(entries: &[crate::model::LockEntry]) -> String {
    let mut out = String::from("| PID | OWNER | MODE | TYPE | PATH |\n|---|---|---|---|---|\n");
    for l in sorted_locks(entries) {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            l.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
            l.owner,
            l.mode,
            l.kind,
            l.path,
        );
    }
    out
}

/// Shared `--services` row order: running units (a main pid in hand) float
/// to the top — `| head` on a long launchd listing still shows the live
/// ones — then manager, then name, case-insensitively. Applied by the
/// dispatch so all four formats agree.
pub fn sort_services(svcs: &mut [crate::model::Service]) {
    svcs.sort_by(|a, b| {
        (a.pid.is_none(), a.manager.as_str(), a.name.to_lowercase())
            .cmp(&(b.pid.is_none(), b.manager.as_str(), b.name.to_lowercase()))
    });
}

/// `--services` text table: MANAGER / NAME / STATE / PID / DESCRIPTION.
pub fn render_services(svcs: &[crate::model::Service], p: &Painter) -> String {
    if svcs.is_empty() {
        return "no services reported (is a service manager running?)\n".to_string();
    }
    let mgr_w = svcs.iter().map(|s| s.manager.len()).max().unwrap_or(7).max(7);
    let name_w = svcs
        .iter()
        .map(|s| s.name.len())
        .max()
        .unwrap_or(4)
        .clamp(4, 48);
    let state_w = svcs.iter().map(|s| s.state.len()).max().unwrap_or(5).max(5);
    let pid_w = svcs
        .iter()
        .map(|s| s.pid.map(|p| p.to_string().len()).unwrap_or(1))
        .max()
        .unwrap_or(3)
        .max(3);
    let mut out = String::new();
    let mgr_h = "MANAGER";
    let name_h = "NAME";
    let state_h = "STATE";
    let pid_h = "PID";
    let desc_h = "DESCRIPTION";
    let _ = writeln!(
        out,
        "{mgr_h:<mgr_w$}  {name_h:<name_w$}  {state_h:<state_w$}  {pid_h:>pid_w$}  {desc_h}"
    );
    for s in svcs {
        let _ = writeln!(
            out,
            "{:<mgr_w$}  {:<name_w$}  {:<state_w$}  {:>pid_w$}  {}",
            s.manager,
            s.name,
            p.dim(&s.state),
            s.pid.map(|pid| pid.to_string()).unwrap_or_else(|| "-".into()),
            s.desc,
        );
    }
    out
}

/// `--services --csv`: one row per unit (empty pid = not running).
pub fn render_services_csv(svcs: &[crate::model::Service]) -> String {
    let mut out = String::from("manager,name,state,pid,desc\n");
    for s in svcs {
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            csv_field(&s.manager),
            csv_field(&s.name),
            csv_field(&s.state),
            s.pid.map(|p| p.to_string()).unwrap_or_default(),
            csv_field(&s.desc),
        ));
    }
    out
}

/// `--services --markdown`: the same rows pasted into docs and issues.
pub fn render_services_markdown(svcs: &[crate::model::Service]) -> String {
    let mut out = String::from(
        "| MANAGER | NAME | STATE | PID | DESCRIPTION |\n|---|---|---|---|---|\n",
    );
    for s in svcs {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            s.manager,
            s.name,
            s.state,
            s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
            s.desc,
        );
    }
    out
}

/// One `--conns` row: a socket in any state except LISTEN (listening is
/// `--ports`' turf), with its owning process — and, when the peer is on
/// this host, the process on the other end.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnRow {
    pub proto: String, // tcp / tcp6 / udp / udp6
    pub local: String, // "addr:port"
    /// "addr:port", or "" for unconnected UDP sockets.
    pub peer: String,
    pub state: String,
    pub pid: Option<Pid>,
    /// Owner display line "name (pid N)"; empty when nobody owns it.
    pub owner: String,
    /// Set only for loopback peers: the local process on the other end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_pid: Option<Pid>,
    #[serde(skip_serializing_if = "std::string::String::is_empty")]
    pub peer_owner: String,
}

fn loopback_addr(a: &str) -> bool {
    let bare = a.trim_start_matches('[').trim_end_matches(']');
    bare == "::1" || bare.starts_with("127.")
}

fn owned(pid: Option<Pid>, names: &HashMap<Pid, String>) -> String {
    match pid {
        Some(p) => match names.get(&p) {
            Some(n) => format!("{n} (pid {p})"),
            None => format!("(pid {p})"),
        },
        None => String::new(),
    }
}

/// Fold a socket sweep into `--conns` rows: drop LISTEN, resolve each
/// socket's owner against the process table, and attribute loopback peers
/// by looking up which local socket holds the peer's port. Rows sort
/// ownerless-last so the attributable connections read first.
pub fn collect_conns(sockets: &[crate::model::Socket], procs: &[Process]) -> Vec<ConnRow> {
    let names: HashMap<Pid, String> = procs.iter().map(|p| (p.pid, p.name.clone())).collect();
    let mut by_port: HashMap<u16, Vec<&crate::model::Socket>> = HashMap::new();
    for s in sockets {
        by_port.entry(s.local_port).or_default().push(s);
    }
    let mut rows: Vec<ConnRow> = sockets
        .iter()
        .filter(|s| !s.state.eq_ignore_ascii_case("LISTEN"))
        .map(|s| {
            let peer = match (&s.peer_addr, s.peer_port) {
                (Some(a), Some(p)) => format!("{}:{}", a, p),
                _ => String::new(),
            };
            // loopback attribution: prefer the established socket on that
            // port owned by someone else, else any other owned socket
            let mut peer_attr: Option<(Pid, String)> = None;
            let mut fallback: Option<(Pid, String)> = None;
            if let (Some(a), Some(p)) = (&s.peer_addr, s.peer_port) {
                if loopback_addr(a) {
                    for c in by_port.get(&p).into_iter().flatten() {
                        if c.pid.is_none() || c.pid == s.pid {
                            continue;
                        }
                        let who = (c.pid.unwrap(), owned(c.pid, &names));
                        if c.state.eq_ignore_ascii_case("ESTABLISHED") {
                            peer_attr = Some(who);
                            break;
                        }
                        if fallback.is_none() {
                            fallback = Some(who);
                        }
                    }
                }
            }
            let peer_attr = peer_attr.or(fallback);
            ConnRow {
                proto: s.proto.clone(),
                local: format!("{}:{}", s.local_addr, s.local_port),
                peer,
                state: s.state.clone(),
                pid: s.pid,
                owner: owned(s.pid, &names),
                peer_pid: peer_attr.as_ref().map(|(p, _)| *p),
                peer_owner: peer_attr.map(|(_, o)| o).unwrap_or_default(),
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        a.owner.is_empty()
            .cmp(&b.owner.is_empty())
            .then_with(|| a.owner.cmp(&b.owner))
            .then_with(|| a.proto.cmp(&b.proto))
            .then_with(|| a.local.cmp(&b.local))
    });
    rows
}

/// `--conns` text table: PROTO / LOCAL / PEER / STATE / OWNER; loopback
/// peers get "↔ other end" appended to the owner cell.
pub fn render_conns(rows: &[ConnRow], p: &Painter) -> String {
    if rows.is_empty() {
        return "no connections (nothing outside LISTEN)\n".to_string();
    }
    let proto_w = rows.iter().map(|r| r.proto.len()).max().unwrap_or(5).max(5);
    let local_w = rows.iter().map(|r| r.local.len()).max().unwrap_or(5).clamp(5, 44);
    let peer_w = rows.iter().map(|r| r.peer.len().max(4)).max().unwrap_or(4).clamp(4, 44);
    let state_w = rows.iter().map(|r| r.state.len()).max().unwrap_or(5).max(5);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<proto_w$}  {:<local_w$}  {:<peer_w$}  {:<state_w$}  OWNER",
        "PROTO", "LOCAL", "PEER", "STATE"
    );
    for r in rows {
        let mut owner = if r.owner.is_empty() {
            "-".to_string()
        } else {
            r.owner.clone()
        };
        if !r.peer_owner.is_empty() {
            owner.push_str(&format!(" ↔ {}", r.peer_owner));
        }
        let _ = writeln!(
            out,
            "{:<proto_w$}  {:<local_w$}  {:<peer_w$}  {:<state_w$}  {}",
            p.dim(&r.proto),
            r.local,
            r.peer,
            p.dim(&r.state),
            owner,
        );
    }
    out
}

/// `--conns --csv`: peer attribution as its own columns.
pub fn render_conns_csv(rows: &[ConnRow]) -> String {
    let mut out = String::from("proto,local,peer,state,pid,owner,peer_pid,peer_owner\n");
    for r in rows {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            csv_field(&r.proto),
            csv_field(&r.local),
            csv_field(&r.peer),
            csv_field(&r.state),
            r.pid.map(|p| p.to_string()).unwrap_or_default(),
            csv_field(&r.owner),
            r.peer_pid.map(|p| p.to_string()).unwrap_or_default(),
            csv_field(&r.peer_owner),
        ));
    }
    out
}

/// `--conns --markdown`: the same rows pasted into docs and issues.
pub fn render_conns_markdown(rows: &[ConnRow]) -> String {
    let mut out = String::from(
        "| PROTO | LOCAL | PEER | STATE | PID | OWNER | PEER OWNER |\n\
         |---|---|---|---|---|---|---|\n",
    );
    for r in rows {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} | {} |",
            r.proto,
            r.local,
            r.peer,
            r.state,
            r.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
            if r.owner.is_empty() { "-" } else { &r.owner },
            r.peer_owner,
        );
    }
    out
}

/// `--conns --by-peer` row: one remote address, with the connection count,
/// the established subset, the remaining states and the local owners that
/// reach it — "who is this machine talking to".
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerRow {
    /// Remote address without the port ("1.2.3.4"); "(no peer)" groups
    /// unconnected UDP sockets.
    pub peer: String,
    pub conns: usize,
    pub established: usize,
    /// Every state → count, ESTABLISHED included (JSON keeps the full map).
    pub states: std::collections::BTreeMap<String, usize>,
    /// Distinct local owner lines ("name (pid N)"); empty when all unowned.
    pub owners: Vec<String>,
}

/// Fold `--conns` rows into per-peer aggregates, busiest first. The peer is
/// the address only — the aggregate answers "which hosts", the per-port
/// detail stays in the plain table.
pub fn collect_conns_by_peer(rows: &[ConnRow]) -> Vec<PeerRow> {
    let mut order: Vec<String> = Vec::new();
    let mut by_peer: HashMap<String, PeerRow> = HashMap::new();
    for r in rows {
        let peer = if r.peer.is_empty() {
            "(no peer)".to_string()
        } else {
            // rsplit survives both "1.2.3.4:443" and "[::1]:443"
            r.peer
                .rsplit_once(':')
                .map(|(a, _)| a.to_string())
                .unwrap_or_else(|| r.peer.clone())
        };
        let e = by_peer.entry(peer.clone()).or_insert_with(|| {
            order.push(peer.clone());
            PeerRow {
                peer: peer.clone(),
                conns: 0,
                established: 0,
                states: Default::default(),
                owners: Vec::new(),
            }
        });
        e.conns += 1;
        *e.states.entry(r.state.clone()).or_default() += 1;
        if r.state.eq_ignore_ascii_case("ESTABLISHED") {
            e.established += 1;
        }
        if !r.owner.is_empty() && !e.owners.contains(&r.owner) {
            e.owners.push(r.owner.clone());
        }
    }
    let mut out: Vec<PeerRow> = order
        .into_iter()
        .map(|p| by_peer.remove(&p).unwrap())
        .collect();
    out.sort_by(|a, b| b.conns.cmp(&a.conns).then_with(|| a.peer.cmp(&b.peer)));
    out
}

/// States other than ESTABLISHED, compact: "TIME_WAIT 2 · CLOSE_WAIT 1".
fn non_est_states(states: &std::collections::BTreeMap<String, usize>) -> String {
    let rest: Vec<String> = states
        .iter()
        .filter(|(s, _)| !s.eq_ignore_ascii_case("ESTABLISHED"))
        .map(|(s, n)| format!("{s} {n}"))
        .collect();
    rest.join(" · ")
}

/// `--conns --by-peer` text table: PEER / CONNS / EST / STATES / OWNERS.
pub fn render_conns_by_peer(rows: &[PeerRow], p: &Painter) -> String {
    if rows.is_empty() {
        return "no connections (nothing outside LISTEN)\n".to_string();
    }
    let peer_w = rows
        .iter()
        .map(|r| r.peer.len())
        .max()
        .unwrap_or(4)
        .clamp(4, 44);
    let states_w = rows
        .iter()
        .map(|r| non_est_states(&r.states).len())
        .max()
        .unwrap_or(6)
        .clamp(6, 40);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<peer_w$}  {:>5}  {:>3}  {:<states_w$}  OWNERS",
        "PEER", "CONNS", "EST", ""
    );
    for r in rows {
        let _ = writeln!(
            out,
            "{:<peer_w$}  {:>5}  {:>3}  {:<states_w$}  {}",
            r.peer,
            r.conns,
            r.established,
            p.dim(&non_est_states(&r.states)),
            if r.owners.is_empty() {
                "-".to_string()
            } else {
                r.owners.join(", ")
            },
        );
    }
    out
}

/// `--conns --by-peer --csv`: states packed as "STATE:n;STATE:n".
pub fn render_conns_by_peer_csv(rows: &[PeerRow]) -> String {
    let mut out = String::from("peer,conns,established,states,owners\n");
    for r in rows {
        let states = r
            .states
            .iter()
            .map(|(s, n)| format!("{s}:{n}"))
            .collect::<Vec<_>>()
            .join(";");
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            csv_field(&r.peer),
            r.conns,
            r.established,
            csv_field(&states),
            csv_field(&r.owners.join(";")),
        ));
    }
    out
}

/// `--conns --by-peer --markdown`.
pub fn render_conns_by_peer_markdown(rows: &[PeerRow]) -> String {
    let mut out = String::from(
        "| PEER | CONNS | EST | STATES | OWNERS |\n\
         |---|---|---|---|---|\n",
    );
    for r in rows {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            r.peer,
            r.conns,
            r.established,
            non_est_states(&r.states),
            if r.owners.is_empty() {
                "-".to_string()
            } else {
                r.owners.join(", ")
            },
        );
    }
    out
}

/// Escape for HTML text content and double-quoted attributes.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The normalized row behind the csv / markdown / html listing outputs —
/// one flat view of a process so the three formats can't drift apart.
pub struct ListingRow {
    pub pid: i32,
    pub ppid: Option<i32>,
    pub user: String,
    pub cpu: Option<f64>,
    pub rss_mb: Option<u64>,
    pub state: String,
    pub age: String,
    pub name: String,
    pub command: String,
}

fn listing_row(p: &Process, now: i64) -> ListingRow {
    ListingRow {
        pid: p.pid,
        ppid: p.ppid,
        user: p.user.clone().unwrap_or_else(|| "-".into()),
        cpu: p.cpu,
        rss_mb: p.mem_kb.map(|kb| kb / 1024),
        state: p.state.clone().unwrap_or_default(),
        age: p.started.map(|t| fmt_age(now - t)).unwrap_or_default(),
        name: p.name.clone(),
        command: p.command_line(),
    }
}

/// `--csv` on the listing / --top: one header row, one row per process.
pub fn render_csv(procs: &[Process]) -> String {
    let now = crate::util::now_unix();
    let mut out = String::from(
        "pid,ppid,user,cpu_pct,rss_mb,state,age,name,command\n",
    );
    for p in procs {
        let r = listing_row(p, now);
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{}\n",
            r.pid,
            r.ppid.map(|x| x.to_string()).unwrap_or_default(),
            csv_field(&r.user),
            r.cpu.map(|c| format!("{c:.1}")).unwrap_or_default(),
            r.rss_mb.map(|m| m.to_string()).unwrap_or_default(),
            csv_field(&r.state),
            csv_field(&r.age),
            csv_field(&r.name),
            csv_field(&r.command),
        ));
    }
    out
}

/// `--markdown` on the listing / --top: a GitHub-flavored table. Pipe
/// characters in commands are escaped so the row structure survives
/// pasting into an issue.
pub fn render_markdown(procs: &[Process]) -> String {
    let now = crate::util::now_unix();
    let mut out = String::from("| PID | PPID | USER | CPU% | RSS MB | STATE | AGE | NAME | COMMAND |\n");
    out.push_str("|---:|---:|---|---:|---:|---|---|---|---|\n");
    for p in procs {
        let r = listing_row(p, now);
        let dash = "-".to_string();
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            r.pid,
            r.ppid.map(|x| x.to_string()).unwrap_or_else(|| dash.clone()),
            r.user,
            r.cpu.map(|c| format!("{c:.1}")).unwrap_or_else(|| dash.clone()),
            r.rss_mb.map(|m| m.to_string()).unwrap_or_else(|| dash.clone()),
            if r.state.is_empty() { dash.clone() } else { r.state.clone() },
            if r.age.is_empty() { dash.clone() } else { r.age },
            r.name,
            r.command.replace('|', "\\|"),
        ));
    }
    out
}

/// `--top METRIC`: the highest-ranked processes by one metric, value first.
/// Processes the metric can't measure (foreign-user fd counts, no io
/// counters off Linux) drop out rather than rank as zero. `rates` carries
/// the sampler's per-pid I/O rates (bytes/s) for `--top io-rate`.
pub fn render_top(
    procs: &[Process],
    metric: crate::cli::TopMetric,
    count: usize,
    fds: Option<&std::collections::HashMap<crate::model::Pid, u64>>,
    rates: Option<&crate::history::History>,
    p: &Painter,
) -> String {
    let now = crate::util::now_unix();
    let mut ranked: Vec<(f64, &Process)> = procs
        .iter()
        .filter_map(|pr| {
            let v = match metric {
                crate::cli::TopMetric::Cpu => pr.cpu,
                crate::cli::TopMetric::Mem => pr.mem_kb.map(|kb| kb as f64),
                crate::cli::TopMetric::Fd => fds.and_then(|m| m.get(&pr.pid)).map(|&n| n as f64),
                crate::cli::TopMetric::Io => {
                    let r = pr.io_read_bytes.unwrap_or(0);
                    let w = pr.io_write_bytes.unwrap_or(0);
                    (pr.io_read_bytes.is_some() || pr.io_write_bytes.is_some())
                        .then_some((r + w) as f64)
                }
                crate::cli::TopMetric::IoRate => rates
                    .and_then(|h| h.io_rate_of(pr.pid))
                    .map(|(r, w)| r + w),
                // age in seconds — desc order puts the oldest first
                crate::cli::TopMetric::Age => pr.started.map(|t| (now.saturating_sub(t)) as f64),
                crate::cli::TopMetric::Gpu => pr.gpu_sm_pct.map(|v| v as f64),
            }?;
            Some((v, pr))
        })
        .collect();
    ranked.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    ranked.truncate(count);

    // age ranking already shows the age — swap the trailing AGE column for
    // the process state so the table doesn't repeat itself
    let age_col = if metric == crate::cli::TopMetric::Age { "STATE" } else { "AGE" };
    let mut rows: Vec<[String; 5]> = vec![[
        "PID".into(),
        "USER".into(),
        metric.header().into(),
        age_col.into(),
        "COMMAND".into(),
    ]];
    for (v, pr) in &ranked {
        let val = match metric {
            crate::cli::TopMetric::Cpu => format!("{v:.1}"),
            crate::cli::TopMetric::Mem => crate::util::fmt_bytes(*v as u64),
            crate::cli::TopMetric::Fd => format!("{}", *v as u64),
            crate::cli::TopMetric::Io => crate::util::fmt_bytes(*v as u64),
            crate::cli::TopMetric::IoRate => {
                format!("{}/s", crate::util::fmt_bytes(*v as u64))
            }
            crate::cli::TopMetric::Age => fmt_age(*v as i64),
            crate::cli::TopMetric::Gpu => format!("{v:.1}"),
        };
        let extra = if metric == crate::cli::TopMetric::Age {
            pr.state.clone().unwrap_or_else(|| "-".into())
        } else {
            pr.started.map(|t| fmt_age(now - t)).unwrap_or_else(|| "-".into())
        };
        rows.push([
            pr.pid.to_string(),
            pr.user.clone().unwrap_or_else(|| "-".into()),
            val,
            extra,
            pr.command_line(),
        ]);
    }
    let w = [
        rows.iter().map(|r| r[0].chars().count()).max().unwrap_or(3),
        rows.iter().map(|r| r[1].chars().count()).max().unwrap_or(4),
        rows.iter().map(|r| r[2].chars().count()).max().unwrap_or(3),
        rows.iter().map(|r| r[3].chars().count()).max().unwrap_or(3),
    ];
    let mut out = String::new();
    let head = p.bold(&rows[0][0]);
    let _ = writeln!(
        out,
        "{:>w0$}  {:<w1$}  {:>w2$}  {:>w3$}  {}",
        head,
        p.bold(&rows[0][1]),
        p.bold(&rows[0][2]),
        p.bold(&rows[0][3]),
        p.bold(&rows[0][4]),
        w0 = w[0],
        w1 = w[1],
        w2 = w[2],
        w3 = w[3]
    );
    for r in rows.iter().skip(1) {
        let _ = writeln!(
            out,
            "{:>w0$}  {:<w1$}  {:>w2$}  {:>w3$}  {}",
            r[0], r[1], r[2], r[3], r[4],
            w0 = w[0],
            w1 = w[1],
            w2 = w[2],
            w3 = w[3]
        );
    }
    if ranked.is_empty() {
        let why = match metric {
            crate::cli::TopMetric::Fd => "no fd counts available on this platform".to_string(),
            crate::cli::TopMetric::Io | crate::cli::TopMetric::IoRate => {
                "no per-process I/O counters (a Linux /proc feature)".to_string()
            }
            crate::cli::TopMetric::Age => "no processes carry a start time".to_string(),
            _ => "no processes report this metric".to_string(),
        };
        let _ = writeln!(out, "({why})");
    }
    out
}

/// `--report-html FILE`: a self-contained report — no JS, no external
/// assets. Summary + top-5 lists + the full table, with css bars for the
/// cpu/mem columns so outliers read at a glance.
pub fn render_html_report(procs: &[Process]) -> String {
    let now = crate::util::now_unix();
    let rows: Vec<ListingRow> = procs.iter().map(|p| listing_row(p, now)).collect();
    let max_cpu = rows.iter().filter_map(|r| r.cpu).fold(0.0f64, f64::max);
    let max_rss = rows.iter().filter_map(|r| r.rss_mb).max().unwrap_or(0);

    let mut top_cpu: Vec<&ListingRow> = rows.iter().filter(|r| r.cpu.is_some()).collect();
    top_cpu.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal));
    top_cpu.truncate(5);
    let mut top_mem: Vec<&ListingRow> = rows.iter().filter(|r| r.rss_mb.is_some_and(|m| m > 0)).collect();
    top_mem.sort_by_key(|r| std::cmp::Reverse(r.rss_mb));
    top_mem.truncate(5);

    let top_list = |items: &[&ListingRow], val: &dyn Fn(&ListingRow) -> String| -> String {
        let mut s = String::from("<ol>");
        for r in items {
            s.push_str(&format!(
                "<li><span class=\"who\">{}</span> <span class=\"val\">{}</span></li>",
                html_escape(&r.name),
                val(r),
            ));
        }
        s.push_str("</ol>");
        s
    };

    let mut table = String::new();
    for r in &rows {
        let cpu_bar = r.cpu.map(|c| {
            let w = if max_cpu > 0.0 { (c / max_cpu * 100.0).round() as u32 } else { 0 };
            format!("<div class=\"bar\"><div class=\"fill cpu\" style=\"width:{w}%\"></div></div> {:.1}", c)
        }).unwrap_or_else(|| "-".into());
        let rss_bar = r.rss_mb.map(|m| {
            let w = (m * 100).checked_div(max_rss).unwrap_or(0) as u32;
            format!("<div class=\"bar\"><div class=\"fill rss\" style=\"width:{w}%\"></div></div> {m} MB")
        }).unwrap_or_else(|| "-".into());
        table.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>\n",
            r.pid,
            r.ppid.map(|x| x.to_string()).unwrap_or_else(|| "-".into()),
            html_escape(&r.user),
            cpu_bar,
            rss_bar,
            html_escape(&r.state),
            html_escape(&r.age),
            html_escape(&r.name),
            html_escape(&r.command),
        ));
    }

    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n\
         <title>witr-rs report · {when}</title>\n\
         <style>\n\
         body {{ font-family: -apple-system, 'Segoe UI', sans-serif; margin: 2rem; color: #1a1a2e; }}\n\
         h1 {{ font-size: 1.4rem; }} .muted {{ color: #777; }}\n\
         .cols {{ display: flex; gap: 3rem; flex-wrap: wrap; }}\n\
         ol {{ padding-left: 1.2rem; }} .who {{ font-weight: 600; }} .val {{ color: #555; }}\n\
         table {{ border-collapse: collapse; width: 100%; margin-top: 2rem; font-size: 0.85rem; }}\n\
         th, td {{ text-align: left; padding: 0.3rem 0.6rem; border-bottom: 1px solid #e5e5ef; }}\n\
         td.num {{ white-space: nowrap; }}\n\
         .bar {{ display: inline-block; width: 8rem; height: 0.5rem; background: #eef; border-radius: 3px; vertical-align: middle; margin-right: 0.4rem; }}\n\
         .fill {{ height: 100%; border-radius: 3px; }} .fill.cpu {{ background: #e5534b; }} .fill.rss {{ background: #3f6ad8; }}\n\
         code {{ font-size: 0.8rem; color: #444; }}\n\
         </style></head><body>\n\
         <h1>witr-rs report</h1>\n\
         <p class=\"muted\">{when} · {n} processes</p>\n\
         <div class=\"cols\">\n\
         <div><h2>Top CPU</h2>{top_cpu_html}</div>\n\
         <div><h2>Top memory</h2>{top_mem_html}</div>\n\
         </div>\n\
         <table>\n\
         <tr><th>PID</th><th>PPID</th><th>USER</th><th>CPU%</th><th>RSS</th><th>STATE</th><th>AGE</th><th>NAME</th><th>COMMAND</th></tr>\n\
         {table}</table>\n\
         </body></html>\n",
        when = crate::util::fmt_time(now),
        n = rows.len(),
        top_cpu_html = top_list(&top_cpu, &|r| {
            format!("{:.1}%", r.cpu.unwrap_or(0.0))
        }),
        top_mem_html = top_list(&top_mem, &|r| {
            format!("{} MB", r.rss_mb.unwrap_or(0))
        }),
        table = table,
    )
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
    pub fn cyan(&self, s: &str) -> String {
        self.wrap("36", s)
    }
    pub fn red(&self, s: &str) -> String {
        self.wrap("31", s)
    }
}

pub fn render(reports: &[TargetReport], format: Format, color: bool) -> String {
    let p = Painter::new(color);
    if format == Format::Json {
        return serde_json::to_string_pretty(reports).unwrap_or_else(|_| "[]".into());
    }
    let body = |r: &TargetReport| match format {
        Format::Short => render_short(r, &p),
        Format::Tree => render_tree(r, &p),
        Format::Warnings => render_warnings(r, &p),
        Format::EnvOnly => render_env_only(r, &p),
        _ => render_standard(r, &p),
    };
    if reports.len() > 1 {
        // Go witr's multi-target mode: a cyan divider labels each section.
        let mut out = String::new();
        for r in reports {
            if !out.is_empty() {
                out.push('\n');
            }
            let _ = writeln!(
                out,
                "{}",
                p.cyan(&format!("----- [{}] -----", r.target.divider_label()))
            );
            out.push_str(&body(r));
        }
        out
    } else {
        reports.iter().map(body).collect::<Vec<_>>().join("\n\n")
    }
}

fn error_line(r: &TargetReport, p: &Painter) -> String {
    if !r.found && r.container.is_some() {
        return render_container_fallback(r, p);
    }
    p.yellow(r.error.as_deref().unwrap_or("no process matched"))
}

/// A container whose main process witr-rs can't see on this host
/// (VM-backed runtime like Docker Desktop / podman machine): show the
/// runtime-side view instead of a bare error.
fn render_container_fallback(r: &TargetReport, p: &Painter) -> String {
    let mut out = String::new();
    let Some(c) = &r.container else {
        return out;
    };
    let _ = writeln!(
        out,
        "{} {}",
        p.bold("Target:"),
        r.target.divider_label()
    );
    let mut line = format!("{} {}", p.bold("Container:"), p.green(&c.name));
    let short: String = c.id.chars().take(12).collect();
    if !short.is_empty() {
        line.push_str(&format!(" {}", p.dim(&format!("(id {short})"))));
    }
    let tag = c.state_tag();
    if !tag.is_empty() {
        let colored = if tag == "healthy" {
            p.green(&format!("[{tag}]"))
        } else {
            p.red(&format!("[{tag}]"))
        };
        line.push_str(&format!(" {colored}"));
    }
    let _ = writeln!(out, "{}", line);
    if !c.image.is_empty() {
        let _ = writeln!(out, "{} {}", p.bold("Image:"), c.image);
    }
    if !c.command.is_empty() {
        let _ = writeln!(out, "{} {}", p.bold("Command:"), c.command);
    }
    if !c.status.is_empty() {
        let _ = writeln!(out, "{} {}", p.bold("Status:"), c.status);
    }
    if !c.ports.is_empty() {
        let _ = writeln!(out, "{} {}", p.bold("Ports:"), c.ports);
    }
    if let Some(e) = &r.error {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", p.yellow(e));
    }
    out.trim_end().to_string() + "\n"
}

fn render_short(r: &TargetReport, p: &Painter) -> String {
    if !r.found {
        if let Some(c) = &r.container {
            // compact fallback: just the identity line
            return format!("{} {}", p.bold("container:"), c.format_line());
        }
        return p.yellow(r.error.as_deref().unwrap_or("no match"));
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
    lines
        .iter()
        .map(|l| format!("{}{}", l, warn))
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_standard(r: &TargetReport, p: &Painter) -> String {
    let mut out = String::new();
    if !r.found {
        let _ = writeln!(out, "{}", error_line(r, p));
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
        if m.forked {
            title.push_str(&format!(" {}", p.yellow("{forked}")));
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
        if let Some(t) = &m.tty {
            if t == "-" {
                let _ = writeln!(out, "  {}", p.dim("detached (no controlling terminal)"));
            } else {
                let _ = writeln!(out, "  tty {t}");
            }
        }
        if m.pgid.is_some() || m.sid.is_some() {
            let mut line = String::from("  ");
            if let Some(g) = m.pgid {
                line.push_str(&format!("pgid {g}"));
            }
            if m.pgid.is_some() && m.sid.is_some() {
                line.push_str(" · ");
            }
            if let Some(s) = m.sid {
                line.push_str(&format!("sid {s}"));
            }
            let _ = writeln!(out, "{line}");
        }
        // cgroup v2 (Linux detail-time): path plus the group's own memory
        // and CPU totals — the container/service view a bare RSS can't give
        if let Some(cg) = &m.cgroup {
            let mut line = format!("  cgroup {cg}");
            if let Some(bytes) = m.cgroup_mem_bytes {
                line.push_str(&format!(" · mem {}", crate::util::fmt_bytes(bytes)));
            }
            if let Some(usec) = m.cgroup_cpu_usec {
                line.push_str(&format!(" · cpu {:.1}s", usec as f64 / 1_000_000.0));
            }
            let _ = writeln!(out, "{}", p.dim(&line));
        }
        if m.git_repo.is_some() || m.git_branch.is_some() {
            let mut line = String::from("  git ");
            if let Some(repo) = &m.git_repo {
                line.push_str(repo);
                if let Some(branch) = &m.git_branch {
                    if !branch.is_empty() {
                        line.push_str(&format!(" ({branch})"));
                    }
                }
            }
            let _ = writeln!(out, "{}", p.dim(&line));
        }
        if let Some(container) = &m.container {
            let _ = writeln!(out, "  {} {}", p.bold("container:"), container);
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
        if let Some((used, limit)) = r.fd_usage {
            if let Some(pct) = (used * 100).checked_div(limit) {
                let line = format!("  open files {} of {} ({}%)", used, limit, pct);
                if pct > 80 {
                    let _ = writeln!(out, "{}", p.yellow(&line));
                } else {
                    let _ = writeln!(out, "{}", line);
                }
            }
        }

        if let Some(s) = &r.source {
            let _ = writeln!(out);
            let _ = writeln!(out, "  {}", p.green("started by:"));
            let mut line = format!("    {} {}", s.kind, s.label.clone().unwrap_or_default());
            if let Some(d) = &s.detail {
                line.push_str(&format!(" — {}", d));
            }
            let _ = writeln!(out, "{}", line.trim_end());
            if let Some(n) = s.restarts {
                if n > 0 {
                    let _ = writeln!(out, "    {} restart(s) recorded by the service manager", p.yellow(&n.to_string()));
                }
            }
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
            let mut explained: Vec<&str> = Vec::new();
            for s in &r.sockets {
                let mut line = format!("    {:<5} {}:{}", s.proto, s.local_addr, s.local_port);
                if let (Some(pa), Some(pp)) = (&s.peer_addr, s.peer_port) {
                    line.push_str(&format!(" → {}:{}", pa, pp));
                }
                line.push_str(&format!(" {}", s.state));
                let _ = writeln!(out, "{}", line);
                // For --port targets the state is the interesting part:
                // explain each distinct state once, under the list.
                if matches!(r.target, crate::model::TargetSpec::Port { .. })
                    && !explained.contains(&s.state.as_str())
                {
                    if let Some(note) = socket_explanation(&s.state) {
                        explained.push(&s.state);
                        let _ = writeln!(out, "      {} {}", p.dim(&s.state), p.dim(&format!("— {note}")));
                    }
                }
            }
        }

        if !r.children.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "  {} ({}):", p.dim("children"), r.children.len());
            for c in &r.children {
                let _ = writeln!(out, "    pid {:<7} {}", c.pid, c.name);
            }
        }

        if !r.locks.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "  {} ({}):", p.dim("locks"), r.locks.len());
            for l in r.locks.iter().take(10) {
                let _ = writeln!(
                    out,
                    "    {} {} {} ({})",
                    l.kind, l.mode, l.path, l.owner
                );
            }
            if r.locks.len() > 10 {
                let _ = writeln!(out, "    … {} more", r.locks.len() - 10);
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
/// detail page shows, including env values, open files and locks, for
/// pasting into issues.
pub fn render_export(reports: &[TargetReport]) -> String {
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
        if let Some(t) = &m.tty {
            let v = if t == "-" {
                "(detached)".to_string()
            } else {
                t.clone()
            };
            kv(&mut out, "tty", v);
        }
        if let Some(g) = m.pgid {
            kv(&mut out, "pgid", g.to_string());
        }
        if let Some(s) = m.sid {
            kv(&mut out, "sid", s.to_string());
        }
        // cgroup v2 (Linux detail-time): bare path in the key/value export —
        // the memory/cpu numbers live on the human block above
        if let Some(cg) = &m.cgroup {
            kv(&mut out, "cgroup", cg.clone());
        }
        if let Some(exe) = &m.exe {
            let mut line = exe.clone();
            if m.exe_deleted {
                line.push_str("  [deleted from disk]");
            }
            kv(&mut out, "exe", line);
        }
        if let Some(b) = &r.binary {
            if let Some(h) = &b.sha256 {
                kv(&mut out, "sha256", h.clone());
            }
            if let Some(sig) = &b.signature {
                kv(&mut out, "signature", sig.clone());
            }
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
        if let Some((used, limit)) = r.fd_usage {
            kv(&mut out, "fds", format!("{used}/{limit}"));
        }
        if !r.locks.is_empty() {
            kv(&mut out, "locks", format!("{}", r.locks.len()));
            for l in r.locks.iter().take(20) {
                let _ = writeln!(out, "  {} {} {} ({})", l.kind, l.mode, l.path, l.owner);
            }
            if r.locks.len() > 20 {
                let _ = writeln!(out, "  … {} more", r.locks.len() - 20);
            }
        }
        if let Some(fs) = &r.open_files {
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
    if !r.found {
        let _ = writeln!(
            out,
            "{}",
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

/// Go witr's RenderWarnings: process identity, then only the warnings.
fn render_warnings(r: &TargetReport, p: &Painter) -> String {
    let mut out = String::new();
    let Some(m) = r.matches.first() else {
        let _ = writeln!(out, "{}", p.yellow(r.error.as_deref().unwrap_or("no process matched")));
        return out;
    };
    let _ = writeln!(out, "{} {}", p.bold(&format!("{} (pid {})", m.name, m.pid)), m.command_line());
    if r.warnings.is_empty() {
        let _ = writeln!(out, "{} {}", p.bold("Warnings:"), p.green("No warnings."));
        return out;
    }
    let _ = writeln!(out, "{}", p.red("Warnings:"));
    for w in &r.warnings {
        let _ = writeln!(out, "  {} {}", p.yellow("•"), w);
    }
    out
}

/// Go witr's RenderEnvOnly: the command and environment block, nothing else.
/// Multiple matches are an error so the values can't be misattributed.
fn render_env_only(r: &TargetReport, p: &Painter) -> String {
    let mut out = String::new();
    if !r.found {
        if let Some(c) = &r.container {
            let _ = writeln!(out, "{}", p.yellow(&format!("error: {} ({})", r.error.as_deref().unwrap_or("not visible"), c.format_line())));
        } else {
            let _ = writeln!(out, "{}", p.yellow(r.error.as_deref().unwrap_or("no process matched")));
        }
        return out;
    }
    if r.matches.len() > 1 {
        let _ = writeln!(
            out,
            "{}",
            p.yellow(&format!(
                "error: multiple processes matched ({} results) — narrow the target",
                r.matches.len()
            ))
        );
        return out;
    }
    let m = &r.matches[0];
    let _ = writeln!(
        out,
        "{} {} {}",
        p.bold("Process"),
        p.dim(&format!("(pid {}):", m.pid)),
        p.green(&m.command_line())
    );
    match &m.env {
        Some(env) if !env.is_empty() => {
            let _ = writeln!(out, "{}", p.bold("Environment:"));
            for (k, v) in env {
                let _ = writeln!(out, "  {k}={v}");
            }
        }
        _ => {
            let _ = writeln!(
                out,
                "{} {}",
                p.bold("Environment:"),
                p.red("No environment variables found.")
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: i32, name: &str, cpu: Option<f64>, mem_kb: Option<u64>) -> Process {
        Process {
            pid,
            name: name.into(),
            cmdline: vec![name.into(), "--flag".into()],
            cpu,
            mem_kb,
            ..Default::default()
        }
    }

    #[test]
    fn csv_fields_escape_commas_quotes_and_newlines() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("two\nlines"), "\"two\nlines\"");
    }

    #[test]
    fn listeners_table_and_csv_cover_empty_and_shared_ports() {
        let p = Painter::new(false);
        // empty: the nothing-to-see note, no panic on max() over nothing
        assert!(render_listeners(&[], &p).contains("no listening sockets"));
        assert_eq!(render_listeners_csv(&[]), "port,proto,owners,scope\n");

        let mk = |proto: &str, port: u16, who: &[&str], binds: &[&str]| crate::snapshot::Listener {
            proto: proto.into(),
            port,
            who: who.iter().map(|s| s.to_string()).collect(),
            binds: binds.iter().map(|s| s.to_string()).collect(),
        };
        let listeners = vec![
            mk("tcp", 80, &["nginx (pid 7)"], &["0.0.0.0"]),
            mk("tcp", 8080, &["a (pid 1)", "b (pid 2)"], &["127.0.0.1"]),
        ];
        let table = render_listeners(&listeners, &p);
        assert!(
            table.contains("PORT")
                && table.contains("PROTO")
                && table.contains("SCOPE")
                && table.contains("OWNER(S)")
        );
        let l80 = table.lines().find(|l| l.contains(" 80 ")).unwrap();
        assert!(l80.contains("nginx (pid 7)"), "{table}");
        // the wildcard listener reads as internet-reachable, the loopback
        // one as local-only
        assert!(table.contains("internet"), "{table}");
        assert!(table.contains("loopback"), "{table}");

        let csv = render_listeners_csv(&listeners);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "port,proto,owners,scope");
        assert_eq!(lines[1], "80,tcp,nginx (pid 7),internet");
        // two owners on one port: "; "-joined so the comma stays a separator
        assert_eq!(lines[2], "8080,tcp,a (pid 1); b (pid 2),loopback");
    }

    #[test]
    fn by_name_folds_identities_and_sorts_by_total_rss() {
        let mk = |pid: i32, name: &str, user: Option<&str>, kb: u64, cpu: f64, ms: u64| Process {
            pid,
            name: name.into(),
            user: user.map(|u| u.into()),
            mem_kb: Some(kb),
            cpu: Some(cpu),
            cpu_time_ms: Some(ms),
            started: Some(crate::util::now_unix() - 100),
            ..Default::default()
        };
        // two nginx under root fold together; the same name under another
        // user stays a separate identity
        let procs = vec![
            mk(1, "nginx", Some("root"), 1024, 1.0, 60_000),
            mk(2, "nginx", Some("root"), 2048, 2.0, 120_000),
            mk(3, "nginx", Some("www"), 4096, 4.0, 240_000),
            mk(4, "idle", None, 0, 0.0, 0),
        ];
        let groups = aggregate_by_name(&procs);
        assert_eq!(groups.len(), 3);
        // heaviest total RSS first: www's 4 MB single instance
        assert_eq!(&groups[0].name, "nginx");
        assert_eq!(&groups[0].user, "www");
        assert_eq!(groups[0].rss_mb, 4);
        // root's pair folded: count 2, Σrss 3, Σcpu 3.0, Σcputime 180s
        let root = groups.iter().find(|g| g.user == "root").unwrap();
        assert_eq!(root.count, 2);
        assert_eq!(root.rss_mb, 3);
        assert!((root.cpu_pct - 3.0).abs() < 0.001, "{}", root.cpu_pct);
        assert_eq!(root.cpu_time_ms, 180_000);
        assert_eq!(root.oldest_secs, Some(100));
        // a userless process still aggregates under "-"
        assert_eq!(&groups.iter().find(|g| g.name == "idle").unwrap().user, "-");

        let p = Painter::new(false);
        let table = render_by_name(&groups, &p);
        assert!(table.contains("NAME") && table.contains("ΣCPUTIME"), "{table}");
        assert!(render_by_name(&[], &p).contains("no processes"));
        let csv = render_by_name_csv(&groups);
        assert_eq!(
            csv.lines().next().unwrap(),
            "name,user,count,cpu_pct,rss_mb,cpu_time_ms,oldest_age_secs"
        );
        assert!(csv.contains("nginx,root,2,3.0,3,180000,100\n"), "{csv}");
    }

    #[test]
    fn zombies_resolve_parents_and_sort_oldest_first() {
        let mk = |pid: i32, ppid: Option<i32>, state: Option<&str>, name: &str, started: Option<i64>| Process {
            pid,
            ppid,
            state: state.map(|s| s.into()),
            name: name.into(),
            started,
            ..Default::default()
        };
        let now = crate::util::now_unix();
        let procs = vec![
            mk(1, None, Some("S"), "init", Some(now - 500)),
            // oldest zombie first, parent resolved by ppid
            mk(2, Some(1), Some("Z"), "old-zombie", Some(now - 100)),
            mk(4, Some(2), Some("Z"), "young-zombie", Some(now - 10)),
            // parent 999 not in the table → parent None, age None sorts last
            mk(5, Some(999), Some("Z"), "orphan-zombie", None),
            // a healthy process is not a zombie
            mk(6, Some(1), Some("S"), "live", Some(now - 50)),
        ];
        let rows = collect_zombies(&procs);
        let pids: Vec<i32> = rows.iter().map(|r| r.pid).collect();
        assert_eq!(pids, vec![2, 4, 5]);
        assert_eq!(rows[0].parent.as_deref(), Some("init"));
        assert_eq!(rows[0].age_secs, Some(100));
        assert_eq!(rows[2].parent, None);
        assert_eq!(rows[2].age_secs, None);
        let p = Painter::new(false);
        assert!(render_zombies(&[], &p).contains("clean"));
        let table = render_zombies(&rows, &p);
        assert!(table.contains("old-zombie"), "{table}");
        assert!(table.contains("init (pid 1)"), "{table}");
    }

    #[test]
    fn locks_table_sorts_by_pid_then_path() {
        let e = |pid, owner: &str, mode: &str, path: &str| crate::model::LockEntry {
            id: String::new(),
            kind: "FLOCK".into(),
            mode: mode.into(),
            pid: Some(pid),
            owner: owner.into(),
            path: path.into(),
        };
        let entries = vec![
            e(9, "b", "READ", "/z.lock"),
            e(9, "b", "RW", "/a.lock"),
            e(2, "a", "WRITE", "/m.lock"),
            e(1, "c", "READ", "/k.lock"),
        ];
        let p = Painter::new(false);
        let out = render_locks_table(&entries, &p);
        let body: Vec<String> = out
            .lines()
            .skip(1)
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.to_string())
            .collect();
        // pid ascending, path ascending within one pid
        assert!(body[0].contains("/k.lock"), "{out}");
        assert!(body[1].contains("/m.lock"), "{out}");
        assert!(body[2].contains("/a.lock"), "{out}");
        assert!(body[3].contains("/z.lock"), "{out}");
        assert!(render_locks_table(&[], &p).contains("no file locks"));
    }

    #[test]
    fn zombies_csv_and_markdown_keep_raw_age_and_parent_columns() {
        let rows = vec![ZombieRow {
            pid: 2,
            name: "old-zombie, v1".into(),
            ppid: Some(1),
            parent: Some("init".into()),
            age_secs: Some(100),
        }];
        let csv = render_zombies_csv(&rows);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "pid,name,parent_pid,parent,age_secs");
        // comma inside the name must be quoted; age raw seconds
        assert_eq!(lines[1], "2,\"old-zombie, v1\",1,init,100");
        assert_eq!(render_zombies_csv(&[]), "pid,name,parent_pid,parent,age_secs\n");

        // parent gone (None): empty cells, not "(gone)" prose
        let orphan = vec![ZombieRow {
            pid: 5,
            name: "orphan-zombie".into(),
            ppid: Some(999),
            parent: None,
            age_secs: None,
        }];
        let orphan_csv = render_zombies_csv(&orphan);
        assert_eq!(orphan_csv.lines().nth(1).unwrap(), "5,orphan-zombie,999,,");

        let md = render_zombies_markdown(&rows);
        assert!(md.starts_with("| PID | NAME | PARENT | AGE |"));
        assert!(md.contains("| init (pid 1) |"), "{md}");
        assert!(md.contains("| 1m 40s |"), "{md}");
    }

    #[test]
    fn locks_csv_and_markdown_sort_like_the_text_table() {
        let e = |pid, owner: &str, mode: &str, path: &str| crate::model::LockEntry {
            id: String::new(),
            kind: "POSIX".into(),
            mode: mode.into(),
            pid: Some(pid),
            owner: owner.into(),
            path: path.into(),
        };
        let entries = vec![e(9, "b", "READ", "/z.lock"), e(2, "a", "WRITE", "/m.lock")];
        let csv = render_locks_csv(&entries);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "pid,owner,mode,type,path");
        assert_eq!(lines[1], "2,a,WRITE,POSIX,/m.lock");
        assert_eq!(lines[2], "9,b,READ,POSIX,/z.lock");
        assert_eq!(render_locks_csv(&[]), "pid,owner,mode,type,path\n");

        let md = render_locks_markdown(&entries);
        assert!(md.starts_with("| PID | OWNER | MODE | TYPE | PATH |"));
        assert!(md.contains("| /m.lock |"), "{md}");
    }

    #[test]
    fn services_table_sorts_running_first_and_formats_all_ways() {
        let svc = |mgr: &str, name: &str, state: &str, pid: Option<i32>, desc: &str| {
            crate::model::Service {
                manager: mgr.into(),
                name: name.into(),
                state: state.into(),
                desc: desc.into(),
                pid,
            }
        };
        let mut svcs = vec![
            svc("launchd", "zeta.agent", "not running", None, ""),
            svc("systemd", "nginx.service", "active/running", Some(7), "web server"),
            svc("systemd", "alpha.service", "failed", None, "broken"),
        ];
        sort_services(&mut svcs);
        // running first; then manager (launchd < systemd) and name
        assert_eq!(svcs[0].name, "nginx.service");
        assert_eq!(svcs[1].name, "zeta.agent");
        assert_eq!(svcs[2].name, "alpha.service");

        let p = Painter::new(false);
        assert!(render_services(&[], &p).contains("no services reported"));
        let table = render_services(&svcs, &p);
        assert!(
            table.contains("MANAGER") && table.contains("DESCRIPTION"),
            "{table}"
        );
        assert!(table.contains("nginx.service"), "{table}");
        assert!(table.lines().nth(1).unwrap().contains("web server"));

        let csv = render_services_csv(&svcs);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "manager,name,state,pid,desc");
        assert_eq!(lines[1], "systemd,nginx.service,active/running,7,web server");
        // not running: empty pid field
        assert!(
            csv.lines()
                .any(|l| l == "systemd,alpha.service,failed,,broken"),
            "{csv}"
        );

        let md = render_services_markdown(&svcs);
        assert!(md.starts_with("| MANAGER | NAME | STATE | PID | DESCRIPTION |"));
        assert!(md.contains("| 7 |"), "{md}");
    }

    fn sock(
        proto: &str,
        local: &str,
        lport: u16,
        peer: Option<(&str, u16)>,
        state: &str,
        pid: Option<i32>,
    ) -> crate::model::Socket {
        crate::model::Socket {
            proto: proto.into(),
            local_addr: local.into(),
            local_port: lport,
            peer_addr: peer.map(|(a, _)| a.to_string()),
            peer_port: peer.map(|(_, p)| p),
            state: state.into(),
            pid,
        }
    }

    #[test]
    fn conns_drop_listen_attribute_loopback_peers_and_sort_ownerless_last() {
        let sockets = vec![
            // a loopback request/response pair + its listener
            sock("tcp", "127.0.0.1", 52000, Some(("127.0.0.1", 8080)), "ESTABLISHED", Some(100)),
            sock("tcp", "127.0.0.1", 8080, Some(("127.0.0.1", 52000)), "ESTABLISHED", Some(200)),
            sock("tcp", "127.0.0.1", 8080, None, "LISTEN", Some(200)),
            // a remote connection and an ownerless time-wait leftover
            sock("tcp", "10.0.0.5", 33976, Some(("8.8.8.8", 443)), "ESTABLISHED", Some(100)),
            sock("tcp", "10.0.0.5", 40001, Some(("8.8.8.8", 443)), "TIME_WAIT", None),
        ];
        let procs = vec![proc(100, "curl", None, None), proc(200, "nginx", None, None)];
        let rows = collect_conns(&sockets, &procs);
        // LISTEN dropped: 4 rows
        assert_eq!(rows.len(), 4, "{rows:?}");
        // both ends of the loopback pair attributed to each other
        let client = rows.iter().find(|r| r.local.contains(":52000")).unwrap();
        assert_eq!(client.owner, "curl (pid 100)");
        assert_eq!(client.peer_pid, Some(200));
        assert_eq!(client.peer_owner, "nginx (pid 200)");
        let server = rows.iter().find(|r| r.local.contains(":8080")).unwrap();
        assert_eq!(server.peer_pid, Some(100));
        // remote peer stays unattributed
        let remote = rows.iter().find(|r| r.peer.contains("8.8.8.8:443") && r.pid == Some(100)).unwrap();
        assert_eq!(remote.peer_owner, "");
        // ownerless rows sort last
        assert_eq!(rows.last().unwrap().owner, "");
        // don't attribute to yourself: a socket pair within one pid stays quiet
        let solo = collect_conns(
            &[sock(
                "tcp",
                "127.0.0.1",
                9000,
                Some(("127.0.0.1", 9001)),
                "ESTABLISHED",
                Some(100),
            )],
            &procs,
        );
        assert_eq!(solo[0].peer_owner, "");

        let p = Painter::new(false);
        assert!(render_conns(&[], &p).contains("no connections"));
        let table = render_conns(&rows, &p);
        assert!(table.contains("PROTO") && table.contains("OWNER"));
        assert!(table.contains("↔ nginx (pid 200)"), "{table}");

        let csv = render_conns_csv(&rows);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "proto,local,peer,state,pid,owner,peer_pid,peer_owner");
        assert!(
            lines
                .iter()
                .any(|l| l.contains(":52000") && l.ends_with(",200,nginx (pid 200)")),
            "{csv}"
        );

        let md = render_conns_markdown(&rows);
        assert!(md.starts_with("| PROTO | LOCAL | PEER | STATE | PID | OWNER | PEER OWNER |"));
        assert!(md.contains("| nginx (pid 200) |"), "{md}");
    }

    #[test]
    fn conns_by_peer_folds_ports_and_sorts_busiest_first() {
        let sockets = vec![
            sock("tcp", "10.0.0.5", 33976, Some(("8.8.8.8", 443)), "ESTABLISHED", Some(100)),
            sock("tcp", "10.0.0.5", 40001, Some(("8.8.8.8", 443)), "TIME_WAIT", None),
            sock("tcp", "10.0.0.5", 41000, Some(("8.8.4.4", 53)), "ESTABLISHED", Some(100)),
            // unconnected UDP folds under the (no peer) bucket
            sock("udp", "0.0.0.0", 5353, None, "UNCONNECTED", Some(200)),
        ];
        let procs = vec![proc(100, "curl", None, None), proc(200, "mdns", None, None)];
        let rows = collect_conns(&sockets, &procs);
        let peers = collect_conns_by_peer(&rows);
        assert_eq!(peers.len(), 3, "{peers:?}");
        // the two :443 connections fold into one peer, ports stripped
        let dns = peers.iter().find(|p| p.peer == "8.8.4.4").unwrap();
        let gw = peers.iter().find(|p| p.peer == "8.8.8.8").unwrap();
        assert_eq!(gw.conns, 2);
        assert_eq!(gw.established, 1);
        assert_eq!(gw.states.get("TIME_WAIT"), Some(&1));
        assert_eq!(gw.owners, vec!["curl (pid 100)"], "TIME_WAIT unowned adds no owner");
        // busiest first
        assert_eq!(peers[0].peer, "8.8.8.8");
        assert_eq!(dns.conns, 1);
        let none = peers.iter().find(|p| p.peer == "(no peer)").unwrap();
        assert_eq!(none.conns, 1);
        assert_eq!(none.established, 0);

        let p = Painter::new(false);
        assert!(render_conns_by_peer(&[], &p).contains("no connections"));
        let table = render_conns_by_peer(&peers, &p);
        assert!(table.contains("PEER") && table.contains("CONNS") && table.contains("EST"));
        assert!(table.contains("TIME_WAIT 1"), "{table}");
        let csv = render_conns_by_peer_csv(&peers);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "peer,conns,established,states,owners");
        assert!(
            lines.iter().any(|l| l.starts_with("8.8.8.8,2,1,")),
            "{csv}"
        );
        let md = render_conns_by_peer_markdown(&peers);
        assert!(md.starts_with("| PEER | CONNS | EST | STATES | OWNERS |"), "{md}");
    }

    #[test]
    fn csv_and_markdown_render_header_plus_rows() {
        let procs = vec![proc(7, "nginx", Some(1.5), Some(2048))];
        let csv = render_csv(&procs);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "pid,ppid,user,cpu_pct,rss_mb,state,age,name,command");
        assert!(lines[1].starts_with("7,,"));
        assert!(lines[1].contains("1.5"));
        assert!(lines[1].contains("2"), "2048 KiB → 2 MB");
        assert!(lines[1].contains("nginx --flag"));
        let md = render_markdown(&procs);
        assert!(md.starts_with("| PID | PPID | USER | CPU% | RSS MB | STATE | AGE | NAME | COMMAND |"));
        assert!(md.contains("| 7 |"));
        assert!(md.contains("| 1.5 |"));
    }

    #[test]
    fn markdown_escapes_pipes_in_commands() {
        let mut p = proc(1, "sh", None, None);
        p.cmdline = vec!["sh".into(), "-c".into(), "a | b".into()];
        let md = render_markdown(std::slice::from_ref(&p));
        assert!(md.contains("a \\| b"), "{md}");
    }

    #[test]
    fn top_ranks_by_metric_and_drops_unmeasured() {
        use crate::cli::TopMetric;
        let painter = Painter::new(false);
        let procs = vec![
            proc(1, "low", Some(0.5), Some(1024)),
            proc(2, "high", Some(9.0), Some(8192)),
            proc(3, "unknown", None, None),
        ];
        let out = render_top(&procs, TopMetric::Cpu, 10, None, None, &painter);
        let high = out.find("high").unwrap();
        let low = out.find("low").unwrap();
        assert!(high < low, "9.0 ranks above 0.5:\n{out}");
        assert!(!out.contains("unknown"), "unmeasured processes drop out");
        // count caps the rows
        let out2 = render_top(&procs, TopMetric::Cpu, 1, None, None, &painter);
        assert!(out2.contains("high"));
        assert!(!out2.contains("low"), "count=1 keeps only the best");
        // fd without a counts map → nothing to rank, note explains
        let out3 = render_top(&procs, TopMetric::Fd, 10, None, None, &painter);
        assert!(out3.contains("no fd counts"));
        // io never measured → platform note
        let out4 = render_top(&procs, TopMetric::Io, 10, None, None, &painter);
        assert!(out4.contains("no per-process I/O counters"));
    }

    #[test]
    fn top_fd_uses_the_counts_map() {
        use crate::cli::TopMetric;
        use std::collections::HashMap;
        let painter = Painter::new(false);
        let procs = vec![proc(1, "a", None, None), proc(2, "b", None, None)];
        let mut fds = HashMap::new();
        fds.insert(1, 4u64);
        fds.insert(2, 900u64);
        let out = render_top(&procs, TopMetric::Fd, 10, Some(&fds), None, &painter);
        let b = out.find("b").unwrap();
        let a = out.find("a").unwrap();
        assert!(b < a, "900 fds ranks above 4:\n{out}");
    }

    #[test]
    fn html_report_escapes_and_bars() {
        let mut p = proc(1, "<script>", Some(50.0), Some(4096));
        p.cmdline = vec!["x".into(), "&y".into()];
        let html = render_html_report(std::slice::from_ref(&p));
        assert!(!html.contains("<script>"), "name is escaped");
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&amp;y"));
        assert!(html.contains("width:100%"), "max-cpu row gets a full bar");
        assert!(html.contains("Top CPU"));
        assert!(html.contains("1 processes"));
    }
}
