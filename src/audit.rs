//! `--audit CMD`: run a command and observe only its process subtree, then
//! print the resource report on exit — wall duration, exit code, spawned
//! process count, peak subtree CPU/RSS, disk I/O and the process tree.
//!
//! Sampling walks the whole process table every 500 ms and keeps everything
//! reachable from the audited root via ppid links. Two approximations, both
//! documented because they shape the numbers:
//!
//! - a child that exits mid-run keeps its contribution: per-pid cumulative
//!   I/O counters and identity info are remembered at last sighting, so
//!   short-lived build steps aren't dropped from the totals;
//! - a child whose *parent* exited mid-run usually reparents (unix: to
//!   init), breaking the ppid walk — one generation of catch-up is done by
//!   also adopting processes whose parent was in the previous tick's
//!   subtree. Deeper reparent chains can still slip away (rare in build
//!   trees, where the chain dies root-first).

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::time::{Duration, Instant};

use crate::model::{Pid, Process};

/// How often the subtree is sampled (peak tracking resolution).
const SAMPLE_EVERY: Duration = Duration::from_millis(500);

/// One audit run: spawn `cmd` under the shell, sample until it exits,
/// print the report. Returns the command's exit code (1 when it died to a
/// signal or could not be spawned).
pub fn run(cmd: &str, color: bool) -> i32 {
    #[cfg(windows)]
    let mut child = match std::process::Command::new("cmd").args(["/C", cmd]).spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("--audit {cmd}: {e}");
            return 1;
        }
    };
    #[cfg(not(windows))]
    let mut child = match std::process::Command::new("sh").args(["-c", cmd]).spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("--audit {cmd}: {e}");
            return 1;
        }
    };
    let root: Pid = child.id() as i32;
    let platform = crate::platform::get();
    let mut hist = crate::history::History::new();
    let painter = crate::render::Painter::new(color);

    // every pid ever seen in the subtree → its last sighting (identity for
    // the tree, cumulative io for the totals)
    let mut seen: HashMap<Pid, Process> = HashMap::new();
    // last tick's subtree membership — the reparent catch-up set
    let mut prev_members: HashSet<Pid> = HashSet::new();
    let mut peak_rss_kb: u64 = 0;
    let mut peak_cpu: f64 = 0.0;
    let mut peak_alive: usize = 0;
    let mut io_total: HashMap<Pid, (u64, u64)> = HashMap::new();
    let started = Instant::now();

    loop {
        // reap without blocking: a finished command ends the sampling loop
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        std::thread::sleep(SAMPLE_EVERY);
        let Ok(mut procs) = platform.list_processes() else {
            continue;
        };
        platform.enrich_listing(&mut procs);
        let _ = hist.update(&procs);
        let by_pid: HashMap<Pid, &Process> = procs.iter().map(|p| (p.pid, p)).collect();
        // membership: the root, anything whose parent is the root or a
        // current member, plus one generation of reparent catch-up (parent
        // was a member last tick)
        let mut members: HashSet<Pid> = HashSet::new();
        let mut grew = true;
        while grew {
            grew = false;
            for p in &procs {
                if members.contains(&p.pid) {
                    continue;
                }
                let in_tree = p.pid == root
                    || p.ppid.is_some_and(|pp| pp == root || members.contains(&pp))
                    || p.ppid.is_some_and(|pp| prev_members.contains(&pp) && !by_pid.contains_key(&pp));
                if in_tree {
                    members.insert(p.pid);
                    grew = true;
                }
            }
        }
        if members.is_empty() && prev_members.contains(&root) {
            // the whole subtree is gone — nothing left to measure
            break;
        }
        let mut rss_sum: u64 = 0;
        let mut cpu_sum: f64 = 0.0;
        for pid in &members {
            let Some(p) = by_pid.get(pid) else { continue };
            rss_sum += p.mem_kb.unwrap_or(0);
            cpu_sum += hist.cpu_now.get(pid).copied().unwrap_or(0.0);
            if let (Some(r), Some(w)) = (p.io_read_bytes, p.io_write_bytes) {
                let e = io_total.entry(*pid).or_insert((0, 0));
                e.0 = e.0.max(r);
                e.1 = e.1.max(w);
            }
            seen.insert(*pid, (*p).clone());
        }
        peak_rss_kb = peak_rss_kb.max(rss_sum);
        peak_cpu = peak_cpu.max(cpu_sum);
        peak_alive = peak_alive.max(members.len());
        prev_members = members;
    }

    let elapsed = started.elapsed();

    // ---- the report --------------------------------------------------
    let mut out = String::new();
    let _ = writeln!(out, "== audit: {cmd} ==");
    let (code_txt, code) = match child.wait() {
        Ok(st) => match st.code() {
            Some(c) => (format!("exit code {c}"), c),
            None => ("killed by signal".into(), 1),
        },
        Err(e) => (format!("wait failed: {e}"), 1),
    };
    let _ = writeln!(
        out,
        "duration {} · {code_txt}",
        crate::util::fmt_age(elapsed.as_secs() as i64),
    );
    let io_read: u64 = io_total.values().map(|(r, _)| r).sum();
    let io_write: u64 = io_total.values().map(|(_, w)| w).sum();
    let _ = writeln!(
        out,
        "processes spawned {} (peak alive {peak_alive}) · peak CPU (subtree) {peak_cpu:.0}% · peak RSS {}",
        seen.len(),
        crate::util::fmt_bytes(peak_rss_kb * 1024),
    );
    let _ = writeln!(
        out,
        "disk I/O: read {} · write {}",
        crate::util::fmt_bytes(io_read),
        crate::util::fmt_bytes(io_write),
    );
    // the tree: last sighting of every member, rendered as a forest — the
    // audit root is a root here because witr-rs's own pid isn't in the set
    let mut members: Vec<Process> = seen.into_values().collect();
    members.sort_by_key(|p| p.pid);
    let _ = writeln!(out, "\nprocess tree ({} processes, last sighting):", members.len());
    let _ = write!(out, "{}", crate::render::render_process_forest(&members, &painter));
    print!("{out}");
    let _ = std::io::stdout().flush();
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn audit_of_true_reports_zero_and_fast() {
        // the smallest real command: exits 0 almost immediately
        let code = run("true", false);
        assert_eq!(code, 0);
    }

    #[cfg(unix)]
    #[test]
    fn audit_mirrors_child_exit_code() {
        let code = run("sh -c 'exit 3'", false);
        assert_eq!(code, 3);
    }

    #[cfg(unix)]
    #[test]
    fn audit_counts_spawned_children() {
        // two levels of children: sh -c spawns sh -c spawns sleep
        let code = run("sh -c 'sh -c \"sleep 0.2\" ; true'", false);
        assert_eq!(code, 0);
    }
}
