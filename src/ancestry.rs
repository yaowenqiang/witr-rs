use std::collections::{HashMap, HashSet};

use crate::model::{Child, Pid, Process};

pub struct Ancestry {
    /// root first, the traced process last
    pub chain: Vec<Process>,
    pub warnings: Vec<String>,
}

/// Walk the ppid chain of `start` over the snapshot `procs`, with cycle
/// and depth guards. The chain is returned root-first.
pub fn build_ancestry(procs: &HashMap<Pid, Process>, start: Pid, max_depth: usize) -> Ancestry {
    let mut chain: Vec<Process> = Vec::new();
    let mut warnings = Vec::new();
    let mut seen: HashSet<Pid> = HashSet::new();
    let mut cur = start;
    loop {
        match procs.get(&cur) {
            Some(p) => {
                chain.push(p.clone());
                seen.insert(cur);
                match p.ppid {
                    Some(ppid) if ppid != cur && ppid > 0 => {
                        if seen.contains(&ppid) {
                            warnings.push(format!(
                                "process {} ({}) claims parent {} which is already in the chain — cycle (kernel bug or recycled pid)",
                                p.pid, p.name, ppid
                            ));
                            break;
                        }
                        if chain.len() >= max_depth {
                            warnings.push(format!(
                                "stopped walking ancestry at depth {} (pid {})",
                                max_depth, ppid
                            ));
                            break;
                        }
                        cur = ppid;
                    }
                    _ => break, // reached the root
                }
            }
            None => {
                if chain.is_empty() {
                    warnings.push(format!("pid {} not found (exited, or permission denied)", cur));
                } else {
                    warnings.push(format!(
                        "parent pid {} no longer exists — it exited after spawning {} (orphaned/double-forked)",
                        cur,
                        chain.last().map(|p| p.name.as_str()).unwrap_or("?")
                    ));
                }
                break;
            }
        }
    }
    chain.reverse();
    Ancestry { chain, warnings }
}

pub fn direct_children(procs: &HashMap<Pid, Process>, pid: Pid) -> Vec<Child> {
    let mut kids: Vec<Child> = procs
        .values()
        .filter(|p| p.ppid == Some(pid) && p.pid != pid)
        .map(|p| Child {
            pid: p.pid,
            name: p.name.clone(),
            command: if p.cmdline.is_empty() { p.name.clone() } else { p.cmdline.join(" ") },
        })
        .collect();
    kids.sort_by_key(|c| c.pid);
    kids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: Pid, ppid: Option<Pid>, name: &str) -> Process {
        Process { pid, ppid, name: name.into(), ..Default::default() }
    }

    #[test]
    fn walks_to_root() {
        let m: HashMap<Pid, Process> = [
            proc(1, None, "init"),
            proc(100, Some(1), "sshd"),
            proc(200, Some(100), "bash"),
        ]
        .into_iter()
        .map(|p| (p.pid, p))
        .collect();
        let a = build_ancestry(&m, 200, 64);
        let names: Vec<&str> = a.chain.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["init", "sshd", "bash"]);
        assert!(a.warnings.is_empty());
    }

    #[test]
    fn missing_parent() {
        let m: HashMap<Pid, Process> = [proc(1, None, "init"), proc(200, Some(99), "daemon")]
            .into_iter()
            .map(|p| (p.pid, p))
            .collect();
        let a = build_ancestry(&m, 200, 64);
        // only the daemon itself is in the chain; the parent is gone
        assert_eq!(a.chain.len(), 1);
        assert!(a.warnings[0].contains("no longer exists"));
    }

    #[test]
    fn cycle_guard() {
        let m: HashMap<Pid, Process> = [
            proc(10, Some(11), "a"),
            proc(11, Some(10), "b"),
        ]
        .into_iter()
        .map(|p| (p.pid, p))
        .collect();
        let a = build_ancestry(&m, 10, 64);
        assert!(a.warnings[0].contains("cycle"));
    }

    #[test]
    fn depth_guard() {
        let m: HashMap<Pid, Process> = (0..10)
            .map(|i| {
                let p = proc(i, Some(i + 1), "x");
                (i, p)
            })
            .collect();
        let a = build_ancestry(&m, 0, 5);
        assert_eq!(a.chain.len(), 5);
        assert!(a.warnings[0].contains("depth 5"));
    }

    #[test]
    fn children() {
        let m: HashMap<Pid, Process> = [
            proc(1, None, "init"),
            proc(2, Some(1), "a"),
            proc(3, Some(1), "b"),
            proc(4, Some(2), "grandchild"),
        ]
        .into_iter()
        .map(|p| (p.pid, p))
        .collect();
        let kids = direct_children(&m, 1);
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0].pid, 2);
        assert_eq!(kids[1].pid, 3);
    }
}
