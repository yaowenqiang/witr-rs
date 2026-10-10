//! NVIDIA GPU usage per pid: one `nvidia-smi pmon -c 1` sample parsed into
//! (SM%, mem MiB) per pid. Best effort — no nvidia-smi, no GPU, or a
//! failing driver all degrade to "no data", probed only once per run so
//! watch/TUI loops don't keep paying for a missing binary.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::model::{Pid, Process};

/// pid → (SM utilization %, dedicated memory MiB)
pub type GpuUsage = HashMap<Pid, (u32, u64)>;

/// One sample. None once the probe has failed (cached for the process
/// lifetime).
pub fn sample() -> Option<GpuUsage> {
    static UNAVAILABLE: OnceLock<()> = OnceLock::new();
    if UNAVAILABLE.get().is_some() {
        return None;
    }
    let Some(usage) = probe() else {
        let _ = UNAVAILABLE.set(());
        return None;
    };
    Some(usage)
}

fn probe() -> Option<GpuUsage> {
    use std::process::{Command, Stdio};
    let out = Command::new("nvidia-smi")
        .args(["pmon", "-c", "1"])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_pmon(&String::from_utf8_lossy(&out.stdout)))
}

/// pmon rows: `# gpu pid type sm mem enc dec command`, whitespace
/// separated; sm/mem read "-" for idle processes. A pid can appear once
/// per GPU: SM keeps the max, memory is summed.
pub fn parse_pmon(out: &str) -> GpuUsage {
    let mut map: GpuUsage = HashMap::new();
    for line in out.lines() {
        if line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        //        0   1    2     3   4    5   6    7
        if f.len() < 5 {
            continue;
        }
        let Ok(pid) = f[1].parse::<Pid>() else { continue };
        let sm = f[3].parse::<u32>().unwrap_or(0);
        let mem = f[4].parse::<u64>().unwrap_or(0);
        let e = map.entry(pid).or_insert((0, 0));
        e.0 = e.0.max(sm);
        e.1 += mem;
    }
    map
}

/// Fill the gpu_* fields of each process from one sample. No-op when the
/// host has no usable nvidia-smi.
pub fn enrich(procs: &mut [Process]) {
    let Some(usage) = sample() else { return };
    for p in procs.iter_mut() {
        if let Some((sm, mem)) = usage.get(&p.pid) {
            p.gpu_sm_pct = Some(*sm);
            p.gpu_mem_mb = Some(*mem);
        }
    }
}

/// Copy gpu fields from an enriched listing entry — TUI detail pages reuse
/// the sample the last refresh took instead of re-probing per selection.
pub fn copy_fields(from: &Process, to: &mut Process) {
    to.gpu_sm_pct = from.gpu_sm_pct;
    to.gpu_mem_mb = from.gpu_mem_mb;
}

/// True when this process carries any GPU data — drives the conditional
/// TUI column.
pub fn has_gpu_data(p: &Process) -> bool {
    p.gpu_sm_pct.is_some() || p.gpu_mem_mb.is_some()
}

/// Compact cell form for the process table: "45% 1.2G", "800M", "12%", "-".
pub fn cell(p: &Process) -> String {
    let mut s = String::new();
    if let Some(sm) = p.gpu_sm_pct {
        s.push_str(&format!("{sm}%"));
    }
    if let Some(mb) = p.gpu_mem_mb {
        if !s.is_empty() {
            s.push(' ');
        }
        if mb >= 1024 {
            s.push_str(&format!("{:.1}G", mb as f64 / 1024.0));
        } else {
            s.push_str(&format!("{mb}M"));
        }
    }
    if s.is_empty() { "-".into() } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmon_rows_parse_and_aggregate() {
        let out = "# gpu pid type sm mem enc dec command\n\
                   0         1234   C    45  1200  0   0   python3\n\
                   0         1234   C    30   800  0   0   python3\n\
                   1         555    G    -    512  0   0   Xorg\n\
                   malformed line with two fields\n\
                   n/a not-a-pid C x y 0 0 junk\n";
        let m = parse_pmon(out);
        // two GPUs: SM keeps the max, memory sums
        assert_eq!(m.get(&1234), Some(&(45, 2000)));
        // "-" SM reads as 0, memory still counts
        assert_eq!(m.get(&555), Some(&(0, 512)));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn pmon_empty_and_headers_only() {
        assert!(parse_pmon("").is_empty());
        assert!(parse_pmon("# gpu pid type sm mem enc dec command\n").is_empty());
    }

    #[test]
    fn enrich_sets_matching_pids() {
        let mut procs = [
            Process { pid: 5, name: "a".into(), ..Default::default() },
            Process { pid: 9, name: "b".into(), ..Default::default() },
        ];
        let usage: GpuUsage = [(5i32, (12u32, 256u64))].into_iter().collect();
        for p in procs.iter_mut() {
            if let Some((sm, mem)) = usage.get(&p.pid) {
                p.gpu_sm_pct = Some(*sm);
                p.gpu_mem_mb = Some(*mem);
            }
        }
        assert_eq!(procs[0].gpu_sm_pct, Some(12));
        assert_eq!(procs[0].gpu_mem_mb, Some(256));
        assert_eq!(procs[1].gpu_sm_pct, None);
        assert!(has_gpu_data(&procs[0]));
        assert!(!has_gpu_data(&procs[1]));
    }

    #[test]
    fn cell_formats() {
        let mk = |sm: Option<u32>, mem: Option<u64>| Process {
            pid: 1,
            gpu_sm_pct: sm,
            gpu_mem_mb: mem,
            ..Default::default()
        };
        assert_eq!(cell(&mk(Some(45), Some(1200))), "45% 1.2G");
        assert_eq!(cell(&mk(None, Some(800))), "800M");
        assert_eq!(cell(&mk(Some(12), None)), "12%");
        assert_eq!(cell(&mk(None, None)), "-");
    }
}
