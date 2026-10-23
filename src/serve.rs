//! `--serve [HOST]:PORT`: a Prometheus text-format endpoint (/metrics) and
//! a small JSON API — /api/ps (process table), /api/ports (listeners),
//! /api/tree (nested forest), /api/top?metric=&n= (ranked slice),
//! /api/services (service-manager units), /api/conns (sockets outside
//! LISTEN with owner + loopback peer attribution), all in the same
//! versioned envelopes the CLI prints. Every scrape samples the
//! process table fresh — no background
//! sampler, no interval to tune; scrape frequency IS the sample rate.
//!
//! Hand-rolled on std::net (one thread per connection, sequential reads)
//! so the binary keeps zero extra dependencies. Cardinality stays bounded:
//! per-process gauges cover the union of the top-20 CPU and top-20 RSS
//! processes (including cumulative IO read/write counters — `rate()` them
//! for throughput), plus the machine totals; port gauges are one series per
//! listening (proto, port).

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use crate::model::{Pid, Process};
use crate::platform::Platform;

/// How many processes get per-process series, per metric (the union of the
/// two sets is exported — keeps label cardinality predictable).
const TOP_N: usize = 20;

/// Parse a `--serve` value: `[HOST]:PORT` or a bare PORT (host defaults to
/// 127.0.0.1 — metrics may name processes; don't broadcast by default).
pub fn parse_addr(spec: &str) -> Option<String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    if let Ok(port) = spec.parse::<u16>() {
        return Some(format!("127.0.0.1:{port}"));
    }
    // reject obvious garbage early; the real check is TcpListener::bind
    (spec.contains(':') && !spec.ends_with(':')).then(|| spec.to_string())
}

/// Metric labels escape: backslash, quote and newline (Prometheus label
/// value rules).
fn label_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// The union of the top-N cpu and top-N rss processes — the set that gets
/// per-process series this scrape.
fn export_set(procs: &[Process], n: usize) -> Vec<&Process> {
    let mut pick: HashSet<Pid> = HashSet::new();
    let mut by_cpu: Vec<&Process> = procs.iter().filter(|p| p.cpu.is_some()).collect();
    by_cpu.sort_by(|a, b| {
        b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal)
    });
    pick.extend(by_cpu.iter().take(n).map(|p| p.pid));
    let mut by_mem: Vec<&Process> = procs.iter().filter(|p| p.mem_kb.is_some()).collect();
    by_mem.sort_by_key(|p| std::cmp::Reverse(p.mem_kb));
    pick.extend(by_mem.iter().take(n).map(|p| p.pid));
    let mut out: Vec<&Process> = procs.iter().filter(|p| pick.contains(&p.pid)).collect();
    out.sort_by_key(|p| p.pid);
    out
}

/// One scrape: sample the platform and render the Prometheus exposition.
fn scrape(platform: &dyn Platform, fds: Option<&HashMap<Pid, u64>>) -> String {
    let mut out = String::with_capacity(16 * 1024);
    let mut procs = platform.list_processes().unwrap_or_default();
    // IO counters need enrich_listing (proc_pid_rusage / /proc/<pid>/io per
    // process) — same cost class as the fd sweep, paid once per scrape
    platform.enrich_listing(&mut procs);
    let rss_total: u64 = procs.iter().filter_map(|p| p.mem_kb).sum::<u64>() / 1024;
    out.push_str("# HELP witr_process_count Visible processes\n");
    out.push_str("# TYPE witr_process_count gauge\n");
    out.push_str(&format!("witr_process_count {}\n", procs.len()));
    out.push_str("# HELP witr_rss_total_mb Sum of resident memory (MB) across visible processes\n");
    out.push_str("# TYPE witr_rss_total_mb gauge\n");
    out.push_str(&format!("witr_rss_total_mb {rss_total}\n"));

    let set = export_set(&procs, TOP_N);
    out.push_str("# HELP witr_process_cpu_percent CPU percent (lifetime average as reported by the platform)\n");
    out.push_str("# TYPE witr_process_cpu_percent gauge\n");
    for p in &set {
        if let Some(v) = p.cpu {
            out.push_str(&format!(
                "witr_process_cpu_percent{{pid=\"{}\",name=\"{}\",user=\"{}\"}} {v:.2}\n",
                p.pid,
                label_escape(&p.name),
                label_escape(p.user.as_deref().unwrap_or("-")),
            ));
        }
    }
    out.push_str("# HELP witr_process_rss_bytes Resident set size in bytes\n");
    out.push_str("# TYPE witr_process_rss_bytes gauge\n");
    for p in &set {
        if let Some(kb) = p.mem_kb {
            out.push_str(&format!(
                "witr_process_rss_bytes{{pid=\"{}\",name=\"{}\",user=\"{}\"}} {}\n",
                p.pid,
                label_escape(&p.name),
                label_escape(p.user.as_deref().unwrap_or("-")),
                kb * 1024,
            ));
        }
    }
    // cumulative disk I/O as counters — `rate()` in PromQL turns them into
    // per-process read/write throughput (same top-N set, bounded cardinality)
    out.push_str("# HELP witr_process_io_read_bytes_total Cumulative disk read bytes\n");
    out.push_str("# TYPE witr_process_io_read_bytes_total counter\n");
    for p in &set {
        if let Some(v) = p.io_read_bytes {
            out.push_str(&format!(
                "witr_process_io_read_bytes_total{{pid=\"{}\",name=\"{}\"}} {v}\n",
                p.pid,
                label_escape(&p.name),
            ));
        }
    }
    out.push_str("# HELP witr_process_io_write_bytes_total Cumulative disk write bytes\n");
    out.push_str("# TYPE witr_process_io_write_bytes_total counter\n");
    for p in &set {
        if let Some(v) = p.io_write_bytes {
            out.push_str(&format!(
                "witr_process_io_write_bytes_total{{pid=\"{}\",name=\"{}\"}} {v}\n",
                p.pid,
                label_escape(&p.name),
            ));
        }
    }
    out.push_str("# HELP witr_process_open_fds Open file descriptors\n");
    out.push_str("# TYPE witr_process_open_fds gauge\n");
    for p in &set {
        if let Some(n) = fds.and_then(|m| m.get(&p.pid)) {
            out.push_str(&format!(
                "witr_process_open_fds{{pid=\"{}\",name=\"{}\"}} {n}\n",
                p.pid,
                label_escape(&p.name),
            ));
        }
    }
    // process start time as a unix timestamp: a series reset to now after a
    // dip is the standard Prometheus restart signal (rate() breaks, alert
    // on the jump)
    out.push_str("# HELP witr_process_start_time_seconds Process start time as unix seconds\n");
    out.push_str("# TYPE witr_process_start_time_seconds gauge\n");
    for p in &set {
        if let Some(t) = p.started {
            out.push_str(&format!(
                "witr_process_start_time_seconds{{pid=\"{}\",name=\"{}\"}} {t}\n",
                p.pid,
                label_escape(&p.name),
            ));
        }
    }
    // listening sockets: one series per (proto, port), owner a comma-joined
    // "name (pid N)" list — port sprawl and unexpected listeners at a glance
    let socks = platform.list_sockets().unwrap_or_default();
    let listeners = crate::snapshot::to_listeners(&socks, &procs);
    out.push_str("# HELP witr_port_listeners Listening sockets by proto and port\n");
    out.push_str("# TYPE witr_port_listeners gauge\n");
    for l in &listeners {
        out.push_str(&format!(
            "witr_port_listeners{{proto=\"{}\",port=\"{}\",owner=\"{}\"}} 1\n",
            label_escape(&l.proto),
            l.port,
            label_escape(&l.who.join(", ")),
        ));
    }
    // self-monitoring: total scrapes served and how long the last one took
    out.push_str("# HELP witr_scrapes_total Scrapes served since startup\n");
    out.push_str("# TYPE witr_scrapes_total counter\n");
    out.push_str(&format!(
        "witr_scrapes_total {}\n",
        SCRAPES.load(std::sync::atomic::Ordering::Relaxed)
    ));
    out.push_str("# HELP witr_scrape_duration_seconds Duration of the last scrape\n");
    out.push_str("# TYPE witr_scrape_duration_seconds gauge\n");
    out.push_str(&format!(
        "witr_scrape_duration_seconds {:.6}\n",
        LAST_SCRAPE_MICROS.load(std::sync::atomic::Ordering::Relaxed) as f64 / 1_000_000.0
    ));
    out.push_str("# HELP witr_scrape_timestamp_unix Unix seconds of this scrape\n");
    out.push_str("# TYPE witr_scrape_timestamp_unix gauge\n");
    out.push_str(&format!(
        "witr_scrape_timestamp_unix {}\n",
        crate::util::now_unix()
    ));
    out
}

/// Parse the /api/top query string: `metric=` and `n=` params, defaults
/// cpu / 10, n clamped to 1..=500 (unknown params ignored, a bad n falls
/// back to 10 — same leniency as the CLI's defaults).
fn parse_top_query(query: &str) -> (String, usize) {
    let mut metric = "cpu".to_string();
    let mut n: usize = 10;
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        if let Some((k, v)) = kv.split_once('=') {
            match k {
                "metric" => metric = v.to_string(),
                "n" => n = v.parse().unwrap_or(10),
                _ => {}
            }
        }
    }
    (metric, n.clamp(1, 500))
}

/// Self-monitoring counters (process-global — each connection thread bumps
/// them around its scrape).
static SCRAPES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LAST_SCRAPE_MICROS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn respond(stream: &mut TcpStream, status: &str, ctype: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}

/// Bind and serve until the process is killed. Each connection thread
/// builds its own platform instance (`platform::get()` — the impls carry
/// internal caches, and the trait isn't Sync), so scrapes never contend.
/// Per-pid fd counts cost one sweep; they're only paid for real scrapes
/// when the platform supports them (one lsof scan on macOS, a /proc walk
/// on Linux).
pub fn run(addr: &str, fds_enabled: bool) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    crate::write_out(&format!(
        "serving Prometheus metrics → http://{addr}/metrics (Ctrl-C to stop)"
    ));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let Ok(n) = stream.read(&mut buf) else { return };
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req.split_whitespace().nth(1).unwrap_or("");
            // /api/ps: the full process table as the same versioned JSON
            // envelope `--json` prints — a machine-readable sibling to the
            // Prometheus gauges
            if path == "/api/ps" || path.starts_with("/api/ps?") {
                let platform = crate::platform::get();
                let mut procs = platform.list_processes().unwrap_or_default();
                platform.enrich_listing(&mut procs);
                respond(
                    &mut stream,
                    "200 OK",
                    "application/json",
                    &crate::json_envelope(&procs),
                );
                return;
            }
            // /api/ports: the LISTEN table (proto, port, owners) — the
            // `--ports` listing as JSON
            if path == "/api/ports" || path.starts_with("/api/ports?") {
                let platform = crate::platform::get();
                let procs = platform.list_processes().unwrap_or_default();
                let socks = platform.list_sockets().unwrap_or_default();
                let mut listeners = crate::snapshot::to_listeners(&socks, &procs);
                listeners.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.proto.cmp(&b.proto)));
                let doc = serde_json::json!({
                    "schema_version": crate::SCHEMA_VERSION,
                    "generated_at": crate::util::now_unix(),
                    "listener_count": listeners.len(),
                    "listeners": listeners,
                });
                respond(
                    &mut stream,
                    "200 OK",
                    "application/json",
                    &serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()),
                );
                return;
            }
            // /api/tree: the nested children forest — `--tree --json` over
            // HTTP
            if path == "/api/tree" || path.starts_with("/api/tree?") {
                let platform = crate::platform::get();
                let procs = platform.list_processes().unwrap_or_default();
                respond(
                    &mut stream,
                    "200 OK",
                    "application/json",
                    &crate::json_tree_forest(&procs),
                );
                return;
            }
            // /api/services: the service manager's units — the `--services`
            // listing as JSON (running units first, same order the CLI prints)
            if path == "/api/services" || path.starts_with("/api/services?") {
                let mut svcs = crate::platform::enumerate_services();
                crate::render::sort_services(&mut svcs);
                let doc = serde_json::json!({
                    "schema_version": crate::SCHEMA_VERSION,
                    "generated_at": crate::util::now_unix(),
                    "service_count": svcs.len(),
                    "services": svcs,
                });
                respond(
                    &mut stream,
                    "200 OK",
                    "application/json",
                    &serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()),
                );
                return;
            }
            // /api/conns: every socket outside LISTEN, owners resolved and
            // loopback peers attributed — the `--conns` board as JSON
            if path == "/api/conns" || path.starts_with("/api/conns?") {
                let platform = crate::platform::get();
                let procs = platform.list_processes().unwrap_or_default();
                let socks = platform.list_all_sockets().unwrap_or_default();
                let rows = crate::render::collect_conns(&socks, &procs);
                let doc = serde_json::json!({
                    "schema_version": crate::SCHEMA_VERSION,
                    "generated_at": crate::util::now_unix(),
                    "connection_count": rows.len(),
                    "connections": rows,
                });
                respond(
                    &mut stream,
                    "200 OK",
                    "application/json",
                    &serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()),
                );
                return;
            }
            // /api/top?metric=cpu|mem|fd|age|io|io-rate&n=N: a ranked slice of the
            // process table — the `--top` view over HTTP. One entry per
            // process ({pid, name, user, value}); value's unit follows the
            // metric (percent / bytes / count / seconds).
            if path == "/api/top" || path.starts_with("/api/top?") {
                let (metric, n) = parse_top_query(
                    path.split_once('?').map(|(_, q)| q).unwrap_or(""),
                );
                if !matches!(
                    metric.as_str(),
                    "cpu" | "mem" | "fd" | "age" | "io" | "io-rate"
                ) {
                    respond(
                        &mut stream,
                        "400 Bad Request",
                        "text/plain",
                        "metric must be one of: cpu, mem, fd, age, io, io-rate\n",
                    );
                    return;
                }
                let platform = crate::platform::get();
                let mut procs = platform.list_processes().unwrap_or_default();
                // the io metrics rank enriched counters — paid only when asked
                if matches!(metric.as_str(), "io" | "io-rate") {
                    platform.enrich_listing(&mut procs);
                }
                // io-rate is a delta metric: two enriched samples one second
                // apart turn the cumulative counters into bytes/s (the CLI's
                // one-shot --top io-rate works the same way)
                let rates = if metric == "io-rate" {
                    let mut hist = crate::history::History::new();
                    let _ = hist.update(&procs);
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    let mut again = platform.list_processes().unwrap_or_default();
                    platform.enrich_listing(&mut again);
                    let _ = hist.update(&again);
                    Some(hist)
                } else {
                    None
                };
                let fd_map = if metric == "fd" {
                    platform.fd_counts()
                } else {
                    None
                };
                if metric == "fd" && fd_map.is_none() {
                    respond(
                        &mut stream,
                        "400 Bad Request",
                        "text/plain",
                        "fd counts not available on this platform\n",
                    );
                    return;
                }
                // (sort key, pid, name, user, value) — sorted by value desc,
                // pid asc as the tiebreak so equal values stay stable
                let mut ranked: Vec<(f64, Pid, String, String, serde_json::Value)> = Vec::new();
                for p in &procs {
                    let value = match metric.as_str() {
                        "cpu" => p.cpu.map(|c| serde_json::json!(c)),
                        "mem" => p.mem_kb.map(|kb| serde_json::json!(kb * 1024)),
                        "fd" => fd_map
                            .as_ref()
                            .and_then(|m| m.get(&p.pid))
                            .map(|v| serde_json::json!(v)),
                        // cumulative read+write bytes; zero-IO processes stay
                        // out of the ranking rather than pinning the top
                        "io" => {
                            let r = p.io_read_bytes.unwrap_or(0);
                            let w = p.io_write_bytes.unwrap_or(0);
                            (r + w > 0).then(|| serde_json::json!(r + w))
                        }
                        "io-rate" => rates
                            .as_ref()
                            .and_then(|h| h.io_rate_of(p.pid))
                            .map(|(r, w)| serde_json::json!(r + w)),
                        _ => p
                            .started
                            .map(|t| serde_json::json!(crate::util::now_unix() - t)),
                    };
                    if let Some(value) = value {
                        ranked.push((
                            value.as_f64().unwrap_or(0.0),
                            p.pid,
                            p.name.clone(),
                            p.user.clone().unwrap_or_else(|| "-".into()),
                            value,
                        ));
                    }
                }
                ranked.sort_by(|a, b| {
                    b.0.partial_cmp(&a.0)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| a.1.cmp(&b.1))
                });
                ranked.truncate(n);
                let entries: Vec<serde_json::Value> = ranked
                    .into_iter()
                    .map(|(_, pid, name, user, value)| {
                        serde_json::json!({
                            "pid": pid, "name": name, "user": user, "value": value
                        })
                    })
                    .collect();
                let doc = serde_json::json!({
                    "schema_version": crate::SCHEMA_VERSION,
                    "generated_at": crate::util::now_unix(),
                    "metric": metric,
                    "n": entries.len(),
                    "entries": entries,
                });
                respond(
                    &mut stream,
                    "200 OK",
                    "application/json",
                    &serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into()),
                );
                return;
            }
            if !path.starts_with("/metrics") {
                match path {
                    "/" => respond(
                        &mut stream,
                        "200 OK",
                        "text/plain; charset=utf-8",
                        "witr-rs: /metrics (Prometheus) · /api/ps (process table) · /api/ports (listeners) · /api/conns (connections) · /api/tree (forest) · /api/top?metric=cpu|mem|fd|age|io|io-rate&n=N (rankings) · /api/services (service units)\n",
                    ),
                    _ => respond(&mut stream, "404 Not Found", "text/plain", "not found\n"),
                }
                return;
            }
            let platform = crate::platform::get();
            let fds = if fds_enabled { platform.fd_counts() } else { None };
            // bump before rendering so the current scrape counts itself
            SCRAPES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let started = std::time::Instant::now();
            let body = scrape(platform.as_ref(), fds.as_ref());
            LAST_SCRAPE_MICROS.store(
                started.elapsed().as_micros() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            respond(
                &mut stream,
                "200 OK",
                "text/plain; version=0.0.4; charset=utf-8",
                &body,
            );
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_addr_defaults_host_and_rejects_garbage() {
        assert_eq!(parse_addr("9100").as_deref(), Some("127.0.0.1:9100"));
        assert_eq!(parse_addr(":9100").as_deref(), Some(":9100"));
        assert_eq!(
            parse_addr("0.0.0.0:9100").as_deref(),
            Some("0.0.0.0:9100")
        );
        assert_eq!(parse_addr(""), None);
        assert_eq!(parse_addr("no-colon"), None);
        assert_eq!(parse_addr("host:"), None);
    }

    #[test]
    fn label_escape_follows_prometheus_rules() {
        assert_eq!(label_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn top_query_defaults_ignores_unknown_and_clamps_n() {
        assert_eq!(parse_top_query(""), ("cpu".into(), 10));
        assert_eq!(parse_top_query("metric=age"), ("age".into(), 10));
        assert_eq!(parse_top_query("metric=io-rate&n=25"), ("io-rate".into(), 25));
        assert_eq!(parse_top_query("n=9999"), ("cpu".into(), 500));
        assert_eq!(parse_top_query("n=0"), ("cpu".into(), 1));
        assert_eq!(parse_top_query("n=bad&metric=mem"), ("mem".into(), 10));
        assert_eq!(parse_top_query("foo=bar"), ("cpu".into(), 10));
    }

    #[test]
    fn export_set_is_the_union_of_both_tops() {
        let p = |pid: i32, cpu: Option<f64>, kb: Option<u64>| crate::model::Process {
            pid,
            cpu,
            mem_kb: kb,
            name: format!("p{pid}"),
            ..Default::default()
        };
        // 3 cpu-heavy, 3 mem-heavy, 1 idle-small — tops overlap at none
        let procs = vec![
            p(1, Some(90.0), Some(100)),
            p(2, Some(50.0), Some(200)),
            p(3, Some(10.0), Some(300)),
            p(4, None, Some(400)),
            p(5, Some(1.0), None),
        ];
        let set = export_set(&procs, 2);
        let pids: Vec<i32> = set.iter().map(|p| p.pid).collect();
        // top-2 cpu = {1,2}; top-2 mem = {4,3}; pid 5 neither
        assert_eq!(pids, vec![1, 2, 3, 4]);
    }
}
