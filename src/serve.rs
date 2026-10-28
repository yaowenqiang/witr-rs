//! `--serve [HOST]:PORT`: a Prometheus text-format endpoint (/metrics) and
//! a small JSON API — /api/ps (process table), /api/ports (listeners),
//! /api/tree (nested forest), /api/top?metric=&n= (ranked slice),
//! /api/services (service-manager units), /api/conns (sockets outside
//! LISTEN with owner + loopback peer attribution), all in the same
//! versioned envelopes the CLI prints. Every scrape samples the
//! process table fresh — no background
//! sampler, no interval to tune; scrape frequency IS the sample rate.
//! The one exception is /api/events (Server-Sent Events): a 5s delta
//! sampler arms lazily on the first hit and streams the process
//! started/exited/restarted edges.
//! Container gauges ride a background `stats --no-stream` sweep (seconds
//! per runtime CLI) refreshed at most every 30s — scrapes never block on
//! it.
//!
//! Hand-rolled on std::net (one thread per connection, sequential reads)
//! so the binary keeps zero extra dependencies. Cardinality stays bounded:
//! per-process gauges cover the union of the top-20 CPU and top-20 RSS
//! processes (including cumulative IO read/write counters — `rate()` them
//! for throughput), plus the machine totals; port gauges are one series per
//! listening (proto, port).

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;

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

/// The `/` dashboard: a self-contained, zero-JS HTML view of the machine —
/// gauges (cpu / memory / load / procs), the top-10 CPU and RSS tables and
/// the current listeners, auto-refreshed by a meta tag. Every request
/// samples fresh, same as /metrics; the cpu gauge is a delta between
/// requests, so the very first view of a cold server shows "–" until the
/// second refresh.
fn dashboard_html(platform: &dyn Platform) -> String {
    let esc = crate::render::html_escape;
    let procs = platform.list_processes().unwrap_or_default();
    let stats = platform.system_stats().unwrap_or_default();
    let listeners = {
        let socks = platform.list_sockets().unwrap_or_default();
        let mut ls = crate::snapshot::to_listeners(&socks, &procs);
        ls.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.proto.cmp(&b.proto)));
        ls
    };
    let top_cpu: Vec<&Process> = {
        let mut v: Vec<&Process> = procs.iter().filter(|p| p.cpu.is_some()).collect();
        v.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal));
        v.truncate(10);
        v
    };
    let top_mem: Vec<&Process> = {
        let mut v: Vec<&Process> = procs.iter().filter(|p| p.mem_kb.is_some()).collect();
        v.sort_by_key(|p| std::cmp::Reverse(p.mem_kb));
        v.truncate(10);
        v
    };

    let mut out = String::with_capacity(24 * 1024);
    out.push_str(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\n\
         <meta http-equiv=\"refresh\" content=\"5\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>witr-rs · dashboard</title>\n\
         <style>\n\
         body{font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;\
         margin:24px;color:#1c1c1c;background:#fafafa}\n\
         h1{font-size:19px;margin:0 0 2px}h2{font-size:13px;margin:22px 0 6px;color:#555;\
         text-transform:uppercase;letter-spacing:.05em}\n\
         .sub{color:#777;font-size:12px;margin-bottom:14px}.sub a{color:#0366d6}\n\
         .tiles{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:6px}\n\
         .tile{background:#fff;border:1px solid #e3e3e3;border-radius:8px;padding:10px 14px;min-width:130px}\n\
         .tile .k{font-size:11px;color:#777;text-transform:uppercase;letter-spacing:.05em}\n\
         .tile .v{font-size:22px;font-variant-numeric:tabular-nums;margin-top:2px}\n\
         .tile .bar{height:5px;border-radius:3px;background:#e6e6e6;margin-top:7px;overflow:hidden}\n\
         .tile .bar i{display:block;height:100%;background:#4a8f57}\n\
         table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #e3e3e3}\n\
         th,td{padding:5px 10px;text-align:left;border-bottom:1px solid #eee;\
         font-variant-numeric:tabular-nums;font-size:13px}\n\
         th{background:#f4f4f4;font-weight:600;font-size:11px;text-transform:uppercase;\
         letter-spacing:.04em;color:#555}\n\
         td.cmd{color:#666;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n\
         .hot{color:#b02a2a}.warm{color:#9a6b00}\n\
         </style></head><body>\n",
    );
    let _ = writeln!(
        out,
        "<h1>witr-rs dashboard</h1>\n\
         <div class=\"sub\">{} · {} process(es) · auto-refreshes every 5s · APIs: \
         <a href=\"/metrics\">/metrics</a> <a href=\"/api/ps\">/api/ps</a> \
         <a href=\"/api/ports\">/api/ports</a> <a href=\"/api/conns\">/api/conns</a> \
         <a href=\"/api/tree\">/api/tree</a> <a href=\"/api/services\">/api/services</a> \
         <a href=\"/api/events\">/api/events</a> \
         <a href=\"/api/top?metric=cpu&amp;n=10\">/api/top</a></div>",
        esc(&crate::util::fmt_time(crate::util::now_unix())),
        procs.len(),
    );

    // gauge tiles
    let tile = |k: &str, v: String, pct: Option<f64>| -> String {
        let bar = pct
            .map(|p| {
                let w = p.clamp(0.0, 100.0);
                let cls = if p >= 90.0 { "hot" } else { "" };
                format!(
                    "<div class=\"bar\"><i class=\"{cls}\" style=\"width:{w:.0}%\"></i></div>"
                )
            })
            .unwrap_or_default();
        format!("<div class=\"tile\"><div class=\"k\">{}</div><div class=\"v\">{}</div>{bar}</div>", esc(k), v)
    };
    let cpu_v = stats
        .cpu_percent
        .map(|c| format!("{c:.1}<span style=\"font-size:12px\">%</span>"))
        .unwrap_or_else(|| "–".into());
    let mem_v = match (stats.mem_used_mb, stats.mem_total_mb) {
        (Some(u), Some(t)) if t > 0 => format!(
            "{}<span style=\"font-size:12px\"> / {}</span>",
            esc(&crate::util::fmt_bytes(u * 1024 * 1024)),
            esc(&crate::util::fmt_bytes(t * 1024 * 1024))
        ),
        _ => "–".into(),
    };
    let load_v = stats
        .load1
        .map(|l| format!("{l:.2}"))
        .unwrap_or_else(|| "–".into());
    out.push_str("<div class=\"tiles\">");
    out.push_str(&tile("cpu", cpu_v, stats.cpu_percent));
    out.push_str(&tile(
        "memory",
        mem_v,
        stats
            .mem_used_mb
            .zip(stats.mem_total_mb)
            .and_then(|(u, t)| {
                if t > 0 {
                    Some(u as f64 / t as f64 * 100.0)
                } else {
                    None
                }
            }),
    ));
    out.push_str(&tile("load (1m)", load_v, None));
    out.push_str(&tile("processes", procs.len().to_string(), None));
    if let Some((label, c)) = &stats.temp {
        out.push_str(&tile(
            &format!("temp · {label}"),
            format!("{c:.0}°C"),
            None,
        ));
    }
    if let Some(psi) = &stats.psi {
        let worst = psi.worst_full();
        out.push_str(&tile(
            "psi full (worst)",
            format!("{worst:.1}<span style=\"font-size:12px\">%</span>"),
            None,
        ));
    }
    out.push_str("</div>\n");

    let head = "<tr><th>PID</th><th>USER</th><th>NAME</th><th>COMMAND</th><th>VALUE</th></tr>";
    let row = |p: &Process, v: String, cls: &str| -> String {
        format!(
            "<tr><td>{}</td><td>{}</td><td><b>{}</b></td><td class=\"cmd\">{}</td><td class=\"{cls}\">{}</td></tr>",
            p.pid,
            esc(p.user.as_deref().unwrap_or("-")),
            esc(&p.name),
            esc(&p.command_line()),
            v,
        )
    };
    let _ = writeln!(out, "<h2>top cpu</h2><table>{head}");
    for p in &top_cpu {
        out.push_str(&row(
            p,
            format!("{:.1}%", p.cpu.unwrap_or(0.0)),
            if p.cpu.unwrap_or(0.0) >= 80.0 { "hot" } else { "" },
        ));
    }
    out.push_str("</table>\n");
    let _ = writeln!(out, "<h2>top memory</h2><table>{head}");
    for p in &top_mem {
        out.push_str(&row(
            p,
            crate::util::fmt_bytes(p.mem_kb.unwrap_or(0) * 1024),
            "",
        ));
    }
    out.push_str("</table>\n");

    let _ = writeln!(
        out,
        "<h2>listeners</h2><table><tr><th>PORT</th><th>PROTO</th><th>SCOPE</th><th>OWNER(S)</th></tr>"
    );
    for l in &listeners {
        let scope = l.scope();
        let scope_cls = match scope {
            "internet" => "hot",
            "loopback" => "",
            _ => "warm",
        };
        let _ = writeln!(
            out,
            "<tr><td><b>{}</b></td><td>{}</td><td class=\"{scope_cls}\">{}</td><td>{}</td></tr>",
            l.port,
            esc(&l.proto),
            scope,
            esc(&l.who.join(", ")),
        );
    }
    out.push_str("</table>\n</body></html>\n");
    out
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

    // machine-wide gauges: whole-box cpu/memory/load so a witr scrape can
    // be the only node exporter a small host needs. CPU is a delta between
    // scrapes — the very first one reports nothing (same as the TUI's
    // first tick).
    if let Some(s) = platform.system_stats() {
        if let Some(cpu) = s.cpu_percent {
            out.push_str("# HELP witr_machine_cpu_percent Total CPU busy percent across all cores\n");
            out.push_str("# TYPE witr_machine_cpu_percent gauge\n");
            out.push_str(&format!("witr_machine_cpu_percent {cpu:.2}\n"));
        }
        if let Some(mb) = s.mem_used_mb {
            out.push_str("# HELP witr_machine_mem_used_bytes Used physical memory in bytes\n");
            out.push_str("# TYPE witr_machine_mem_used_bytes gauge\n");
            out.push_str(&format!("witr_machine_mem_used_bytes {}\n", mb * 1024 * 1024));
        }
        if let Some(mb) = s.mem_total_mb {
            out.push_str("# HELP witr_machine_mem_total_bytes Total physical memory in bytes\n");
            out.push_str("# TYPE witr_machine_mem_total_bytes gauge\n");
            out.push_str(&format!("witr_machine_mem_total_bytes {}\n", mb * 1024 * 1024));
        }
        if let Some(l) = s.load1 {
            out.push_str("# HELP witr_machine_load1 1-minute load average\n");
            out.push_str("# TYPE witr_machine_load1 gauge\n");
            out.push_str(&format!("witr_machine_load1 {l:.2}\n"));
        }
    }
    // cumulative NIC bytes as counters (loopback excluded) — rate() gives
    // per-interface throughput
    let nics = platform.net_counters();
    if !nics.is_empty() {
        out.push_str("# HELP witr_machine_net_rx_bytes_total Cumulative received bytes per non-loopback interface\n");
        out.push_str("# TYPE witr_machine_net_rx_bytes_total counter\n");
        for n in &nics {
            out.push_str(&format!(
                "witr_machine_net_rx_bytes_total{{nic=\"{}\"}} {}\n",
                label_escape(&n.name),
                n.rx_bytes,
            ));
        }
        out.push_str("# HELP witr_machine_net_tx_bytes_total Cumulative transmitted bytes per non-loopback interface\n");
        out.push_str("# TYPE witr_machine_net_tx_bytes_total counter\n");
        for n in &nics {
            out.push_str(&format!(
                "witr_machine_net_tx_bytes_total{{nic=\"{}\"}} {}\n",
                label_escape(&n.name),
                n.tx_bytes,
            ));
        }
    }

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
    // "name (pid N)" list, scope the exposure class (internet/loopback/
    // iface) — port sprawl and unexpected listeners at a glance
    let socks = platform.list_sockets().unwrap_or_default();
    let listeners = crate::snapshot::to_listeners(&socks, &procs);
    out.push_str("# HELP witr_port_listeners Listening sockets by proto and port\n");
    out.push_str("# TYPE witr_port_listeners gauge\n");
    for l in &listeners {
        out.push_str(&format!(
            "witr_port_listeners{{proto=\"{}\",port=\"{}\",scope=\"{}\",owner=\"{}\"}} 1\n",
            label_escape(&l.proto),
            l.port,
            l.scope(),
            label_escape(&l.who.join(", ")),
        ));
    }
    // container gauges: one info series per container from the runtime
    // listing (a cheap `ps --all`), cpu/mem from the cached background
    // `stats --no-stream` sweep (seconds per runtime — it rides a thread
    // so a scrape never blocks on the runtime CLI; the first scrapes
    // report only the info series)
    let containers = crate::platform::enumerate_containers();
    if !containers.is_empty() {
        let stats = refresh_container_stats();
        render_container_metrics(&mut out, &containers, &stats);
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

/// The cached `stats --no-stream` sweep: one in flight at a time, results
/// older than 30s trigger a refresh on the next scrape. Scrapes read the
/// last completed sweep and never wait on the runtime CLI.
fn refresh_container_stats() -> HashMap<String, (f64, u64, u64)> {
    let mut g = stats_cache().lock().unwrap();
    let stale = g
        .at
        .is_none_or(|t| t.elapsed() > std::time::Duration::from_secs(30));
    if stale && !g.in_flight {
        g.in_flight = true;
        std::thread::spawn(|| {
            let fresh = crate::platform::container_stats();
            let mut g = stats_cache().lock().unwrap();
            g.stats = fresh;
            g.at = Some(std::time::Instant::now());
            g.in_flight = false;
        });
    }
    g.stats.clone()
}

struct ContainerStatsCache {
    at: Option<std::time::Instant>,
    in_flight: bool,
    stats: HashMap<String, (f64, u64, u64)>,
}

/// The shared cache cell — module-level so both the scrape path and the
/// spawned sweep thread see the same state.
fn stats_cache() -> &'static Mutex<ContainerStatsCache> {
    static CACHE: std::sync::OnceLock<Mutex<ContainerStatsCache>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        Mutex::new(ContainerStatsCache {
            at: None,
            in_flight: false,
            stats: HashMap::new(),
        })
    })
}

/// Container series: `witr_container_info` one per container, plus
/// cpu/mem gauges where the sweep has a sample. Pure so tests can feed
/// fixtures; id matching is exact then 12-char prefix (runtimes
/// abbreviate either side).
fn render_container_metrics(
    out: &mut String,
    containers: &[crate::model::Container],
    stats: &HashMap<String, (f64, u64, u64)>,
) {
    out.push_str("# HELP witr_container_info Container metadata, one series per container\n");
    out.push_str("# TYPE witr_container_info gauge\n");
    let mut emitted = false;
    for c in containers {
        let id = &c.id;
        let sample = stats
            .get(id)
            .or_else(|| {
                let prefix: String = id.chars().take(12).collect();
                stats
                    .iter()
                    .find(|(k, _)| k.starts_with(&prefix))
                    .map(|(_, v)| v)
            })
            .copied();
        if let Some((cpu, used, total)) = sample {
            if !emitted {
                out.push_str("# HELP witr_container_cpu_percent Live CPU percent from the runtime's stats sweep\n");
                out.push_str("# TYPE witr_container_cpu_percent gauge\n");
                out.push_str("# HELP witr_container_mem_used_bytes Resident memory in use, from the runtime's stats sweep\n");
                out.push_str("# TYPE witr_container_mem_used_bytes gauge\n");
                out.push_str("# HELP witr_container_mem_total_bytes Memory limit visible to the container\n");
                out.push_str("# TYPE witr_container_mem_total_bytes gauge\n");
                emitted = true;
            }
            out.push_str(&format!(
                "witr_container_cpu_percent{{runtime=\"{}\",id=\"{}\",name=\"{}\"}} {cpu:.2}\n",
                label_escape(&c.runtime),
                label_escape(id),
                label_escape(&c.name),
            ));
            out.push_str(&format!(
                "witr_container_mem_used_bytes{{runtime=\"{}\",id=\"{}\",name=\"{}\"}} {used}\n",
                label_escape(&c.runtime),
                label_escape(id),
                label_escape(&c.name),
            ));
            out.push_str(&format!(
                "witr_container_mem_total_bytes{{runtime=\"{}\",id=\"{}\",name=\"{}\"}} {total}\n",
                label_escape(&c.runtime),
                label_escape(id),
                label_escape(&c.name),
            ));
        }
    }
    for c in containers {
        out.push_str(&format!(
            "witr_container_info{{runtime=\"{}\",id=\"{}\",name=\"{}\",image=\"{}\",state=\"{}\"}} 1\n",
            label_escape(&c.runtime),
            label_escape(&c.id),
            label_escape(&c.name),
            label_escape(&c.image),
            label_escape(&c.state),
        ));
    }
}

/// Parse the /api/top query string: `metric=` and `n=` params, defaults
/// cpu / 10, n clamped to 1..=500 (unknown params ignored, a bad n falls
/// back to 10 — same leniency as the CLI's defaults).
/// Pull the `Authorization: Bearer <token>` value out of a raw request
/// text (header name matched case-insensitively, per RFC 7235). None when
/// the header is absent or not a Bearer credential.
fn bearer_token(req: &str) -> Option<String> {
    for line in req.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("authorization") {
            return value
                .trim()
                .strip_prefix("Bearer ")
                .map(|t| t.trim().to_string());
        }
    }
    None
}

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

/// Subscribers waiting on /api/events plus the one-shot flag for the
/// sampler thread. A subscriber whose receiver hung up is pruned on the
/// first failed publish.
struct EventHub {
    subs: Mutex<Vec<std::sync::mpsc::Sender<crate::history::TuiEvent>>>,
    sampler_armed: std::sync::atomic::AtomicBool,
}

impl EventHub {
    fn new() -> Self {
        Self {
            subs: Mutex::new(Vec::new()),
            sampler_armed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn publish(&self, events: &[crate::history::TuiEvent]) {
        let mut subs = self.subs.lock().unwrap_or_else(|e| e.into_inner());
        subs.retain(|tx| events.iter().all(|e| tx.send(e.clone()).is_ok()));
    }

    /// Arm the delta sampler on the first /api/events hit — pure /metrics
    /// deployments pay nothing. It shares the scrapes' platform instance
    /// (process CPU% deltas need consecutive samples on one instance) but
    /// keeps its own History, whose update deltas are exactly the
    /// started/exited/restarted edges the TUI ring carries.
    fn ensure_sampler(self: &std::sync::Arc<Self>) {
        if self
            .sampler_armed
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }
        let hub = self.clone();
        std::thread::Builder::new()
            .name("serve-events".into())
            .spawn(move || {
                let platform = crate::platform::get_shared();
                let mut hist = crate::history::History::new();
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    let procs = {
                        let guard = platform.lock().unwrap_or_else(|e| e.into_inner());
                        guard.list_processes().unwrap_or_default()
                    };
                    let events = hist.update(&procs);
                    if !events.is_empty() {
                        hub.publish(&events);
                    }
                }
            })
            .ok();
    }
}

/// Bind and serve until the process is killed. Each connection thread
/// builds its own platform instance (`platform::get()` — the impls carry
/// internal caches, and the trait isn't Sync), so scrapes never contend.
/// Per-pid fd counts cost one sweep; they're only paid for real scrapes
/// when the platform supports them (a native libproc sweep on macOS, a
/// /proc walk on Linux). `token` arms bearer auth: every request must
/// carry `Authorization: Bearer <token>` or get a 401 — the metrics name
/// processes, so gate them before binding past 127.0.0.1.
pub fn run(addr: &str, fds_enabled: bool, token: Option<&str>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    // owned so the per-connection threads can move it in ('static)
    let token = token.map(str::to_string);
    // one platform for every request: the delta-based metrics (machine
    // CPU%) need consecutive calls on the same instance
    let platform = crate::platform::get_shared();
    let hub = std::sync::Arc::new(EventHub::new());
    crate::write_out(&format!(
        "serving Prometheus metrics → http://{addr}/metrics{} (Ctrl-C to stop)",
        if token.is_some() { " · bearer auth on" } else { "" },
    ));
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let platform = platform.clone();
        let token = token.clone();
        let hub = hub.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let Ok(n) = stream.read(&mut buf) else { return };
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req.split_whitespace().nth(1).unwrap_or("");
            // bearer auth (when armed) before any routing — one check for
            // /metrics and every /api/* endpoint alike. The raw request
            // buffer already holds the headers for the clients that matter
            // (Prometheus, curl, jq pipelines).
            if let Some(expected) = &token {
                if bearer_token(&req).as_deref() != Some(expected.as_str()) {
                    respond(
                        &mut stream,
                        "401 Unauthorized",
                        "application/json",
                        "{\"error\":\"unauthorized\"}",
                    );
                    return;
                }
            }
            // /api/ps: the full process table as the same versioned JSON
            // envelope `--json` prints — a machine-readable sibling to the
            // Prometheus gauges
            if path == "/api/ps" || path.starts_with("/api/ps?") {
                let procs = {
                    let platform = platform.lock().unwrap_or_else(|e| e.into_inner());
                    let mut procs = platform.list_processes().unwrap_or_default();
                    platform.enrich_listing(&mut procs);
                    procs
                };
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
                let (procs, socks) = {
                    let platform = platform.lock().unwrap_or_else(|e| e.into_inner());
                    let procs = platform.list_processes().unwrap_or_default();
                    let socks = platform.list_sockets().unwrap_or_default();
                    (procs, socks)
                };
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
                let procs = {
                    let platform = platform.lock().unwrap_or_else(|e| e.into_inner());
                    platform.list_processes().unwrap_or_default()
                };
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
                let (procs, socks) = {
                    let platform = platform.lock().unwrap_or_else(|e| e.into_inner());
                    let procs = platform.list_processes().unwrap_or_default();
                    let socks = platform.list_all_sockets().unwrap_or_default();
                    (procs, socks)
                };
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
                    "cpu" | "mem" | "fd" | "age" | "io" | "io-rate" | "threads" | "conn"
                ) {
                    respond(
                        &mut stream,
                        "400 Bad Request",
                        "text/plain",
                        "metric must be one of: cpu, mem, fd, age, io, io-rate, threads, conn\n",
                    );
                    return;
                }
                let mut guard = platform.lock().unwrap_or_else(|e| e.into_inner());
                let platform: &mut dyn crate::platform::Platform = &mut **guard;
                let mut procs = platform.list_processes().unwrap_or_default();
                // the io metrics rank enriched counters — paid only when asked
                if matches!(metric.as_str(), "io" | "io-rate") {
                    platform.enrich_listing(&mut procs);
                }
                // conn ranks live ESTABLISHED sockets per pid — one socket
                // sweep, same attribution the /api/conns view uses
                let conn_map = if metric == "conn" {
                    Some(crate::tui::established_per_pid(
                        &platform.list_all_sockets().unwrap_or_default(),
                    ))
                } else {
                    None
                };
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
                        "threads" => p.threads.map(|t| serde_json::json!(t)),
                        "conn" => conn_map
                            .as_ref()
                            .and_then(|m| m.get(&p.pid))
                            .map(|v| serde_json::json!(v)),
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
            // /api/events: Server-Sent Events — the delta sampler's
            // started/exited/restarted edges (the same TuiEvent JSON the
            // TUI ring and --events-log carry), one `data:` line per
            // event and a comment ping every 15s of silence. The sampler
            // arms on the first hit; a hung-up client is pruned by the
            // next publish.
            if path == "/api/events" || path.starts_with("/api/events?") {
                hub.ensure_sampler();
                let (tx, rx) = std::sync::mpsc::channel::<crate::history::TuiEvent>();
                hub.subs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(tx);
                let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(b"retry: 5000\n\n");
                let _ = stream.flush();
                loop {
                    match rx.recv_timeout(std::time::Duration::from_secs(15)) {
                        Ok(e) => {
                            let json = serde_json::to_string(&e).unwrap_or_default();
                            if stream
                                .write_all(format!("data: {json}\n\n").as_bytes())
                                .is_err()
                            {
                                break; // client hung up; rx drops, publish prunes tx
                            }
                            let _ = stream.flush();
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            if stream.write_all(b": ping\n\n").is_err() {
                                break;
                            }
                            let _ = stream.flush();
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                return;
            }
            if !path.starts_with("/metrics") {
                match path {
                    // the human view: a zero-JS dashboard (meta-refresh)
                    // over the same live sampling the APIs do
                    "/" => {
                        let body = {
                            let platform = platform.lock().unwrap_or_else(|e| e.into_inner());
                            dashboard_html(platform.as_ref())
                        };
                        respond(&mut stream, "200 OK", "text/html; charset=utf-8", &body);
                    }
                    _ => respond(&mut stream, "404 Not Found", "text/plain", "not found\n"),
                }
                return;
            }
            let fds = {
                let platform = platform.lock().unwrap_or_else(|e| e.into_inner());
                if fds_enabled {
                    platform.fd_counts()
                } else {
                    None
                }
            };
            // bump before rendering so the current scrape counts itself
            SCRAPES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let started = std::time::Instant::now();
            let body = {
                let platform = platform.lock().unwrap_or_else(|e| e.into_inner());
                scrape(platform.as_ref(), fds.as_ref())
            };
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
    fn event_hub_fans_out_and_prunes_hung_up_subs() {
        let hub = EventHub::new();
        let (tx, rx) = std::sync::mpsc::channel();
        let (gone_tx, gone_rx) = std::sync::mpsc::channel();
        drop(gone_rx); // this subscriber already hung up
        hub.subs.lock().unwrap().push(tx);
        hub.subs.lock().unwrap().push(gone_tx);
        let e = crate::history::TuiEvent {
            at_unix: 1,
            kind: "started".into(),
            pid: 1,
            name: "n".into(),
            detail: String::new(),
        };
        hub.publish(std::slice::from_ref(&e));
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap(),
            e
        );
        // the dead subscriber's sender was pruned by that same publish
        assert_eq!(hub.subs.lock().unwrap().len(), 1);
        hub.publish(std::slice::from_ref(&e));
        assert_eq!(rx.try_recv().unwrap(), e);
        assert_eq!(hub.subs.lock().unwrap().len(), 1);
    }

    #[test]
    fn bearer_token_reads_the_header_case_insensitively() {
        let req = "GET /metrics HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer s3cret\r\n\r\n";
        assert_eq!(bearer_token(req).as_deref(), Some("s3cret"));
        let lower = "GET /metrics HTTP/1.1\r\nauthorization:Bearer  padded  \r\n\r\n";
        assert_eq!(bearer_token(lower).as_deref(), Some("padded"));
        // no header, wrong scheme, or a bare GET all read as unauthorized
        assert_eq!(bearer_token("GET /metrics HTTP/1.1\r\nHost: h\r\n\r\n"), None);
        assert_eq!(
            bearer_token("GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"),
            None
        );
        assert_eq!(bearer_token(""), None);
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

    #[test]
    fn scrape_includes_machine_gauges_when_measurable() {
        let platform = crate::platform::get();
        let out = scrape(platform.as_ref(), None);
        assert!(out.contains("witr_process_count "));
        // net counters ship as a matched rx/tx pair, labeled per interface
        let has_rx = out.contains("witr_machine_net_rx_bytes_total ");
        let has_tx = out.contains("witr_machine_net_tx_bytes_total ");
        assert_eq!(has_rx, has_tx, "rx and tx counters ship together");
        if has_rx {
            assert!(out.contains("nic=\""), "per-interface label present");
        }
        // on a platform with system_stats, the always-known fields emit
        if platform.system_stats().is_some() {
            let has_mem = out.contains("witr_machine_mem_used_bytes ")
                || out.contains("witr_machine_mem_total_bytes ");
            assert!(has_mem, "memory gauges emit whenever the platform measures");
        }
    }

    /// A tiny deterministic platform for the dashboard render.
    struct DashPlatform;
    impl Platform for DashPlatform {
        fn name(&self) -> &'static str {
            "test"
        }
        fn capabilities(&self) -> crate::platform::Capabilities {
            crate::platform::Capabilities { file_lookup: false, env: false }
        }
        fn list_processes(&self) -> crate::platform::PlatResult<Vec<Process>> {
            Ok(vec![Process {
                pid: 7,
                name: "<script>".into(),
                user: Some("bob".into()),
                cpu: Some(90.0),
                mem_kb: Some(2_048_000),
                cmdline: vec!["nginx".into(), "-g".into(), "daemon off;".into()],
                ..Default::default()
            }])
        }
        fn detail(&self, brief: &Process, _want_env: bool) -> Process {
            brief.clone()
        }
        fn port_to_sockets(&self, _port: u16) -> crate::platform::PlatResult<Vec<crate::model::Socket>> {
            Ok(Vec::new())
        }
        fn list_sockets(&self) -> crate::platform::PlatResult<Vec<crate::model::Socket>> {
            Ok(vec![crate::model::Socket {
                proto: "tcp".into(),
                local_addr: "0.0.0.0".into(),
                local_port: 8080,
                peer_addr: None,
                peer_port: None,
                state: "LISTEN".into(),
                pid: Some(7),
            }])
        }
        fn file_to_pids(&self, _path: &str) -> crate::platform::PlatResult<Vec<i32>> {
            Ok(Vec::new())
        }
        fn container_of(&self, _pid: i32) -> Option<crate::model::Source> {
            None
        }
        fn service_source(&self, _procs: &[Process]) -> Option<crate::model::Source> {
            None
        }
        fn system_stats(&self) -> Option<crate::platform::SystemStats> {
            Some(crate::platform::SystemStats {
                cpu_percent: Some(12.5),
                mem_used_mb: Some(1000),
                mem_total_mb: Some(4000),
                load1: Some(0.10),
                ..Default::default()
            })
        }
    }

    #[test]
    fn dashboard_is_zero_js_and_escapes() {
        let html = dashboard_html(&DashPlatform);
        assert!(html.contains("http-equiv=\"refresh\""), "auto-refresh meta tag");
        assert!(!html.to_lowercase().contains("<script"), "zero JS: no script tags");
        assert!(!html.contains("<script>"), "process name is escaped");
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("12.5"), "cpu gauge renders");
        assert!(html.contains("top cpu"), "top table section");
        assert!(html.contains("top memory"));
        assert!(html.contains("listeners"));
        assert!(html.contains(">8080<"), "listener port in its table");
        assert!(html.contains("internet"), "wildcard bind is flagged");
        assert!(html.contains("/api/ps"), "API index still reachable from the page");
        // cold server: cpu is a delta between requests, dashes are fine
        struct Cold;
        impl Platform for Cold {
            fn name(&self) -> &'static str {
                "test"
            }
            fn capabilities(&self) -> crate::platform::Capabilities {
                crate::platform::Capabilities { file_lookup: false, env: false }
            }
            fn list_processes(&self) -> crate::platform::PlatResult<Vec<Process>> {
                Ok(Vec::new())
            }
            fn detail(&self, brief: &Process, _want_env: bool) -> Process {
                brief.clone()
            }
            fn port_to_sockets(&self, _port: u16) -> crate::platform::PlatResult<Vec<crate::model::Socket>> {
                Ok(Vec::new())
            }
            fn list_sockets(&self) -> crate::platform::PlatResult<Vec<crate::model::Socket>> {
                Ok(Vec::new())
            }
            fn file_to_pids(&self, _path: &str) -> crate::platform::PlatResult<Vec<i32>> {
                Ok(Vec::new())
            }
            fn container_of(&self, _pid: i32) -> Option<crate::model::Source> {
                None
            }
            fn service_source(&self, _procs: &[Process]) -> Option<crate::model::Source> {
                None
            }
        }
        let html = dashboard_html(&Cold);
        assert!(html.contains("–"), "missing gauges render a dash");
        assert!(html.contains("0 process(es)"));
    }

    #[test]
    fn container_metrics_match_ids_and_skip_missing_samples() {
        let c = |id: &str, name: &str| crate::model::Container {
            runtime: "docker".into(),
            id: id.into(),
            name: name.into(),
            image: "alpine".into(),
            command: String::new(),
            state: "running".into(),
            status: "Up".into(),
            ports: String::new(),
            pod: None,
            restarts: None,
            cpu_pct: None,
            mem_used_mb: None,
            mem_total_mb: None,
    throttled_usec: None,
    oom_kills: None,
        };
        let containers = vec![
            c("abc123def456fullid", "web"),
            c("ffffffffffffnostat", "idle"),
        ];
        // the sweep keyed the 12-char prefix; the full id in the listing
        // must still match
        let stats: HashMap<String, (f64, u64, u64)> = [(
            "abc123def456".to_string(),
            (12.5, 1024 * 1024, 100 * 1024 * 1024),
        )]
        .into();
        let mut out = String::new();
        render_container_metrics(&mut out, &containers, &stats);
        assert!(
            out.contains("witr_container_cpu_percent{runtime=\"docker\",id=\"abc123def456fullid\",name=\"web\"} 12.50"),
            "{out}"
        );
        assert!(
            out.contains("witr_container_mem_used_bytes{runtime=\"docker\",id=\"abc123def456fullid\",name=\"web\"} 1048576"),
            "{out}"
        );
        // info series: every container, one each
        assert_eq!(out.matches("witr_container_info{").count(), 2);
        assert!(out.contains("name=\"idle\",image=\"alpine\",state=\"running\"} 1"), "{out}");
        // no sample → no cpu/mem series for that container
        assert!(!out.contains("name=\"idle\"} 12"), "{out}");
        // empty sweep → only info series, no cpu HELP/TYPE block
        let mut out = String::new();
        render_container_metrics(&mut out, &containers, &HashMap::new());
        assert_eq!(out.matches("witr_container_info{").count(), 2);
        assert!(!out.contains("witr_container_cpu_percent"), "{out}");
    }
}

