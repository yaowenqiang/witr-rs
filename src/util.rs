use std::collections::HashMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Copy text to the system clipboard using whatever CLI tool exists
/// (pbcopy on macOS, wl-copy/xclip on Linux, clip on Windows).
pub fn clipboard_copy(text: &str) -> Result<usize, String> {
    #[cfg(target_os = "macos")]
    let candidates: &[&[&str]] = &[&["pbcopy"]];
    #[cfg(all(unix, not(target_os = "macos")))]
    let candidates: &[&[&str]] = &[&["wl-copy"], &["xclip", "-selection", "clipboard"]];
    #[cfg(windows)]
    let candidates: &[&[&str]] = &[&["clip"]];

    for tool in candidates {
        let (cmd, args) = tool.split_first().unwrap();
        let Ok(mut child) = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue; // not installed — try the next one
        };
        use std::io::Write as _;
        let written = child
            .stdin
            .as_mut()
            .and_then(|s| s.write_all(text.as_bytes()).ok())
            .is_some();
        child.stdin.take(); // close stdin so the tool exits
        let _ = child.wait();
        if written {
            return Ok(text.len());
        }
    }
    Err("no clipboard tool found (pbcopy / wl-copy / xclip / clip)".into())
}

/// Run an external command, capture stdout, enforce a timeout.
/// Stdout is drained on a separate thread so big outputs can't deadlock
/// the wait; timed-out children are killed best-effort.
pub fn run(cmd: &str, args: &[&str], timeout: Duration) -> std::io::Result<String> {
    let trace = std::env::var_os("WITR_TRACE").is_some();
    let t0 = Instant::now();
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let mut stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(pipe) = stdout.as_mut() {
            let _ = pipe.read_to_string(&mut buf);
        }
        buf
    });

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait()? {
            Some(st) => break Some(st),
            None if Instant::now() >= deadline => break None,
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    };

    match status {
        Some(st) if st.success() => {
            let out = reader.join().unwrap_or_default();
            if trace {
                eprintln!("[witr-trace] {} {:?} took {:?}", cmd, args.first().unwrap_or(&""), t0.elapsed());
            }
            Ok(out)
        }
        Some(st) => {
            if trace {
                eprintln!("[witr-trace] {} exited {} after {:?}", cmd, st.code().unwrap_or(-1), t0.elapsed());
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{} exited with {}", cmd, st.code().unwrap_or(-1)),
            ))
        }
        None => {
            if trace {
                eprintln!("[witr-trace] {} TIMEOUT after {:?}", cmd, t0.elapsed());
            }
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("{} timed out", cmd),
            ))
        }
    }
}

/// Like [`run`], but any failure (missing binary, non-zero exit, timeout)
/// becomes None — for best-effort lookups.
pub fn run_ok(cmd: &str, args: &[&str], timeout: Duration) -> Option<String> {
    run(cmd, args, timeout).ok()
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// uid → username resolver with a lookup cache (including negative
/// results): macOS system users are absent from /etc/passwd, so every uid
/// costs one `id -un` process unless cached.
pub struct Users {
    cache: std::cell::RefCell<HashMap<u32, Option<String>>>,
}

impl Users {
    /// Seed the cache from /etc/passwd (Unix); empty on Windows.
    pub fn load() -> Self {
        let mut seed: HashMap<u32, Option<String>> = HashMap::new();
        if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let f: Vec<&str> = line.split(':').collect();
                if f.len() >= 3 {
                    if let Ok(uid) = f[2].parse::<u32>() {
                        seed.entry(uid).or_insert_with(|| Some(f[0].to_string()));
                    }
                }
            }
        }
        Users { cache: std::cell::RefCell::new(seed) }
    }

    pub fn name_for(&self, uid: u32) -> Option<String> {
        if let Some(hit) = self.cache.borrow().get(&uid) {
            return hit.clone();
        }
        let resolved = {
            #[cfg(unix)]
            {
                run_ok("id", &["-un", &uid.to_string()], Duration::from_secs(3))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            }
            #[cfg(not(unix))]
            {
                let _ = uid;
                None
            }
        };
        self.cache.borrow_mut().insert(uid, resolved.clone());
        resolved
    }
}

impl Default for Users {
    fn default() -> Self {
        Self::load()
    }
}

/// Days-since-epoch → (year, month, day). Howard Hinnant's civil_from_days.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Format a unix timestamp as local naive time. We avoid a timezone
/// database dependency, so this uses the process' local offset (only
/// correct for the current offset — fine for display purposes).
pub fn fmt_time(unix: i64) -> String {
    fmt_time_utc(unix + local_utc_offset_secs())
}

/// Pure civil-time formatting (input already offset-adjusted).
fn fmt_time_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        y,
        mo,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn local_utc_offset_secs() -> i64 {
    // Cheap way to get the current offset without libc/tz crates:
    // `date +%z` on unix. Falls back to UTC.
    #[cfg(unix)]
    {
        if let Some(out) = run_ok("date", &["+%z"], Duration::from_secs(2)) {
            let s = out.trim();
            if s.len() == 5 && (s.starts_with('+') || s.starts_with('-')) {
                let sign = if s.starts_with('-') { -1 } else { 1 };
                if let (Ok(h), Ok(m)) = (s[1..3].parse::<i64>(), s[3..5].parse::<i64>()) {
                    return sign * (h * 3600 + m * 60);
                }
            }
        }
    }
    0
}

/// Human-friendly duration: "3d 2h", "2h 13m", "5m 12s", "42s".
pub fn fmt_age(seconds: i64) -> String {
    let s = seconds.max(0);
    if s >= 86_400 {
        format!("{}d {}h", s / 86_400, (s % 86_400) / 3600)
    } else if s >= 3600 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m {}s", s / 60, s % 60)
    } else {
        format!("{}s", s)
    }
}

/// Parse `ps etime` style durations: "37", "12:05", "03:10:31", "1-03:10:31".
pub fn parse_etime_to_secs(s: &str) -> Option<i64> {
    let (days, rest) = match s.split_once('-') {
        Some((d, r)) => (d.parse::<i64>().ok()?, r),
        None => (0, s),
    };
    let parts: Vec<i64> = rest.split(':').map(|p| p.parse().ok()).collect::<Option<_>>()?;
    let total = match parts.len() {
        3 => days * 86_400 + parts[0] * 3600 + parts[1] * 60 + parts[2],
        // no days part: "mm:ss" or plain seconds
        2 if days == 0 => parts[0] * 60 + parts[1],
        1 if days == 0 => parts[0],
        _ => return None,
    };
    Some(total)
}

/// Strip a trailing " (deleted)" that kernels append to exe paths.
pub fn strip_deleted_suffix(p: &str) -> (&str, bool) {
    match p.strip_suffix(" (deleted)") {
        Some(base) => (base, true),
        None => (p, false),
    }
}

pub fn basename(p: &str) -> String {
    p.rsplit('/').next().unwrap_or(p).to_string()
}

/// "1.2.3.4:80", "[::]:443", "*:22" → (addr, port)
pub fn split_host_port(s: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let port = rest[close + 1..].strip_prefix(':')?;
        (host.to_string(), port.parse().ok()?)
    } else {
        let (h, p) = s.rsplit_once(':')?;
        (h.to_string(), p.parse().ok()?)
    };
    Some((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etime_formats() {
        assert_eq!(parse_etime_to_secs("42"), Some(42));
        assert_eq!(parse_etime_to_secs("12:05"), Some(725));
        assert_eq!(parse_etime_to_secs("03:10:31"), Some(11431));
        assert_eq!(parse_etime_to_secs("1-03:10:31"), Some(97831));
        assert_eq!(parse_etime_to_secs("bad"), None);
    }

    #[test]
    fn deleted_suffix() {
        let (p, deleted) = strip_deleted_suffix("/usr/bin/foo (deleted)");
        assert_eq!(p, "/usr/bin/foo");
        assert!(deleted);
        let (p, deleted) = strip_deleted_suffix("/usr/bin/foo");
        assert_eq!(p, "/usr/bin/foo");
        assert!(!deleted);
    }

    #[test]
    fn age_format() {
        assert_eq!(fmt_age(42), "42s");
        assert_eq!(fmt_age(312), "5m 12s");
        assert_eq!(fmt_age(8000), "2h 13m");
        assert_eq!(fmt_age(265_000), "3d 1h");
    }

    #[test]
    fn epoch() {
        // pure UTC formatting (no local offset applied)
        assert_eq!(fmt_time_utc(0), "1970-01-01 00:00:00");
        assert_eq!(fmt_time_utc(1_000_000_000), "2001-09-09 01:46:40");
        // fmt_time must differ from UTC by exactly the machine's offset
        assert_eq!(fmt_time_utc(now_unix() + local_utc_offset_secs()), fmt_time(now_unix()));
    }
}
