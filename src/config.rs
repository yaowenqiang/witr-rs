//! Optional user config: a flat `key = value` toml subset read once at
//! startup. Everything is a default — CLI flags win over the file, the
//! file wins over built-in defaults. Invalid lines are skipped (collected
//! as warnings), a missing file means all defaults.
//!
//! Location: `~/.config/witr-rs/config.toml` (Linux, XDG),
//! `~/Library/Application Support/witr-rs/config.toml` (macOS),
//! `%APPDATA%\witr-rs\config.toml` (Windows).
//!
//! ```toml
//! refresh_secs = 3        # TUI sampling interval (min 1)
//! sort = "cpu"            # default Processes-tab sort: pid/name/user/cpu/mem/started
//! notify = false          # desktop notifications on restarts (as --notify)
//! paused = false          # start with sampling frozen (as 'P')
//! watch = ["nginx|nginx|www"]  # TUI watchlist ('w'), one "name|exe|user" per entry
//! notes = ["nginx|nginx|www|reverse proxy for the lab"]  # 'N' annotations
//! ```

use std::path::PathBuf;

/// Known keys with their parsed values; unknown/invalid lines are
/// reported, never fatal.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Config {
    pub refresh_secs: Option<u64>,
    pub sort: Option<String>,
    pub notify: Option<bool>,
    pub paused: Option<bool>,
    /// TUI watchlist entries, each "name|exe_basename|user" (util's
    /// process-identity triple) — matches across restarts because the pid
    /// is not part of the key. Written back by `save_watch` when 'w' is
    /// pressed in the TUI.
    pub watch: Vec<String>,
    /// Process annotations, each "name|exe_basename|user|note text" — the
    /// identity triple extended with the note as a 4th field (splitn(4),
    /// so note text may itself contain `|`). Written back by `save_notes`
    /// when 'N' commits in the TUI.
    pub notes: Vec<String>,
}

impl Config {
    /// User-level config path for the current platform (XDG respected on
    /// Linux). None when $HOME is unset.
    pub fn path() -> Option<PathBuf> {
        let home = PathBuf::from(std::env::var_os("HOME")?);
        Some(Self::path_under(&home))
    }

    /// Platform config path under a home dir (split out for tests).
    pub fn path_under(home: &std::path::Path) -> PathBuf {
        #[cfg(target_os = "macos")]
        let base = home.join("Library/Application Support");
        #[cfg(target_os = "linux")]
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        #[cfg(windows)]
        let base = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData/Roaming"));
        base.join("witr-rs").join("config.toml")
    }

    /// Read + parse the user config; every problem is a default.
    pub fn load() -> Config {
        let Some(path) = Self::path() else {
            return Config::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => Config::parse(&text).0,
            Err(_) => Config::default(),
        }
    }

    /// Persist the watchlist: reads the existing file (when present) and
    /// rewrites only the `watch = [...]` line, appending it when missing —
    /// comments, unknown keys and ordering elsewhere survive. Entries are
    /// quoted and TOML-escaped. Never creates the file just to record an
    /// empty list.
    pub fn save_watch(entries: &[String]) -> std::io::Result<()> {
        let Some(home) = std::env::var_os("HOME") else {
            return Ok(());
        };
        Self::save_watch_under(&std::path::PathBuf::from(home), entries)
    }

    /// save_watch under an explicit home dir (split out for tests).
    pub fn save_watch_under(home: &std::path::Path, entries: &[String]) -> std::io::Result<()> {
        let path = Self::path_under(home);
        if entries.is_empty() && !path.exists() {
            return Ok(());
        }
        let old = std::fs::read_to_string(&path).unwrap_or_default();
        let items: Vec<String> = entries
            .iter()
            .map(|e| format!("\"{}\"", e.replace('\\', "\\\\").replace('"', "\\\"")))
            .collect();
        let line = format!("watch = [{}]", items.join(", "));
        let mut out = String::with_capacity(old.len() + line.len() + 2);
        let mut replaced = false;
        for raw in old.lines() {
            let is_watch_line = raw
                .split_once('=')
                .is_some_and(|(k, _)| k.trim() == "watch");
            if is_watch_line {
                if !replaced {
                    out.push_str(&line);
                    out.push('\n');
                    replaced = true;
                }
            } else {
                out.push_str(raw);
                out.push('\n');
            }
        }
        if !replaced {
            if !old.is_empty() && !old.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&line);
            out.push('\n');
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, out)
    }

    /// Persist the notes list — same surgical line rewrite as
    /// [`Config::save_watch`], for the `notes = [...]` key.
    pub fn save_notes(entries: &[String]) -> std::io::Result<()> {
        let Some(home) = std::env::var_os("HOME") else {
            return Ok(());
        };
        Self::save_notes_under(&std::path::PathBuf::from(home), entries)
    }

    /// save_notes under an explicit home dir (split out for tests).
    pub fn save_notes_under(home: &std::path::Path, entries: &[String]) -> std::io::Result<()> {
        let path = Self::path_under(home);
        if entries.is_empty() && !path.exists() {
            return Ok(());
        }
        let old = std::fs::read_to_string(&path).unwrap_or_default();
        let items: Vec<String> = entries
            .iter()
            .map(|e| format!("\"{}\"", e.replace('\\', "\\\\").replace('"', "\\\"")))
            .collect();
        let line = format!("notes = [{}]", items.join(", "));
        let mut out = String::with_capacity(old.len() + line.len() + 2);
        let mut replaced = false;
        for raw in old.lines() {
            let is_notes_line = raw
                .split_once('=')
                .is_some_and(|(k, _)| k.trim() == "notes");
            if is_notes_line {
                if !replaced {
                    out.push_str(&line);
                    out.push('\n');
                    replaced = true;
                }
            } else {
                out.push_str(raw);
                out.push('\n');
            }
        }
        if !replaced {
            if !old.is_empty() && !old.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&line);
            out.push('\n');
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, out)
    }

    /// Parse the flat subset: `key = value` lines, `#` comments, `[section]`
    /// headers tolerated and ignored. Returns the config plus one warning
    /// string per skipped line (unknown key, bad value, no `=`).
    pub fn parse(text: &str) -> (Config, Vec<String>) {
        let mut cfg = Config::default();
        let mut warnings = Vec::new();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                warnings.push(format!("line {n}: not key = value, skipped"));
                continue;
            };
            let key = key.trim();
            // trailing comment first, then trim, then unquote
            let value = strip_comment(value).trim();
            let quoted = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            match key {
                "refresh_secs" => match quoted.parse::<u64>() {
                    Ok(v) => cfg.refresh_secs = Some(v),
                    Err(_) => warnings.push(format!("line {n}: refresh_secs {quoted:?} is not a number, skipped")),
                },
                "sort" => cfg.sort = Some(quoted.to_string()),
                "watch" => match parse_string_array(value) {
                    Some(list) => cfg.watch = list,
                    None => warnings.push(format!("line {n}: watch is not a string array, skipped")),
                },
                "notes" => match parse_string_array(value) {
                    Some(list) => cfg.notes = list,
                    None => warnings.push(format!("line {n}: notes is not a string array, skipped")),
                },
                "notify" | "paused" => match quoted.parse::<bool>() {
                    Ok(v) => {
                        if key == "notify" {
                            cfg.notify = Some(v);
                        } else {
                            cfg.paused = Some(v);
                        }
                    }
                    Err(_) => warnings.push(format!(
                        "line {n}: {key} {quoted:?} is not true/false, skipped"
                    )),
                },
                _ => warnings.push(format!("line {n}: unknown key {key:?}, skipped")),
            }
        }
        (cfg, warnings)
    }
}

/// Drop a trailing `# comment` (only when preceded by whitespace so values
/// like `"#fff"` survive).
fn strip_comment(value: &str) -> &str {
    if let Some(pos) = value.find(" #") {
        &value[..pos]
    } else {
        value
    }
}

/// Parse a flat TOML string array: `["a", "b"]` — brackets, comma
/// separation, optional trailing comma. Escapes are not interpreted (watch
/// entries never contain quotes in practice). None when the value isn't
/// bracketed or an item is unquoted.
fn parse_string_array(value: &str) -> Option<Vec<String>> {
    let inner = value.trim().strip_prefix('[')?.strip_suffix(']')?;
    let mut out = Vec::new();
    for item in inner.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue; // trailing comma / empty array
        }
        let quoted = item
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(item);
        out.push(quoted.to_string());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_config() {
        let text = "\
# witr-rs config
refresh_secs = 5
sort = \"cpu\"       # hottest first
notify = true
paused = false
watch = [\"nginx|nginx|www\", \"tailspid|sleep|\"]

[ignored-section]
";
        let (cfg, warnings) = Config::parse(text);
        assert_eq!(
            cfg,
            Config {
                refresh_secs: Some(5),
                sort: Some("cpu".into()),
                notify: Some(true),
                paused: Some(false),
                watch: vec!["nginx|nginx|www".into(), "tailspid|sleep|".into()],
                notes: Vec::new(),
            }
        );
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn parse_notes_and_save_roundtrips() {
        let (cfg, w) = Config::parse("notes = [\"nginx|nginx|www|reverse proxy\"]\n");
        assert_eq!(cfg.notes, vec!["nginx|nginx|www|reverse proxy"]);
        assert!(w.is_empty());
        // a note whose text contains `|` survives — splitn(4) keeps it whole
        let (cfg, _) = Config::parse("notes = [\"a|b|c|first | second\"]\n");
        assert_eq!(cfg.notes, vec!["a|b|c|first | second"]);
        let (cfg, w) = Config::parse("notes = oops\n");
        assert!(cfg.notes.is_empty());
        assert_eq!(w.len(), 1);

        // save preserves the rest of the file, like save_watch
        let dir = std::env::temp_dir().join(format!("witr-notes-test-{}", std::process::id()));
        let path = Config::path_under(&dir);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "refresh_secs = 3\nnotes = [\"old|x|y|stale\"]\n").unwrap();
        Config::save_notes_under(&dir, &["nginx|nginx|www|hello world".to_string()]).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let (cfg, _) = Config::parse(&text);
        assert_eq!(cfg.notes, vec!["nginx|nginx|www|hello world"]);
        assert_eq!(cfg.refresh_secs, Some(3), "untouched key survives");
        assert_eq!(text.matches("notes =").count(), 1, "exactly one notes line");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn parse_watch_array_edge_cases() {
        // empty array, trailing comma, bare (unquoted) items
        let (cfg, w) = Config::parse("watch = []\n");
        assert!(cfg.watch.is_empty());
        assert!(w.is_empty());
        let (cfg, w) = Config::parse("watch = [\"a|b|c\",]\n");
        assert_eq!(cfg.watch, vec!["a|b|c"]);
        assert!(w.is_empty());
        let (cfg, w) = Config::parse("watch = [a|b|c]\n");
        assert_eq!(cfg.watch, vec!["a|b|c"]);
        assert!(w.is_empty());
        // not an array at all → warning, default kept
        let (cfg, w) = Config::parse("watch = oops\n");
        assert!(cfg.watch.is_empty());
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("not a string array"));
    }

    #[test]
    fn save_watch_roundtrips_and_preserves_the_rest() {
        let dir = std::env::temp_dir().join(format!("witr-cfg-test-{}", std::process::id()));
        let path = Config::path_under(&dir);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "# my config\nrefresh_secs = 7\nwatch_old = \"keep me\"\nwatch = [\"old|exe|u\"]\nnotify = true\n",
        )
        .unwrap();
        Config::save_watch_under(&dir, &["nginx|nginx|www".into()]).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let (cfg, _) = Config::parse(&text);
        assert_eq!(cfg.watch, vec!["nginx|nginx|www"]);
        assert_eq!(cfg.refresh_secs, Some(7), "untouched key survives");
        assert_eq!(cfg.notify, Some(true));
        assert!(text.starts_with("# my config"), "comment survives");
        assert!(text.contains("keep me"), "similarly-named keys are untouched");
        assert!(!text.contains("old|exe|u"), "stale entry replaced");
        assert_eq!(text.matches("watch =").count(), 1, "exactly one watch line");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn parse_skips_bad_lines_and_reports() {
        let text = "\
refresh_secs = fast
sort = mem
notify = maybe
wat = 1
no_equals_here
";
        let (cfg, warnings) = Config::parse(text);
        assert_eq!(cfg.refresh_secs, None, "bad number skipped");
        assert_eq!(cfg.sort.as_deref(), Some("mem"));
        assert_eq!(cfg.notify, None, "bad bool skipped");
        assert_eq!(warnings.len(), 4, "{warnings:?}");
        assert!(warnings.iter().any(|w| w.contains("unknown key")));
        assert!(warnings.iter().any(|w| w.contains("not key = value")));
    }

    #[test]
    fn parse_tolerates_bare_values_and_missing_file() {
        // unquoted strings and ints work like quoted ones
        let (cfg, w) = Config::parse("refresh_secs = 2\nsort = mem\n");
        assert_eq!(cfg.refresh_secs, Some(2));
        assert_eq!(cfg.sort.as_deref(), Some("mem"));
        assert!(w.is_empty());
        // nothing set → all defaults
        assert_eq!(Config::parse("").0, Config::default());
    }

    #[test]
    fn path_lands_in_the_right_place() {
        let p = Config::path_under(&std::path::PathBuf::from("/home/u"));
        #[cfg(target_os = "macos")]
        assert_eq!(
            p,
            std::path::PathBuf::from("/home/u/Library/Application Support/witr-rs/config.toml")
        );
        #[cfg(target_os = "linux")]
        assert_eq!(p, std::path::PathBuf::from("/home/u/.config/witr-rs/config.toml"));
        #[cfg(windows)]
        assert_eq!(p, std::path::PathBuf::from("/home/u/AppData/Roaming/witr-rs/config.toml"));
    }
}
