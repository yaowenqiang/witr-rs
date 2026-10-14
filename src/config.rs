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
            }
        );
        assert!(warnings.is_empty(), "{warnings:?}");
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
