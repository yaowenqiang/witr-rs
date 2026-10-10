//! Binary identity for detail views and `--export`: the running binary's
//! sha256 plus its OS code-signature verdict. Only computed on demand —
//! hashing (and on Windows, a PowerShell call) is far too expensive for
//! process listings.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Read;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BinaryIdentity {
    /// sha256 of the executable file (lowercase hex). None when unreadable
    /// (permissions, vanished between ps and open).
    pub sha256: Option<String>,
    /// Human signature verdict: "valid (…identity…)", "unsigned",
    /// "NOT VALID: <reason>", or None when the platform has no signature
    /// infrastructure (Linux) or the check failed.
    pub signature: Option<String>,
}

impl BinaryIdentity {
    /// True when the signature verdict is itself a red flag (drives risk
    /// signals); informational lines don't count.
    pub fn suspicious(&self) -> Option<String> {
        let unsigned_risky = cfg!(windows);
        match &self.signature {
            Some(s) if s.starts_with("NOT VALID") => Some(format!("code signature {}", s)),
            Some(s) if s == "unsigned" && unsigned_risky => {
                Some("code signature: unsigned (unusual and risky on Windows)".into())
            }
            _ => None,
        }
    }
}

/// Inspect one executable path. Never panics; every failure degrades to a
/// None field.
pub fn inspect(exe: &str) -> BinaryIdentity {
    BinaryIdentity {
        sha256: hash_file(exe),
        signature: signature_verdict(exe),
    }
}

fn hash_file(path: &str) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

/// Command exit + combined stdout/stderr output (codesign writes its
/// verdict — both success info and errors — to stderr).
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn run_capture(cmd: &str, args: &[&str]) -> Option<(bool, String)> {
    use std::process::{Command, Stdio};
    let out = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Some((out.status.success(), text))
}

#[cfg(target_os = "macos")]
fn signature_verdict(exe: &str) -> Option<String> {
    // plain --verify (no --strict: strict mode false-positives on nested
    // bundle symlinks); non-zero when unsigned, tampered, or invalid
    let (ok, out) = run_capture("codesign", &["--verify", exe])?;
    if ok {
        // identity from the display verb (stderr); -dvv also prints the
        // Authority certificate chain, which reads better than the team id
        let id = run_capture("codesign", &["-dvv", exe]).and_then(|(_, text)| {
            text.lines()
                .find_map(|l| {
                    let v = l.split_once('=')?;
                    match v.0 {
                        "Authority" if !v.1.trim().is_empty() => Some(v.1.trim().to_string()),
                        // "unknown"/"not set" mean no team: ad-hoc signature
                        "TeamIdentifier"
                            if !v.1.trim().is_empty()
                                && v.1.trim() != "unknown"
                                && v.1.trim() != "not set" =>
                        {
                            Some(format!("team {}", v.1.trim()))
                        }
                        _ => None,
                    }
                })
                .or(Some("ad-hoc".into()))
        });
        return Some(match id {
            Some(x) if x != "ad-hoc" => format!("valid ({x})"),
            _ => "valid (ad-hoc)".into(),
        });
    }
    if out.contains("code object is not signed at all") {
        return Some("unsigned".into());
    }
    let reason = out
        .lines()
        .find(|l| l.contains("code object is not signed") || l.contains("invalid"))
        .unwrap_or("verification failed")
        .trim()
        .trim_end_matches(':')
        .to_string();
    // drop the path prefix codesign prepends: "path: reason" → "reason"
    let reason = reason
        .split_once(": ")
        .map(|(_, r)| r.to_string())
        .unwrap_or(reason);
    Some(format!("NOT VALID: {reason}"))
}

#[cfg(target_os = "windows")]
fn signature_verdict(exe: &str) -> Option<String> {
    let status = run_capture(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            &format!("(Get-AuthenticodeSignature -LiteralPath '{}').Status", exe.replace('\'', "''")),
        ],
    )?;
    let (_, text) = status;
    match text.trim() {
        "Valid" => Some("valid (Authenticode)".into()),
        "NotSigned" => Some("unsigned".into()),
        other if !other.is_empty() => Some(format!("NOT VALID: {other}")),
        _ => None,
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn signature_verdict(_exe: &str) -> Option<String> {
    // Linux has no kernel-enforced code signing story — the hash is the
    // identity of record.
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        let dir = std::env::temp_dir().join("witr-rs-hash-test");
        std::fs::create_dir_all(&dir).unwrap();
        // NIST FIPS 180 vectors
        let cases: &[(&[u8], &str)] = &[
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ];
        for (i, (content, want)) in cases.iter().enumerate() {
            let path = dir.join(format!("probe{i}.bin"));
            std::fs::write(&path, content).unwrap();
            let id = inspect(path.to_str().unwrap());
            assert_eq!(id.sha256.as_deref(), Some(*want), "vector {i}");
        }
    }

    #[test]
    fn missing_file_degrades() {
        let id = inspect("/nonexistent/binary/nowhere");
        assert_eq!(id.sha256, None);
    }

    #[test]
    fn suspicious_flags_only_invalid() {
        let mut id = BinaryIdentity { sha256: None, signature: Some("valid (x)".into()) };
        assert!(id.suspicious().is_none());
        id.signature = Some("unsigned".into());
        // unsigned is only suspicious on Windows builds
        let un = id.suspicious();
        assert_eq!(un.is_some(), cfg!(windows));
        id.signature = Some("NOT VALID: HashMismatch".into());
        assert!(id.suspicious().is_some());
        id.signature = None;
        assert!(id.suspicious().is_none());
    }
}
