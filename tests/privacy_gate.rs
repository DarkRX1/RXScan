//! Privacy gate: identity, secret and dev-trace regression test.
//!
//! This is the build-failing half of `scripts/privacy_gate.sh`. The shell
//! script is the operator-facing CLI; this test is the same policy enforced
//! natively on every OS in the CI matrix, with no new dependency and no
//! network access.
//!
//! Policy (see docs/PRIVACY_SCRUB_REPORT.md):
//!   * Scan git-tracked files only. Untracked local state is not shipped.
//!   * Reserved values are always acceptable: `example.test`, `*.invalid`,
//!     RFC 5737 / RFC 3849 / RFC 6598 / RFC 1122 ranges, loopback, and the
//!     555-01xx fictitious phone block.
//!   * Exceptions are keyed on the VALUE DIGEST, never on the path alone, so
//!     clearing one known fixture never blinds the detector to a different
//!     value appearing in the same file later.
//!   * A finding never prints the matched value, only a SHA-256 prefix.
//!
//! The detector-id set is shared with the shell script; `detector_ids_match_
//! the_shell_script` fails the build if the two implementations drift apart.

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Canonical detector ids. Must equal `PATTERN_IDS` in scripts/privacy_gate.sh.
const PATTERN_IDS: &[&str] = &[
    "email",
    "home_path",
    "private_key",
    "bearer",
    "aws_key",
    "forge_token",
    "coauthor",
    "agent_footer",
    "env_assignment",
    "public_ip",
    "phone",
];

const ALLOWLIST: &str = "scripts/privacy_gate.allowlist";
const SHELL_GATE: &str = "scripts/privacy_gate.sh";

/// Binary payloads carry no scannable text and are skipped for speed.
fn is_binary(path: &str) -> bool {
    const EXTS: &[&str] = &[
        "png", "jpg", "jpeg", "gif", "webp", "pdf", "zip", "gz", "woff", "woff2", "ico",
    ];
    match path.rsplit_once('.') {
        Some((_, ext)) => EXTS.contains(&ext.to_ascii_lowercase().as_str()),
        None => false,
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tracked_files() -> Vec<String> {
    let output = Command::new("git")
        .args(["ls-files"])
        .current_dir(repo_root())
        .output()
        .expect("git ls-files runs in the repository checkout");
    assert!(
        output.status.success(),
        "git ls-files must succeed in the repository checkout"
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

fn digest(value: &str) -> String {
    use std::fmt::Write as _;

    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let out = hasher.finalize();

    // Append into one buffer rather than allocating a String per byte
    // (clippy::format_collect).
    let mut hex = String::with_capacity(16);
    for byte in out.iter().take(8) {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// A reviewed exception from the committed allowlist.
struct Exception {
    id: String,
    path: String,
    digest_prefix: String,
}

fn load_allowlist() -> Vec<Exception> {
    let raw = std::fs::read_to_string(repo_root().join(ALLOWLIST))
        .unwrap_or_else(|e| panic!("{ALLOWLIST} must exist and be readable: {e}"));
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|line| {
            let mut parts = line.split('|');
            let id = parts.next().unwrap_or_default().to_owned();
            let path = parts.next().unwrap_or_default().to_owned();
            let digest_prefix = parts.next().unwrap_or_default().to_owned();
            assert!(
                !id.is_empty() && !path.is_empty() && !digest_prefix.is_empty(),
                "malformed allowlist entry (need <id>|<path>|<sha256-prefix>|<reason>): {line}"
            );
            Exception {
                id,
                path,
                digest_prefix,
            }
        })
        .collect()
}

/// True when a reviewed exception covers this exact detector/value/path.
fn is_allowlisted(id: &str, path: &str, value: &str, exceptions: &[Exception]) -> bool {
    let dg = digest(value);
    exceptions.iter().any(|e| {
        if e.id != id && e.id != "*" {
            return false;
        }
        let path_ok = e.path == path
            || (e.path.ends_with('/') && path.starts_with(e.path.trim_end_matches('/')));
        if !path_ok {
            return false;
        }
        e.digest_prefix == "*" || dg.starts_with(&e.digest_prefix)
    })
}

// ---------------------------------------------------------------------------
// Reserved-value policy
// ---------------------------------------------------------------------------

fn email_is_reserved(email: &str) -> bool {
    let Some((local, domain)) = email.rsplit_once('@') else {
        return false;
    };
    if local.is_empty() || !domain.contains('.') {
        return false;
    }
    matches!(
        domain.to_ascii_lowercase().as_str(),
        "example.test" | "example.com" | "example.org" | "example.net" | "localhost" | "test"
    ) || domain.ends_with(".invalid")
}

fn ip_is_reserved(ip: [u32; 4]) -> bool {
    let [a, b, c, d] = ip;
    let _ = d;
    match a {
        // 0/8 "this network", 10/8, 127/8 loopback
        0 | 10 | 127 => true,
        // 1.0.0.0/8 "this network" (RFC 1122)
        1 => b == 0,
        // 100.64/10 CGNAT (RFC 6598)
        100 => (64..=127).contains(&b),
        // 169.254/16 link-local
        169 => b == 254,
        // 172.16/12
        172 => (16..=31).contains(&b),
        // 192.0.2/24 documentation and 192.168/16 private
        192 => (b == 0 && c == 2) || b == 168,
        // 198.18/15 benchmarking and 198.51.100/24 documentation
        198 => (b == 18 || b == 19) || (b == 51 && c == 100),
        // 203.0.113/24 documentation
        203 => b == 0 && c == 113,
        // 224/4 multicast, 240/4 reserved for future use
        224..=239 => true,
        _ => false,
    }
}

fn phone_is_reserved(token: &str) -> bool {
    let digits: String = token.chars().filter(|c| c.is_ascii_digit()).collect();
    // NANP fictitious block is NPA-555-01XX: the exchange is 555 and the line
    // number is 01XX. Testing from position 0 would miss "415-555-0100".
    if digits.len() == 10 && &digits[3..6] == "555" && &digits[6..8] == "01" {
        return true;
    }
    // Toll-free and emergency prefixes.
    matches!(digits.as_str(), "911" | "112") || digits.starts_with("1800")
}

// ---------------------------------------------------------------------------
// Detectors. Each returns the matched tokens on one line.
// ---------------------------------------------------------------------------

fn is_email_local(c: char) -> bool {
    c.is_ascii_alphanumeric() || "._%+-".contains(c)
}

fn detect_email(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    for (i, &c) in chars.iter().enumerate() {
        if c != '@' {
            continue;
        }
        let mut start = i;
        while start > 0 && is_email_local(chars[start - 1]) {
            start -= 1;
        }
        let mut end = i + 1;
        while end < chars.len() && (chars[end].is_ascii_alphanumeric() || ".-".contains(chars[end]))
        {
            end += 1;
        }
        let domain: String = chars[i + 1..end].iter().collect();
        // Require a dotted domain with a 2+ char TLD, and a non-empty local part.
        if start < i && domain.contains('.') {
            let tld = domain.rsplit('.').next().unwrap_or("");
            if tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()) {
                out.push(chars[start..end].iter().collect());
            }
        }
    }
    out
}

fn detect_home_path(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for needle in ["/home/", "/Users/"] {
        if let Some(idx) = line.find(needle) {
            // Scan the NAME portion only: the leading '/' would otherwise
            // terminate the token immediately and yield an empty match.
            let rest = &line[idx + needle.len()..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || "._-".contains(c)))
                .unwrap_or(rest.len());
            // A bare "/home/" needle entry carries no name; that is the
            // detector's own vocabulary, not an operator path.
            if end > 0 {
                out.push(format!("{needle}{}", &rest[..end]));
            }
        }
    }
    let lower = line.to_ascii_lowercase();
    if let Some(idx) = lower.find(":\\users\\") {
        let rest = &line[idx + ":\\users\\".len()..];
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || "._-".contains(c)))
            .unwrap_or(rest.len());
        if end > 0 {
            out.push(format!(":\\Users\\{}", &rest[..end]));
        }
    }
    out
}

/// Canonical token is the PEM header itself, never the surrounding line text,
/// so the digest stays stable no matter what else shares the line.
fn detect_private_key(line: &str) -> Vec<String> {
    const OPEN: &str = "-----BEGIN ";
    const CLOSE: &str = "PRIVATE KEY-----";
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = line[from..].find(OPEN) {
        let start = from + rel;
        let after = &line[start + OPEN.len()..];
        if let Some(end) = after.find(CLOSE) {
            out.push(format!("{OPEN}{}{CLOSE}", &after[..end]));
            from = start + OPEN.len() + end + CLOSE.len();
        } else {
            break;
        }
    }
    out
}

fn detect_bearer(line: &str) -> Vec<String> {
    let lower = line.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = lower[from..].find("bearer ") {
        let idx = from + rel + "bearer ".len();
        let token: String = line[idx..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || "._~+/=-".contains(*c))
            .collect();
        if token.len() >= 20 {
            out.push(token);
        }
        from = idx;
    }
    out
}

fn detect_aws_key(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for window in line.as_bytes().windows(20) {
        if window.starts_with(b"AKIA")
            && window[4..]
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            out.push(String::from_utf8_lossy(window).into_owned());
        }
    }
    out
}

fn detect_forge_token(line: &str) -> Vec<String> {
    let markers = [
        "ghp_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "xoxs-",
        "sk-",
    ];
    let mut out = Vec::new();
    for marker in markers {
        let mut from = 0usize;
        while let Some(rel) = line[from..].find(marker) {
            let start = from + rel;
            let token: String = line[start..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
                .collect();
            if token.len() >= marker.len() + 16 {
                out.push(token);
            }
            from = start + marker.len();
            if from >= line.len() {
                break;
            }
        }
    }
    out
}

const AGENT_FOOTERS: &[&str] = &[
    "Co-Generated-By",
    "Generated with",
    "Generated by",
    "Written by an AI",
    "Written by a AI",
    "Written by AI",
    "Written by LLM",
];

/// Returns the matched phrase itself, never the whole line, so the digest is
/// stable regardless of surrounding text.
fn detect_keyword(line: &str, keywords: &[&str]) -> Vec<String> {
    keywords
        .iter()
        .filter(|k| line.contains(**k))
        .map(|k| (*k).to_owned())
        .collect()
}

const ENV_KEYWORDS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "APIKEY",
    "API_KEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
];

fn detect_env_assignment(line: &str) -> Vec<String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return Vec::new();
    }
    let body = trimmed
        .strip_prefix("export")
        .unwrap_or(trimmed)
        .trim_start();
    let Some(eq) = body.find('=') else {
        return Vec::new();
    };
    let name = &body[..eq];
    if name.is_empty()
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        || !name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
    {
        return Vec::new();
    }
    if ENV_KEYWORDS.iter().any(|k| name.contains(k)) {
        vec![name.to_owned()]
    } else {
        Vec::new()
    }
}

fn detect_public_ip(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes: Vec<char> = line.chars().collect();
    let mut i = 0usize;
    while i < bytes.len() {
        if !(bytes[i].is_ascii_digit() || bytes[i] == '.') {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == '.') {
            i += 1;
        }
        let token: String = bytes[start..i].iter().collect();
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 4 {
            continue;
        }
        let mut octets = [0u32; 4];
        let mut ok = true;
        for (slot, part) in octets.iter_mut().zip(parts.iter()) {
            // Reject leading-zero and out-of-range forms so "999.1.1.1" and
            // "010.0.0.1" never masquerade as addresses.
            if part.is_empty() || part.len() > 3 || (part.len() > 1 && part.starts_with('0')) {
                ok = false;
                break;
            }
            match part.parse::<u32>() {
                Ok(v) if v <= 255 => *slot = v,
                _ => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && !ip_is_reserved(octets) {
            out.push(token);
        }
    }
    out
}

fn detect_phone(line: &str) -> Vec<String> {
    let chars: Vec<char> = line.chars().collect();
    let digit = |i: usize| i < chars.len() && chars[i].is_ascii_digit();
    let sep = |i: usize| i < chars.len() && (chars[i] == '.' || chars[i] == ' ' || chars[i] == '-');
    let group = |from: usize, len: usize| -> bool { (from..from + len).all(digit) };

    let mut out = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        if !digit(i) {
            i += 1;
            continue;
        }
        // Match DDD sep DDD sep DDDD, mirroring the shell pattern so both
        // gates emit the identical substring and therefore the same digest.
        if group(i, 3) && sep(i + 3) && group(i + 4, 3) && sep(i + 7) && group(i + 8, 4) {
            let start = i;
            let end = i + 12;
            let bounded_left = start == 0 || !digit(start - 1);
            let bounded_right = end >= chars.len() || !digit(end);
            if bounded_left && bounded_right {
                let token: String = chars[start..end].iter().collect();
                if !phone_is_reserved(&token) {
                    out.push(token);
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Run every detector over one line, returning `(id, token)` pairs.
fn scan_line(id: &str, line: &str) -> Vec<String> {
    match id {
        "email" => detect_email(line)
            .into_iter()
            .filter(|e| !email_is_reserved(e))
            .collect(),
        "home_path" => detect_home_path(line),
        "private_key" => detect_private_key(line),
        "bearer" => detect_bearer(line),
        "aws_key" => detect_aws_key(line),
        "forge_token" => detect_forge_token(line),
        "coauthor" => detect_keyword(line, &["Co-Authored-By:"]),
        "agent_footer" => detect_keyword(line, AGENT_FOOTERS),
        "env_assignment" => detect_env_assignment(line),
        "public_ip" => detect_public_ip(line),
        "phone" => detect_phone(line),
        other => panic!("unknown detector id: {other}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn detector_ids_match_the_shell_script() {
    let script = std::fs::read_to_string(repo_root().join(SHELL_GATE))
        .unwrap_or_else(|e| panic!("{SHELL_GATE} must exist: {e}"));
    let line = script
        .lines()
        .find(|l| l.starts_with("PATTERN_IDS="))
        .unwrap_or_else(|| panic!("{SHELL_GATE} must declare PATTERN_IDS"));
    let declared: Vec<&str> = line
        .trim_start_matches("PATTERN_IDS=")
        .trim()
        .trim_matches('"')
        .split_whitespace()
        .collect();
    assert_eq!(
        declared, PATTERN_IDS,
        "the shell gate and this test must declare the same detector ids"
    );
}

/// Proves each detector actually fires. A gate that cannot fail is worthless,
/// and this is the regression guard for detector bugs that silently stop
/// matching (for example a leading `-` in a pattern being read as a flag).
#[test]
fn every_detector_fires_on_a_synthetic_sample() {
    let cases: &[(&str, &str)] = &[
        (
            "email",
            "reach me at operator@not-reserved-domain.net please",
        ),
        ("home_path", "cd /home/operator/project && ls"),
        ("home_path", "open /Users/operator/Desktop"),
        ("private_key", "-----BEGIN RSA PRIVATE KEY-----"),
        (
            "bearer",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789",
        ),
        ("aws_key", "AKIAIOSFODNN7EXAMPLE"),
        (
            "forge_token",
            "token ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        ),
        (
            "coauthor",
            "Co-Authored-By: Some Person <p@example.invalid>",
        ),
        ("agent_footer", "Generated with SomeAI Assistant"),
        ("env_assignment", "MY_API_TOKEN=hunter2secretvalue"),
        ("env_assignment", "API_KEY=abc"),
        ("env_assignment", "  DB_PASSWORD=z"),
        ("env_assignment", "export GITHUB_TOKEN=y"),
        // Must stay NON-reserved. `ip_is_reserved` drops reserved values, so a
        // documentation address here would leave the detector with nothing to
        // fire on and this test would assert nothing. See the Verification
        // section of docs/PRIVACY_SCRUB_REPORT.md: this fixture is the one
        // literal here that is a real routable address, and it needs a
        // digest-keyed allowlist entry when the wildcard is tightened.
        ("public_ip", "connecting to 203.0.114.55 now"),
        ("phone", "call 415-555-2671 tomorrow"),
    ];
    for (id, sample) in cases {
        let hits = scan_line(id, sample);
        assert!(
            !hits.is_empty(),
            "detector `{id}` failed to fire on its own synthetic sample"
        );
    }
}

/// The complement: values that are reserved or structural must never fire.
#[test]
fn reserved_and_structural_values_do_not_fire() {
    let cases: &[(&str, &str)] = &[
        ("email", "operator@example.test"),
        ("email", "root@localhost"),
        ("email", "a@b.invalid"),
        ("public_ip", "192.0.2.10 and 198.51.100.7 and 203.0.113.9"),
        (
            "public_ip",
            "loopback 127.0.0.1 and private 10.0.0.1 and 192.168.1.1",
        ),
        ("public_ip", "cgnat 100.64.0.1 and this-network 1.0.0.0"),
        (
            "public_ip",
            "multicast 239.255.255.250 and link-local 169.254.1.1",
        ),
        ("phone", "fictitious 555-0100 number"),
        ("phone", "toll free 800-555-0199"),
        ("env_assignment", "HOME=/root"),
        ("home_path", "the needles /home/ and /Users/ are forbidden"),
    ];
    for (id, sample) in cases {
        let hits = scan_line(id, sample);
        assert!(
            hits.is_empty(),
            "detector `{id}` fired on a reserved/structural value: {sample}"
        );
    }
}

#[test]
fn allowlist_entries_are_well_formed_and_current() {
    let exceptions = load_allowlist();
    assert!(
        !exceptions.is_empty(),
        "the allowlist should record the reviewed exceptions found during Phase 1"
    );
    let tracked: HashSet<String> = tracked_files().into_iter().collect();
    for e in &exceptions {
        assert!(
            PATTERN_IDS.contains(&e.id.as_str()) || e.id == "*" || e.id == "denylist",
            "allowlist names an unknown detector id: {}",
            e.id
        );
        let path_ok = tracked.contains(&e.path)
            || (e.path.ends_with('/')
                && tracked
                    .iter()
                    .any(|t| t.starts_with(e.path.trim_end_matches('/'))));
        assert!(
            path_ok,
            "allowlist entry references a path that is not tracked: {}",
            e.path
        );
        if e.digest_prefix != "*" {
            assert_eq!(
                e.digest_prefix.len(),
                16,
                "allowlist digests must be a 16-char SHA-256 prefix: {}",
                e.digest_prefix
            );
        }
    }
}

/// A wildcard exception silently re-opens a whole file to any finding, so it
/// is permitted only for the gate's own files and nowhere else. Without this
/// test, the easiest way to make the gate green would be to sprinkle `*`
/// entries across the tree.
#[test]
fn wildcard_exceptions_are_limited_to_the_gate_itself() {
    const GATE_FILES: &[&str] = &["scripts/privacy_gate.sh", "tests/privacy_gate.rs"];
    for e in load_allowlist() {
        let id_is_wild = e.id == "*";
        let digest_is_wild = e.digest_prefix == "*";
        if !(id_is_wild || digest_is_wild) {
            continue;
        }
        assert!(
            GATE_FILES.contains(&e.path.as_str()),
            "wildcard exception names a file outside the gate itself: {}|{}|{}",
            e.id,
            e.path,
            e.digest_prefix
        );
    }
}

#[test]
fn no_unreviewed_privacy_findings_in_tracked_files() {
    let exceptions = load_allowlist();
    let mut findings: Vec<String> = Vec::new();

    for path in tracked_files() {
        if is_binary(&path) {
            continue;
        }
        let full = repo_root().join(&path);
        let Ok(bytes) = std::fs::read(&full) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        for (idx, line) in text.lines().enumerate() {
            let lineno = idx + 1;
            for id in PATTERN_IDS {
                for token in scan_line(id, line) {
                    if is_allowlisted(id, &path, &token, &exceptions) {
                        continue;
                    }
                    findings.push(format!("{id} {path}:{lineno} sha256:{}", digest(&token)));
                }
            }
        }
    }

    findings.sort();
    findings.dedup();
    assert!(
        findings.is_empty(),
        "privacy gate found {} unreviewed value(s) in tracked files.\n\
         Never print the matched value; each line carries a SHA-256 prefix.\n\
         Fix the value (use a reserved equivalent), or record a reviewed \
         exception in {ALLOWLIST} as <id>|<path>|<sha256-prefix>|<reason>.\n\n{}",
        findings.len(),
        findings.join("\n")
    );
}

/// The gate must catch a planted leak, not merely stay quiet. Uses a value
/// that is reserved nowhere and appears in no allowlist entry.
#[test]
fn a_planted_leak_is_detected() {
    let planted = "ping operator@leak-canary-domain.example";
    let exceptions = load_allowlist();
    let hits = scan_line("email", planted);
    let unreviewed: Vec<&String> = hits
        .iter()
        .filter(|t| !is_allowlisted("email", "canary", t, &exceptions))
        .collect();
    assert!(
        !unreviewed.is_empty(),
        "a planted, non-reserved contact address must be reported"
    );
}

/// Guard the helper used by every other test.
/// Locks `digest` to known SHA-256 prefixes. Every entry in
/// `scripts/privacy_gate.allowlist` is keyed on this function's output, so a
/// silent change here would silently re-open every reviewed exception.
/// The vectors below were computed with `sha256sum`, independently of this
/// code, so they cannot be satisfied by a bug in `digest` itself.
#[test]
fn digest_matches_known_sha256_vectors() {
    for (input, expected) in [
        ("", "e3b0c44298fc1c14"),
        ("a", "ca978112ca1bbdca"),
        ("abc", "ba7816bf8f01cfea"),
        ("operator@example.test", "8a39ca2160d1a170"),
        ("/home/operator", "53a8fcca9845a83e"),
    ] {
        assert_eq!(
            digest(input),
            expected,
            "digest({input:?}) must stay byte-identical: the allowlist is keyed on it"
        );
    }
    // Lowercase hex only, fixed width. These samples are only digested, never
    // scanned, so they may all use reserved values.
    for sample in ["a", "", "abc", "/home/operator", "203.0.113.55"] {
        let d = digest(sample);
        assert_eq!(d.len(), 16, "digest width changed for {sample:?}");
        assert!(
            d.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "digest must be lowercase hex: {d}"
        );
    }
}

#[test]
fn digest_is_stable_and_value_preserving() {
    assert_eq!(digest(""), digest(""));
    assert_ne!(digest("a"), digest("b"));
    assert_eq!(digest("a").len(), 16);
    assert!(digest("a").chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn repo_root_is_the_crate_directory() {
    assert!(Path::new(&repo_root()).join("Cargo.toml").exists());
}
