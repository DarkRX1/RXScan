//! Phase 7 service-intelligence model: observations, confidence, planning.
//!
//! Takes open TCP ports (Phase 6) and determines what protocol is actually
//! speaking there — never guessing from the port number alone.
//!
//! # Evidence tiers (confidence)
//!
//! * Port hint only (no probe evidence): NEVER emitted as a classification.
//!   There is no `ServiceObservation` without probe evidence.
//! * Valid protocol handshake (e.g. `SSH-2.0-…`, `HTTP/1.1 200`, TLS
//!   ServerHello, `220` FTP greeting, `+PONG`): medium/high (70–90).
//! * Handshake + banner/details (product/version strings, cert fields,
//!   SMTP capabilities): high (85–95).
//! * Unparseable banner or silence: `unknown` (20–55), banner preserved.
//!
//! Three facts stay separate: `port_hint` (why a probe ran first),
//! `observed_protocol` (what the handshake proved), and
//! `product/version_hint` (strings copied from protocol data, never inferred
//! from the port).
//!
//! # Planner inputs → ordered probes
//!
//! Port, transport, level, goal, and budgets select a small ordered probe set
//! (deterministic by priority then probe id). `--level` controls breadth,
//! `--speed` controls pressure only. Unknown high ports get a level-graded
//! speculative set (passive always; L2 +HTTP, L3 +Redis, L4 +TLS, L5
//! +PostgreSQL and 220-gated mail disambiguation); known ports add pivots
//! at L4/L5 so hints prioritize without permanently excluding protocols.
//!
//! # Boundaries
//!
//! No authentication (no USER/PASS/AUTH/LOGIN bytes are ever sent —
//! asserted by tests), no destructive commands, no crawling, no fuzzing.
//! Product/version hints are raw observed strings; the full technology
//! fingerprint engine belongs to a later phase.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::discovery::AddressFamily;
use crate::plan::{ScanGoal, SpeedSetting};

/// Probe identifiers. New protocols register here without touching the
/// scheduler; the planner orders them deterministically.
pub const PROBE_SSH: &str = "ssh";
pub const PROBE_HTTP: &str = "http";
pub const PROBE_TLS: &str = "tls";
pub const PROBE_FTP: &str = "ftp";
pub const PROBE_SMTP: &str = "smtp";
pub const PROBE_REDIS: &str = "redis";
pub const PROBE_MYSQL: &str = "mysql";
pub const PROBE_POSTGRES: &str = "postgres";
pub const PROBE_GENERIC: &str = "generic";

/// Deferred seams (documented, NOT implemented): imap, pop3, ldap, mqtt,
/// rdp, smb, dns-over-tcp, rpc, ntp, kerberos.
pub const DEFERRED_PROTOCOLS: &[&str] = &[
    "imap",
    "pop3",
    "ldap",
    "mqtt",
    "rdp",
    "smb",
    "dns-over-tcp",
    "rpc",
    "ntp",
    "kerberos",
];

/// One registered probe: identity, transports, likely ports, order.
/// Lower `priority` runs first; ties break by probe id (deterministic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeSpec {
    pub id: &'static str,
    pub priority: u8,
    pub likely_ports: &'static [u16],
}

pub static PROBE_REGISTRY: &[ProbeSpec] = &[
    ProbeSpec {
        id: PROBE_SSH,
        priority: 10,
        likely_ports: &[22],
    },
    ProbeSpec {
        id: PROBE_HTTP,
        priority: 10,
        likely_ports: &[80, 3000, 5000, 8000, 8001, 8080, 8081, 8888, 9000, 9090],
    },
    ProbeSpec {
        id: PROBE_TLS,
        priority: 10,
        likely_ports: &[443, 8443, 465],
    },
    ProbeSpec {
        id: PROBE_FTP,
        priority: 10,
        likely_ports: &[21],
    },
    ProbeSpec {
        id: PROBE_SMTP,
        priority: 10,
        likely_ports: &[25, 465, 587],
    },
    ProbeSpec {
        id: PROBE_REDIS,
        priority: 10,
        likely_ports: &[6379],
    },
    ProbeSpec {
        id: PROBE_MYSQL,
        priority: 10,
        likely_ports: &[3306, 3307],
    },
    ProbeSpec {
        id: PROBE_POSTGRES,
        priority: 10,
        likely_ports: &[5432],
    },
    ProbeSpec {
        id: PROBE_GENERIC,
        priority: 100,
        likely_ports: &[],
    },
];

/// Maximum probes executed per port task (hard bound; plans rarely reach it
/// because classification stops the sequence early).
pub const MAX_PROBES_PER_PORT: usize = 6;

// ---------------- confidence classes ----------------

/// Named service-identification confidence classes.
///
/// Protocol identity must come from observed evidence; port numbers
/// contribute zero identity confidence by themselves, and agreement
/// between matchers over the SAME observation never inflates the class.
/// The 0–100 representation is preserved for typed output compatibility.
pub mod confidence {
    /// Complete protocol grammar plus identifying token fully valid
    /// (e.g. strict SSH identification string with software token,
    /// exact `+PONG` to PING, valid HTTP response with Server header).
    pub const CONFIRMED: u8 = 90;
    /// Valid handshake/framing plus characteristic details (e.g. FTP/SMTP
    /// greeting disambiguated by command exchange, MySQL packet framing
    /// with version, HTTP without Server header).
    pub const STRONG: u8 = 85;
    /// Characteristic grammar without full details (e.g. valid SSH
    /// identification string with no usable software token, bare TLS
    /// handshake without certificate facts).
    pub const CHARACTERISTIC: u8 = 80;
    /// Useful but incomplete evidence (e.g. single-byte PostgreSQL
    /// SSLRequest reply, auth-gated Redis error, SMTP without EHLO caps).
    pub const PROBABLE: u8 = 70;
    /// Unknown service with a preserved banner (correlation evidence only,
    /// never identity).
    pub const BANNER: u8 = 50;
    /// Unknown service, silent or timed out (nothing observed).
    pub const SILENT: u8 = 20;
}

/// Response/request byte budgets (neither side may grow without bound).
pub const MAX_BANNER_BYTES: usize = 2048;
pub const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_HTTP_BODY_BYTES: usize = 16 * 1024;
pub const MAX_CERT_CHAIN_BYTES: usize = 32 * 1024;
pub const MAX_SMTP_REPLY_BYTES: usize = 4096;

/// Bounded deterministic fingerprint of an unidentified service, for later
/// correlation — never an identity claim.
///
/// Computed over the same bounded observation bytes the generic classifier
/// preserved. The hash is FNV-1a 64-bit (as used for asset IDs elsewhere in
/// RXScan): deterministic and compact, explicitly NON-cryptographic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnknownFingerprint {
    /// Observed byte count (capped by the reader budget).
    pub len: usize,
    /// FNV-1a 64 hex over the observed bytes (non-cryptographic).
    pub hash16: String,
    /// Percentage of printable ASCII bytes (0–100).
    pub printable_pct: u8,
    /// Whether the server spoke first (vs silence / client-first).
    pub spoke_first: bool,
    /// Probe that produced the observation (e.g. `generic`, `passive`).
    pub probe: String,
    /// Whether the observation hit the reader byte budget.
    pub truncated: bool,
}

impl UnknownFingerprint {
    /// Build from bounded observation bytes. Returns `None` for empty
    /// input: silence fingerprints nothing (absence of bytes is not
    /// correlation evidence).
    pub fn compute(bytes: &[u8], spoke_first: bool, probe: &str, truncated: bool) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        let mut hash: u64 = 0xcbf29ce484222325;
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        let printable = bytes
            .iter()
            .filter(|byte| {
                let byte = **byte;
                (0x20..0x7f).contains(&byte) || matches!(byte, b'\t' | b'\n' | b'\r')
            })
            .count();
        Some(Self {
            len: bytes.len(),
            hash16: format!("{hash:016x}"),
            printable_pct: ((printable * 100) / bytes.len().max(1)).min(100) as u8,
            spoke_first,
            probe: probe.to_owned(),
            truncated,
        })
    }
}

/// Normalized service observation: one open port, one conclusion, evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceObservation {
    pub target: String,
    pub address: String,
    pub address_family: AddressFamily,
    pub port: u16,
    pub transport: String,
    pub parent_port_asset_id: String,
    pub asset_id: String,
    /// Observed protocol: ssh|http|ftp|smtp|redis|mysql|postgres|tls|unknown.
    /// `tls` alone means a bare TLS session with no application classification.
    pub protocol: String,
    /// True when application data ran inside TLS (https/smtps composition).
    pub tls: bool,
    /// Human label: `https`/`smtps` when `tls`, else `protocol`.
    pub service_label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub confidence: u8,
    pub evidence_lines: Vec<String>,
    pub timestamp: u64,
    /// Registry probe (or `passive` fan-out step) whose evidence classified
    /// this service. `None` for unclassified observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_by: Option<String>,
    /// Bounded correlation fingerprint, present only for unidentified
    /// services with a non-empty observation. Never an identity claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_fingerprint: Option<UnknownFingerprint>,
}

impl ServiceObservation {
    pub fn is_classified(&self) -> bool {
        self.protocol != "unknown"
    }
}

/// Stable FNV-1a hex (mirrors asset-ID stability elsewhere).
fn fnv_hex(input: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

/// Stable service-asset ID: parent port asset + protocol + TLS flag.
/// Distinct protocols on one port never collide.
pub fn service_asset_id(parent_port_asset_id: &str, protocol: &str, tls: bool) -> String {
    format!(
        "asset_service_{}",
        fnv_hex(&format!(
            "service:{parent_port_asset_id}:{protocol}:tls={tls}"
        ))
    )
}

pub fn service_asset_identity(parent_port_asset_id: &str, protocol: &str, tls: bool) -> String {
    let label = if tls && protocol == "http" {
        "https".to_owned()
    } else if tls && protocol == "smtp" {
        "smtps".to_owned()
    } else {
        protocol.to_owned()
    };
    format!("{parent_port_asset_id}:service/{label}")
}

/// Deterministic probe plan for one open port.
///
/// * Known ports: primary probe first, alternates per level, generic last,
///   plus pivots at deep levels (L4 +HTTP; L5 +Redis/+TLS) so a port hint
///   prioritizes without permanently excluding other protocols.
///   (`generic` is covered by the shared passive observation — it never
///   reconnects; the module evaluates it on passive bytes.)
/// * Unknown ports: passive observation plus level-graded speculative
///   actives. Level sets the cap (existing 1/2/3/4/6 scheme); port hints
///   order candidacy but never exclude at deep levels:
///   L1 passive only; L2 +HTTP; L3 +Redis; L4 +TLS; L5 +PostgreSQL and
///   220-gated mail disambiguation. SSH/MySQL/FTP/SMTP greetings classify
///   (or gate disambiguation) from passive bytes at every level ≥1.
/// * L1 caps at 1 probe; L2 at 2; L3 at 3; L4 at 4; L5 at [`MAX_PROBES_PER_PORT`].
pub fn plan_probes(port: u16, level: u8, _goal: ScanGoal) -> Vec<&'static str> {
    let level = level.clamp(1, 5);
    let mut ordered: Vec<&'static str> = Vec::new();
    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    let mut push = |id: &'static str| {
        if seen.insert(id) {
            ordered.push(id);
        }
    };

    let primary: Option<&'static str> = PROBE_REGISTRY
        .iter()
        .find(|spec| spec.id != PROBE_GENERIC && spec.likely_ports.contains(&port))
        .map(|spec| spec.id);
    // Alternates only where a second handshake is genuinely sensible:
    // TLS-wrapped SMTP on 465 tries TLS first, then plaintext SMTP.
    let alternates: &[&'static str] = match port {
        465 => &[PROBE_SMTP],
        _ => &[],
    };

    match primary {
        Some(first) => {
            push(first);
            // Port 443/8443 compose HTTPS inside the TLS session (module
            // behavior), so no separate plaintext HTTP probe is planned.
            if level >= 4 {
                for alternate in alternates {
                    push(alternate);
                }
            }
            if level >= 2 {
                push(PROBE_GENERIC);
            }
            // Deep levels append pivots to known ports too: a hint may
            // prioritize, but at L4+ it must not permanently exclude other
            // protocols from a port (cap still bounds the list).
            if level >= 4 {
                push(PROBE_HTTP);
            }
            if level >= 5 {
                push(PROBE_REDIS);
                push(PROBE_TLS);
            }
        }
        None => {
            push(PROBE_GENERIC);
            // Speculative actives by level (each its own bounded
            // connection). HTTP is the universal pivot; Redis is a 7-byte
            // definitive check; TLS handshakes fail fast off-port; the
            // 1-byte PostgreSQL check and mail disambiguation ride last at
            // L5 (mail runs earlier whenever passive shows a 220 greeting,
            // regardless of level, via module gating).
            match level {
                0 | 1 => {}
                2 => push(PROBE_HTTP),
                3 => {
                    push(PROBE_HTTP);
                    push(PROBE_REDIS);
                }
                4 => {
                    push(PROBE_HTTP);
                    push(PROBE_REDIS);
                    push(PROBE_TLS);
                }
                _ => {
                    push(PROBE_HTTP);
                    push(PROBE_REDIS);
                    push(PROBE_TLS);
                    push(PROBE_POSTGRES);
                    push(PROBE_SMTP);
                }
            }
        }
    }

    let cap = match level {
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        _ => MAX_PROBES_PER_PORT,
    };
    ordered.truncate(cap);
    ordered
}

/// Per-probe wall-clock budget derived from speed (pressure only).
/// Bounded 500..=5000ms. Truth criteria never change with speed.
pub fn service_timeout_for_speed(speed: SpeedSetting) -> Duration {
    use crate::plan::NamedSpeed;
    let millis = match speed {
        SpeedSetting::Named(NamedSpeed::Slow) => 3000,
        SpeedSetting::Named(NamedSpeed::Balanced) => 2000,
        SpeedSetting::Named(NamedSpeed::Fast) => 1000,
        SpeedSetting::Named(NamedSpeed::Auto) => 2000,
        SpeedSetting::Numeric(value) => 3000u64.saturating_sub((2500u64 * u64::from(value)) / 100),
    };
    Duration::from_millis(millis.clamp(500, 5000))
}

/// Split `Server`-style `Product/Version (...)` tokens into a product hint
/// and optional version hint. Raw observed strings only — never inferred.
pub fn split_product_token(value: &str) -> (String, Option<String>) {
    let first = value.split_whitespace().next().unwrap_or("").trim();
    if first.is_empty() {
        return (String::new(), None);
    }
    match first.split_once('/') {
        Some((product, version)) if !product.is_empty() && !version.is_empty() => {
            (product.to_owned(), Some(version.to_owned()))
        }
        _ => (first.to_owned(), None),
    }
}

/// Split a greeting remainder (`FixtureFTP 1.0 ready`, `server ESMTP`) into
/// a product hint and optional version hint. Handles `Product/Version`,
/// `Product_Version`, and bare `Product Version` word order (common in
/// FTP/SMTP greetings). Raw observed text only — never inferred from ports.
///
/// NOTE: prefer [`product_from_greeting`] for greeting lines: it skips
/// hostname/chatter tokens and sanitizes, while this helper parses a single
/// token pair verbatim (kept for unit-level compatibility).
pub fn product_and_version(remainder: &str) -> (String, Option<String>) {
    let mut words = remainder.split_whitespace();
    let first = words.next().unwrap_or("");
    if first.is_empty() {
        return (String::new(), None);
    }
    let (product, version) = split_product_token(first);
    if product.is_empty() {
        return (String::new(), None);
    }
    if version.is_some() {
        return (product, version);
    }
    if let Some(next) = words.next() {
        if next
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_digit())
        {
            return (product, Some(next.to_owned()));
        }
    }
    (product, None)
}

/// Bare tokens that are protocol chatter or generic words, never product
/// names. The sanitizer drops these instead of inventing precision.
const NON_PRODUCT_TOKENS: &[&str] = &[
    "server",
    "servers",
    "service",
    "services",
    "ready",
    "welcome",
    "hello",
    "hi",
    "ok",
    "hey",
    "banner",
    "test",
    "unknown",
    "localhost",
    "mail",
    "ftp",
    "smtp",
    "esmtp",
    "ssh",
    "http",
    "https",
    "tls",
    "ssl",
    "version",
    "protocol",
    "greeting",
    "connection",
    "connected",
];

/// Clean one raw token into a plausible product name, or `None` when the
/// token cannot justify a product claim. Strips wrapping punctuation,
/// requires an ASCII-letter-led token of bounded length over a safe
/// alphabet, and rejects chatter words. Never invents precision.
pub fn sanitize_product_token(raw: &str) -> Option<String> {
    let mut token = raw.trim();
    // Strip wrapping punctuation such as `(vsFTPd` / `"nginx"` / `[test]`.
    token = token.trim_matches(|c: char| {
        matches!(
            c,
            '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | '"' | '\'' | ',' | ';' | ':'
        )
    });
    token = token.trim();
    if token.is_empty() || token.len() > 64 {
        return None;
    }
    let mut chars = token.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphanumeric() => {}
        _ => return None,
    }
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/' | '~'))
    {
        return None;
    }
    if token.starts_with(|c: char| c.is_ascii_digit()) {
        // Digit-led tokens are versions, never products.
        return None;
    }
    if !token.chars().any(|c| c.is_ascii_alphabetic()) {
        // Pure numbers/dots are versions, never products (handled separately).
        return None;
    }
    if NON_PRODUCT_TOKENS.contains(&token.to_ascii_lowercase().as_str()) {
        return None;
    }
    Some(token.to_owned())
}

/// Whether `token` looks like a version string (digit-led, dotted,
/// bounded). Undotted numerics (`3com`, bare `7`) never qualify alone.
fn looks_like_version(token: &str) -> bool {
    let token = token.trim().trim_matches(['(', ')', '"', '\'']);
    match token.chars().next() {
        Some(first) if first.is_ascii_digit() => {}
        _ => return false,
    }
    token.contains('.')
        && token.len() <= 32
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
}

/// Extract a justified (product, version) pair from a greeting remainder.
///
/// Scans whitespace-separated words for the first token that justifies a
/// product claim: a structured `Product/version` token, or a clean token
/// followed by a version-like token. Hostnames, chatter words, and bare
/// protocol words are skipped. Returns `(None, None)` rather than guessing.
///
/// Examples: `"FixtureFTP 1.0 ready"` → `("FixtureFTP", "1.0")`;
/// `"mx.example.com ESMTP Postfix 3.7"` → `("Postfix", "3.7")`;
/// `"server ESMTP"` → `(None, None)`; `"(vsFTPd 3.0.3)"` → `("vsFTPd", "3.0.3")`.
pub fn product_from_greeting(remainder: &str) -> (Option<String>, Option<String>) {
    let words: Vec<&str> = remainder.split_whitespace().collect();
    let mut index = 0;
    while index < words.len() {
        let word = words[index];
        // Bare IP literals are addresses, never products or versions.
        if word
            .trim_matches(['(', ')', '"', '\''])
            .parse::<std::net::IpAddr>()
            .is_ok()
        {
            index += 1;
            continue;
        }
        // Digit-led tokens with letters (`10.5.22-MariaDB`): split the
        // leading dotted-numeric version from the trailing product text.
        if word.starts_with(|c: char| c.is_ascii_digit())
            && word.chars().any(|c| c.is_ascii_alphabetic())
        {
            let prefix_len = word
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .map(char::len_utf8)
                .sum::<usize>();
            let (prefix, rest) = word.split_at(prefix_len.min(word.len()));
            if looks_like_version(prefix) {
                let rest = rest.trim_start_matches(['-', '_', '/', ' ']);
                let product = sanitize_product_token(rest);
                let version = prefix.trim().trim_matches(['(', ')', '"', '\'']).to_owned();
                return (product, Some(version));
            }
            index += 1;
            continue;
        }
        // Hostname-like tokens (letters plus dots, no structured
        // separator) are addresses, never products — skip them.
        if word.contains('.')
            && !word.contains('/')
            && word.chars().any(|c| c.is_ascii_alphabetic())
        {
            index += 1;
            continue;
        }
        // Structured `Product/version` (or _/- separated with version) is
        // the strongest single-token product evidence.
        let (structured_product, structured_version) = split_product_token(word);
        if !structured_product.is_empty()
            && structured_version.is_some()
            && sanitize_product_token(&structured_product).is_some()
        {
            let product = sanitize_product_token(&structured_product).unwrap_or_default();
            if !product.is_empty() {
                return (Some(product), structured_version);
            }
        }
        // Bare token followed by a version-like token (`Postfix 3.7`).
        if let Some(clean) = sanitize_product_token(word) {
            if let Some(next) = words.get(index + 1) {
                if looks_like_version(next) {
                    let version = next.trim().trim_matches(['(', ')', '"', '\'']).to_owned();
                    return (Some(clean), Some(version));
                }
            }
            // Bare product-like token with separators but no adjacent
            // version (`Pure-FTPd`, `dropbear`) is still a justified
            // product claim, without a version. A lone plain word is
            // NOT: greeting first words are usually hostnames, and an
            // unversioned plain word cannot be told apart from chatter,
            // so it stays unknown (banner preserved separately).
            if word.contains(['/', '_', '-']) {
                return (Some(clean), None);
            }
        } else if looks_like_version(word) {
            // A version with no product context (e.g. MySQL `8.0.36`):
            // version evidence only, never an invented product.
            let version = word.trim().trim_matches(['(', ')', '"', '\'']).to_owned();
            return (None, Some(version));
        }
        index += 1;
    }
    (None, None)
}

/// Truncate evidence text to a byte budget on a char boundary, reporting
/// whether truncation happened.
pub fn truncate_bounded(text: &str, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text.to_owned(), false);
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use confidence::*;

    #[test]
    fn confidence_classes_keep_wire_order() {
        const _: () = {
            assert!(CONFIRMED > STRONG);
            assert!(STRONG > CHARACTERISTIC);
            assert!(CHARACTERISTIC > PROBABLE);
            assert!(PROBABLE > BANNER);
            assert!(BANNER > SILENT);
            assert!(CONFIRMED == 90);
            assert!(STRONG == 85);
            assert!(CHARACTERISTIC == 80);
            assert!(PROBABLE == 70);
            assert!(BANNER == 50);
            assert!(SILENT == 20);
        };
    }

    #[test]
    fn greeting_products_require_justification() {
        // Valid product + version.
        assert_eq!(
            product_from_greeting("FixtureFTP 1.0 ready"),
            (Some("FixtureFTP".to_owned()), Some("1.0".to_owned()))
        );
        // Hostname and chatter skipped; real product found later.
        assert_eq!(
            product_from_greeting("mx.example.com ESMTP Postfix 3.7"),
            (Some("Postfix".to_owned()), Some("3.7".to_owned()))
        );
        // Chatter alone: unknown beats invented precision.
        assert_eq!(product_from_greeting("server ESMTP"), (None, None));
        assert_eq!(product_from_greeting("ready"), (None, None));
        // Punctuation-wrapped token.
        assert_eq!(
            product_from_greeting("(vsFTPd 3.0.3)"),
            (Some("vsFTPd".to_owned()), Some("3.0.3".to_owned()))
        );
        // Structured token.
        assert_eq!(
            product_from_greeting("nginx/1.27.2"),
            (Some("nginx".to_owned()), Some("1.27.2".to_owned()))
        );
        // Separated product without version stays a product, no version.
        assert_eq!(
            product_from_greeting("Pure-FTPd"),
            (Some("Pure-FTPd".to_owned()), None)
        );
        // Bare IP literal is never a product or version.
        assert_eq!(product_from_greeting("192.168.1.1"), (None, None));
        // Version-led mixed token splits version from product.
        assert_eq!(
            product_from_greeting("10.5.22-MariaDB"),
            (Some("MariaDB".to_owned()), Some("10.5.22".to_owned()))
        );
        // Version alone: version evidence only, product stays unknown.
        assert_eq!(
            product_from_greeting("8.0.36"),
            (None, Some("8.0.36".to_owned()))
        );
        // Non-ASCII tokens cannot justify products.
        assert_eq!(
            product_from_greeting("sérver 1.0"),
            (None, Some("1.0".to_owned()))
        );
        // Oversized tokens cannot justify products.
        assert_eq!(product_from_greeting(&"A".repeat(70)), (None, None));
        // SSH-shaped text inside a greeting fabricates nothing.
        assert_eq!(product_from_greeting("SSH-2.0 server"), (None, None));
        // Malformed/empty input.
        assert_eq!(product_from_greeting(""), (None, None));
        assert_eq!(product_from_greeting("   "), (None, None));
    }

    #[test]
    fn planner_prioritizes_likely_probes_first() {
        assert_eq!(plan_probes(22, 3, ScanGoal::Recon)[0], PROBE_SSH);
        assert_eq!(plan_probes(80, 3, ScanGoal::Recon)[0], PROBE_HTTP);
        assert_eq!(plan_probes(443, 3, ScanGoal::Recon)[0], PROBE_TLS);
    }

    #[test]
    fn level_controls_breadth_with_hard_cap() {
        let l1 = plan_probes(443, 1, ScanGoal::Recon);
        let l5 = plan_probes(443, 5, ScanGoal::Recon);
        assert!(l1.len() <= 1);
        assert!(l5.len() <= MAX_PROBES_PER_PORT);
        assert!(l1.len() <= l5.len());
        let unknown_l1 = plan_probes(54321, 1, ScanGoal::Recon);
        assert_eq!(unknown_l1, vec![PROBE_GENERIC]);
    }

    #[test]
    fn unknown_ports_stay_conservative() {
        // Level-graded speculative budgets: passive always, then pivots.
        assert_eq!(plan_probes(54321, 1, ScanGoal::Recon), vec![PROBE_GENERIC]);
        assert_eq!(
            plan_probes(54321, 2, ScanGoal::Recon),
            vec![PROBE_GENERIC, PROBE_HTTP]
        );
        assert_eq!(
            plan_probes(54321, 3, ScanGoal::Recon),
            vec![PROBE_GENERIC, PROBE_HTTP, PROBE_REDIS]
        );
        assert_eq!(
            plan_probes(54321, 4, ScanGoal::Recon),
            vec![PROBE_GENERIC, PROBE_HTTP, PROBE_REDIS, PROBE_TLS]
        );
        let l5 = plan_probes(54321, 5, ScanGoal::Recon);
        assert_eq!(
            l5,
            vec![
                PROBE_GENERIC,
                PROBE_HTTP,
                PROBE_REDIS,
                PROBE_TLS,
                PROBE_POSTGRES,
                PROBE_SMTP
            ]
        );
        assert!(l5.len() <= MAX_PROBES_PER_PORT);
        // Goal never changes the unknown-port set (order/candidacy may
        // consider ports, identity never does).
        assert_eq!(
            plan_probes(54321, 3, ScanGoal::Web),
            plan_probes(54321, 3, ScanGoal::Recon)
        );
    }

    #[test]
    fn speed_changes_timeout_not_plan() {
        let slow = plan_probes(80, 3, ScanGoal::Recon);
        let fast = plan_probes(80, 3, ScanGoal::Recon);
        assert_eq!(slow, fast);
        assert!(
            service_timeout_for_speed(SpeedSetting::Numeric(100))
                < service_timeout_for_speed(SpeedSetting::Numeric(0))
        );
    }
}
