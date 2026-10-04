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
pub const PROBE_SMB: &str = "smb";
pub const PROBE_RDP: &str = "rdp";
pub const PROBE_MONGODB: &str = "mongodb";
pub const PROBE_MQTT: &str = "mqtt";
pub const PROBE_GENERIC: &str = "generic";

/// Deferred seams (documented, NOT implemented): imap, pop3, ldap,
/// dns-over-tcp, rpc, ntp, kerberos.
pub const DEFERRED_PROTOCOLS: &[&str] = &[
    "imap",
    "pop3",
    "ldap",
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
        id: PROBE_SMB,
        priority: 10,
        likely_ports: &[445],
    },
    ProbeSpec {
        id: PROBE_RDP,
        priority: 10,
        likely_ports: &[3389],
    },
    ProbeSpec {
        id: PROBE_MONGODB,
        priority: 10,
        likely_ports: &[27017],
    },
    ProbeSpec {
        id: PROBE_MQTT,
        priority: 10,
        likely_ports: &[1883, 8883],
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
    /// Derived version family (`1.24.0` → `1.24.x`). Never an exactness
    /// claim beyond the observed `version_hint`; useful for range-level
    /// correlation without overstating patch precision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_family: Option<String>,
    /// Inferred vendor for well-known products (static map, evidence-backed
    /// only when `product_hint` is present). `None` means unknown vendor —
    /// never guessed from the port number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_hint: Option<String>,
    /// CPE 2.3 candidate (`cpe:2.3:a:vendor:product:version:...`, `*` for
    /// unknown components). Present only when a product is observed;
    /// correlation input, never a vulnerability claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpe_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub confidence: u8,
    /// Per-field certainty (protocol/product/version/vendor). Additive;
    /// old serialized observations without it deserialize to `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_confidence: Option<FieldConfidence>,
    pub evidence_lines: Vec<String>,
    pub timestamp: u64,
    /// Registry probe (or `passive` fan-out step) whose evidence classified
    /// this service. `None` for unclassified observations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_by: Option<String>,
    /// Fingerprint rule source (`builtin:<probe>` or `fingerprints/<file>#<id>`).
    /// Always present when classified; documents which rule produced the
    /// product/vendor/version conclusion for auditability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_source: Option<String>,
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

// ---------------- fingerprint enrichment (Phase 8/36) ----------------
//
// Pure, deterministic, evidence-gated derivation from already-observed
// product/version strings. No network, no port-number guessing: every
// conclusion requires an observed product token. Confidence reflects
// evidence strength, never port priors.

/// Well-known product → vendor map. Bounded static list for correlation;
/// unknown products yield `None` (never guessed).
pub fn vendor_for_product(product: &str) -> Option<&'static str> {
    match product.to_ascii_lowercase().as_str() {
        "nginx" => Some("f5"),
        "apache" | "httpd" => Some("apache"),
        "openssh" | "dropbear" => Some("openbsd"),
        "postfix" => Some("wietse_venema"),
        "vsftpd" => Some("beasts"),
        "pure-ftpd" | "pure_ftpd" => Some("pureftpd"),
        "proftpd" => Some("proftpd"),
        "redis" => Some("redis"),
        "mysql" | "mariadb" => Some("oracle"),
        "postgresql" | "postgres" => Some("postgresql"),
        "exim" => Some("exim"),
        "sendmail" => Some("sendmail"),
        "dovecot" => Some("dovecot"),
        "iis" | "microsoft-iis" => Some("microsoft"),
        "lighttpd" => Some("lighttpd"),
        "caddy" => Some("caddyserver"),
        "traefik" => Some("traefik"),
        "haproxy" => Some("haproxy"),
        "squid" => Some("squid"),
        "varnish" => Some("varnish"),
        _ => None,
    }
}

/// Sanitize one CPE component: lowercase, safe alphabet, bounded length.
/// Returns `*` for empty/unsafe input (CPE wildcard, never invented text).
fn sanitize_cpe_component(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.is_empty() || lower.len() > 64 {
        return "*".to_owned();
    }
    let cleaned: String = lower
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '~') {
                c
            } else {
                '_'
            }
        })
        .collect();
    // CPE forbids leading digit-only collapse issues; keep as-is but never
    // emit empty.
    if cleaned.trim_matches(['.', '_', '-']).is_empty() {
        "*".to_owned()
    } else {
        cleaned
    }
}

/// CPE 2.3 candidate for an observed product/version pair.
///
/// Format: `cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*`.
/// Unknown vendor/version become `*`. Returns `None` when no product was
/// observed (never synthesize identity from a port number).
pub fn cpe_for_product_version(
    product: Option<&str>,
    version: Option<&str>,
    vendor: Option<&str>,
) -> Option<String> {
    let product = product.filter(|p| !p.trim().is_empty())?;
    let vendor_part = vendor
        .filter(|v| !v.trim().is_empty())
        .map(sanitize_cpe_component)
        .unwrap_or_else(|| "*".to_owned());
    let product_part = sanitize_cpe_component(product);
    let version_part = version
        .filter(|v| !v.trim().is_empty())
        .map(sanitize_cpe_component)
        .unwrap_or_else(|| "*".to_owned());
    Some(format!(
        "cpe:2.3:a:{vendor_part}:{product_part}:{version_part}:*:*:*:*:*:*:*"
    ))
}

/// Derive a version family (`1.24.0` → `1.24.x`, `8.0` → `8.0`,
/// `22.2p1` → `22.2.x`). Returns `None` for absent input; passes through
/// non-numeric suffixes conservatively without inventing precision.
pub fn version_family(version: Option<&str>) -> Option<String> {
    let version = version.filter(|v| !v.trim().is_empty())?;
    let version = version.trim();
    // Split off any trailing non-numeric build tag after the dotted core
    // (`22.2p1` → core `22.2`, tag `p1` dropped for the family).
    let core_end = version
        .char_indices()
        .take_while(|(_, c)| c.is_ascii_digit() || *c == '.')
        .map(|(i, c)| i + c.len_utf8())
        .last()
        .unwrap_or(0);
    let core = version[..core_end.min(version.len())].trim_matches('.');
    if core.is_empty() {
        return Some(version.to_owned());
    }
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() >= 3 {
        Some(format!("{}.{}.x", parts[0], parts[1]))
    } else {
        Some(core.to_owned())
    }
}

/// Calibrate identification confidence from evidence signals.
///
/// Rules (never exceed 95; port priors add zero):
/// * base = strongest single-signal class (CONFIRMED/STRONG/...);
/// * each *independent* corroborating signal (distinct probe or artifact:
///   banner + cert + header + behavior) adds +1, capped at 95;
/// * agreement over the SAME bytes adds nothing (no double-count);
/// * exact version without a second signal caps at 90 (family may still
///   be reported; exactness needs corroboration).
pub fn calibrate_confidence(
    base: u8,
    independent_signals: usize,
    exact_version_claimed: bool,
) -> u8 {
    let mut confidence = base.saturating_add(independent_signals.min(5) as u8);
    if exact_version_claimed && independent_signals == 0 {
        confidence = confidence.min(90);
    }
    confidence.min(95)
}

/// Enriched fingerprint conclusion for one classified observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintEnrichment {
    pub vendor: Option<String>,
    pub version_family: Option<String>,
    pub cpe: Option<String>,
    pub confidence: u8,
    pub rule_source: String,
}

/// Enrich an observed (product, version, base confidence, probe) tuple.
/// Pure function: deterministic, no I/O. `independent_signals` counts
/// distinct corroborating artifacts beyond the primary observation.
pub fn enrich_fingerprint(
    product: Option<&str>,
    version: Option<&str>,
    base_confidence: u8,
    matched_by: Option<&str>,
    independent_signals: usize,
) -> FingerprintEnrichment {
    let vendor = product.and_then(vendor_for_product).map(str::to_owned);
    let version_family = version_family(version);
    let cpe = cpe_for_product_version(product, version, vendor.as_deref());
    let exact_version = version.is_some_and(|v| !v.trim().is_empty());
    let confidence = calibrate_confidence(base_confidence, independent_signals, exact_version);
    let rule_source = match matched_by {
        Some(probe) => format!("builtin:{probe}"),
        None => "builtin:passive".to_owned(),
    };
    FingerprintEnrichment {
        vendor,
        version_family,
        cpe,
        confidence,
        rule_source,
    }
}

// ---------------- evidence classes + candidate merge (correlation engine) ----------------
//
// Confidence merging must not double-count correlated evidence: an HTTP
// Server header and an external fingerprint matching the SAME banner bytes
// are one underlying signal, not two. Evidence is classified so merging
// counts distinct CLASSES, never raw matcher hits.

/// Evidence class for confidence merging. Variants are semantic buckets;
/// two observations in the same class corroborate weakly (duplicate), two
/// in different classes corroborate independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceClass {
    /// Port-number prior: ordering hint only, always zero confidence weight.
    TransportHint,
    /// Deterministic protocol handshake (SSH ident string, TLS ServerHello,
    /// Redis PONG, MySQL framing). Strongest single class.
    ProtocolHandshake,
    /// Product token parsed from a banner/greeting by built-in grammar.
    BannerToken,
    /// TLS certificate/version/cipher artifacts beyond the handshake.
    TlsArtifact,
    /// HTTP headers/status beyond the status line.
    HttpArtifact,
    /// External fingerprint-pack rule match.
    ExternalFingerprint,
    /// Behavioral evidence (timing, error behavior, capability exchange).
    Behavior,
}

/// Count distinct merging classes in a class list (deduplicated). Port
/// priors (`TransportHint`) never count.
pub fn count_distinct_classes(classes: &[EvidenceClass]) -> usize {
    let mut seen = std::collections::BTreeSet::new();
    for class in classes {
        if *class == EvidenceClass::TransportHint {
            continue;
        }
        seen.insert(*class);
    }
    seen.len()
}

/// Combine a base confidence with corroborating evidence classes.
/// Same rule as [`calibrate_confidence`]: +1 per distinct extra class,
/// cap 95, exact version caps at 90 with fewer than 2 distinct classes.
pub fn combine_confidence(
    base: u8,
    extra_classes: &[EvidenceClass],
    exact_version_claimed: bool,
) -> u8 {
    calibrate_confidence(
        base,
        count_distinct_classes(extra_classes),
        exact_version_claimed,
    )
}

/// One merged alternate product hypothesis (conflicting evidence kept
/// visible, never silently dropped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlternateProduct {
    pub product: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    pub confidence: u8,
    pub rule_id: String,
    pub rule_source: String,
}

/// Result of merging external fingerprint candidates with the built-in
/// conclusion, following strict precedence:
/// 1. deterministic protocol handshake (built-in protocol always wins);
/// 2. exact built-in signature product;
/// 3. exact external signature (supplements ONLY when built-in has no product);
/// 4. conflicting external products become bounded alternates.
///
/// An external version adopted for an agreed product that the built-in
/// observation did not version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptedVersion {
    pub version: String,
    pub confidence: u8,
    pub rule_id: String,
    pub rule_source: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CandidateMerge {
    /// External product adopted (only when built-in observed none).
    pub adopted: Option<AdoptedProduct>,
    /// External version adopted (only when the final product is agreed
    /// and the built-in observation had no version).
    pub adopted_version: Option<AdoptedVersion>,
    /// Conflicting hypotheses kept visible (bounded, deterministic order).
    pub alternates: Vec<AlternateProduct>,
    /// External matches agreeing with the built-in product (corroboration).
    pub corroborated_by: Vec<Corroboration>,
    /// Conflicting external versions (built-in version wins; bounded).
    pub version_conflicts: Vec<AlternateVersion>,
}

/// An external rule agreeing with the built-in product conclusion.
/// Recorded for audit; same-bytes agreement never inflates confidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Corroboration {
    pub rule_id: String,
    pub rule_source: String,
}

/// An external product adopted into the primary conclusion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptedProduct {
    pub product: String,
    pub vendor: Option<String>,
    pub confidence: u8,
    pub rule_id: String,
    pub rule_source: String,
    /// Adopted declarative version (only when the rule extracted one and
    /// the built-in observation had none).
    pub version: Option<String>,
    /// Version confidence: capped at or below the adopted product
    /// confidence (a version is never surer than its product without
    /// independent corroboration).
    pub version_confidence: Option<u8>,
}

/// A conflicting external version kept visible. The built-in observed
/// version always wins; the conflict is evidence, not a silent drop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlternateVersion {
    pub product: String,
    pub builtin_version: String,
    pub external_version: String,
    pub external_confidence: u8,
    pub rule_id: String,
    pub rule_source: String,
}

/// Per-field confidence: protocol, product, version, and vendor identifications
/// carry different evidence, so they carry different certainty. The aggregate
/// observation confidence is preserved separately for compatibility; it is
/// NOT the minimum of these fields (one weak field must not erase strong
/// ones). Unknown fields report 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldConfidence {
    pub protocol: u8,
    pub product: u8,
    pub version: u8,
    pub vendor: u8,
}

/// Maximum alternates retained per observation (bounded ambiguity).
pub const MAX_ALTERNATES: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCandidateView<'a> {
    pub product: &'a str,
    pub vendor: Option<&'a str>,
    pub confidence: u8,
    pub rule_id: &'a str,
    pub rule_source: &'a str,
    pub matcher: &'a crate::fingerprints::MatcherKind,
    pub version: Option<&'a str>,
    pub version_confidence: Option<u8>,
}

/// Confidence cap for unclassified-observation suggestions by matcher
/// strength: a `contains` hit on unknown bytes is a weak heuristic (60),
/// `prefix` is stronger (75), `exact` on the whole observation is strong
/// (85). Never exceeds the rule's own confidence.
pub fn unknown_suggestion_cap(
    matcher: &crate::fingerprints::MatcherKind,
    rule_confidence: u8,
) -> u8 {
    let cap = match matcher {
        crate::fingerprints::MatcherKind::Exact => 85,
        crate::fingerprints::MatcherKind::Prefix => 75,
        crate::fingerprints::MatcherKind::Contains => 60,
    };
    rule_confidence.min(cap)
}

/// Merge external candidates with the built-in product conclusion.
/// Pure, deterministic, bounded. Built-in evidence is authoritative: an
/// external product never overwrites an observed built-in product, and an
/// external version never overwrites an observed built-in version.
/// Versions compare by trimmed case-insensitive equality; anything else is
/// a visible conflict, never a silent replacement.
pub fn merge_external_candidates(
    builtin_product: Option<&str>,
    builtin_version: Option<&str>,
    builtin_confidence: u8,
    candidates: &[ExternalCandidateView<'_>],
) -> CandidateMerge {
    let mut merge = CandidateMerge::default();
    // Deterministic candidate order: confidence desc, then rule id.
    let mut ordered: Vec<&ExternalCandidateView<'_>> = candidates.iter().collect();
    ordered.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.rule_id.cmp(b.rule_id))
    });
    let versions_equal = |left: &str, right: &str| {
        left.trim().eq_ignore_ascii_case(right.trim()) && !left.trim().is_empty()
    };
    match builtin_product.filter(|p| !p.trim().is_empty()) {
        Some(builtin) => {
            for candidate in ordered {
                if candidate.product.eq_ignore_ascii_case(builtin) {
                    merge.corroborated_by.push(Corroboration {
                        rule_id: candidate.rule_id.to_owned(),
                        rule_source: candidate.rule_source.to_owned(),
                    });
                    // Same product: version may still add information.
                    match (
                        builtin_version.filter(|v| !v.trim().is_empty()),
                        candidate.version.filter(|v| !v.trim().is_empty()),
                    ) {
                        (Some(_), Some(_)) => {}
                        (None, Some(external)) if merge.adopted_version.is_none() => {
                            let confidence = candidate
                                .version_confidence
                                .unwrap_or(candidate.confidence)
                                .min(builtin_confidence)
                                .min(95);
                            merge.adopted_version = Some(AdoptedVersion {
                                version: external.to_owned(),
                                confidence,
                                rule_id: candidate.rule_id.to_owned(),
                                rule_source: candidate.rule_source.to_owned(),
                            });
                        }
                        _ => {}
                    }
                    continue;
                }
                if merge.alternates.len() < MAX_ALTERNATES
                    && !merge
                        .alternates
                        .iter()
                        .any(|alt| alt.product.eq_ignore_ascii_case(candidate.product))
                {
                    merge.alternates.push(AlternateProduct {
                        product: candidate.product.to_owned(),
                        vendor: candidate.vendor.map(str::to_owned),
                        confidence: candidate.confidence.min(builtin_confidence).min(95),
                        rule_id: candidate.rule_id.to_owned(),
                        rule_source: candidate.rule_source.to_owned(),
                    });
                }
            }
            // Version conflicts only against the agreed product: conflicting
            // products are already alternates, their versions meaningless.
            if let Some(builtin_v) = builtin_version.filter(|v| !v.trim().is_empty()) {
                for candidate in candidates {
                    let Some(external_v) = candidate.version.filter(|v| !v.trim().is_empty())
                    else {
                        continue;
                    };
                    if !candidate.product.eq_ignore_ascii_case(builtin) {
                        continue;
                    }
                    if versions_equal(builtin_v, external_v) {
                        continue;
                    }
                    if merge.version_conflicts.len() >= MAX_ALTERNATES {
                        break;
                    }
                    if merge
                        .version_conflicts
                        .iter()
                        .any(|conflict| conflict.rule_id == candidate.rule_id)
                    {
                        continue;
                    }
                    merge.version_conflicts.push(AlternateVersion {
                        product: builtin.to_owned(),
                        builtin_version: builtin_v.to_owned(),
                        external_version: external_v.to_owned(),
                        external_confidence: candidate.confidence,
                        rule_id: candidate.rule_id.to_owned(),
                        rule_source: candidate.rule_source.to_owned(),
                    });
                }
            }
        }
        None => {
            // No built-in product: the strongest external candidate may
            // supply one, calibrated as a single-signal claim (exact
            // version unknown at this layer → conservative).
            if let Some(best) = ordered.first() {
                let adopted_confidence = best.confidence.min(90);
                let (version, version_confidence) =
                    match best.version.filter(|v| !v.trim().is_empty()) {
                        Some(extracted) => {
                            let confidence = best
                                .version_confidence
                                .unwrap_or(best.confidence)
                                .min(adopted_confidence);
                            (Some(extracted.to_owned()), Some(confidence))
                        }
                        None => (None, None),
                    };
                merge.adopted = Some(AdoptedProduct {
                    product: best.product.to_owned(),
                    vendor: best.vendor.map(str::to_owned),
                    confidence: adopted_confidence,
                    rule_id: best.rule_id.to_owned(),
                    rule_source: best.rule_source.to_owned(),
                    version,
                    version_confidence,
                });
                for candidate in ordered.iter().skip(1) {
                    if merge.alternates.len() >= MAX_ALTERNATES {
                        break;
                    }
                    if candidate.product.eq_ignore_ascii_case(best.product)
                        || merge
                            .alternates
                            .iter()
                            .any(|alt| alt.product.eq_ignore_ascii_case(candidate.product))
                    {
                        continue;
                    }
                    merge.alternates.push(AlternateProduct {
                        product: candidate.product.to_owned(),
                        vendor: candidate.vendor.map(str::to_owned),
                        confidence: candidate.confidence.min(90),
                        rule_id: candidate.rule_id.to_owned(),
                        rule_source: candidate.rule_source.to_owned(),
                    });
                }
            }
        }
    }
    merge
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
    fn enrichment_never_guesses_from_ports() {
        // No product → no vendor, no CPE, even with a version string.
        let enriched = enrich_fingerprint(None, Some("1.0"), 80, Some("http"), 0);
        assert_eq!(enriched.vendor, None);
        assert_eq!(enriched.cpe, None);
        // Unknown product → no vendor, wildcard vendor CPE.
        let enriched = enrich_fingerprint(
            Some("TotallyUnknownDaemon"),
            Some("9.9"),
            80,
            Some("generic"),
            0,
        );
        assert_eq!(enriched.vendor, None);
        assert_eq!(
            enriched.cpe.as_deref(),
            Some("cpe:2.3:a:*:totallyunknowndaemon:9.9:*:*:*:*:*:*:*")
        );
    }

    #[test]
    fn enrichment_maps_vendor_cpe_family() {
        let enriched = enrich_fingerprint(Some("nginx"), Some("1.24.0"), 90, Some("http"), 1);
        assert_eq!(enriched.vendor.as_deref(), Some("f5"));
        assert_eq!(enriched.version_family.as_deref(), Some("1.24.x"));
        assert_eq!(
            enriched.cpe.as_deref(),
            Some("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*")
        );
        assert_eq!(enriched.rule_source, "builtin:http");
        // Exact version with corroboration keeps high confidence, capped 95.
        assert!(enriched.confidence <= 95 && enriched.confidence >= 90);
        // Exact version with NO second signal caps at 90.
        let solo = enrich_fingerprint(Some("nginx"), Some("1.24.0"), 90, Some("http"), 0);
        assert_eq!(solo.confidence, 90);
    }

    #[test]
    fn version_family_stays_conservative() {
        assert_eq!(version_family(Some("1.24.0")).as_deref(), Some("1.24.x"));
        assert_eq!(version_family(Some("8.0")).as_deref(), Some("8.0"));
        assert_eq!(version_family(Some("22.2p1")).as_deref(), Some("22.2"));
        assert_eq!(version_family(None), None);
        assert_eq!(version_family(Some("  ")), None);
    }

    #[test]
    fn confidence_never_exceeds_95_or_counts_port_priors() {
        // Even max base + many signals caps at 95.
        assert_eq!(calibrate_confidence(95, 5, true), 95);
        assert_eq!(calibrate_confidence(90, 10, true), 95);
        // Same-bytes agreement (0 independent signals) adds nothing beyond cap rule.
        assert_eq!(calibrate_confidence(80, 0, false), 80);
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
