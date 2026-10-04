//! Structured fingerprint database (Phase 9 scaffolding).
//!
//! Fingerprints live OUTSIDE core Rust logic in versioned JSON packs under
//! `fingerprints/v1/*.json`. This module validates packs before loading:
//! malformed packs return [`FingerprintError`] and never crash the scanner.
//!
//! # Record schema
//!
//! ```json
//! {
//!   "schema_version": 1,
//!   "fingerprints": [
//!     {
//!       "id": "http-nginx-server-header",
//!       "protocol": "http",
//!       "probe": "http",
//!       "matcher": {"kind": "contains", "pattern": "nginx", "case_insensitive": true},
//!       "product": "nginx",
//!       "vendor": "f5",
//!       "confidence": 85,
//!       "source": "seed-v1"
//!     }
//!   ]
//! }
//! ```
//!
//! Matcher kinds are intentionally small (`exact`/`prefix`/`contains`) so
//! matching is bounded, deterministic, and panic-free on untrusted input.
//! Regex is deliberately NOT supported (no new deps, no ReDoS surface).
//! Confidence is capped at 95 (evidence cap; never certainty).

use std::{collections::BTreeSet, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const FINGERPRINT_SCHEMA_VERSION: u32 = 1;
/// Max matcher pattern bytes (bounded input, bounded matching).
pub const MAX_PATTERN_BYTES: usize = 512;
/// Max fingerprints per pack file (bounded load).
pub const MAX_FINGERPRINTS_PER_FILE: usize = 1024;

#[derive(Debug, Error)]
pub enum FingerprintError {
    #[error("could not read fingerprint file '{path}': {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("could not parse fingerprint file '{path}': {detail}")]
    Parse { path: String, detail: String },
    #[error("invalid fingerprint pack '{path}': {reason}")]
    Invalid { path: String, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatcherKind {
    Exact,
    Prefix,
    Contains,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintMatcher {
    pub kind: MatcherKind,
    pub pattern: String,
    #[serde(default = "default_case_insensitive")]
    pub case_insensitive: bool,
}

fn default_case_insensitive() -> bool {
    true
}

/// Maximum captured version length in bytes (bounded extraction).
pub const MAX_VERSION_LEN: usize = 32;

/// Declarative version extractor. All variants operate on `&str` with
/// explicit bounds — no backtracking engine, no regex, no code execution.
/// Extraction failure yields `None` and never invalidates the product
/// match it rides on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum VersionExtractor {
    /// Capture the token after the first occurrence of `delimiter`.
    /// Example: delimiter `"OpenSSH_"` on `"SSH-2.0-OpenSSH_9.7p1"` → `9.7p1`.
    AfterDelimiter { delimiter: String, max_len: usize },
    /// Capture the Nth whitespace-separated token (0-based).
    TokenPosition { index: usize },
    /// Capture the token after `key` followed by `=` or `:` (optional
    /// whitespace around the separator). Example: key `"version"` on
    /// `"server myd/2; version=3.1"` → `3.1`.
    KeyValue { key: String },
    /// Capture the remainder of the first token starting with `prefix`,
    /// with the prefix stripped. Example: prefix `"nginx/"` on
    /// `"Server: nginx/1.24.0"` → `1.24.0`.
    PrefixedToken { prefix: String, max_len: usize },
    /// Capture the first semver-like numeric token (`1.24.0`, `9.7p1`,
    /// `8.0.36-11`). Bounded manual scan, no regex.
    SemVerToken {},
}

impl VersionExtractor {
    fn validate(&self, rule_id: &str, path: &str) -> Result<(), FingerprintError> {
        let invalid = |reason: String| FingerprintError::Invalid {
            path: path.to_owned(),
            reason,
        };
        match self {
            Self::AfterDelimiter { delimiter, max_len } => {
                if delimiter.is_empty() || delimiter.len() > 64 {
                    return Err(invalid(format!(
                        "fingerprint '{rule_id}': after_delimiter delimiter must be 1..=64 bytes"
                    )));
                }
                if *max_len == 0 || *max_len > MAX_VERSION_LEN {
                    return Err(invalid(format!(
                        "fingerprint '{rule_id}': max_len must be 1..={MAX_VERSION_LEN}"
                    )));
                }
            }
            Self::TokenPosition { index } => {
                if *index > 15 {
                    return Err(invalid(format!(
                        "fingerprint '{rule_id}': token index must be 0..=15"
                    )));
                }
            }
            Self::KeyValue { key } => {
                if key.is_empty() || key.len() > 64 {
                    return Err(invalid(format!(
                        "fingerprint '{rule_id}': key must be 1..=64 bytes"
                    )));
                }
            }
            Self::PrefixedToken { prefix, max_len } => {
                if prefix.is_empty() || prefix.len() > 64 {
                    return Err(invalid(format!(
                        "fingerprint '{rule_id}': prefix must be 1..=64 bytes"
                    )));
                }
                if *max_len == 0 || *max_len > MAX_VERSION_LEN {
                    return Err(invalid(format!(
                        "fingerprint '{rule_id}': max_len must be 1..={MAX_VERSION_LEN}"
                    )));
                }
            }
            Self::SemVerToken {} => {}
        }
        Ok(())
    }

    /// Extract a version string from observed text. Returns `None` on any
    /// failure (missing delimiter, empty capture, overlong value, unsafe
    /// characters, non-UTF8 boundaries handled). Deterministic.
    pub fn extract(&self, text: &str) -> Option<String> {
        let raw = match self {
            Self::AfterDelimiter { delimiter, .. } => {
                let (_, after) = text.split_once(delimiter.as_str())?;
                after.split_whitespace().next().unwrap_or("")
            }
            Self::TokenPosition { index } => text.split_whitespace().nth(*index).unwrap_or(""),
            Self::KeyValue { key } => {
                let mut search = text;
                loop {
                    let pos = search.find(key.as_str())?;
                    let after_key = &search[pos + key.len()..];
                    let after_sep = after_key
                        .trim_start()
                        .strip_prefix(['=', ':'])
                        .map(str::trim_start)?;
                    // `key` must be a standalone token prefix: reject
                    // matches inside longer identifiers (`myversion=`).
                    let before = &search[..pos];
                    let boundary_ok = before
                        .chars()
                        .next_back()
                        .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'));
                    if boundary_ok {
                        break after_sep.split_whitespace().next().unwrap_or("");
                    }
                    search = after_key;
                    if search.is_empty() {
                        return None;
                    }
                }
            }
            Self::PrefixedToken { prefix, .. } => {
                let token = text
                    .split_whitespace()
                    .find(|token| token.starts_with(prefix.as_str()))?;
                token.strip_prefix(prefix.as_str()).unwrap_or("")
            }
            Self::SemVerToken {} => semver_token(text)?,
        };
        sanitize_version_token(raw, self.max_len())
    }

    fn max_len(&self) -> usize {
        match self {
            Self::AfterDelimiter { max_len, .. } | Self::PrefixedToken { max_len, .. } => *max_len,
            Self::TokenPosition { .. } | Self::KeyValue { .. } | Self::SemVerToken {} => {
                MAX_VERSION_LEN
            }
        }
    }
}

/// First semver-like numeric token in text: digit-led, dots/dashes with
/// alphanumerics, e.g. `1.24.0`, `9.7p1`, `8.0.36-11`. Manual bounded scan.
fn semver_token(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_digit() {
            let mut end = index;
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric()
                    || matches!(bytes[end], b'.' | b'_' | b'-' | b'+'))
            {
                end += 1;
            }
            let token = &text[index..end];
            if token.contains('.') || token.len() > 1 {
                return Some(token);
            }
            index = end.max(index + 1);
        } else {
            index += 1;
        }
    }
    None
}

/// Validate and bound a raw captured version. Requires ASCII-only safe
/// token characters, at least one digit (guards against `stable`/`latest`
/// style non-versions), and the extractor's length bound. Char-boundary
/// safe on every cut. One layer of surrounding quotes/backticks is
/// stripped first (evidence text routinely quotes values); anything else
/// outside the safe token set rejects the capture.
fn sanitize_version_token(raw: &str, max_len: usize) -> Option<String> {
    let token = raw.trim();
    if token.is_empty() {
        return None;
    }
    if !token.is_ascii() {
        return None;
    }
    let token = token.trim_matches(['"', '\'', '`']);
    if token.is_empty() {
        return None;
    }
    if !token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b'~' | b':'))
    {
        return None;
    }
    if !token.bytes().any(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut end = token.len().min(max_len);
    while end > 0 && !token.is_char_boundary(end) {
        end -= 1;
    }
    let token = token[..end].trim().to_owned();
    if token.is_empty() || token.len() > max_len {
        return None;
    }
    Some(token)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintRecord {
    pub id: String,
    pub protocol: String,
    pub probe: String,
    pub matcher: FingerprintMatcher,
    pub product: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Static confidence for this rule (1..=95). Calibrated downstream with
    /// corroboration; never 100.
    pub confidence: u8,
    pub source: String,
    /// Optional bounded version extractor. Old product-only rules omit it
    /// and keep loading unchanged (additive schema).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_extractor: Option<VersionExtractor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintPack {
    pub schema_version: u32,
    #[serde(default)]
    pub fingerprints: Vec<FingerprintRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintMatch {
    pub rule_id: String,
    pub product: String,
    pub vendor: Option<String>,
    pub confidence: u8,
    pub source: String,
}

impl FingerprintPack {
    fn validate(&self, path: &str) -> Result<(), FingerprintError> {
        let invalid = |reason: String| FingerprintError::Invalid {
            path: path.to_owned(),
            reason,
        };
        if self.schema_version != FINGERPRINT_SCHEMA_VERSION {
            return Err(invalid(format!(
                "unsupported schema_version {}, expected {FINGERPRINT_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.fingerprints.len() > MAX_FINGERPRINTS_PER_FILE {
            return Err(invalid(format!(
                "too many fingerprints ({} > {MAX_FINGERPRINTS_PER_FILE})",
                self.fingerprints.len()
            )));
        }
        let mut ids = BTreeSet::new();
        for record in &self.fingerprints {
            if record.id.trim().is_empty() || record.id.len() > 128 {
                return Err(invalid("fingerprint id must be 1..=128 chars".to_owned()));
            }
            if !ids.insert(record.id.clone()) {
                return Err(invalid(format!("duplicate fingerprint id '{}'", record.id)));
            }
            for (field, value) in [
                ("protocol", &record.protocol),
                ("probe", &record.probe),
                ("product", &record.product),
                ("source", &record.source),
            ] {
                if value.trim().is_empty() || value.len() > 64 {
                    return Err(invalid(format!(
                        "fingerprint '{}': {field} must be 1..=64 chars",
                        record.id
                    )));
                }
            }
            if record.confidence == 0 || record.confidence > 95 {
                return Err(invalid(format!(
                    "fingerprint '{}': confidence must be 1..=95, got {}",
                    record.id, record.confidence
                )));
            }
            if record.matcher.pattern.is_empty() || record.matcher.pattern.len() > MAX_PATTERN_BYTES
            {
                return Err(invalid(format!(
                    "fingerprint '{}': matcher pattern must be 1..={MAX_PATTERN_BYTES} bytes",
                    record.id
                )));
            }
            if let Some(vendor) = &record.vendor {
                if vendor.trim().is_empty() || vendor.len() > 64 {
                    return Err(invalid(format!(
                        "fingerprint '{}': vendor must be 1..=64 chars",
                        record.id
                    )));
                }
            }
            if let Some(extractor) = &record.version_extractor {
                extractor.validate(&record.id, path)?;
            }
        }
        Ok(())
    }

    /// Deterministic match: first rule (sorted by id) whose matcher hits.
    /// Returns `None` for empty input (silence matches nothing).
    pub fn match_observation(&self, protocol: &str, observation: &str) -> Option<FingerprintMatch> {
        if observation.is_empty() {
            return None;
        }
        let mut sorted: Vec<&FingerprintRecord> = self.fingerprints.iter().collect();
        sorted.sort_by(|a, b| a.id.cmp(&b.id));
        for record in sorted {
            if record.protocol != protocol {
                continue;
            }
            if matcher_hits(&record.matcher, observation) {
                return Some(FingerprintMatch {
                    rule_id: record.id.clone(),
                    product: record.product.clone(),
                    vendor: record.vendor.clone(),
                    confidence: record.confidence,
                    source: record.source.clone(),
                });
            }
        }
        None
    }
}

fn matcher_hits(matcher: &FingerprintMatcher, observation: &str) -> bool {
    if matcher.case_insensitive {
        let haystack = observation.to_ascii_lowercase();
        let needle = matcher.pattern.to_ascii_lowercase();
        match matcher.kind {
            MatcherKind::Exact => haystack == needle,
            MatcherKind::Prefix => haystack.starts_with(&needle),
            MatcherKind::Contains => haystack.contains(&needle),
        }
    } else {
        match matcher.kind {
            MatcherKind::Exact => observation == matcher.pattern,
            MatcherKind::Prefix => observation.starts_with(&matcher.pattern),
            MatcherKind::Contains => observation.contains(&matcher.pattern),
        }
    }
}

/// Load and validate every `*.json` pack in `dir`. Malformed files are
/// reported per-file; valid files still load (fail-one-not-all). A missing
/// directory yields an empty pack (built-in logic remains authoritative).
pub fn load_dir(dir: &Path) -> Result<Vec<(String, FingerprintPack)>, FingerprintError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(source) => {
            return Err(FingerprintError::Read {
                path: dir.display().to_string(),
                source,
            });
        }
    };
    let mut packs = Vec::new();
    let mut files: Vec<_> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| FingerprintError::Read {
            path: dir.display().to_string(),
            source,
        })?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            files.push(path);
        }
    }
    files.sort();
    for path in files {
        let contents = std::fs::read_to_string(&path).map_err(|source| FingerprintError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let pack: FingerprintPack =
            serde_json::from_str(&contents).map_err(|error| FingerprintError::Parse {
                path: path.display().to_string(),
                detail: error.to_string(),
            })?;
        pack.validate(&path.display().to_string())?;
        packs.push((path.display().to_string(), pack));
    }
    Ok(packs)
}

/// Parse + validate one pack from a JSON string (tests, API input).
/// Never panics on untrusted input.
pub fn parse_pack(json: &str, label: &str) -> Result<FingerprintPack, FingerprintError> {
    let pack: FingerprintPack =
        serde_json::from_str(json).map_err(|error| FingerprintError::Parse {
            path: label.to_owned(),
            detail: error.to_string(),
        })?;
    pack.validate(label)?;
    Ok(pack)
}

// ---------------- live runtime database (correlation engine) ----------------
//
// Packs are loaded ONCE per scan (see `run.rs`) into an immutable,
// shareable [`FingerprintDb`]. Per-port matching borrows the compiled rule
// lists — no filesystem access, no JSON parsing in the hot path. Matching
// stays bounded: a fixed candidate cap, deterministic rule-id order, and
// mandatory protocol gating (an SSH rule never fires on HTTP bytes).

/// Maximum external candidates returned per observation (bounded merge).
pub const MAX_CANDIDATES_PER_OBSERVATION: usize = 4;
/// Maximum observation bytes scanned per rule (bounded matching).
pub const MAX_MATCH_BYTES: usize = 2048;

/// One external candidate observation. Candidates never mutate findings
/// directly; they merge through the confidence policy in `service.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintCandidate {
    pub product: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Declaratively extracted version, if the rule declares an extractor
    /// and it succeeded. Extraction failure never invalidates the product.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Version confidence: the rule confidence at candidate level; the merge
    /// layer caps it at or below the adopted product confidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_confidence: Option<u8>,
    pub confidence: u8,
    pub rule_id: String,
    /// Pack-qualified rule source (`<pack-path>#<rule-id>`).
    pub rule_source: String,
    pub matcher: MatcherKind,
    /// Short supporting evidence excerpt (bounded, sanitized to lossy text).
    pub evidence: String,
}

/// Load statistics for diagnostics and `--explain` honesty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintLoadStats {
    pub packs_loaded: usize,
    pub rules_accepted: usize,
    pub files_rejected: usize,
    #[serde(default)]
    pub rejected_files: Vec<String>,
    /// Accepted pack paths in load order (classifier provenance).
    #[serde(default)]
    pub pack_paths: Vec<String>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    id: String,
    protocol: String,
    product: String,
    vendor: Option<String>,
    confidence: u8,
    pack_path: String,
    matcher: FingerprintMatcher,
    version_extractor: Option<VersionExtractor>,
}

/// Immutable compiled fingerprint database, shared across all service-probe
/// tasks of one scan via `Arc`. Construction validates every pack; matching
/// is pure and deterministic.
#[derive(Debug, Clone, Default)]
pub struct FingerprintDb {
    rules: Vec<CompiledRule>,
    stats: FingerprintLoadStats,
}

impl FingerprintDb {
    /// Empty database: built-in evidence remains authoritative.
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn stats(&self) -> &FingerprintLoadStats {
        &self.stats
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Compile validated packs. Rules sort by rule id for deterministic
    /// match order regardless of pack file order. Duplicate rule ids across
    /// packs keep the first pack's rule (packs in path-sorted order);
    /// duplicates never produce double candidates.
    pub fn from_packs(packs: Vec<(String, FingerprintPack)>) -> Self {
        let mut rules = Vec::new();
        let mut seen_ids = std::collections::BTreeSet::new();
        let mut stats = FingerprintLoadStats {
            packs_loaded: packs.len(),
            ..FingerprintLoadStats::default()
        };
        for (path, pack) in packs {
            if !stats.pack_paths.contains(&path) {
                stats.pack_paths.push(path.clone());
            }
            for record in pack.fingerprints {
                if !seen_ids.insert(record.id.clone()) {
                    continue;
                }
                stats.rules_accepted += 1;
                rules.push(CompiledRule {
                    id: record.id,
                    protocol: record.protocol,
                    product: record.product,
                    vendor: record.vendor,
                    confidence: record.confidence,
                    pack_path: path.clone(),
                    matcher: record.matcher,
                    version_extractor: record.version_extractor,
                });
            }
        }
        rules.sort_by(|a, b| a.id.cmp(&b.id));
        Self { rules, stats }
    }

    /// Load every pack in `dir` once. Missing directory yields an empty DB
    /// (built-ins stay authoritative). Malformed files are counted in stats
    /// and skipped — one bad pack never aborts a scan.
    pub fn load_from_dir(dir: &Path) -> Self {
        match load_dir_strict(dir) {
            Ok((packs, stats)) => {
                let mut db = Self::from_packs(packs);
                db.stats.files_rejected = stats.files_rejected;
                db.stats.rejected_files = stats.rejected_files;
                db
            }
            Err(_) => Self::empty(),
        }
    }

    /// Match one protocol-gated observation against every rule, returning at
    /// most [`MAX_CANDIDATES_PER_OBSERVATION`] candidates in deterministic
    /// rule-id order. Empty input matches nothing. Only the first
    /// [`MAX_MATCH_BYTES`] of the observation are scanned (bounded).
    pub fn candidates_for(&self, protocol: &str, observation: &str) -> Vec<FingerprintCandidate> {
        if observation.is_empty() {
            return Vec::new();
        }
        let mut bounded_end = observation.len().min(MAX_MATCH_BYTES);
        while bounded_end > 0 && !observation.is_char_boundary(bounded_end) {
            bounded_end -= 1;
        }
        let bounded = &observation[..bounded_end];
        let mut out = Vec::new();
        for rule in &self.rules {
            if out.len() >= MAX_CANDIDATES_PER_OBSERVATION {
                break;
            }
            // Mandatory protocol gating: an SSH rule never fires on HTTP
            // bytes even when the byte patterns overlap.
            if rule.protocol != protocol {
                continue;
            }
            if matcher_hits(&rule.matcher, bounded) {
                out.push(self.candidate_for(rule, bounded));
            }
        }
        out
    }

    /// Match an unclassified observation across all protocols. Each
    /// candidate carries its rule's protocol as a *suggestion* (never a
    /// classification); the merge layer caps confidence by matcher
    /// strength. Deterministic rule-id order, same bounds as
    /// [`candidates_for`](Self::candidates_for).
    pub fn candidates_for_unknown(&self, observation: &str) -> Vec<UnknownCandidate> {
        if observation.is_empty() {
            return Vec::new();
        }
        let mut bounded_end = observation.len().min(MAX_MATCH_BYTES);
        while bounded_end > 0 && !observation.is_char_boundary(bounded_end) {
            bounded_end -= 1;
        }
        let bounded = &observation[..bounded_end];
        let mut out = Vec::new();
        for rule in &self.rules {
            if out.len() >= MAX_CANDIDATES_PER_OBSERVATION {
                break;
            }
            if matcher_hits(&rule.matcher, bounded) {
                out.push(UnknownCandidate {
                    candidate: self.candidate_for(rule, bounded),
                    suggested_protocol: rule.protocol.clone(),
                });
            }
        }
        out
    }

    fn candidate_for(&self, rule: &CompiledRule, bounded: &str) -> FingerprintCandidate {
        let version = rule
            .version_extractor
            .as_ref()
            .and_then(|extractor| extractor.extract(bounded));
        FingerprintCandidate {
            product: rule.product.clone(),
            vendor: rule.vendor.clone(),
            version,
            version_confidence: Some(rule.confidence),
            confidence: rule.confidence,
            rule_id: rule.id.clone(),
            rule_source: format!("{}#{}", rule.pack_path, rule.id),
            matcher: rule.matcher.kind.clone(),
            evidence: crate::service::truncate_bounded(bounded, 160).0,
        }
    }
}

/// An external candidate for an unclassified observation, with the rule's
/// protocol as an explicit suggestion (not a classification).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownCandidate {
    #[serde(flatten)]
    pub candidate: FingerprintCandidate,
    pub suggested_protocol: String,
}

fn load_dir_strict(
    dir: &Path,
) -> Result<(Vec<(String, FingerprintPack)>, FingerprintLoadStats), FingerprintError> {
    let mut stats = FingerprintLoadStats::default();
    let mut packs = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((packs, stats));
        }
        Err(source) => {
            return Err(FingerprintError::Read {
                path: dir.display().to_string(),
                source,
            });
        }
    };
    let mut files: Vec<_> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| FingerprintError::Read {
            path: dir.display().to_string(),
            source,
        })?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            files.push(path);
        }
    }
    files.sort();
    for path in files {
        let label = path.display().to_string();
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(_) => {
                stats.files_rejected += 1;
                stats.rejected_files.push(label);
                continue;
            }
        };
        let pack: FingerprintPack = match serde_json::from_str(&contents) {
            Ok(pack) => pack,
            Err(_) => {
                stats.files_rejected += 1;
                stats.rejected_files.push(label);
                continue;
            }
        };
        if pack.validate(&label).is_err() {
            stats.files_rejected += 1;
            stats.rejected_files.push(label);
            continue;
        }
        stats.packs_loaded += 1;
        stats.rules_accepted += pack.fingerprints.len();
        packs.push((label, pack));
    }
    Ok((packs, stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &str = r#"{
        "schema_version": 1,
        "fingerprints": [
            {"id": "http-nginx", "protocol": "http", "probe": "http",
             "matcher": {"kind": "contains", "pattern": "nginx", "case_insensitive": true},
             "product": "nginx", "vendor": "f5", "confidence": 85, "source": "seed-v1"},
            {"id": "ssh-openssh", "protocol": "ssh", "probe": "ssh",
             "matcher": {"kind": "prefix", "pattern": "SSH-2.0-OpenSSH", "case_insensitive": false},
             "product": "OpenSSH", "vendor": "openbsd", "confidence": 90, "source": "seed-v1"}
        ]
    }"#;

    #[test]
    fn valid_pack_matches_deterministically() {
        let pack = parse_pack(SEED, "test").unwrap();
        let matched = pack
            .match_observation("http", "Server: nginx/1.24.0")
            .unwrap();
        assert_eq!(matched.product, "nginx");
        assert_eq!(matched.rule_id, "http-nginx");
        // Protocol gate: ssh rule never fires on http observations.
        assert!(
            pack.match_observation("http", "SSH-2.0-OpenSSH_9.3")
                .is_some()
                || pack
                    .match_observation("ssh", "SSH-2.0-OpenSSH_9.3")
                    .is_some()
        );
        assert!(pack.match_observation("http", "").is_none());
    }

    #[test]
    fn version_extractors_capture_bounded_versions() {
        let after = VersionExtractor::AfterDelimiter {
            delimiter: "OpenSSH_".to_owned(),
            max_len: 32,
        };
        assert_eq!(
            after.extract("SSH-2.0-OpenSSH_9.7p1"),
            Some("9.7p1".to_owned())
        );
        // Missing delimiter → None, never a guess.
        assert_eq!(after.extract("SSH-2.0-dropbear"), None);
        // Overlong capture truncated to max_len on safe boundaries.
        let long = format!("SSH-2.0-OpenSSH_{}", "1".repeat(100));
        let capped = after.extract(&long).unwrap();
        assert!(capped.len() <= 32);

        let prefixed = VersionExtractor::PrefixedToken {
            prefix: "nginx/".to_owned(),
            max_len: 32,
        };
        assert_eq!(
            prefixed.extract("Server: nginx/1.24.0 (Ubuntu)"),
            Some("1.24.0".to_owned())
        );
        assert_eq!(prefixed.extract("Server: apache"), None);

        let keyed = VersionExtractor::KeyValue {
            key: "version".to_owned(),
        };
        assert_eq!(
            keyed.extract("server myd/2; version=3.1"),
            Some("3.1".to_owned())
        );
        assert_eq!(
            keyed.extract("server myd/2; version: 3.1"),
            Some("3.1".to_owned())
        );
        // No partial-identifier matches.
        assert_eq!(keyed.extract("myversion=9.9"), None);

        let positioned = VersionExtractor::TokenPosition { index: 1 };
        assert_eq!(
            positioned.extract("FixtureFTP 1.0 ready"),
            Some("1.0".to_owned())
        );
        assert_eq!(positioned.extract("lonely"), None);

        let semver = VersionExtractor::SemVerToken {};
        assert_eq!(
            semver.extract("mysql 8.0.36-11 community"),
            Some("8.0.36-11".to_owned())
        );
        assert_eq!(semver.extract("no digits here"), None);
    }

    #[test]
    fn version_sanitizer_rejects_unsafe_captures() {
        let after = VersionExtractor::AfterDelimiter {
            delimiter: "X-".to_owned(),
            max_len: 32,
        };
        // Shell metacharacters rejected.
        assert_eq!(after.extract("X-1.2; rm -rf"), None);
        // Non-versions (no digit) rejected.
        assert_eq!(after.extract("X-stable"), None);
        // Unicode rejected.
        assert_eq!(after.extract("X-1.2é"), None);
        // Empty capture rejected.
        assert_eq!(after.extract("X- "), None);
        // Whitespace terminates the capture.
        assert_eq!(after.extract("X-1.2 extra"), Some("1.2".to_owned()));
    }

    #[test]
    fn version_sanitizer_dequotes_evidence_text() {
        let keyed = VersionExtractor::KeyValue {
            key: "version".to_owned(),
        };
        // Evidence formatters quote values; quotes are wrapping, not content.
        assert_eq!(
            keyed.extract(r#"Server "MyServer version=2.0""#),
            Some("2.0".to_owned())
        );
        assert_eq!(keyed.extract("version='3.1'"), Some("3.1".to_owned()));
    }

    #[test]
    fn extractor_validation_rejects_malformed_rules() {
        let bad = |extractor: VersionExtractor| {
            parse_pack(
                &serde_json::json!({
                    "schema_version": 1,
                    "fingerprints": [{
                        "id": "v",
                        "protocol": "http",
                        "probe": "http",
                        "matcher": {"kind": "contains", "pattern": "x"},
                        "product": "x",
                        "confidence": 80,
                        "source": "t",
                        "version_extractor": extractor,
                    }],
                })
                .to_string(),
                "t",
            )
        };
        assert!(
            bad(VersionExtractor::AfterDelimiter {
                delimiter: String::new(),
                max_len: 32,
            })
            .is_err()
        );
        assert!(
            bad(VersionExtractor::AfterDelimiter {
                delimiter: "x".to_owned(),
                max_len: 0,
            })
            .is_err()
        );
        assert!(
            bad(VersionExtractor::AfterDelimiter {
                delimiter: "x".to_owned(),
                max_len: 9999,
            })
            .is_err()
        );
        assert!(bad(VersionExtractor::TokenPosition { index: 99 }).is_err());
        assert!(bad(VersionExtractor::KeyValue { key: String::new() }).is_err());
        assert!(
            bad(VersionExtractor::PrefixedToken {
                prefix: String::new(),
                max_len: 8,
            })
            .is_err()
        );
        // Unknown extractor type rejected by serde.
        assert!(
            parse_pack(
                r#"{"schema_version": 1, "fingerprints": [
                {"id": "v", "protocol": "http", "probe": "http",
                 "matcher": {"kind": "contains", "pattern": "x"},
                 "product": "x", "confidence": 80, "source": "t",
                 "version_extractor": {"type": "regex", "pattern": ".*"}}]}"#,
                "t",
            )
            .is_err()
        );
        // Product-only rules (no extractor) keep loading.
        assert!(
            parse_pack(
                r#"{"schema_version": 1, "fingerprints": [
                {"id": "v", "protocol": "http", "probe": "http",
                 "matcher": {"kind": "contains", "pattern": "x"},
                 "product": "x", "confidence": 80, "source": "t"}]}"#,
                "t",
            )
            .is_ok()
        );
    }

    #[test]
    fn candidates_carry_extracted_versions() {
        let db = FingerprintDb::from_packs(vec![(
            "v.json".to_owned(),
            parse_pack(
                r#"{"schema_version": 1, "fingerprints": [
                {"id": "ssh-versioned", "protocol": "ssh", "probe": "ssh",
                 "matcher": {"kind": "prefix", "pattern": "SSH-2.0-OpenSSH", "case_insensitive": false},
                 "product": "OpenSSH", "vendor": "openbsd", "confidence": 90, "source": "t",
                 "version_extractor": {"type": "after_delimiter", "delimiter": "OpenSSH_", "max_len": 32}}]}"#,
                "t",
            )
            .unwrap(),
        )]);
        let hits = db.candidates_for("ssh", "SSH-2.0-OpenSSH_9.7p1");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].version.as_deref(), Some("9.7p1"));
        assert_eq!(hits[0].version_confidence, Some(90));
        // Failed extraction keeps the product match, drops the version.
        let misses = db.candidates_for("ssh", "SSH-2.0-OpenSSH_");
        assert_eq!(misses.len(), 1);
        assert_eq!(misses[0].version, None);
    }

    #[test]
    fn malformed_packs_fail_safely() {
        // Bad schema version.
        assert!(parse_pack(r#"{"schema_version": 99, "fingerprints": []}"#, "t").is_err());
        // Confidence 100 rejected (evidence cap 95).
        assert!(
            parse_pack(
                r#"{"schema_version": 1, "fingerprints": [
                {"id": "x", "protocol": "http", "probe": "http",
                 "matcher": {"kind": "contains", "pattern": "x"},
                 "product": "x", "confidence": 100, "source": "t"}]}"#,
                "t"
            )
            .is_err()
        );
        // Duplicate ids rejected.
        assert!(
            parse_pack(
                r#"{"schema_version": 1, "fingerprints": [
                {"id": "dup", "protocol": "http", "probe": "http",
                 "matcher": {"kind": "contains", "pattern": "a"},
                 "product": "a", "confidence": 80, "source": "t"},
                {"id": "dup", "protocol": "http", "probe": "http",
                 "matcher": {"kind": "contains", "pattern": "b"},
                 "product": "b", "confidence": 80, "source": "t"}]}"#,
                "t"
            )
            .is_err()
        );
        // Empty pattern rejected.
        assert!(
            parse_pack(
                r#"{"schema_version": 1, "fingerprints": [
                {"id": "e", "protocol": "http", "probe": "http",
                 "matcher": {"kind": "contains", "pattern": ""},
                 "product": "e", "confidence": 80, "source": "t"}]}"#,
                "t"
            )
            .is_err()
        );
        // Garbage JSON never panics.
        assert!(parse_pack("{{{not json", "t").is_err());
    }
}
