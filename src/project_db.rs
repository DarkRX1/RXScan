//! Persistent project graph (SQLite backend).
//!
//! Per-scan correlation (`graph.rs`) is in-memory and bounded; this module
//! persists normalized entities, observations, relationships, evidence,
//! clusters, classifier provenance, and coverage across scans so RXScan can
//! answer "what changed since the last observation?" without rescanning.
//!
//! Design notes:
//! - SQLite via `rusqlite` (bundled): embedded, transactional, indexed,
//!   portable. JSONL streaming stays available; one-shot scans never
//!   require a database.
//! - Schema versioning from the start: `meta.schema_version` gates open;
//!   `MIGRATIONS` applies pending upgrades inside one transaction; files
//!   newer than this build are refused, never silently rewritten.
//! - Transaction safety: each scan import commits atomically. A killed
//!   scan leaves either the previous consistent state or a run explicitly
//!   marked `interrupted` — never a half-imported run marked complete.
//! - Untrusted input: reopened databases are validated (id lengths, kind
//!   allowlists, confidence bounds, JSON size caps). Invalid rows error,
//!   never panic, never touch the filesystem or network.
//! - Retention modes bound stored evidence: Minimal (facts only), Standard
//!   (2 KiB excerpts), Full (8 KiB excerpts). Network bodies are never
//!   stored wholesale.

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use thiserror::Error;

use crate::graph::{EdgeRelation, EntityKind, ScanGraph};

/// Current on-disk schema version. Bump with a matching `MIGRATIONS` entry.
pub const PROJECT_DB_SCHEMA_VERSION: u32 = 4;
/// Scanner version stamped on every imported run (classifier provenance).
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum entity id length (DoS bound on untrusted DB content).
pub const MAX_ENTITY_ID_LEN: usize = 512;
/// Maximum single JSON blob stored (details/attrs/coverage).
pub const MAX_STORED_JSON_BYTES: usize = 65_536;

#[derive(Debug, Error)]
pub enum ProjectDbError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error(
        "unsupported project database schema version {found} (this build supports up to {supported})"
    )]
    UnsupportedVersion { found: u32, supported: u32 },
    #[error("invalid project input: {0}")]
    InvalidInput(String),
    #[error("project database I/O: {0}")]
    Io(String),
}

/// Evidence retention mode for persisted evidence details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionMode {
    /// Normalized facts + hashes only; no excerpts.
    Minimal,
    /// Bounded 2 KiB excerpts (default).
    #[default]
    Standard,
    /// Bounded 8 KiB excerpts within the configured cap.
    Full,
}

impl RetentionMode {
    fn details_cap(self) -> usize {
        match self {
            Self::Minimal => 0,
            Self::Standard => 2048,
            Self::Full => 8192,
        }
    }
}

/// Per-scan coverage snapshot: what was actually assessed. The diff engine
/// consults it so missing evidence never becomes negative evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageSnapshot {
    #[serde(default)]
    pub hosts_attempted: Vec<String>,
    /// Transport-partitioned attempted port intervals per host IP.
    #[serde(default)]
    pub tcp_attempted: BTreeMap<String, Vec<(u16, u16)>>,
    #[serde(default)]
    pub udp_attempted: BTreeMap<String, Vec<(u16, u16)>>,
    /// Hostnames with a completed DNS observation.
    #[serde(default)]
    pub dns_queried: Vec<String>,
    /// Task kinds with at least one succeeded task.
    #[serde(default)]
    pub modules_completed: Vec<String>,
    /// True when the scan ended truncated (deadline/budget/interrupted).
    #[serde(default)]
    pub truncated: bool,
}

/// Minimal task-coverage input for [`coverage_from_tasks`]. Callers resolve
/// level-derived selections (e.g. `common`) to explicit intervals first.
#[derive(Debug, Clone)]
pub struct TaskCoverageInput {
    pub kind: String,
    pub host: Option<String>,
    pub ports_spec: Option<String>,
    pub transport: Option<String>,
    pub hostname: Option<String>,
    pub succeeded: bool,
}

/// Parse a port spec (`"all"`, `"80"`, `"1-100,200-300"`) into merged
/// closed intervals. Unparseable tokens are skipped (fail closed: unknown
/// coverage, never false coverage).
pub fn coverage_ports_to_intervals(spec: &str) -> Vec<(u16, u16)> {
    let spec = spec.trim();
    if spec.eq_ignore_ascii_case("all") {
        return vec![(1, 65_535)];
    }
    let mut intervals = Vec::new();
    for part in spec.split(',') {
        let part = part.trim().trim_start_matches("explicit:");
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(start), Ok(end)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                if start > 0 && start <= end {
                    insert_interval(&mut intervals, start, end);
                }
            }
        } else if let Ok(port) = part.parse::<u16>() {
            if port > 0 {
                insert_interval(&mut intervals, port, port);
            }
        }
    }
    intervals
}

fn insert_interval(intervals: &mut Vec<(u16, u16)>, start: u16, end: u16) {
    intervals.push((start, end));
    intervals.sort();
    let mut merged: Vec<(u16, u16)> = Vec::with_capacity(intervals.len());
    for (lo, hi) in intervals.drain(..) {
        if let Some(last) = merged.last_mut() {
            if lo <= last.1.saturating_add(1) {
                last.1 = last.1.max(hi);
                continue;
            }
        }
        merged.push((lo, hi));
    }
    *intervals = merged;
}

/// Build a coverage snapshot from completed-task summaries. Only succeeded
/// tasks count (attempted work that never completed covers nothing).
/// Deterministic: hosts/names sorted and deduped.
pub fn coverage_from_tasks(tasks: &[TaskCoverageInput], truncated: bool) -> CoverageSnapshot {
    let mut snapshot = CoverageSnapshot {
        truncated,
        ..CoverageSnapshot::default()
    };
    let mut modules = BTreeSet::new();
    for task in tasks {
        if !task.succeeded {
            continue;
        }
        modules.insert(task.kind.clone());
        match task.kind.as_str() {
            kind if kind == "PortDiscovery" || kind == "UdpDiscovery" => {
                let (Some(host), Some(spec)) = (task.host.clone(), task.ports_spec.clone()) else {
                    continue;
                };
                let transport = task.transport.clone().unwrap_or_else(|| "tcp".to_owned());
                let map = if transport.eq_ignore_ascii_case("udp") {
                    &mut snapshot.udp_attempted
                } else {
                    &mut snapshot.tcp_attempted
                };
                let entry = map.entry(host).or_default();
                for (lo, hi) in coverage_ports_to_intervals(&spec) {
                    insert_interval(entry, lo, hi);
                }
            }
            "HostDiscovery" => {
                if let Some(host) = task.host.clone() {
                    if !snapshot.hosts_attempted.contains(&host) {
                        snapshot.hosts_attempted.push(host);
                    }
                }
            }
            "DnsProbe" => {
                if let Some(name) = task.hostname.clone() {
                    let normalized = name.trim().trim_end_matches('.').to_ascii_lowercase();
                    if !normalized.is_empty() && !snapshot.dns_queried.contains(&normalized) {
                        snapshot.dns_queried.push(normalized);
                    }
                }
            }
            _ => {}
        }
    }
    snapshot.hosts_attempted.sort();
    snapshot.dns_queried.sort();
    let mut modules: Vec<String> = modules.into_iter().collect();
    modules.sort();
    snapshot.modules_completed = modules;
    snapshot
}

impl CoverageSnapshot {
    pub fn host_covered(&self, ip: &str) -> bool {
        let ip = ip.trim().to_ascii_lowercase();
        self.hosts_attempted
            .iter()
            .any(|candidate| candidate.trim().to_ascii_lowercase() == ip)
    }

    pub fn port_covered(&self, transport: &str, ip: &str, port: u16) -> bool {
        let map = if transport.eq_ignore_ascii_case("udp") {
            &self.udp_attempted
        } else {
            &self.tcp_attempted
        };
        let ip = ip.trim().to_ascii_lowercase();
        map.iter()
            .find(|(candidate, _)| candidate.trim().to_ascii_lowercase() == ip)
            .is_some_and(|(_, intervals)| {
                intervals.iter().any(|(lo, hi)| *lo <= port && port <= *hi)
            })
    }

    pub fn dns_covered(&self, hostname: &str) -> bool {
        let name = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        self.dns_queried
            .iter()
            .any(|candidate| candidate.trim().trim_end_matches('.').to_ascii_lowercase() == name)
    }
}

/// Classifier provenance persisted per scan: which intelligence classified
/// what. Distinguishes "observed service changed" from "rules changed".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifierProvenance {
    #[serde(default)]
    pub tool_version: String,
    #[serde(default)]
    pub packs: Vec<PackProvenance>,
    /// Distinct rule sources that fired this scan (bounded).
    #[serde(default)]
    pub rules_used: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackProvenance {
    pub path: String,
    pub schema_version: u32,
    pub rule_count: usize,
}

/// One scan import unit. Built by callers (see `run.rs` wiring) from the
/// correlation graph, scheduler report, plan, and fingerprint stats.
#[derive(Debug, Clone)]
pub struct ScanImport {
    pub scan_id: String,
    pub plan_id: String,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub scope_json: String,
    pub workflow: String,
    pub level: u8,
    pub termination: String,
    pub tasks_admitted: u64,
    pub tasks_completed: u64,
    pub coverage: CoverageSnapshot,
    pub classifier: ClassifierProvenance,
    pub retention: RetentionMode,
}

#[derive(Debug, Clone, Default)]
pub struct ImportStats {
    pub entities_upserted: usize,
    pub observations_added: usize,
    pub relationships_upserted: usize,
    pub evidence_stored: usize,
    pub clusters_stored: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityRow {
    pub entity_id: String,
    pub kind: String,
    pub label: String,
    pub attributes_json: String,
    pub first_seen_scan: String,
    pub last_seen_scan: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub observation_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationRow {
    pub id: i64,
    pub scan_run: String,
    pub entity_id: String,
    pub kind: String,
    pub label: String,
    pub attrs_json: String,
    pub confidence: u8,
    pub evidence_excerpt: String,
    pub module: String,
    pub task_id: String,
    pub timestamp_ms: u64,
}

/// Change categories: confirmed transitions vs newly-observed additions.
/// Absence without coverage never produces a removal record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    Appeared,
    Disappeared,
    Opened,
    Closed,
    Changed,
    Added,
    Removed,
    ConfidenceChanged,
}

impl ChangeType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Appeared => "appeared",
            Self::Disappeared => "disappeared",
            Self::Opened => "opened",
            Self::Closed => "closed",
            Self::Changed => "changed",
            Self::Added => "added",
            Self::Removed => "removed",
            Self::ConfidenceChanged => "confidence_changed",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "appeared" => Some(Self::Appeared),
            "disappeared" => Some(Self::Disappeared),
            "opened" => Some(Self::Opened),
            "closed" => Some(Self::Closed),
            "changed" => Some(Self::Changed),
            "added" => Some(Self::Added),
            "removed" => Some(Self::Removed),
            "confidence_changed" => Some(Self::ConfidenceChanged),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphChange {
    pub change_type: ChangeType,
    pub entity_id: String,
    #[serde(default)]
    pub old_value: String,
    #[serde(default)]
    pub new_value: String,
    pub confidence: u8,
    #[serde(default)]
    pub evidence: String,
}

/// Operational attention severity. Deterministic policy maps evidence to
/// these levels; no subsystem invents its own ratings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttentionSeverity {
    Info,
    Noteworthy,
    Warning,
}

impl AttentionSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Noteworthy => "noteworthy",
            Self::Warning => "warning",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "info" => Some(Self::Info),
            "noteworthy" => Some(Self::Noteworthy),
            "warning" => Some(Self::Warning),
            _ => None,
        }
    }
}

/// One operational attention item: deterministic category + severity with
/// the evidence behind it. Informational by default; nothing here is a
/// vulnerability verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttentionEvent {
    pub category: String,
    pub severity: AttentionSeverity,
    pub entity_id: String,
    pub title: String,
    pub reason: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    pub scan_run: String,
}

const SCHEMA_V1: &str = "
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scan_runs(
  scan_id TEXT PRIMARY KEY,
  plan_id TEXT NOT NULL,
  started_at_ms INTEGER NOT NULL,
  finished_at_ms INTEGER NOT NULL,
  scope_json TEXT NOT NULL,
  workflow TEXT NOT NULL,
  level INTEGER NOT NULL,
  tool_version TEXT NOT NULL,
  termination TEXT NOT NULL,
  tasks_admitted INTEGER NOT NULL DEFAULT 0,
  tasks_completed INTEGER NOT NULL DEFAULT 0,
  coverage_json TEXT NOT NULL,
  classifier_json TEXT NOT NULL,
  truncated INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS entities(
  entity_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  label TEXT NOT NULL,
  attributes_json TEXT NOT NULL DEFAULT '{}',
  first_seen_scan TEXT NOT NULL,
  last_seen_scan TEXT NOT NULL,
  first_seen_ms INTEGER NOT NULL DEFAULT 0,
  last_seen_ms INTEGER NOT NULL DEFAULT 0,
  observation_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS entities_kind ON entities(kind);
CREATE TABLE IF NOT EXISTS observations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_run TEXT NOT NULL REFERENCES scan_runs(scan_id),
  entity_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  label TEXT NOT NULL,
  attrs_json TEXT NOT NULL DEFAULT '{}',
  confidence INTEGER NOT NULL DEFAULT 0,
  evidence_excerpt TEXT NOT NULL DEFAULT '',
  module TEXT NOT NULL DEFAULT '',
  task_id TEXT NOT NULL DEFAULT '',
  timestamp_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS observations_entity ON observations(entity_id);
CREATE INDEX IF NOT EXISTS observations_scan ON observations(scan_run);
CREATE TABLE IF NOT EXISTS relationships(
  from_id TEXT NOT NULL,
  to_id TEXT NOT NULL,
  relation TEXT NOT NULL,
  confidence INTEGER NOT NULL DEFAULT 0,
  scan_run TEXT NOT NULL,
  module TEXT NOT NULL DEFAULT '',
  task_id TEXT NOT NULL DEFAULT '',
  evidence TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(from_id, to_id, relation)
);
CREATE INDEX IF NOT EXISTS relationships_to ON relationships(to_id);
CREATE TABLE IF NOT EXISTS edge_observations(
  scan_run TEXT NOT NULL,
  from_id TEXT NOT NULL,
  to_id TEXT NOT NULL,
  relation TEXT NOT NULL,
  PRIMARY KEY(scan_run, from_id, to_id, relation)
);
CREATE INDEX IF NOT EXISTS edge_observations_scan ON edge_observations(scan_run);
CREATE TABLE IF NOT EXISTS evidence_store(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_run TEXT NOT NULL,
  source TEXT NOT NULL,
  asset_id TEXT NOT NULL DEFAULT '',
  confidence INTEGER NOT NULL DEFAULT 0,
  details_json TEXT NOT NULL DEFAULT '{}',
  timestamp_ms INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS changes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_new TEXT NOT NULL,
  scan_old TEXT NOT NULL,
  change_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  old_value TEXT NOT NULL DEFAULT '',
  new_value TEXT NOT NULL DEFAULT '',
  confidence INTEGER NOT NULL DEFAULT 0,
  evidence TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS changes_scan ON changes(scan_new);
CREATE TABLE IF NOT EXISTS clusters(
  scan_run TEXT NOT NULL,
  members_json TEXT NOT NULL,
  verdict TEXT NOT NULL,
  confidence INTEGER NOT NULL DEFAULT 0,
  reasons_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS classifier_provenance(
  scan_run TEXT PRIMARY KEY,
  tool_version TEXT NOT NULL,
  packs_json TEXT NOT NULL,
  rules_used_json TEXT NOT NULL DEFAULT '[]'
);
";

/// Ordered schema migrations; index+1 is the resulting version.
const MIGRATIONS: &[&str] = &[SCHEMA_V1, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4];

/// V4: Ultimate OSINT expansion (additive only). New tables for timestamped
/// routing observations, identity hypotheses (supporting/contradicting
/// evidence), and historical archive snapshots. Existing tables untouched;
/// v1-v3 databases migrate forward and remain readable.
const SCHEMA_V4: &str = "
CREATE TABLE IF NOT EXISTS route_observations(
  scan_run TEXT NOT NULL,
  prefix TEXT NOT NULL,
  asn TEXT NOT NULL,
  rpki TEXT NOT NULL DEFAULT 'not_checked',
  observed_at TEXT NOT NULL DEFAULT '',
  retrieved_at_ms INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(scan_run, prefix, asn)
);
CREATE INDEX IF NOT EXISTS route_prefix ON route_observations(prefix);
CREATE INDEX IF NOT EXISTS route_asn ON route_observations(asn);
CREATE TABLE IF NOT EXISTS hypotheses(
  scan_run TEXT NOT NULL,
  hypothesis_id TEXT NOT NULL,
  subjects_json TEXT NOT NULL DEFAULT '[]',
  claim TEXT NOT NULL DEFAULT '',
  assessment TEXT NOT NULL DEFAULT 'UNKNOWN',
  supports_json TEXT NOT NULL DEFAULT '[]',
  contradicts_json TEXT NOT NULL DEFAULT '[]',
  explanation TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(scan_run, hypothesis_id)
);
CREATE INDEX IF NOT EXISTS hypo_scan ON hypotheses(scan_run);
CREATE TABLE IF NOT EXISTS archive_snapshots(
  scan_run TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  url TEXT NOT NULL,
  timestamp TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL DEFAULT '',
  last_seen TEXT NOT NULL DEFAULT '',
  historical INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(scan_run, snapshot_id)
);
CREATE INDEX IF NOT EXISTS archive_url ON archive_snapshots(url);
";

const SCHEMA_V3: &str = "
ALTER TABLE vulnerability_candidates ADD COLUMN dataset_version TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS vuln_advisory ON vulnerability_candidates(advisory_id);
";

const SCHEMA_V2: &str = "
CREATE TABLE IF NOT EXISTS os_candidates(
  scan_run TEXT NOT NULL,
  host TEXT NOT NULL,
  family TEXT NOT NULL,
  generation TEXT NOT NULL DEFAULT '',
  variant TEXT NOT NULL DEFAULT '',
  confidence INTEGER NOT NULL DEFAULT 0,
  supporting_json TEXT NOT NULL DEFAULT '[]',
  rule_ids_json TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY(scan_run, host, family)
);
CREATE TABLE IF NOT EXISTS device_candidates(
  scan_run TEXT NOT NULL,
  host TEXT NOT NULL,
  role TEXT NOT NULL,
  vendor TEXT NOT NULL DEFAULT '',
  model TEXT NOT NULL DEFAULT '',
  role_confidence INTEGER NOT NULL DEFAULT 0,
  vendor_confidence INTEGER NOT NULL DEFAULT 0,
  model_confidence INTEGER NOT NULL DEFAULT 0,
  evidence_json TEXT NOT NULL DEFAULT '[]',
  rule_ids_json TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY(scan_run, host, role)
);
CREATE TABLE IF NOT EXISTS software_identities(
  scan_run TEXT NOT NULL,
  product TEXT NOT NULL,
  vendor TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '',
  family TEXT NOT NULL DEFAULT '',
  cpe TEXT NOT NULL DEFAULT '',
  confidence INTEGER NOT NULL DEFAULT 0,
  version_confidence INTEGER NOT NULL DEFAULT 0,
  hosts_json TEXT NOT NULL DEFAULT '[]',
  endpoints_json TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY(scan_run, product, vendor, version)
);
CREATE INDEX IF NOT EXISTS software_product ON software_identities(product);
CREATE TABLE IF NOT EXISTS vulnerability_candidates(
  scan_run TEXT NOT NULL,
  advisory_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  product TEXT NOT NULL,
  matched_version TEXT NOT NULL DEFAULT '',
  match_type TEXT NOT NULL,
  outcome TEXT NOT NULL,
  confidence INTEGER NOT NULL DEFAULT 0,
  severity TEXT NOT NULL DEFAULT '',
  host TEXT NOT NULL DEFAULT '',
  endpoint TEXT NOT NULL DEFAULT '',
  identity_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY(scan_run, advisory_id, product, matched_version)
);
CREATE INDEX IF NOT EXISTS vuln_scan ON vulnerability_candidates(scan_run);
CREATE TABLE IF NOT EXISTS attention_events(
  scan_run TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  title TEXT NOT NULL,
  reason TEXT NOT NULL,
  evidence_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS attention_scan ON attention_events(scan_run);
";

fn validate_id(id: &str, what: &str) -> Result<(), ProjectDbError> {
    if id.is_empty() || id.len() > MAX_ENTITY_ID_LEN || id.bytes().any(|b| b == 0) {
        return Err(ProjectDbError::InvalidInput(format!(
            "{what} id invalid (empty, NUL, or longer than {MAX_ENTITY_ID_LEN})"
        )));
    }
    Ok(())
}

fn validate_confidence(value: u8, what: &str) -> Result<(), ProjectDbError> {
    if value > 100 {
        return Err(ProjectDbError::InvalidInput(format!(
            "{what} confidence {value} exceeds 100"
        )));
    }
    Ok(())
}

fn check_json_size(value: &str, what: &str) -> Result<(), ProjectDbError> {
    if value.len() > MAX_STORED_JSON_BYTES {
        return Err(ProjectDbError::InvalidInput(format!(
            "{what} JSON exceeds {MAX_STORED_JSON_BYTES} bytes"
        )));
    }
    Ok(())
}

pub struct ProjectDb {
    conn: Connection,
}

impl ProjectDb {
    fn init(conn: &Connection) -> Result<(), ProjectDbError> {
        // Fresh files have no meta table yet: any read failure here means
        // version 0 (migrations create everything). Genuine corruption
        // surfaces when the migration batch executes.
        let current: u32 = conn
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |row| {
                    let text: String = row.get(0)?;
                    text.parse::<u32>().map_err(|_| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            "invalid schema_version".into(),
                        )
                    })
                },
            )
            .unwrap_or(0);
        if current > PROJECT_DB_SCHEMA_VERSION {
            return Err(ProjectDbError::UnsupportedVersion {
                found: current,
                supported: PROJECT_DB_SCHEMA_VERSION,
            });
        }
        // Migrations apply atomically: a killed migration rolls back,
        // leaving the previous consistent version behind.
        let tx = conn.unchecked_transaction()?;
        let mut version = current;
        while (version as usize) < MIGRATIONS.len() {
            tx.execute_batch(MIGRATIONS[version as usize])?;
            version += 1;
            tx.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?1)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![version.to_string()],
            )?;
        }
        tx.execute(
            "INSERT INTO meta(key, value) VALUES('created_tool_version', ?1)
             ON CONFLICT(key) DO NOTHING",
            params![TOOL_VERSION],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Open (creating) a project database file. Refuses files newer than
    /// this build; migrates older files forward transactionally.
    pub fn open(path: &Path) -> Result<Self, ProjectDbError> {
        let conn = Connection::open(path)
            .map_err(|error| ProjectDbError::Io(format!("{}: {error}", path.display())))?;
        Self::init(&conn)?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self, ProjectDbError> {
        let conn = Connection::open_in_memory()?;
        Self::init(&conn)?;
        Ok(Self { conn })
    }
    pub fn schema_version(&self) -> Result<u32, ProjectDbError> {
        let text: String = self.conn.query_row(
            "SELECT value FROM meta WHERE key='schema_version'",
            [],
            |row| row.get(0),
        )?;
        text.parse::<u32>()
            .map_err(|_| ProjectDbError::InvalidInput("bad schema_version".to_owned()))
    }

    /// Test support: execute raw SQL (migration/corruption fixtures).
    /// Never used by scanner paths.
    pub fn conn_execute_for_test(&self, sql: &str) -> Result<(), ProjectDbError> {
        self.conn.execute_batch(sql)?;
        Ok(())
    }

    /// Test support: read one text column from raw SQL.
    /// Never used by scanner paths.
    pub fn conn_query_for_test(&self, sql: &str) -> Vec<String> {
        let mut stmt = match self.conn.prepare(sql) {
            Ok(stmt) => stmt,
            Err(_) => return Vec::new(),
        };
        let rows = match stmt.query_map([], |row| row.get::<_, String>(0)) {
            Ok(rows) => rows,
            Err(_) => return Vec::new(),
        };
        rows.filter_map(Result::ok).collect()
    }

    /// Import one scan atomically: graph entities/edges, service detail
    /// observations, evidence excerpts per retention, clusters, coverage,
    /// and classifier provenance commit together or not at all.
    pub fn import_scan(
        &mut self,
        import: &ScanImport,
        graph: &ScanGraph,
    ) -> Result<ImportStats, ProjectDbError> {
        validate_id(&import.scan_id, "scan")?;
        check_json_size(&import.scope_json, "scope")?;
        let coverage_json = serde_json::to_string(&import.coverage)
            .map_err(|error| ProjectDbError::InvalidInput(error.to_string()))?;
        check_json_size(&coverage_json, "coverage")?;
        let classifier_json = serde_json::to_string(&import.classifier)
            .map_err(|error| ProjectDbError::InvalidInput(error.to_string()))?;
        check_json_size(&classifier_json, "classifier")?;

        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO scan_runs(scan_id, plan_id, started_at_ms, finished_at_ms,
              scope_json, workflow, level, tool_version, termination,
              tasks_admitted, tasks_completed, coverage_json, classifier_json, truncated)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)
             ON CONFLICT(scan_id) DO UPDATE SET
               finished_at_ms=excluded.finished_at_ms,
               termination=excluded.termination,
               tasks_admitted=excluded.tasks_admitted,
               tasks_completed=excluded.tasks_completed,
               coverage_json=excluded.coverage_json,
               classifier_json=excluded.classifier_json,
               truncated=excluded.truncated",
            params![
                import.scan_id,
                import.plan_id,
                import.started_at_ms as i64,
                import.finished_at_ms as i64,
                import.scope_json,
                import.workflow,
                import.level,
                TOOL_VERSION,
                import.termination,
                import.tasks_admitted as i64,
                import.tasks_completed as i64,
                coverage_json,
                classifier_json,
                i64::from(import.coverage.truncated),
            ],
        )?;
        let mut stats = ImportStats::default();
        let now_ms = import.finished_at_ms;
        // Entities + one observation row each (temporal history preserved;
        // historical rows are never mutated).
        for entity in graph.entities.values() {
            validate_id(&entity.id, "entity")?;
            let kind = entity.kind.to_string();
            EntityKind::parse(&kind).ok_or_else(|| {
                ProjectDbError::InvalidInput(format!("unknown entity kind {kind}"))
            })?;
            if entity.label.len() > MAX_ENTITY_ID_LEN {
                return Err(ProjectDbError::InvalidInput(
                    "entity label too long".to_owned(),
                ));
            }
            let attrs = serde_json::to_string(&entity.attributes)
                .map_err(|error| ProjectDbError::InvalidInput(error.to_string()))?;
            check_json_size(&attrs, "entity attributes")?;
            let affected = tx.execute(
                "INSERT INTO entities(entity_id, kind, label, attributes_json,
                  first_seen_scan, last_seen_scan, first_seen_ms, last_seen_ms, observation_count)
                 VALUES(?1,?2,?3,?4,?5,?5,?6,?6,1)
                 ON CONFLICT(entity_id) DO UPDATE SET
                   last_seen_scan=excluded.last_seen_scan,
                   last_seen_ms=excluded.last_seen_ms,
                   label=excluded.label,
                   attributes_json=excluded.attributes_json,
                   observation_count=observation_count+1",
                params![
                    entity.id,
                    kind,
                    entity.label,
                    attrs,
                    import.scan_id,
                    now_ms as i64,
                ],
            )?;
            if affected > 0 {
                stats.entities_upserted += 1;
            }
            tx.execute(
                "INSERT INTO observations(scan_run, entity_id, kind, label, attrs_json,
                  confidence, evidence_excerpt, module, task_id, timestamp_ms)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    import.scan_id,
                    entity.id,
                    kind,
                    entity.label,
                    attrs,
                    0u8,
                    "",
                    entity.provenance.module,
                    entity.provenance.task_id.clone().unwrap_or_default(),
                    entity.provenance.timestamp as i64,
                ],
            )?;
            stats.observations_added += 1;
        }
        // Relationships: latest-state upsert + per-scan edge observations
        // (rotation/removal diffing reads the per-scan table).
        for edge in &graph.edges {
            validate_id(&edge.from, "edge from")?;
            validate_id(&edge.to, "edge to")?;
            validate_confidence(edge.confidence, "edge")?;
            let relation = edge.relation.to_string();
            EdgeRelation::parse(&relation).ok_or_else(|| {
                ProjectDbError::InvalidInput(format!("unknown relation {relation}"))
            })?;
            let evidence = edge.evidence.join("; ");
            tx.execute(
                "INSERT INTO relationships(from_id, to_id, relation, confidence,
                  scan_run, module, task_id, evidence)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
                 ON CONFLICT(from_id, to_id, relation) DO UPDATE SET
                   confidence=excluded.confidence, scan_run=excluded.scan_run,
                   module=excluded.module, task_id=excluded.task_id,
                   evidence=excluded.evidence",
                params![
                    edge.from,
                    edge.to,
                    relation,
                    edge.confidence,
                    import.scan_id,
                    edge.provenance.module,
                    edge.provenance.task_id.clone().unwrap_or_default(),
                    truncate_str(&evidence, 1024),
                ],
            )?;
            tx.execute(
                "INSERT INTO edge_observations(scan_run, from_id, to_id, relation)
                 VALUES(?1,?2,?3,?4) ON CONFLICT DO NOTHING",
                params![import.scan_id, edge.from, edge.to, relation],
            )?;
            stats.relationships_upserted += 1;
        }
        // Reconciliation clusters for this scan.
        for cluster in crate::graph::reconcile_candidates(graph) {
            let members = serde_json::to_string(&cluster.members)
                .map_err(|error| ProjectDbError::InvalidInput(error.to_string()))?;
            let reasons = serde_json::to_string(&cluster.reasons)
                .map_err(|error| ProjectDbError::InvalidInput(error.to_string()))?;
            let verdict = match cluster.verdict {
                crate::graph::IdentityVerdict::SameIdentity => "same_identity",
                crate::graph::IdentityVerdict::Related => "related",
            };
            tx.execute(
                "INSERT INTO clusters(scan_run, members_json, verdict, confidence, reasons_json)
                 VALUES(?1,?2,?3,?4,?5)",
                params![
                    import.scan_id,
                    members,
                    verdict,
                    cluster.confidence,
                    reasons
                ],
            )?;
            stats.clusters_stored += 1;
        }
        // Classifier provenance: which intelligence classified what.
        let packs = serde_json::to_string(&import.classifier.packs)
            .map_err(|error| ProjectDbError::InvalidInput(error.to_string()))?;
        let rules = serde_json::to_string(&import.classifier.rules_used)
            .map_err(|error| ProjectDbError::InvalidInput(error.to_string()))?;
        tx.execute(
            "INSERT INTO classifier_provenance(scan_run, tool_version, packs_json, rules_used_json)
             VALUES(?1,?2,?3,?4)
             ON CONFLICT(scan_run) DO UPDATE SET
               tool_version=excluded.tool_version, packs_json=excluded.packs_json,
               rules_used_json=excluded.rules_used_json",
            params![import.scan_id, import.classifier.tool_version, packs, rules],
        )?;
        tx.commit()?;
        Ok(stats)
    }

    /// Store bounded evidence excerpts for a scan (retention-gated).
    /// Separate from `import_scan` so callers control volume explicitly.
    pub fn store_evidence(
        &mut self,
        scan_id: &str,
        items: &[(String, String, u8, serde_json::Value, u64)],
        retention: RetentionMode,
    ) -> Result<usize, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        let cap = retention.details_cap();
        let tx = self.conn.transaction()?;
        let mut stored = 0usize;
        for (source, asset_id, confidence, details, timestamp_ms) in items {
            validate_confidence(*confidence, "evidence")?;
            if asset_id.len() > MAX_ENTITY_ID_LEN || source.len() > 256 {
                return Err(ProjectDbError::InvalidInput(
                    "evidence field too long".to_owned(),
                ));
            }
            let mut text = serde_json::to_string(details)
                .map_err(|error| ProjectDbError::InvalidInput(error.to_string()))?;
            // Retention gating: Minimal keeps facts only; over-cap details
            // degrade to an explicit truncation marker (never silent loss,
            // never oversized storage).
            if retention == RetentionMode::Minimal || text.len() > cap.max(2) {
                text = r#"{"truncated":true}"#.to_owned();
            }
            check_json_size(&text, "evidence details")?;
            tx.execute(
                "INSERT INTO evidence_store(scan_run, source, asset_id, confidence, details_json, timestamp_ms)
                 VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    scan_id,
                    source,
                    asset_id,
                    confidence,
                    text,
                    *timestamp_ms as i64
                ],
            )?;
            stored += 1;
        }
        tx.commit()?;
        Ok(stored)
    }

    // ---------------- queries (indexed access paths) ----------------

    pub fn entities_by_kind(&self, kind: EntityKind) -> Result<Vec<EntityRow>, ProjectDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT entity_id, kind, label, attributes_json, first_seen_scan,
                    last_seen_scan, first_seen_ms, last_seen_ms, observation_count
             FROM entities WHERE kind=?1 ORDER BY entity_id",
        )?;
        let rows = stmt.query_map(params![kind.to_string()], row_to_entity)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectDbError::from)
    }

    pub fn edges_from(&self, entity_id: &str) -> Result<Vec<EdgeRow>, ProjectDbError> {
        validate_id(entity_id, "entity")?;
        let mut stmt = self.conn.prepare(
            "SELECT from_id, to_id, relation, confidence, scan_run, module, task_id, evidence
             FROM relationships WHERE from_id=?1 ORDER BY to_id, relation",
        )?;
        let rows = stmt.query_map(params![entity_id], row_to_edge)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectDbError::from)
    }

    pub fn edges_to(&self, entity_id: &str) -> Result<Vec<EdgeRow>, ProjectDbError> {
        validate_id(entity_id, "entity")?;
        let mut stmt = self.conn.prepare(
            "SELECT from_id, to_id, relation, confidence, scan_run, module, task_id, evidence
             FROM relationships WHERE to_id=?1 ORDER BY from_id, relation",
        )?;
        let rows = stmt.query_map(params![entity_id], row_to_edge)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectDbError::from)
    }

    /// Certificates presented by more than one port (reuse correlation).
    pub fn certificate_reuse(&self) -> Result<Vec<(String, Vec<String>)>, ProjectDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT to_id, from_id FROM relationships
             WHERE relation='presents_certificate' ORDER BY to_id, from_id",
        )?;
        let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (cert, presenter) = row?;
            grouped.entry(cert).or_default().push(presenter);
        }
        Ok(grouped
            .into_iter()
            .filter(|(_, presenters)| presenters.len() > 1)
            .collect())
    }

    /// Provenance chain for one entity: observations across scans.
    pub fn provenance_chain(&self, entity_id: &str) -> Result<Vec<ObservationRow>, ProjectDbError> {
        validate_id(entity_id, "entity")?;
        let mut stmt = self.conn.prepare(
            "SELECT id, scan_run, entity_id, kind, label, attrs_json, confidence,
                    evidence_excerpt, module, task_id, timestamp_ms
             FROM observations WHERE entity_id=?1 ORDER BY timestamp_ms, scan_run",
        )?;
        let rows = stmt.query_map(params![entity_id], row_to_observation)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectDbError::from)
    }

    pub fn scan_ids(&self) -> Result<Vec<String>, ProjectDbError> {
        let mut stmt = self
            .conn
            .prepare("SELECT scan_id FROM scan_runs ORDER BY finished_at_ms, scan_id")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectDbError::from)
    }

    pub fn scan_termination(&self, scan_id: &str) -> Result<String, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        self.conn
            .query_row(
                "SELECT termination FROM scan_runs WHERE scan_id=?1",
                params![scan_id],
                |row| row.get(0),
            )
            .map_err(ProjectDbError::from)
    }

    /// Web/API support: one entity row by id (`None` when absent).
    pub fn entity(&self, entity_id: &str) -> Result<Option<EntityRow>, ProjectDbError> {
        validate_id(entity_id, "entity")?;
        let mut stmt = self.conn.prepare(
            "SELECT entity_id, kind, label, attributes_json, first_seen_scan,
                    last_seen_scan, first_seen_ms, last_seen_ms, observation_count
             FROM entities WHERE entity_id=?1",
        )?;
        let mut rows = stmt.query_map(params![entity_id], row_to_entity)?;
        match rows.next() {
            None => Ok(None),
            Some(row) => row.map(Some).map_err(ProjectDbError::from),
        }
    }

    /// Web/API support: bounded entity page, newest observations first.
    /// `kind` filters by exact stored kind; `None` returns all kinds.
    pub fn entities_page(
        &self,
        kind: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<EntityRow>, ProjectDbError> {
        let limit = limit.min(500) as i64;
        let offset = offset.min(1_000_000) as i64;
        if let Some(kind) = kind {
            if kind.len() > 64 || kind.is_empty() {
                return Err(ProjectDbError::InvalidInput(
                    "invalid entity kind".to_owned(),
                ));
            }
            let mut stmt = self.conn.prepare(
                "SELECT entity_id, kind, label, attributes_json, first_seen_scan,
                        last_seen_scan, first_seen_ms, last_seen_ms, observation_count
                 FROM entities WHERE kind=?1 ORDER BY last_seen_ms DESC, entity_id
                 LIMIT ?2 OFFSET ?3",
            )?;
            let rows = stmt.query_map(params![kind, limit, offset], row_to_entity)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(ProjectDbError::from)
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT entity_id, kind, label, attributes_json, first_seen_scan,
                        last_seen_scan, first_seen_ms, last_seen_ms, observation_count
                 FROM entities ORDER BY last_seen_ms DESC, entity_id
                 LIMIT ?1 OFFSET ?2",
            )?;
            let rows = stmt.query_map(params![limit, offset], row_to_entity)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(ProjectDbError::from)
        }
    }

    /// Web/API support: bounded observation page (findings/timeline source),
    /// newest first.
    pub fn observations_page(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ObservationRow>, ProjectDbError> {
        let limit = limit.min(500) as i64;
        let offset = offset.min(1_000_000) as i64;
        let mut stmt = self.conn.prepare(
            "SELECT id, scan_run, entity_id, kind, label, attrs_json, confidence,
                    evidence_excerpt, module, task_id, timestamp_ms
             FROM observations ORDER BY timestamp_ms DESC, id DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit, offset], row_to_observation)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectDbError::from)
    }

    /// Web/API support: `(entities, observations, relationships, runs)`.
    pub fn counts(&self) -> Result<(u64, u64, u64, u64), ProjectDbError> {
        let count = |sql: &str| -> Result<u64, ProjectDbError> {
            let value: i64 = self.conn.query_row(sql, [], |row| row.get(0))?;
            Ok(u64::try_from(value).unwrap_or(0))
        };
        Ok((
            count("SELECT COUNT(*) FROM entities")?,
            count("SELECT COUNT(*) FROM observations")?,
            count("SELECT COUNT(*) FROM relationships")?,
            count("SELECT COUNT(*) FROM scan_runs")?,
        ))
    }

    pub fn coverage_of(&self, scan_id: &str) -> Result<CoverageSnapshot, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        let text: String = self.conn.query_row(
            "SELECT coverage_json FROM scan_runs WHERE scan_id=?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        serde_json::from_str(&text).map_err(|error| ProjectDbError::InvalidInput(error.to_string()))
    }

    pub fn changes_since(
        &self,
        scan_new: &str,
        limit: usize,
    ) -> Result<Vec<StoredChange>, ProjectDbError> {
        validate_id(scan_new, "scan")?;
        let mut stmt = self.conn.prepare(
            "SELECT scan_new, scan_old, change_type, entity_id, old_value, new_value,
                    confidence, evidence FROM changes
             WHERE scan_new=?1 ORDER BY id LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![scan_new, limit as i64], |row| {
            let confidence: i64 = row.get(6)?;
            let change_type: String = row.get(2)?;
            ChangeType::parse(&change_type).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    format!("unknown change type {change_type}").into(),
                )
            })?;
            Ok(StoredChange {
                scan_new: row.get(0)?,
                scan_old: row.get(1)?,
                change_type,
                entity_id: row.get(3)?,
                old_value: row.get(4)?,
                new_value: row.get(5)?,
                confidence: confidence.clamp(0, 100) as u8,
                evidence: row.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectDbError::from)
    }

    /// Persist computed changes for a scan pair (part of the diff commit).
    pub fn record_changes(
        &mut self,
        scan_new: &str,
        scan_old: &str,
        changes: &[GraphChange],
    ) -> Result<(), ProjectDbError> {
        validate_id(scan_new, "scan")?;
        validate_id(scan_old, "scan")?;
        let tx = self.conn.transaction()?;
        for change in changes {
            validate_id(&change.entity_id, "change entity")?;
            validate_confidence(change.confidence, "change")?;
            tx.execute(
                "INSERT INTO changes(scan_new, scan_old, change_type, entity_id,
                  old_value, new_value, confidence, evidence)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    scan_new,
                    scan_old,
                    change.change_type.as_str(),
                    change.entity_id,
                    truncate_str(&change.old_value, 1024),
                    truncate_str(&change.new_value, 1024),
                    change.confidence,
                    truncate_str(&change.evidence, 1024),
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    // ---------------- cross-scan diff ----------------
    //
    // Compares two scans with coverage gating: an entity observed before
    // but absent now becomes a removal-class change ONLY when the new scan
    // demonstrably covered it; otherwise no record is produced (unknown,
    // never a false removal). Additions are always recorded (new
    // information, graded by prior coverage).

    /// Deterministic diff between two imported scans. Pure reads; callers
    /// persist via [`record_changes`](Self::record_changes).
    pub fn diff_scan_runs(
        &self,
        scan_old: &str,
        scan_new: &str,
    ) -> Result<Vec<GraphChange>, ProjectDbError> {
        validate_id(scan_old, "scan")?;
        validate_id(scan_new, "scan")?;
        let old_cov = self.coverage_of(scan_old)?;
        let new_cov = self.coverage_of(scan_new)?;
        let old_obs = self.observations_by_entity(scan_old)?;
        let new_obs = self.observations_by_entity(scan_new)?;
        let old_edges = self.edge_set(scan_old)?;
        let new_edges = self.edge_set(scan_new)?;
        let mut changes = Vec::new();

        // Ports: opened / closed (coverage-gated both directions).
        let old_ports = port_states(&old_obs);
        let new_ports = port_states(&new_obs);
        for (entity_id, (transport, ip, port)) in &new_ports {
            if !old_ports.contains_key(entity_id) {
                let confidence = if port_covered_in_snapshot(&old_cov, transport, ip, *port) {
                    85
                } else {
                    65
                };
                let change_type = if port_covered_in_snapshot(&old_cov, transport, ip, *port) {
                    ChangeType::Opened
                } else {
                    ChangeType::Appeared
                };
                changes.push(GraphChange {
                    change_type,
                    entity_id: entity_id.clone(),
                    old_value: String::new(),
                    new_value: format!("{transport}/{port} open on {ip}"),
                    confidence,
                    evidence: format!("first observed in {scan_new}"),
                });
            }
        }
        for (entity_id, (transport, ip, port)) in &old_ports {
            if new_ports.contains_key(entity_id) {
                continue;
            }
            // Absence without coverage is unknown — never a removal.
            if !port_covered_in_snapshot(&new_cov, transport, ip, *port) {
                continue;
            }
            changes.push(GraphChange {
                change_type: ChangeType::Closed,
                entity_id: entity_id.clone(),
                old_value: format!("{transport}/{port} open on {ip}"),
                new_value: format!("{transport}/{port} not observed (covered)"),
                confidence: 85,
                evidence: format!("covered by {scan_new} without observation"),
            });
        }

        // Hosts: appeared / disappeared (host-level coverage = attempted).
        let old_hosts = host_set(&old_obs);
        let new_hosts = host_set(&new_obs);
        for host in new_hosts.difference(&old_hosts) {
            changes.push(GraphChange {
                change_type: ChangeType::Appeared,
                entity_id: host.clone(),
                old_value: String::new(),
                new_value: "observed".to_owned(),
                confidence: 75,
                evidence: format!("first observed in {scan_new}"),
            });
        }
        for host in old_hosts.difference(&new_hosts) {
            let ip = host.strip_prefix("ip:").unwrap_or(host);
            if !new_cov.host_covered(ip) {
                continue;
            }
            changes.push(GraphChange {
                change_type: ChangeType::Disappeared,
                entity_id: host.clone(),
                old_value: "observed".to_owned(),
                new_value: "not observed (host covered)".to_owned(),
                confidence: 80,
                evidence: format!("host covered by {scan_new} without observation"),
            });
        }

        // Services: product/version/technology changes on stable ids.
        let old_services = service_states(&old_obs);
        let new_services = service_states(&new_obs);
        for (entity_id, new_state) in &new_services {
            match old_services.get(entity_id) {
                None => {
                    // New service on (possibly new) port: record appearance
                    // only if the port itself is new, else it was merely
                    // unclassified before (probable, not confirmed).
                    let port_new = !old_ports
                        .keys()
                        .any(|port_id| entity_id.starts_with(&format!("service:{port_id}:")));
                    changes.push(GraphChange {
                        change_type: if port_new {
                            ChangeType::Appeared
                        } else {
                            ChangeType::Added
                        },
                        entity_id: entity_id.clone(),
                        old_value: String::new(),
                        new_value: new_state.describe(),
                        confidence: if port_new { 80 } else { 65 },
                        evidence: format!("first classified in {scan_new}"),
                    });
                }
                Some(old_state) => {
                    if old_state.product != new_state.product {
                        changes.push(GraphChange {
                            change_type: ChangeType::Changed,
                            entity_id: entity_id.clone(),
                            old_value: format!("product {}", old_state.product),
                            new_value: format!("product {}", new_state.product),
                            confidence: 75,
                            evidence: "reclassified between scans".to_owned(),
                        });
                    } else if old_state.version != new_state.version {
                        changes.push(GraphChange {
                            change_type: ChangeType::Changed,
                            entity_id: entity_id.clone(),
                            old_value: format!("version {}", old_state.version),
                            new_value: format!("version {}", new_state.version),
                            confidence: 80,
                            evidence: "version differs between scans".to_owned(),
                        });
                    }
                }
            }
        }

        // Certificates: rotation on the same port (history retained: both
        // certificates stay in the database; the change links them).
        let old_certs = cert_presenters(&old_edges);
        let new_certs = cert_presenters(&new_edges);
        for (port, new_cert) in &new_certs {
            match old_certs.get(port) {
                Some(old_cert) if old_cert != new_cert => {
                    changes.push(GraphChange {
                        change_type: ChangeType::Changed,
                        entity_id: port.clone(),
                        old_value: format!("certificate {old_cert}"),
                        new_value: format!("certificate {new_cert}"),
                        confidence: 90,
                        evidence: format!("different certificate presented in {scan_new}"),
                    });
                }
                None => {
                    changes.push(GraphChange {
                        change_type: ChangeType::Added,
                        entity_id: port.clone(),
                        old_value: String::new(),
                        new_value: format!("certificate {new_cert}"),
                        confidence: 70,
                        evidence: format!("first certificate observed in {scan_new}"),
                    });
                }
                _ => {}
            }
        }

        // Hostnames: added / removed (DNS re-query gates removal).
        let old_names = hostname_set(&old_obs);
        let new_names = hostname_set(&new_obs);
        for name in new_names.difference(&old_names) {
            changes.push(GraphChange {
                change_type: ChangeType::Added,
                entity_id: name.clone(),
                old_value: String::new(),
                new_value: "observed".to_owned(),
                confidence: 75,
                evidence: format!("first observed in {scan_new}"),
            });
        }
        for name in old_names.difference(&new_names) {
            let bare = name.strip_prefix("host:").unwrap_or(name);
            if !new_cov.dns_covered(bare) {
                continue;
            }
            changes.push(GraphChange {
                change_type: ChangeType::Removed,
                entity_id: name.clone(),
                old_value: "observed".to_owned(),
                new_value: "not observed (name re-queried)".to_owned(),
                confidence: 75,
                evidence: format!("DNS re-queried in {scan_new} without observation"),
            });
        }

        // Relationships: added always; removed only with port/host/DNS
        // coverage for the involved endpoints (coarse but honest).
        for edge in new_edges.difference(&old_edges) {
            changes.push(GraphChange {
                change_type: ChangeType::Added,
                entity_id: format!("{}→{}", edge.0, edge.1),
                old_value: String::new(),
                new_value: format!("{} {} {}", edge.0, edge.2, edge.1),
                confidence: 70,
                evidence: format!("first observed in {scan_new}"),
            });
        }

        // SSH host-key rotation: same port, different key. History stays in
        // the database (both keys retained); the change links them.
        let old_ssh = presenters_for(&old_edges, "presents_ssh_host_key");
        let new_ssh = presenters_for(&new_edges, "presents_ssh_host_key");
        for (port, new_key) in &new_ssh {
            match old_ssh.get(port) {
                Some(old_key) if old_key != new_key => {
                    changes.push(GraphChange {
                        change_type: ChangeType::Changed,
                        entity_id: port.clone(),
                        old_value: format!("ssh key {old_key}"),
                        new_value: format!("ssh key {new_key}"),
                        confidence: 90,
                        evidence: format!("different host key presented in {scan_new}"),
                    });
                }
                None => {
                    changes.push(GraphChange {
                        change_type: ChangeType::Added,
                        entity_id: port.clone(),
                        old_value: String::new(),
                        new_value: format!("ssh key {new_key}"),
                        confidence: 70,
                        evidence: format!("first host key observed in {scan_new}"),
                    });
                }
                _ => {}
            }
        }

        // TLS posture drift: negotiated version, cipher, ALPN per port.
        // Coverage-aware: only ports observed in both scans compare.
        let old_tls = tls_posture_states(&old_obs);
        let new_tls = tls_posture_states(&new_obs);
        for (port, new_state) in &new_tls {
            let Some(old_state) = old_tls.get(port) else {
                continue;
            };
            for (field, old_value, new_value) in [
                ("tls version", &old_state.version, &new_state.version),
                ("cipher", &old_state.cipher, &new_state.cipher),
                ("ALPN", &old_state.alpn, &new_state.alpn),
            ] {
                if old_value != new_value && !(old_value.is_empty() && new_value.is_empty()) {
                    changes.push(GraphChange {
                        change_type: ChangeType::Changed,
                        entity_id: port.clone(),
                        old_value: format!("{field} {old_value}"),
                        new_value: format!("{field} {new_value}"),
                        confidence: 80,
                        evidence: "posture differs between scans".to_owned(),
                    });
                }
            }
        }

        // OS classification drift: top family per host differs while the
        // host was observed in both scans (new hosts already `appeared`).
        let old_os = self.top_os_by_host(scan_old)?;
        let new_os = self.top_os_by_host(scan_new)?;
        for (host, new_family) in &new_os {
            if let Some(old_family) = old_os.get(host) {
                if old_family != new_family {
                    changes.push(GraphChange {
                        change_type: ChangeType::Changed,
                        entity_id: host.clone(),
                        old_value: format!("os {old_family}"),
                        new_value: format!("os {new_family}"),
                        confidence: 65,
                        evidence: "top OS hypothesis differs between scans".to_owned(),
                    });
                }
            }
        }

        // Device-role drift: top role per host differs while the host was
        // observed in both scans (mirrors OS drift, separate confidence).
        let old_devices = self.top_device_by_host(scan_old)?;
        let new_devices = self.top_device_by_host(scan_new)?;
        for (host, new_role) in &new_devices {
            if let Some(old_role) = old_devices.get(host) {
                if old_role != new_role {
                    changes.push(GraphChange {
                        change_type: ChangeType::Changed,
                        entity_id: host.clone(),
                        old_value: format!("device {old_role}"),
                        new_value: format!("device {new_role}"),
                        confidence: 60,
                        evidence: "top device hypothesis differs between scans".to_owned(),
                    });
                }
            }
        }

        // Vulnerability history: newly matched advisories, resolved matches
        // (software upgraded out of range), and confidence changes. Keys are
        // (advisory, product, version); dataset-version differences are
        // recorded in evidence so database-changed vs software-changed stays
        // distinguishable. Only `matched` outcomes diff (indeterminate and
        // not-matched are point-in-time observations, not state).
        let old_vulns = self.vuln_match_set(scan_old)?;
        let new_vulns = self.vuln_match_set(scan_new)?;
        for (key, new_row) in &new_vulns {
            match old_vulns.get(key) {
                None => changes.push(GraphChange {
                    change_type: ChangeType::Added,
                    entity_id: format!("vuln:{}:{}", new_row.product, new_row.advisory_id),
                    old_value: String::new(),
                    new_value: format!(
                        "potential {} match for {} {}",
                        new_row.advisory_id, new_row.product, new_row.matched_version
                    ),
                    confidence: new_row.confidence.min(85),
                    evidence: format!(
                        "newly matched in {scan_new} (provider {} {})",
                        new_row.provider, new_row.dataset_version
                    ),
                }),
                Some(old_row) if old_row.confidence != new_row.confidence => {
                    changes.push(GraphChange {
                        change_type: ChangeType::ConfidenceChanged,
                        entity_id: format!("vuln:{}:{}", new_row.product, new_row.advisory_id),
                        old_value: format!("confidence {}", old_row.confidence),
                        new_value: format!("confidence {}", new_row.confidence),
                        confidence: new_row.confidence.min(80),
                        evidence: format!(
                            "candidate confidence changed (provider {} {} → {} {})",
                            old_row.provider,
                            old_row.dataset_version,
                            new_row.provider,
                            new_row.dataset_version
                        ),
                    });
                }
                Some(old_row)
                    if old_row.dataset_version != new_row.dataset_version
                        && old_row.outcome == new_row.outcome =>
                {
                    // Same verdict, new feed: informational provenance bump,
                    // not a finding change (prevents false history when feeds
                    // evolve without software changing).
                    changes.push(GraphChange {
                        change_type: ChangeType::ConfidenceChanged,
                        entity_id: format!("vuln:{}:{}", new_row.product, new_row.advisory_id),
                        old_value: format!("dataset {}", old_row.dataset_version),
                        new_value: format!("dataset {}", new_row.dataset_version),
                        confidence: 50,
                        evidence: "advisory metadata/dataset changed; software unchanged"
                            .to_owned(),
                    });
                }
                _ => {}
            }
        }
        for (key, old_row) in &old_vulns {
            if !new_vulns.contains_key(key) {
                let (resolution, confidence) = self
                    .vuln_resolution(
                        &old_row.product,
                        &old_row.matched_version,
                        &old_row.advisory_id,
                        &old_row.dataset_version,
                        scan_new,
                    )
                    .unwrap_or(("unknown".to_owned(), 40));
                changes.push(GraphChange {
                    change_type: ChangeType::Removed,
                    entity_id: format!("vuln:{}:{}", old_row.product, old_row.advisory_id),
                    old_value: format!(
                        "potential {} match for {} {}",
                        old_row.advisory_id, old_row.product, old_row.matched_version
                    ),
                    new_value: format!("no longer matched ({resolution})"),
                    confidence,
                    evidence: format!("matched in {scan_old}, absent in {scan_new}: {resolution}"),
                });
            }
        }

        // Investigation / exposure entities: new account, removed link
        // target, new domain/repository/exposure, disappeared account.
        // Coverage-gated per producing module: an entity absent from the
        // new run is `Removed` only when the new run completed the module
        // that produced it (blocked/truncated/deadline runs leave
        // UNKNOWN, never negative evidence). Modules are the observation
        // `module` values (`investigate.*`, `exposure.*`); network-scan
        // entities never enter this layer.
        fn investigation_module(module: &str) -> bool {
            module.starts_with("investigate.") || module.starts_with("exposure.")
        }
        for (entity_id, new_row) in &new_obs {
            if old_obs.contains_key(entity_id) || !investigation_module(&new_row.module) {
                continue;
            }
            changes.push(GraphChange {
                change_type: ChangeType::Added,
                entity_id: entity_id.clone(),
                old_value: String::new(),
                new_value: format!("{} observed", new_row.kind),
                confidence: 75,
                evidence: format!("first observed in {scan_new} via {}", new_row.module),
            });
        }
        for (entity_id, old_row) in &old_obs {
            if new_obs.contains_key(entity_id) || !investigation_module(&old_row.module) {
                continue;
            }
            if !new_cov.modules_completed.contains(&old_row.module) {
                // Producing transform did not complete in the new run:
                // unknown, not removed.
                continue;
            }
            changes.push(GraphChange {
                change_type: ChangeType::Removed,
                entity_id: entity_id.clone(),
                old_value: format!("{} observed", old_row.kind),
                new_value: "not observed (covered)".to_owned(),
                confidence: 80,
                evidence: format!(
                    "covered by {} ({}) without observation",
                    scan_new, old_row.module
                ),
            });
        }
        // Investigation / exposure relationships: removed links are
        // reported only when both endpoints' producing modules completed
        // in the new run (added links already surface above generically).
        for edge in old_edges.difference(&new_edges) {
            let (from, to, relation) = edge;
            let (Some(from_row), Some(to_row)) = (old_obs.get(from), old_obs.get(to)) else {
                continue;
            };
            if !investigation_module(&from_row.module)
                || !investigation_module(&to_row.module)
                || !new_cov.modules_completed.contains(&from_row.module)
                || !new_cov.modules_completed.contains(&to_row.module)
            {
                continue;
            }
            changes.push(GraphChange {
                change_type: ChangeType::Removed,
                entity_id: format!("{from}→{to}"),
                old_value: format!("{from} {relation} {to}"),
                new_value: "link not observed (covered)".to_owned(),
                confidence: 75,
                evidence: format!("covered by {scan_new} without observation"),
            });
        }

        changes.sort_by(|a, b| {
            (a.change_type.as_str(), &a.entity_id).cmp(&(b.change_type.as_str(), &b.entity_id))
        });
        // Bounded diff output: deterministic order above, visible truncation.
        const MAX_DIFF_CHANGES: usize = 2048;
        if changes.len() > MAX_DIFF_CHANGES {
            changes.truncate(MAX_DIFF_CHANGES);
        }
        Ok(changes)
    }

    fn observations_by_entity(
        &self,
        scan_run: &str,
    ) -> Result<BTreeMap<String, ObservationRow>, ProjectDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, scan_run, entity_id, kind, label, attrs_json, confidence,
                    evidence_excerpt, module, task_id, timestamp_ms
             FROM observations WHERE scan_run=?1 ORDER BY entity_id",
        )?;
        let rows = stmt.query_map(params![scan_run], row_to_observation)?;
        let mut map = BTreeMap::new();
        for row in rows {
            let row: ObservationRow = row?;
            map.insert(row.entity_id.clone(), row);
        }
        Ok(map)
    }

    fn edge_set(
        &self,
        scan_run: &str,
    ) -> Result<BTreeSet<(String, String, String)>, ProjectDbError> {
        let mut stmt = self
            .conn
            .prepare("SELECT from_id, to_id, relation FROM edge_observations WHERE scan_run=?1")?;
        let rows = stmt.query_map(params![scan_run], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut set = BTreeSet::new();
        for row in rows {
            set.insert(row?);
        }
        Ok(set)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeRow {
    pub from_id: String,
    pub to_id: String,
    pub relation: String,
    pub confidence: u8,
    pub scan_run: String,
    pub module: String,
    pub task_id: String,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredChange {
    pub scan_new: String,
    pub scan_old: String,
    pub change_type: String,
    pub entity_id: String,
    pub old_value: String,
    pub new_value: String,
    pub confidence: u8,
    pub evidence: String,
}

fn row_to_entity(row: &rusqlite::Row<'_>) -> rusqlite::Result<EntityRow> {
    let first_seen_ms: i64 = row.get(6)?;
    let last_seen_ms: i64 = row.get(7)?;
    let observation_count: i64 = row.get(8)?;
    Ok(EntityRow {
        entity_id: row.get(0)?,
        kind: row.get(1)?,
        label: row.get(2)?,
        attributes_json: row.get(3)?,
        first_seen_scan: row.get(4)?,
        last_seen_scan: row.get(5)?,
        first_seen_ms: u64::try_from(first_seen_ms).unwrap_or(0),
        last_seen_ms: u64::try_from(last_seen_ms).unwrap_or(0),
        observation_count: u64::try_from(observation_count).unwrap_or(0),
    })
}

fn row_to_observation(row: &rusqlite::Row<'_>) -> rusqlite::Result<ObservationRow> {
    let confidence: i64 = row.get(6)?;
    Ok(ObservationRow {
        id: row.get(0)?,
        scan_run: row.get(1)?,
        entity_id: row.get(2)?,
        kind: row.get(3)?,
        label: row.get(4)?,
        attrs_json: row.get(5)?,
        confidence: confidence.clamp(0, 100) as u8,
        evidence_excerpt: row.get(7)?,
        module: row.get(8)?,
        task_id: row.get(9)?,
        timestamp_ms: row.get(10)?,
    })
}

fn row_to_edge(row: &rusqlite::Row<'_>) -> rusqlite::Result<EdgeRow> {
    let confidence: i64 = row.get(3)?;
    Ok(EdgeRow {
        from_id: row.get(0)?,
        to_id: row.get(1)?,
        relation: row.get(2)?,
        confidence: confidence.clamp(0, 100) as u8,
        scan_run: row.get(4)?,
        module: row.get(5)?,
        task_id: row.get(6)?,
        evidence: row.get(7)?,
    })
}

fn sorted_unique(values: &[String]) -> Vec<String> {
    let mut out: Vec<String> = values.to_vec();
    out.sort();
    out.dedup();
    out
}

fn truncate_str(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn port_states(
    observations: &BTreeMap<String, ObservationRow>,
) -> BTreeMap<String, (String, String, u16)> {
    let mut out = BTreeMap::new();
    for (id, row) in observations {
        if row.kind != "port" {
            continue;
        }
        let attrs: BTreeMap<String, String> =
            serde_json::from_str(&row.attrs_json).unwrap_or_default();
        let transport = attrs
            .get("transport")
            .cloned()
            .unwrap_or_else(|| "tcp".to_owned());
        let address = attrs.get("address").cloned().unwrap_or_default();
        let port = attrs
            .get("port")
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(0);
        if address.is_empty() || port == 0 {
            continue;
        }
        out.insert(id.clone(), (transport, address, port));
    }
    out
}

fn port_covered_in_snapshot(
    coverage: &CoverageSnapshot,
    transport: &str,
    ip: &str,
    port: u16,
) -> bool {
    coverage.port_covered(transport, ip, port)
}

fn host_set(observations: &BTreeMap<String, ObservationRow>) -> BTreeSet<String> {
    observations
        .iter()
        .filter(|(_, row)| row.kind == "ip_address" || row.kind == "host")
        .map(|(id, _)| id.clone())
        .collect()
}

fn hostname_set(observations: &BTreeMap<String, ObservationRow>) -> BTreeSet<String> {
    observations
        .iter()
        .filter(|(_, row)| row.kind == "hostname")
        .map(|(id, _)| id.clone())
        .collect()
}

struct ServiceState {
    product: String,
    version: String,
}

impl ServiceState {
    fn describe(&self) -> String {
        if self.version.is_empty() {
            format!("service {}", self.product)
        } else {
            format!("service {} {}", self.product, self.version)
        }
    }
}

fn service_states(
    observations: &BTreeMap<String, ObservationRow>,
) -> BTreeMap<String, ServiceState> {
    let mut out = BTreeMap::new();
    for (id, row) in observations {
        if row.kind != "service" {
            continue;
        }
        let attrs: BTreeMap<String, String> =
            serde_json::from_str(&row.attrs_json).unwrap_or_default();
        out.insert(
            id.clone(),
            ServiceState {
                product: attrs
                    .get("product_hint")
                    .or_else(|| attrs.get("product"))
                    .cloned()
                    .unwrap_or_default(),
                version: attrs
                    .get("version_hint")
                    .or_else(|| attrs.get("version"))
                    .cloned()
                    .unwrap_or_default(),
            },
        );
    }
    out
}

struct TlsPostureState {
    version: String,
    cipher: String,
    alpn: String,
}

fn tls_posture_states(
    observations: &BTreeMap<String, ObservationRow>,
) -> BTreeMap<String, TlsPostureState> {
    let mut out = BTreeMap::new();
    for (id, row) in observations {
        if row.kind != "tls_posture" {
            continue;
        }
        let attrs: BTreeMap<String, String> =
            serde_json::from_str(&row.attrs_json).unwrap_or_default();
        out.insert(
            id.clone(),
            TlsPostureState {
                version: attrs.get("version").cloned().unwrap_or_default(),
                cipher: attrs.get("cipher").cloned().unwrap_or_default(),
                alpn: attrs.get("alpn").cloned().unwrap_or_default(),
            },
        );
    }
    out
}

/// Port entity id → presenting certificate/key entity id, from per-scan
/// edges of one relation.
fn presenters_for(
    edges: &BTreeSet<(String, String, String)>,
    relation: &str,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (from, to, rel) in edges {
        if rel == relation {
            out.insert(from.clone(), to.clone());
        }
    }
    out
}

/// Port entity id → presenting certificate entity id, from per-scan edges.
fn cert_presenters(edges: &BTreeSet<(String, String, String)>) -> BTreeMap<String, String> {
    presenters_for(edges, "presents_certificate")
}

/// Human-readable one-screen change summary (concise by default; detail
/// lives in structured records).
pub fn human_changes_summary(changes: &[GraphChange]) -> String {
    if changes.is_empty() {
        return "No changes detected.".to_owned();
    }
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for change in changes {
        *counts.entry(change.change_type.as_str()).or_default() += 1;
    }
    let mut lines = vec!["Changes since previous scan:".to_owned()];
    for (kind, count) in &counts {
        lines.push(format!("  {kind}: {count}"));
    }
    lines.join("\n")
}

// ---------------- intelligence import (OS/device/software/vuln/TLS) ----------------

/// One TLS posture observation for a port entity (built from
/// `TlsPostureObserved` events at import time).
#[derive(Debug, Clone)]
pub struct TlsObservationImport {
    pub port_entity: String,
    pub version: String,
    pub cipher: String,
    pub alpn: String,
    pub cert_id: String,
}

/// Intelligence payload imported alongside the graph: OS/device
/// candidates, software inventory, vulnerability candidates, and TLS
/// posture observations. Stored in normalized tables (relationships over
/// duplication); JSONL streaming of the same records happens in `run.rs`.
#[derive(Debug, Clone, Default)]
pub struct IntelImport {
    pub os: Vec<(String, crate::os_fingerprint::OsCandidate)>,
    pub devices: Vec<(String, crate::device::DeviceCandidate)>,
    pub software: Vec<SoftwareImport>,
    pub vulns: Vec<VulnImport>,
    pub tls: Vec<TlsObservationImport>,
}

#[derive(Debug, Clone)]
pub struct SoftwareImport {
    pub product: String,
    pub vendor: String,
    pub version: String,
    pub family: String,
    pub cpe: String,
    pub confidence: u8,
    pub version_confidence: u8,
    pub hosts: Vec<String>,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VulnImport {
    pub advisory_id: String,
    pub provider: String,
    /// Provider dataset version/date at lookup time (provenance: distinguishes
    /// software-changed from database-changed history).
    #[allow(clippy::struct_field_names)]
    pub dataset_version: String,
    pub product: String,
    pub matched_version: String,
    pub match_type: String,
    pub outcome: String,
    pub confidence: u8,
    pub severity: String,
    pub host: String,
    pub endpoint: String,
    pub identity_json: String,
}

#[derive(Debug, Clone, Default)]
pub struct IntelImportStats {
    pub os_stored: usize,
    pub devices_stored: usize,
    pub software_stored: usize,
    pub vulns_stored: usize,
    pub tls_stored: usize,
}

/// One normalized software identity row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoftwareRow {
    pub product: String,
    pub vendor: String,
    pub version: String,
    pub family: String,
    pub cpe: String,
    pub confidence: u8,
    pub hosts: Vec<String>,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AssetSummary {
    pub hosts: usize,
    pub services: usize,
    pub certificates: usize,
    pub ssh_host_keys: usize,
    pub software_identities: usize,
    pub device_candidates: usize,
    pub os_classified_high: usize,
    pub os_classified_medium: usize,
    pub vulnerability_candidates: usize,
    pub attention_items: usize,
}

impl ProjectDb {
    /// Import intelligence rows for a scan (transactional with the same
    /// atomicity as [`import_scan`](Self::import_scan)). Validates every
    /// row; invalid input aborts the whole import, never partially.
    pub fn import_intelligence(
        &mut self,
        scan_id: &str,
        intel: &IntelImport,
    ) -> Result<IntelImportStats, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        let tx = self.conn.transaction()?;
        let mut stats = IntelImportStats::default();
        for (host, candidate) in &intel.os {
            validate_id(host, "os host")?;
            validate_confidence(candidate.confidence, "os candidate")?;
            if candidate.family.trim().is_empty() || candidate.family.len() > 64 {
                return Err(ProjectDbError::InvalidInput(
                    "os family out of range".to_owned(),
                ));
            }
            tx.execute(
                "INSERT INTO os_candidates(scan_run, host, family, generation, variant,
                  confidence, supporting_json, rule_ids_json)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
                 ON CONFLICT(scan_run, host, family) DO UPDATE SET
                   generation=excluded.generation, variant=excluded.variant,
                   confidence=excluded.confidence, supporting_json=excluded.supporting_json,
                   rule_ids_json=excluded.rule_ids_json",
                params![
                    scan_id,
                    host,
                    candidate.family,
                    candidate.generation.clone().unwrap_or_default(),
                    candidate.variant.clone().unwrap_or_default(),
                    candidate.confidence,
                    serde_json::to_string(&candidate.supporting).unwrap_or_default(),
                    serde_json::to_string(&candidate.rule_ids).unwrap_or_default(),
                ],
            )?;
            stats.os_stored += 1;
        }
        for (host, candidate) in &intel.devices {
            validate_id(host, "device host")?;
            validate_confidence(candidate.role_confidence, "device role")?;
            if candidate.role.trim().is_empty() || candidate.role.len() > 64 {
                return Err(ProjectDbError::InvalidInput(
                    "device role out of range".to_owned(),
                ));
            }
            tx.execute(
                "INSERT INTO device_candidates(scan_run, host, role, vendor, model,
                  role_confidence, vendor_confidence, model_confidence, evidence_json, rule_ids_json)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
                 ON CONFLICT(scan_run, host, role) DO UPDATE SET
                   vendor=excluded.vendor, model=excluded.model,
                   role_confidence=excluded.role_confidence,
                   vendor_confidence=excluded.vendor_confidence,
                   model_confidence=excluded.model_confidence,
                   evidence_json=excluded.evidence_json,
                   rule_ids_json=excluded.rule_ids_json",
                params![
                    scan_id,
                    host,
                    candidate.role,
                    candidate.vendor.clone().unwrap_or_default(),
                    candidate.model_hint.clone().unwrap_or_default(),
                    candidate.role_confidence,
                    candidate.vendor_confidence.unwrap_or(0),
                    candidate.model_confidence.unwrap_or(0),
                    serde_json::to_string(&candidate.evidence).unwrap_or_default(),
                    serde_json::to_string(&candidate.rule_ids).unwrap_or_default(),
                ],
            )?;
            stats.devices_stored += 1;
        }
        for software in &intel.software {
            if software.product.trim().is_empty() || software.product.len() > 128 {
                return Err(ProjectDbError::InvalidInput(
                    "software product out of range".to_owned(),
                ));
            }
            validate_confidence(software.confidence, "software")?;
            let hosts = serde_json::to_string(&sorted_unique(&software.hosts))
                .map_err(|error| ProjectDbError::InvalidInput(error.to_string()))?;
            let endpoints = serde_json::to_string(&sorted_unique(&software.endpoints))
                .map_err(|error| ProjectDbError::InvalidInput(error.to_string()))?;
            check_json_size(&hosts, "software hosts")?;
            tx.execute(
                "INSERT INTO software_identities(scan_run, product, vendor, version, family,
                  cpe, confidence, version_confidence, hosts_json, endpoints_json)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
                 ON CONFLICT(scan_run, product, vendor, version) DO UPDATE SET
                   family=excluded.family, cpe=excluded.cpe, confidence=excluded.confidence,
                   version_confidence=excluded.version_confidence,
                   hosts_json=excluded.hosts_json, endpoints_json=excluded.endpoints_json",
                params![
                    scan_id,
                    software.product,
                    software.vendor,
                    software.version,
                    software.family,
                    software.cpe,
                    software.confidence,
                    software.version_confidence,
                    hosts,
                    endpoints,
                ],
            )?;
            stats.software_stored += 1;
        }
        for vuln in &intel.vulns {
            if vuln.advisory_id.trim().is_empty() || vuln.advisory_id.len() > 128 {
                return Err(ProjectDbError::InvalidInput(
                    "advisory id out of range".to_owned(),
                ));
            }
            validate_confidence(vuln.confidence, "vulnerability")?;
            if vuln.dataset_version.len() > 256 {
                return Err(ProjectDbError::InvalidInput(
                    "dataset version out of range".to_owned(),
                ));
            }
            tx.execute(
                "INSERT INTO vulnerability_candidates(scan_run, advisory_id, provider, product,
                  matched_version, match_type, outcome, confidence, severity, host, endpoint, identity_json,
                  dataset_version)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
                 ON CONFLICT(scan_run, advisory_id, product, matched_version) DO UPDATE SET
                   match_type=excluded.match_type, outcome=excluded.outcome,
                   confidence=excluded.confidence, severity=excluded.severity,
                   host=excluded.host, endpoint=excluded.endpoint,
                   identity_json=excluded.identity_json,
                   dataset_version=excluded.dataset_version",
                params![
                    scan_id,
                    vuln.advisory_id,
                    vuln.provider,
                    vuln.product,
                    vuln.matched_version,
                    vuln.match_type,
                    vuln.outcome,
                    vuln.confidence,
                    vuln.severity,
                    vuln.host,
                    vuln.endpoint,
                    vuln.identity_json,
                    vuln.dataset_version,
                ],
            )?;
            stats.vulns_stored += 1;
        }
        for tls in &intel.tls {
            validate_id(&tls.port_entity, "tls port")?;
            tx.execute(
                "INSERT INTO observations(scan_run, entity_id, kind, label, attrs_json,
                  confidence, evidence_excerpt, module, task_id, timestamp_ms)
                 VALUES(?1,?2,'tls_posture',?3,?4,85,'tls handshake posture','rxscan.service','',0)",
                params![
                    scan_id,
                    tls.port_entity,
                    format!("tls posture for {}", tls.port_entity),
                    serde_json::json!({
                        "version": tls.version,
                        "cipher": tls.cipher,
                        "alpn": tls.alpn,
                        "cert_id": tls.cert_id,
                    })
                    .to_string(),
                ],
            )?;
            stats.tls_stored += 1;
        }
        tx.commit()?;
        Ok(stats)
    }

    /// Persist attention events for a scan (generated by
    /// [`generate_attention`]).
    pub fn record_attention(
        &mut self,
        scan_id: &str,
        events: &[AttentionEvent],
    ) -> Result<(), ProjectDbError> {
        validate_id(scan_id, "scan")?;
        let tx = self.conn.transaction()?;
        for event in events {
            validate_id(&event.entity_id, "attention entity")?;
            if AttentionSeverity::parse(event.severity.as_str()).is_none() {
                return Err(ProjectDbError::InvalidInput("unknown severity".to_owned()));
            }
            let evidence = serde_json::to_string(&event.evidence)
                .map_err(|error| ProjectDbError::InvalidInput(error.to_string()))?;
            check_json_size(&evidence, "attention evidence")?;
            tx.execute(
                "INSERT INTO attention_events(scan_run, category, severity, entity_id,
                  title, reason, evidence_json)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    scan_id,
                    event.category,
                    event.severity.as_str(),
                    event.entity_id,
                    truncate_str(&event.title, 256),
                    truncate_str(&event.reason, 1024),
                    evidence,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn attention_for_scan(&self, scan_id: &str) -> Result<Vec<AttentionEvent>, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        let mut stmt = self.conn.prepare(
            "SELECT category, severity, entity_id, title, reason, evidence_json
             FROM attention_events WHERE scan_run=?1 ORDER BY rowid",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            let severity_text: String = row.get(1)?;
            let severity = AttentionSeverity::parse(&severity_text).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    format!("unknown severity {severity_text}").into(),
                )
            })?;
            let evidence_json: String = row.get(5)?;
            let evidence: Vec<String> = serde_json::from_str(&evidence_json).unwrap_or_default();
            Ok(AttentionEvent {
                category: row.get(0)?,
                severity,
                entity_id: row.get(2)?,
                title: row.get(3)?,
                reason: row.get(4)?,
                evidence,
                scan_run: scan_id.to_owned(),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectDbError::from)
    }

    // ---------------- inventory + summary queries ----------------

    /// Normalized software inventory for one scan, ordered by product.
    pub fn software_inventory(&self, scan_id: &str) -> Result<Vec<SoftwareRow>, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        let mut stmt = self.conn.prepare(
            "SELECT product, vendor, version, family, cpe, confidence, hosts_json, endpoints_json
             FROM software_identities WHERE scan_run=?1 ORDER BY product, version",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            let confidence: i64 = row.get(5)?;
            let hosts: String = row.get(6)?;
            let endpoints: String = row.get(7)?;
            Ok(SoftwareRow {
                product: row.get(0)?,
                vendor: row.get(1)?,
                version: row.get(2)?,
                family: row.get(3)?,
                cpe: row.get(4)?,
                confidence: confidence.clamp(0, 100) as u8,
                hosts: serde_json::from_str(&hosts).unwrap_or_default(),
                endpoints: serde_json::from_str(&endpoints).unwrap_or_default(),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectDbError::from)
    }

    /// Software versions observed on one host across its services.
    pub fn software_for_host(
        &self,
        scan_id: &str,
        host: &str,
    ) -> Result<Vec<SoftwareRow>, ProjectDbError> {
        Ok(self
            .software_inventory(scan_id)?
            .into_iter()
            .filter(|row| row.hosts.iter().any(|candidate| candidate == host))
            .collect())
    }

    /// Concise project-wide asset summary derived from normalized data.
    /// OS bands: high ≥75, medium 55–74 (weak hints excluded by design).
    pub fn asset_summary(&self, scan_id: &str) -> Result<AssetSummary, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        let hosts: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT entity_id) FROM observations
             WHERE scan_run=?1 AND kind IN ('ip_address','host')",
            params![scan_id],
            |row| row.get(0),
        )?;
        let services: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM observations WHERE scan_run=?1 AND kind='service'",
            params![scan_id],
            |row| row.get(0),
        )?;
        let certificates: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM observations WHERE scan_run=?1 AND kind='certificate'",
            params![scan_id],
            |row| row.get(0),
        )?;
        let ssh_keys: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM observations WHERE scan_run=?1 AND kind='ssh_host_key'",
            params![scan_id],
            |row| row.get(0),
        )?;
        let software: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM software_identities WHERE scan_run=?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        let devices: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM device_candidates WHERE scan_run=?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        let os_high: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM os_candidates WHERE scan_run=?1 AND confidence>=75",
            params![scan_id],
            |row| row.get(0),
        )?;
        let os_medium: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM os_candidates
             WHERE scan_run=?1 AND confidence>=55 AND confidence<75",
            params![scan_id],
            |row| row.get(0),
        )?;
        let vulns: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM vulnerability_candidates WHERE scan_run=?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        let attention: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM attention_events WHERE scan_run=?1",
            params![scan_id],
            |row| row.get(0),
        )?;
        Ok(AssetSummary {
            hosts: hosts.max(0) as usize,
            services: services.max(0) as usize,
            certificates: certificates.max(0) as usize,
            ssh_host_keys: ssh_keys.max(0) as usize,
            software_identities: software.max(0) as usize,
            device_candidates: devices.max(0) as usize,
            os_classified_high: os_high.max(0) as usize,
            os_classified_medium: os_medium.max(0) as usize,
            vulnerability_candidates: vulns.max(0) as usize,
            attention_items: attention.max(0) as usize,
        })
    }

    /// Services running on one host (service entities observed this scan).
    pub fn services_on_host(
        &self,
        scan_id: &str,
        host: &str,
    ) -> Result<Vec<ObservationRow>, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        Ok(self
            .observations_by_entity_scan(scan_id)?
            .into_iter()
            .filter(|row| {
                row.kind == "service"
                    && serde_json::from_str::<BTreeMap<String, String>>(&row.attrs_json)
                        .map(|attrs| attrs.get("address").is_some_and(|a| a == host))
                        .unwrap_or(false)
            })
            .collect())
    }

    /// Hostnames resolving to one IP (observed RESOLVES_TO edges).
    pub fn hostnames_for_ip(&self, scan_id: &str, ip: &str) -> Result<Vec<String>, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        let want = format!("ip:{ip}");
        let mut stmt = self.conn.prepare(
            "SELECT from_id FROM edge_observations
             WHERE scan_run=?1 AND to_id=?2 AND relation='resolves_to' ORDER BY from_id",
        )?;
        let rows = stmt.query_map(params![scan_id, want], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectDbError::from)
    }

    /// IPs one hostname resolves to (observed RESOLVES_TO edges).
    pub fn ips_for_hostname(
        &self,
        scan_id: &str,
        hostname: &str,
    ) -> Result<Vec<String>, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        let want = format!(
            "host:{}",
            hostname.trim().trim_end_matches('.').to_ascii_lowercase()
        );
        let mut stmt = self.conn.prepare(
            "SELECT to_id FROM edge_observations
             WHERE scan_run=?1 AND from_id=?2 AND relation='resolves_to' ORDER BY to_id",
        )?;
        let rows = stmt.query_map(params![scan_id, want], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectDbError::from)
    }

    /// Endpoints served through ports presenting one certificate:
    /// ports→cert presenter lookup, then endpoints resolving to them.
    pub fn endpoints_for_certificate(
        &self,
        scan_id: &str,
        cert_entity_id: &str,
    ) -> Result<Vec<String>, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        validate_id(cert_entity_id, "certificate")?;
        let mut ports_stmt = self.conn.prepare(
            "SELECT from_id FROM edge_observations
             WHERE scan_run=?1 AND to_id=?2 AND relation='presents_certificate'",
        )?;
        let ports: Vec<String> = ports_stmt
            .query_map(params![scan_id, cert_entity_id], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if ports.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = ports.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        // rusqlite params! cannot expand a runtime list; bind port ids by
        // querying per port (bounded: presenter fan-out is small).
        let mut endpoints = BTreeSet::new();
        for port in &ports {
            let mut stmt = self.conn.prepare(
                "SELECT from_id FROM edge_observations
                 WHERE scan_run=?1 AND to_id=?2 AND relation='resolves_to_endpoint'",
            )?;
            for row in stmt.query_map(params![scan_id, port], |row| row.get::<_, String>(0))? {
                endpoints.insert(row?);
            }
        }
        let _ = placeholders;
        let mut endpoints: Vec<String> = endpoints.into_iter().collect();
        endpoints.sort();
        Ok(endpoints)
    }

    /// Vulnerability candidates for a scan at or above a confidence floor,
    /// strongest first (deterministic).
    pub fn vuln_candidates(
        &self,
        scan_id: &str,
        min_confidence: u8,
    ) -> Result<Vec<VulnCandidateRow>, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        // dataset_version exists on v3+ databases; older files migrate on
        // open, but tolerate its absence for robustness (e.g. external
        // readers) by falling back to the pre-v3 column list.
        if self.has_vuln_dataset_version() {
            let mut stmt = self.conn.prepare(
                "SELECT advisory_id, provider, dataset_version, product, matched_version, match_type,
                        outcome, confidence, severity, host, endpoint
                 FROM vulnerability_candidates
                 WHERE scan_run=?1 AND confidence>=?2
                 ORDER BY confidence DESC, advisory_id",
            )?;
            let rows = stmt.query_map(params![scan_id, min_confidence], |row| {
                let confidence: i64 = row.get(7)?;
                Ok(VulnCandidateRow {
                    advisory_id: row.get(0)?,
                    provider: row.get(1)?,
                    dataset_version: row.get(2)?,
                    product: row.get(3)?,
                    matched_version: row.get(4)?,
                    match_type: row.get(5)?,
                    outcome: row.get(6)?,
                    confidence: confidence.clamp(0, 100) as u8,
                    severity: row.get(8)?,
                    host: row.get(9)?,
                    endpoint: row.get(10)?,
                })
            })?;
            return rows
                .collect::<Result<Vec<_>, _>>()
                .map_err(ProjectDbError::from);
        }
        let mut stmt = self.conn.prepare(
            "SELECT advisory_id, provider, product, matched_version, match_type,
                    outcome, confidence, severity, host, endpoint
             FROM vulnerability_candidates
             WHERE scan_run=?1 AND confidence>=?2
             ORDER BY confidence DESC, advisory_id",
        )?;
        let rows = stmt.query_map(params![scan_id, min_confidence], |row| {
            let confidence: i64 = row.get(6)?;
            Ok(VulnCandidateRow {
                advisory_id: row.get(0)?,
                provider: row.get(1)?,
                dataset_version: String::new(),
                product: row.get(2)?,
                matched_version: row.get(3)?,
                match_type: row.get(4)?,
                outcome: row.get(5)?,
                confidence: confidence.clamp(0, 100) as u8,
                severity: row.get(7)?,
                host: row.get(8)?,
                endpoint: row.get(9)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectDbError::from)
    }

    /// OS candidates for one host in a scan (confidence desc).
    pub fn os_for_host(
        &self,
        scan_id: &str,
        host: &str,
    ) -> Result<Vec<OsCandidateRow>, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        let mut stmt = self.conn.prepare(
            "SELECT family, generation, variant, confidence
             FROM os_candidates WHERE scan_run=?1 AND host=?2 ORDER BY confidence DESC",
        )?;
        let rows = stmt.query_map(params![scan_id, host], |row| {
            let confidence: i64 = row.get(3)?;
            Ok(OsCandidateRow {
                family: row.get(0)?,
                generation: row.get(1)?,
                variant: row.get(2)?,
                confidence: confidence.clamp(0, 100) as u8,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectDbError::from)
    }

    /// Device candidates for one host in a scan (role confidence desc).
    pub fn device_for_host(
        &self,
        scan_id: &str,
        host: &str,
    ) -> Result<Vec<DeviceCandidateRow>, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        let mut stmt = self.conn.prepare(
            "SELECT role, vendor, model, role_confidence, vendor_confidence, model_confidence
             FROM device_candidates WHERE scan_run=?1 AND host=?2 ORDER BY role_confidence DESC",
        )?;
        let rows = stmt.query_map(params![scan_id, host], |row| {
            let role_confidence: i64 = row.get(3)?;
            let vendor_confidence: i64 = row.get(4)?;
            let model_confidence: i64 = row.get(5)?;
            Ok(DeviceCandidateRow {
                role: row.get(0)?,
                vendor: row.get(1)?,
                model: row.get(2)?,
                role_confidence: role_confidence.clamp(0, 100) as u8,
                vendor_confidence: vendor_confidence.clamp(0, 100) as u8,
                model_confidence: model_confidence.clamp(0, 100) as u8,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectDbError::from)
    }

    /// Top OS family per host for one scan (highest confidence wins).
    fn top_os_by_host(&self, scan_id: &str) -> Result<BTreeMap<String, String>, ProjectDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT host, family FROM os_candidates
             WHERE scan_run=?1 ORDER BY host, confidence DESC",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (host, family): (String, String) = row?;
            out.entry(host).or_insert(family);
        }
        Ok(out)
    }

    /// Top device role per host for one scan (highest role confidence wins).
    fn top_device_by_host(
        &self,
        scan_id: &str,
    ) -> Result<BTreeMap<String, String>, ProjectDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT host, role FROM device_candidates
             WHERE scan_run=?1 ORDER BY host, role_confidence DESC",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (host, role): (String, String) = row?;
            out.entry(host).or_insert(role);
        }
        Ok(out)
    }

    /// Whether this database has the v3 `dataset_version` column.
    /// v3+ files always do (migrated on open); the check keeps external
    /// pre-v3 readers from failing on the wider select.
    fn has_vuln_dataset_version(&self) -> bool {
        self.conn
            .prepare("SELECT dataset_version FROM vulnerability_candidates LIMIT 0")
            .is_ok()
    }

    /// Matched vulnerability set per scan keyed by (advisory, product,
    /// version). Only `matched` outcomes participate in history (indeterminate
    /// and not-matched are point-in-time, not state).
    fn vuln_match_set(
        &self,
        scan_id: &str,
    ) -> Result<BTreeMap<(String, String, String), VulnHistoryRow>, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        let has_dataset_version = self.has_vuln_dataset_version();
        let sql = if has_dataset_version {
            "SELECT advisory_id, provider, dataset_version, product, matched_version,
                    outcome, confidence FROM vulnerability_candidates WHERE scan_run=?1"
        } else {
            "SELECT advisory_id, provider, product, matched_version,
                    outcome, confidence FROM vulnerability_candidates WHERE scan_run=?1"
        };
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params![scan_id], |row| {
            if has_dataset_version {
                let confidence: i64 = row.get(6)?;
                Ok(VulnHistoryRow {
                    advisory_id: row.get(0)?,
                    provider: row.get(1)?,
                    dataset_version: row.get(2)?,
                    product: row.get(3)?,
                    matched_version: row.get(4)?,
                    outcome: row.get(5)?,
                    confidence: confidence.clamp(0, 100) as u8,
                })
            } else {
                let confidence: i64 = row.get(5)?;
                Ok(VulnHistoryRow {
                    advisory_id: row.get(0)?,
                    provider: row.get(1)?,
                    dataset_version: String::new(),
                    product: row.get(2)?,
                    matched_version: row.get(3)?,
                    outcome: row.get(4)?,
                    confidence: confidence.clamp(0, 100) as u8,
                })
            }
        })?;
        let mut out = BTreeMap::new();
        for row in rows {
            let row: VulnHistoryRow = row?;
            if row.outcome != "matched" {
                continue;
            }
            out.insert(
                (
                    row.advisory_id.clone(),
                    row.product.clone(),
                    row.matched_version.clone(),
                ),
                row,
            );
        }
        Ok(out)
    }

    fn vuln_resolution(
        &self,
        product: &str,
        matched_version: &str,
        advisory_id: &str,
        old_dataset: &str,
        scan_new: &str,
    ) -> Result<(String, u8), ProjectDbError> {
        let inventory = self.software_inventory(scan_new)?;
        let observed: Vec<&str> = inventory
            .iter()
            .filter(|row| row.product.eq_ignore_ascii_case(product))
            .map(|row| row.version.as_str())
            .collect();
        if observed.is_empty() {
            return Ok(("coverage_insufficient".to_owned(), 30));
        }
        if !observed.contains(&matched_version) {
            return Ok(("resolved_by_software_change".to_owned(), 75));
        }
        if self.vuln_dataset_changed(advisory_id, old_dataset, scan_new)? {
            return Ok(("dataset_changed".to_owned(), 50));
        }
        Ok(("unknown".to_owned(), 40))
    }

    fn vuln_dataset_changed(
        &self,
        advisory_id: &str,
        old_dataset: &str,
        scan_new: &str,
    ) -> Result<bool, ProjectDbError> {
        validate_id(scan_new, "scan")?;
        if !self.has_vuln_dataset_version() {
            return Ok(false);
        }
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT dataset_version FROM vulnerability_candidates
             WHERE scan_run=?1 AND advisory_id=?2",
        )?;
        let versions: Vec<String> = stmt
            .query_map(params![scan_new, advisory_id], |row| row.get(0))?
            .collect::<Result<_, _>>()
            .map_err(ProjectDbError::from)?;
        if versions.is_empty() {
            return Ok(true);
        }
        Ok(versions.iter().any(|version| version != old_dataset))
    }

    fn observations_by_entity_scan(
        &self,
        scan_id: &str,
    ) -> Result<Vec<ObservationRow>, ProjectDbError> {
        validate_id(scan_id, "scan")?;
        let mut stmt = self.conn.prepare(
            "SELECT id, scan_run, entity_id, kind, label, attrs_json, confidence,
                    evidence_excerpt, module, task_id, timestamp_ms
             FROM observations WHERE scan_run=?1 ORDER BY entity_id",
        )?;
        let rows = stmt.query_map(params![scan_id], row_to_observation)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(ProjectDbError::from)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VulnCandidateRow {
    pub advisory_id: String,
    pub provider: String,
    /// Provider dataset version at lookup time (empty for pre-v3 imports).
    #[allow(clippy::struct_field_names)]
    pub dataset_version: String,
    pub product: String,
    pub matched_version: String,
    pub match_type: String,
    pub outcome: String,
    pub confidence: u8,
    pub severity: String,
    pub host: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VulnHistoryRow {
    advisory_id: String,
    provider: String,
    dataset_version: String,
    product: String,
    matched_version: String,
    outcome: String,
    confidence: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsCandidateRow {
    pub family: String,
    pub generation: String,
    pub variant: String,
    pub confidence: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCandidateRow {
    pub role: String,
    pub vendor: String,
    pub model: String,
    pub role_confidence: u8,
    pub vendor_confidence: u8,
    pub model_confidence: u8,
}

// ---------------- TLS posture observations ----------------

/// One TLS posture fact for a port entity (built from
/// `TlsPostureObserved` events at import time).
#[derive(Debug, Clone)]
pub struct TlsPostureImport {
    pub port_entity: String,
    pub version: String,
    pub cipher: String,
    pub alpn: String,
    pub cert_id: String,
}

/// Store TLS posture rows for a scan (transactional). Posture joins the
/// port entity it describes; version/cipher/ALPN drift diffs off these.
pub fn store_tls_posture(
    db: &mut ProjectDb,
    scan_id: &str,
    rows: &[TlsObservationImport],
) -> Result<usize, ProjectDbError> {
    validate_id(scan_id, "scan")?;
    let tx = db.conn.transaction()?;
    let mut stored = 0usize;
    for row in rows {
        validate_id(&row.port_entity, "tls port")?;
        if row.version.len() > 32 || row.cipher.len() > 128 || row.alpn.len() > 64 {
            return Err(ProjectDbError::InvalidInput(
                "tls posture field too long".to_owned(),
            ));
        }
        if !row.cert_id.is_empty() {
            validate_id(&row.cert_id, "tls cert")?;
        }
        let attrs = serde_json::json!({
            "version": row.version,
            "cipher": row.cipher,
            "alpn": row.alpn,
            "cert_id": row.cert_id,
        })
        .to_string();
        tx.execute(
            "INSERT INTO observations(scan_run, entity_id, kind, label, attrs_json,
              confidence, evidence_excerpt, module, task_id, timestamp_ms)
             VALUES(?1,?2,'tls_posture',?3,?4,85,'tls handshake posture','rxscan.service','',0)",
            params![
                scan_id,
                row.port_entity,
                format!("tls posture for {}", row.port_entity),
                attrs,
            ],
        )?;
        stored += 1;
    }
    tx.commit()?;
    Ok(stored)
}

// ---------------- attention generation ----------------

/// Thresholds (days) for certificate-expiry attention. Expired is always
/// a warning; nearer horizons escalate deterministically.
#[derive(Debug, Clone, Copy)]
pub struct AttentionThresholds {
    pub expiry_warning_days: u64,
    pub expiry_noteworthy_days: u64,
    pub expiry_info_days: u64,
}

impl Default for AttentionThresholds {
    fn default() -> Self {
        Self {
            expiry_warning_days: 7,
            expiry_noteworthy_days: 30,
            expiry_info_days: 90,
        }
    }
}

/// Ports whose exposure draws higher attention when newly opened.
const REMOTE_MANAGEMENT_PORTS: [u16; 11] =
    [22, 23, 3389, 5900, 5901, 1433, 3306, 5432, 6379, 27017, 161];

/// Deterministic operational attention for one scan: certificate expiry,
/// rotation/new-service/version/TLS changes vs the previous scan,
/// vulnerability candidates, and coverage health. Severity comes only
/// from this policy — no subsystem invents ratings.
///
/// `now_ms` is caller time (milliseconds since epoch); tests pin it.
pub fn generate_attention(
    db: &ProjectDb,
    scan_id: &str,
    prev_scan: Option<&str>,
    now_ms: u64,
    thresholds: AttentionThresholds,
) -> Result<Vec<AttentionEvent>, ProjectDbError> {
    validate_id(scan_id, "scan")?;
    let mut events = Vec::new();
    // Certificate expiry from stored validity epochs.
    let mut stmt = db.conn.prepare(
        "SELECT entity_id, attrs_json FROM observations
         WHERE scan_run=?1 AND kind='certificate'",
    )?;
    let rows = stmt.query_map(params![scan_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (entity_id, attrs_json): (String, String) = row?;
        let attrs: BTreeMap<String, String> = serde_json::from_str(&attrs_json).unwrap_or_default();
        let Some(not_after) = attrs
            .get("not_after_epoch")
            .and_then(|text| text.parse::<i64>().ok())
        else {
            continue;
        };
        let now_sec = (now_ms / 1000) as i64;
        let days_left = (not_after - now_sec).div_euclid(86_400);
        let (severity, title) = if days_left < 0 {
            (
                AttentionSeverity::Warning,
                format!("certificate expired {} days ago", -days_left),
            )
        } else if days_left <= thresholds.expiry_warning_days as i64 {
            (
                AttentionSeverity::Warning,
                format!("certificate expires in {days_left} days"),
            )
        } else if days_left <= thresholds.expiry_noteworthy_days as i64 {
            (
                AttentionSeverity::Noteworthy,
                format!("certificate expires in {days_left} days"),
            )
        } else if days_left <= thresholds.expiry_info_days as i64 {
            (
                AttentionSeverity::Info,
                format!("certificate expires in {days_left} days"),
            )
        } else {
            continue;
        };
        events.push(AttentionEvent {
            category: "certificate_expiry".to_owned(),
            severity,
            entity_id: entity_id.clone(),
            title,
            reason: format!(
                "leaf validity ends {} (observed this scan)",
                attrs.get("not_after").cloned().unwrap_or_default()
            ),
            evidence: vec![format!("cert {entity_id}")],
            scan_run: scan_id.to_owned(),
        });
    }
    // Changes vs the previous scan drive rotation/new/version attention.
    if let Some(previous) = prev_scan {
        let changes = db.diff_scan_runs(previous, scan_id)?;
        for change in &changes {
            let event = match change.change_type {
                ChangeType::Opened => {
                    let remote_mgmt = change
                        .new_value
                        .split(|c: char| !c.is_ascii_digit())
                        .filter_map(|token| token.parse::<u16>().ok())
                        .any(|port| REMOTE_MANAGEMENT_PORTS.contains(&port));
                    AttentionEvent {
                        category: "newly_exposed_service".to_owned(),
                        severity: if remote_mgmt {
                            AttentionSeverity::Warning
                        } else {
                            AttentionSeverity::Noteworthy
                        },
                        entity_id: change.entity_id.clone(),
                        title: format!("newly exposed service: {}", change.new_value),
                        reason: "port observed open with covering scan".to_owned(),
                        evidence: vec![change.evidence.clone()],
                        scan_run: scan_id.to_owned(),
                    }
                }
                ChangeType::Changed if change.old_value.starts_with("certificate ") => {
                    AttentionEvent {
                        category: "certificate_rotation".to_owned(),
                        severity: AttentionSeverity::Info,
                        entity_id: change.entity_id.clone(),
                        title: "certificate rotated".to_owned(),
                        reason: format!("{} → {}", change.old_value, change.new_value),
                        evidence: vec![change.evidence.clone()],
                        scan_run: scan_id.to_owned(),
                    }
                }
                ChangeType::Changed if change.old_value.starts_with("ssh key ") => AttentionEvent {
                    category: "ssh_key_rotation".to_owned(),
                    severity: AttentionSeverity::Noteworthy,
                    entity_id: change.entity_id.clone(),
                    title: "SSH host key rotated".to_owned(),
                    reason: format!("{} → {}", change.old_value, change.new_value),
                    evidence: vec![change.evidence.clone()],
                    scan_run: scan_id.to_owned(),
                },
                ChangeType::Changed if change.old_value.starts_with("version ") => {
                    // Version direction decides severity: upgrades inform,
                    // downgrades merit a closer look (ordering may be
                    // indeterminate — then informational).
                    let direction = version_direction(&change.old_value, &change.new_value);
                    AttentionEvent {
                        category: "software_version_changed".to_owned(),
                        severity: match direction {
                            VersionDirection::Downgrade => AttentionSeverity::Noteworthy,
                            _ => AttentionSeverity::Info,
                        },
                        entity_id: change.entity_id.clone(),
                        title: format!("software version changed: {}", change.new_value),
                        reason: format!("{} → {}", change.old_value, change.new_value),
                        evidence: vec![change.evidence.clone()],
                        scan_run: scan_id.to_owned(),
                    }
                }
                ChangeType::Changed if change.old_value.starts_with("tls ") => AttentionEvent {
                    category: "tls_changed".to_owned(),
                    severity: AttentionSeverity::Noteworthy,
                    entity_id: change.entity_id.clone(),
                    title: format!("TLS posture changed: {}", change.new_value),
                    reason: format!("{} → {}", change.old_value, change.new_value),
                    evidence: vec![change.evidence.clone()],
                    scan_run: scan_id.to_owned(),
                },
                _ => continue,
            };
            events.push(event);
        }
        // Coverage regression: new scan attempted far fewer ports.
        let old_cov = db.coverage_of(previous)?;
        let new_cov = db.coverage_of(scan_id)?;
        let old_ports: u64 = old_cov
            .tcp_attempted
            .values()
            .flatten()
            .map(|(lo, hi)| u64::from(hi.saturating_sub(*lo).saturating_add(1)))
            .sum::<u64>()
            + old_cov
                .udp_attempted
                .values()
                .flatten()
                .map(|(lo, hi)| u64::from(hi.saturating_sub(*lo).saturating_add(1)))
                .sum::<u64>();
        let new_ports: u64 = new_cov
            .tcp_attempted
            .values()
            .flatten()
            .map(|(lo, hi)| u64::from(hi.saturating_sub(*lo).saturating_add(1)))
            .sum::<u64>()
            + new_cov
                .udp_attempted
                .values()
                .flatten()
                .map(|(lo, hi)| u64::from(hi.saturating_sub(*lo).saturating_add(1)))
                .sum::<u64>();
        if old_ports > 0 && new_ports * 2 < old_ports {
            events.push(AttentionEvent {
                category: "coverage_regression".to_owned(),
                severity: AttentionSeverity::Warning,
                entity_id: scan_id.to_owned(),
                title: format!(
                    "scan coverage decreased ({old_ports} → {new_ports} ports attempted)"
                ),
                reason: "missing findings must not be read as closed/disappeared".to_owned(),
                evidence: vec!["coverage comparison across scans".to_owned()],
                scan_run: scan_id.to_owned(),
            });
        }
    }
    // Vulnerability candidates by policy: strong exact matches merit
    // attention; weak/product-only matches stay informational or silent.
    // dataset_version is advisory provenance (v3+); older rows read as "".
    let has_vuln_dataset_version = db.has_vuln_dataset_version();
    let vuln_sql = if has_vuln_dataset_version {
        "SELECT advisory_id, provider, dataset_version, product, matched_version, match_type,
                outcome, confidence, severity, host, endpoint
         FROM vulnerability_candidates WHERE scan_run=?1"
    } else {
        "SELECT advisory_id, provider, product, matched_version, match_type,
                outcome, confidence, severity, host, endpoint
         FROM vulnerability_candidates WHERE scan_run=?1"
    };
    let mut stmt = db.conn.prepare(vuln_sql)?;
    let rows = stmt.query_map(params![scan_id], |row| {
        if has_vuln_dataset_version {
            let confidence: i64 = row.get(7)?;
            Ok((
                row.get::<_, String>(0)?,
                format!("{} {}", row.get::<_, String>(1)?, row.get::<_, String>(2)?)
                    .trim()
                    .to_owned(),
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                confidence.clamp(0, 100) as u8,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
            ))
        } else {
            let confidence: i64 = row.get(6)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                confidence.clamp(0, 100) as u8,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        }
    })?;
    for row in rows {
        let (
            advisory,
            provider,
            product,
            version,
            match_type,
            outcome,
            confidence,
            severity,
            host,
            endpoint,
        ) = row?;
        if outcome != "matched" {
            if outcome == "indeterminate" && confidence >= 60 {
                events.push(AttentionEvent {
                    category: "vulnerability_candidate".to_owned(),
                    severity: AttentionSeverity::Info,
                    entity_id: if host.is_empty() {
                        endpoint.clone()
                    } else {
                        host.clone()
                    },
                    title: format!("potential {advisory} match indeterminate for {product}"),
                    reason: format!("version comparison indeterminate ({version})"),
                    evidence: vec![format!("provider {provider}")],
                    scan_run: scan_id.to_owned(),
                });
            }
            continue;
        }
        let _ = (match_type, severity);
        if confidence >= 80 {
            events.push(AttentionEvent {
                category: "vulnerability_candidate".to_owned(),
                severity: AttentionSeverity::Noteworthy,
                entity_id: if host.is_empty() {
                    endpoint.clone()
                } else {
                    host.clone()
                },
                title: format!("potential {advisory} match for {product} {version}"),
                reason: "exact product/version range match at high confidence".to_owned(),
                evidence: vec![format!("provider {provider}")],
                scan_run: scan_id.to_owned(),
            });
        } else {
            events.push(AttentionEvent {
                category: "vulnerability_candidate".to_owned(),
                severity: AttentionSeverity::Info,
                entity_id: if host.is_empty() {
                    endpoint.clone()
                } else {
                    host.clone()
                },
                title: format!("potential {advisory} match for {product}"),
                reason: "product-level match below exact-evidence threshold".to_owned(),
                evidence: vec![format!("provider {provider}")],
                scan_run: scan_id.to_owned(),
            });
        }
    }
    // Deprecated TLS versions observed this scan.
    let mut stmt = db.conn.prepare(
        "SELECT entity_id, attrs_json FROM observations
         WHERE scan_run=?1 AND kind='tls_posture'",
    )?;
    let rows = stmt.query_map(params![scan_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (entity_id, attrs_json): (String, String) = row?;
        let attrs: BTreeMap<String, String> = serde_json::from_str(&attrs_json).unwrap_or_default();
        if attrs
            .get("version")
            .is_some_and(|version| version == "TLSv1.0" || version == "TLSv1.1")
        {
            events.push(AttentionEvent {
                category: "deprecated_tls".to_owned(),
                severity: AttentionSeverity::Noteworthy,
                entity_id,
                title: format!(
                    "deprecated TLS version observed ({})",
                    attrs.get("version").cloned().unwrap_or_default()
                ),
                reason: "TLS 1.0/1.1 observed in handshake".to_owned(),
                evidence: vec!["tls_posture observation".to_owned()],
                scan_run: scan_id.to_owned(),
            });
        }
    }
    events.sort_by(|a, b| {
        (a.severity.as_str(), &a.category, &a.entity_id).cmp(&(
            b.severity.as_str(),
            &b.category,
            &b.entity_id,
        ))
    });
    // Bounded attention output: deterministic order above, visible
    // truncation (callers persist what is returned; no silent growth).
    const MAX_ATTENTION_EVENTS: usize = 512;
    if events.len() > MAX_ATTENTION_EVENTS {
        events.truncate(MAX_ATTENTION_EVENTS);
    }
    Ok(events)
}

enum VersionDirection {
    Upgrade,
    Downgrade,
    Unknown,
}

fn version_direction(old_value: &str, new_value: &str) -> VersionDirection {
    // Values look like "version 1.24.0": compare trailing tokens.
    let token = |text: &str| {
        text.split_whitespace()
            .last()
            .unwrap_or("")
            .trim()
            .to_owned()
    };
    let (Some(old), Some(new)) = (
        crate::vuln::Version::parse(&token(old_value)),
        crate::vuln::Version::parse(&token(new_value)),
    ) else {
        return VersionDirection::Unknown;
    };
    match crate::vuln::compare_versions(&old, &new) {
        Some(std::cmp::Ordering::Less) => VersionDirection::Upgrade,
        Some(std::cmp::Ordering::Greater) => VersionDirection::Downgrade,
        _ => VersionDirection::Unknown,
    }
}
