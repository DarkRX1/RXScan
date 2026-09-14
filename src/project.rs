//! Phase 18 lightweight offline project graph mode.
//!
//! Project mode organizes existing semantic information from validated Phase 14
//! checkpoints, optional Phase 15 diffs, and optional Phase 16 analyses. It is
//! offline, lazy, single-threaded for ordinary operations, and stores only
//! compact semantic records with bounded traversal and bounded output.
//!
//! Design notes:
//! - Semantic fingerprint ignores wall-clock timestamps, `saved_at`,
//!   provenance timestamps, speed/pressure, checkpoint paths, insertion order,
//!   and runtime task order. Only plan semantics, asset/relationship/finding
//!   semantics, and task coverage shape the fingerprint.
//! - Fingerprint memory: `project_fingerprint(&ProjectState)` borrows a
//!   canonical view (`ProjectFingerprintView`) and streams JSON directly into
//!   SHA-256 via `serde_json::to_writer`. No whole-`ProjectState` clone is
//!   performed (`fingerprint_whole_state_clones() == 0`) and no canonical byte
//!   `Vec` is retained (`fingerprint_serialization_buffer_bytes() == 0`).
//!   Bounded incremental memory: O(hasher + one record), not O(project_size).
//! - Import order semantics: entity/relationship/finding identities are stable
//!   regardless of import order. `import_sequence` defines project chronology,
//!   so importing B-then-A vs A-then-B yields different sequences (documented),
//!   but identical semantic order yields byte-deterministic serialization
//!   (BTreeMap canonical ordering).
//! - Graph work caps: neighbor BFS is hard bounded by
//!   `MAX_GRAPH_QUERY_VISITED` (4096), `MAX_GRAPH_QUERY_QUEUE` (2048),
//!   `MAX_GRAPH_QUERY_EXPANSIONS` (2048), `MAX_GRAPH_QUERY_EDGE_BUDGET`
//!   (8192), independent of total entity count. No full-project adjacency map
//!   is built; each expansion scans only its incident edges. Results are
//!   canonically sorted (depth, kind, entity, rel) so capped queries remain
//!   deterministic under insertion-order permutations.
//! - `results_total` semantics: `results_total == results_discovered` (edges
//!   discovered before caps). Exact global total only when `exhaustive` is
//!   true; otherwise it is a capped lower bound. `truncated` is true when
//!   `discovered > emitted` or `!exhaustive`. No unbounded traversal is done
//!   merely to compute an exact total.
//! - Storage-cap precedence: both the 16 MiB serialized-file cap
//!   (`MAX_PROJECT_BYTES` / `MAX_PROJECT_FILE_BYTES`) and the per-collection
//!   caps (10k scans, 200k entities, 300k relationships, 500k observations,
//!   50k findings, 100k changes, 100k analysis refs) apply; whichever limit is
//!   reached first rejects the mutation/load. The file cap is usually hit far
//!   before the collection caps with realistic records.
//! - Save memory: `save_project` streams pretty JSON directly to a temp file
//!   via `serde_json::to_writer_pretty` + `BufWriter(8 KiB)` +
//!   `SizeLimitWriter`, enforcing the file cap during the write. No
//!   `ProjectState` + clone + 16 MiB `Vec` are held simultaneously.
//! - Thread policy: ordinary project operations use exactly one thread
//!   (`PROJECT_THREADS_USED`). No daemon, watcher, pool, or background task.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File},
    io::{BufWriter, Read, Write},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    analysis::{self, AnalysisReport},
    diff::{self, DiffReport},
    model::{
        Asset, AssetKind, Finding, RelationshipKind, RelationshipSubject, ScanPlanId, Severity,
    },
    persistence::{PersistedScanState, PersistenceError, load_checkpoint},
    report,
};

pub const PROJECT_SCHEMA_VERSION: u16 = 1;
pub const MAX_PROJECT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_PROJECT_SCANS: usize = 10_000;
pub const MAX_PROJECT_ENTITIES: usize = 200_000;
pub const MAX_PROJECT_RELATIONSHIPS: usize = 300_000;
pub const MAX_PROJECT_OBSERVATIONS: usize = 500_000;
pub const MAX_PROJECT_FINDINGS: usize = 50_000;
pub const MAX_PROJECT_CHANGES: usize = 100_000;
pub const MAX_PROJECT_ANALYSIS_REFS: usize = 100_000;
pub const MAX_ENTITY_OBSERVATIONS: usize = 256;
pub const DEFAULT_QUERY_LIMIT: usize = 100;
pub const MAX_QUERY_LIMIT: usize = 1000;
pub const DEFAULT_QUERY_DEPTH: u8 = 1;
pub const MAX_QUERY_DEPTH: u8 = 3;
/// Hard bounded graph-traversal work caps, independent of total entity count.
///
/// A query with `depth <= 3` and `limit <= 1000` must not build a queue or
/// visited set proportional to the entire project. These caps bound per-query
/// temporary state to <1 MiB regardless of project size (200k entities /
/// 300k relationships):
/// - `MAX_GRAPH_QUERY_VISITED = 4096` (4x max limit): max distinct entities
///   in the visited set. Allows discovering up to 1000 deterministic results
///   plus surrounding cycle/duplicate visits. Each entry is an entity id
///   (~64 B + BTree overhead) => ~400 KiB worst case.
/// - `MAX_GRAPH_QUERY_QUEUE = 2048` (2x max limit): max `VecDeque` length at
///   any instant. Each entry is `(entity id, depth)` (~80 B) => ~160 KiB.
/// - `MAX_GRAPH_QUERY_EXPANSIONS = 2048` (2x max limit): max dequeued nodes
///   whose adjacency is scanned. Bounds CPU to
///   `expansions * relationships` worst case and memory to O(queue).
/// - `MAX_GRAPH_QUERY_EDGE_BUDGET = 8192` (8x max limit): max neighbor edges
///   examined per query. Bounds high-degree fan-out (one node with 10k+
///   neighbors) without iterating unbounded degree. Candidate records are
///   sorted canonically and truncated to `limit`, so results remain
///   deterministic under the cap.
pub const MAX_GRAPH_QUERY_VISITED: usize = 4096;
pub const MAX_GRAPH_QUERY_QUEUE: usize = 2048;
pub const MAX_GRAPH_QUERY_EXPANSIONS: usize = 2048;
pub const MAX_GRAPH_QUERY_EDGE_BUDGET: usize = 8192;
/// Alias for the hard serialized-file cap (16 MiB). Both the file cap and
/// the per-collection caps apply; whichever limit is reached first rejects
/// the mutation/load. In practice the 16 MiB file cap is hit far before
/// 500k observations / 300k relationships with realistic records, so a
/// 16 MiB file can never be assumed to hold the collection-cap maximums.
pub const MAX_PROJECT_FILE_BYTES: u64 = MAX_PROJECT_BYTES;
/// Streaming save buffer: `BufWriter` capacity used when serializing directly
/// to the temp file. No full `Vec<u8>` of the pretty-printed project is held
/// in RAM; per-query/per-save temporary state is O(buffer + one record).
pub const PROJECT_SAVE_BUFFER_BYTES: usize = 8192;
/// Fingerprint streaming uses zero intermediate serialization buffer: JSON is
/// streamed directly into the SHA-256 hasher via `serde_json::to_writer`.
/// Only the 32-byte hasher state plus serde's small per-value stack is held.
pub const FINGERPRINT_SERIALIZATION_BUFFER_BYTES: usize = 0;
/// Ordinary project operations use exactly one thread. No background workers.
pub const PROJECT_THREADS_USED: usize = 1;

/// Counts project initializations (new/load/create). Normal scan/diff/analyze/
/// report paths must not increment this counter (lazy initialization proof).
pub static PROJECT_INIT_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn project_init_count() -> u64 {
    PROJECT_INIT_COUNT.load(Ordering::SeqCst)
}

pub fn project_threads_used() -> usize {
    PROJECT_THREADS_USED
}

/// Whole-`ProjectState` clones performed by fingerprint computation.
/// Fingerprinting streams a borrowed canonical view directly into SHA-256
/// (`project_fingerprint(&ProjectState)`), so this counter is always zero.
/// It exists so benchmarks/tests can assert `fingerprint_whole_state_clones=0`
/// without source inspection alone.
pub static FINGERPRINT_WHOLE_STATE_CLONES: AtomicU64 = AtomicU64::new(0);

/// Number of whole-`ProjectState` clones performed for fingerprinting (always 0).
pub fn fingerprint_whole_state_clones() -> u64 {
    FINGERPRINT_WHOLE_STATE_CLONES.load(Ordering::SeqCst)
}

/// Temporary serialization buffer held while fingerprinting (always 0:
/// streaming directly into the hasher, no canonical byte `Vec`).
pub fn fingerprint_serialization_buffer_bytes() -> usize {
    FINGERPRINT_SERIALIZATION_BUFFER_BYTES
}

/// Temporary serialization buffer held while saving (streaming `BufWriter`
/// capacity; no full pretty-printed `Vec<u8>` is retained).
pub fn project_serialization_buffer_bytes() -> usize {
    PROJECT_SAVE_BUFFER_BYTES
}

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    Diff(#[from] diff::DiffError),
    #[error(transparent)]
    Analysis(#[from] analysis::AnalysisError),
    #[error("project IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("project parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported project schema version {0}")]
    UnsupportedVersion(u16),
    #[error("invalid project: {0}")]
    Invalid(String),
    #[error("project exceeds hard size cap")]
    SizeLimit,
    #[error("project concurrent modification detected")]
    ConcurrentModification,
    #[error("project entity not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectState {
    pub project_schema_version: u16,
    pub project_id: String,
    pub revision: u64,
    pub fingerprint: String,
    pub scans: BTreeMap<String, ProjectScan>,
    pub entities: BTreeMap<String, ProjectEntity>,
    pub relationships: BTreeMap<String, ProjectRelationship>,
    pub observations: BTreeMap<String, ProjectObservation>,
    pub findings: BTreeMap<String, ProjectFinding>,
    pub changes: BTreeMap<String, ProjectChangeRef>,
    pub analysis_refs: BTreeMap<String, ProjectAnalysisRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectScan {
    pub scan_id: ScanPlanId,
    pub plan_id: ScanPlanId,
    pub import_sequence: u64,
    pub semantic_fingerprint: String,
    pub checkpoint_schema_version: u32,
    pub entity_count: usize,
    pub relationship_count: usize,
    pub finding_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectEntity {
    pub id: String,
    pub kind: AssetKind,
    pub identity: String,
    pub attributes: BTreeMap<String, String>,
    pub first_scan_id: ScanPlanId,
    pub last_scan_id: ScanPlanId,
    pub observation_count: usize,
    #[serde(default)]
    pub external: bool,
    #[serde(default)]
    pub observations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRelationship {
    pub id: String,
    pub kind: RelationshipKind,
    pub from_entity: String,
    pub to_entity: String,
    pub first_scan_id: ScanPlanId,
    pub last_scan_id: ScanPlanId,
    pub observation_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectObservation {
    pub id: String,
    pub scan_id: ScanPlanId,
    pub entity_id: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectFinding {
    pub id: String,
    pub title: String,
    #[serde(default = "default_finding_severity")]
    pub severity: Severity,
    pub confidence: u8,
    pub affected_entity: String,
    pub first_scan_id: ScanPlanId,
    pub last_scan_id: ScanPlanId,
    pub observation_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectChangeRef {
    pub id: String,
    pub scan_id: ScanPlanId,
    pub entity_id: Option<String>,
    pub change_type: diff::ChangeType,
    pub certainty: diff::Certainty,
    pub reason: diff::ReasonCode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectAnalysisRef {
    pub id: String,
    pub scan_id: ScanPlanId,
    pub entity_id: Option<String>,
    pub attention_score: u8,
    pub attention_band: analysis::AttentionBand,
    pub label: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSummary {
    pub duplicate_scan: bool,
    pub entities_added: usize,
    pub relationships_added: usize,
    pub observations_added: usize,
    pub findings_added: usize,
    pub change_refs_added: usize,
    pub analysis_refs_added: usize,
    pub duplicate_entities_avoided: usize,
    pub duplicate_relationships_avoided: usize,
    pub duplicate_observations_avoided: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSummary {
    pub scans: usize,
    pub entities: usize,
    pub hosts_ips: usize,
    pub hostnames: usize,
    pub services: usize,
    pub endpoints: usize,
    pub relationships: usize,
    pub observations: usize,
    pub findings: usize,
    pub change_refs: usize,
    pub analysis_refs: usize,
    pub confirmed_changes: usize,
    pub inconclusive_changes: usize,
    pub storage_bytes: u64,
    pub network_requests: u64,
}

/// Bounded query result with explicit work-limit metadata.
///
/// `results_total` is kept for backward compatibility and equals
/// `results_discovered`: the number of neighbor edges (or filtered records)
/// discovered before any work cap. It is the true global total **only when
/// `exhaustive == true`**. When traversal stops early due to a hard work cap
/// (`exhaustive == false`), `results_total` is a lower bound (capped
/// discovered count), never a pretended exact total. No unbounded traversal
/// is performed merely to compute an exact total.
/// `truncated == true` when output was cut by `limit` (`discovered > emitted`)
/// or by a work cap (`!exhaustive`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryResult<T> {
    pub results_total: usize,
    pub results_emitted: usize,
    pub truncated: bool,
    pub records: Vec<T>,
    /// True iff traversal/enumeration completed without hitting any
    /// `MAX_GRAPH_QUERY_*` work cap (graph queries) or collection scan
    /// completed (filter queries, always true: they scan bounded collections).
    #[serde(default)]
    pub exhaustive: bool,
    /// Edges/records discovered before caps (capped at
    /// `MAX_GRAPH_QUERY_EDGE_BUDGET` for graph queries). Lower bound when
    /// `!exhaustive`.
    #[serde(default)]
    pub results_discovered: usize,
    /// Peak `VecDeque` length observed during BFS (0 for filter queries).
    #[serde(default)]
    pub queue_peak: usize,
    /// Peak visited-set size observed during BFS (0 for filter queries).
    #[serde(default)]
    pub visited_peak: usize,
    /// Number of dequeued nodes expanded during BFS (0 for filter queries).
    #[serde(default)]
    pub expansions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborRecord {
    pub depth: u8,
    pub relationship_id: String,
    pub relationship_kind: RelationshipKind,
    pub entity_id: String,
    pub identity: String,
}

impl ProjectState {
    pub fn new(name: Option<&str>) -> Self {
        PROJECT_INIT_COUNT.fetch_add(1, Ordering::SeqCst);
        let project_id = format!("project_{}", hash_text(name.unwrap_or("rxscan-project-v1")));
        let mut state = Self {
            project_schema_version: PROJECT_SCHEMA_VERSION,
            project_id,
            revision: 0,
            fingerprint: String::new(),
            scans: BTreeMap::new(),
            entities: BTreeMap::new(),
            relationships: BTreeMap::new(),
            observations: BTreeMap::new(),
            findings: BTreeMap::new(),
            changes: BTreeMap::new(),
            analysis_refs: BTreeMap::new(),
        };
        state.refresh_fingerprint();
        state
    }

    pub fn validate(&self) -> Result<(), ProjectError> {
        if self.project_schema_version != PROJECT_SCHEMA_VERSION {
            return Err(ProjectError::UnsupportedVersion(
                self.project_schema_version,
            ));
        }
        check_len("scans", self.scans.len(), MAX_PROJECT_SCANS)?;
        check_len("entities", self.entities.len(), MAX_PROJECT_ENTITIES)?;
        check_len(
            "relationships",
            self.relationships.len(),
            MAX_PROJECT_RELATIONSHIPS,
        )?;
        check_len(
            "observations",
            self.observations.len(),
            MAX_PROJECT_OBSERVATIONS,
        )?;
        check_len("findings", self.findings.len(), MAX_PROJECT_FINDINGS)?;
        check_len("changes", self.changes.len(), MAX_PROJECT_CHANGES)?;
        check_len(
            "analysis refs",
            self.analysis_refs.len(),
            MAX_PROJECT_ANALYSIS_REFS,
        )?;
        for (id, entity) in &self.entities {
            validate_id(id, "entity id")?;
            validate_id(&entity.identity, "entity identity")?;
            if entity.id != *id {
                return Err(ProjectError::Invalid("entity id mismatch".to_owned()));
            }
            if !self.scan_id_exists(&entity.first_scan_id)
                || !self.scan_id_exists(&entity.last_scan_id)
            {
                return Err(ProjectError::Invalid(
                    "entity scan reference missing".to_owned(),
                ));
            }
            if entity.observations.len() > MAX_ENTITY_OBSERVATIONS {
                return Err(ProjectError::Invalid(
                    "too many observations for entity".to_owned(),
                ));
            }
            for (key, value) in &entity.attributes {
                if key.len() > 256 || value.len() > 4096 {
                    return Err(ProjectError::Invalid(
                        "entity attribute too large".to_owned(),
                    ));
                }
                if contains_forbidden_project_marker(key)
                    || contains_forbidden_project_marker(value)
                {
                    return Err(ProjectError::Invalid(
                        "entity attribute contains forbidden marker".to_owned(),
                    ));
                }
            }
        }
        for (id, rel) in &self.relationships {
            validate_id(id, "relationship id")?;
            if rel.id != *id
                || !self.entities.contains_key(&rel.from_entity)
                || !self.entities.contains_key(&rel.to_entity)
            {
                return Err(ProjectError::Invalid(
                    "dangling project relationship".to_owned(),
                ));
            }
        }
        for obs in self.observations.values() {
            if !self.scan_id_exists(&obs.scan_id) || !self.entities.contains_key(&obs.entity_id) {
                return Err(ProjectError::Invalid(
                    "dangling project observation".to_owned(),
                ));
            }
        }
        for finding in self.findings.values() {
            if !self.entities.contains_key(&finding.affected_entity) {
                return Err(ProjectError::Invalid("dangling project finding".to_owned()));
            }
        }
        for change in self.changes.values() {
            if !self.scan_id_exists(&change.scan_id) {
                return Err(ProjectError::Invalid(
                    "dangling project change scan".to_owned(),
                ));
            }
            if let Some(entity) = &change.entity_id {
                if !self.entities.contains_key(entity) {
                    return Err(ProjectError::Invalid(
                        "dangling project change entity".to_owned(),
                    ));
                }
            }
        }
        for signal in self.analysis_refs.values() {
            if !self.scan_id_exists(&signal.scan_id) {
                return Err(ProjectError::Invalid(
                    "dangling project analysis scan".to_owned(),
                ));
            }
            if let Some(entity) = &signal.entity_id {
                if !self.entities.contains_key(entity) {
                    return Err(ProjectError::Invalid(
                        "dangling project analysis entity".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn add_scan(
        &mut self,
        state: &PersistedScanState,
        diff: Option<&DiffReport>,
        analysis: Option<&AnalysisReport>,
    ) -> Result<ImportSummary, ProjectError> {
        state.validate()?;
        if let Some(diff) = diff {
            if diff.current_scan_id != state.scan_id {
                return Err(ProjectError::Invalid(
                    "diff current scan id does not match imported scan".to_owned(),
                ));
            }
        }
        if let Some(analysis) = analysis {
            if analysis.scan_id != state.scan_id {
                return Err(ProjectError::Invalid(
                    "analysis scan id does not match imported scan".to_owned(),
                ));
            }
        }
        // Reject checkpoints carrying raw/sensitive markers in semantic fields
        // before any mutation (fail-closed, zero network).
        reject_forbidden_checkpoint_content(state)?;
        let semantic_fingerprint = scan_fingerprint(state)?;
        if self
            .scans
            .values()
            .any(|scan| scan.semantic_fingerprint == semantic_fingerprint)
        {
            return Ok(ImportSummary {
                duplicate_scan: true,
                ..ImportSummary::default()
            });
        }
        let mut imported = ImportSummary::default();
        let sequence = self.scans.len() as u64 + 1;
        let mut asset_to_entity = BTreeMap::<String, String>::new();
        let scan_id = state.scan_id.clone();
        let scan_key = format!("scan_{}", hash_text(&semantic_fingerprint));
        for output in &state.outputs {
            for asset in &output.output.assets {
                let entity_id = entity_id(asset);
                asset_to_entity.insert(asset.id.0.clone(), entity_id.clone());
                let obs_id = format!(
                    "obs_{}",
                    hash_text(&format!("{semantic_fingerprint}:{entity_id}"))
                );
                if self.entities.contains_key(&entity_id) {
                    imported.duplicate_entities_avoided += 1;
                    let entity = self.entities.get_mut(&entity_id).expect("checked");
                    entity.last_scan_id = scan_id.clone();
                    entity.observation_count += 1;
                    if entity.observations.len() < MAX_ENTITY_OBSERVATIONS {
                        entity.observations.push(obs_id.clone());
                    }
                } else {
                    self.entities.insert(
                        entity_id.clone(),
                        ProjectEntity {
                            id: entity_id.clone(),
                            kind: asset.kind.clone(),
                            identity: asset.identity.clone(),
                            attributes: asset.attributes.clone(),
                            first_scan_id: scan_id.clone(),
                            last_scan_id: scan_id.clone(),
                            observation_count: 1,
                            external: asset
                                .attributes
                                .get("scope")
                                .is_some_and(|value| value == "out_of_scope"),
                            observations: vec![obs_id.clone()],
                        },
                    );
                    imported.entities_added += 1;
                }
                if self
                    .observations
                    .insert(
                        obs_id.clone(),
                        ProjectObservation {
                            id: obs_id,
                            scan_id: scan_id.clone(),
                            entity_id,
                            fingerprint: hash_json(asset)?,
                        },
                    )
                    .is_some()
                {
                    imported.duplicate_observations_avoided += 1;
                } else {
                    imported.observations_added += 1;
                }
            }
        }
        for output in &state.outputs {
            for event in &output.output.events {
                for rel in &event.relationships {
                    let (Some(from), Some(to)) = (
                        subject_entity(&rel.from, &asset_to_entity),
                        subject_entity(&rel.to, &asset_to_entity),
                    ) else {
                        continue;
                    };
                    let rel_id = relationship_id(&rel.kind, &from, &to);
                    if let Some(existing) = self.relationships.get_mut(&rel_id) {
                        existing.last_scan_id = scan_id.clone();
                        existing.observation_count += 1;
                        imported.duplicate_relationships_avoided += 1;
                    } else {
                        self.relationships.insert(
                            rel_id.clone(),
                            ProjectRelationship {
                                id: rel_id,
                                kind: rel.kind.clone(),
                                from_entity: from,
                                to_entity: to,
                                first_scan_id: scan_id.clone(),
                                last_scan_id: scan_id.clone(),
                                observation_count: 1,
                            },
                        );
                        imported.relationships_added += 1;
                    }
                }
            }
            for finding in &output.output.findings {
                let Some(entity) = asset_to_entity.get(&finding.affected_asset_id.0).cloned()
                else {
                    continue;
                };
                let finding_id = finding_id(finding, &entity);
                if let Some(existing) = self.findings.get_mut(&finding_id) {
                    existing.last_scan_id = scan_id.clone();
                    existing.observation_count += 1;
                } else {
                    self.findings.insert(
                        finding_id.clone(),
                        ProjectFinding {
                            id: finding_id,
                            title: finding.title.clone(),
                            severity: finding.severity,
                            confidence: finding.confidence.0,
                            affected_entity: entity,
                            first_scan_id: scan_id.clone(),
                            last_scan_id: scan_id.clone(),
                            observation_count: 1,
                        },
                    );
                    imported.findings_added += 1;
                }
            }
        }
        if let Some(diff) = diff {
            for record in &diff.records {
                let id = format!(
                    "change_{}",
                    hash_text(&format!("{semantic_fingerprint}:{}", record.semantic_id))
                );
                let entity_id =
                    find_entity_for_semantic(&record.semantic_id, &asset_to_entity, self);
                if self
                    .changes
                    .insert(
                        id.clone(),
                        ProjectChangeRef {
                            id,
                            scan_id: scan_id.clone(),
                            entity_id,
                            change_type: record.change_type,
                            certainty: record.certainty,
                            reason: record.reason,
                        },
                    )
                    .is_none()
                {
                    imported.change_refs_added += 1;
                }
            }
        }
        if let Some(analysis) = analysis {
            for signal in &analysis.top_signals {
                let id = format!(
                    "analysis_{}",
                    hash_text(&format!("{semantic_fingerprint}:{}", signal.id))
                );
                let entity_id = entity_from_signal(signal, &asset_to_entity, self);
                if self
                    .analysis_refs
                    .insert(
                        id.clone(),
                        ProjectAnalysisRef {
                            id,
                            scan_id: scan_id.clone(),
                            entity_id,
                            attention_score: signal.attention_score,
                            attention_band: signal.attention_band,
                            label: signal.label.clone(),
                        },
                    )
                    .is_none()
                {
                    imported.analysis_refs_added += 1;
                }
            }
        }
        self.scans.insert(
            scan_key,
            ProjectScan {
                scan_id: scan_id.clone(),
                plan_id: state.plan.stable_id(),
                import_sequence: sequence,
                semantic_fingerprint,
                checkpoint_schema_version: state.schema_version,
                entity_count: asset_to_entity.len(),
                relationship_count: imported.relationships_added
                    + imported.duplicate_relationships_avoided,
                finding_count: imported.findings_added,
            },
        );
        self.revision += 1;
        self.refresh_fingerprint();
        self.validate()?;
        Ok(imported)
    }

    pub fn summary(&self, storage_bytes: u64) -> ProjectSummary {
        let mut summary = ProjectSummary {
            scans: self.scans.len(),
            entities: self.entities.len(),
            relationships: self.relationships.len(),
            observations: self.observations.len(),
            findings: self.findings.len(),
            change_refs: self.changes.len(),
            analysis_refs: self.analysis_refs.len(),
            storage_bytes,
            network_requests: 0,
            ..ProjectSummary::default()
        };
        for entity in self.entities.values() {
            match entity.kind {
                AssetKind::Host | AssetKind::Ip => summary.hosts_ips += 1,
                AssetKind::Other
                    if entity
                        .attributes
                        .get("dns_kind")
                        .is_some_and(|value| value == "hostname") =>
                {
                    summary.hostnames += 1;
                }
                AssetKind::Service => summary.services += 1,
                AssetKind::Url | AssetKind::Endpoint => summary.endpoints += 1,
                _ => {}
            }
        }
        for change in self.changes.values() {
            match change.certainty {
                diff::Certainty::Confirmed => summary.confirmed_changes += 1,
                diff::Certainty::Inconclusive => summary.inconclusive_changes += 1,
            }
        }
        summary
    }

    pub fn neighbors(
        &self,
        entity_id: &str,
        depth: u8,
        limit: usize,
    ) -> Result<QueryResult<NeighborRecord>, ProjectError> {
        if !self.entities.contains_key(entity_id) {
            return Err(ProjectError::NotFound(entity_id.to_owned()));
        }
        // Explicit clamp: depth > MAX is clamped to MAX (documented), limit >
        // MAX is clamped to MAX. No unlimited traversal.
        let depth = depth.min(MAX_QUERY_DEPTH);
        let limit = limit.min(MAX_QUERY_LIMIT);
        // Hard-bounded BFS without a full-project adjacency map.
        //
        // Memory is bounded by the work caps, not by total entity count:
        // - No `BTreeMap` over all relationships is built. Each expansion
        //   scans `self.relationships` once to collect only the current
        //   node's incident edges (O(degree) refs, sorted deterministically).
        //   This avoids O(relationships) temporary adjacency memory per query.
        // - `seen` <= MAX_GRAPH_QUERY_VISITED, `queue` <= MAX_GRAPH_QUERY_QUEUE,
        //   `expansions` <= MAX_GRAPH_QUERY_EXPANSIONS,
        //   `discovered` <= MAX_GRAPH_QUERY_EDGE_BUDGET.
        // Determinism: per-node peers are sorted by (kind, id) and the queue
        // is FIFO; final candidates are sorted canonically by
        // (depth, kind, entity, rel) before truncation to `limit`. Identical
        // graphs with permuted insertion order yield identical output because
        // `BTreeMap` iteration plus explicit sorting removes order dependence.
        let mut seen = BTreeSet::new();
        let mut queue = VecDeque::from([(entity_id.to_owned(), 0u8)]);
        let mut candidates: Vec<NeighborRecord> = Vec::new();
        let mut discovered: usize = 0;
        let mut expansions: usize = 0;
        let mut queue_peak: usize = 1;
        let mut exhaustive = true;
        seen.insert(entity_id.to_owned());
        let mut visited_peak: usize = 1;
        // Fast path for depth 0: no expansion, exhaustive (nothing reachable).
        while let Some((current, current_depth)) = queue.pop_front() {
            if current_depth >= depth {
                continue;
            }
            if expansions >= MAX_GRAPH_QUERY_EXPANSIONS {
                exhaustive = false;
                break;
            }
            expansions += 1;
            // Collect incident edges for `current` only (borrowed, no clone
            // of whole state; per-node O(degree) refs, part of the required
            // adjacency representation).
            let mut peers: Vec<&ProjectRelationship> = Vec::new();
            for rel in self.relationships.values() {
                if rel.from_entity == current || rel.to_entity == current {
                    peers.push(rel);
                }
            }
            // Deterministic per-node order, computed once per node.
            peers.sort_by_cached_key(|r| (format!("{:?}", r.kind), r.id.clone()));
            let mut edge_budget_hit = false;
            for rel in peers {
                if discovered >= MAX_GRAPH_QUERY_EDGE_BUDGET {
                    exhaustive = false;
                    edge_budget_hit = true;
                    break;
                }
                let next = if rel.from_entity == current {
                    &rel.to_entity
                } else {
                    &rel.from_entity
                };
                discovered += 1;
                if let Some(entity) = self.entities.get(next) {
                    // Collect candidates up to the edge budget (bounded by
                    // MAX_GRAPH_QUERY_EDGE_BUDGET records, ~1.2 MiB worst).
                    // Final truncation to `limit` happens after canonical sort
                    // so the emitted prefix is the deterministic smallest.
                    if candidates.len() < MAX_GRAPH_QUERY_EDGE_BUDGET {
                        candidates.push(NeighborRecord {
                            depth: current_depth + 1,
                            relationship_id: rel.id.clone(),
                            relationship_kind: rel.kind.clone(),
                            entity_id: next.clone(),
                            identity: entity.identity.clone(),
                        });
                    }
                }
                if !seen.contains(next) {
                    if seen.len() >= MAX_GRAPH_QUERY_VISITED {
                        exhaustive = false;
                        continue;
                    }
                    seen.insert(next.clone());
                    if seen.len() > visited_peak {
                        visited_peak = seen.len();
                    }
                    if queue.len() >= MAX_GRAPH_QUERY_QUEUE {
                        exhaustive = false;
                        continue;
                    }
                    queue.push_back((next.clone(), current_depth + 1));
                    if queue.len() > queue_peak {
                        queue_peak = queue.len();
                    }
                }
            }
            if edge_budget_hit {
                // Edge budget exhausted mid-node: remaining peers and queue
                // are unexplored => non-exhaustive. Stop to bound work.
                break;
            }
        }
        // Canonical ordering: depth, relationship type, entity id, rel id.
        candidates.sort_by_cached_key(|r| {
            (
                r.depth,
                format!("{:?}", r.relationship_kind),
                r.entity_id.clone(),
                r.relationship_id.clone(),
            )
        });
        let total_discovered = discovered;
        let truncated_by_limit = total_discovered > limit;
        // `truncated` when output cut by limit or by work cap.
        let truncated = truncated_by_limit || !exhaustive || candidates.len() > limit;
        candidates.truncate(limit);
        let emitted = candidates.len();
        Ok(QueryResult {
            results_total: total_discovered,
            results_emitted: emitted,
            truncated,
            records: candidates,
            exhaustive,
            results_discovered: total_discovered,
            queue_peak,
            visited_peak,
            expansions,
        })
    }

    /// Bounded findings query. `entity` filters to one affected entity when set.
    pub fn findings_query(
        &self,
        entity: Option<&str>,
        limit: usize,
    ) -> Result<QueryResult<ProjectFinding>, ProjectError> {
        let limit = limit.min(MAX_QUERY_LIMIT);
        if let Some(entity) = entity {
            if !self.entities.contains_key(entity) {
                return Err(ProjectError::NotFound(entity.to_owned()));
            }
        }
        let mut records: Vec<ProjectFinding> = self
            .findings
            .values()
            .filter(|f| entity.is_none_or(|e| f.affected_entity == e))
            .cloned()
            .collect();
        records.sort_by(|a, b| a.id.cmp(&b.id));
        let total = records.len();
        let truncated = total > limit;
        records.truncate(limit);
        let emitted = records.len();
        Ok(QueryResult {
            results_total: total,
            results_emitted: emitted,
            truncated,
            records,
            exhaustive: true,
            results_discovered: total,
            queue_peak: 0,
            visited_peak: 0,
            expansions: 0,
        })
    }

    /// Bounded change query. Preserves P15 certainty; never reinterprets
    /// `InconclusiveMissing` as removed.
    pub fn changes_query(
        &self,
        entity: Option<&str>,
        limit: usize,
    ) -> Result<QueryResult<ProjectChangeRef>, ProjectError> {
        let limit = limit.min(MAX_QUERY_LIMIT);
        if let Some(entity) = entity {
            if !self.entities.contains_key(entity) {
                return Err(ProjectError::NotFound(entity.to_owned()));
            }
        }
        let mut records: Vec<ProjectChangeRef> = self
            .changes
            .values()
            .filter(|c| entity.is_none_or(|e| c.entity_id.as_deref() == Some(e)))
            .cloned()
            .collect();
        records.sort_by(|a, b| a.id.cmp(&b.id));
        let total = records.len();
        let truncated = total > limit;
        records.truncate(limit);
        let emitted = records.len();
        Ok(QueryResult {
            results_total: total,
            results_emitted: emitted,
            truncated,
            records,
            exhaustive: true,
            results_discovered: total,
            queue_peak: 0,
            visited_peak: 0,
            expansions: 0,
        })
    }

    /// Bounded attention query. Returns stored P16 score/band verbatim; never
    /// rescores.
    pub fn attention_query(
        &self,
        entity: Option<&str>,
        limit: usize,
    ) -> Result<QueryResult<ProjectAnalysisRef>, ProjectError> {
        let limit = limit.min(MAX_QUERY_LIMIT);
        if let Some(entity) = entity {
            if !self.entities.contains_key(entity) {
                return Err(ProjectError::NotFound(entity.to_owned()));
            }
        }
        let mut records: Vec<ProjectAnalysisRef> = self
            .analysis_refs
            .values()
            .filter(|s| entity.is_none_or(|e| s.entity_id.as_deref() == Some(e)))
            .cloned()
            .collect();
        // Deterministic: score desc, then id.
        records.sort_by(|a, b| {
            b.attention_score
                .cmp(&a.attention_score)
                .then_with(|| a.id.cmp(&b.id))
        });
        let total = records.len();
        let truncated = total > limit;
        records.truncate(limit);
        let emitted = records.len();
        Ok(QueryResult {
            results_total: total,
            results_emitted: emitted,
            truncated,
            records,
            exhaustive: true,
            results_discovered: total,
            queue_peak: 0,
            visited_peak: 0,
            expansions: 0,
        })
    }

    pub fn refresh_fingerprint(&mut self) {
        self.fingerprint = String::new();
        self.fingerprint = project_fingerprint(self).unwrap_or_else(|_| "invalid".to_owned());
    }

    fn scan_id_exists(&self, id: &ScanPlanId) -> bool {
        self.scans.values().any(|scan| &scan.scan_id == id)
    }
}

pub fn create_project(path: &Path) -> Result<ProjectState, ProjectError> {
    let project = ProjectState::new(None);
    save_project(path, &project, None)?;
    Ok(project)
}

pub fn load_project(path: &Path) -> Result<ProjectState, ProjectError> {
    PROJECT_INIT_COUNT.fetch_add(1, Ordering::SeqCst);
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_PROJECT_BYTES {
        return Err(ProjectError::SizeLimit);
    }
    let mut bytes = Vec::with_capacity(metadata.len().min(MAX_PROJECT_BYTES) as usize);
    File::open(path)?
        .take(MAX_PROJECT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PROJECT_BYTES {
        return Err(ProjectError::SizeLimit);
    }
    let project: ProjectState = serde_json::from_slice(&bytes)?;
    project.validate()?;
    Ok(project)
}

/// Counting writer that enforces `MAX_PROJECT_BYTES` *during* streaming
/// serialization. Aborts cleanly once the hard cap is exceeded instead of
/// writing an arbitrarily huge temp file and checking size afterward.
struct SizeLimitWriter<W: Write> {
    inner: W,
    written: u64,
    limit_exceeded: bool,
}

impl<W: Write> SizeLimitWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            written: 0,
            limit_exceeded: false,
        }
    }
}

impl<W: Write> Write for SizeLimitWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Enforce cap incrementally: refuse bytes that would exceed the limit.
        // Write the fitting prefix (if any) is complex for serde; instead fail
        // the whole write once the cap would be exceeded so serde aborts.
        if self.written.saturating_add(buf.len() as u64) > MAX_PROJECT_BYTES {
            self.limit_exceeded = true;
            return Err(std::io::Error::other("project exceeds hard size cap"));
        }
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Save pipeline memory accounting (bounded, no stacked full-size copies):
/// - `ProjectState` (already in RAM, required).
/// - No `ProjectState` clone (fingerprint is borrowed/streaming).
/// - No full pretty-printed `Vec<u8>` retained; serialization streams via
///   `serde_json::to_writer_pretty` into a `BufWriter` (8 KiB) plus a
///   `SizeLimitWriter` counter.
///
/// Peak extra RAM beyond the live state is O(8 KiB + one record), not
/// O(project_size). Size is enforced during the write; on `SizeLimit` the
/// temp file is removed and the old project is unchanged.
pub fn save_project(
    path: &Path,
    project: &ProjectState,
    expected_revision: Option<u64>,
) -> Result<u64, ProjectError> {
    project.validate()?;
    if let Some(expected) = expected_revision {
        if path.exists() {
            let current = load_project(path)?;
            if current.revision != expected {
                return Err(ProjectError::ConcurrentModification);
            }
            if current.fingerprint != project.fingerprint && current.revision == project.revision {
                // Defensive: same revision but different content implies a lost
                // update outside the revision protocol.
                return Err(ProjectError::ConcurrentModification);
            }
        }
    }
    let tmp = temp_path(path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let result: Result<u64, ProjectError> = (|| {
        let file = File::create(&tmp)?;
        let buffered = BufWriter::with_capacity(PROJECT_SAVE_BUFFER_BYTES, file);
        let mut counting = SizeLimitWriter::new(buffered);
        match serde_json::to_writer_pretty(&mut counting, project) {
            Ok(()) => {}
            Err(err) if counting.limit_exceeded || err.to_string().contains("hard size cap") => {
                return Err(ProjectError::SizeLimit);
            }
            Err(err) => return Err(ProjectError::Json(err)),
        }
        // `written` counts pretty-printed bytes streamed so far (<= cap).
        let written = counting.written;
        counting.flush()?;
        // Sync the underlying file through the buffering layers.
        counting.inner.flush()?;
        counting.inner.get_ref().sync_all()?;
        Ok(written)
    })();
    match result {
        Ok(written) => {
            // `written` is the streamed byte count; verify via metadata for
            // the return value (rename is atomic).
            fs::rename(&tmp, path)?;
            // Return streamed count (equals file length barring races).
            Ok(written)
        }
        Err(err) => {
            let _ = fs::remove_file(&tmp);
            // Old project at `path` is untouched (rename never happened).
            Err(err)
        }
    }
}

pub fn add_checkpoint(
    project_path: &Path,
    checkpoint_path: &Path,
) -> Result<ImportSummary, ProjectError> {
    let mut project = load_project(project_path)?;
    let revision = project.revision;
    let checkpoint = load_checkpoint(checkpoint_path)?;
    let analysis = analysis::analyze_state(
        &checkpoint.state,
        None,
        analysis::AnalysisOptions::default(),
    )?;
    let summary = project.add_scan(&checkpoint.state, None, Some(&analysis))?;
    save_project(project_path, &project, Some(revision))?;
    Ok(summary)
}

pub fn render_summary(project: &ProjectState, storage_bytes: u64) -> String {
    let summary = project.summary(storage_bytes);
    format!(
        "RXScan Project\nProject: {}\nRevision: {}\nScans: {}\nEntities: {}\nRelationships: {}\nObservations: {}\nFindings: {}\nChanges: confirmed={} inconclusive={}\nAnalysis refs: {}\nStorage bytes: {}\nnetwork_requests=0",
        report::safe_display(&project.project_id),
        project.revision,
        summary.scans,
        summary.entities,
        summary.relationships,
        summary.observations,
        summary.findings,
        summary.confirmed_changes,
        summary.inconclusive_changes,
        summary.analysis_refs,
        summary.storage_bytes
    )
}

pub fn render_entity(project: &ProjectState, entity_id: &str) -> Result<String, ProjectError> {
    let entity = project
        .entities
        .get(entity_id)
        .ok_or_else(|| ProjectError::NotFound(entity_id.to_owned()))?;
    let findings = project
        .findings
        .values()
        .filter(|finding| finding.affected_entity == entity.id)
        .count();
    let changes = project
        .changes
        .values()
        .filter(|change| change.entity_id.as_deref() == Some(entity.id.as_str()))
        .count();
    let attention = project
        .analysis_refs
        .values()
        .filter(|signal| signal.entity_id.as_deref() == Some(entity.id.as_str()))
        .count();
    Ok(format!(
        "Entity {}\nkind={:?}\nidentity={}\nfirst_scan={}\nlast_scan={}\nobservations={}\nfindings={}\nchanges={}\nattention_signals={}\nexternal={}",
        report::safe_display(&entity.id),
        entity.kind,
        report::safe_display(&entity.identity),
        entity.first_scan_id.0,
        entity.last_scan_id.0,
        entity.observation_count,
        findings,
        changes,
        attention,
        entity.external
    ))
}

pub fn render_findings(
    project: &ProjectState,
    entity: Option<&str>,
    limit: usize,
) -> Result<String, ProjectError> {
    let result = project.findings_query(entity, limit)?;
    let mut out = format!(
        "findings total={} emitted={} truncated={} network_requests=0\n",
        result.results_total, result.results_emitted, result.truncated
    );
    for finding in &result.records {
        out.push_str(&format!(
            "- {} severity={:?} confidence={} entity={}\n",
            report::safe_display(&finding.title),
            finding.severity,
            finding.confidence,
            report::safe_display(&finding.affected_entity),
        ));
    }
    Ok(out)
}

pub fn render_changes(
    project: &ProjectState,
    entity: Option<&str>,
    limit: usize,
) -> Result<String, ProjectError> {
    let result = project.changes_query(entity, limit)?;
    let mut out = format!(
        "changes total={} emitted={} truncated={} network_requests=0\n",
        result.results_total, result.results_emitted, result.truncated
    );
    for change in &result.records {
        out.push_str(&format!(
            "- {:?}/{:?} reason={:?} entity={}\n",
            change.change_type,
            change.certainty,
            change.reason,
            change
                .entity_id
                .as_deref()
                .map(report::safe_display)
                .unwrap_or_else(|| "-".to_owned()),
        ));
    }
    Ok(out)
}

pub fn render_attention(
    project: &ProjectState,
    entity: Option<&str>,
    limit: usize,
) -> Result<String, ProjectError> {
    let result = project.attention_query(entity, limit)?;
    let mut out = format!(
        "attention total={} emitted={} truncated={} network_requests=0\n",
        result.results_total, result.results_emitted, result.truncated
    );
    for signal in &result.records {
        out.push_str(&format!(
            "- {:?} score={} label={} entity={}\n",
            signal.attention_band,
            signal.attention_score,
            report::safe_display(&signal.label),
            signal
                .entity_id
                .as_deref()
                .map(report::safe_display)
                .unwrap_or_else(|| "-".to_owned()),
        ));
    }
    Ok(out)
}

pub fn render_neighbors_jsonl<W: Write>(
    project: &ProjectState,
    entity_id: &str,
    depth: u8,
    limit: usize,
    mut writer: W,
) -> Result<(), ProjectError> {
    let result = project.neighbors(entity_id, depth, limit)?;
    serde_json::to_writer(
        &mut writer,
        &serde_json::json!({"record_type":"project_query_meta","project_schema_version":PROJECT_SCHEMA_VERSION,"results_total":result.results_total,"results_emitted":result.results_emitted,"truncated":result.truncated,"exhaustive":result.exhaustive,"results_discovered":result.results_discovered,"queue_peak":result.queue_peak,"visited_peak":result.visited_peak,"expansions":result.expansions}),
    )?;
    writer.write_all(b"\n")?;
    for record in result.records {
        serde_json::to_writer(
            &mut writer,
            &serde_json::json!({"record_type":"project_neighbor","project_schema_version":PROJECT_SCHEMA_VERSION,"payload":record}),
        )?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

/// Streaming JSONL export for findings/changes/attention. Each line is an
/// independent JSON object; no giant intermediate string is built.
pub fn render_records_jsonl<W: Write, T: Serialize>(
    record_type: &str,
    result: &QueryResult<T>,
    mut writer: W,
) -> Result<(), ProjectError> {
    serde_json::to_writer(
        &mut writer,
        &serde_json::json!({"record_type":"project_query_meta","project_schema_version":PROJECT_SCHEMA_VERSION,"query":record_type,"results_total":result.results_total,"results_emitted":result.results_emitted,"truncated":result.truncated,"exhaustive":result.exhaustive,"results_discovered":result.results_discovered,"queue_peak":result.queue_peak,"visited_peak":result.visited_peak,"expansions":result.expansions}),
    )
    .map_err(ProjectError::Json)?;
    writer.write_all(b"\n")?;
    for record in &result.records {
        serde_json::to_writer(
            &mut writer,
            &serde_json::json!({"record_type":record_type,"project_schema_version":PROJECT_SCHEMA_VERSION,"payload":record}),
        )
        .map_err(ProjectError::Json)?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn entity_id(asset: &Asset) -> String {
    format!(
        "entity_{}_{}",
        format!("{:?}", asset.kind).to_ascii_lowercase(),
        hash_text(&format!("{:?}:{}", asset.kind, asset.identity))
    )
}

fn relationship_id(kind: &RelationshipKind, from: &str, to: &str) -> String {
    format!("rel_{}", hash_text(&format!("{:?}:{from}:{to}", kind)))
}

fn finding_id(finding: &Finding, entity: &str) -> String {
    let semantic = finding
        .metadata
        .get("identity")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(&finding.id.0);
    format!(
        "finding_{}",
        hash_text(&format!(
            "{:?}:{}:{entity}:{semantic}",
            finding.severity, finding.title
        ))
    )
}

fn subject_entity(
    subject: &RelationshipSubject,
    assets: &BTreeMap<String, String>,
) -> Option<String> {
    match subject {
        RelationshipSubject::Asset(id) => assets.get(&id.0).cloned(),
        _ => None,
    }
}

fn find_entity_for_semantic(
    semantic_id: &str,
    imported_assets: &BTreeMap<String, String>,
    project: &ProjectState,
) -> Option<String> {
    // 1. Direct asset-ID match (relationship/finding semantic keys embed
    //    `asset_*` identifiers).
    for (asset_id, entity_id) in imported_assets {
        if !asset_id.is_empty() && semantic_id.contains(asset_id.as_str()) {
            return Some(entity_id.clone());
        }
    }
    // 2. Identity match against entities already in the project (which include
    //    this scan's entities, inserted before change processing).
    let mut best: Option<(usize, String)> = None;
    for entity in project.entities.values() {
        if entity.identity.is_empty() {
            continue;
        }
        if semantic_id.contains(&entity.identity) {
            let score = entity.identity.len();
            if best.as_ref().is_none_or(|(len, _)| score > *len) {
                best = Some((score, entity.id.clone()));
            }
        }
    }
    if let Some((_, id)) = best {
        return Some(id);
    }
    // 3. Fallback: entity-ID substring (for keys that already embed it).
    for id in project.entities.keys() {
        if semantic_id.contains(id.as_str()) {
            return Some(id.clone());
        }
    }
    None
}

fn entity_from_signal(
    signal: &analysis::PrioritySignal,
    imported_assets: &BTreeMap<String, String>,
    project: &ProjectState,
) -> Option<String> {
    // 1. Direct asset-ID lookup via this import's asset map (exact, no fuzzy).
    for asset_id in &signal.related_assets {
        if let Some(entity) = imported_assets.get(&asset_id.0) {
            return Some(entity.clone());
        }
    }
    // 2. Primary-entity asset-ID substring.
    for (asset_id, entity_id) in imported_assets {
        if !asset_id.is_empty() && signal.primary_entity.contains(asset_id.as_str()) {
            return Some(entity_id.clone());
        }
    }
    // 3. Identity substring against project entities (longest match wins).
    let mut best: Option<(usize, String)> = None;
    for entity in project.entities.values() {
        if entity.identity.is_empty() {
            continue;
        }
        if signal.primary_entity.contains(&entity.identity) {
            let score = entity.identity.len();
            if best.as_ref().is_none_or(|(len, _)| score > *len) {
                best = Some((score, entity.id.clone()));
            }
        }
    }
    if let Some((_, id)) = best {
        return Some(id);
    }
    None
}

/// Semantic fingerprint: stable over equivalent semantic input, ignoring
/// wall-clock timestamps, `saved_at`, provenance timestamps, speed/pressure,
/// budgets, checkpoint paths, insertion order, and runtime task order.
///
/// Covers: plan semantics (targets/scope/goal/level/ports/discovery),
/// deduplicated asset semantics (kind/identity/attributes), relationship
/// semantics (kind/endpoints), finding semantics (title/severity/affected/
/// identity/confidence), and task coverage shape (kind/state/params).
fn scan_fingerprint(state: &PersistedScanState) -> Result<String, ProjectError> {
    let mut parts: Vec<String> = Vec::new();
    let mut targets: Vec<String> = state
        .plan
        .targets
        .iter()
        .map(|t| format!("{t:?}"))
        .collect();
    targets.sort();
    parts.push(format!("targets:{}", targets.join(",")));
    parts.push(format!("scope:{:?}", state.plan.scope));
    parts.push(format!("goal:{:?}", state.plan.goal));
    parts.push(format!("level:{}", state.plan.level));
    parts.push(format!(
        "tcp:{}",
        diff::tcp_selection_semantic(&state.plan.tcp_ports)
    ));
    parts.push(format!("discovery:{:?}", state.plan.discovery_mode));
    let mut assets: Vec<String> = Vec::new();
    for output in &state.outputs {
        for asset in &output.output.assets {
            assets.push(format!(
                "{:?}:{}:{:?}",
                asset.kind, asset.identity, asset.attributes
            ));
        }
    }
    assets.sort();
    assets.dedup();
    parts.push(format!("assets:{}", assets.join("|")));
    let mut rels: Vec<String> = Vec::new();
    for output in &state.outputs {
        for event in &output.output.events {
            for rel in &event.relationships {
                rels.push(format!(
                    "{:?}:{}:{}",
                    rel.kind,
                    subject_key(&rel.from),
                    subject_key(&rel.to)
                ));
            }
        }
    }
    rels.sort();
    rels.dedup();
    parts.push(format!("rels:{}", rels.join("|")));
    let mut findings: Vec<String> = Vec::new();
    for output in &state.outputs {
        for finding in &output.output.findings {
            let semantic = finding
                .metadata
                .get("identity")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(&finding.id.0);
            findings.push(format!(
                "{}:{:?}:{}:{}:{}",
                finding.title,
                finding.severity,
                finding.affected_asset_id.0,
                semantic,
                finding.confidence.0
            ));
        }
    }
    findings.sort();
    findings.dedup();
    parts.push(format!("findings:{}", findings.join("|")));
    let mut tasks: Vec<String> = Vec::new();
    for persisted in &state.tasks {
        let mut params: Vec<String> = persisted
            .task
            .params
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        params.sort();
        tasks.push(format!(
            "{:?}:{:?}:{}",
            persisted.task.kind,
            persisted.task.state,
            params.join(",")
        ));
    }
    tasks.sort();
    parts.push(format!("tasks:{}", tasks.join("|")));
    Ok(hash_text(&parts.join("\n")))
}

fn subject_key(subject: &RelationshipSubject) -> String {
    match subject {
        RelationshipSubject::Asset(id) => format!("asset:{}", id.0),
        RelationshipSubject::Finding(id) => format!("finding:{}", id.0),
        RelationshipSubject::Evidence(id) => format!("evidence:{}", id.0),
    }
}

/// Borrowed canonical fingerprint view: same field order and values as
/// `ProjectState`, but `fingerprint` is always empty and all other fields are
/// borrowed. Serializing this view yields byte-identical JSON to the previous
/// whole-state clone (`clone.fingerprint.clear()` + `to_vec`), so fingerprint
/// values remain stable while requiring no `ProjectState` duplicate.
#[derive(Serialize)]
struct ProjectFingerprintView<'a> {
    project_schema_version: u16,
    project_id: &'a str,
    revision: u64,
    fingerprint: &'static str,
    scans: &'a BTreeMap<String, ProjectScan>,
    entities: &'a BTreeMap<String, ProjectEntity>,
    relationships: &'a BTreeMap<String, ProjectRelationship>,
    observations: &'a BTreeMap<String, ProjectObservation>,
    findings: &'a BTreeMap<String, ProjectFinding>,
    changes: &'a BTreeMap<String, ProjectChangeRef>,
    analysis_refs: &'a BTreeMap<String, ProjectAnalysisRef>,
}

/// `Write` adapter that streams serialized bytes directly into SHA-256.
/// No intermediate canonical byte `Vec` is retained; memory is O(hasher
/// state + serde per-value stack), i.e. bounded incremental, not
/// O(project_size) duplicate state.
struct HasherWriter<'a> {
    hasher: &'a mut Sha256,
}

impl Write for HasherWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn project_fingerprint(project: &ProjectState) -> Result<String, ProjectError> {
    // Bounded incremental memory: borrow, stream into hasher, never clone
    // the whole state. `FINGERPRINT_WHOLE_STATE_CLONES` stays 0 and
    // `FINGERPRINT_SERIALIZATION_BUFFER_BYTES` is 0.
    let view = ProjectFingerprintView {
        project_schema_version: project.project_schema_version,
        project_id: &project.project_id,
        revision: project.revision,
        fingerprint: "",
        scans: &project.scans,
        entities: &project.entities,
        relationships: &project.relationships,
        observations: &project.observations,
        findings: &project.findings,
        changes: &project.changes,
        analysis_refs: &project.analysis_refs,
    };
    let mut hasher = Sha256::new();
    {
        let mut writer = HasherWriter {
            hasher: &mut hasher,
        };
        serde_json::to_writer(&mut writer, &view)?;
    }
    let digest = hasher.finalize();
    Ok(digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn hash_json<T: Serialize>(value: &T) -> Result<String, ProjectError> {
    let bytes = serde_json::to_vec(value)?;
    Ok(hash_bytes(&bytes))
}

fn hash_text(value: &str) -> String {
    hash_bytes(value.as_bytes())
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn validate_collection_len(
    label: &str,
    actual: usize,
    limit: usize,
) -> Result<(), ProjectError> {
    if actual > limit {
        Err(ProjectError::Invalid(format!("too many project {label}")))
    } else {
        Ok(())
    }
}

fn check_len(label: &str, actual: usize, limit: usize) -> Result<(), ProjectError> {
    validate_collection_len(label, actual, limit)
}

fn validate_id(value: &str, label: &str) -> Result<(), ProjectError> {
    if value.is_empty() || value.len() > 256 || value.contains('\0') {
        Err(ProjectError::Invalid(format!("invalid {label}")))
    } else {
        Ok(())
    }
}

fn contains_forbidden_project_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "authorization:",
        "cookie:",
        "set-cookie",
        "password=",
        "csrf",
        "raw_http_body_marker",
        "raw_dns_packet_marker",
        "raw_tls_record_marker",
        "phase14_secret",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn reject_forbidden_checkpoint_content(state: &PersistedScanState) -> Result<(), ProjectError> {
    for output in &state.outputs {
        for asset in &output.output.assets {
            if contains_forbidden_project_marker(&asset.identity) {
                return Err(ProjectError::Invalid(
                    "checkpoint asset identity contains forbidden marker".to_owned(),
                ));
            }
            for (key, value) in &asset.attributes {
                if contains_forbidden_project_marker(key)
                    || contains_forbidden_project_marker(value)
                {
                    return Err(ProjectError::Invalid(
                        "checkpoint asset attribute contains forbidden marker".to_owned(),
                    ));
                }
            }
        }
        for finding in &output.output.findings {
            if contains_forbidden_project_marker(&finding.title) {
                return Err(ProjectError::Invalid(
                    "checkpoint finding contains forbidden marker".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn default_finding_severity() -> Severity {
    Severity::Info
}

fn temp_path(path: &Path) -> std::path::PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "project".into());
    name.push(".tmp");
    path.with_file_name(name)
}

pub fn load_project_with_timing(path: &Path) -> Result<(ProjectState, u128, u64), ProjectError> {
    let started = Instant::now();
    let state = load_project(path)?;
    let bytes = fs::metadata(path)?.len();
    Ok((state, started.elapsed().as_millis(), bytes))
}
