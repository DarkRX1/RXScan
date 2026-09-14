//! Phase 15 offline semantic scan diff.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Instant,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    execution::{TaskKind, TaskState},
    model::{Asset, AssetKind, Finding, Relationship, RelationshipSubject, ScanPlanId},
    persistence::{LoadedCheckpoint, PersistedScanState, PersistenceError, load_checkpoint},
    plan::{ScanPlan, TcpPortSelection},
};

pub const DIFF_SCHEMA_VERSION: u16 = 1;
pub const MAX_DIFF_RECORDS: usize = 10_000;

#[derive(Debug, Error)]
pub enum DiffError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error("checkpoints are incompatible: {0}")]
    Incompatible(String),
    #[error("could not serialize diff: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonStatus {
    Comparable,
    ComparableWithPlanDifferences,
    Incompatible,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    Added,
    Removed,
    Modified,
    Unchanged,
    InconclusiveMissing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Asset,
    Relationship,
    Finding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Certainty {
    Confirmed,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    NewSemanticEntity,
    NewlyObservedWithExpandedCoverage,
    MissingWithComparableCoverage,
    MissingWithoutComparableCoverage,
    CoverageReduced,
    TaskIncomplete,
    AttributeChanged,
    RelationshipAdded,
    RelationshipRemoved,
    FindingChanged,
    ScopeNarrowed,
    ModuleDisabled,
    RecordTypeNotCovered,
    NetworkErrorPreventsConfirmation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanCompatibility {
    pub status: ComparisonStatus,
    pub target_difference: bool,
    pub scope_difference: bool,
    pub level_difference: Option<(u8, u8)>,
    pub goal_difference: bool,
    pub tcp_port_difference: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffSummary {
    pub assets_added: usize,
    pub assets_removed_confirmed: usize,
    pub assets_modified: usize,
    pub assets_missing_inconclusive: usize,
    pub relationships_added: usize,
    pub relationships_removed_confirmed: usize,
    pub relationships_missing_inconclusive: usize,
    pub findings_added: usize,
    pub findings_removed_confirmed: usize,
    pub findings_modified: usize,
    pub findings_missing_inconclusive: usize,
    pub unchanged: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffRecord {
    pub change_type: ChangeType,
    pub entity_type: EntityType,
    pub semantic_id: String,
    pub certainty: Certainty,
    pub reason: ReasonCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffReport {
    pub diff_schema_version: u16,
    pub baseline_scan_id: ScanPlanId,
    pub current_scan_id: ScanPlanId,
    pub comparison_status: ComparisonStatus,
    pub plan: PlanCompatibility,
    pub summary: DiffSummary,
    pub records: Vec<DiffRecord>,
    pub diff_records_truncated: bool,
    pub truncated_records: usize,
    pub network_requests: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DiffOptions {
    pub summary_only: bool,
    pub max_records: usize,
}

#[derive(Debug, Clone)]
struct SemanticSnapshot {
    plan: ScanPlan,
    scan_id: ScanPlanId,
    partial: bool,
    coverage: Coverage,
    assets: BTreeMap<String, Asset>,
    relationships: BTreeMap<String, Relationship>,
    findings: BTreeMap<String, Finding>,
}

#[derive(Debug, Clone, Default)]
struct Coverage {
    succeeded: BTreeSet<TaskKind>,
    terminal_errors: BTreeSet<TaskKind>,
    /// Verbatim single-port tokens (e.g. `"443"`). Exact strings are kept so
    /// membership truth is identical to the pre-Phase-19 expansion.
    ports: BTreeSet<String>,
    /// Merged closed intervals from `start-end` tokens (e.g. `"1-65535"`).
    ///
    /// Phase 19: a full-range scan previously materialized up to 65,535 heap
    /// `String`s plus one `BTreeSet` node per port. One interval covers the
    /// same membership truth with O(1) memory; `port_covered` binary-searches
    /// the merged list.
    port_ranges: Vec<(u16, u16)>,
    dns_types: BTreeSet<String>,
    crawl_depth: Option<u8>,
    content: bool,
    fuzz_params: BTreeSet<String>,
}

impl Coverage {
    /// Membership test for a canonical port token. Exact single-port tokens
    /// match verbatim; otherwise a decimal `u16` token matches when covered
    /// by a recorded range interval.
    fn port_covered(&self, port: &str) -> bool {
        if self.ports.contains(port) {
            return true;
        }
        let Ok(number) = port.parse::<u16>() else {
            return false;
        };
        // `port_ranges` is kept sorted and merged; binary search on starts.
        let mut low = 0usize;
        let mut high = self.port_ranges.len();
        while low < high {
            let mid = low + (high - low) / 2;
            let (start, end) = self.port_ranges[mid];
            if number < start {
                high = mid;
            } else if number > end {
                low = mid + 1;
            } else {
                return true;
            }
        }
        false
    }

    /// Insert a closed range and re-merge the interval list so it stays
    /// sorted, disjoint, and minimal.
    fn insert_port_range(&mut self, start: u16, end: u16) {
        if start > end {
            // Matches the old `start..=end` expansion, which yields nothing
            // for a reversed range.
            return;
        }
        self.port_ranges.push((start, end));
        self.port_ranges.sort_unstable();
        let mut merged: Vec<(u16, u16)> = Vec::with_capacity(self.port_ranges.len());
        for (start, end) in self.port_ranges.drain(..) {
            if let Some(last) = merged.last_mut() {
                // Adjacent intervals merge too: coverage is identical and the
                // list stays minimal.
                if start <= last.1.saturating_add(1) {
                    last.1 = last.1.max(end);
                    continue;
                }
            }
            merged.push((start, end));
        }
        self.port_ranges = merged;
    }

    fn record_task(&mut self, kind: &TaskKind, params: &BTreeMap<String, String>) {
        match kind {
            TaskKind::PortDiscovery => {
                for key in ["port", "ports", "scanned_ports"] {
                    if let Some(value) = params.get(key) {
                        for part in value.split(',') {
                            let part = part.trim();
                            if let Some((start, end)) = part.split_once('-') {
                                if let (Ok(start), Ok(end)) =
                                    (start.trim().parse::<u16>(), end.trim().parse::<u16>())
                                {
                                    self.insert_port_range(start, end);
                                }
                            } else if part.parse::<u16>().is_ok() {
                                self.ports.insert(part.to_owned());
                            }
                        }
                    }
                }
            }
            TaskKind::DnsProbe => {
                for key in ["record_type", "record_types", "dns_type"] {
                    if let Some(value) = params.get(key) {
                        for part in value.split(',') {
                            let part = part.trim().to_ascii_lowercase();
                            if !part.is_empty() {
                                self.dns_types.insert(part);
                            }
                        }
                    }
                }
                if self.dns_types.is_empty() {
                    self.dns_types.insert("all".to_owned());
                }
            }
            TaskKind::Crawl => {
                let depth = params
                    .get("depth")
                    .or_else(|| params.get("max_depth"))
                    .and_then(|value| value.parse::<u8>().ok())
                    .unwrap_or(1);
                self.crawl_depth = Some(self.crawl_depth.unwrap_or(0).max(depth));
            }
            TaskKind::ContentDiscovery => self.content = true,
            TaskKind::Fuzz => {
                if let Some(param) = params.get("param").or_else(|| params.get("parameter")) {
                    self.fuzz_params.insert(param.clone());
                }
            }
            _ => {}
        }
    }

    fn comparable_asset(&self, other: &Self, asset: &Asset) -> Result<(), ReasonCode> {
        if self.succeeded.contains(&TaskKind::PortDiscovery) {
            self.requires_network_safe(TaskKind::PortDiscovery, other)?;
            if asset.kind == AssetKind::Port {
                let port = asset
                    .attributes
                    .get("port")
                    .cloned()
                    .or_else(|| asset.identity.rsplit(':').next().map(str::to_owned));
                if let Some(port) = port {
                    if !other.port_covered(&port) {
                        return Err(ReasonCode::MissingWithoutComparableCoverage);
                    }
                }
            }
        }
        match asset.kind {
            AssetKind::Port => self.requires_network_safe(TaskKind::PortDiscovery, other),
            AssetKind::Service => self.requires_network_safe(TaskKind::ServiceProbe, other),
            AssetKind::Url | AssetKind::Endpoint => {
                if asset.attributes.get("module").map(String::as_str) == Some("content")
                    && !other.content
                {
                    return Err(ReasonCode::ModuleDisabled);
                }
                if let Some(param) = asset.attributes.get("fuzz_param") {
                    self.requires_network_safe(TaskKind::Fuzz, other)?;
                    if !other.fuzz_params.contains(param) {
                        return Err(ReasonCode::MissingWithoutComparableCoverage);
                    }
                }
                let required_depth = asset
                    .attributes
                    .get("crawl_depth")
                    .and_then(|value| value.parse::<u8>().ok())
                    .unwrap_or(0);
                if required_depth > 0 {
                    if !other.succeeded.contains(&TaskKind::Crawl) {
                        return Err(ReasonCode::ModuleDisabled);
                    }
                    if other.crawl_depth.unwrap_or(0) < required_depth {
                        return Err(ReasonCode::CoverageReduced);
                    }
                }
                if asset.attributes.contains_key("status") {
                    self.requires_network_safe(TaskKind::HttpProbe, other)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn comparable_relationship(
        &self,
        other: &Self,
        relationship: &Relationship,
    ) -> Result<(), ReasonCode> {
        let record = match relationship.kind {
            crate::model::RelationshipKind::HostnameResolvesToIp => Some("a"),
            crate::model::RelationshipKind::MailExchangeFor => Some("mx"),
            crate::model::RelationshipKind::NameServerFor => Some("ns"),
            crate::model::RelationshipKind::ReverseResolvesTo => Some("ptr"),
            crate::model::RelationshipKind::HostnameAliasesTo => Some("cname"),
            _ => None,
        };
        if let Some(record) = record {
            self.requires_network_safe(TaskKind::DnsProbe, other)?;
            if !other.dns_types.contains(record) && !other.dns_types.contains("all") {
                return Err(ReasonCode::RecordTypeNotCovered);
            }
        }
        Ok(())
    }

    fn comparable_finding(&self, other: &Self) -> Result<(), ReasonCode> {
        for kind in [
            TaskKind::ServiceProbe,
            TaskKind::HttpProbe,
            TaskKind::Baseline,
            TaskKind::ContentDiscovery,
            TaskKind::Fuzz,
            TaskKind::DnsProbe,
        ] {
            if self.succeeded.contains(&kind) {
                self.requires_network_safe(kind, other)?;
            }
        }
        Ok(())
    }

    fn requires_network_safe(&self, kind: TaskKind, other: &Self) -> Result<(), ReasonCode> {
        if other.terminal_errors.contains(&kind) {
            return Err(ReasonCode::NetworkErrorPreventsConfirmation);
        }
        if self.succeeded.contains(&kind) && !other.succeeded.contains(&kind) {
            return Err(ReasonCode::ModuleDisabled);
        }
        Ok(())
    }
}

pub fn diff_checkpoints(
    baseline_path: &Path,
    current_path: &Path,
    options: DiffOptions,
) -> Result<(DiffReport, u128, u128, u128), DiffError> {
    let started = Instant::now();
    let old = load_checkpoint(baseline_path)?;
    let new = load_checkpoint(current_path)?;
    let load_ms = started.elapsed().as_millis();
    let normalize_start = Instant::now();
    let old = normalize_loaded(old)?;
    let new = normalize_loaded(new)?;
    let normalization_ms = normalize_start.elapsed().as_millis();
    let compare_start = Instant::now();
    let report = compare_snapshots(&old, &new, options)?;
    let comparison_ms = compare_start.elapsed().as_millis();
    Ok((report, load_ms, normalization_ms, comparison_ms))
}

pub fn compare_states(
    baseline: &PersistedScanState,
    current: &PersistedScanState,
    options: DiffOptions,
) -> Result<DiffReport, DiffError> {
    baseline.validate()?;
    current.validate()?;
    let old = normalize_state(baseline)?;
    let new = normalize_state(current)?;
    compare_snapshots(&old, &new, options)
}

fn normalize_loaded(loaded: LoadedCheckpoint) -> Result<SemanticSnapshot, DiffError> {
    normalize_state(&loaded.state)
}

fn normalize_state(state: &PersistedScanState) -> Result<SemanticSnapshot, DiffError> {
    let mut coverage = Coverage::default();
    let mut partial = false;
    for task in &state.tasks {
        match task.task.state {
            TaskState::Succeeded => {
                coverage.succeeded.insert(task.task.kind.clone());
                coverage.record_task(&task.task.kind, &task.task.params);
            }
            TaskState::Failed | TaskState::TimedOut | TaskState::Cancelled => {
                coverage.terminal_errors.insert(task.task.kind.clone());
                partial = true;
            }
            TaskState::Pending | TaskState::Ready | TaskState::Running | TaskState::Skipped => {
                partial = true;
            }
        }
    }
    let mut assets = BTreeMap::new();
    let mut relationships = BTreeMap::new();
    let mut findings = BTreeMap::new();
    for output in &state.outputs {
        for asset in &output.output.assets {
            assets.insert(asset_key(asset), asset.clone());
        }
        for event in &output.output.events {
            for rel in &event.relationships {
                relationships.insert(relationship_key(rel), rel.clone());
            }
        }
        for finding in &output.output.findings {
            findings.insert(finding_key(finding), finding.clone());
        }
    }
    Ok(SemanticSnapshot {
        plan: state.plan.clone(),
        scan_id: state.scan_id.clone(),
        partial,
        coverage,
        assets,
        relationships,
        findings,
    })
}

fn compare_snapshots(
    old: &SemanticSnapshot,
    new: &SemanticSnapshot,
    options: DiffOptions,
) -> Result<DiffReport, DiffError> {
    let plan = compatibility(&old.plan, &new.plan);
    if plan.status == ComparisonStatus::Incompatible {
        return Err(DiffError::Incompatible(
            "target sets or scope are incompatible".to_owned(),
        ));
    }
    let mut builder = ReportBuilder::new(options);
    let mut context = CompareContext {
        old_coverage: &old.coverage,
        new_coverage: &new.coverage,
        old_level: old.plan.level,
        new_level: new.plan.level,
        scope_narrowed: plan.scope_difference,
        builder: &mut builder,
    };
    compare_map(
        EntityType::Asset,
        &old.assets,
        &new.assets,
        &mut context,
        asset_value,
        Coverage::comparable_asset,
    );
    compare_map(
        EntityType::Relationship,
        &old.relationships,
        &new.relationships,
        &mut context,
        relationship_value,
        Coverage::comparable_relationship,
    );
    compare_map(
        EntityType::Finding,
        &old.findings,
        &new.findings,
        &mut context,
        finding_value,
        |old, new, _| old.comparable_finding(new),
    );
    let mut status = plan.status;
    if old.partial || new.partial {
        status = ComparisonStatus::Partial;
    }
    Ok(DiffReport {
        diff_schema_version: DIFF_SCHEMA_VERSION,
        baseline_scan_id: old.scan_id.clone(),
        current_scan_id: new.scan_id.clone(),
        comparison_status: status,
        plan,
        summary: builder.summary,
        records: builder.records,
        diff_records_truncated: builder.truncated_records > 0,
        truncated_records: builder.truncated_records,
        network_requests: 0,
    })
}

struct CompareContext<'a, 'b> {
    old_coverage: &'a Coverage,
    new_coverage: &'a Coverage,
    old_level: u8,
    new_level: u8,
    scope_narrowed: bool,
    builder: &'b mut ReportBuilder,
}

fn compare_map<T: PartialEq>(
    entity: EntityType,
    old: &BTreeMap<String, T>,
    new: &BTreeMap<String, T>,
    context: &mut CompareContext<'_, '_>,
    value: fn(&T) -> serde_json::Value,
    missing_check: fn(&Coverage, &Coverage, &T) -> Result<(), ReasonCode>,
) {
    let mut keys = old.keys().cloned().collect::<BTreeSet<_>>();
    keys.extend(new.keys().cloned());
    for key in keys {
        match (old.get(&key), new.get(&key)) {
            (None, Some(after)) => {
                let reason = if context.new_level > context.old_level {
                    ReasonCode::NewlyObservedWithExpandedCoverage
                } else {
                    ReasonCode::NewSemanticEntity
                };
                context.builder.push(DiffRecord {
                    change_type: ChangeType::Added,
                    entity_type: entity,
                    semantic_id: key,
                    certainty: Certainty::Confirmed,
                    reason,
                    before: None,
                    after: Some(value(after)),
                });
            }
            (Some(before), None) => {
                let missing_reason =
                    missing_check(context.old_coverage, context.new_coverage, before);
                let (change_type, certainty, reason) = if context.scope_narrowed {
                    (
                        ChangeType::InconclusiveMissing,
                        Certainty::Inconclusive,
                        ReasonCode::ScopeNarrowed,
                    )
                } else if missing_reason.is_ok() && context.new_level >= context.old_level {
                    (
                        ChangeType::Removed,
                        Certainty::Confirmed,
                        ReasonCode::MissingWithComparableCoverage,
                    )
                } else if context.new_level < context.old_level {
                    (
                        ChangeType::InconclusiveMissing,
                        Certainty::Inconclusive,
                        ReasonCode::CoverageReduced,
                    )
                } else {
                    (
                        ChangeType::InconclusiveMissing,
                        Certainty::Inconclusive,
                        missing_reason
                            .err()
                            .unwrap_or(ReasonCode::MissingWithoutComparableCoverage),
                    )
                };
                context.builder.push(DiffRecord {
                    change_type,
                    entity_type: entity,
                    semantic_id: key,
                    certainty,
                    reason,
                    before: Some(value(before)),
                    after: None,
                });
            }
            (Some(before), Some(after)) if value(before) == value(after) => {
                context.builder.summary.unchanged += 1;
            }
            (Some(before), Some(after)) => {
                context.builder.push(DiffRecord {
                    change_type: ChangeType::Modified,
                    entity_type: entity,
                    semantic_id: key,
                    certainty: Certainty::Confirmed,
                    reason: match entity {
                        EntityType::Asset => ReasonCode::AttributeChanged,
                        EntityType::Relationship => ReasonCode::RelationshipAdded,
                        EntityType::Finding => ReasonCode::FindingChanged,
                    },
                    before: Some(value(before)),
                    after: Some(value(after)),
                });
            }
            (None, None) => {}
        }
    }
}

struct ReportBuilder {
    max_records: usize,
    summary_only: bool,
    records: Vec<DiffRecord>,
    truncated_records: usize,
    summary: DiffSummary,
}

impl ReportBuilder {
    fn new(options: DiffOptions) -> Self {
        Self {
            max_records: if options.max_records == 0 {
                MAX_DIFF_RECORDS
            } else {
                options.max_records.min(MAX_DIFF_RECORDS)
            },
            summary_only: options.summary_only,
            records: Vec::new(),
            truncated_records: 0,
            summary: DiffSummary::default(),
        }
    }

    fn push(&mut self, record: DiffRecord) {
        match (record.entity_type, record.change_type) {
            (EntityType::Asset, ChangeType::Added) => self.summary.assets_added += 1,
            (EntityType::Asset, ChangeType::Removed) => self.summary.assets_removed_confirmed += 1,
            (EntityType::Asset, ChangeType::Modified) => self.summary.assets_modified += 1,
            (EntityType::Asset, ChangeType::InconclusiveMissing) => {
                self.summary.assets_missing_inconclusive += 1
            }
            (EntityType::Relationship, ChangeType::Added) => self.summary.relationships_added += 1,
            (EntityType::Relationship, ChangeType::Removed) => {
                self.summary.relationships_removed_confirmed += 1
            }
            (EntityType::Relationship, ChangeType::InconclusiveMissing) => {
                self.summary.relationships_missing_inconclusive += 1
            }
            (EntityType::Finding, ChangeType::Added) => self.summary.findings_added += 1,
            (EntityType::Finding, ChangeType::Removed) => {
                self.summary.findings_removed_confirmed += 1
            }
            (EntityType::Finding, ChangeType::Modified) => self.summary.findings_modified += 1,
            (EntityType::Finding, ChangeType::InconclusiveMissing) => {
                self.summary.findings_missing_inconclusive += 1
            }
            _ => {}
        }
        if self.summary_only || self.records.len() >= self.max_records {
            self.truncated_records += 1;
        } else {
            self.records.push(record);
        }
    }
}

fn compatibility(old: &ScanPlan, new: &ScanPlan) -> PlanCompatibility {
    let target_difference = canonical_targets(old) != canonical_targets(new);
    let scope_difference = old.scope != new.scope;
    let level_difference = (old.level != new.level).then_some((old.level, new.level));
    let goal_difference = old.goal != new.goal;
    let tcp_port_difference = old.tcp_ports != new.tcp_ports;
    let status = if target_difference {
        ComparisonStatus::Incompatible
    } else if scope_difference
        || level_difference.is_some()
        || goal_difference
        || tcp_port_difference
    {
        ComparisonStatus::ComparableWithPlanDifferences
    } else {
        ComparisonStatus::Comparable
    };
    PlanCompatibility {
        status,
        target_difference,
        scope_difference,
        level_difference,
        goal_difference,
        tcp_port_difference,
    }
}

fn canonical_targets(plan: &ScanPlan) -> Vec<String> {
    let mut values = plan
        .targets
        .iter()
        .map(|target| format!("{target:?}"))
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn asset_key(asset: &Asset) -> String {
    format!("{:?}:{}", asset.kind, asset.identity)
}

fn relationship_key(rel: &Relationship) -> String {
    format!(
        "{:?}:{}:{}",
        rel.kind,
        subject_key(&rel.from),
        subject_key(&rel.to)
    )
}

fn finding_key(finding: &Finding) -> String {
    let semantic = finding
        .metadata
        .get("identity")
        .or_else(|| finding.metadata.get("kind"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or(&finding.id.0);
    format!(
        "{}:{:?}:{}:{}",
        finding.title, finding.severity, finding.affected_asset_id.0, semantic
    )
}

fn subject_key(subject: &RelationshipSubject) -> String {
    match subject {
        RelationshipSubject::Asset(id) => format!("asset:{}", id.0),
        RelationshipSubject::Finding(id) => format!("finding:{}", id.0),
        RelationshipSubject::Evidence(id) => format!("evidence:{}", id.0),
    }
}

fn asset_value(asset: &Asset) -> serde_json::Value {
    serde_json::json!({
        "kind": asset.kind,
        "identity": asset.identity,
        "attributes": asset.attributes,
    })
}

fn relationship_value(rel: &Relationship) -> serde_json::Value {
    serde_json::json!({
        "kind": rel.kind,
        "from": subject_key(&rel.from),
        "to": subject_key(&rel.to),
    })
}

fn finding_value(finding: &Finding) -> serde_json::Value {
    serde_json::json!({
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "asset": finding.affected_asset_id,
        "metadata": finding.metadata,
    })
}

pub fn human_summary(report: &DiffReport) -> String {
    format!(
        "RXScan diff\nBaseline: {}\nCurrent: {}\nstatus={:?}\nassets: +{} -{} ~{} ?{}\nrelationships: +{} -{} ?{}\nfindings: +{} -{} ~{} ?{}\nunchanged={}\nnetwork_requests=0",
        report.baseline_scan_id.0,
        report.current_scan_id.0,
        report.comparison_status,
        report.summary.assets_added,
        report.summary.assets_removed_confirmed,
        report.summary.assets_modified,
        report.summary.assets_missing_inconclusive,
        report.summary.relationships_added,
        report.summary.relationships_removed_confirmed,
        report.summary.relationships_missing_inconclusive,
        report.summary.findings_added,
        report.summary.findings_removed_confirmed,
        report.summary.findings_modified,
        report.summary.findings_missing_inconclusive,
        report.summary.unchanged,
    )
}

pub fn to_json(report: &DiffReport) -> Result<String, DiffError> {
    serde_json::to_string_pretty(report)
        .map_err(|error| DiffError::Serialization(error.to_string()))
}

pub fn kind_bucket(kind: &AssetKind) -> &'static str {
    match kind {
        AssetKind::Host | AssetKind::Ip => "host",
        AssetKind::Port => "port",
        AssetKind::Service => "service",
        AssetKind::Url | AssetKind::Endpoint => "endpoint",
        AssetKind::Certificate => "certificate",
        AssetKind::Technology => "technology",
        AssetKind::Other => "other",
    }
}

pub fn tcp_selection_semantic(selection: &TcpPortSelection) -> String {
    match selection {
        TcpPortSelection::Common => "common".to_owned(),
        TcpPortSelection::All => "all".to_owned(),
        TcpPortSelection::Explicit(ports) => format!("explicit:{ports:?}"),
    }
}
