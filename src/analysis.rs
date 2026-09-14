//! Phase 16 deterministic offline analysis and prioritization.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Instant,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    diff::{Certainty, ChangeType, DiffReport, EntityType, ReasonCode},
    model::{
        Asset, AssetId, AssetKind, EvidenceId, Finding, Relationship, RelationshipKind,
        RelationshipSubject, ScanPlanId, Severity,
    },
    persistence::{PersistedScanState, PersistenceError, load_checkpoint},
};

pub const ANALYSIS_SCHEMA_VERSION: u16 = 1;
pub const MAX_ANALYSIS_SIGNALS: usize = 10_000;
pub const DEFAULT_TOP_SIGNALS: usize = 100;
pub const MAX_SIGNAL_EVIDENCE_REFS: usize = 16;
pub const MAX_SIGNAL_RELATED_ASSETS: usize = 16;
pub const SCORE_MIN: i16 = 0;
pub const SCORE_MAX: i16 = 100;
pub const EVIDENCE_MAX: i16 = 25;
pub const NOVELTY_MAX: i16 = 25;
pub const EXPOSURE_MAX: i16 = 20;
pub const CORROBORATION_MAX: i16 = 15;
pub const BREADTH_MAX: i16 = 10;
pub const CONTEXT_MAX: i16 = 10;
pub const UNCERTAINTY_PENALTY_MAX: i16 = 30;
pub const EVIDENCE_PORT: i16 = 20;
pub const EVIDENCE_SERVICE: i16 = 18;
pub const EVIDENCE_WEB: i16 = 16;
pub const EVIDENCE_HOST: i16 = 12;
pub const EVIDENCE_DNS_RELATIONSHIP: i16 = 16;
pub const EVIDENCE_REFLECTION: i16 = 18;
pub const EVIDENCE_UNCERTAINTY: i16 = 8;
pub const EXPOSURE_OPEN_PORT: i16 = 18;
pub const EXPOSURE_NON_OPEN_PORT: i16 = 8;
pub const EXPOSURE_SERVICE: i16 = 14;
pub const EXPOSURE_WEB: i16 = 10;
pub const EXPOSURE_HOST: i16 = 4;
pub const EXPOSURE_FINDING_ASSET_PRESENT: i16 = 8;
pub const NOVELTY_ADDED_CONFIRMED: i16 = 22;
pub const NOVELTY_ADDED_EXPANDED_COVERAGE: i16 = 12;
pub const NOVELTY_MODIFIED: i16 = 18;
pub const CONTEXT_UNUSUAL_PORT: i16 = 3;
pub const CONTEXT_SENSITIVE_PATH: i16 = 4;
pub const CONTEXT_DNS_RELATIONSHIP: i16 = 6;
pub const CONTEXT_REFLECTION: i16 = 10;
pub const CONTEXT_UNCERTAINTY: i16 = 4;
pub const CONTEXT_FINDING_INFO: i16 = 2;
pub const CONTEXT_FINDING_LOW: i16 = 4;
pub const CONTEXT_FINDING_MEDIUM: i16 = 6;
pub const CONTEXT_FINDING_HIGH: i16 = 8;
pub const CONTEXT_FINDING_CRITICAL: i16 = 10;
pub const CORROBORATION_MULTIPLE_EVIDENCE: i16 = 6;
pub const CORROBORATION_MERGE_INCREMENT: i16 = 4;
pub const UNCERTAINTY_SOFT404: i16 = 20;
pub const UNCERTAINTY_OUT_OF_SCOPE_RELATIONSHIP: i16 = 10;
pub const UNCERTAINTY_INCONCLUSIVE_MISSING: i16 = 20;
pub const UNCERTAINTY_INCONCLUSIVE_CERTAINTY: i16 = 12;
pub const UNCERTAINTY_DIFF_SIGNAL: i16 = 18;

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error("analysis diff mismatch: {0}")]
    DiffMismatch(String),
    #[error("could not serialize analysis: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttentionBand {
    Informational,
    LowAttention,
    MediumAttention,
    HighAttention,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalCategory {
    Network,
    Service,
    Web,
    Dns,
    Finding,
    Change,
    Correlation,
    Uncertainty,
    Informational,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalType {
    Exposure,
    Change,
    Finding,
    WebSurface,
    NetworkSurface,
    DnsSurface,
    IdentityChange,
    Correlation,
    Uncertainty,
    Informational,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisReason {
    NewlyObservedOpenPort,
    NewServiceObserved,
    ServiceChanged,
    NewEndpointObserved,
    EndpointBehaviorChanged,
    DnsMappingChanged,
    NewFindingObserved,
    FindingChanged,
    ExternallyReachableAsset,
    HighConfidenceObservation,
    MultipleEvidenceSources,
    CrossModuleCorroboration,
    ExpandedAttackSurface,
    ReducedConfidenceDueToTimeout,
    InconclusiveCoverage,
    OutOfScopeRelationship,
    SensitiveLookingEndpointName,
    UnusualServicePortCombination,
    BehavioralReflectionObserved,
    Soft404OrWildcardSuppressed,
    PersistentObservation,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreComponents {
    pub evidence: i16,
    pub novelty: i16,
    pub exposure: i16,
    pub corroboration: i16,
    pub breadth: i16,
    pub context: i16,
    pub uncertainty_penalty: i16,
}

impl ScoreComponents {
    pub fn bounded(self) -> Self {
        Self {
            evidence: self.evidence.clamp(SCORE_MIN, EVIDENCE_MAX),
            novelty: self.novelty.clamp(SCORE_MIN, NOVELTY_MAX),
            exposure: self.exposure.clamp(SCORE_MIN, EXPOSURE_MAX),
            corroboration: self.corroboration.clamp(SCORE_MIN, CORROBORATION_MAX),
            breadth: self.breadth.clamp(SCORE_MIN, BREADTH_MAX),
            context: self.context.clamp(SCORE_MIN, CONTEXT_MAX),
            uncertainty_penalty: self
                .uncertainty_penalty
                .clamp(SCORE_MIN, UNCERTAINTY_PENALTY_MAX),
        }
    }

    pub fn total(self) -> u8 {
        let self_ = self.bounded();
        let total = i32::from(self_.evidence)
            + i32::from(self_.novelty)
            + i32::from(self_.exposure)
            + i32::from(self_.corroboration)
            + i32::from(self_.breadth)
            + i32::from(self_.context)
            - i32::from(self_.uncertainty_penalty);
        total.clamp(0, 100) as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrioritySignal {
    pub id: String,
    pub signal_type: SignalType,
    pub category: SignalCategory,
    pub primary_entity: String,
    pub attention_score: u8,
    pub attention_band: AttentionBand,
    pub confidence: u8,
    pub components: ScoreComponents,
    pub reasons: Vec<AnalysisReason>,
    pub evidence_ids: Vec<EvidenceId>,
    pub related_assets: Vec<AssetId>,
    pub newly_observed: bool,
    pub changed: bool,
    pub persistent: bool,
    pub inconclusive: bool,
    pub externally_related: bool,
    pub label: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub high_attention: usize,
    pub medium_attention: usize,
    pub low_attention: usize,
    pub informational: usize,
    pub network_signals: usize,
    pub web_signals: usize,
    pub dns_signals: usize,
    pub finding_signals: usize,
    pub change_signals: usize,
    pub correlation_signals: usize,
    pub inconclusive_signals: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub analysis_schema_version: u16,
    pub scan_id: ScanPlanId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_scan_id: Option<ScanPlanId>,
    pub total_signals: usize,
    pub signals_emitted: usize,
    pub signals_truncated: bool,
    pub truncated_signals: usize,
    pub summary: AnalysisSummary,
    pub top_signals: Vec<PrioritySignal>,
    pub network_requests: u64,
}

#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    pub max_signals: usize,
    pub top_signals: usize,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            max_signals: MAX_ANALYSIS_SIGNALS,
            top_signals: DEFAULT_TOP_SIGNALS,
        }
    }
}

#[derive(Debug, Clone)]
struct SignalDraft {
    id: String,
    signal_type: SignalType,
    category: SignalCategory,
    primary_entity: String,
    confidence: u8,
    components: ScoreComponents,
    reasons: BTreeSet<AnalysisReason>,
    evidence_ids: BTreeSet<EvidenceId>,
    related_assets: BTreeSet<AssetId>,
    newly_observed: bool,
    changed: bool,
    persistent: bool,
    inconclusive: bool,
    externally_related: bool,
    label: String,
}

#[derive(Debug, Default)]
struct AnalysisIndex<'a> {
    assets: BTreeMap<String, &'a Asset>,
    relationships: Vec<&'a Relationship>,
    findings: Vec<&'a Finding>,
    evidence_by_asset: BTreeMap<AssetId, BTreeSet<EvidenceId>>,
    degree: BTreeMap<AssetId, usize>,
}

pub fn analyze_checkpoint(
    path: &Path,
    options: AnalysisOptions,
) -> Result<(AnalysisReport, u128), AnalysisError> {
    let started = Instant::now();
    let loaded = load_checkpoint(path)?;
    let report = analyze_state(&loaded.state, None, options)?;
    Ok((report, started.elapsed().as_millis()))
}

pub fn analyze_checkpoint_with_diff(
    current_path: &Path,
    diff: &DiffReport,
    options: AnalysisOptions,
) -> Result<(AnalysisReport, u128), AnalysisError> {
    let started = Instant::now();
    let loaded = load_checkpoint(current_path)?;
    let report = analyze_state(&loaded.state, Some(diff), options)?;
    Ok((report, started.elapsed().as_millis()))
}

pub fn analyze_state(
    state: &PersistedScanState,
    diff: Option<&DiffReport>,
    options: AnalysisOptions,
) -> Result<AnalysisReport, AnalysisError> {
    state.validate()?;
    if let Some(diff) = diff {
        if diff.current_scan_id != state.scan_id {
            return Err(AnalysisError::DiffMismatch(
                "diff current scan id does not match analyzed state".to_owned(),
            ));
        }
    }
    let options = AnalysisOptions {
        max_signals: options.max_signals.min(MAX_ANALYSIS_SIGNALS),
        top_signals: options.top_signals.min(MAX_ANALYSIS_SIGNALS),
    };
    let index = build_index(state);
    let diff_map = build_diff_map(diff);
    let mut builder = SignalBuilder::new(options.max_signals);
    analyze_assets(&index, &diff_map, &mut builder);
    analyze_relationships(&index, &diff_map, &mut builder);
    analyze_findings(&index, &diff_map, &mut builder);
    analyze_diff_uncertainty(diff, &mut builder);
    let total_signals = builder.total_signals;
    let truncated_signals = builder.truncated_signals;
    let summary = builder.summary.clone();
    let mut signals = builder.finish();
    sort_signals(&mut signals);
    let emitted = signals.len().min(options.top_signals);
    signals.truncate(emitted);
    Ok(AnalysisReport {
        analysis_schema_version: ANALYSIS_SCHEMA_VERSION,
        scan_id: state.scan_id.clone(),
        baseline_scan_id: diff.map(|report| report.baseline_scan_id.clone()),
        total_signals,
        signals_emitted: signals.len(),
        signals_truncated: truncated_signals > 0,
        truncated_signals,
        summary,
        top_signals: signals,
        network_requests: 0,
    })
}

pub fn to_json(report: &AnalysisReport) -> Result<String, AnalysisError> {
    serde_json::to_string_pretty(report)
        .map_err(|error| AnalysisError::Serialization(error.to_string()))
}

pub fn human_summary(report: &AnalysisReport) -> String {
    let mut out = String::new();
    out.push_str("RXScan analysis\n");
    out.push_str(&format!(
        "signals={} emitted={} truncated={} network_requests={}\n",
        report.total_signals,
        report.signals_emitted,
        report.signals_truncated,
        report.network_requests
    ));
    for signal in report.top_signals.iter().take(10) {
        out.push_str(&format!(
            "{:?} score={} confidence={} {} ({})\n",
            signal.attention_band,
            signal.attention_score,
            signal.confidence,
            signal.label,
            signal.primary_entity
        ));
    }
    out
}

fn build_index(state: &PersistedScanState) -> AnalysisIndex<'_> {
    let mut index = AnalysisIndex::default();
    for output in &state.outputs {
        for asset in &output.output.assets {
            index.assets.insert(asset.id.0.clone(), asset);
        }
        for evidence in &output.output.evidence {
            index
                .evidence_by_asset
                .entry(evidence.asset_id.clone())
                .or_default()
                .insert(evidence.id.clone());
        }
        for event in &output.output.events {
            for rel in &event.relationships {
                if let RelationshipSubject::Asset(id) = &rel.from {
                    *index.degree.entry(id.clone()).or_default() += 1;
                }
                if let RelationshipSubject::Asset(id) = &rel.to {
                    *index.degree.entry(id.clone()).or_default() += 1;
                }
                index.relationships.push(rel);
            }
        }
        for finding in &output.output.findings {
            index.findings.push(finding);
        }
    }
    index
}

fn build_diff_map(diff: Option<&DiffReport>) -> BTreeMap<String, &crate::diff::DiffRecord> {
    let mut map = BTreeMap::new();
    if let Some(diff) = diff {
        for record in &diff.records {
            map.insert(
                format!("{:?}:{}", record.entity_type, record.semantic_id),
                record,
            );
        }
    }
    map
}

fn analyze_assets(
    index: &AnalysisIndex<'_>,
    diff: &BTreeMap<String, &crate::diff::DiffRecord>,
    builder: &mut SignalBuilder,
) {
    for asset in index.assets.values() {
        let semantic_key = asset_key(asset);
        let diff_record = diff.get(&format!("{:?}:{}", EntityType::Asset, semantic_key));
        let mut draft = match asset.kind {
            AssetKind::Port => port_signal(asset),
            AssetKind::Service => service_signal(asset),
            AssetKind::Url | AssetKind::Endpoint => web_signal(asset),
            AssetKind::Ip | AssetKind::Host => host_signal(asset),
            _ => info_signal(asset),
        };
        attach_asset_context(&mut draft, asset, index);
        apply_diff(&mut draft, diff_record.copied());
        builder.push(draft);
    }
}

fn analyze_relationships(
    index: &AnalysisIndex<'_>,
    diff: &BTreeMap<String, &crate::diff::DiffRecord>,
    builder: &mut SignalBuilder,
) {
    for rel in &index.relationships {
        let semantic_key = relationship_key(rel);
        let diff_record = diff.get(&format!("{:?}:{}", EntityType::Relationship, semantic_key));
        match rel.kind {
            RelationshipKind::HostnameResolvesToIp
            | RelationshipKind::HostnameAliasesTo
            | RelationshipKind::MailExchangeFor
            | RelationshipKind::NameServerFor
            | RelationshipKind::ReverseResolvesTo => {
                let mut draft = base_signal(
                    SignalType::DnsSurface,
                    SignalCategory::Dns,
                    format!("relationship:{semantic_key}"),
                    "DNS relationship observed",
                );
                draft.components.evidence = EVIDENCE_DNS_RELATIONSHIP;
                draft.components.context = CONTEXT_DNS_RELATIONSHIP;
                draft.reasons.insert(AnalysisReason::DnsMappingChanged);
                if is_out_of_scope_relationship(rel, index) {
                    draft.externally_related = true;
                    draft.reasons.insert(AnalysisReason::OutOfScopeRelationship);
                    draft.components.exposure = 0;
                    draft.components.uncertainty_penalty += UNCERTAINTY_OUT_OF_SCOPE_RELATIONSHIP;
                }
                add_related_from_subject(&mut draft, &rel.from);
                add_related_from_subject(&mut draft, &rel.to);
                apply_diff(&mut draft, diff_record.copied());
                builder.push(draft);
            }
            RelationshipKind::ReflectsInput => {
                let mut draft = base_signal(
                    SignalType::WebSurface,
                    SignalCategory::Web,
                    format!("relationship:{semantic_key}"),
                    "Input reflection observed",
                );
                draft.components.evidence = EVIDENCE_REFLECTION;
                draft.components.context = CONTEXT_REFLECTION;
                draft
                    .reasons
                    .insert(AnalysisReason::BehavioralReflectionObserved);
                add_related_from_subject(&mut draft, &rel.from);
                add_related_from_subject(&mut draft, &rel.to);
                apply_diff(&mut draft, diff_record.copied());
                builder.push(draft);
            }
            _ => {}
        }
    }
}

fn analyze_findings(
    index: &AnalysisIndex<'_>,
    diff: &BTreeMap<String, &crate::diff::DiffRecord>,
    builder: &mut SignalBuilder,
) {
    for finding in &index.findings {
        let semantic_key = finding_key(finding);
        let diff_record = diff.get(&format!("{:?}:{}", EntityType::Finding, semantic_key));
        let mut draft = base_signal(
            SignalType::Finding,
            SignalCategory::Finding,
            format!("finding:{semantic_key}"),
            &format!("Finding observed: {}", bounded_label(&finding.title)),
        );
        draft.confidence = finding.confidence.0;
        draft.components.evidence = i16::from(finding.confidence.0 / 4).min(EVIDENCE_MAX);
        draft.components.context = match finding.severity {
            Severity::Info => CONTEXT_FINDING_INFO,
            Severity::Low => CONTEXT_FINDING_LOW,
            Severity::Medium => CONTEXT_FINDING_MEDIUM,
            Severity::High => CONTEXT_FINDING_HIGH,
            Severity::Critical => CONTEXT_FINDING_CRITICAL,
        };
        draft
            .reasons
            .insert(AnalysisReason::HighConfidenceObservation);
        for evidence_id in finding.evidence_ids.iter().take(MAX_SIGNAL_EVIDENCE_REFS) {
            draft.evidence_ids.insert(evidence_id.clone());
        }
        if finding.evidence_ids.len() > 1 {
            draft.components.corroboration += CORROBORATION_MULTIPLE_EVIDENCE;
            draft
                .reasons
                .insert(AnalysisReason::MultipleEvidenceSources);
        }
        draft
            .related_assets
            .insert(finding.affected_asset_id.clone());
        if index.assets.contains_key(&finding.affected_asset_id.0) {
            draft.components.exposure += EXPOSURE_FINDING_ASSET_PRESENT;
        }
        let degree = index
            .degree
            .get(&finding.affected_asset_id)
            .copied()
            .unwrap_or(0);
        if degree >= 3 {
            draft.components.breadth += (degree.min(BREADTH_MAX as usize) as i16).min(BREADTH_MAX);
            draft
                .reasons
                .insert(AnalysisReason::CrossModuleCorroboration);
        }
        apply_diff(&mut draft, diff_record.copied());
        if matches!(diff_record.map(|r| r.change_type), Some(ChangeType::Added)) {
            draft.reasons.insert(AnalysisReason::NewFindingObserved);
        } else if matches!(
            diff_record.map(|r| r.change_type),
            Some(ChangeType::Modified)
        ) {
            draft.reasons.insert(AnalysisReason::FindingChanged);
        }
        builder.push(draft);
    }
}

fn analyze_diff_uncertainty(diff: Option<&DiffReport>, builder: &mut SignalBuilder) {
    let Some(diff) = diff else {
        return;
    };
    for record in &diff.records {
        if record.change_type != ChangeType::InconclusiveMissing {
            continue;
        }
        let mut draft = base_signal(
            SignalType::Uncertainty,
            SignalCategory::Uncertainty,
            format!(
                "uncertainty:{:?}:{}",
                record.entity_type, record.semantic_id
            ),
            "Inconclusive missing observation",
        );
        draft.confidence = 35;
        draft.inconclusive = true;
        draft.components.evidence = EVIDENCE_UNCERTAINTY;
        draft.components.context = CONTEXT_UNCERTAINTY;
        draft.components.uncertainty_penalty = UNCERTAINTY_DIFF_SIGNAL;
        draft.reasons.insert(match record.reason {
            ReasonCode::NetworkErrorPreventsConfirmation => {
                AnalysisReason::ReducedConfidenceDueToTimeout
            }
            _ => AnalysisReason::InconclusiveCoverage,
        });
        builder.push(draft);
    }
}

fn port_signal(asset: &Asset) -> SignalDraft {
    let mut draft = base_signal(
        SignalType::NetworkSurface,
        SignalCategory::Network,
        format!("asset:{}", asset.id.0),
        "Open or observed network port",
    );
    draft.components.evidence = EVIDENCE_PORT;
    draft.components.exposure = if asset.attributes.get("state").map(String::as_str) == Some("open")
    {
        EXPOSURE_OPEN_PORT
    } else {
        EXPOSURE_NON_OPEN_PORT
    };
    draft
        .reasons
        .insert(AnalysisReason::ExternallyReachableAsset);
    if is_unusual_port(asset) {
        draft.components.context += CONTEXT_UNUSUAL_PORT;
        draft
            .reasons
            .insert(AnalysisReason::UnusualServicePortCombination);
    }
    draft
}

fn service_signal(asset: &Asset) -> SignalDraft {
    let mut draft = base_signal(
        SignalType::Exposure,
        SignalCategory::Service,
        format!("asset:{}", asset.id.0),
        "Service observed",
    );
    draft.components.evidence = EVIDENCE_SERVICE;
    draft.components.exposure = EXPOSURE_SERVICE;
    draft.reasons.insert(AnalysisReason::NewServiceObserved);
    draft
}

fn web_signal(asset: &Asset) -> SignalDraft {
    let mut draft = base_signal(
        SignalType::WebSurface,
        SignalCategory::Web,
        format!("asset:{}", asset.id.0),
        "Web surface observed",
    );
    draft.components.evidence = EVIDENCE_WEB;
    draft.components.exposure = EXPOSURE_WEB;
    if looks_soft404(asset) {
        draft.components.uncertainty_penalty += UNCERTAINTY_SOFT404;
        draft
            .reasons
            .insert(AnalysisReason::Soft404OrWildcardSuppressed);
    }
    if has_sensitive_path_hint(&asset.identity) {
        draft.components.context += CONTEXT_SENSITIVE_PATH;
        draft
            .reasons
            .insert(AnalysisReason::SensitiveLookingEndpointName);
    }
    draft
}

fn host_signal(asset: &Asset) -> SignalDraft {
    let mut draft = base_signal(
        SignalType::Informational,
        SignalCategory::Informational,
        format!("asset:{}", asset.id.0),
        "Host or address observed",
    );
    draft.components.evidence = EVIDENCE_HOST;
    draft.components.exposure = EXPOSURE_HOST;
    draft
}

fn info_signal(asset: &Asset) -> SignalDraft {
    base_signal(
        SignalType::Informational,
        SignalCategory::Informational,
        format!("asset:{}", asset.id.0),
        "Asset observed",
    )
}

fn base_signal(
    signal_type: SignalType,
    category: SignalCategory,
    primary_entity: String,
    label: &str,
) -> SignalDraft {
    SignalDraft {
        id: signal_id(signal_type, &primary_entity, label),
        signal_type,
        category,
        primary_entity,
        confidence: 70,
        components: ScoreComponents::default(),
        reasons: BTreeSet::new(),
        evidence_ids: BTreeSet::new(),
        related_assets: BTreeSet::new(),
        newly_observed: false,
        changed: false,
        persistent: true,
        inconclusive: false,
        externally_related: false,
        label: bounded_label(label),
    }
}

fn attach_asset_context(draft: &mut SignalDraft, asset: &Asset, index: &AnalysisIndex<'_>) {
    draft.related_assets.insert(asset.id.clone());
    if let Some(evidence) = index.evidence_by_asset.get(&asset.id) {
        for evidence_id in evidence.iter().take(MAX_SIGNAL_EVIDENCE_REFS) {
            draft.evidence_ids.insert(evidence_id.clone());
        }
        if evidence.len() > 1 {
            draft.components.corroboration += CORROBORATION_MULTIPLE_EVIDENCE;
            draft
                .reasons
                .insert(AnalysisReason::MultipleEvidenceSources);
        }
    }
    let degree = index.degree.get(&asset.id).copied().unwrap_or(0);
    if degree >= 3 {
        draft.components.breadth += (degree.min(BREADTH_MAX as usize) as i16).min(BREADTH_MAX);
        draft
            .reasons
            .insert(AnalysisReason::CrossModuleCorroboration);
    }
}

fn apply_diff(draft: &mut SignalDraft, record: Option<&crate::diff::DiffRecord>) {
    let Some(record) = record else {
        draft.reasons.insert(AnalysisReason::PersistentObservation);
        return;
    };
    match record.change_type {
        ChangeType::Added => {
            draft.newly_observed = true;
            draft.persistent = false;
            draft.components.novelty += match record.reason {
                ReasonCode::NewlyObservedWithExpandedCoverage => NOVELTY_ADDED_EXPANDED_COVERAGE,
                _ => NOVELTY_ADDED_CONFIRMED,
            };
            draft.reasons.insert(match draft.category {
                SignalCategory::Network => AnalysisReason::NewlyObservedOpenPort,
                SignalCategory::Service => AnalysisReason::NewServiceObserved,
                SignalCategory::Web => AnalysisReason::NewEndpointObserved,
                SignalCategory::Dns => AnalysisReason::DnsMappingChanged,
                SignalCategory::Finding => AnalysisReason::NewFindingObserved,
                _ => AnalysisReason::ExpandedAttackSurface,
            });
        }
        ChangeType::Modified => {
            draft.changed = true;
            draft.persistent = false;
            draft.components.novelty += NOVELTY_MODIFIED;
            draft.reasons.insert(match draft.category {
                SignalCategory::Service => AnalysisReason::ServiceChanged,
                SignalCategory::Web => AnalysisReason::EndpointBehaviorChanged,
                SignalCategory::Dns => AnalysisReason::DnsMappingChanged,
                SignalCategory::Finding => AnalysisReason::FindingChanged,
                _ => AnalysisReason::ExpandedAttackSurface,
            });
        }
        ChangeType::InconclusiveMissing => {
            draft.inconclusive = true;
            draft.persistent = false;
            draft.confidence = draft.confidence.min(45);
            draft.components.uncertainty_penalty += UNCERTAINTY_INCONCLUSIVE_MISSING;
            draft.reasons.insert(AnalysisReason::InconclusiveCoverage);
        }
        ChangeType::Removed | ChangeType::Unchanged => {}
    }
    if record.certainty == Certainty::Inconclusive {
        draft.inconclusive = true;
        draft.confidence = draft.confidence.min(45);
        draft.components.uncertainty_penalty += UNCERTAINTY_INCONCLUSIVE_CERTAINTY;
    }
}

struct SignalBuilder {
    drafts: BTreeMap<String, SignalDraft>,
    max: usize,
    total_signals: usize,
    truncated_signals: usize,
    summary: AnalysisSummary,
}

impl SignalBuilder {
    fn new(max: usize) -> Self {
        Self {
            drafts: BTreeMap::new(),
            max,
            total_signals: 0,
            truncated_signals: 0,
            summary: AnalysisSummary::default(),
        }
    }

    fn push(&mut self, draft: SignalDraft) {
        self.total_signals += 1;
        summarize_signal(&mut self.summary, &draft);
        if let Some(existing) = self.drafts.get_mut(&draft.id) {
            merge(existing, draft);
            return;
        }
        if self.drafts.len() >= self.max {
            self.truncated_signals += 1;
            return;
        }
        self.drafts.insert(draft.id.clone(), draft);
    }

    fn finish(self) -> Vec<PrioritySignal> {
        self.drafts
            .into_values()
            .map(|draft| {
                let components = draft.components.bounded();
                let score = components.total();
                PrioritySignal {
                    id: draft.id,
                    signal_type: draft.signal_type,
                    category: draft.category,
                    primary_entity: draft.primary_entity,
                    attention_score: score,
                    attention_band: band(score),
                    confidence: draft.confidence,
                    components,
                    reasons: draft.reasons.into_iter().collect(),
                    evidence_ids: draft
                        .evidence_ids
                        .into_iter()
                        .take(MAX_SIGNAL_EVIDENCE_REFS)
                        .collect(),
                    related_assets: draft
                        .related_assets
                        .into_iter()
                        .take(MAX_SIGNAL_RELATED_ASSETS)
                        .collect(),
                    newly_observed: draft.newly_observed,
                    changed: draft.changed,
                    persistent: draft.persistent,
                    inconclusive: draft.inconclusive,
                    externally_related: draft.externally_related,
                    label: draft.label,
                }
            })
            .collect()
    }
}

fn merge(existing: &mut SignalDraft, incoming: SignalDraft) {
    existing.confidence = existing.confidence.max(incoming.confidence);
    existing.components.evidence = existing
        .components
        .evidence
        .max(incoming.components.evidence);
    existing.components.novelty = existing.components.novelty.max(incoming.components.novelty);
    existing.components.exposure = existing
        .components
        .exposure
        .max(incoming.components.exposure);
    existing.components.context = existing.components.context.max(incoming.components.context);
    existing.components.uncertainty_penalty = existing
        .components
        .uncertainty_penalty
        .max(incoming.components.uncertainty_penalty);
    existing.components.corroboration =
        (existing.components.corroboration + CORROBORATION_MERGE_INCREMENT).min(CORROBORATION_MAX);
    existing.reasons.extend(incoming.reasons);
    existing.evidence_ids.extend(incoming.evidence_ids);
    existing.related_assets.extend(incoming.related_assets);
    existing.newly_observed |= incoming.newly_observed;
    existing.changed |= incoming.changed;
    existing.persistent &= incoming.persistent;
    existing.inconclusive |= incoming.inconclusive;
    existing.externally_related |= incoming.externally_related;
}

fn sort_signals(signals: &mut [PrioritySignal]) {
    signals.sort_by(|left, right| {
        right
            .attention_score
            .cmp(&left.attention_score)
            .then_with(|| right.confidence.cmp(&left.confidence))
            .then_with(|| left.signal_type.cmp(&right.signal_type))
            .then_with(|| left.primary_entity.cmp(&right.primary_entity))
            .then_with(|| left.id.cmp(&right.id))
    });
}

fn summarize_signal(summary: &mut AnalysisSummary, signal: &SignalDraft) {
    match band(signal.components.total()) {
        AttentionBand::HighAttention => summary.high_attention += 1,
        AttentionBand::MediumAttention => summary.medium_attention += 1,
        AttentionBand::LowAttention => summary.low_attention += 1,
        AttentionBand::Informational => summary.informational += 1,
    }
    match signal.category {
        SignalCategory::Network => summary.network_signals += 1,
        SignalCategory::Web => summary.web_signals += 1,
        SignalCategory::Dns => summary.dns_signals += 1,
        SignalCategory::Finding => summary.finding_signals += 1,
        SignalCategory::Change => summary.change_signals += 1,
        SignalCategory::Correlation => summary.correlation_signals += 1,
        SignalCategory::Uncertainty => summary.inconclusive_signals += 1,
        SignalCategory::Service => summary.network_signals += 1,
        SignalCategory::Informational => {}
    }
    if signal.changed || signal.newly_observed {
        summary.change_signals += 1;
    }
    if signal.inconclusive {
        summary.inconclusive_signals += 1;
    }
    if signal
        .reasons
        .contains(&AnalysisReason::CrossModuleCorroboration)
    {
        summary.correlation_signals += 1;
    }
}

fn band(score: u8) -> AttentionBand {
    match score {
        80..=100 => AttentionBand::HighAttention,
        50..=79 => AttentionBand::MediumAttention,
        20..=49 => AttentionBand::LowAttention,
        _ => AttentionBand::Informational,
    }
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

fn signal_id(signal_type: SignalType, primary: &str, label: &str) -> String {
    format!(
        "analysis_{:016x}",
        stable_hash(&format!("{signal_type:?}:{primary}:{label}"))
    )
}

fn stable_hash(input: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn add_related_from_subject(draft: &mut SignalDraft, subject: &RelationshipSubject) {
    if let RelationshipSubject::Asset(id) = subject {
        draft.related_assets.insert(id.clone());
    }
}

fn is_out_of_scope_relationship(rel: &Relationship, index: &AnalysisIndex<'_>) -> bool {
    for subject in [&rel.from, &rel.to] {
        if let RelationshipSubject::Asset(id) = subject {
            if !index.assets.contains_key(&id.0) {
                return true;
            }
            if index
                .assets
                .get(&id.0)
                .and_then(|asset| asset.attributes.get("scope"))
                .map(String::as_str)
                == Some("out_of_scope")
            {
                return true;
            }
        }
    }
    false
}

fn has_sensitive_path_hint(identity: &str) -> bool {
    let lowered = identity.to_ascii_lowercase();
    ["admin", "login", "debug", "api", "internal", "backup"]
        .iter()
        .any(|needle| lowered.contains(needle))
}

fn looks_soft404(asset: &Asset) -> bool {
    asset.attributes.iter().any(|(key, value)| {
        let text = format!("{key}:{value}").to_ascii_lowercase();
        text.contains("soft404") || text.contains("soft_404") || text.contains("wildcard")
    })
}

fn is_unusual_port(asset: &Asset) -> bool {
    let port = asset
        .attributes
        .get("port")
        .and_then(|value| value.parse::<u16>().ok())
        .or_else(|| {
            asset
                .identity
                .rsplit(':')
                .next()
                .and_then(|value| value.parse().ok())
        });
    matches!(port, Some(port) if !matches!(port, 21 | 22 | 25 | 53 | 80 | 110 | 143 | 443 | 465 | 587 | 993 | 995))
}

fn bounded_label(label: &str) -> String {
    const MAX_LABEL: usize = 160;
    let clean = label
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_LABEL)
        .collect::<String>();
    if clean.is_empty() {
        "Observation".to_owned()
    } else {
        clean
    }
}
