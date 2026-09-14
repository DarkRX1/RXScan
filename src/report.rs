//! Phase 17 deterministic offline reporting and semantic raw export.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    analysis::{self, AnalysisReport},
    diff::{self, DiffReport},
    execution::TaskState,
    model::{
        Asset, AssetKind, Evidence, Finding, RelationshipKind, RelationshipSubject, ScanPlanId,
    },
    persistence::{PersistedScanState, PersistenceError, load_checkpoint},
};

pub const REPORT_SCHEMA_VERSION: u16 = 1;
pub const DEFAULT_REPORT_TOP_N: usize = 10;
pub const MAX_REPORT_TOP_N: usize = 100;
pub const HUMAN_DETAIL_LIMIT: usize = 20;
pub const HUMAN_FIELD_MAX_CHARS: usize = 120;

#[derive(Debug, Error)]
pub enum ReportError {
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
    #[error(transparent)]
    Diff(#[from] diff::DiffError),
    #[error(transparent)]
    Analysis(#[from] analysis::AnalysisError),
    #[error("report input mismatch: {0}")]
    InputMismatch(String),
    #[error("unsupported report format: {0}")]
    UnsupportedFormat(String),
    #[error("report IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("report serialization error: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Human,
    Json,
    Jsonl,
    Raw,
}

impl ReportFormat {
    pub fn parse(value: &str) -> Result<Self, ReportError> {
        match value {
            "human" => Ok(Self::Human),
            "json" => Ok(Self::Json),
            "jsonl" => Ok(Self::Jsonl),
            "raw" => Ok(Self::Raw),
            other => Err(ReportError::UnsupportedFormat(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReportOptions {
    pub format: ReportFormat,
    pub summary_only: bool,
    pub top_n: usize,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            format: ReportFormat::Human,
            summary_only: false,
            top_n: DEFAULT_REPORT_TOP_N,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportSummary {
    pub targets: usize,
    pub assets: usize,
    pub hosts_ips: usize,
    pub hostnames: usize,
    pub open_ports: usize,
    pub services: usize,
    pub endpoints: usize,
    pub dns_relationships: usize,
    pub relationships: usize,
    pub findings: usize,
    pub evidence: usize,
    pub completed_tasks: usize,
    pub failed_incomplete_tasks: usize,
    pub diff_changes: usize,
    pub diff_inconclusive_missing: usize,
    pub high_attention: usize,
    pub medium_attention: usize,
    pub low_attention: usize,
    pub informational_attention: usize,
    pub analysis_signals: usize,
    pub network_requests: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetView {
    pub id: String,
    pub kind: AssetKind,
    pub identity: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationshipView {
    pub kind: RelationshipKind,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingView {
    pub id: String,
    pub title: String,
    pub confidence: u8,
    pub severity: String,
    pub affected_asset_id: String,
    pub evidence_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSummary {
    pub id: String,
    pub source: String,
    pub asset_id: String,
    pub confidence: u8,
    pub captured_bytes: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportTruncation {
    pub details_truncated: bool,
    pub signals_shown: usize,
    pub signals_total: usize,
    pub human_detail_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RawSemanticExport {
    pub raw_schema_version: u16,
    pub scan_id: ScanPlanId,
    pub tasks: Vec<crate::persistence::PersistedTask>,
    pub outputs: Vec<crate::persistence::PersistedModuleOutput>,
    pub registries: crate::persistence::PersistedRegistries,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<DiffReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<AnalysisReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportModel {
    pub report_schema_version: u16,
    pub scan_id: ScanPlanId,
    pub plan_id: ScanPlanId,
    pub level: u8,
    pub goal: String,
    pub summary: ReportSummary,
    pub assets: Vec<AssetView>,
    pub relationships: Vec<RelationshipView>,
    pub findings: Vec<FindingView>,
    pub evidence_summary: Vec<EvidenceSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<DiffReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<AnalysisReport>,
    pub truncation: ReportTruncation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<RawSemanticExport>,
}

pub fn build_report_model(
    state: &PersistedScanState,
    diff: Option<DiffReport>,
    analysis: Option<AnalysisReport>,
    options: &ReportOptions,
) -> Result<ReportModel, ReportError> {
    state.validate()?;
    if let Some(diff) = &diff {
        if diff.current_scan_id != state.scan_id {
            return Err(ReportError::InputMismatch(
                "diff current scan id does not match report scan".to_owned(),
            ));
        }
    }
    if let Some(analysis) = &analysis {
        if analysis.scan_id != state.scan_id {
            return Err(ReportError::InputMismatch(
                "analysis scan id does not match report scan".to_owned(),
            ));
        }
    }
    let mut assets = BTreeMap::<String, Asset>::new();
    let mut relationships = BTreeMap::<(String, String, String), RelationshipKind>::new();
    let mut findings = BTreeMap::<String, Finding>::new();
    let mut evidence = BTreeMap::<String, Evidence>::new();

    for output in &state.outputs {
        for asset in &output.output.assets {
            assets
                .entry(asset.id.0.clone())
                .or_insert_with(|| asset.clone());
        }
        for event in &output.output.events {
            for rel in &event.relationships {
                relationships.insert(
                    (
                        format!("{:?}", rel.kind),
                        subject_key(&rel.from),
                        subject_key(&rel.to),
                    ),
                    rel.kind.clone(),
                );
            }
        }
        for finding in &output.output.findings {
            findings
                .entry(finding.id.0.clone())
                .or_insert_with(|| finding.clone());
        }
        for item in &output.output.evidence {
            evidence
                .entry(item.id.0.clone())
                .or_insert_with(|| item.clone());
        }
    }

    let asset_views = assets
        .values()
        .map(|asset| AssetView {
            id: asset.id.0.clone(),
            kind: asset.kind.clone(),
            identity: asset.identity.clone(),
            attributes: asset.attributes.clone(),
        })
        .collect::<Vec<_>>();
    let relationship_views = relationships
        .iter()
        .map(|((_, from, to), kind)| RelationshipView {
            kind: kind.clone(),
            from: from.clone(),
            to: to.clone(),
        })
        .collect::<Vec<_>>();
    let finding_views = findings
        .values()
        .map(|finding| FindingView {
            id: finding.id.0.clone(),
            title: finding.title.clone(),
            confidence: finding.confidence.0,
            severity: format!("{:?}", finding.severity),
            affected_asset_id: finding.affected_asset_id.0.clone(),
            evidence_count: finding.evidence_ids.len(),
        })
        .collect::<Vec<_>>();
    let evidence_summary = evidence
        .values()
        .map(|item| EvidenceSummary {
            id: item.id.0.clone(),
            source: item.source.clone(),
            asset_id: item.asset_id.0.clone(),
            confidence: item.confidence.0,
            captured_bytes: item.details.captured_bytes,
            truncated: item.details.truncated,
        })
        .collect::<Vec<_>>();

    let mut summary = ReportSummary {
        targets: state.plan.targets.len(),
        assets: asset_views.len(),
        relationships: relationship_views.len(),
        findings: finding_views.len(),
        evidence: evidence_summary.len(),
        completed_tasks: state
            .tasks
            .iter()
            .filter(|task| matches!(task.task.state, TaskState::Succeeded))
            .count(),
        failed_incomplete_tasks: state
            .tasks
            .iter()
            .filter(|task| !matches!(task.task.state, TaskState::Succeeded))
            .count(),
        network_requests: 0,
        ..ReportSummary::default()
    };
    for asset in assets.values() {
        match asset.kind {
            AssetKind::Host | AssetKind::Ip => summary.hosts_ips += 1,
            AssetKind::Other
                if asset.attributes.get("dns_kind").map(String::as_str) == Some("hostname") =>
            {
                summary.hostnames += 1;
            }
            AssetKind::Port
                if asset.attributes.get("state").map(String::as_str) == Some("open") =>
            {
                summary.open_ports += 1;
            }
            AssetKind::Service => summary.services += 1,
            AssetKind::Url | AssetKind::Endpoint => summary.endpoints += 1,
            _ => {}
        }
    }
    for view in &relationship_views {
        if matches!(
            view.kind,
            RelationshipKind::HostnameResolvesToIp
                | RelationshipKind::HostnameAliasesTo
                | RelationshipKind::MailExchangeFor
                | RelationshipKind::NameServerFor
                | RelationshipKind::ReverseResolvesTo
        ) {
            summary.dns_relationships += 1;
        }
    }
    if let Some(diff) = &diff {
        summary.diff_changes = diff.records.len();
        summary.diff_inconclusive_missing = diff
            .records
            .iter()
            .filter(|record| record.change_type == crate::diff::ChangeType::InconclusiveMissing)
            .count();
    }
    if let Some(analysis) = &analysis {
        summary.high_attention = analysis.summary.high_attention;
        summary.medium_attention = analysis.summary.medium_attention;
        summary.low_attention = analysis.summary.low_attention;
        summary.informational_attention = analysis.summary.informational;
        summary.analysis_signals = analysis.total_signals;
    }
    let top_n = options.top_n.min(MAX_REPORT_TOP_N);
    let signals_total = analysis.as_ref().map(|a| a.total_signals).unwrap_or(0);
    let signals_shown = analysis
        .as_ref()
        .map(|a| a.top_signals.len().min(top_n))
        .unwrap_or(0);
    let asset_count = asset_views.len();
    let relationship_count = relationship_views.len();
    let finding_count = finding_views.len();
    let raw = (options.format == ReportFormat::Raw).then(|| RawSemanticExport {
        raw_schema_version: REPORT_SCHEMA_VERSION,
        scan_id: state.scan_id.clone(),
        tasks: state.tasks.clone(),
        outputs: state.outputs.clone(),
        registries: state.registries.clone(),
        diff: diff.clone(),
        analysis: analysis.clone(),
    });
    Ok(ReportModel {
        report_schema_version: REPORT_SCHEMA_VERSION,
        scan_id: state.scan_id.clone(),
        plan_id: state.plan.stable_id(),
        level: state.plan.level,
        goal: format!("{:?}", state.plan.goal),
        summary,
        assets: asset_views,
        relationships: relationship_views,
        findings: finding_views,
        evidence_summary,
        diff,
        analysis,
        truncation: ReportTruncation {
            details_truncated: signals_total > signals_shown
                || asset_count > HUMAN_DETAIL_LIMIT
                || relationship_count > HUMAN_DETAIL_LIMIT
                || finding_count > HUMAN_DETAIL_LIMIT,
            signals_shown,
            signals_total,
            human_detail_limit: HUMAN_DETAIL_LIMIT,
        },
        raw,
    })
}

pub fn report_checkpoint(
    current_path: &Path,
    baseline_path: Option<&Path>,
    include_analysis: bool,
    options: ReportOptions,
) -> Result<ReportModel, ReportError> {
    let current = load_checkpoint(current_path)?;
    let diff = if let Some(baseline) = baseline_path {
        Some(
            diff::diff_checkpoints(baseline, current_path, diff::DiffOptions::default())
                .map(|(report, _, _, _)| report)?,
        )
    } else {
        None
    };
    let analysis = if include_analysis {
        Some(analysis::analyze_state(
            &current.state,
            diff.as_ref(),
            analysis::AnalysisOptions::default(),
        )?)
    } else {
        None
    };
    build_report_model(&current.state, diff, analysis, &options)
}

pub fn render_human(model: &ReportModel, options: &ReportOptions) -> String {
    let mut out = String::new();
    out.push_str("RXScan Summary\n");
    out.push_str(&format!(
        "Scan: {} level={} goal={}\n",
        safe_display(&model.scan_id.0),
        model.level,
        safe_display(&model.goal)
    ));
    out.push_str(&format!(
        "Targets: {}  Assets: {}  Hosts/IPs: {}  Hostnames: {}\n",
        model.summary.targets,
        model.summary.assets,
        model.summary.hosts_ips,
        model.summary.hostnames
    ));
    out.push_str(&format!(
        "Open ports: {}  Services: {}  Endpoints: {}  DNS relationships: {}\n",
        model.summary.open_ports,
        model.summary.services,
        model.summary.endpoints,
        model.summary.dns_relationships
    ));
    out.push_str(&format!(
        "Findings: {}  Evidence: {}  Completed tasks: {}  Incomplete tasks: {}\n",
        model.summary.findings,
        model.summary.evidence,
        model.summary.completed_tasks,
        model.summary.failed_incomplete_tasks
    ));
    if model.summary.failed_incomplete_tasks > 0 {
        out.push_str(&format!(
            "Incomplete / Inconclusive Work: {} task(s) pending, failed, cancelled, or timed out.\n",
            model.summary.failed_incomplete_tasks
        ));
    }
    if let Some(analysis) = &model.analysis {
        out.push_str(&format!(
            "Attention: high={} medium={} low={} informational={} total={}\n",
            model.summary.high_attention,
            model.summary.medium_attention,
            model.summary.low_attention,
            model.summary.informational_attention,
            analysis.total_signals
        ));
        if !options.summary_only && !analysis.top_signals.is_empty() {
            out.push_str("Top Attention Signals\n");
            for signal in analysis
                .top_signals
                .iter()
                .take(options.top_n.min(MAX_REPORT_TOP_N))
            {
                out.push_str(&format!(
                    "- {:?} score={} entity={} confidence={} label={}\n",
                    signal.attention_band,
                    signal.attention_score,
                    safe_display(&signal.primary_entity),
                    signal.confidence,
                    safe_display(&signal.label)
                ));
            }
        }
    }
    if let Some(diff) = &model.diff {
        out.push_str(&format!(
            "Changes: added={} modified={} confirmed_removed={} inconclusive_missing={} status={:?}\n",
            diff.summary.assets_added
                + diff.summary.relationships_added
                + diff.summary.findings_added,
            diff.summary.assets_modified + diff.summary.findings_modified,
            diff.summary.assets_removed_confirmed
                + diff.summary.relationships_removed_confirmed
                + diff.summary.findings_removed_confirmed,
            model.summary.diff_inconclusive_missing,
            diff.comparison_status
        ));
        if model.summary.diff_inconclusive_missing > 0 {
            out.push_str(
                "Changes include InconclusiveMissing records; these are not rendered as removed.\n",
            );
        }
    }
    if !options.summary_only {
        if !model.findings.is_empty() {
            out.push_str("Findings\n");
            for finding in model.findings.iter().take(HUMAN_DETAIL_LIMIT) {
                out.push_str(&format!(
                    "- {} confidence={} affected={} evidence={}\n",
                    safe_display(&finding.title),
                    finding.confidence,
                    safe_display(&finding.affected_asset_id),
                    finding.evidence_count
                ));
            }
        }
        if !model.assets.is_empty() {
            out.push_str("Surface Overview\n");
            for asset in model.assets.iter().take(HUMAN_DETAIL_LIMIT) {
                let external = asset
                    .attributes
                    .get("scope")
                    .is_some_and(|scope| scope == "out_of_scope");
                out.push_str(&format!(
                    "- {:?} {}{}\n",
                    asset.kind,
                    safe_display(&asset.identity),
                    if external {
                        " (external / out of scope)"
                    } else {
                        ""
                    }
                ));
            }
        }
    }
    if model.truncation.details_truncated {
        out.push_str(&format!(
            "Output Notes: details truncated; signals_shown={} signals_total={}\n",
            model.truncation.signals_shown, model.truncation.signals_total
        ));
    }
    out
}

pub fn render_json(model: &ReportModel) -> Result<String, ReportError> {
    serde_json::to_string_pretty(model)
        .map_err(|error| ReportError::Serialization(error.to_string()))
}

pub fn render_raw(model: &ReportModel) -> Result<String, ReportError> {
    serde_json::to_string_pretty(&model.raw)
        .map_err(|error| ReportError::Serialization(error.to_string()))
}

pub fn render_jsonl<W: Write>(model: &ReportModel, mut writer: W) -> Result<(), ReportError> {
    write_jsonl_record(
        &mut writer,
        "report_meta",
        &serde_json::json!({
            "report_schema_version": model.report_schema_version,
            "scan_id": model.scan_id,
            "plan_id": model.plan_id,
            "level": model.level,
            "goal": model.goal,
        }),
    )?;
    write_jsonl_record(&mut writer, "summary", &model.summary)?;
    for asset in &model.assets {
        write_jsonl_record(&mut writer, "asset", asset)?;
    }
    for rel in &model.relationships {
        write_jsonl_record(&mut writer, "relationship", rel)?;
    }
    for finding in &model.findings {
        write_jsonl_record(&mut writer, "finding", finding)?;
    }
    for evidence in &model.evidence_summary {
        write_jsonl_record(&mut writer, "evidence_summary", evidence)?;
    }
    if let Some(diff) = &model.diff {
        for record in &diff.records {
            write_jsonl_record(&mut writer, "diff_change", record)?;
        }
    }
    if let Some(analysis) = &model.analysis {
        for signal in &analysis.top_signals {
            write_jsonl_record(&mut writer, "analysis_signal", signal)?;
        }
    }
    Ok(())
}

pub fn render_to_bytes(
    model: &ReportModel,
    options: &ReportOptions,
) -> Result<Vec<u8>, ReportError> {
    match options.format {
        ReportFormat::Human => Ok(render_human(model, options).into_bytes()),
        ReportFormat::Json => Ok(render_json(model)?.into_bytes()),
        ReportFormat::Raw => Ok(render_raw(model)?.into_bytes()),
        ReportFormat::Jsonl => {
            let mut bytes = Vec::new();
            render_jsonl(model, &mut bytes)?;
            Ok(bytes)
        }
    }
}

pub fn write_output(path: &Path, bytes: &[u8], input_paths: &[&Path]) -> Result<(), ReportError> {
    for input in input_paths {
        if same_path(path, input) {
            return Err(ReportError::InputMismatch(
                "report output path must not overwrite an input checkpoint".to_owned(),
            ));
        }
    }
    let tmp = temp_path(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    {
        let mut writer = BufWriter::new(File::create(&tmp)?);
        writer.write_all(bytes)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn write_jsonl_record<W: Write, T: Serialize>(
    writer: &mut W,
    record_type: &str,
    payload: &T,
) -> Result<(), ReportError> {
    let value = serde_json::json!({
        "record_type": record_type,
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "payload": payload,
    });
    serde_json::to_writer(&mut *writer, &value)
        .map_err(|error| ReportError::Serialization(error.to_string()))?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn subject_key(subject: &RelationshipSubject) -> String {
    match subject {
        RelationshipSubject::Asset(id) => format!("asset:{}", id.0),
        RelationshipSubject::Finding(id) => format!("finding:{}", id.0),
        RelationshipSubject::Evidence(id) => format!("evidence:{}", id.0),
    }
}

pub fn safe_display(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        let safe = match ch {
            '\n' | '\r' | '\t' => ' ',
            c if c.is_control() => ' ',
            c => c,
        };
        out.push(safe);
        if out.chars().count() >= HUMAN_FIELD_MAX_CHARS {
            out.push_str("...");
            break;
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn temp_path(path: &Path) -> std::path::PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "report".into());
    name.push(".tmp");
    path.with_file_name(name)
}

fn same_path(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
