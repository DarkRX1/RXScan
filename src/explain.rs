//! Explain mode (Phase 7): one evidence-chain code path for CLI and GUI.
//!
//! `rxscan explain finding <id> --checkpoint <scan.rxscan>` and
//! `rxscan explain node <id> --project-db <proj.db>` render from the same
//! [`crate::graph_view::EvidenceLink`] chains the GUI detail panel uses
//! (`GET /api/v1/projects/:name/graph/node` serves
//! [`crate::graph_view::node_detail`] directly). Every chain answers:
//! what was observed, how it was interpreted, the confidence, and what
//! would raise or lower it. All strings are secret-masked.

use std::collections::BTreeMap;
use std::path::Path;

use crate::exposure::scrub_text;
use crate::graph_view::{EvidenceLink, NodeDetail};
use crate::model::{Evidence, Finding};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplainError {
    NotFound(String),
    Store(String),
}

impl std::fmt::Display for ExplainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(detail) => write!(f, "not found: {detail}"),
            Self::Store(detail) => write!(f, "store error: {detail}"),
        }
    }
}

/// A finding plus its resolved evidence chain (shared renderer input).
#[derive(Debug, Clone)]
pub struct ExplainedFinding {
    pub finding: Finding,
    pub asset_identity: String,
    pub chain: Vec<EvidenceLink>,
}

/// Resolve a finding by id from a checkpoint and attach its evidence.
pub fn explain_finding(checkpoint: &Path, id: &str) -> Result<ExplainedFinding, ExplainError> {
    let loaded = crate::persistence::load_checkpoint(checkpoint)
        .map_err(|error| ExplainError::Store(error.to_string()))?;
    let mut findings: BTreeMap<String, &Finding> = BTreeMap::new();
    let mut evidence: BTreeMap<String, &Evidence> = BTreeMap::new();
    let mut assets: BTreeMap<String, String> = BTreeMap::new();
    for output in &loaded.state.outputs {
        for asset in &output.output.assets {
            assets
                .entry(asset.id.0.clone())
                .or_insert_with(|| asset.identity.clone());
        }
        for item in &output.output.evidence {
            evidence.entry(item.id.0.clone()).or_insert(item);
        }
        for finding in &output.output.findings {
            findings.entry(finding.id.0.clone()).or_insert(finding);
        }
    }
    let finding = findings
        .get(id)
        .ok_or_else(|| ExplainError::NotFound(format!("finding {id}")))?;
    let asset_identity = assets
        .get(&finding.affected_asset_id.0)
        .cloned()
        .unwrap_or_else(|| finding.affected_asset_id.0.clone());
    let mut chain: Vec<EvidenceLink> = finding
        .evidence_ids
        .iter()
        .filter_map(|evidence_id| evidence.get(&evidence_id.0))
        .map(|item| EvidenceLink {
            summary: format!(
                "observed: {} (confidence {})",
                item.source, item.confidence.0
            ),
            module: item.provenance.module_name.clone(),
            scan_run: item.provenance.scan_plan_id.0.clone(),
            confidence: Some(item.confidence.0),
            observed: None,
        })
        .collect();
    chain.sort_by(|a, b| a.summary.cmp(&b.summary));
    chain.truncate(64);
    Ok(ExplainedFinding {
        finding: (*finding).clone(),
        asset_identity,
        chain,
    })
}

/// Resolve a graph node from a project database with its evidence chain.
/// Same [`crate::graph_view::node_detail`] path the GUI inspector uses.
pub fn explain_node(db_path: &Path, id: &str) -> Result<NodeDetail, ExplainError> {
    let db = crate::project_db::ProjectDb::open(db_path)
        .map_err(|error| ExplainError::Store(error.to_string()))?;
    let options = crate::graph_view::ViewOptions {
        seed: Some(id.to_owned()),
        depth: 1,
        limit_nodes: 500,
        limit_edges: 1000,
        ..crate::graph_view::ViewOptions::default()
    }
    .bounded();
    let view = crate::graph_view::build_from_db(&db, &options).map_err(ExplainError::Store)?;
    let observations: Vec<EvidenceLink> = db
        .provenance_chain(id)
        .unwrap_or_default()
        .into_iter()
        .take(32)
        .map(|row| EvidenceLink {
            summary: format!("observed by {} ({})", row.module, row.scan_run),
            module: scrub_text(&row.module),
            scan_run: scrub_text(&row.scan_run),
            confidence: Some(row.confidence),
            observed: None,
        })
        .collect();
    crate::graph_view::node_detail(&view, &scrub_text(id), observations)
        .ok_or_else(|| ExplainError::NotFound(format!("node {id}")))
}

/// Masked JSON for a finding explanation (machine output path).
pub fn finding_json(explained: &ExplainedFinding) -> serde_json::Value {
    let chain: Vec<serde_json::Value> = explained
        .chain
        .iter()
        .map(|link| {
            serde_json::json!({
                "summary": scrub_text(&link.summary),
                "module": scrub_text(&link.module),
                "scan_run": scrub_text(&link.scan_run),
                "confidence": link.confidence,
                "observed": link.observed,
            })
        })
        .collect();
    serde_json::json!({
        "kind": "finding",
        "id": scrub_text(&explained.finding.id.0),
        "title": scrub_text(&explained.finding.title),
        "severity": format!("{:?}", explained.finding.severity),
        "confidence": explained.finding.confidence.0,
        "asset": scrub_text(&explained.asset_identity),
        "chain": chain,
    })
}

/// Render one evidence chain as human text (CLI) — the same links the
/// GUI renders as key/value rows.
pub fn render_chain(chain: &[EvidenceLink]) -> String {
    let mut out = String::new();
    if chain.is_empty() {
        out.push_str("  (no evidence excerpts; provenance recorded on the record itself)\n");
        return out;
    }
    for (index, link) in chain.iter().enumerate() {
        out.push_str(&format!("  {}. {}\n", index + 1, scrub_text(&link.summary)));
        out.push_str(&format!(
            "     module={} run={} confidence={} {}\n",
            scrub_text(&link.module),
            scrub_text(&link.scan_run),
            link.confidence
                .map(|c| c.to_string())
                .unwrap_or_else(|| "unrated".to_owned()),
            match link.observed {
                Some(true) => "observed",
                Some(false) => "inferred",
                None => "recorded",
            },
        ));
    }
    out
}

const RAISE: &str = "raising confidence: independent re-observation by another module or scan; corroborating evidence on the same relationship.";
const LOWER: &str = "lowering confidence: contradictory evidence, stale observation (recency penalty), single-source derivation (independence cap).";

/// Render a full finding explanation.
pub fn render_finding(explained: &ExplainedFinding) -> String {
    let finding = &explained.finding;
    let mut modules: Vec<String> = explained
        .chain
        .iter()
        .map(|link| link.module.clone())
        .collect();
    modules.sort();
    modules.dedup();
    let mut out = String::new();
    out.push_str(&format!("EXPLAIN finding {}\n", scrub_text(&finding.id.0)));
    out.push_str(&format!(
        "interpreted: {} (severity {:?}) on {}\n",
        scrub_text(&finding.title),
        finding.severity,
        scrub_text(&explained.asset_identity),
    ));
    out.push_str(&format!(
        "confidence: {} (stored) — supported by {} evidence item(s) from {} module(s){}\n",
        finding.confidence.0,
        explained.chain.len(),
        modules.len(),
        if modules.is_empty() { "" } else { ": " }
    ));
    if !modules.is_empty() {
        let masked: Vec<String> = modules.iter().map(|module| scrub_text(module)).collect();
        out.push_str(&format!("  modules: {}\n", masked.join(", ")));
    }
    out.push_str("observed:\n");
    out.push_str(&render_chain(&explained.chain));
    out.push_str(RAISE);
    out.push('\n');
    out.push_str(LOWER);
    out.push('\n');
    out
}

/// Render a full node explanation (embeds the shared node explanation so
/// CLI text and the GUI chain agree verbatim).
pub fn render_node(detail: &NodeDetail) -> String {
    let mut out = String::new();
    out.push_str(&format!("EXPLAIN node {}\n", scrub_text(&detail.node.id)));
    out.push_str("observed:\n");
    out.push_str(&render_chain(&detail.evidence_chain));
    out.push_str(&detail.explanation);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_renders_all_links_masked() {
        let chain = vec![
            EvidenceLink {
                summary: "observed: x (confidence 80)".to_owned(),
                module: "m".to_owned(),
                scan_run: "s".to_owned(),
                confidence: Some(80),
                observed: Some(true),
            },
            EvidenceLink {
                summary: "login token=FAKE-EXPLAIN-1".to_owned(),
                module: "m".to_owned(),
                scan_run: "s".to_owned(),
                confidence: None,
                observed: None,
            },
        ];
        let text = render_chain(&chain);
        assert!(text.contains("observed"));
        assert!(!text.contains("FAKE-EXPLAIN-1"));
        assert!(render_chain(&[]).contains("no evidence excerpts"));
    }
}
