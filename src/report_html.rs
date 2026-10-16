//! Standalone offline HTML reports (Phase 2).
//!
//! One self-contained `.html` file per scan: executive summary, scope and
//! coverage statement with the scan time window, an embedded interactive
//! evidence graph (the Phase 1 viewer, inlined via `iframe srcdoc`),
//! sortable/filterable findings with per-finding evidence chains, and a
//! methodology/limitations section. Two templates: Executive (short,
//! risk-oriented) and Technical (full evidence). Zero external requests:
//! all CSS/JS/data is inlined and every string is secret-masked through
//! the shared `exposure` display helpers.

use std::collections::BTreeMap;
use std::path::Path;

use crate::exposure::{mask_json, scrub_text};
use crate::model::{Evidence, Finding};
use crate::report::{ReportError, ReportModel, ReportOptions, build_report_model};
use crate::{analysis, diff};

// ---------------------------------------------------------------------------
// Templates.
// ---------------------------------------------------------------------------

/// Report templates: short risk-oriented vs full evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReportTemplate {
    Executive,
    #[default]
    Technical,
}

impl ReportTemplate {
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "executive" | "exec" => Some(Self::Executive),
            "technical" | "tech" | "full" => Some(Self::Technical),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Executive => "executive",
            Self::Technical => "technical",
        }
    }
}

/// HTML report options.
#[derive(Debug, Clone)]
pub struct HtmlReportOptions {
    pub template: ReportTemplate,
    pub include_graph: bool,
    pub graph_node_limit: usize,
    pub max_findings: usize,
    pub max_evidence_per_finding: usize,
}

impl Default for HtmlReportOptions {
    fn default() -> Self {
        Self {
            template: ReportTemplate::Technical,
            include_graph: true,
            graph_node_limit: 300,
            max_findings: 500,
            max_evidence_per_finding: 8,
        }
    }
}

// ---------------------------------------------------------------------------
// Entry points.
// ---------------------------------------------------------------------------

/// Render an HTML report file from checkpoints (CLI path): loads state,
/// builds the standard model (diff/analysis optional), then renders.
pub fn render_html_file(
    current_path: &Path,
    baseline_path: Option<&Path>,
    include_analysis: bool,
    options: HtmlReportOptions,
) -> Result<Vec<u8>, ReportError> {
    let loaded = crate::persistence::load_checkpoint(current_path)?;
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
            &loaded.state,
            diff.as_ref(),
            analysis::AnalysisOptions::default(),
        )?)
    } else {
        None
    };
    let model = build_report_model(&loaded.state, diff, analysis, &ReportOptions::default())?;
    Ok(render_html(&loaded.state, &model, &options).into_bytes())
}

/// Render the HTML document from a loaded state + report model.
pub fn render_html(
    state: &crate::persistence::PersistedScanState,
    model: &ReportModel,
    options: &HtmlReportOptions,
) -> String {
    let mut doc = String::new();
    doc.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n");
    doc.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    doc.push_str("<meta name=\"referrer\" content=\"same-origin\">\n<title>");
    doc.push_str(&esc(&format!(
        "RXScan {} report — {}",
        options.template.as_str(),
        model.scan_id.0
    )));
    doc.push_str("</title>\n<style>\n");
    doc.push_str(REPORT_CSS);
    doc.push_str("\n</style>\n</head>\n<body>\n");
    // Header.
    doc.push_str("<header><h1>RXScan report");
    doc.push_str(if options.template == ReportTemplate::Executive {
        " — executive</h1>\n"
    } else {
        " — technical detail</h1>\n"
    });
    doc.push_str("<p class=\"muted\">Scan ");
    doc.push_str(&esc(&model.scan_id.0));
    doc.push_str(" · level ");
    doc.push_str(&model.level.to_string());
    doc.push_str(" · goal ");
    doc.push_str(&esc(&model.goal));
    doc.push_str(" · checkpoint saved ");
    doc.push_str(&fmt_epoch(state.saved_at.0));
    doc.push_str("</p></header>\n");
    // Sections.
    doc.push_str(&section_summary(model, options));
    doc.push_str(&section_scope_coverage(state, model));
    if options.include_graph {
        doc.push_str(&section_graph(state, &model.scan_id.0, options));
    }
    doc.push_str(&section_findings(state, options));
    if options.template == ReportTemplate::Technical {
        doc.push_str(&section_analysis(model));
        doc.push_str(&section_diff(model));
    }
    doc.push_str(&section_methodology(state, model, options));
    doc.push_str("<footer><p class=\"muted\">report schema v");
    doc.push_str(&crate::report::REPORT_SCHEMA_VERSION.to_string());
    doc.push_str(" · network_requests=0 · offline document (no external requests)</p></footer>\n");
    doc.push_str("<script>\n");
    doc.push_str(REPORT_JS);
    doc.push_str("\n</script>\n</body>\n</html>\n");
    doc
}

const REPORT_CSS: &str = r#"
:root{--rx-bg:#020711;--rx-surface:#061426;--rx-surface-2:#081c32;--rx-border:#123553;--rx-cyan:#00efff;--rx-text:#f4f8ff;--rx-muted:#8fa9c2;--rx-ok:#3ddc84;--rx-warn:#f0a04b;--rx-bad:#f06666}
*{box-sizing:border-box}body{margin:0 auto;max-width:1100px;background:var(--rx-bg);color:var(--rx-text);font-family:system-ui,sans-serif;line-height:1.5;padding:1rem}
header{border-bottom:1px solid var(--rx-border);margin-bottom:1rem}
h1{font-size:1.4rem}h2{margin:1.4rem 0 .5rem;font-size:1.1rem;border-bottom:1px solid var(--rx-border);padding-bottom:.25rem}
.muted{color:var(--rx-muted)}.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
table{width:100%;border-collapse:collapse;font-size:.88rem;margin:.5rem 0}
th,td{text-align:left;padding:.4rem .55rem;border-bottom:1px solid var(--rx-border);vertical-align:top;overflow-wrap:anywhere}
thead th{color:var(--rx-muted);cursor:pointer}
tbody tr:hover{background:#0a233d}
.toolbar{display:flex;gap:.5rem;flex-wrap:wrap;margin:.5rem 0;align-items:center}
.toolbar input{background:var(--rx-surface-2);color:var(--rx-text);border:1px solid var(--rx-border);border-radius:6px;padding:.4rem .6rem;font:inherit;width:16rem}
details{border:1px solid var(--rx-border);border-radius:6px;padding:.4rem .7rem;margin:.4rem 0;background:rgba(8,28,50,.5)}
summary{cursor:pointer;font-weight:700}
iframe.graph{width:100%;height:520px;border:1px solid var(--rx-border);border-radius:6px;background:#010813}
.pill{display:inline-block;border:1px solid var(--rx-border);border-radius:10px;padding:.05rem .5rem;font-size:.75rem}
.sev-critical{color:var(--rx-bad);font-weight:700}.sev-high{color:var(--rx-bad)}
.sev-medium{color:var(--rx-warn)}.sev-low{color:var(--rx-ok)}.sev-info{color:var(--rx-muted)}
pre.ev{background:#020a16;border:1px solid var(--rx-border);border-radius:6px;padding:.5rem;overflow:auto;font-size:.78rem;white-space:pre-wrap}
@media (prefers-reduced-motion: reduce){*{animation:none!important;transition:none!important}}
"#;

const REPORT_JS: &str = r#"
(function(){
"use strict";
function bindTable(tableId, filterId){
  var table=document.getElementById(tableId);
  if(!table)return;
  var input=document.getElementById(filterId);
  var ths=table.querySelectorAll("thead th");
  var dir={};
  ths.forEach(function(th,idx){
    th.setAttribute("tabindex","0");
    th.setAttribute("role","button");
    var go=function(){
      var tb=table.querySelector("tbody");
      var rows=Array.prototype.slice.call(tb.querySelectorAll("tr"));
      var asc=!(dir[idx]===true);
      dir[idx]=asc;
      rows.sort(function(a,b){
        var x=a.children[idx]?a.children[idx].textContent:"";
        var y=b.children[idx]?b.children[idx].textContent:"";
        var xn=parseFloat(x),yn=parseFloat(y);
        if(!isNaN(xn)&&!isNaN(yn))return asc?xn-yn:yn-xn;
        return asc?x.localeCompare(y):y.localeCompare(x);
      });
      rows.forEach(function(r){tb.appendChild(r);});
    };
    th.addEventListener("click",go);
    th.addEventListener("keydown",function(ev){if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();go();}});
  });
  if(input){
    input.addEventListener("input",function(){
      var q=input.value.toLowerCase();
      table.querySelectorAll("tbody tr").forEach(function(r){
        r.style.display=r.textContent.toLowerCase().indexOf(q)>=0?"":"none";
      });
    });
  }
}
bindTable("findings-table","findings-filter");
bindTable("tasks-table","");
})();
"#;

// ---------------------------------------------------------------------------
// Sections.
// ---------------------------------------------------------------------------

fn esc(text: &str) -> String {
    let masked = scrub_text(text);
    let mut out = String::with_capacity(masked.len());
    for ch in masked.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c if c.is_control() && c != '\n' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// Gregorian calendar date from epoch seconds (deterministic, no locale).
fn fmt_epoch(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u64;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u64;
    year += i64::from(month <= 2);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year,
        month,
        day,
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}

fn severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

struct FindingChain<'a> {
    finding: &'a Finding,
    asset_identity: String,
    evidence: Vec<&'a Evidence>,
}

fn finding_chains<'a>(
    state: &'a crate::persistence::PersistedScanState,
) -> (
    Vec<FindingChain<'a>>,
    BTreeMap<String, &'a crate::model::Asset>,
) {
    let mut assets: BTreeMap<String, &crate::model::Asset> = BTreeMap::new();
    let mut evidence: BTreeMap<String, &Evidence> = BTreeMap::new();
    let mut findings: Vec<&Finding> = Vec::new();
    for output in &state.outputs {
        for asset in &output.output.assets {
            assets.entry(asset.id.0.clone()).or_insert(asset);
        }
        for item in &output.output.evidence {
            evidence.entry(item.id.0.clone()).or_insert(item);
        }
        for finding in &output.output.findings {
            if !findings.iter().any(|f| f.id == finding.id) {
                findings.push(finding);
            }
        }
    }
    let mut chains: Vec<FindingChain<'a>> = findings
        .into_iter()
        .map(|finding| {
            let asset_identity = assets
                .get(&finding.affected_asset_id.0)
                .map(|asset| asset.identity.clone())
                .unwrap_or_else(|| finding.affected_asset_id.0.clone());
            let mut chain_evidence: Vec<&Evidence> = finding
                .evidence_ids
                .iter()
                .filter_map(|id| evidence.get(&id.0).copied())
                .collect();
            chain_evidence.sort_by(|a, b| a.id.0.cmp(&b.id.0));
            FindingChain {
                finding,
                asset_identity,
                evidence: chain_evidence,
            }
        })
        .collect();
    chains.sort_by(|a, b| {
        severity_rank(&format!("{:?}", a.finding.severity))
            .cmp(&severity_rank(&format!("{:?}", b.finding.severity)))
            .then(b.finding.confidence.0.cmp(&a.finding.confidence.0))
            .then(a.finding.title.cmp(&b.finding.title))
    });
    (chains, assets)
}

fn section_summary(model: &ReportModel, options: &HtmlReportOptions) -> String {
    let mut out = String::from("<section><h2>Executive summary</h2>\n<dl class=\"mono\">\n");
    let s = &model.summary;
    for (label, value) in [
        ("targets", s.targets),
        ("assets", s.assets),
        ("open ports", s.open_ports),
        ("services", s.services),
        ("endpoints", s.endpoints),
        ("findings", s.findings),
        ("evidence items", s.evidence),
        ("completed tasks", s.completed_tasks),
        ("incomplete tasks", s.failed_incomplete_tasks),
    ] {
        out.push_str(&format!("<div><dt>{label}</dt><dd>{value}</dd></div>\n"));
    }
    out.push_str("</dl>\n");
    if s.failed_incomplete_tasks > 0 {
        out.push_str("<p><span class=\"pill\">incomplete work</span> ");
        out.push_str(&s.failed_incomplete_tasks.to_string());
        out.push_str(" task(s) pending, failed, cancelled, or timed out — related absences are inconclusive, never removals.</p>\n");
    }
    if let Some(analysis) = &model.analysis {
        out.push_str("<h3>Attention signals</h3>\n<ul>\n");
        let top: usize = if options.template == ReportTemplate::Executive {
            5
        } else {
            10
        };
        for signal in analysis.top_signals.iter().take(top) {
            out.push_str("<li>");
            out.push_str(&esc(&format!(
                "{:?} score={} {} (confidence {})",
                signal.attention_band, signal.attention_score, signal.label, signal.confidence
            )));
            out.push_str("</li>\n");
        }
        out.push_str("</ul>\n");
    }
    if let Some(diff) = &model.diff {
        out.push_str("<p>Changes vs baseline: status ");
        out.push_str(&esc(&format!("{:?}", diff.comparison_status)));
        out.push_str("; inconclusive (not covered) records are never shown as removed.</p>\n");
    }
    out.push_str("</section>\n");
    out
}

fn section_scope_coverage(
    state: &crate::persistence::PersistedScanState,
    model: &ReportModel,
) -> String {
    let mut out = String::from("<section><h2>Scope and coverage</h2>\n");
    out.push_str("<h3>Targets</h3>\n<ul>\n");
    for target in &state.plan.targets {
        out.push_str("<li class=\"mono\">");
        out.push_str(&esc(&target.original_input));
        out.push_str("</li>\n");
    }
    out.push_str("</ul>\n<h3>Scope policy</h3>\n<ul>\n");
    for rule in &state.plan.scope.allowed {
        out.push_str("<li class=\"mono\">allow ");
        out.push_str(&esc(&scope_rule_text(rule)));
        out.push_str("</li>\n");
    }
    for rule in &state.plan.scope.exclusions {
        out.push_str("<li class=\"mono\">exclude ");
        out.push_str(&esc(&scope_rule_text(rule)));
        out.push_str("</li>\n");
    }
    out.push_str("</ul>\n<h3>Scan time window</h3>\n<p>");
    let mut created: Vec<u64> = state
        .tasks
        .iter()
        .map(|task| task.task.created_at.0)
        .collect();
    created.sort_unstable();
    match created.first() {
        Some(first) => {
            out.push_str("first task created ");
            out.push_str(&fmt_epoch(*first));
            out.push_str("; checkpoint saved ");
            out.push_str(&fmt_epoch(state.saved_at.0));
        }
        None => out.push_str("no tasks recorded"),
    }
    out.push_str("</p>\n<h3>Task coverage</h3>\n");
    out.push_str("<table id=\"tasks-table\"><thead><tr><th>Task kind</th><th>State</th><th>Module</th></tr></thead><tbody>\n");
    let mut tasks: Vec<(&str, String, String)> = Vec::new();
    for task in state.tasks.iter().take(100) {
        tasks.push((
            "row",
            format!("{:?}", task.task.kind),
            format!("{:?}|{}", task.task.state, task.task.module_name),
        ));
    }
    tasks.sort();
    for (_, kind, rest) in tasks {
        let mut parts = rest.splitn(2, '|');
        out.push_str("<tr><td>");
        out.push_str(&esc(&kind));
        out.push_str("</td><td>");
        out.push_str(&esc(parts.next().unwrap_or("?")));
        out.push_str("</td><td>");
        out.push_str(&esc(parts.next().unwrap_or("?")));
        out.push_str("</td></tr>\n");
    }
    out.push_str("</tbody></table>\n");
    if model.truncation.details_truncated {
        out.push_str("<p class=\"muted\">Output notes: details truncated (signals shown ");
        out.push_str(&model.truncation.signals_shown.to_string());
        out.push_str(" of ");
        out.push_str(&model.truncation.signals_total.to_string());
        out.push_str(").</p>\n");
    }
    out.push_str("</section>\n");
    out
}

fn scope_rule_text(rule: &crate::scope::ScopeRule) -> String {
    match rule {
        crate::scope::ScopeRule::Ip(ip) => ip.to_string(),
        crate::scope::ScopeRule::Network(net) => net.to_string(),
        crate::scope::ScopeRule::Hostname(host) => host.clone(),
    }
}

fn section_graph(
    state: &crate::persistence::PersistedScanState,
    title: &str,
    options: &HtmlReportOptions,
) -> String {
    // Rebuild the real correlation graph from module outputs so the
    // embedded graph carries true confidences and evidence (not a sketch).
    let outputs: Vec<(crate::execution::TaskId, crate::execution::ModuleOutput)> = state
        .outputs
        .iter()
        .map(|output| (output.task_id.clone(), output.output.clone()))
        .collect();
    let graph = crate::graph::build_graph(&outputs, None);
    if graph.entity_count() == 0 {
        return "<section><h2>Evidence graph</h2>\n<p class=\"muted\">No graph entities observed.</p>\n</section>\n"
            .to_owned();
    }
    let view_options = crate::graph_view::ViewOptions {
        limit_nodes: options
            .graph_node_limit
            .clamp(1, crate::graph_view::MAX_VIEW_NODES),
        limit_edges: options
            .graph_node_limit
            .saturating_mul(2)
            .clamp(1, crate::graph_view::MAX_VIEW_EDGES),
        ..crate::graph_view::ViewOptions::default()
    }
    .bounded();
    let view = crate::graph_view::build_from_scan_graph(&graph, &view_options);
    let positions = crate::graph_view::layout(&view, crate::graph_view::LayoutKind::Organic, None);
    let embedded = crate::graph_view::to_html(&view, &positions, title);
    // iframe srcdoc: escape once for the attribute (data stays masked).
    let srcdoc = embedded.replace('&', "&amp;").replace('"', "&quot;");
    let mut out = String::from("<section><h2>Evidence graph</h2>\n<p class=\"muted\">");
    out.push_str(&view.nodes.len().to_string());
    out.push_str(" nodes, ");
    out.push_str(&view.edges.len().to_string());
    out.push_str(" relationships");
    if view.truncated {
        out.push_str(" (truncated — narrow with the CLI graph export)");
    }
    out.push_str(". Solid = observed, dashed = inferred, width = confidence.</p>\n");
    out.push_str("<iframe class=\"graph\" title=\"Interactive evidence graph\" srcdoc=\"");
    out.push_str(&srcdoc);
    out.push_str("\"></iframe>\n</section>\n");
    out
}

fn section_findings(
    state: &crate::persistence::PersistedScanState,
    options: &HtmlReportOptions,
) -> String {
    let (chains, _) = finding_chains(state);
    let total = chains.len();
    // Executive is risk-oriented and short: top 5 findings, no chains.
    // Technical carries the full table plus per-finding evidence.
    let cap = if options.template == ReportTemplate::Executive {
        5
    } else {
        options.max_findings
    };
    let shown = chains.into_iter().take(cap).collect::<Vec<_>>();
    let mut out = String::from("<section><h2>Findings</h2>\n");
    out.push_str("<div class=\"toolbar\"><label for=\"findings-filter\">Filter</label>");
    out.push_str("<input id=\"findings-filter\" type=\"text\" value=\"\" aria-label=\"Filter findings rows\">");
    out.push_str("<span class=\"muted\">click a header to sort</span></div>\n");
    out.push_str("<table id=\"findings-table\"><thead><tr><th>Severity</th><th>Title</th><th>Confidence</th><th>Asset</th><th>Evidence</th></tr></thead><tbody>\n");
    for chain in &shown {
        let severity = format!("{:?}", chain.finding.severity);
        out.push_str("<tr><td class=\"sev-");
        out.push_str(&severity.to_ascii_lowercase());
        out.push_str("\">");
        out.push_str(&esc(&severity));
        out.push_str("</td><td>");
        out.push_str(&esc(&chain.finding.title));
        out.push_str("</td><td>");
        out.push_str(&chain.finding.confidence.0.to_string());
        out.push_str("</td><td class=\"mono\">");
        out.push_str(&esc(&chain.asset_identity));
        out.push_str("</td><td>");
        out.push_str(&chain.evidence.len().to_string());
        out.push_str("</td></tr>\n");
    }
    out.push_str("</tbody></table>\n");
    if total > shown.len() {
        out.push_str("<p class=\"muted\">Showing ");
        out.push_str(&shown.len().to_string());
        out.push_str(" of ");
        out.push_str(&total.to_string());
        out.push_str(" findings (bounded output; the technical template lists more).</p>\n");
    }
    if options.template == ReportTemplate::Technical {
        out.push_str("<h3>Evidence chains</h3>\n");
        for chain in &shown {
            out.push_str("<details><summary>");
            out.push_str(&esc(&chain.finding.title));
            out.push_str(" — confidence ");
            out.push_str(&chain.finding.confidence.0.to_string());
            out.push_str("</summary>\n<p>Affected asset: <span class=\"mono\">");
            out.push_str(&esc(&chain.asset_identity));
            out.push_str("</span></p>\n");
            if chain.evidence.is_empty() {
                out.push_str("<p class=\"muted\">No evidence items linked (provenance: module ");
                out.push_str(&esc(&chain.finding.provenance.module_name));
                out.push_str(").</p>\n");
            }
            for item in chain.evidence.iter().take(options.max_evidence_per_finding) {
                out.push_str("<p>Source: ");
                out.push_str(&esc(&item.source));
                out.push_str(" · confidence ");
                out.push_str(&item.confidence.0.to_string());
                out.push_str(" · observed ");
                out.push_str(&fmt_epoch(item.timestamp.0));
                out.push_str(" · module ");
                out.push_str(&esc(&item.provenance.module_name));
                out.push_str("</p>\n<pre class=\"ev\">");
                let masked = mask_json(&item.details.data);
                let pretty =
                    serde_json::to_string_pretty(&masked).unwrap_or_else(|_| "{}".to_owned());
                let capped: String = pretty.chars().take(2048).collect();
                out.push_str(&esc(&capped));
                out.push_str("</pre>\n");
            }
            if let Some(remediation) = chain.finding.remediation.as_deref() {
                out.push_str("<p>Remediation: ");
                out.push_str(&esc(remediation));
                out.push_str("</p>\n");
            }
            out.push_str("</details>\n");
        }
    }
    out.push_str("</section>\n");
    out
}

fn section_analysis(model: &ReportModel) -> String {
    let Some(analysis) = &model.analysis else {
        return String::new();
    };
    let mut out = String::from("<section><h2>Analysis signals</h2>\n<ul>\n");
    for signal in analysis.top_signals.iter().take(20) {
        out.push_str("<li>");
        out.push_str(&esc(&format!(
            "{:?} score={} {} (confidence {})",
            signal.attention_band, signal.attention_score, signal.label, signal.confidence
        )));
        out.push_str("</li>\n");
    }
    out.push_str("</ul>\n</section>\n");
    out
}

fn section_diff(model: &ReportModel) -> String {
    let Some(diff) = &model.diff else {
        return String::new();
    };
    let mut out = String::from("<section><h2>Changes vs baseline</h2>\n<p>Status ");
    out.push_str(&esc(&format!("{:?}", diff.comparison_status)));
    out.push_str(
        ". Inconclusive (not covered) records are reported as such — never as removals.</p>\n",
    );
    out.push_str("<table><thead><tr><th>Change</th><th>Entity</th><th>ID</th><th>Certainty</th><th>Reason</th></tr></thead><tbody>\n");
    for record in diff.records.iter().take(100) {
        out.push_str("<tr><td>");
        out.push_str(&esc(&format!("{:?}", record.change_type)));
        out.push_str("</td><td>");
        out.push_str(&esc(&format!("{:?}", record.entity_type)));
        out.push_str("</td><td class=\"mono\">");
        out.push_str(&esc(&record.semantic_id));
        out.push_str("</td><td>");
        out.push_str(&esc(&format!("{:?}", record.certainty)));
        out.push_str("</td><td>");
        out.push_str(&esc(&format!("{:?}", record.reason)));
        out.push_str("</td></tr>\n");
    }
    out.push_str("</tbody></table>\n</section>\n");
    out
}

fn section_methodology(
    state: &crate::persistence::PersistedScanState,
    model: &ReportModel,
    options: &HtmlReportOptions,
) -> String {
    let mut out = String::from("<section><h2>Methodology and limitations</h2>\n<ul>\n");
    out.push_str("<li>Bounded, authorized reconnaissance only: every probe ran inside the scope policy above; no credential guessing, brute force, exploitation, or destructive actions.</li>\n");
    out.push_str("<li>Evidence-first: every finding links to stored evidence with a confidence value. Confidence is fused conservatively (source reliability, independence, contradiction, recency) and never exceeds 95 from fusion.</li>\n");
    out.push_str("<li>Absence honesty: entities not observed without comparable coverage are reported inconclusive (not covered), never as removed.</li>\n");
    out.push_str("<li>Secret-safe: usable secret material is never persisted or displayed; this document carries metadata only.</li>\n");
    out.push_str("<li>Offline: this file makes no network requests and embeds all assets.</li>\n");
    if model.summary.failed_incomplete_tasks > 0 || options.template == ReportTemplate::Technical {
        out.push_str("<li>Incomplete tasks this run: ");
        out.push_str(&model.summary.failed_incomplete_tasks.to_string());
        out.push_str(". Related findings carry reduced confidence; re-run with wider budgets to confirm.</li>\n");
        let pending: Vec<String> = state
            .tasks
            .iter()
            .filter(|task| !matches!(task.task.state, crate::execution::TaskState::Succeeded))
            .take(20)
            .map(|task| format!("{:?}/{:?}", task.task.kind, task.task.state))
            .collect();
        if !pending.is_empty() {
            out.push_str("<li>Non-completed tasks: ");
            out.push_str(&esc(&pending.join(", ")));
            out.push_str(".</li>\n");
        }
    }
    out.push_str("</ul>\n</section>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_parse() {
        assert_eq!(
            ReportTemplate::parse("executive"),
            Some(ReportTemplate::Executive)
        );
        assert_eq!(
            ReportTemplate::parse("TECHNICAL"),
            Some(ReportTemplate::Technical)
        );
        assert_eq!(
            ReportTemplate::parse("full"),
            Some(ReportTemplate::Technical)
        );
        assert_eq!(ReportTemplate::parse("pdf"), None);
    }

    #[test]
    fn epoch_formats_as_utc() {
        assert_eq!(fmt_epoch(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(fmt_epoch(1_700_000_000), "2023-11-14 22:13:20 UTC");
        assert_eq!(fmt_epoch(1_700_000_001), "2023-11-14 22:13:21 UTC");
    }

    #[test]
    fn severity_orders_risk_first() {
        assert!(severity_rank("critical") < severity_rank("high"));
        assert!(severity_rank("high") < severity_rank("medium"));
        assert!(severity_rank("medium") < severity_rank("low"));
        assert!(severity_rank("low") < severity_rank("info"));
    }

    #[test]
    fn escaping_neutralizes_markup_after_masking() {
        let out = esc("a<b>&\"c\" password=hunter2");
        assert!(!out.contains("<b>"));
        assert!(!out.contains("hunter2"));
        assert!(out.contains("&lt;b&gt;"));
    }
}
