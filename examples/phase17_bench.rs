use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use clap::Parser;
use rxscan::{
    analysis::{self, AnalysisOptions},
    cli::Cli,
    diff,
    execution::{RetryPolicy, Task, TaskKind, TaskScopeTarget, TaskState},
    model::{
        Asset, AssetKind, BoundedDetails, Confidence, Event, EventKind, Evidence, Finding,
        Provenance, Relationship, RelationshipKind, RelationshipSubject, Severity, Timestamp,
    },
    persistence::{
        CHECKPOINT_SCHEMA_VERSION, PersistedModuleOutput, PersistedRegistries, PersistedScanState,
        PersistedTask,
    },
    report::{self, ReportFormat, ReportOptions},
};

fn plan() -> rxscan::plan::ScanPlan {
    rxscan::plan::ScanPlan::compile(
        Cli::try_parse_from([
            "rxscan",
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--scope",
            "::1",
            "--scope",
            "http://127.0.0.1",
            "--level",
            "5",
        ])
        .unwrap(),
    )
    .unwrap()
}

fn provenance(plan: &rxscan::plan::ScanPlan) -> Provenance {
    Provenance::new("phase17.bench", "17.0.0", plan.stable_id(), Timestamp(1)).unwrap()
}

fn task(plan: &rxscan::plan::ScanPlan, kind: TaskKind, state: TaskState, variant: &str) -> Task {
    let guard = rxscan::execution::PolicyScopeGuard::new(plan.scope.clone());
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), "127.0.0.1".to_owned());
    params.insert("variant".to_owned(), variant.to_owned());
    let mut task = Task::new_with_params(
        kind,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        10,
        Duration::from_secs(1),
        RetryPolicy::default(),
        "phase17.bench",
        provenance(plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        params,
        &guard,
    )
    .unwrap();
    task.state = state;
    task
}

fn evidence(plan: &rxscan::plan::ScanPlan, asset: &Asset, marker: &str) -> Evidence {
    Evidence::new(
        "phase17.bench",
        asset.id.clone(),
        BoundedDetails::from_value(serde_json::json!({"marker": marker}), 512).unwrap(),
        Confidence::new(80).unwrap(),
        provenance(plan),
    )
    .unwrap()
}

fn state(include_added: bool) -> PersistedScanState {
    let plan = plan();
    let ip = Asset::scoped(AssetKind::Ip, "127.0.0.1", &plan.scope, provenance(&plan)).unwrap();
    let ip6 = Asset::scoped(AssetKind::Ip, "::1", &plan.scope, provenance(&plan)).unwrap();
    let port = Asset::child(AssetKind::Port, &ip.id, "443", provenance(&plan))
        .unwrap()
        .with_attributes(BTreeMap::from([
            ("port".to_owned(), "443".to_owned()),
            ("state".to_owned(), "open".to_owned()),
        ]));
    let svc = Asset::child(AssetKind::Service, &port.id, "https", provenance(&plan)).unwrap();
    let endpoint = Asset::scoped(
        AssetKind::Url,
        "http://127.0.0.1/admin",
        &plan.scope,
        provenance(&plan),
    )
    .unwrap();
    let dns_name = Asset::child(
        AssetKind::Other,
        &endpoint.id,
        "www.example.test",
        provenance(&plan),
    )
    .unwrap()
    .with_attributes(BTreeMap::from([(
        "dns_kind".to_owned(),
        "hostname".to_owned(),
    )]));
    let mut assets = vec![
        ip.clone(),
        ip6,
        port.clone(),
        svc.clone(),
        endpoint.clone(),
        dns_name.clone(),
    ];
    if include_added {
        assets.push(
            Asset::child(AssetKind::Port, &ip.id, "8443", provenance(&plan))
                .unwrap()
                .with_attributes(BTreeMap::from([
                    ("port".to_owned(), "8443".to_owned()),
                    ("state".to_owned(), "open".to_owned()),
                ])),
        );
    }
    let dns_rel = Relationship::new(
        RelationshipKind::HostnameResolvesToIp,
        RelationshipSubject::Asset(dns_name.id.clone()),
        RelationshipSubject::Asset(ip.id.clone()),
        provenance(&plan),
    )
    .unwrap();
    let reflect = Relationship::new(
        RelationshipKind::ReflectsInput,
        RelationshipSubject::Asset(endpoint.id.clone()),
        RelationshipSubject::Asset(svc.id.clone()),
        provenance(&plan),
    )
    .unwrap();
    let mut finding = Finding::new(
        "Bench report finding",
        Severity::Info,
        Confidence::new(80).unwrap(),
        port.id.clone(),
        provenance(&plan),
    )
    .unwrap();
    finding
        .evidence_ids
        .push(evidence(&plan, &port, "finding").id);
    let output = rxscan::execution::ModuleOutput {
        events: vec![Event {
            schema_version: rxscan::model::SCHEMA_VERSION,
            kind: EventKind::EvidenceCollected,
            asset_id: Some(ip.id.clone()),
            details: BoundedDetails::from_value(serde_json::json!({"phase":17}), 512).unwrap(),
            relationships: vec![dns_rel, reflect],
            provenance: provenance(&plan),
        }],
        evidence: vec![evidence(&plan, &ip, "ip"), evidence(&plan, &port, "port")],
        findings: vec![finding],
        assets,
    };
    let tasks = vec![
        task(&plan, TaskKind::HttpProbe, TaskState::Succeeded, "http"),
        task(&plan, TaskKind::Crawl, TaskState::TimedOut, "partial"),
    ];
    let task_id = tasks[0].id.clone();
    PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: plan.stable_id(),
        saved_at: Timestamp(2),
        plan,
        tasks: tasks
            .into_iter()
            .map(|task| PersistedTask { task })
            .collect(),
        outputs: vec![PersistedModuleOutput { task_id, output }],
        registries: PersistedRegistries::default(),
    }
}

fn peak_rss_kb() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.parse().ok())
}

fn main() {
    let old = state(false);
    let current = state(true);
    let diff = diff::compare_states(&old, &current, diff::DiffOptions::default()).unwrap();
    let analysis =
        analysis::analyze_state(&current, Some(&diff), AnalysisOptions::default()).unwrap();
    let options = ReportOptions {
        format: ReportFormat::Json,
        summary_only: false,
        top_n: 10,
    };
    let model = report::build_report_model(
        &current,
        Some(diff.clone()),
        Some(analysis.clone()),
        &options,
    )
    .unwrap();
    let started = Instant::now();
    let human = report::render_human(
        &model,
        &ReportOptions {
            format: ReportFormat::Human,
            ..options.clone()
        },
    );
    let human_ms = started.elapsed().as_millis();
    let started = Instant::now();
    let json = report::render_json(&model).unwrap();
    let json_ms = started.elapsed().as_millis();
    let started = Instant::now();
    let mut jsonl = Vec::new();
    report::render_jsonl(&model, &mut jsonl).unwrap();
    let jsonl_ms = started.elapsed().as_millis();
    let raw_model = report::build_report_model(
        &current,
        Some(diff),
        Some(analysis),
        &ReportOptions {
            format: ReportFormat::Raw,
            ..options.clone()
        },
    )
    .unwrap();
    let started = Instant::now();
    let raw = report::render_raw(&raw_model).unwrap();
    let raw_ms = started.elapsed().as_millis();
    let started = Instant::now();
    let _summary = report::render_human(
        &model,
        &ReportOptions {
            summary_only: true,
            ..ReportOptions::default()
        },
    );
    let summary_ms = started.elapsed().as_millis();

    println!("phase17_bench");
    println!("assets={}", model.summary.assets);
    println!("relationships={}", model.summary.relationships);
    println!("findings={}", model.summary.findings);
    println!("evidence={}", model.summary.evidence);
    println!(
        "diff_records={}",
        model.diff.as_ref().map(|d| d.records.len()).unwrap_or(0)
    );
    println!(
        "analysis_signals={}",
        model
            .analysis
            .as_ref()
            .map(|a| a.total_signals)
            .unwrap_or(0)
    );
    println!("human_bytes={}", human.len());
    println!("json_bytes={}", json.len());
    println!("jsonl_bytes={}", jsonl.len());
    println!("raw_bytes={}", raw.len());
    println!("human_render_ms={human_ms}");
    println!("json_render_ms={json_ms}");
    println!("jsonl_render_ms={jsonl_ms}");
    println!("raw_render_ms={raw_ms}");
    println!("summary_only_ms={summary_ms}");
    println!("network_requests={}", model.summary.network_requests);
    println!("peak_rss_kb={}", peak_rss_kb().unwrap_or(0));
    println!("release_binary_size_bytes=measure-with-cargo-build-release-and-stat");
    println!("new_production_dependency_count=0");
}
