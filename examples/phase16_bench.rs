use std::{collections::BTreeMap, time::Duration};

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
    plan::ScanPlan,
};

fn plan(level: u8) -> ScanPlan {
    ScanPlan::compile(
        Cli::try_parse_from([
            "rxscan",
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--level",
            &level.to_string(),
        ])
        .unwrap(),
    )
    .unwrap()
}

fn provenance(plan: &ScanPlan) -> Provenance {
    Provenance::new("phase16.bench", "16.0.0", plan.stable_id(), Timestamp(1)).unwrap()
}

fn task(plan: &ScanPlan, kind: TaskKind, state: TaskState, variant: &str) -> Task {
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
        "phase16.bench",
        provenance(plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        params,
        &guard,
    )
    .unwrap();
    task.state = state;
    task
}

fn ip(plan: &ScanPlan) -> Asset {
    Asset::scoped(AssetKind::Ip, "127.0.0.1", &plan.scope, provenance(plan)).unwrap()
}

fn url(plan: &ScanPlan, path: &str) -> Asset {
    Asset::scoped(
        AssetKind::Url,
        format!("http://127.0.0.1{path}"),
        &plan.scope,
        provenance(plan),
    )
    .unwrap()
}

fn port(plan: &ScanPlan, parent: &Asset, value: &str, state: &str) -> Asset {
    Asset::child(AssetKind::Port, &parent.id, value, provenance(plan))
        .unwrap()
        .with_attributes(BTreeMap::from([
            ("port".to_owned(), value.to_owned()),
            ("state".to_owned(), state.to_owned()),
        ]))
}

fn service(plan: &ScanPlan, parent: &Asset, value: &str) -> Asset {
    Asset::child(AssetKind::Service, &parent.id, value, provenance(plan)).unwrap()
}

fn finding(plan: &ScanPlan, asset: &Asset, identity: &str, confidence: u8) -> Finding {
    let mut finding = Finding::new(
        "Bench typed observation",
        Severity::Info,
        Confidence::new(confidence).unwrap(),
        asset.id.clone(),
        provenance(plan),
    )
    .unwrap();
    finding
        .metadata
        .insert("identity".to_owned(), serde_json::json!(identity));
    finding
}

fn evidence(plan: &ScanPlan, asset: &Asset, marker: &str) -> Evidence {
    Evidence::new(
        "phase16.bench",
        asset.id.clone(),
        BoundedDetails::from_value(serde_json::json!({"marker": marker}), 256).unwrap(),
        Confidence::new(80).unwrap(),
        provenance(plan),
    )
    .unwrap()
}

fn output(
    plan: &ScanPlan,
    assets: Vec<Asset>,
    relationships: Vec<Relationship>,
    evidence: Vec<Evidence>,
    findings: Vec<Finding>,
) -> rxscan::execution::ModuleOutput {
    rxscan::execution::ModuleOutput {
        events: vec![Event {
            schema_version: rxscan::model::SCHEMA_VERSION,
            kind: EventKind::EvidenceCollected,
            asset_id: assets.first().map(|asset| asset.id.clone()),
            details: BoundedDetails::from_value(serde_json::json!({"bench": true}), 1024).unwrap(),
            relationships,
            provenance: provenance(plan),
        }],
        evidence,
        findings,
        assets,
    }
}

fn state(
    plan: ScanPlan,
    tasks: Vec<Task>,
    output: rxscan::execution::ModuleOutput,
) -> PersistedScanState {
    let task_id = tasks.first().map(|task| task.id.clone()).unwrap();
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
    let old_plan = plan(5);
    let current_plan = plan(5);
    let old_ip = ip(&old_plan);
    let old_443 = port(&old_plan, &old_ip, "443", "open");
    let old_8443 = port(&old_plan, &old_ip, "8443", "closed");
    let old_service = service(&old_plan, &old_443, "https");
    let old_endpoint = url(&old_plan, "/admin")
        .with_attributes(BTreeMap::from([("status".to_owned(), "200".to_owned())]));
    let old = state(
        old_plan.clone(),
        vec![task(
            &old_plan,
            TaskKind::PortDiscovery,
            TaskState::Succeeded,
            "old",
        )],
        output(
            &old_plan,
            vec![old_ip.clone(), old_443, old_8443, old_service, old_endpoint],
            vec![],
            vec![],
            vec![finding(&old_plan, &old_ip, "persistent", 50)],
        ),
    );

    let current_ip = ip(&current_plan);
    let current_443 = port(&current_plan, &current_ip, "443", "open");
    let current_8443 = port(&current_plan, &current_ip, "8443", "open");
    let current_service = service(&current_plan, &current_8443, "http");
    let endpoint = url(&current_plan, "/admin")
        .with_attributes(BTreeMap::from([("status".to_owned(), "404".to_owned())]));
    let reflected = url(&current_plan, "/search");
    let dns_alias = url(&current_plan, "/dns-alias");
    let soft = url(&current_plan, "/wildcard").with_attributes(BTreeMap::from([(
        "classification".to_owned(),
        "soft404_like".to_owned(),
    )]));
    let outside = Asset::child(
        AssetKind::Other,
        &reflected.id,
        "external.example",
        provenance(&current_plan),
    )
    .unwrap()
    .with_attributes(BTreeMap::from([(
        "scope".to_owned(),
        "out_of_scope".to_owned(),
    )]));
    let rel_reflect = Relationship::new(
        RelationshipKind::ReflectsInput,
        RelationshipSubject::Asset(reflected.id.clone()),
        RelationshipSubject::Asset(endpoint.id.clone()),
        provenance(&current_plan),
    )
    .unwrap();
    let rel_dns = Relationship::new(
        RelationshipKind::HostnameAliasesTo,
        RelationshipSubject::Asset(reflected.id.clone()),
        RelationshipSubject::Asset(dns_alias.id.clone()),
        provenance(&current_plan),
    )
    .unwrap();
    let rel_runs = Relationship::new(
        RelationshipKind::Runs,
        RelationshipSubject::Asset(current_8443.id.clone()),
        RelationshipSubject::Asset(current_service.id.clone()),
        provenance(&current_plan),
    )
    .unwrap();
    let rel_endpoint = Relationship::new(
        RelationshipKind::ReferencesEndpoint,
        RelationshipSubject::Asset(current_8443.id.clone()),
        RelationshipSubject::Asset(endpoint.id.clone()),
        provenance(&current_plan),
    )
    .unwrap();
    let rel_soft = Relationship::new(
        RelationshipKind::LinksTo,
        RelationshipSubject::Asset(current_8443.id.clone()),
        RelationshipSubject::Asset(soft.id.clone()),
        provenance(&current_plan),
    )
    .unwrap();
    let rel_external = Relationship::new(
        RelationshipKind::HostnameAliasesTo,
        RelationshipSubject::Asset(reflected.id.clone()),
        RelationshipSubject::Asset(outside.id.clone()),
        provenance(&current_plan),
    )
    .unwrap();
    let current = state(
        current_plan.clone(),
        vec![
            task(
                &current_plan,
                TaskKind::PortDiscovery,
                TaskState::Succeeded,
                "ports",
            ),
            task(
                &current_plan,
                TaskKind::HttpProbe,
                TaskState::Succeeded,
                "http",
            ),
            task(&current_plan, TaskKind::Fuzz, TaskState::Succeeded, "fuzz"),
            task(
                &current_plan,
                TaskKind::DnsProbe,
                TaskState::Succeeded,
                "dns",
            ),
        ],
        output(
            &current_plan,
            vec![
                current_ip.clone(),
                current_443,
                current_8443,
                current_service,
                endpoint,
                reflected,
                dns_alias,
                soft,
                outside,
            ],
            vec![
                rel_reflect,
                rel_dns,
                rel_runs,
                rel_endpoint,
                rel_soft,
                rel_external,
            ],
            vec![
                evidence(&current_plan, &current_ip, "a"),
                evidence(&current_plan, &current_ip, "b"),
            ],
            vec![
                finding(&current_plan, &current_ip, "persistent", 50),
                finding(&current_plan, &current_ip, "new", 95),
            ],
        ),
    );
    let mut diff = diff::compare_states(&old, &current, diff::DiffOptions::default()).unwrap();
    diff.records.push(diff::DiffRecord {
        change_type: diff::ChangeType::InconclusiveMissing,
        entity_type: diff::EntityType::Asset,
        semantic_id: "endpoint:missing-timeout".to_owned(),
        certainty: diff::Certainty::Inconclusive,
        reason: diff::ReasonCode::NetworkErrorPreventsConfirmation,
        before: None,
        after: None,
    });
    let started = std::time::Instant::now();
    let report =
        analysis::analyze_state(&current, Some(&diff), AnalysisOptions::default()).unwrap();
    let analysis_ms = started.elapsed().as_millis();
    println!("phase16_bench");
    println!("assets_analyzed={}", current.outputs[0].output.assets.len());
    println!(
        "relationships_analyzed={}",
        current.outputs[0].output.events[0].relationships.len()
    );
    println!(
        "findings_analyzed={}",
        current.outputs[0].output.findings.len()
    );
    println!("diff_records_analyzed={}", diff.records.len());
    println!("signals_generated={}", report.total_signals);
    println!("signals_emitted={}", report.signals_emitted);
    println!("signals_truncated={}", report.signals_truncated);
    println!("high_attention={}", report.summary.high_attention);
    println!("medium_attention={}", report.summary.medium_attention);
    println!("low_attention={}", report.summary.low_attention);
    println!("informational={}", report.summary.informational);
    println!("network_signals={}", report.summary.network_signals);
    println!("web_signals={}", report.summary.web_signals);
    println!("dns_signals={}", report.summary.dns_signals);
    println!("finding_signals={}", report.summary.finding_signals);
    println!("change_signals={}", report.summary.change_signals);
    println!("correlation_signals={}", report.summary.correlation_signals);
    println!(
        "inconclusive_signals={}",
        report.summary.inconclusive_signals
    );
    println!(
        "max_attention_score={}",
        report
            .top_signals
            .iter()
            .map(|s| s.attention_score)
            .max()
            .unwrap_or(0)
    );
    println!(
        "min_attention_score={}",
        report
            .top_signals
            .iter()
            .map(|s| s.attention_score)
            .min()
            .unwrap_or(0)
    );
    println!("analysis_ms={analysis_ms}");
    println!("network_requests={}", report.network_requests);
    println!("peak_rss_kb={}", peak_rss_kb().unwrap_or(0));
    println!("release_binary_size_bytes=measure-with-cargo-build-release-and-stat");
    println!("new_production_dependency_count=0");
}
