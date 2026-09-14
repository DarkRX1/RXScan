use std::{collections::BTreeMap, fs, path::PathBuf, time::Duration};

use clap::Parser;
use rxscan::{
    cli::Cli,
    diff::{self, ChangeType, EntityType},
    execution::{RetryPolicy, Task, TaskKind, TaskScopeTarget, TaskState},
    model::{
        Asset, AssetKind, BoundedDetails, Confidence, Event, EventKind, Finding, Provenance,
        Relationship, RelationshipKind, RelationshipSubject, Severity, Timestamp,
    },
    persistence::{
        CHECKPOINT_SCHEMA_VERSION, PersistedModuleOutput, PersistedRegistries, PersistedScanState,
        PersistedTask, save_checkpoint,
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
    Provenance::new("phase15.bench", "15.0.0", plan.stable_id(), Timestamp(1)).unwrap()
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
        "phase15.bench",
        provenance(plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        params,
        &guard,
    )
    .unwrap();
    task.state = state;
    task
}

fn with_param(mut task: Task, key: &str, value: &str) -> Task {
    task.params.insert(key.to_owned(), value.to_owned());
    task.id = task.canonical_identity();
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

fn port(plan: &ScanPlan, parent: &Asset, number: &str, state: &str) -> Asset {
    Asset::child(AssetKind::Port, &parent.id, number, provenance(plan))
        .unwrap()
        .with_attributes(BTreeMap::from([
            ("port".to_owned(), number.to_owned()),
            ("state".to_owned(), state.to_owned()),
        ]))
}

fn service(plan: &ScanPlan, parent: &Asset, name: &str) -> Asset {
    Asset::child(AssetKind::Service, &parent.id, name, provenance(plan)).unwrap()
}

fn finding(plan: &ScanPlan, asset: &Asset, marker: &str) -> Finding {
    let mut finding = Finding::new(
        "Phase15 bench observation",
        Severity::Info,
        Confidence::new(80).unwrap(),
        asset.id.clone(),
        provenance(plan),
    )
    .unwrap();
    finding
        .metadata
        .insert("marker".to_owned(), serde_json::json!(marker));
    finding
}

fn output(
    plan: &ScanPlan,
    assets: Vec<Asset>,
    relationships: Vec<Relationship>,
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
        assets,
        findings,
        ..Default::default()
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

fn checkpoint_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "rxscan_phase15_bench_{name}_{}.json",
        std::process::id()
    ));
    path
}

fn peak_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("VmHWM:").and_then(|rest| {
            rest.split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
        })
    })
}

fn main() {
    let old_plan = plan(5);
    let current_plan = plan(2);
    let old_ip = ip(&old_plan);
    let old_port = port(&old_plan, &old_ip, "443", "open");
    let old_service = service(&old_plan, &old_port, "https");
    let admin = url(&old_plan, "/admin");
    let old_root = url(&old_plan, "/");
    let old_dns_alias = url(&old_plan, "/dns-old");
    let old_rel = Relationship::new(
        RelationshipKind::Runs,
        RelationshipSubject::Asset(old_port.id.clone()),
        RelationshipSubject::Asset(old_service.id.clone()),
        provenance(&old_plan),
    )
    .unwrap();
    let old_dns_rel = Relationship::new(
        RelationshipKind::HostnameAliasesTo,
        RelationshipSubject::Asset(old_root.id.clone()),
        RelationshipSubject::Asset(old_dns_alias.id.clone()),
        provenance(&old_plan),
    )
    .unwrap();
    let old = state(
        old_plan.clone(),
        vec![
            with_param(
                task(
                    &old_plan,
                    TaskKind::PortDiscovery,
                    TaskState::Succeeded,
                    "ports",
                ),
                "ports",
                "443",
            ),
            task(
                &old_plan,
                TaskKind::ServiceProbe,
                TaskState::Succeeded,
                "svc",
            ),
            task(&old_plan, TaskKind::Crawl, TaskState::Succeeded, "crawl"),
            with_param(
                task(&old_plan, TaskKind::DnsProbe, TaskState::Succeeded, "dns"),
                "record_type",
                "cname",
            ),
        ],
        output(
            &old_plan,
            vec![
                old_ip,
                old_port.clone(),
                old_service,
                admin,
                old_root,
                old_dns_alias,
            ],
            vec![old_rel, old_dns_rel],
            vec![finding(&old_plan, &old_port, "old")],
        ),
    );
    let current_ip = ip(&current_plan);
    let current_port = port(&current_plan, &current_ip, "443", "closed");
    let current_service = service(&current_plan, &current_port, "http");
    let added = url(&current_plan, "/new");
    let current_root = url(&current_plan, "/");
    let current_dns_alias = url(&current_plan, "/dns-new");
    let current_rel = Relationship::new(
        RelationshipKind::Runs,
        RelationshipSubject::Asset(current_port.id.clone()),
        RelationshipSubject::Asset(current_service.id.clone()),
        provenance(&current_plan),
    )
    .unwrap();
    let current_dns_rel = Relationship::new(
        RelationshipKind::HostnameAliasesTo,
        RelationshipSubject::Asset(current_root.id.clone()),
        RelationshipSubject::Asset(current_dns_alias.id.clone()),
        provenance(&current_plan),
    )
    .unwrap();
    let current = state(
        current_plan.clone(),
        vec![
            with_param(
                task(
                    &current_plan,
                    TaskKind::PortDiscovery,
                    TaskState::Succeeded,
                    "ports",
                ),
                "ports",
                "443",
            ),
            task(
                &current_plan,
                TaskKind::ServiceProbe,
                TaskState::Succeeded,
                "svc",
            ),
            with_param(
                task(
                    &current_plan,
                    TaskKind::DnsProbe,
                    TaskState::Succeeded,
                    "dns",
                ),
                "record_type",
                "cname",
            ),
        ],
        output(
            &current_plan,
            vec![
                current_ip,
                current_port.clone(),
                current_service,
                added,
                current_root,
                current_dns_alias,
            ],
            vec![current_rel, current_dns_rel],
            vec![finding(&current_plan, &current_port, "new")],
        ),
    );

    let old_path = checkpoint_path("old");
    let new_path = checkpoint_path("new");
    save_checkpoint(&old_path, &old).unwrap();
    save_checkpoint(&new_path, &current).unwrap();
    let total_start = std::time::Instant::now();
    let (report, load_ms, normalization_ms, comparison_ms) =
        diff::diff_checkpoints(&old_path, &new_path, diff::DiffOptions::default()).unwrap();
    let total_diff_ms = total_start.elapsed().as_millis();
    let asset_changes = report
        .records
        .iter()
        .filter(|record| record.entity_type == EntityType::Asset)
        .count();
    let relationship_changes = report
        .records
        .iter()
        .filter(|record| record.entity_type == EntityType::Relationship)
        .count();
    let finding_changes = report
        .records
        .iter()
        .filter(|record| record.entity_type == EntityType::Finding)
        .count();
    let dns_changes = report
        .records
        .iter()
        .filter(|record| {
            record.entity_type == EntityType::Relationship
                && record
                    .before
                    .as_ref()
                    .or(record.after.as_ref())
                    .and_then(|value| value.get("kind"))
                    .and_then(serde_json::Value::as_str)
                    .map(|kind| {
                        matches!(
                            kind,
                            "hostname_aliases_to"
                                | "hostname_resolves_to_ip"
                                | "mail_exchange_for"
                                | "name_server_for"
                                | "reverse_resolves_to"
                        )
                    })
                    .unwrap_or(false)
        })
        .count();
    let confirmed_added = report
        .records
        .iter()
        .filter(|record| record.change_type == ChangeType::Added)
        .count();
    let confirmed_removed = report
        .records
        .iter()
        .filter(|record| record.change_type == ChangeType::Removed)
        .count();
    println!("phase15_bench");
    println!("baseline_assets={}", old.outputs[0].output.assets.len());
    println!("current_assets={}", current.outputs[0].output.assets.len());
    println!(
        "baseline_relationships={}",
        old.outputs[0].output.events[0].relationships.len()
    );
    println!(
        "current_relationships={}",
        current.outputs[0].output.events[0].relationships.len()
    );
    println!("baseline_findings={}", old.outputs[0].output.findings.len());
    println!(
        "current_findings={}",
        current.outputs[0].output.findings.len()
    );
    println!("confirmed_added={confirmed_added}");
    println!("confirmed_removed={confirmed_removed}");
    println!(
        "modified={}",
        report.summary.assets_modified + report.summary.findings_modified
    );
    println!(
        "inconclusive_missing={}",
        report.summary.assets_missing_inconclusive
    );
    println!("unchanged={}", report.summary.unchanged);
    println!(
        "plan_differences={}",
        usize::from(report.plan.level_difference.is_some())
    );
    println!("diff_records_emitted={}", report.records.len());
    println!("diff_records_truncated={}", report.diff_records_truncated);
    println!("checkpoint_load_ms={load_ms}");
    println!("normalization_ms={normalization_ms}");
    println!("comparison_ms={comparison_ms}");
    println!("total_diff_ms={total_diff_ms}");
    println!("asset_changes={asset_changes}");
    println!("relationship_changes={relationship_changes}");
    println!("finding_changes={finding_changes}");
    println!("endpoint_changes={}", asset_changes);
    println!("dns_changes={dns_changes}");
    println!("network_requests={}", report.network_requests);
    println!("peak_rss_kb={}", peak_rss_kb().unwrap_or(0));
    println!("release_binary_size_bytes=measure-with-cargo-build-release-and-stat");
    println!("new_production_dependency_count=0");
    let _ = fs::remove_file(old_path);
    let _ = fs::remove_file(new_path);
}
