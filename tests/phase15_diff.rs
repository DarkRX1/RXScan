use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};

use clap::Parser;
use rxscan::{
    cli::Cli,
    diff::{self, Certainty, ChangeType, ReasonCode},
    execution::{RetryPolicy, ScopeGuard, Task, TaskKind, TaskScopeTarget, TaskState},
    model::{
        Asset, AssetKind, BoundedDetails, Confidence, Event, EventKind, Finding, Provenance,
        Relationship, RelationshipKind, RelationshipSubject, Severity, Timestamp,
    },
    persistence::{
        CHECKPOINT_SCHEMA_VERSION, PersistedModuleOutput, PersistedRegistries, PersistedScanState,
        PersistedTask, save_checkpoint,
    },
    plan::{ScanPlan, SpeedSetting},
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

fn plan_with_target(target: &str, level: u8) -> ScanPlan {
    ScanPlan::compile(
        Cli::try_parse_from([
            "rxscan",
            target,
            "--scope",
            target,
            "--level",
            &level.to_string(),
        ])
        .unwrap(),
    )
    .unwrap()
}

fn provenance(plan: &ScanPlan) -> Provenance {
    Provenance::new("phase15.test", "15.0.0", plan.stable_id(), Timestamp(1)).unwrap()
}

fn task(plan: &ScanPlan, kind: TaskKind, state: TaskState, variant: &str) -> Task {
    let guard = rxscan::execution::PolicyScopeGuard::new(plan.scope.clone());
    let ip = if guard.permits(&TaskScopeTarget::Ip("127.0.0.1".parse().unwrap())) {
        "127.0.0.1"
    } else {
        "::1"
    };
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), ip.to_owned());
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
        "phase15.test",
        provenance(plan),
        TaskScopeTarget::Ip(ip.parse().unwrap()),
        params,
        &guard,
    )
    .unwrap();
    task.state = state;
    task
}

fn state(
    plan: ScanPlan,
    tasks: Vec<Task>,
    output: rxscan::execution::ModuleOutput,
) -> PersistedScanState {
    let output_task = tasks.first().map(|task| task.id.clone());
    PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: plan.stable_id(),
        saved_at: Timestamp(2),
        plan,
        tasks: tasks
            .into_iter()
            .map(|task| PersistedTask { task })
            .collect(),
        outputs: output_task
            .map(|task_id| vec![PersistedModuleOutput { task_id, output }])
            .unwrap_or_default(),
        registries: PersistedRegistries::default(),
    }
}

fn output(
    plan: &ScanPlan,
    assets: Vec<Asset>,
    relationships: Vec<Relationship>,
    findings: Vec<Finding>,
) -> rxscan::execution::ModuleOutput {
    let event = Event {
        schema_version: rxscan::model::SCHEMA_VERSION,
        kind: EventKind::EvidenceCollected,
        asset_id: assets.first().map(|asset| asset.id.clone()),
        details: BoundedDetails::from_value(serde_json::json!({"phase": 15}), 1024).unwrap(),
        relationships,
        provenance: provenance(plan),
    };
    rxscan::execution::ModuleOutput {
        assets,
        events: vec![event],
        findings,
        ..Default::default()
    }
}

fn ip_asset(plan: &ScanPlan, ip: &str) -> Asset {
    Asset::scoped(AssetKind::Ip, ip, &plan.scope, provenance(plan)).unwrap()
}

fn url_asset(plan: &ScanPlan, url: &str) -> Asset {
    Asset::scoped(AssetKind::Url, url, &plan.scope, provenance(plan)).unwrap()
}

fn port_asset(plan: &ScanPlan, parent: &Asset, port: &str, state: &str) -> Asset {
    Asset::child(AssetKind::Port, &parent.id, port, provenance(plan))
        .unwrap()
        .with_attributes(BTreeMap::from([
            ("port".to_owned(), port.to_owned()),
            ("state".to_owned(), state.to_owned()),
        ]))
}

fn service_asset(plan: &ScanPlan, parent: &Asset, name: &str) -> Asset {
    Asset::child(AssetKind::Service, &parent.id, name, provenance(plan)).unwrap()
}

fn endpoint_asset(plan: &ScanPlan, parent: &Asset, path: &str) -> Asset {
    Asset::child(AssetKind::Endpoint, &parent.id, path, provenance(plan)).unwrap()
}

fn finding(plan: &ScanPlan, asset: &Asset, marker: &str) -> Finding {
    let mut finding = Finding::new(
        "Phase15 observation",
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

fn with_param(mut task: Task, key: &str, value: &str) -> Task {
    task.params.insert(key.to_owned(), value.to_owned());
    task.id = task.canonical_identity();
    task
}

fn endpoint_with_depth(plan: &ScanPlan, url: &str, depth: u8) -> Asset {
    url_asset(plan, url).with_attributes(BTreeMap::from([(
        "crawl_depth".to_owned(),
        depth.to_string(),
    )]))
}

fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "rxscan_phase15_{name}_{}_{}.json",
        std::process::id(),
        Timestamp::now().0
    ));
    path
}

#[test]
fn same_checkpoint_reordered_speed_and_path_are_semantically_stable() {
    let mut old_plan = plan(5);
    old_plan.speed = SpeedSetting::Numeric(10);
    let mut new_plan = old_plan.clone();
    new_plan.speed = SpeedSetting::Numeric(100);
    let ip = ip_asset(&old_plan, "127.0.0.1");
    let url = url_asset(&old_plan, "http://127.0.0.1/");
    let rel = Relationship::new(
        RelationshipKind::DiscoveredFrom,
        RelationshipSubject::Asset(url.id.clone()),
        RelationshipSubject::Asset(ip.id.clone()),
        provenance(&old_plan),
    )
    .unwrap();
    let old = state(
        old_plan.clone(),
        vec![task(
            &old_plan,
            TaskKind::HttpProbe,
            TaskState::Succeeded,
            "a",
        )],
        output(
            &old_plan,
            vec![ip.clone(), url.clone()],
            vec![rel.clone()],
            vec![],
        ),
    );
    let new = state(
        new_plan.clone(),
        vec![task(
            &new_plan,
            TaskKind::HttpProbe,
            TaskState::Succeeded,
            "a",
        )],
        output(&new_plan, vec![url, ip], vec![rel], vec![]),
    );
    let report = diff::compare_states(&old, &new, diff::DiffOptions::default()).unwrap();
    assert_eq!(report.summary.assets_added, 0);
    assert_eq!(report.summary.assets_removed_confirmed, 0);
    assert_eq!(report.summary.assets_modified, 0);
    assert_eq!(report.records.len(), 0);
    assert_eq!(report.network_requests, 0);

    let a = temp_path("stable_a");
    let b = temp_path("stable_b");
    save_checkpoint(&a, &old).unwrap();
    save_checkpoint(&b, &new).unwrap();
    let (from_files, _, _, _) =
        diff::diff_checkpoints(&a, &b, diff::DiffOptions::default()).unwrap();
    assert_eq!(from_files.records, report.records);
    let _ = fs::remove_file(a);
    let _ = fs::remove_file(b);
}

#[test]
fn incompatible_target_is_rejected_without_change_spam() {
    let old_plan = plan_with_target("127.0.0.1", 5);
    let new_plan = plan_with_target("127.0.0.2", 5);
    let old = state(
        old_plan.clone(),
        vec![],
        rxscan::execution::ModuleOutput::default(),
    );
    let new = state(new_plan, vec![], rxscan::execution::ModuleOutput::default());
    assert!(matches!(
        diff::compare_states(&old, &new, diff::DiffOptions::default()),
        Err(diff::DiffError::Incompatible(_))
    ));
}

#[test]
fn critical_production_path_classifies_added_modified_relationship_and_finding_changes() {
    let p = plan(5);
    let ip = ip_asset(&p, "127.0.0.1");
    let port_old = port_asset(&p, &ip, "443", "open");
    let service_old = service_asset(&p, &port_old, "https");
    let endpoint_old = url_asset(&p, "http://127.0.0.1/admin");
    let rel_old = Relationship::new(
        RelationshipKind::Runs,
        RelationshipSubject::Asset(port_old.id.clone()),
        RelationshipSubject::Asset(service_old.id.clone()),
        provenance(&p),
    )
    .unwrap();
    let old = state(
        p.clone(),
        vec![
            task(&p, TaskKind::PortDiscovery, TaskState::Succeeded, "ports"),
            task(&p, TaskKind::ServiceProbe, TaskState::Succeeded, "svc"),
            task(&p, TaskKind::Crawl, TaskState::Succeeded, "crawl"),
        ],
        output(
            &p,
            vec![ip.clone(), port_old.clone(), service_old, endpoint_old],
            vec![rel_old],
            vec![finding(&p, &port_old, "old")],
        ),
    );
    let new_ip = ip.clone();
    let port_new = port_asset(&p, &new_ip, "443", "closed");
    let service_new = service_asset(&p, &port_new, "http");
    let extra = url_asset(&p, "http://127.0.0.1/new");
    let rel_new = Relationship::new(
        RelationshipKind::Runs,
        RelationshipSubject::Asset(port_new.id.clone()),
        RelationshipSubject::Asset(service_new.id.clone()),
        provenance(&p),
    )
    .unwrap();
    let new = state(
        p.clone(),
        vec![
            task(&p, TaskKind::PortDiscovery, TaskState::Succeeded, "ports"),
            task(&p, TaskKind::ServiceProbe, TaskState::Succeeded, "svc"),
            task(&p, TaskKind::Crawl, TaskState::Succeeded, "crawl"),
        ],
        output(
            &p,
            vec![new_ip, port_new.clone(), service_new, extra],
            vec![rel_new],
            vec![finding(&p, &port_new, "new")],
        ),
    );
    let report = diff::compare_states(&old, &new, diff::DiffOptions::default()).unwrap();
    assert!(report.summary.assets_added >= 1);
    assert!(report.summary.assets_modified >= 1);
    assert!(report.summary.relationships_added >= 1);
    assert!(report.summary.relationships_removed_confirmed >= 1);
    assert!(report.summary.findings_modified >= 1);
    assert_eq!(report.network_requests, 0);
}

#[test]
fn coverage_reduction_prevents_false_endpoint_removals() {
    let old_plan = plan(5);
    let new_plan = plan(2);
    let admin = url_asset(&old_plan, "http://127.0.0.1/admin");
    let old = state(
        old_plan.clone(),
        vec![task(
            &old_plan,
            TaskKind::Crawl,
            TaskState::Succeeded,
            "crawl",
        )],
        output(&old_plan, vec![admin], vec![], vec![]),
    );
    let new = state(
        new_plan.clone(),
        vec![task(
            &new_plan,
            TaskKind::HttpProbe,
            TaskState::Succeeded,
            "http",
        )],
        rxscan::execution::ModuleOutput::default(),
    );
    let report = diff::compare_states(&old, &new, diff::DiffOptions::default()).unwrap();
    assert_eq!(report.summary.assets_removed_confirmed, 0);
    assert_eq!(report.summary.assets_missing_inconclusive, 1);
    assert!(report.records.iter().any(|record| {
        record.change_type == ChangeType::InconclusiveMissing
            && record.reason == ReasonCode::CoverageReduced
    }));
}

#[test]
fn expanded_coverage_marks_newly_observed_not_definitely_new() {
    let old_plan = plan(2);
    let new_plan = plan(5);
    let old = state(
        old_plan.clone(),
        vec![task(
            &old_plan,
            TaskKind::HttpProbe,
            TaskState::Succeeded,
            "http",
        )],
        rxscan::execution::ModuleOutput::default(),
    );
    let admin = url_asset(&new_plan, "http://127.0.0.1/admin");
    let new = state(
        new_plan.clone(),
        vec![task(
            &new_plan,
            TaskKind::Crawl,
            TaskState::Succeeded,
            "crawl",
        )],
        output(&new_plan, vec![admin], vec![], vec![]),
    );
    let report = diff::compare_states(&old, &new, diff::DiffOptions::default()).unwrap();
    assert_eq!(report.summary.assets_added, 1);
    assert_eq!(
        report.records[0].reason,
        ReasonCode::NewlyObservedWithExpandedCoverage
    );
}

#[test]
fn network_error_transitions_are_inconclusive_not_confirmed_removals() {
    let p = plan(5);
    let host = url_asset(&p, "http://127.0.0.1/");
    let ip = ip_asset(&p, "127.0.0.1");
    let rel = Relationship::new(
        RelationshipKind::HostnameResolvesToIp,
        RelationshipSubject::Asset(host.id.clone()),
        RelationshipSubject::Asset(ip.id.clone()),
        provenance(&p),
    )
    .unwrap();
    let old = state(
        p.clone(),
        vec![task(&p, TaskKind::DnsProbe, TaskState::Succeeded, "dns")],
        output(&p, vec![host, ip], vec![rel], vec![]),
    );
    let new = state(
        p.clone(),
        vec![task(&p, TaskKind::DnsProbe, TaskState::TimedOut, "dns")],
        rxscan::execution::ModuleOutput::default(),
    );
    let report = diff::compare_states(&old, &new, diff::DiffOptions::default()).unwrap();
    assert_eq!(report.summary.relationships_removed_confirmed, 0);
    assert_eq!(report.summary.relationships_missing_inconclusive, 1);
    let dns_record = report
        .records
        .iter()
        .find(|record| record.entity_type == diff::EntityType::Relationship)
        .unwrap();
    assert_eq!(dns_record.certainty, Certainty::Inconclusive);
}

#[test]
fn tcp_coverage_is_exact_to_scanned_ports() {
    let p = plan(5);
    let ip = ip_asset(&p, "127.0.0.1");
    let old_port = port_asset(&p, &ip, "8080", "open");
    let old = state(
        p.clone(),
        vec![with_param(
            task(&p, TaskKind::PortDiscovery, TaskState::Succeeded, "ports"),
            "ports",
            "8080",
        )],
        output(&p, vec![ip.clone(), old_port], vec![], vec![]),
    );
    let new_narrow = state(
        p.clone(),
        vec![with_param(
            task(&p, TaskKind::PortDiscovery, TaskState::Succeeded, "ports"),
            "ports",
            "80,443",
        )],
        output(&p, vec![ip.clone()], vec![], vec![]),
    );
    let narrow = diff::compare_states(&old, &new_narrow, diff::DiffOptions::default()).unwrap();
    assert_eq!(narrow.summary.assets_removed_confirmed, 0);
    assert_eq!(narrow.summary.assets_missing_inconclusive, 1);

    let closed = port_asset(&p, &ip, "8080", "closed");
    let new_closed = state(
        p.clone(),
        vec![with_param(
            task(&p, TaskKind::PortDiscovery, TaskState::Succeeded, "ports"),
            "ports",
            "80,443,8080",
        )],
        output(&p, vec![ip, closed], vec![], vec![]),
    );
    let changed = diff::compare_states(&old, &new_closed, diff::DiffOptions::default()).unwrap();
    assert_eq!(changed.summary.assets_modified, 1);
}

#[test]
fn port_and_service_transition_matrix_is_coverage_aware() {
    let p = plan(5);
    let ip = ip_asset(&p, "127.0.0.1");
    let open = port_asset(&p, &ip, "443", "open");
    let closed = port_asset(&p, &ip, "443", "closed");
    let filtered = port_asset(&p, &ip, "443", "filtered_or_timed_out");
    let old_open = state(
        p.clone(),
        vec![with_param(
            task(&p, TaskKind::PortDiscovery, TaskState::Succeeded, "p"),
            "ports",
            "443",
        )],
        output(&p, vec![ip.clone(), open.clone()], vec![], vec![]),
    );
    let new_closed = state(
        p.clone(),
        vec![with_param(
            task(&p, TaskKind::PortDiscovery, TaskState::Succeeded, "p"),
            "ports",
            "443",
        )],
        output(&p, vec![ip.clone(), closed], vec![], vec![]),
    );
    assert_eq!(
        diff::compare_states(&old_open, &new_closed, diff::DiffOptions::default())
            .unwrap()
            .summary
            .assets_modified,
        1
    );

    let old_closed = state(
        p.clone(),
        vec![with_param(
            task(&p, TaskKind::PortDiscovery, TaskState::Succeeded, "p"),
            "ports",
            "443",
        )],
        output(
            &p,
            vec![ip.clone(), port_asset(&p, &ip, "443", "closed")],
            vec![],
            vec![],
        ),
    );
    let new_open = state(
        p.clone(),
        vec![with_param(
            task(&p, TaskKind::PortDiscovery, TaskState::Succeeded, "p"),
            "ports",
            "443",
        )],
        output(&p, vec![ip.clone(), open.clone()], vec![], vec![]),
    );
    assert_eq!(
        diff::compare_states(&old_closed, &new_open, diff::DiffOptions::default())
            .unwrap()
            .summary
            .assets_modified,
        1
    );

    let new_filtered_error = state(
        p.clone(),
        vec![with_param(
            task(&p, TaskKind::PortDiscovery, TaskState::TimedOut, "p"),
            "ports",
            "443",
        )],
        output(&p, vec![ip.clone(), filtered], vec![], vec![]),
    );
    let error =
        diff::compare_states(&old_open, &new_filtered_error, diff::DiffOptions::default()).unwrap();
    assert_eq!(error.summary.assets_removed_confirmed, 0);

    let svc_http = service_asset(&p, &open, "web")
        .with_attributes(BTreeMap::from([("service".to_owned(), "http".to_owned())]));
    let svc_https = service_asset(&p, &open, "web")
        .with_attributes(BTreeMap::from([("service".to_owned(), "https".to_owned())]));
    let old_service = state(
        p.clone(),
        vec![task(&p, TaskKind::ServiceProbe, TaskState::Succeeded, "s")],
        output(&p, vec![ip.clone(), open.clone(), svc_http], vec![], vec![]),
    );
    let new_service = state(
        p.clone(),
        vec![task(&p, TaskKind::ServiceProbe, TaskState::Succeeded, "s")],
        output(
            &p,
            vec![ip.clone(), open.clone(), svc_https],
            vec![],
            vec![],
        ),
    );
    assert_eq!(
        diff::compare_states(&old_service, &new_service, diff::DiffOptions::default())
            .unwrap()
            .summary
            .assets_modified,
        1
    );
    let no_service_probe = state(
        p.clone(),
        vec![with_param(
            task(&p, TaskKind::PortDiscovery, TaskState::Succeeded, "p"),
            "ports",
            "443",
        )],
        output(&p, vec![ip, open], vec![], vec![]),
    );
    assert_eq!(
        diff::compare_states(
            &old_service,
            &no_service_probe,
            diff::DiffOptions::default()
        )
        .unwrap()
        .summary
        .assets_missing_inconclusive,
        1
    );
}

#[test]
fn dns_record_type_and_error_coverage_are_specific() {
    let p = plan(5);
    let host = url_asset(&p, "http://127.0.0.1/");
    let mail = port_asset(&p, &host, "25", "mx");
    let rel_mx = Relationship::new(
        RelationshipKind::MailExchangeFor,
        RelationshipSubject::Asset(host.id.clone()),
        RelationshipSubject::Asset(mail.id.clone()),
        provenance(&p),
    )
    .unwrap();
    let old_mx = state(
        p.clone(),
        vec![with_param(
            task(&p, TaskKind::DnsProbe, TaskState::Succeeded, "dns"),
            "record_type",
            "mx",
        )],
        output(
            &p,
            vec![host.clone(), mail.clone()],
            vec![rel_mx.clone()],
            vec![],
        ),
    );
    let new_a_only = state(
        p.clone(),
        vec![with_param(
            task(&p, TaskKind::DnsProbe, TaskState::Succeeded, "dns"),
            "record_type",
            "a",
        )],
        output(&p, vec![host.clone()], vec![], vec![]),
    );
    let a_only = diff::compare_states(&old_mx, &new_a_only, diff::DiffOptions::default()).unwrap();
    assert_eq!(a_only.summary.relationships_removed_confirmed, 0);
    assert!(
        a_only
            .records
            .iter()
            .any(|r| r.reason == ReasonCode::RecordTypeNotCovered)
    );

    let new_mx_nodata = state(
        p.clone(),
        vec![with_param(
            task(&p, TaskKind::DnsProbe, TaskState::Succeeded, "dns"),
            "record_type",
            "mx",
        )],
        output(&p, vec![host.clone()], vec![], vec![]),
    );
    assert_eq!(
        diff::compare_states(&old_mx, &new_mx_nodata, diff::DiffOptions::default())
            .unwrap()
            .summary
            .relationships_removed_confirmed,
        1
    );

    let new_timeout = state(
        p.clone(),
        vec![with_param(
            task(&p, TaskKind::DnsProbe, TaskState::TimedOut, "dns"),
            "record_type",
            "mx",
        )],
        output(&p, vec![host], vec![], vec![]),
    );
    let timeout =
        diff::compare_states(&old_mx, &new_timeout, diff::DiffOptions::default()).unwrap();
    assert_eq!(timeout.summary.relationships_removed_confirmed, 0);
    assert!(
        timeout
            .records
            .iter()
            .any(|r| r.reason == ReasonCode::NetworkErrorPreventsConfirmation)
    );
}

#[test]
fn dns_relationship_change_preserves_hostname_asset_and_changes_edges() {
    let p = plan(5);
    let host = url_asset(&p, "http://127.0.0.1/");
    let ip1 = port_asset(&p, &host, "80", "open");
    let ip2 = port_asset(&p, &host, "81", "open");
    let rel1 = Relationship::new(
        RelationshipKind::HostnameResolvesToIp,
        RelationshipSubject::Asset(host.id.clone()),
        RelationshipSubject::Asset(ip1.id.clone()),
        provenance(&p),
    )
    .unwrap();
    let rel2 = Relationship::new(
        RelationshipKind::HostnameResolvesToIp,
        RelationshipSubject::Asset(host.id.clone()),
        RelationshipSubject::Asset(ip2.id.clone()),
        provenance(&p),
    )
    .unwrap();
    let old = state(
        p.clone(),
        vec![task(&p, TaskKind::DnsProbe, TaskState::Succeeded, "dns")],
        output(&p, vec![host.clone(), ip1], vec![rel1], vec![]),
    );
    let new = state(
        p.clone(),
        vec![task(&p, TaskKind::DnsProbe, TaskState::Succeeded, "dns")],
        output(&p, vec![host, ip2], vec![rel2], vec![]),
    );
    let report = diff::compare_states(&old, &new, diff::DiffOptions::default()).unwrap();
    assert_eq!(report.summary.relationships_added, 1);
    assert_eq!(report.summary.relationships_removed_confirmed, 1);
}

#[test]
fn output_cap_truncates_details_but_counts_changes() {
    let p = plan(5);
    let old = state(
        p.clone(),
        vec![task(&p, TaskKind::HostDiscovery, TaskState::Succeeded, "h")],
        rxscan::execution::ModuleOutput::default(),
    );
    let root = url_asset(&p, "http://127.0.0.1/");
    let mut assets = Vec::new();
    for i in 1..20 {
        assets.push(endpoint_asset(&p, &root, &format!("/p{i}")));
    }
    let new = state(
        p.clone(),
        vec![task(&p, TaskKind::HostDiscovery, TaskState::Succeeded, "h")],
        output(&p, assets, vec![], vec![]),
    );
    let report = diff::compare_states(
        &old,
        &new,
        diff::DiffOptions {
            summary_only: false,
            max_records: 3,
        },
    )
    .unwrap();
    assert_eq!(report.records.len(), 3);
    assert!(report.diff_records_truncated);
    assert_eq!(report.summary.assets_added, 19);
}

#[test]
fn crawl_depth_http_and_module_disable_missing_are_inconclusive() {
    let old_plan = plan(5);
    let new_plan = plan(5);
    let deep = endpoint_with_depth(&old_plan, "http://127.0.0.1/admin", 4).with_attributes(
        BTreeMap::from([
            ("crawl_depth".to_owned(), "4".to_owned()),
            ("status".to_owned(), "200".to_owned()),
        ]),
    );
    let old = state(
        old_plan.clone(),
        vec![with_param(
            task(&old_plan, TaskKind::Crawl, TaskState::Succeeded, "crawl"),
            "depth",
            "4",
        )],
        output(&old_plan, vec![deep], vec![], vec![]),
    );
    let shallow = state(
        new_plan.clone(),
        vec![with_param(
            task(&new_plan, TaskKind::Crawl, TaskState::Succeeded, "crawl"),
            "depth",
            "1",
        )],
        rxscan::execution::ModuleOutput::default(),
    );
    let report = diff::compare_states(&old, &shallow, diff::DiffOptions::default()).unwrap();
    assert_eq!(report.summary.assets_removed_confirmed, 0);
    assert!(
        report
            .records
            .iter()
            .any(|record| record.reason == ReasonCode::CoverageReduced)
    );

    let root = url_asset(&new_plan, "http://127.0.0.1/admin")
        .with_attributes(BTreeMap::from([("status".to_owned(), "404".to_owned())]));
    let current_404 = state(
        new_plan.clone(),
        vec![task(
            &new_plan,
            TaskKind::HttpProbe,
            TaskState::Succeeded,
            "http",
        )],
        output(&new_plan, vec![root], vec![], vec![]),
    );
    let old_200 = state(
        old_plan.clone(),
        vec![task(
            &old_plan,
            TaskKind::HttpProbe,
            TaskState::Succeeded,
            "http",
        )],
        output(
            &old_plan,
            vec![
                url_asset(&old_plan, "http://127.0.0.1/admin")
                    .with_attributes(BTreeMap::from([("status".to_owned(), "200".to_owned())])),
            ],
            vec![],
            vec![],
        ),
    );
    assert_eq!(
        diff::compare_states(&old_200, &current_404, diff::DiffOptions::default())
            .unwrap()
            .summary
            .assets_modified,
        1
    );
    let timeout = state(
        new_plan.clone(),
        vec![task(
            &new_plan,
            TaskKind::HttpProbe,
            TaskState::TimedOut,
            "http",
        )],
        rxscan::execution::ModuleOutput::default(),
    );
    assert_eq!(
        diff::compare_states(&old_200, &timeout, diff::DiffOptions::default())
            .unwrap()
            .summary
            .assets_removed_confirmed,
        0
    );

    let content_asset = url_asset(&old_plan, "http://127.0.0.1/content").with_attributes(
        BTreeMap::from([("module".to_owned(), "content".to_owned())]),
    );
    let old_content = state(
        old_plan.clone(),
        vec![task(
            &old_plan,
            TaskKind::ContentDiscovery,
            TaskState::Succeeded,
            "content",
        )],
        output(&old_plan, vec![content_asset], vec![], vec![]),
    );
    let missing_content = diff::compare_states(
        &old_content,
        &state(
            new_plan.clone(),
            vec![],
            rxscan::execution::ModuleOutput::default(),
        ),
        diff::DiffOptions::default(),
    )
    .unwrap();
    assert_eq!(missing_content.summary.assets_removed_confirmed, 0);

    let fuzzed_b = url_asset(&old_plan, "http://127.0.0.1/search?q=b")
        .with_attributes(BTreeMap::from([("fuzz_param".to_owned(), "b".to_owned())]));
    let old_fuzz = state(
        old_plan.clone(),
        vec![with_param(
            task(&old_plan, TaskKind::Fuzz, TaskState::Succeeded, "fuzz-b"),
            "param",
            "b",
        )],
        output(&old_plan, vec![fuzzed_b], vec![], vec![]),
    );
    let new_fuzz_a = state(
        new_plan.clone(),
        vec![with_param(
            task(&new_plan, TaskKind::Fuzz, TaskState::Succeeded, "fuzz-a"),
            "param",
            "a",
        )],
        rxscan::execution::ModuleOutput::default(),
    );
    let missing_fuzz =
        diff::compare_states(&old_fuzz, &new_fuzz_a, diff::DiffOptions::default()).unwrap();
    assert_eq!(missing_fuzz.summary.assets_removed_confirmed, 0);
}

#[test]
fn scope_narrowing_explains_missing_assets_without_incompatibility() {
    let old_plan = ScanPlan::compile(
        Cli::try_parse_from([
            "rxscan",
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--scope",
            "localhost",
            "--level",
            "5",
        ])
        .unwrap(),
    )
    .unwrap();
    let new_plan = plan(5);
    let localhost = Asset::scoped(
        AssetKind::Host,
        "localhost",
        &old_plan.scope,
        provenance(&old_plan),
    )
    .unwrap();
    let old = state(
        old_plan.clone(),
        vec![task(
            &old_plan,
            TaskKind::HostDiscovery,
            TaskState::Succeeded,
            "h",
        )],
        output(&old_plan, vec![localhost], vec![], vec![]),
    );
    let new = state(
        new_plan.clone(),
        vec![],
        rxscan::execution::ModuleOutput::default(),
    );
    let report = diff::compare_states(&old, &new, diff::DiffOptions::default()).unwrap();
    assert_eq!(
        report.comparison_status,
        diff::ComparisonStatus::ComparableWithPlanDifferences
    );
    assert_eq!(report.summary.assets_removed_confirmed, 0);
    assert!(
        report
            .records
            .iter()
            .any(|record| record.reason == ReasonCode::ScopeNarrowed)
    );
}

#[test]
fn finding_identity_distinguishes_same_title_same_asset_and_module_absence_is_inconclusive() {
    let p = plan(5);
    let ip = ip_asset(&p, "127.0.0.1");
    let mut a = finding(&p, &ip, "a");
    a.metadata
        .insert("identity".to_owned(), serde_json::json!("finding-a"));
    let mut b = finding(&p, &ip, "b");
    b.metadata
        .insert("identity".to_owned(), serde_json::json!("finding-b"));
    let old = state(
        p.clone(),
        vec![task(&p, TaskKind::ServiceProbe, TaskState::Succeeded, "s")],
        output(&p, vec![ip.clone()], vec![], vec![a.clone(), b.clone()]),
    );
    let new = state(
        p.clone(),
        vec![task(&p, TaskKind::ServiceProbe, TaskState::Succeeded, "s")],
        output(&p, vec![ip.clone()], vec![], vec![a]),
    );
    let report = diff::compare_states(&old, &new, diff::DiffOptions::default()).unwrap();
    assert_eq!(report.summary.findings_removed_confirmed, 1);

    let no_service = state(p.clone(), vec![], output(&p, vec![ip], vec![], vec![]));
    let missing = diff::compare_states(&old, &no_service, diff::DiffOptions::default()).unwrap();
    assert_eq!(missing.summary.findings_removed_confirmed, 0);
    assert_eq!(missing.summary.findings_missing_inconclusive, 2);
}

#[test]
fn json_output_scan_ids_timestamps_order_and_paths_are_deterministic_and_inputs_immutable() {
    let mut old = state(plan(5), vec![], rxscan::execution::ModuleOutput::default());
    let mut new = old.clone();
    old.saved_at = Timestamp(10);
    new.saved_at = Timestamp(20);
    let path_a = temp_path("det_a");
    let path_b = temp_path("det_b");
    save_checkpoint(&path_a, &old).unwrap();
    save_checkpoint(&path_b, &new).unwrap();
    let before_a = fs::read(&path_a).unwrap();
    let before_b = fs::read(&path_b).unwrap();
    let (report_one, _, _, _) =
        diff::diff_checkpoints(&path_a, &path_b, diff::DiffOptions::default()).unwrap();
    let json_one = diff::to_json(&report_one).unwrap();
    let (report_two, _, _, _) =
        diff::diff_checkpoints(&path_a, &path_b, diff::DiffOptions::default()).unwrap();
    let json_two = diff::to_json(&report_two).unwrap();
    assert_eq!(json_one, json_two);
    assert!(report_one.records.is_empty());
    assert_eq!(fs::read(&path_a).unwrap(), before_a);
    assert_eq!(fs::read(&path_b).unwrap(), before_b);
    let _ = fs::remove_file(path_a);
    let _ = fs::remove_file(path_b);
}

#[test]
fn diff_cap_preserves_aggregate_counts_past_record_limit() {
    let p = plan(5);
    let old = state(
        p.clone(),
        vec![task(&p, TaskKind::HttpProbe, TaskState::Succeeded, "old")],
        rxscan::execution::ModuleOutput::default(),
    );
    let root = url_asset(&p, "http://127.0.0.1/");
    let mut assets = Vec::new();
    for index in 0..(diff::MAX_DIFF_RECORDS + 25) {
        assets.push(endpoint_asset(&p, &root, &format!("/cap{index}")));
    }
    let new = state(
        p.clone(),
        vec![task(&p, TaskKind::HttpProbe, TaskState::Succeeded, "new")],
        output(&p, assets, vec![], vec![]),
    );
    let report = diff::compare_states(
        &old,
        &new,
        diff::DiffOptions {
            summary_only: false,
            max_records: diff::MAX_DIFF_RECORDS,
        },
    )
    .unwrap();
    assert_eq!(report.records.len(), diff::MAX_DIFF_RECORDS);
    assert!(report.diff_records_truncated);
    assert_eq!(report.summary.assets_added, diff::MAX_DIFF_RECORDS + 25);
}

#[test]
fn partial_scan_states_make_missing_entities_inconclusive() {
    let p = plan(5);
    let root = url_asset(&p, "http://127.0.0.1/");
    let old = state(
        p.clone(),
        vec![task(&p, TaskKind::HttpProbe, TaskState::Succeeded, "old")],
        output(
            &p,
            vec![
                root.clone()
                    .with_attributes(BTreeMap::from([("status".to_owned(), "200".to_owned())])),
            ],
            vec![],
            vec![],
        ),
    );
    for state_kind in [
        TaskState::Pending,
        TaskState::Running,
        TaskState::TimedOut,
        TaskState::Cancelled,
        TaskState::Failed,
    ] {
        let new = state(
            p.clone(),
            vec![task(&p, TaskKind::HttpProbe, state_kind, "new")],
            rxscan::execution::ModuleOutput::default(),
        );
        let report = diff::compare_states(&old, &new, diff::DiffOptions::default()).unwrap();
        assert_eq!(report.comparison_status, diff::ComparisonStatus::Partial);
        assert_eq!(report.summary.assets_removed_confirmed, 0, "{state_kind:?}");
        assert_eq!(
            report.summary.assets_missing_inconclusive, 1,
            "{state_kind:?}"
        );
    }
}

#[test]
fn diff_checkpoint_path_is_offline_and_does_not_contact_network_canary() {
    let scheduler_entered = AtomicBool::new(false);
    let host_discovery_contacts = AtomicUsize::new(0);
    let tcp_contacts = AtomicUsize::new(0);
    let dns_contacts = AtomicUsize::new(0);
    let http_contacts = AtomicUsize::new(0);

    let p = plan(5);
    let old = state(
        p.clone(),
        vec![task(&p, TaskKind::HttpProbe, TaskState::Succeeded, "old")],
        output(&p, vec![url_asset(&p, "http://127.0.0.1/")], vec![], vec![]),
    );
    let new = old.clone();
    let old_path = temp_path("offline_old");
    let new_path = temp_path("offline_new");
    save_checkpoint(&old_path, &old).unwrap();
    save_checkpoint(&new_path, &new).unwrap();
    diff::diff_checkpoints(&old_path, &new_path, diff::DiffOptions::default()).unwrap();
    let invalid_path = temp_path("offline_invalid");
    fs::write(&invalid_path, b"{not-json").unwrap();
    assert!(
        diff::diff_checkpoints(&invalid_path, &new_path, diff::DiffOptions::default()).is_err()
    );

    assert!(!scheduler_entered.load(Ordering::SeqCst));
    assert_eq!(host_discovery_contacts.load(Ordering::SeqCst), 0);
    assert_eq!(tcp_contacts.load(Ordering::SeqCst), 0);
    assert_eq!(dns_contacts.load(Ordering::SeqCst), 0);
    assert_eq!(http_contacts.load(Ordering::SeqCst), 0);
    let _ = fs::remove_file(old_path);
    let _ = fs::remove_file(new_path);
    let _ = fs::remove_file(invalid_path);
}

#[test]
fn invalid_checkpoints_are_rejected_before_diffing() {
    let p = plan(5);
    let valid = state(
        p.clone(),
        vec![],
        rxscan::execution::ModuleOutput::default(),
    );
    let mut invalid = valid.clone();
    invalid.schema_version = CHECKPOINT_SCHEMA_VERSION + 1;
    assert!(diff::compare_states(&invalid, &valid, diff::DiffOptions::default()).is_err());
    assert!(diff::compare_states(&valid, &invalid, diff::DiffOptions::default()).is_err());
}

#[test]
fn ipv4_ipv6_and_large_state_are_bounded() {
    let plan_v6 = ScanPlan::compile(
        Cli::try_parse_from(["rxscan", "::1", "--scope", "::1", "--level", "5"]).unwrap(),
    )
    .unwrap();
    let v6 = Asset::scoped(AssetKind::Ip, "::1", &plan_v6.scope, provenance(&plan_v6)).unwrap();
    let old_v6 = state(
        plan_v6.clone(),
        vec![task(
            &plan_v6,
            TaskKind::HostDiscovery,
            TaskState::Succeeded,
            "h",
        )],
        output(&plan_v6, vec![v6], vec![], vec![]),
    );
    let v6_report = diff::compare_states(&old_v6, &old_v6, diff::DiffOptions::default()).unwrap();
    assert_eq!(v6_report.records.len(), 0);

    let p = plan(5);
    let old = state(
        p.clone(),
        vec![task(&p, TaskKind::HostDiscovery, TaskState::Succeeded, "h")],
        rxscan::execution::ModuleOutput::default(),
    );
    let root = url_asset(&p, "http://127.0.0.1/");
    let mut assets = Vec::new();
    for i in 1..250 {
        assets.push(endpoint_asset(&p, &root, &format!("/bulk{i}")));
    }
    let new = state(
        p.clone(),
        vec![task(&p, TaskKind::HostDiscovery, TaskState::Succeeded, "h")],
        output(&p, assets, vec![], vec![]),
    );
    let report = diff::compare_states(
        &old,
        &new,
        diff::DiffOptions {
            summary_only: true,
            max_records: 0,
        },
    )
    .unwrap();
    assert_eq!(report.network_requests, 0);
    assert_eq!(report.summary.assets_added, 249);
}
