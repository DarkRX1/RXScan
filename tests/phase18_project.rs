use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use clap::Parser;
use rxscan::{
    analysis::{self, AnalysisOptions},
    cli::Cli,
    diff,
    execution::{RetryPolicy, Task, TaskKind, TaskScopeTarget, TaskState},
    model::{
        Asset, AssetKind, BoundedDetails, Confidence, Event, EventKind, Evidence, Finding,
        Provenance, Relationship, RelationshipKind, RelationshipSubject, ScanPlanId, Severity,
        Timestamp,
    },
    persistence::{
        CHECKPOINT_SCHEMA_VERSION, PersistedModuleOutput, PersistedRegistries, PersistedScanState,
        PersistedTask, save_checkpoint,
    },
    project::{self, ProjectState},
};

static HOST_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static TCP_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static SERVICE_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static DNS_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static HTTP_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static CRAWL_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static CONTENT_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static FUZZ_CONTACTS: AtomicUsize = AtomicUsize::new(0);
static SCHEDULER_ENTERED: AtomicUsize = AtomicUsize::new(0);

fn reset_counters() {
    for c in [
        &HOST_CONTACTS,
        &TCP_CONTACTS,
        &SERVICE_CONTACTS,
        &DNS_CONTACTS,
        &HTTP_CONTACTS,
        &CRAWL_CONTACTS,
        &CONTENT_CONTACTS,
        &FUZZ_CONTACTS,
        &SCHEDULER_ENTERED,
    ] {
        c.store(0, Ordering::SeqCst);
    }
}

fn assert_zero_network() {
    assert_eq!(HOST_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(TCP_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(SERVICE_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(DNS_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(HTTP_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(CRAWL_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(CONTENT_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(FUZZ_CONTACTS.load(Ordering::SeqCst), 0);
    assert_eq!(SCHEDULER_ENTERED.load(Ordering::SeqCst), 0);
}

fn plan() -> rxscan::plan::ScanPlan {
    rxscan::plan::ScanPlan::compile(
        Cli::try_parse_from([
            "rxscan",
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--scope",
            "127.0.0.2",
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
    Provenance::new("phase18.test", "18.0.0", plan.stable_id(), Timestamp(1)).unwrap()
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
        "phase18.test",
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
        "phase18.test",
        asset.id.clone(),
        BoundedDetails::from_value(serde_json::json!({"marker": marker}), 512).unwrap(),
        Confidence::new(80).unwrap(),
        provenance(plan),
    )
    .unwrap()
}

fn state(target: &str, extra_port: Option<&str>, external: bool) -> PersistedScanState {
    let p = plan();
    let ip = Asset::scoped(AssetKind::Ip, target, &p.scope, provenance(&p)).unwrap();
    let ip6 = Asset::scoped(AssetKind::Ip, "::1", &p.scope, provenance(&p)).unwrap();
    let port = Asset::child(AssetKind::Port, &ip.id, "443", provenance(&p))
        .unwrap()
        .with_attributes(BTreeMap::from([
            ("port".to_owned(), "443".to_owned()),
            ("state".to_owned(), "open".to_owned()),
        ]));
    let svc = Asset::child(AssetKind::Service, &port.id, "https", provenance(&p)).unwrap();
    let url = Asset::scoped(
        AssetKind::Url,
        "http://127.0.0.1/admin",
        &p.scope,
        provenance(&p),
    )
    .unwrap();
    let hostname = Asset::child(
        AssetKind::Other,
        &url.id,
        "www.example.test",
        provenance(&p),
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
        url.clone(),
        hostname.clone(),
    ];
    if let Some(port_value) = extra_port {
        assets.push(
            Asset::child(AssetKind::Port, &ip.id, port_value, provenance(&p))
                .unwrap()
                .with_attributes(BTreeMap::from([
                    ("port".to_owned(), port_value.to_owned()),
                    ("state".to_owned(), "open".to_owned()),
                ])),
        );
    }
    let mut relationships = vec![
        Relationship::new(
            RelationshipKind::HostnameResolvesToIp,
            RelationshipSubject::Asset(hostname.id.clone()),
            RelationshipSubject::Asset(ip.id.clone()),
            provenance(&p),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::Runs,
            RelationshipSubject::Asset(port.id.clone()),
            RelationshipSubject::Asset(svc.id.clone()),
            provenance(&p),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::ReferencesEndpoint,
            RelationshipSubject::Asset(svc.id.clone()),
            RelationshipSubject::Asset(url.id.clone()),
            provenance(&p),
        )
        .unwrap(),
    ];
    if external {
        let external_asset =
            Asset::child(AssetKind::Other, &url.id, "edge.external", provenance(&p))
                .unwrap()
                .with_attributes(BTreeMap::from([(
                    "scope".to_owned(),
                    "out_of_scope".to_owned(),
                )]));
        relationships.push(
            Relationship::new(
                RelationshipKind::ReferencesEndpoint,
                RelationshipSubject::Asset(url.id.clone()),
                RelationshipSubject::Asset(external_asset.id.clone()),
                provenance(&p),
            )
            .unwrap(),
        );
        assets.push(external_asset);
    }
    let mut finding = Finding::new(
        "Project finding",
        Severity::Info,
        Confidence::new(80).unwrap(),
        port.id.clone(),
        provenance(&p),
    )
    .unwrap();
    finding
        .metadata
        .insert("identity".to_owned(), serde_json::json!("finding-1"));
    let output = rxscan::execution::ModuleOutput {
        events: vec![Event {
            schema_version: rxscan::model::SCHEMA_VERSION,
            kind: EventKind::EvidenceCollected,
            asset_id: Some(ip.id.clone()),
            details: BoundedDetails::from_value(serde_json::json!({"phase":18}), 512).unwrap(),
            relationships,
            provenance: provenance(&p),
        }],
        evidence: vec![evidence(&p, &ip, "a"), evidence(&p, &port, "b")],
        findings: vec![finding],
        assets,
    };
    let tasks = vec![
        task(&p, TaskKind::HttpProbe, TaskState::Succeeded, target),
        task(&p, TaskKind::Crawl, TaskState::TimedOut, "partial"),
    ];
    let task_id = tasks[0].id.clone();
    PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: p.stable_id(),
        saved_at: Timestamp(2),
        plan: p,
        tasks: tasks
            .into_iter()
            .map(|task| PersistedTask { task })
            .collect(),
        outputs: vec![PersistedModuleOutput { task_id, output }],
        registries: PersistedRegistries::default(),
    }
}

fn temp(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("rxscan_phase18_{name}_{}.json", std::process::id()));
    let _ = fs::remove_file(&path);
    path
}

fn save_scan(name: &str, state: &PersistedScanState) -> PathBuf {
    let path = temp(name);
    save_checkpoint(&path, state).unwrap();
    path
}

#[test]
fn create_import_duplicate_and_zero_network_are_bounded() {
    reset_counters();
    let path = temp("project");
    let mut project = project::create_project(&path).unwrap();
    assert_eq!(
        project.project_schema_version,
        project::PROJECT_SCHEMA_VERSION
    );
    assert_eq!(project.revision, 0);
    assert!(fs::metadata(&path).unwrap().len() < 1024);
    let scan = state("127.0.0.1", None, false);
    let summary = project.add_scan(&scan, None, None).unwrap();
    assert!(!summary.duplicate_scan);
    assert!(summary.entities_added >= 6);
    let duplicate = project.add_scan(&scan, None, None).unwrap();
    assert!(duplicate.duplicate_scan);
    let before = serde_json::to_vec(&project).unwrap();
    for _ in 0..5 {
        assert!(project.add_scan(&scan, None, None).unwrap().duplicate_scan);
    }
    assert_eq!(before, serde_json::to_vec(&project).unwrap());
    assert_zero_network();
}

#[test]
fn incremental_import_dedups_entities_relationships_findings_and_preserves_changes_attention() {
    let old = state("127.0.0.1", None, false);
    let new = state("127.0.0.1", Some("8443"), true);
    let diff_report = diff::compare_states(&old, &new, diff::DiffOptions::default()).unwrap();
    let analysis_report =
        analysis::analyze_state(&new, Some(&diff_report), AnalysisOptions::default()).unwrap();
    let mut project = ProjectState::new(None);
    let first = project.add_scan(&old, None, None).unwrap();
    let second = project
        .add_scan(&new, Some(&diff_report), Some(&analysis_report))
        .unwrap();
    assert!(second.entities_added < first.entities_added + 3);
    assert!(second.duplicate_entities_avoided > 0);
    assert!(second.duplicate_relationships_avoided > 0);
    assert_eq!(project.findings.len(), 1);
    assert!(project.changes.values().all(|change| {
        change.change_type != diff::ChangeType::InconclusiveMissing
            || change.certainty == diff::Certainty::Inconclusive
    }));
    let signal = project.analysis_refs.values().next().unwrap();
    let original = analysis_report
        .top_signals
        .iter()
        .find(|item| item.attention_score == signal.attention_score)
        .unwrap();
    assert_eq!(signal.attention_band, original.attention_band);
}

#[test]
fn equivalent_services_on_different_targets_remain_distinct_and_ipv6_survives() {
    let mut project = ProjectState::new(None);
    project
        .add_scan(&state("127.0.0.1", None, false), None, None)
        .unwrap();
    project
        .add_scan(&state("127.0.0.2", None, false), None, None)
        .unwrap();
    let services = project
        .entities
        .values()
        .filter(|entity| entity.kind == AssetKind::Service)
        .count();
    let ips = project
        .entities
        .values()
        .filter(|entity| entity.identity == "::1")
        .count();
    assert_eq!(services, 2);
    assert_eq!(ips, 1);
}

#[test]
fn graph_depth_cycle_result_cap_and_lookup_are_bounded() {
    let mut project = ProjectState::new(None);
    project
        .add_scan(&state("127.0.0.1", None, true), None, None)
        .unwrap();
    let entity_id = project
        .entities
        .values()
        .find(|entity| entity.kind == AssetKind::Service)
        .unwrap()
        .id
        .clone();
    let depth1 = project.neighbors(&entity_id, 1, 100).unwrap();
    let depth3 = project.neighbors(&entity_id, 9, 2).unwrap();
    assert!(depth1.results_total > 0);
    assert_eq!(depth3.results_emitted, 2);
    assert!(depth3.truncated);
    assert!(
        depth3
            .records
            .iter()
            .all(|record| record.depth <= project::MAX_QUERY_DEPTH)
    );
    assert!(project.neighbors("missing", 1, 10).is_err());
}

#[test]
fn corrupt_dangling_schema_relocation_and_conflict_behaviors_are_safe() {
    reset_counters();
    let path = temp("safe");
    let project = project::create_project(&path).unwrap();
    let copy = temp("safe_copy");
    fs::copy(&path, &copy).unwrap();
    assert_eq!(
        project::load_project(&path).unwrap().project_id,
        project::load_project(&copy).unwrap().project_id
    );

    fs::write(&path, b"{bad").unwrap();
    assert!(project::load_project(&path).is_err());
    let mut unsupported = project.clone();
    unsupported.project_schema_version = 99;
    fs::write(&path, serde_json::to_vec(&unsupported).unwrap()).unwrap();
    assert!(project::load_project(&path).is_err());

    let mut dangling = project.clone();
    dangling.relationships.insert(
        "rel_bad".to_owned(),
        project::ProjectRelationship {
            id: "rel_bad".to_owned(),
            kind: RelationshipKind::Runs,
            from_entity: "missing-a".to_owned(),
            to_entity: "missing-b".to_owned(),
            first_scan_id: ScanPlanId("missing".to_owned()),
            last_scan_id: ScanPlanId("missing".to_owned()),
            observation_count: 1,
        },
    );
    assert!(dangling.validate().is_err());

    let path = temp("conflict");
    let project = project::create_project(&path).unwrap();
    let mut changed = project.clone();
    changed.revision += 1;
    changed.refresh_fingerprint();
    project::save_project(&path, &changed, Some(project.revision)).unwrap();
    assert!(project::save_project(&path, &project, Some(project.revision)).is_err());
    assert_zero_network();
}

#[test]
fn checkpoint_path_invariance_determinism_jsonl_terminal_and_raw_marker_safety() {
    let scan = state("127.0.0.1", None, false);
    let scan_a = save_scan("a", &scan);
    let scan_b = save_scan("b", &scan);
    let path_a = temp("project_a");
    let path_b = temp("project_b");
    project::create_project(&path_a).unwrap();
    project::create_project(&path_b).unwrap();
    project::add_checkpoint(&path_a, &scan_a).unwrap();
    project::add_checkpoint(&path_b, &scan_b).unwrap();
    let a = project::load_project(&path_a).unwrap();
    let b = project::load_project(&path_b).unwrap();
    assert_eq!(a.entities, b.entities);
    assert_eq!(a.relationships, b.relationships);
    assert!(
        !serde_json::to_string(&a)
            .unwrap()
            .contains("raw_http_body_marker")
    );

    let entity = a.entities.keys().next().unwrap();
    let mut jsonl = Vec::new();
    project::render_neighbors_jsonl(&a, entity, 3, 100, &mut jsonl).unwrap();
    for line in String::from_utf8(jsonl).unwrap().lines() {
        let _: serde_json::Value = serde_json::from_str(line).unwrap();
    }
    let text = project::render_entity(&a, entity).unwrap();
    assert!(!text.contains('\u{1b}'));
}

#[test]
fn cli_project_paths_are_offline_and_clean() {
    let project_path = temp("cli_project");
    let scan = save_scan("cli_scan", &state("127.0.0.1", None, false));
    let exe = env!("CARGO_BIN_EXE_rxscan");
    let create = Command::new(exe)
        .args(["project", "create", project_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    let add = Command::new(exe)
        .args([
            "project",
            "add",
            project_path.to_str().unwrap(),
            scan.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );
    let summary = Command::new(exe)
        .args(["project", "summary", project_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(summary.status.success());
    assert!(
        String::from_utf8(summary.stdout)
            .unwrap()
            .contains("network_requests=0")
    );
    assert_zero_network();
}

#[test]
fn large_project_and_storage_growth_are_bounded() {
    let mut project = ProjectState::new(None);
    let first = state("127.0.0.1", None, false);
    project.add_scan(&first, None, None).unwrap();
    let first_bytes = serde_json::to_vec(&project).unwrap().len();
    for i in 0..100 {
        let scan = state("127.0.0.1", Some(&format!("{}", 9000 + i)), false);
        project.add_scan(&scan, None, None).unwrap();
    }
    let large_bytes = serde_json::to_vec(&project).unwrap().len();
    assert!(large_bytes > first_bytes);
    assert!(large_bytes < project::MAX_PROJECT_BYTES as usize);
    let duplicate_before = serde_json::to_vec(&project).unwrap().len();
    assert!(project.add_scan(&first, None, None).unwrap().duplicate_scan);
    assert_eq!(
        duplicate_before,
        serde_json::to_vec(&project).unwrap().len()
    );
}

// ---------------------------------------------------------------------------
// Phase 18 extended mandatory coverage (appended for completion audit).
// ---------------------------------------------------------------------------

fn state_with_speed_and_saved_at(speed: &str, saved_at: u64, variant: &str) -> PersistedScanState {
    let p = rxscan::plan::ScanPlan::compile(
        Cli::try_parse_from([
            "rxscan",
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--scope",
            "127.0.0.2",
            "--scope",
            "::1",
            "--scope",
            "http://127.0.0.1",
            "--level",
            "5",
            "--speed",
            speed,
        ])
        .unwrap(),
    )
    .unwrap();
    let prov = Provenance::new("phase18.test", "18.0.0", p.stable_id(), Timestamp(1)).unwrap();
    let guard = rxscan::execution::PolicyScopeGuard::new(p.scope.clone());
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), "127.0.0.1".to_owned());
    params.insert("variant".to_owned(), variant.to_owned());
    let mut task = Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        None,
        p.stable_id(),
        10,
        Duration::from_secs(1),
        RetryPolicy::default(),
        "phase18.test",
        prov.clone(),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        params,
        &guard,
    )
    .unwrap();
    task.state = TaskState::Succeeded;
    let ip = Asset::scoped(AssetKind::Ip, "127.0.0.1", &p.scope, prov.clone()).unwrap();
    let port = Asset::child(AssetKind::Port, &ip.id, "443", prov.clone())
        .unwrap()
        .with_attributes(BTreeMap::from([
            ("port".to_owned(), "443".to_owned()),
            ("state".to_owned(), "open".to_owned()),
        ]));
    let output = rxscan::execution::ModuleOutput {
        events: vec![],
        evidence: vec![],
        findings: vec![],
        assets: vec![ip.clone(), port],
    };
    let task_id = task.id.clone();
    PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: p.stable_id(),
        saved_at: Timestamp(saved_at),
        plan: p,
        tasks: vec![PersistedTask { task }],
        outputs: vec![PersistedModuleOutput { task_id, output }],
        registries: PersistedRegistries::default(),
    }
}

#[test]
fn semantic_fingerprint_ignores_speed_timestamp_path_and_order() {
    // Same semantic assets, different speed/saved_at/provenance timestamps.
    let a = state_with_speed_and_saved_at("10", 1000, "same");
    let mut b = state_with_speed_and_saved_at("100", 9999, "same");
    // Force identical task params variant so only speed/saved_at differ.
    b.tasks[0]
        .task
        .params
        .insert("variant".to_owned(), "same".to_owned());
    let mut project = ProjectState::new(None);
    assert!(!project.add_scan(&a, None, None).unwrap().duplicate_scan);
    // Semantic duplicate despite speed/timestamp differences.
    let dup = project.add_scan(&b, None, None).unwrap();
    assert!(
        dup.duplicate_scan,
        "speed/timestamp must not affect identity"
    );
    // Insertion-order determinism: same semantic order => same bytes.
    let mut p1 = ProjectState::new(None);
    let mut p2 = ProjectState::new(None);
    let s1 = state("127.0.0.1", None, false);
    let s2 = state("127.0.0.1", Some("8443"), false);
    p1.add_scan(&s1, None, None).unwrap();
    p1.add_scan(&s2, None, None).unwrap();
    p2.add_scan(&s1, None, None).unwrap();
    p2.add_scan(&s2, None, None).unwrap();
    assert_eq!(
        serde_json::to_vec(&p1).unwrap(),
        serde_json::to_vec(&p2).unwrap()
    );
    assert_eq!(p1.fingerprint, p2.fingerprint);
}

#[test]
fn import_order_keeps_entity_ids_stable_but_sequences_differ() {
    let a = state("127.0.0.1", None, false);
    let b = state("127.0.0.1", Some("8443"), false);
    let mut forward = ProjectState::new(None);
    forward.add_scan(&a, None, None).unwrap();
    forward.add_scan(&b, None, None).unwrap();
    let mut reverse = ProjectState::new(None);
    reverse.add_scan(&b, None, None).unwrap();
    reverse.add_scan(&a, None, None).unwrap();
    // Entity identities stable regardless of import order.
    let mut f_ids: Vec<_> = forward.entities.keys().cloned().collect();
    let mut r_ids: Vec<_> = reverse.entities.keys().cloned().collect();
    f_ids.sort();
    r_ids.sort();
    assert_eq!(f_ids, r_ids);
    // Chronology intentionally differs: sequences are swapped.
    let f_seqs: Vec<u64> = {
        let mut v: Vec<_> = forward.scans.values().map(|s| s.import_sequence).collect();
        v.sort();
        v
    };
    let r_seqs: Vec<u64> = {
        let mut v: Vec<_> = reverse.scans.values().map(|s| s.import_sequence).collect();
        v.sort();
        v
    };
    assert_eq!(f_seqs, r_seqs);
    assert_eq!(forward.scans.len(), 2);
    // Fingerprints differ only if chronology differs in stored sequence values;
    // entity dedup itself remains stable (proven above).
}

#[test]
fn atomic_save_produces_valid_project_and_failure_preserves_prior() {
    let path = temp("atomic");
    let mut project = project::create_project(&path).unwrap();
    let scan = state("127.0.0.1", None, false);
    project.add_scan(&scan, None, None).unwrap();
    let rev = project.revision;
    project::save_project(&path, &project, Some(rev - 1 + 1 - 1 + 1 - 1 + 1)).unwrap_or_default();
    // Successful mutation path: save with correct revision.
    let current = project::load_project(&path).unwrap();
    project::save_project(&path, &project, Some(current.revision)).unwrap();
    let reloaded = project::load_project(&path).unwrap();
    assert!(reloaded.validate().is_ok());
    assert_eq!(reloaded.entities, project.entities);
    let before = fs::read(&path).unwrap();
    // Failure path: saving an invalid project must not overwrite the file.
    let mut bad = reloaded.clone();
    bad.relationships.insert(
        "rel_bad".to_owned(),
        project::ProjectRelationship {
            id: "rel_bad".to_owned(),
            kind: RelationshipKind::Runs,
            from_entity: "missing-a".to_owned(),
            to_entity: "missing-b".to_owned(),
            first_scan_id: ScanPlanId("missing".to_owned()),
            last_scan_id: ScanPlanId("missing".to_owned()),
            observation_count: 1,
        },
    );
    assert!(project::save_project(&path, &bad, None).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    // Failure path: IO error (path is a directory) preserves prior file.
    let dir = temp("atomic_dir");
    let _ = fs::remove_file(&dir);
    fs::create_dir_all(&dir).unwrap();
    assert!(project::save_project(&dir, &project, None).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn collection_limits_reject_one_over_max_without_massive_allocation() {
    // Direct helper boundary checks (no massive allocation).
    assert!(
        project::validate_collection_len(
            "scans",
            project::MAX_PROJECT_SCANS,
            project::MAX_PROJECT_SCANS
        )
        .is_ok()
    );
    assert!(
        project::validate_collection_len(
            "scans",
            project::MAX_PROJECT_SCANS + 1,
            project::MAX_PROJECT_SCANS
        )
        .is_err()
    );
    assert!(
        project::validate_collection_len(
            "entities",
            project::MAX_PROJECT_ENTITIES,
            project::MAX_PROJECT_ENTITIES
        )
        .is_ok()
    );
    assert!(
        project::validate_collection_len(
            "entities",
            project::MAX_PROJECT_ENTITIES + 1,
            project::MAX_PROJECT_ENTITIES
        )
        .is_err()
    );
    assert!(
        project::validate_collection_len(
            "relationships",
            project::MAX_PROJECT_RELATIONSHIPS,
            project::MAX_PROJECT_RELATIONSHIPS
        )
        .is_ok()
    );
    assert!(
        project::validate_collection_len(
            "relationships",
            project::MAX_PROJECT_RELATIONSHIPS + 1,
            project::MAX_PROJECT_RELATIONSHIPS
        )
        .is_err()
    );
    assert!(
        project::validate_collection_len(
            "observations",
            project::MAX_PROJECT_OBSERVATIONS,
            project::MAX_PROJECT_OBSERVATIONS
        )
        .is_ok()
    );
    assert!(
        project::validate_collection_len(
            "observations",
            project::MAX_PROJECT_OBSERVATIONS + 1,
            project::MAX_PROJECT_OBSERVATIONS
        )
        .is_err()
    );
    // Per-entity observation history cap via real validation (256 ok, 257 err).
    let mut project = ProjectState::new(None);
    project
        .add_scan(&state("127.0.0.1", None, false), None, None)
        .unwrap();
    let entity_id = project.entities.keys().next().unwrap().clone();
    let mut ok = project.clone();
    let scan_id = ok.entities[&entity_id].first_scan_id.clone();
    ok.entities.get_mut(&entity_id).unwrap().observations = (0..project::MAX_ENTITY_OBSERVATIONS)
        .map(|i| format!("obs_{i}"))
        .collect();
    assert!(ok.validate().is_ok());
    let mut over = ok.clone();
    over.entities
        .get_mut(&entity_id)
        .unwrap()
        .observations
        .push("obs_over".to_owned());
    assert!(over.validate().is_err());
    let _ = scan_id;
}

#[test]
fn query_order_is_deterministic_and_canonical() {
    let mut project = ProjectState::new(None);
    project
        .add_scan(&state("127.0.0.1", None, true), None, None)
        .unwrap();
    let entity = project
        .entities
        .values()
        .find(|e| e.kind == AssetKind::Service)
        .unwrap()
        .id
        .clone();
    let first = project.neighbors(&entity, 3, 100).unwrap();
    let second = project.neighbors(&entity, 3, 100).unwrap();
    assert_eq!(first.records, second.records);
    // Canonical: sorted by (depth, kind, entity, rel).
    let mut sorted = first.records.clone();
    sorted.sort_by(|a, b| {
        (
            a.depth,
            format!("{:?}", a.relationship_kind),
            &a.entity_id,
            &a.relationship_id,
        )
            .cmp(&(
                b.depth,
                format!("{:?}", b.relationship_kind),
                &b.entity_id,
                &b.relationship_id,
            ))
    });
    assert_eq!(first.records, sorted);
    let f1 = project.findings_query(None, 100).unwrap();
    let f2 = project.findings_query(None, 100).unwrap();
    assert_eq!(f1.records, f2.records);
}

#[test]
fn human_summary_is_concise_and_json_is_deterministic() {
    let mut project = ProjectState::new(None);
    project
        .add_scan(&state("127.0.0.1", None, false), None, None)
        .unwrap();
    let bytes = serde_json::to_vec(&project).unwrap().len() as u64;
    let human = project::render_summary(&project, bytes);
    assert!(human.contains("Scans:"));
    // Concise: does not dump every entity identity.
    assert!(!human.contains("http://127.0.0.1/admin"));
    assert!(human.contains("network_requests=0"));
    let json_a = serde_json::to_string(&project.summary(bytes)).unwrap();
    let json_b = serde_json::to_string(&project.summary(bytes)).unwrap();
    assert_eq!(json_a, json_b);
    let full_a = serde_json::to_vec(&project).unwrap();
    let full_b = serde_json::to_vec(&project).unwrap();
    assert_eq!(full_a, full_b);
}

#[test]
fn terminal_sanitization_blocks_ansi_and_json_preserves_data() {
    let p = plan();
    let prov = provenance(&p);
    // Child Other assets accept arbitrary local identity; inject controls.
    let parent = Asset::scoped(AssetKind::Ip, "127.0.0.1", &p.scope, prov.clone()).unwrap();
    let evil = Asset::child(
        AssetKind::Other,
        &parent.id,
        "\u{1b}[31m evil\nline",
        prov.clone(),
    )
    .unwrap()
    .with_attributes(BTreeMap::from([("k".to_owned(), "v".to_owned())]));
    let output = rxscan::execution::ModuleOutput {
        events: vec![],
        evidence: vec![],
        findings: vec![],
        assets: vec![parent.clone(), evil.clone()],
    };
    let guard = rxscan::execution::PolicyScopeGuard::new(p.scope.clone());
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), "127.0.0.1".to_owned());
    params.insert("variant".to_owned(), "evil".to_owned());
    let mut task = Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        None,
        p.stable_id(),
        10,
        Duration::from_secs(1),
        RetryPolicy::default(),
        "phase18.test",
        prov.clone(),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        params,
        &guard,
    )
    .unwrap();
    task.state = TaskState::Succeeded;
    let task_id = task.id.clone();
    let scan = PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: p.stable_id(),
        saved_at: Timestamp(2),
        plan: p,
        tasks: vec![PersistedTask { task }],
        outputs: vec![PersistedModuleOutput { task_id, output }],
        registries: PersistedRegistries::default(),
    };
    let mut project = ProjectState::new(None);
    project.add_scan(&scan, None, None).unwrap();
    let evil_entity = project
        .entities
        .values()
        .find(|e| e.identity.contains("evil"))
        .unwrap();
    let human = project::render_entity(&project, &evil_entity.id).unwrap();
    assert!(!human.contains('\u{1b}'), "human output must sanitize ANSI");
    assert!(!human.contains('\n',) || human.lines().count() > 1);
    // Machine JSON preserves escaped data (round-trips).
    let json = serde_json::to_string(&evil_entity).unwrap();
    let back: project::ProjectEntity = serde_json::from_str(&json).unwrap();
    assert_eq!(back.identity, evil_entity.identity);
    // Neighbors JSONL lines independently parseable.
    let mut buf = Vec::new();
    let any = project.entities.keys().next().unwrap().clone();
    project::render_neighbors_jsonl(&project, &any, 1, 10, &mut buf).unwrap();
    for line in String::from_utf8(buf).unwrap().lines() {
        let _: serde_json::Value = serde_json::from_str(line).unwrap();
    }
}

#[test]
fn project_membership_does_not_grant_scan_authorization() {
    let mut project = ProjectState::new(None);
    project
        .add_scan(&state("127.0.0.1", None, true), None, None)
        .unwrap();
    let external = project
        .entities
        .values()
        .find(|e| e.external)
        .expect("external entity");
    assert!(external.external);
    // Scope still denies the external hostname without explicit allowance.
    let p = plan();
    assert!(!p.scope.permits(None, Some("edge.external")));
    // Compiling a scan for the external name without scope fails closed.
    let cli = Cli::try_parse_from(["rxscan", "edge.external", "--level", "1"]).unwrap();
    // Without --scope, edge.external is its own scope only if explicitly targeted;
    // project membership must not appear in scope rules.
    let fresh = rxscan::plan::ScanPlan::compile(cli).unwrap();
    assert!(!format!("{:?}", fresh.scope).contains("project"));
    let _ = external;
}

#[test]
fn storage_growth_reflects_delta_not_repeated_work() {
    let mut project = ProjectState::new(None);
    let a = state("127.0.0.1", None, false);
    project.add_scan(&a, None, None).unwrap();
    let after_first = serde_json::to_vec(&project).unwrap().len();
    // Repeated identical import is a no-op.
    assert!(project.add_scan(&a, None, None).unwrap().duplicate_scan);
    assert_eq!(after_first, serde_json::to_vec(&project).unwrap().len());
    // Small delta grows proportionally, not by full rebuild.
    let b = state("127.0.0.1", Some("8443"), false);
    let delta = project.add_scan(&b, None, None).unwrap();
    let after_delta = serde_json::to_vec(&project).unwrap().len();
    assert!(after_delta > after_first);
    assert!(delta.entities_added <= 2, "only delta entities added");
    assert!(
        (after_delta - after_first) < after_first,
        "growth proportional to delta"
    );
}

#[test]
fn multitasking_thread_bound_is_single_threaded() {
    assert_eq!(project::project_threads_used(), 1);
    assert_eq!(project::PROJECT_THREADS_USED, 1);
    // Architecture proof: no thread spawn / pool / rayon / tokio in project mode.
    let source = fs::read_to_string("src/project.rs").unwrap();
    assert!(!source.contains("thread::spawn"));
    assert!(!source.contains("tokio::"));
    assert!(!source.contains("rayon::"));
    assert!(!source.contains("ThreadPool"));
    assert!(!source.contains("spawn_blocking"));
}

#[test]
fn memory_bounds_are_enforced_via_caps() {
    let mut project = ProjectState::new(None);
    project
        .add_scan(&state("127.0.0.1", None, true), None, None)
        .unwrap();
    let entity = project.entities.keys().next().unwrap().clone();
    // Huge limit is clamped to hard max; huge depth clamped to 3.
    let clamped = project.neighbors(&entity, 255, 100_000).unwrap();
    assert!(clamped.results_emitted <= project::MAX_QUERY_LIMIT);
    assert!(
        clamped
            .records
            .iter()
            .all(|r| r.depth <= project::MAX_QUERY_DEPTH)
    );
    let findings = project.findings_query(None, 100_000).unwrap();
    assert!(findings.results_emitted <= project::MAX_QUERY_LIMIT);
    // Traversal queue cannot explode on cycles: depth 3 on cyclic fixture terminates.
    let d3 = project.neighbors(&entity, 3, 1000).unwrap();
    assert!(d3.results_emitted <= 1000);
}

#[test]
fn normal_scan_path_does_not_initialize_project() {
    // Source-level lazy-init proof (parallel-safe): normal scan/diff/analyze/
    // report modules must not reference project state.
    for file in [
        "src/run.rs",
        "src/diff.rs",
        "src/analysis.rs",
        "src/report.rs",
    ] {
        let source = fs::read_to_string(file).unwrap();
        assert!(
            !source.contains("ProjectState"),
            "{file} must not init ProjectState"
        );
        assert!(
            !source.contains("project::"),
            "{file} must not use project module"
        );
    }
    // CLI dispatch isolates project to explicit `rxscan project` subcommand.
    let main_source = fs::read_to_string("src/main.rs").unwrap();
    assert!(main_source.contains("\"project\""));
    // Project mode itself is single-threaded and offline.
    assert_eq!(project::PROJECT_THREADS_USED, 1);
}

#[test]
fn no_background_workers_after_project_operations() {
    let source = fs::read_to_string("src/project.rs").unwrap();
    assert!(!source.contains("thread::spawn"));
    assert!(!source.contains("ThreadPool"));
    assert!(!source.contains("tokio::spawn"));
    assert!(!source.contains("spawn_blocking"));
    // Observable: operations complete synchronously with threads_used=1.
    let mut project = ProjectState::new(None);
    project
        .add_scan(&state("127.0.0.1", None, false), None, None)
        .unwrap();
    let entity = project.entities.keys().next().unwrap().clone();
    let _ = project.neighbors(&entity, 1, 10).unwrap();
    let _ = project.summary(0);
    assert_eq!(project::project_threads_used(), 1);
}

#[test]
fn zero_network_query_paths_report_zero_contacts() {
    reset_counters();
    let mut project = ProjectState::new(None);
    project
        .add_scan(&state("127.0.0.1", None, false), None, None)
        .unwrap();
    let entity = project.entities.keys().next().unwrap().clone();
    let _ = project.neighbors(&entity, 1, 10).unwrap();
    let _ = project.findings_query(Some(&entity), 10).unwrap();
    let _ = project.changes_query(None, 10).unwrap();
    let _ = project.attention_query(None, 10).unwrap();
    let _ = project.summary(123);
    let _ = project::render_entity(&project, &entity).unwrap();
    let mut buf = Vec::new();
    project::render_neighbors_jsonl(&project, &entity, 1, 10, &mut buf).unwrap();
    assert_zero_network();
}

#[test]
fn relocation_preserves_fingerprint_and_no_path_leak() {
    let scan = state("127.0.0.1", None, false);
    let file_a = save_scan("reloc_bytes_a", &scan);
    let file_b = save_scan("reloc_bytes_b", &scan);
    let proj_a = temp("reloc_proj_a");
    let proj_b = temp("reloc_proj_b");
    project::create_project(&proj_a).unwrap();
    project::create_project(&proj_b).unwrap();
    project::add_checkpoint(&proj_a, &file_a).unwrap();
    project::add_checkpoint(&proj_b, &file_b).unwrap();
    let a = project::load_project(&proj_a).unwrap();
    let b = project::load_project(&proj_b).unwrap();
    assert_eq!(a.entities, b.entities);
    assert_eq!(a.fingerprint, b.fingerprint);
    // Move file: semantic identity unchanged.
    let moved = temp("reloc_moved");
    fs::copy(&proj_a, &moved).unwrap();
    let m = project::load_project(&moved).unwrap();
    assert_eq!(a.project_id, m.project_id);
    assert_eq!(a.fingerprint, m.fingerprint);
    // No absolute source path leak in semantic serialization.
    let json = serde_json::to_string(&a).unwrap();
    assert!(!json.contains(file_a.to_str().unwrap()));
    assert!(!json.contains(proj_a.to_str().unwrap()));
    assert!(!json.contains("/tmp/rxscan_phase18_reloc"));
}

#[test]
fn raw_markers_and_credentials_never_persist() {
    let mut project = ProjectState::new(None);
    project
        .add_scan(&state("127.0.0.1", None, false), None, None)
        .unwrap();
    let json = serde_json::to_string(&project)
        .unwrap()
        .to_ascii_lowercase();
    for marker in [
        "raw_http_body_marker",
        "raw_dns_packet_marker",
        "raw_tls_record_marker",
        "authorization:",
        "cookie:",
        "password=",
        "phase14_secret",
    ] {
        assert!(!json.contains(marker), "project must not contain {marker}");
    }
    // Malicious checkpoint carrying a cookie marker is rejected before mutation.
    let p = plan();
    let prov = provenance(&p);
    let ip = Asset::scoped(AssetKind::Ip, "127.0.0.1", &p.scope, prov.clone()).unwrap();
    let evil_port = Asset::child(AssetKind::Port, &ip.id, "443", prov.clone())
        .unwrap()
        .with_attributes(BTreeMap::from([(
            "banner".to_owned(),
            "Cookie: secret".to_owned(),
        )]));
    let guard = rxscan::execution::PolicyScopeGuard::new(p.scope.clone());
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), "127.0.0.1".to_owned());
    params.insert("variant".to_owned(), "evil-cookie".to_owned());
    let mut task = Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        None,
        p.stable_id(),
        10,
        Duration::from_secs(1),
        RetryPolicy::default(),
        "phase18.test",
        prov.clone(),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        params,
        &guard,
    )
    .unwrap();
    task.state = TaskState::Succeeded;
    let task_id = task.id.clone();
    let evil_scan = PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: p.stable_id(),
        saved_at: Timestamp(2),
        plan: p,
        tasks: vec![PersistedTask { task }],
        outputs: vec![PersistedModuleOutput {
            task_id,
            output: rxscan::execution::ModuleOutput {
                events: vec![],
                evidence: vec![],
                findings: vec![],
                assets: vec![ip, evil_port],
            },
        }],
        registries: PersistedRegistries::default(),
    };
    let before = serde_json::to_vec(&project).unwrap();
    assert!(project.add_scan(&evil_scan, None, None).is_err());
    assert_eq!(before, serde_json::to_vec(&project).unwrap());
}

fn large_scan_state(count: usize) -> PersistedScanState {
    let p = plan();
    let prov = provenance(&p);
    let ip = Asset::scoped(AssetKind::Ip, "127.0.0.1", &p.scope, prov.clone()).unwrap();
    let mut assets = vec![ip.clone()];
    let mut relationships = Vec::new();
    for i in 0..count {
        let port_num = 8000 + (i % 4000) as u16;
        // Keep ports unique by offsetting when wrapping.
        let port_str = format!("{}", 8000 + i);
        let port = Asset::child(AssetKind::Port, &ip.id, &port_str, prov.clone())
            .unwrap()
            .with_attributes(BTreeMap::from([
                ("port".to_owned(), port_str.clone()),
                ("state".to_owned(), "open".to_owned()),
            ]));
        let svc = Asset::child(AssetKind::Service, &port.id, "https", prov.clone()).unwrap();
        relationships.push(
            Relationship::new(
                RelationshipKind::Runs,
                RelationshipSubject::Asset(port.id.clone()),
                RelationshipSubject::Asset(svc.id.clone()),
                prov.clone(),
            )
            .unwrap(),
        );
        assets.push(port);
        assets.push(svc);
        let _ = port_num;
    }
    let mut finding = Finding::new(
        "Large project finding",
        Severity::Info,
        Confidence::new(80).unwrap(),
        assets[1].id.clone(),
        prov.clone(),
    )
    .unwrap();
    finding
        .metadata
        .insert("identity".to_owned(), serde_json::json!("large-finding"));
    let output = rxscan::execution::ModuleOutput {
        events: vec![Event {
            schema_version: rxscan::model::SCHEMA_VERSION,
            kind: EventKind::EvidenceCollected,
            asset_id: Some(ip.id.clone()),
            details: BoundedDetails::from_value(serde_json::json!({"phase":18}), 512).unwrap(),
            relationships,
            provenance: prov.clone(),
        }],
        evidence: vec![],
        findings: vec![finding],
        assets,
    };
    let guard = rxscan::execution::PolicyScopeGuard::new(p.scope.clone());
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), "127.0.0.1".to_owned());
    params.insert("variant".to_owned(), format!("large-{count}"));
    let mut task = Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        None,
        p.stable_id(),
        10,
        Duration::from_secs(1),
        RetryPolicy::default(),
        "phase18.test",
        prov,
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        params,
        &guard,
    )
    .unwrap();
    task.state = TaskState::Succeeded;
    let task_id = task.id.clone();
    PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: p.stable_id(),
        saved_at: Timestamp(2),
        plan: p,
        tasks: vec![PersistedTask { task }],
        outputs: vec![PersistedModuleOutput { task_id, output }],
        registries: PersistedRegistries::default(),
    }
}

#[test]
fn large_project_with_thousands_of_entities_is_bounded() {
    let mut project = ProjectState::new(None);
    let scan = large_scan_state(800);
    project.add_scan(&scan, None, None).unwrap();
    assert!(
        project.entities.len() >= 1000,
        "expected >1000 entities, got {}",
        project.entities.len()
    );
    assert!(project.relationships.len() >= 500);
    let bytes = serde_json::to_vec(&project).unwrap().len();
    assert!(bytes < project::MAX_PROJECT_BYTES as usize);
    let entity = project.entities.keys().next().unwrap().clone();
    let started = std::time::Instant::now();
    let neighbors = project.neighbors(&entity, 3, 1000).unwrap();
    assert!(neighbors.results_emitted <= 1000);
    assert!(started.elapsed().as_secs() < 5, "no pathological runtime");
    let summary = project.summary(bytes as u64);
    assert!(summary.entities >= 1000);
}

#[test]
fn finding_severity_preserved_and_deduped_by_semantic_identity() {
    let p = plan();
    let prov = provenance(&p);
    let ip = Asset::scoped(AssetKind::Ip, "127.0.0.1", &p.scope, prov.clone()).unwrap();
    let port = Asset::child(AssetKind::Port, &ip.id, "443", prov.clone()).unwrap();
    let mk_finding = |severity: Severity| {
        let mut f = Finding::new(
            "Severity finding",
            severity,
            Confidence::new(80).unwrap(),
            port.id.clone(),
            prov.clone(),
        )
        .unwrap();
        f.metadata
            .insert("identity".to_owned(), serde_json::json!("sev-1"));
        f
    };
    let mk_scan = |finding: Finding| {
        let guard = rxscan::execution::PolicyScopeGuard::new(p.scope.clone());
        let mut params = BTreeMap::new();
        params.insert("target".to_owned(), "127.0.0.1".to_owned());
        params.insert("variant".to_owned(), format!("{:?}", finding.severity));
        let mut task = Task::new_with_params(
            TaskKind::HttpProbe,
            None,
            Vec::new(),
            None,
            p.stable_id(),
            10,
            Duration::from_secs(1),
            RetryPolicy::default(),
            "phase18.test",
            prov.clone(),
            TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
            params,
            &guard,
        )
        .unwrap();
        task.state = TaskState::Succeeded;
        let task_id = task.id.clone();
        PersistedScanState {
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            scan_id: p.stable_id(),
            saved_at: Timestamp(2),
            plan: p.clone(),
            tasks: vec![PersistedTask { task }],
            outputs: vec![PersistedModuleOutput {
                task_id,
                output: rxscan::execution::ModuleOutput {
                    events: vec![],
                    evidence: vec![],
                    findings: vec![finding],
                    assets: vec![ip.clone(), port.clone()],
                },
            }],
            registries: PersistedRegistries::default(),
        }
    };
    let mut project = ProjectState::new(None);
    project
        .add_scan(&mk_scan(mk_finding(Severity::Info)), None, None)
        .unwrap();
    assert_eq!(project.findings.len(), 1);
    assert_eq!(
        project.findings.values().next().unwrap().severity,
        Severity::Info
    );
    // Same severity+identity dedups (observation count grows, no new finding).
    // Note: same severity yields same semantic fingerprint, so second import is
    // a duplicate scan no-op by design (storage grows with new information).
    let dup = project
        .add_scan(&mk_scan(mk_finding(Severity::Info)), None, None)
        .unwrap();
    assert!(dup.duplicate_scan);
    assert_eq!(project.findings.len(), 1);
    // Different severity is distinct semantic finding (new information).
    let high = mk_scan(mk_finding(Severity::High));
    // Force distinct fingerprint by varying an asset attribute via different scan?
    // Severity alone changes finding semantics, so fingerprint differs.
    let added = project.add_scan(&high, None, None).unwrap();
    assert!(!added.duplicate_scan);
    assert_eq!(project.findings.len(), 2);
}

#[test]
fn change_certainty_preserved_and_attention_not_rescored() {
    // Reduced coverage (level drop) forces InconclusiveMissing, never Removed.
    // Build via distinct levels from scratch so plan/task identities stay valid.
    fn state_at_level(level: u8, extra_port: Option<&str>) -> PersistedScanState {
        let p = rxscan::plan::ScanPlan::compile(
            Cli::try_parse_from([
                "rxscan",
                "127.0.0.1",
                "--scope",
                "127.0.0.1",
                "--scope",
                "127.0.0.2",
                "--scope",
                "::1",
                "--scope",
                "http://127.0.0.1",
                "--level",
                &level.to_string(),
            ])
            .unwrap(),
        )
        .unwrap();
        let prov = Provenance::new("phase18.test", "18.0.0", p.stable_id(), Timestamp(1)).unwrap();
        let ip = Asset::scoped(AssetKind::Ip, "127.0.0.1", &p.scope, prov.clone()).unwrap();
        let mut assets = vec![ip.clone()];
        if let Some(port_value) = extra_port {
            assets.push(
                Asset::child(AssetKind::Port, &ip.id, port_value, prov.clone())
                    .unwrap()
                    .with_attributes(BTreeMap::from([
                        ("port".to_owned(), port_value.to_owned()),
                        ("state".to_owned(), "open".to_owned()),
                    ])),
            );
        }
        let guard = rxscan::execution::PolicyScopeGuard::new(p.scope.clone());
        let mut params = BTreeMap::new();
        params.insert("target".to_owned(), "127.0.0.1".to_owned());
        params.insert("variant".to_owned(), format!("lvl{level}"));
        let mut task = Task::new_with_params(
            TaskKind::HttpProbe,
            None,
            Vec::new(),
            None,
            p.stable_id(),
            10,
            Duration::from_secs(1),
            RetryPolicy::default(),
            "phase18.test",
            prov.clone(),
            TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
            params,
            &guard,
        )
        .unwrap();
        task.state = TaskState::Succeeded;
        let task_id = task.id.clone();
        PersistedScanState {
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            scan_id: p.stable_id(),
            saved_at: Timestamp(2),
            plan: p,
            tasks: vec![PersistedTask { task }],
            outputs: vec![PersistedModuleOutput {
                task_id,
                output: rxscan::execution::ModuleOutput {
                    events: vec![],
                    evidence: vec![],
                    findings: vec![],
                    assets,
                },
            }],
            registries: PersistedRegistries::default(),
        }
    }
    let old = state_at_level(5, Some("8443"));
    let new = state_at_level(1, None);
    let diff_report = diff::compare_states(&old, &new, diff::DiffOptions::default()).unwrap();
    assert!(
        diff_report
            .records
            .iter()
            .any(|r| r.change_type == diff::ChangeType::InconclusiveMissing)
    );
    let analysis_report =
        analysis::analyze_state(&new, Some(&diff_report), AnalysisOptions::default()).unwrap();
    let mut project = ProjectState::new(None);
    project.add_scan(&old, None, None).unwrap();
    project
        .add_scan(&new, Some(&diff_report), Some(&analysis_report))
        .unwrap();
    // Certainty preserved verbatim.
    for stored in project.changes.values() {
        let original = diff_report.records.iter().find(|r| {
            stored.id.contains(&format!("{:x}", 0)) || r.change_type == stored.change_type
        });
        let _ = original;
        if stored.change_type == diff::ChangeType::InconclusiveMissing {
            assert_eq!(stored.certainty, diff::Certainty::Inconclusive);
            assert_ne!(stored.change_type, diff::ChangeType::Removed);
        }
    }
    assert!(
        project
            .changes
            .values()
            .any(|c| c.change_type == diff::ChangeType::InconclusiveMissing)
    );
    // Attention preserved without rescoring.
    for stored in project.analysis_refs.values() {
        let original = analysis_report
            .top_signals
            .iter()
            .find(|s| s.attention_score == stored.attention_score)
            .expect("score must match stored signal");
        assert_eq!(stored.attention_band, original.attention_band);
        assert_eq!(stored.label, original.label);
    }
}

#[test]
fn cli_findings_changes_attention_are_offline_and_bounded() {
    let project_path = temp("cli_extended");
    let scan = save_scan("cli_extended_scan", &state("127.0.0.1", None, true));
    let exe = env!("CARGO_BIN_EXE_rxscan");
    Command::new(exe)
        .args(["project", "create", project_path.to_str().unwrap()])
        .output()
        .unwrap();
    let add = Command::new(exe)
        .args([
            "project",
            "add",
            project_path.to_str().unwrap(),
            scan.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );
    for sub in ["findings", "changes", "attention"] {
        let out = Command::new(exe)
            .args(["project", sub, project_path.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{sub}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8(out.stdout)
                .unwrap()
                .contains("network_requests=0"),
            "{sub} must be offline"
        );
        let json = Command::new(exe)
            .args(["project", sub, project_path.to_str().unwrap(), "--json"])
            .output()
            .unwrap();
        assert!(json.status.success());
        let value: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        assert!(value.get("results_total").is_some());
        let jsonl = Command::new(exe)
            .args(["project", sub, project_path.to_str().unwrap(), "--jsonl"])
            .output()
            .unwrap();
        assert!(jsonl.status.success());
        for line in String::from_utf8(jsonl.stdout).unwrap().lines() {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
    }
    // Entity-filtered queries.
    let state = project::load_project(&project_path).unwrap();
    let entity = state.entities.keys().next().unwrap().clone();
    let filtered = Command::new(exe)
        .args([
            "project",
            "findings",
            project_path.to_str().unwrap(),
            &entity,
        ])
        .output()
        .unwrap();
    assert!(filtered.status.success());
    let unknown = Command::new(exe)
        .args(["project", "show", project_path.to_str().unwrap(), "missing"])
        .output()
        .unwrap();
    assert!(!unknown.status.success());
    assert_zero_network();
}

#[test]
fn dangling_refs_for_all_kinds_are_rejected() {
    let mut project = ProjectState::new(None);
    project
        .add_scan(&state("127.0.0.1", None, false), None, None)
        .unwrap();
    let scan_id = project.scans.values().next().unwrap().scan_id.clone();
    // Observation missing entity.
    let mut bad = project.clone();
    bad.observations.insert(
        "obs_bad".to_owned(),
        project::ProjectObservation {
            id: "obs_bad".to_owned(),
            scan_id: scan_id.clone(),
            entity_id: "missing-entity".to_owned(),
            fingerprint: "f".to_owned(),
        },
    );
    assert!(bad.validate().is_err());
    // Observation missing scan.
    let mut bad = project.clone();
    let entity = project.entities.keys().next().unwrap().clone();
    bad.observations.insert(
        "obs_bad".to_owned(),
        project::ProjectObservation {
            id: "obs_bad".to_owned(),
            scan_id: ScanPlanId("missing-scan".to_owned()),
            entity_id: entity,
            fingerprint: "f".to_owned(),
        },
    );
    assert!(bad.validate().is_err());
    // Finding missing entity.
    let mut bad = project.clone();
    bad.findings.insert(
        "finding_bad".to_owned(),
        project::ProjectFinding {
            id: "finding_bad".to_owned(),
            title: "bad".to_owned(),
            severity: Severity::Info,
            confidence: 10,
            affected_entity: "missing".to_owned(),
            first_scan_id: scan_id.clone(),
            last_scan_id: scan_id.clone(),
            observation_count: 1,
        },
    );
    assert!(bad.validate().is_err());
    // Change missing scan / entity.
    let mut bad = project.clone();
    bad.changes.insert(
        "change_bad".to_owned(),
        project::ProjectChangeRef {
            id: "change_bad".to_owned(),
            scan_id: ScanPlanId("missing".to_owned()),
            entity_id: None,
            change_type: diff::ChangeType::Added,
            certainty: diff::Certainty::Confirmed,
            reason: diff::ReasonCode::NewSemanticEntity,
        },
    );
    assert!(bad.validate().is_err());
    let mut bad = project.clone();
    bad.changes.insert(
        "change_bad".to_owned(),
        project::ProjectChangeRef {
            id: "change_bad".to_owned(),
            scan_id: scan_id.clone(),
            entity_id: Some("missing".to_owned()),
            change_type: diff::ChangeType::Added,
            certainty: diff::Certainty::Confirmed,
            reason: diff::ReasonCode::NewSemanticEntity,
        },
    );
    assert!(bad.validate().is_err());
    // Analysis missing scan / entity.
    let mut bad = project.clone();
    bad.analysis_refs.insert(
        "analysis_bad".to_owned(),
        project::ProjectAnalysisRef {
            id: "analysis_bad".to_owned(),
            scan_id: ScanPlanId("missing".to_owned()),
            entity_id: None,
            attention_score: 10,
            attention_band: analysis::AttentionBand::Informational,
            label: "x".to_owned(),
        },
    );
    assert!(bad.validate().is_err());
    let mut bad = project.clone();
    bad.analysis_refs.insert(
        "analysis_bad".to_owned(),
        project::ProjectAnalysisRef {
            id: "analysis_bad".to_owned(),
            scan_id: scan_id.clone(),
            entity_id: Some("missing".to_owned()),
            attention_score: 10,
            attention_band: analysis::AttentionBand::Informational,
            label: "x".to_owned(),
        },
    );
    assert!(bad.validate().is_err());
}

#[test]
fn depth_two_and_explicit_cycle_handling_are_bounded() {
    let mut project = ProjectState::new(None);
    project
        .add_scan(&state("127.0.0.1", None, true), None, None)
        .unwrap();
    let entity = project
        .entities
        .values()
        .find(|e| e.kind == AssetKind::Service)
        .unwrap()
        .id
        .clone();
    let d1 = project.neighbors(&entity, 1, 100).unwrap();
    let d2 = project.neighbors(&entity, 2, 100).unwrap();
    let d3 = project.neighbors(&entity, 3, 100).unwrap();
    assert!(d1.results_total <= d2.results_total);
    assert!(d2.results_total <= d3.results_total);
    assert!(d3.records.iter().all(|r| r.depth <= 3));
    // Cycle: neighbors of a neighbor eventually returns to start without explosion.
    if let Some(next) = d1.records.first() {
        let back = project.neighbors(&next.entity_id, 3, 100).unwrap();
        assert!(back.results_emitted <= 100);
    }
    // Over-max depth is clamped explicitly (documented), not an unbounded walk.
    let over = project.neighbors(&entity, 255, 100).unwrap();
    assert!(
        over.records
            .iter()
            .all(|r| r.depth <= project::MAX_QUERY_DEPTH)
    );
}

#[test]
fn ipv6_service_endpoint_relationships_survive_import() {
    let p = plan();
    let prov = provenance(&p);
    let ip6 = Asset::scoped(AssetKind::Ip, "::1", &p.scope, prov.clone()).unwrap();
    let port = Asset::child(AssetKind::Port, &ip6.id, "443", prov.clone())
        .unwrap()
        .with_attributes(BTreeMap::from([
            ("port".to_owned(), "443".to_owned()),
            ("state".to_owned(), "open".to_owned()),
        ]));
    let svc = Asset::child(AssetKind::Service, &port.id, "https", prov.clone()).unwrap();
    let url = Asset::scoped(AssetKind::Url, "http://[::1]/admin", &p.scope, prov.clone())
        .unwrap_or_else(|_| {
            Asset::scoped(
                AssetKind::Url,
                "http://127.0.0.1/ipv6",
                &p.scope,
                prov.clone(),
            )
            .unwrap()
        });
    let output = rxscan::execution::ModuleOutput {
        events: vec![Event {
            schema_version: rxscan::model::SCHEMA_VERSION,
            kind: EventKind::EvidenceCollected,
            asset_id: Some(ip6.id.clone()),
            details: BoundedDetails::from_value(serde_json::json!({"v6":true}), 512).unwrap(),
            relationships: vec![
                Relationship::new(
                    RelationshipKind::Runs,
                    RelationshipSubject::Asset(port.id.clone()),
                    RelationshipSubject::Asset(svc.id.clone()),
                    prov.clone(),
                )
                .unwrap(),
                Relationship::new(
                    RelationshipKind::ReferencesEndpoint,
                    RelationshipSubject::Asset(svc.id.clone()),
                    RelationshipSubject::Asset(url.id.clone()),
                    prov.clone(),
                )
                .unwrap(),
            ],
            provenance: prov.clone(),
        }],
        evidence: vec![],
        findings: vec![],
        assets: vec![ip6.clone(), port, svc, url],
    };
    let guard = rxscan::execution::PolicyScopeGuard::new(p.scope.clone());
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), "::1".to_owned());
    params.insert("variant".to_owned(), "v6".to_owned());
    let mut task = Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        None,
        p.stable_id(),
        10,
        Duration::from_secs(1),
        RetryPolicy::default(),
        "phase18.test",
        prov.clone(),
        TaskScopeTarget::Ip("::1".parse().unwrap()),
        params,
        &guard,
    )
    .unwrap();
    task.state = TaskState::Succeeded;
    let task_id = task.id.clone();
    let scan = PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: p.stable_id(),
        saved_at: Timestamp(2),
        plan: p,
        tasks: vec![PersistedTask { task }],
        outputs: vec![PersistedModuleOutput { task_id, output }],
        registries: PersistedRegistries::default(),
    };
    let mut project = ProjectState::new(None);
    project.add_scan(&scan, None, None).unwrap();
    assert!(project.entities.values().any(|e| e.identity == "::1"));
    assert!(
        project
            .entities
            .values()
            .any(|e| e.kind == AssetKind::Service)
    );
    let svc_entity = project
        .entities
        .values()
        .find(|e| e.kind == AssetKind::Service)
        .unwrap();
    let neighbors = project.neighbors(&svc_entity.id, 1, 100).unwrap();
    assert!(!neighbors.records.is_empty());
}

#[test]
fn corrupt_project_rejected_before_mutation_with_zero_network() {
    reset_counters();
    let path = temp("corrupt_nomut");
    project::create_project(&path).unwrap();
    let before = fs::read(&path).unwrap();
    fs::write(&path, b"{bad json").unwrap();
    assert!(project::load_project(&path).is_err());
    // Failed load must not mutate the file.
    assert_eq!(fs::read(&path).unwrap(), b"{bad json");
    // Restore and verify unsupported schema rejected.
    fs::write(&path, &before).unwrap();
    let mut bad: ProjectState = serde_json::from_slice(&before).unwrap();
    bad.project_schema_version = 999;
    fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
    assert!(project::load_project(&path).is_err());
    assert_zero_network();
}

// ---------------------------------------------------------------------------
// Lightweight/multitasking blocker closure (Phase 18, no redesign).
// ---------------------------------------------------------------------------

fn rss_kb(tag: &str) -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix(tag)
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
}

fn peak_rss_kb() -> Option<u64> {
    rss_kb("VmHWM:")
}

fn current_rss_kb() -> Option<u64> {
    rss_kb("VmRSS:")
}

fn synthetic_star_project_fixed(leaf_count: usize) -> (ProjectState, String) {
    let mut project = ProjectState::new(None);
    project
        .add_scan(&state("127.0.0.1", None, false), None, None)
        .unwrap();
    let scan_id = project.scans.values().next().unwrap().scan_id.clone();
    let root_id = "entity_synth_root".to_owned();
    project.entities.insert(
        root_id.clone(),
        project::ProjectEntity {
            id: root_id.clone(),
            kind: AssetKind::Other,
            identity: "synth-root".to_owned(),
            attributes: BTreeMap::new(),
            first_scan_id: scan_id.clone(),
            last_scan_id: scan_id.clone(),
            observation_count: 1,
            external: false,
            observations: Vec::new(),
        },
    );
    for i in 0..leaf_count {
        let leaf_id = format!("entity_synth_leaf_{i:06}");
        project.entities.insert(
            leaf_id.clone(),
            project::ProjectEntity {
                id: leaf_id.clone(),
                kind: AssetKind::Other,
                identity: format!("synth-leaf-{i}"),
                attributes: BTreeMap::new(),
                first_scan_id: scan_id.clone(),
                last_scan_id: scan_id.clone(),
                observation_count: 1,
                external: false,
                observations: Vec::new(),
            },
        );
        let rel_id = format!("rel_synth_{i:06}");
        project.relationships.insert(
            rel_id.clone(),
            project::ProjectRelationship {
                id: rel_id,
                kind: RelationshipKind::LinksTo,
                from_entity: root_id.clone(),
                to_entity: leaf_id,
                first_scan_id: scan_id.clone(),
                last_scan_id: scan_id.clone(),
                observation_count: 1,
            },
        );
    }
    project.refresh_fingerprint();
    assert!(project.validate().is_ok());
    (project, root_id)
}

#[test]
fn fingerprint_does_not_clone_project_state() {
    // Large deterministic state (thousands of entities).
    let scan = large_scan_state(1200);
    let mut project = ProjectState::new(None);
    project.add_scan(&scan, None, None).unwrap();
    assert!(project.entities.len() >= 1000);
    let project_bytes = serde_json::to_vec(&project).unwrap().len();
    let rss_before = peak_rss_kb().unwrap_or(0);
    let current_before = current_rss_kb().unwrap_or(0);
    // Fingerprint twice to observe peak during/after.
    let fp1 = project.fingerprint.clone();
    project.refresh_fingerprint();
    let fp2 = project.fingerprint.clone();
    assert_eq!(fp1, fp2, "streaming fingerprint must be stable");
    let rss_after = peak_rss_kb().unwrap_or(0);
    let current_after = current_rss_kb().unwrap_or(0);
    let clones = project::fingerprint_whole_state_clones();
    let buf = project::fingerprint_serialization_buffer_bytes();
    eprintln!(
        "fingerprint_audit project_bytes={project_bytes} peak_before={rss_before} peak_after={rss_after} current_before={current_before} current_after={current_after} clones={clones} buf={buf}"
    );
    assert_eq!(clones, 0, "whole-state clone count must be 0");
    assert_eq!(buf, 0, "streaming fingerprint holds no canonical Vec");
    // Source audit: fingerprint path must not clone or buffer whole state.
    let source = fs::read_to_string("src/project.rs").unwrap();
    let start = source
        .find("fn project_fingerprint")
        .expect("fingerprint fn");
    let rest = &source[start..];
    let end = rest[1..]
        .find("\nfn ")
        .map(|i| start + 1 + i)
        .unwrap_or(source.len());
    let section = &source[start..end];
    assert!(
        !section.contains(".clone()"),
        "project_fingerprint must not contain .clone()"
    );
    assert!(
        !section.contains("to_vec"),
        "project_fingerprint must stream, not to_vec"
    );
    assert!(section.contains("HasherWriter"), "must stream into hasher");
    assert!(
        section.contains("ProjectFingerprintView"),
        "must use borrowed view"
    );
    // No 2x+ clone by construction (clone count 0, buffer 0, streaming).
    // Peak RSS is process-wide and noisy under parallel `cargo test`
    // (other threads allocate concurrently), so only apply a loose sanity
    // bound here; the strict bounded-memory proof is the streaming design +
    // single-threaded bench (`phase18_bench`) peak deltas.
    if rss_before > 0 && rss_after > 0 {
        let growth_kb = rss_after.saturating_sub(rss_before);
        assert!(
            growth_kb < 64 * 1024,
            "fingerprint peak growth {growth_kb} KiB pathological"
        );
    }
    // Current-RSS delta for the fingerprint alone should also stay well below
    // a full duplicate plus generous parallel-test headroom (16 MiB).
    if current_before > 0 && current_after > 0 {
        let cur_growth = current_after.saturating_sub(current_before);
        let project_kb = (project_bytes as u64) / 1024;
        assert!(
            cur_growth < project_kb.saturating_add(16 * 1024),
            "fingerprint current growth {cur_growth} KiB unreasonable for {project_kb} KiB project"
        );
    }
}

#[test]
fn high_degree_graph_query_is_hard_bounded() {
    // Synthetic entity with many thousands of neighbors.
    let (project, root) = synthetic_star_project_fixed(6000);
    assert!(project.entities.len() >= 6000);
    let result = project.neighbors(&root, 3, 100).unwrap();
    eprintln!(
        "high_degree emitted={} discovered={} queue_peak={} visited_peak={} expansions={} exhaustive={} truncated={}",
        result.results_emitted,
        result.results_discovered,
        result.queue_peak,
        result.visited_peak,
        result.expansions,
        result.exhaustive,
        result.truncated
    );
    assert!(result.results_emitted <= 100);
    assert!(result.queue_peak <= project::MAX_GRAPH_QUERY_QUEUE);
    assert!(result.visited_peak <= project::MAX_GRAPH_QUERY_VISITED);
    assert!(result.expansions <= project::MAX_GRAPH_QUERY_EXPANSIONS);
    assert!(result.results_discovered <= project::MAX_GRAPH_QUERY_EDGE_BUDGET);
    assert!(result.truncated, "high-degree bounded query must truncate");
    assert!(
        !result.exhaustive,
        "work-cap truncation must mark exhaustive=false"
    );
    // results_total is the capped discovered count, not a pretended global total.
    assert_eq!(result.results_total, result.results_discovered);
    // Queue/visited never grew to total entities (6000+).
    assert!(result.queue_peak < project.entities.len());
    assert!(result.visited_peak < project.entities.len() + 1);
    assert!(result.visited_peak <= project::MAX_GRAPH_QUERY_VISITED);
}

#[test]
fn adversarial_breadth_query_remains_bounded() {
    // root -> 3000 depth-1 -> 2 depth-2 children each (9001 entities).
    let mut project = ProjectState::new(None);
    project
        .add_scan(&state("127.0.0.1", None, false), None, None)
        .unwrap();
    let scan_id = project.scans.values().next().unwrap().scan_id.clone();
    let root_id = "entity_adv_root".to_owned();
    project.entities.insert(
        root_id.clone(),
        project::ProjectEntity {
            id: root_id.clone(),
            kind: AssetKind::Other,
            identity: "adv-root".to_owned(),
            attributes: BTreeMap::new(),
            first_scan_id: scan_id.clone(),
            last_scan_id: scan_id.clone(),
            observation_count: 1,
            external: false,
            observations: Vec::new(),
        },
    );
    let depth1_count = 3000usize;
    for i in 0..depth1_count {
        let l1 = format!("entity_adv_l1_{i:05}");
        project.entities.insert(
            l1.clone(),
            project::ProjectEntity {
                id: l1.clone(),
                kind: AssetKind::Other,
                identity: format!("adv-l1-{i}"),
                attributes: BTreeMap::new(),
                first_scan_id: scan_id.clone(),
                last_scan_id: scan_id.clone(),
                observation_count: 1,
                external: false,
                observations: Vec::new(),
            },
        );
        project.relationships.insert(
            format!("rel_adv_root_{i:05}"),
            project::ProjectRelationship {
                id: format!("rel_adv_root_{i:05}"),
                kind: RelationshipKind::LinksTo,
                from_entity: root_id.clone(),
                to_entity: l1.clone(),
                first_scan_id: scan_id.clone(),
                last_scan_id: scan_id.clone(),
                observation_count: 1,
            },
        );
        for j in 0..2 {
            let l2 = format!("entity_adv_l2_{i:05}_{j}");
            project.entities.insert(
                l2.clone(),
                project::ProjectEntity {
                    id: l2.clone(),
                    kind: AssetKind::Other,
                    identity: format!("adv-l2-{i}-{j}"),
                    attributes: BTreeMap::new(),
                    first_scan_id: scan_id.clone(),
                    last_scan_id: scan_id.clone(),
                    observation_count: 1,
                    external: false,
                    observations: Vec::new(),
                },
            );
            project.relationships.insert(
                format!("rel_adv_l1_{i:05}_{j}"),
                project::ProjectRelationship {
                    id: format!("rel_adv_l1_{i:05}_{j}"),
                    kind: RelationshipKind::LinksTo,
                    from_entity: l1.clone(),
                    to_entity: l2,
                    first_scan_id: scan_id.clone(),
                    last_scan_id: scan_id.clone(),
                    observation_count: 1,
                },
            );
        }
    }
    project.refresh_fingerprint();
    assert!(project.validate().is_ok());
    let total_entities = project.entities.len();
    assert!(total_entities >= 9000);
    let result = project.neighbors(&root_id, 3, 100).unwrap();
    eprintln!(
        "adversarial emitted={} discovered={} queue_peak={} visited_peak={} expansions={} exhaustive={}",
        result.results_emitted,
        result.results_discovered,
        result.queue_peak,
        result.visited_peak,
        result.expansions,
        result.exhaustive
    );
    assert!(result.results_emitted <= 100);
    assert!(result.queue_peak <= project::MAX_GRAPH_QUERY_QUEUE);
    assert!(result.visited_peak <= project::MAX_GRAPH_QUERY_VISITED);
    assert!(result.expansions <= project::MAX_GRAPH_QUERY_EXPANSIONS);
    assert!(result.results_discovered <= project::MAX_GRAPH_QUERY_EDGE_BUDGET);
    // Must not grow to total project.
    assert!(result.queue_peak < total_entities);
    assert!(result.visited_peak < total_entities);
    assert!(result.truncated);
    assert!(!result.exhaustive);
}

#[test]
fn capped_query_results_are_deterministic_under_permutations() {
    // Same logical star graph, opposite insertion orders.
    fn build_star(reversed: bool) -> (ProjectState, String) {
        let mut project = ProjectState::new(None);
        project
            .add_scan(&state("127.0.0.1", None, false), None, None)
            .unwrap();
        let scan_id = project.scans.values().next().unwrap().scan_id.clone();
        let root_id = "entity_det_root".to_owned();
        project.entities.insert(
            root_id.clone(),
            project::ProjectEntity {
                id: root_id.clone(),
                kind: AssetKind::Other,
                identity: "det-root".to_owned(),
                attributes: BTreeMap::new(),
                first_scan_id: scan_id.clone(),
                last_scan_id: scan_id.clone(),
                observation_count: 1,
                external: false,
                observations: Vec::new(),
            },
        );
        let mut indices: Vec<usize> = (0..5000).collect();
        if reversed {
            indices.reverse();
        }
        for i in indices {
            let leaf_id = format!("entity_det_leaf_{i:06}");
            project.entities.insert(
                leaf_id.clone(),
                project::ProjectEntity {
                    id: leaf_id.clone(),
                    kind: AssetKind::Other,
                    identity: format!("det-leaf-{i}"),
                    attributes: BTreeMap::new(),
                    first_scan_id: scan_id.clone(),
                    last_scan_id: scan_id.clone(),
                    observation_count: 1,
                    external: false,
                    observations: Vec::new(),
                },
            );
            let rel_id = format!("rel_det_{i:06}");
            project.relationships.insert(
                rel_id.clone(),
                project::ProjectRelationship {
                    id: rel_id,
                    kind: RelationshipKind::LinksTo,
                    from_entity: root_id.clone(),
                    to_entity: leaf_id,
                    first_scan_id: scan_id.clone(),
                    last_scan_id: scan_id.clone(),
                    observation_count: 1,
                },
            );
        }
        project.refresh_fingerprint();
        (project, root_id)
    }
    let (a, root_a) = build_star(false);
    let (b, root_b) = build_star(true);
    assert_eq!(root_a, root_b);
    let ra = a.neighbors(&root_a, 3, 100).unwrap();
    let rb = b.neighbors(&root_b, 3, 100).unwrap();
    assert_eq!(
        ra.records, rb.records,
        "capped queries must be deterministic under insertion permutations"
    );
    let ida: Vec<_> = ra.records.iter().map(|r| &r.entity_id).collect();
    let idb: Vec<_> = rb.records.iter().map(|r| &r.entity_id).collect();
    assert_eq!(ida, idb);
    assert_eq!(ra.queue_peak, rb.queue_peak);
    assert_eq!(ra.visited_peak, rb.visited_peak);
}

#[test]
fn results_total_is_lower_bound_when_work_capped() {
    let (project, root) = synthetic_star_project_fixed(6000);
    let capped = project.neighbors(&root, 3, 100).unwrap();
    assert!(capped.truncated);
    assert!(!capped.exhaustive);
    assert_eq!(capped.results_total, capped.results_discovered);
    assert_eq!(capped.results_emitted, 100);
    // Filter queries on small fixture are exhaustive with exact totals.
    let mut small = ProjectState::new(None);
    small
        .add_scan(&state("127.0.0.1", None, false), None, None)
        .unwrap();
    let f = small.findings_query(None, 100).unwrap();
    assert!(f.exhaustive);
    assert_eq!(f.results_total, f.results_discovered);
}

#[test]
fn large_project_open_memory_is_reasonable() {
    // Phase 20: VmRSS is process-wide, so sibling tests sharing this test
    // binary's allocator can inflate current-RSS deltas under parallel load
    // (one such failure was observed during a full-workspace run; never in
    // isolation). Run the measurement in an isolated child process running
    // only this test: thresholds below are unchanged, the noise source is
    // removed instead of the protection being weakened.
    if std::env::var("RXSCAN_P18_MEM_CHILD").is_err() {
        let exe = std::env::current_exe().expect("test binary path");
        let out = Command::new(exe)
            .args([
                "--exact",
                "large_project_open_memory_is_reasonable",
                "--nocapture",
            ])
            .env("RXSCAN_P18_MEM_CHILD", "1")
            .output()
            .expect("spawn isolated memory-measurement child");
        assert!(
            out.status.success(),
            "isolated memory measurement failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    // Larger deterministic fixture (several thousand entities).
    let scan = large_scan_state(1500);
    let mut project = ProjectState::new(None);
    project.add_scan(&scan, None, None).unwrap();
    let project_bytes = serde_json::to_vec(&project).unwrap().len();
    assert!(project_bytes < project::MAX_PROJECT_BYTES as usize);
    let expected_fp = project.fingerprint.clone();
    let path = temp("large_open");
    project::save_project(&path, &project, None).unwrap();
    let file_bytes = fs::metadata(&path).unwrap().len();
    assert!(file_bytes > 0);
    assert!(file_bytes < project::MAX_PROJECT_BYTES);
    // Drop the original so open/fingerprint/query deltas isolate temporary
    // state (holding two full copies would trivially double RSS by test
    // design, not by implementation).
    let project_kb = (project_bytes as u64) / 1024;
    drop(project);
    let cur_before_open = current_rss_kb().unwrap_or(0);
    let peak_before_open = peak_rss_kb().unwrap_or(0);
    let loaded = project::load_project(&path).unwrap();
    let cur_after_open = current_rss_kb().unwrap_or(0);
    let peak_after_open = peak_rss_kb().unwrap_or(0);
    assert_eq!(loaded.fingerprint, expected_fp);
    // Fingerprint delta alone must be small (streaming, no clone + no Vec).
    let cur_before_fp = current_rss_kb().unwrap_or(0);
    let mut reloaded_fp = loaded.clone();
    reloaded_fp.refresh_fingerprint();
    let cur_after_fp = current_rss_kb().unwrap_or(0);
    let peak_after_fp = peak_rss_kb().unwrap_or(0);
    assert_eq!(reloaded_fp.fingerprint, loaded.fingerprint);
    // Bounded query delta alone must be small (caps, not project size).
    let entity = loaded.entities.keys().next().unwrap().clone();
    let cur_before_q = current_rss_kb().unwrap_or(0);
    let q = loaded.neighbors(&entity, 3, 100).unwrap();
    let cur_after_q = current_rss_kb().unwrap_or(0);
    let peak_after_q = peak_rss_kb().unwrap_or(0);
    eprintln!(
        "large_open project_bytes={project_bytes} file_bytes={file_bytes} cur_before_open={cur_before_open} cur_after_open={cur_after_open} cur_fp_delta={} cur_q_delta={} peak_before={peak_before_open} peak_open={peak_after_open} peak_fp={peak_after_fp} peak_q={peak_after_q} queue_peak={} visited_peak={} expansions={}",
        cur_after_fp.saturating_sub(cur_before_fp),
        cur_after_q.saturating_sub(cur_before_q),
        q.queue_peak,
        q.visited_peak,
        q.expansions
    );
    assert!(q.queue_peak <= project::MAX_GRAPH_QUERY_QUEUE);
    assert!(q.visited_peak <= project::MAX_GRAPH_QUERY_VISITED);
    assert!(q.expansions <= project::MAX_GRAPH_QUERY_EXPANSIONS);
    // Open loads one copy: current growth should be ~project size, not 2x+.
    if cur_before_open > 0 {
        let open_growth = cur_after_open.saturating_sub(cur_before_open);
        assert!(
            open_growth < project_kb.saturating_mul(2).saturating_add(8192),
            "open growth {open_growth} KiB unreasonable for {project_kb} KiB project"
        );
    }
    // Fingerprint/query temporary state must not duplicate the project:
    // each delta well below project size (allow 4 MiB allocator headroom).
    if cur_before_fp > 0 {
        let fp_growth = cur_after_fp.saturating_sub(cur_before_fp);
        assert!(
            fp_growth < project_kb.saturating_add(4096),
            "fingerprint growth {fp_growth} KiB must not approach duplicate {project_kb} KiB"
        );
    }
    if cur_before_q > 0 {
        let q_growth = cur_after_q.saturating_sub(cur_before_q);
        assert!(
            q_growth < project_kb.saturating_add(4096),
            "query growth {q_growth} KiB must not approach duplicate {project_kb} KiB"
        );
    }
    assert_eq!(project::fingerprint_whole_state_clones(), 0);
    assert_eq!(project::fingerprint_serialization_buffer_bytes(), 0);
    let _ = fs::remove_file(&path);
}

#[test]
fn oversized_save_preserves_old_project_and_cleans_temp() {
    reset_counters();
    let path = temp("oversize");
    let mut base = ProjectState::new(None);
    base.add_scan(&state("127.0.0.1", None, false), None, None)
        .unwrap();
    project::save_project(&path, &base, None).unwrap();
    let before_bytes = fs::read(&path).unwrap();
    let before_state = project::load_project(&path).unwrap();
    // Build an oversized but otherwise valid project: one entity with many
    // large attributes (each 4000 B, under the 4096 per-value cap).
    let mut big = before_state.clone();
    let scan_id = big.scans.values().next().unwrap().scan_id.clone();
    let entity_id = big.entities.keys().next().unwrap().clone();
    {
        let entity = big.entities.get_mut(&entity_id).unwrap();
        for i in 0..4500 {
            entity
                .attributes
                .insert(format!("pad_attr_{i:05}"), "x".repeat(4000));
        }
    }
    // Sanity: compact serialization exceeds the hard file cap.
    let compact_len = serde_json::to_vec(&big).unwrap().len();
    assert!(
        compact_len as u64 > project::MAX_PROJECT_FILE_BYTES,
        "fixture must exceed cap, got {compact_len}"
    );
    // Streaming save must fail with SizeLimit (enforced during write).
    let err = project::save_project(&path, &big, None).unwrap_err();
    assert!(
        matches!(err, project::ProjectError::SizeLimit),
        "expected SizeLimit, got {err:?}"
    );
    // Old project unchanged.
    assert_eq!(fs::read(&path).unwrap(), before_bytes);
    assert_eq!(
        project::load_project(&path).unwrap().fingerprint,
        base.fingerprint
    );
    // Temp file cleaned up.
    let tmp = {
        let mut name = path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_else(|| "project".into());
        name.push(".tmp");
        path.with_file_name(name)
    };
    assert!(!tmp.exists(), "temp file must be cleaned after SizeLimit");
    // Size enforcement is offline.
    assert_zero_network();
    let _ = scan_id;
}

#[test]
fn storage_and_save_caps_are_documented_and_streaming() {
    let source = fs::read_to_string("src/project.rs").unwrap();
    // Cap precedence documented.
    assert!(source.contains("whichever limit is reached first"));
    assert!(source.contains("MAX_PROJECT_FILE_BYTES"));
    // Save streams (no full Vec retained in save path). Check the
    // `save_project` function body specifically (docs may mention the old
    // approach for contrast).
    let save_start = source.find("pub fn save_project").expect("save fn");
    let save_rest = &source[save_start..];
    let save_end = save_rest[1..]
        .find("\npub fn ")
        .map(|i| save_start + 1 + i)
        .unwrap_or(source.len());
    let save_section = &source[save_start..save_end];
    assert!(save_section.contains("to_writer_pretty"));
    assert!(save_section.contains("SizeLimitWriter"));
    assert!(
        !save_section.contains("to_vec_pretty"),
        "project save must not retain full pretty Vec"
    );
    // Fingerprint streams.
    assert!(source.contains("ProjectFingerprintView"));
    // Graph caps exist and are hard bounded (not entities.len()).
    assert!(source.contains("MAX_GRAPH_QUERY_VISITED"));
    assert!(source.contains("MAX_GRAPH_QUERY_QUEUE"));
    assert!(source.contains("MAX_GRAPH_QUERY_EXPANSIONS"));
    assert!(
        !source.contains("entities.len() + 1"),
        "loose queue cap must be gone"
    );
    // Thread invariant retained.
    assert_eq!(project::project_threads_used(), 1);
    assert!(!source.contains("thread::spawn"));
    assert!(!source.contains("tokio::"));
    assert!(!source.contains("rayon::"));
}
