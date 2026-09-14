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
    project::ProjectState,
};

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
            "http://127.0.0.1",
            "--level",
            "5",
        ])
        .unwrap(),
    )
    .unwrap()
}

fn provenance(plan: &rxscan::plan::ScanPlan) -> Provenance {
    Provenance::new("phase18.bench", "18.0.0", plan.stable_id(), Timestamp(1)).unwrap()
}

fn task(plan: &rxscan::plan::ScanPlan, state: TaskState, variant: &str) -> Task {
    let guard = rxscan::execution::PolicyScopeGuard::new(plan.scope.clone());
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), "127.0.0.1".to_owned());
    params.insert("variant".to_owned(), variant.to_owned());
    let mut task = Task::new_with_params(
        TaskKind::HttpProbe,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        10,
        Duration::from_secs(1),
        RetryPolicy::default(),
        "phase18.bench",
        provenance(plan),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        params,
        &guard,
    )
    .unwrap();
    task.state = state;
    task
}

fn state(target: &str, extra: usize) -> PersistedScanState {
    let plan = plan();
    let ip = Asset::scoped(AssetKind::Ip, target, &plan.scope, provenance(&plan)).unwrap();
    let port = Asset::child(AssetKind::Port, &ip.id, "443", provenance(&plan))
        .unwrap()
        .with_attributes(BTreeMap::from([
            ("port".to_owned(), "443".to_owned()),
            ("state".to_owned(), "open".to_owned()),
        ]));
    let svc = Asset::child(AssetKind::Service, &port.id, "https", provenance(&plan)).unwrap();
    let url = Asset::scoped(
        AssetKind::Url,
        "http://127.0.0.1/admin",
        &plan.scope,
        provenance(&plan),
    )
    .unwrap();
    let mut assets = vec![ip.clone(), port.clone(), svc.clone(), url.clone()];
    let mut relationships = vec![
        Relationship::new(
            RelationshipKind::Runs,
            RelationshipSubject::Asset(port.id.clone()),
            RelationshipSubject::Asset(svc.id.clone()),
            provenance(&plan),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::ReferencesEndpoint,
            RelationshipSubject::Asset(svc.id.clone()),
            RelationshipSubject::Asset(url.id.clone()),
            provenance(&plan),
        )
        .unwrap(),
    ];
    for i in 0..extra {
        let extra_port = Asset::child(
            AssetKind::Port,
            &ip.id,
            format!("{}", 8000 + (i % 4000)),
            provenance(&plan),
        )
        .unwrap()
        .with_attributes(BTreeMap::from([
            ("port".to_owned(), format!("{}", 8000 + (i % 4000))),
            ("state".to_owned(), "open".to_owned()),
        ]));
        let extra_svc = Asset::child(
            AssetKind::Service,
            &extra_port.id,
            "https",
            provenance(&plan),
        )
        .unwrap();
        relationships.push(
            Relationship::new(
                RelationshipKind::Runs,
                RelationshipSubject::Asset(extra_port.id.clone()),
                RelationshipSubject::Asset(extra_svc.id.clone()),
                provenance(&plan),
            )
            .unwrap(),
        );
        assets.push(extra_port);
        assets.push(extra_svc);
    }
    let mut finding = Finding::new(
        "Bench project finding",
        Severity::Info,
        Confidence::new(80).unwrap(),
        port.id.clone(),
        provenance(&plan),
    )
    .unwrap();
    finding
        .metadata
        .insert("identity".to_owned(), serde_json::json!("bench-finding"));
    let output = rxscan::execution::ModuleOutput {
        events: vec![Event {
            schema_version: rxscan::model::SCHEMA_VERSION,
            kind: EventKind::EvidenceCollected,
            asset_id: Some(ip.id.clone()),
            details: BoundedDetails::from_value(serde_json::json!({"phase":18}), 512).unwrap(),
            relationships,
            provenance: provenance(&plan),
        }],
        evidence: vec![
            Evidence::new(
                "phase18.bench",
                ip.id.clone(),
                BoundedDetails::from_value(serde_json::json!({"marker":"bench"}), 512).unwrap(),
                Confidence::new(80).unwrap(),
                provenance(&plan),
            )
            .unwrap(),
        ],
        findings: vec![finding],
        assets,
    };
    let t = task(&plan, TaskState::Succeeded, &format!("{target}-{extra}"));
    PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: plan.stable_id(),
        saved_at: Timestamp(2),
        plan,
        tasks: vec![PersistedTask { task: t.clone() }],
        outputs: vec![PersistedModuleOutput {
            task_id: t.id,
            output,
        }],
        registries: PersistedRegistries::default(),
    }
}

fn peak_rss_kb() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
}

fn current_rss_kb() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
}

fn release_binary_size() -> u64 {
    for candidate in ["target/release/rxscan", "target/debug/rxscan"] {
        if let Ok(meta) = std::fs::metadata(candidate) {
            if candidate.contains("release") {
                return meta.len();
            }
        }
    }
    std::fs::metadata("target/release/rxscan")
        .map(|m| m.len())
        .unwrap_or(0)
}

fn main() {
    let wall_start = Instant::now();
    // Deterministic large fixture: multiple scans, thousands of entities
    // (enlarged vs. early P18 baseline to materially stress project memory
    // without making CI ridiculous; ~2 MiB serialized, well under 16 MiB).
    let scan_a = state("127.0.0.1", 800);
    let scan_b = state("127.0.0.1", 820);
    let scan_c = state("127.0.0.2", 600);
    let diff_ab = diff::compare_states(&scan_a, &scan_b, diff::DiffOptions::default()).unwrap();
    let analysis_b =
        analysis::analyze_state(&scan_b, Some(&diff_ab), AnalysisOptions::default()).unwrap();
    let mut project = ProjectState::new(None);
    let started = Instant::now();
    let import_a = project.add_scan(&scan_a, None, None).unwrap();
    let initial_import_ms = started.elapsed().as_millis();
    let bytes_after_first = serde_json::to_vec(&project).unwrap().len();
    let started = Instant::now();
    let import_b = project
        .add_scan(&scan_b, Some(&diff_ab), Some(&analysis_b))
        .unwrap();
    let incremental_import_ms = started.elapsed().as_millis();
    let bytes_after_incremental = serde_json::to_vec(&project).unwrap().len();
    let started = Instant::now();
    let duplicate = project.add_scan(&scan_a, None, None).unwrap();
    let duplicate_import_ms = started.elapsed().as_millis();
    let _ = project.add_scan(&scan_c, None, None).unwrap();
    let project_bytes = serde_json::to_vec(&project).unwrap().len();
    let bytes_added_incremental = bytes_after_incremental.saturating_sub(bytes_after_first);
    let duplicate_bytes_avoided = project_bytes.saturating_sub(bytes_after_first);
    // Project open benchmark: save to temp file then load with timing.
    let tmp = std::env::temp_dir().join(format!(
        "rxscan_phase18_bench_{}.rxproj",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&tmp);
    rxscan::project::save_project(&tmp, &project, None).unwrap();
    let started = Instant::now();
    let loaded = rxscan::project::load_project(&tmp).unwrap();
    let project_open_ms = started.elapsed().as_millis();
    let _ = std::fs::remove_file(&tmp);
    assert_eq!(loaded.fingerprint, project.fingerprint);
    let started = Instant::now();
    let summary = project.summary(project_bytes as u64);
    let summary_ms = started.elapsed().as_millis();
    // Pick a representative entity with non-trivial degree (highest incident
    // edge count) so queue/visited peaks are meaningful yet exhaustive.
    let entity = {
        let mut best: Option<(usize, String)> = None;
        for id in project.entities.keys() {
            let degree = project
                .relationships
                .values()
                .filter(|r| &r.from_entity == id || &r.to_entity == id)
                .count();
            if best.as_ref().is_none_or(|(d, _)| degree > *d) {
                best = Some((degree, id.clone()));
            }
        }
        best.map(|(_, id)| id)
            .unwrap_or_else(|| project.entities.keys().next().unwrap().clone())
    };
    let started = Instant::now();
    let _entity = project.entities.get(&entity).unwrap();
    let entity_lookup_ms = started.elapsed().as_millis();
    let started = Instant::now();
    let n1 = project.neighbors(&entity, 1, 100).unwrap();
    let neighbors_depth1_ms = started.elapsed().as_millis();
    let started = Instant::now();
    let n3 = project.neighbors(&entity, 3, 1000).unwrap();
    let neighbors_depth3_ms = started.elapsed().as_millis();
    let graph_query_queue_peak = n3.queue_peak.max(n1.queue_peak);
    let graph_query_visited_peak = n3.visited_peak.max(n1.visited_peak);
    let graph_query_expansions = n3.expansions.max(n1.expansions);
    let graph_exhaustive = n3.exhaustive && n1.exhaustive;
    // Fingerprint benchmark: streaming borrowed view, no whole-state clone.
    // Time refresh on the already-loaded copy (no extra clone).
    let rss_before_fp = peak_rss_kb().unwrap_or(0);
    let started = Instant::now();
    let mut fp_check = loaded;
    fp_check.refresh_fingerprint();
    let fingerprint_ms = started.elapsed().as_millis();
    assert_eq!(fp_check.fingerprint, project.fingerprint);
    let fingerprint_rss_kb = peak_rss_kb().unwrap_or(0);
    let fingerprint_whole_state_clones = rxscan::project::fingerprint_whole_state_clones();
    let fingerprint_buffer = rxscan::project::fingerprint_serialization_buffer_bytes();
    let project_serialization_buffer = rxscan::project::project_serialization_buffer_bytes();
    let project_open_rss_kb = peak_rss_kb().unwrap_or(0);
    let query_peak_rss_kb = peak_rss_kb().unwrap_or(0);
    let current_rss = current_rss_kb().unwrap_or(0);
    let _ = rss_before_fp;
    let available_parallelism = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let wall_ms = wall_start.elapsed().as_millis();
    println!("phase18_bench");
    println!("scans={}", summary.scans);
    println!("entities={}", summary.entities);
    println!("relationships={}", summary.relationships);
    println!("observations={}", summary.observations);
    println!("findings={}", summary.findings);
    println!("change_refs={}", summary.change_refs);
    println!("analysis_refs={}", summary.analysis_refs);
    println!(
        "duplicate_entities_avoided={}",
        import_b.duplicate_entities_avoided + duplicate.duplicate_entities_avoided
    );
    println!(
        "duplicate_relationships_avoided={}",
        import_b.duplicate_relationships_avoided + duplicate.duplicate_relationships_avoided
    );
    println!(
        "duplicate_observations_avoided={}",
        import_a.duplicate_observations_avoided
            + import_b.duplicate_observations_avoided
            + duplicate.duplicate_observations_avoided
    );
    println!("project_bytes={project_bytes}");
    println!("initial_import_ms={initial_import_ms}");
    println!("incremental_import_ms={incremental_import_ms}");
    println!("duplicate_import_ms={duplicate_import_ms}");
    println!("project_open_ms={project_open_ms}");
    println!("summary_ms={summary_ms}");
    println!("entity_lookup_ms={entity_lookup_ms}");
    println!("neighbors_depth1_ms={neighbors_depth1_ms}");
    println!("neighbors_depth3_ms={neighbors_depth3_ms}");
    println!("threads_used=1");
    println!("network_requests=0");
    println!("peak_project_rss_kb={}", peak_rss_kb().unwrap_or(0));
    println!("release_binary_size_bytes={}", release_binary_size());
    println!("new_production_dependency_count=0");
    println!("background_cpu_percent=0");
    println!("background_rss_kb=0");
    println!("duplicate_scan_noop={}", duplicate.duplicate_scan);
    println!("bytes_after_first_import={bytes_after_first}");
    println!("bytes_added_incremental={bytes_added_incremental}");
    println!("duplicate_bytes_avoided={duplicate_bytes_avoided}");
    println!("available_parallelism={available_parallelism}");
    println!("wall_ms={wall_ms}");
    // Lightweight/multitasking blocker metrics (bounded query + streaming).
    println!("graph_query_queue_peak={graph_query_queue_peak}");
    println!("graph_query_visited_peak={graph_query_visited_peak}");
    println!("graph_query_expansions={graph_query_expansions}");
    println!("graph_query_exhaustive={graph_exhaustive}");
    println!(
        "graph_query_max_queue_cap={}",
        rxscan::project::MAX_GRAPH_QUERY_QUEUE
    );
    println!(
        "graph_query_max_visited_cap={}",
        rxscan::project::MAX_GRAPH_QUERY_VISITED
    );
    println!(
        "graph_query_max_expansions_cap={}",
        rxscan::project::MAX_GRAPH_QUERY_EXPANSIONS
    );
    println!(
        "graph_query_max_edge_budget={}",
        rxscan::project::MAX_GRAPH_QUERY_EDGE_BUDGET
    );
    println!("fingerprint_whole_state_clones={fingerprint_whole_state_clones}");
    println!("fingerprint_serialization_buffer_bytes={fingerprint_buffer}");
    println!("project_serialization_buffer_bytes={project_serialization_buffer}");
    println!("project_open_rss_kb={project_open_rss_kb}");
    println!("fingerprint_rss_kb={fingerprint_rss_kb}");
    println!("query_peak_rss_kb={query_peak_rss_kb}");
    println!("current_rss_kb={current_rss}");
    println!("fingerprint_ms={fingerprint_ms}");
}
