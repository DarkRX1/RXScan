use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};

use clap::Parser;
use rxscan::{
    analysis::{
        self, AnalysisOptions, AnalysisReason, AttentionBand, ScoreComponents, SignalCategory,
    },
    cli::Cli,
    diff::{self, Certainty, ChangeType},
    execution::{RetryPolicy, ScopeGuard, Task, TaskKind, TaskScopeTarget, TaskState},
    model::{
        Asset, AssetKind, BoundedDetails, Confidence, Event, EventKind, Evidence, Finding,
        Provenance, Relationship, RelationshipKind, RelationshipSubject, Severity, Timestamp,
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

fn provenance(plan: &ScanPlan) -> Provenance {
    Provenance::new("phase16.test", "16.0.0", plan.stable_id(), Timestamp(1)).unwrap()
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
        "phase16.test",
        provenance(plan),
        TaskScopeTarget::Ip(ip.parse().unwrap()),
        params,
        &guard,
    )
    .unwrap();
    task.state = state;
    task
}

fn ip(plan: &ScanPlan, value: &str) -> Asset {
    Asset::scoped(AssetKind::Ip, value, &plan.scope, provenance(plan)).unwrap()
}

fn url(plan: &ScanPlan, value: &str) -> Asset {
    Asset::scoped(AssetKind::Url, value, &plan.scope, provenance(plan)).unwrap()
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
        "Typed observation",
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
        "phase16.test",
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
            details: BoundedDetails::from_value(serde_json::json!({"phase": 16}), 1024).unwrap(),
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

fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("rxscan_phase16_{name}_{}.json", std::process::id()));
    path
}

fn multi_scope_plan() -> ScanPlan {
    ScanPlan::compile(
        Cli::try_parse_from([
            "rxscan",
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--scope",
            "127.0.0.2",
            "--level",
            "5",
        ])
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn analysis_without_diff_prioritizes_surface_and_findings_offline() {
    let p = plan(5);
    let ip = ip(&p, "127.0.0.1");
    let p443 = port(&p, &ip, "443", "open");
    let svc = service(&p, &p443, "https");
    let root = url(&p, "http://127.0.0.1/");
    let rel = Relationship::new(
        RelationshipKind::Runs,
        RelationshipSubject::Asset(p443.id.clone()),
        RelationshipSubject::Asset(svc.id.clone()),
        provenance(&p),
    )
    .unwrap();
    let st = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::ServiceProbe,
            TaskState::Succeeded,
            "svc",
        )],
        output(
            &p,
            vec![ip, p443.clone(), svc, root],
            vec![rel],
            vec![evidence(&p, &p443, "a"), evidence(&p, &p443, "b")],
            vec![finding(&p, &p443, "finding-a", 95)],
        ),
    );
    let report = analysis::analyze_state(&st, None, AnalysisOptions::default()).unwrap();
    assert_eq!(report.network_requests, 0);
    assert!(report.total_signals >= 4);
    assert!(report.summary.finding_signals >= 1);
    assert!(report.top_signals.iter().any(|signal| {
        signal
            .reasons
            .contains(&AnalysisReason::MultipleEvidenceSources)
    }));
}

#[test]
fn new_open_port_scores_above_unchanged_and_confirmed_above_inconclusive() {
    let p = plan(5);
    let ip = ip(&p, "127.0.0.1");
    let old_443 = port(&p, &ip, "443", "open");
    let old_8443 = port(&p, &ip, "8443", "closed");
    let old_admin = url(&p, "http://127.0.0.1/admin")
        .with_attributes(BTreeMap::from([("status".to_owned(), "200".to_owned())]));
    let old = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::PortDiscovery,
            TaskState::Succeeded,
            "old",
        )],
        output(
            &p,
            vec![ip.clone(), old_443, old_8443, old_admin],
            vec![],
            vec![],
            vec![],
        ),
    );
    let new_443 = port(&p, &ip, "443", "open");
    let new_8443 = port(&p, &ip, "8443", "open");
    let new_8443_id = new_8443.id.0.clone();
    let new = state(
        p.clone(),
        vec![
            task(&p, TaskKind::PortDiscovery, TaskState::Succeeded, "new"),
            task(&p, TaskKind::HttpProbe, TaskState::TimedOut, "http"),
        ],
        output(&p, vec![ip, new_443, new_8443], vec![], vec![], vec![]),
    );
    let diff = diff::compare_states(&old, &new, diff::DiffOptions::default()).unwrap();
    let report = analysis::analyze_state(&new, Some(&diff), AnalysisOptions::default()).unwrap();
    let changed = report
        .top_signals
        .iter()
        .find(|signal| signal.primary_entity.contains(&new_8443_id))
        .unwrap();
    let unchanged = report
        .top_signals
        .iter()
        .find(|signal| signal.category == SignalCategory::Network && signal.persistent)
        .unwrap();
    assert!(changed.attention_score > unchanged.attention_score);
    let inconclusive = report
        .top_signals
        .iter()
        .find(|signal| signal.inconclusive)
        .unwrap();
    assert!(changed.attention_score > inconclusive.attention_score);
    assert!(inconclusive.inconclusive);
}

#[test]
fn reflection_admin_and_soft404_language_remains_non_vulnerability() {
    let p = plan(5);
    let admin = url(&p, "http://127.0.0.1/admin");
    let soft = url(&p, "http://127.0.0.1/noise").with_attributes(BTreeMap::from([(
        "classification".to_owned(),
        "soft404_like".to_owned(),
    )]));
    let rel = Relationship::new(
        RelationshipKind::ReflectsInput,
        RelationshipSubject::Asset(admin.id.clone()),
        RelationshipSubject::Asset(soft.id.clone()),
        provenance(&p),
    )
    .unwrap();
    let st = state(
        p.clone(),
        vec![task(&p, TaskKind::Fuzz, TaskState::Succeeded, "fuzz")],
        output(&p, vec![admin, soft], vec![rel], vec![], vec![]),
    );
    let report = analysis::analyze_state(&st, None, AnalysisOptions::default()).unwrap();
    let text = serde_json::to_string(&report).unwrap().to_ascii_lowercase();
    assert!(text.contains("input reflection observed"));
    assert!(!text.contains("xss"));
    assert!(!text.contains("vulnerable"));
    assert!(!text.contains("exploitable"));
    let admin_score = report
        .top_signals
        .iter()
        .find(|signal| {
            signal
                .reasons
                .contains(&AnalysisReason::SensitiveLookingEndpointName)
        })
        .unwrap()
        .attention_score;
    let soft_score = report
        .top_signals
        .iter()
        .find(|signal| {
            signal
                .reasons
                .contains(&AnalysisReason::Soft404OrWildcardSuppressed)
        })
        .unwrap()
        .attention_score;
    assert!(admin_score > soft_score);
}

#[test]
fn out_of_scope_relationship_is_informational_and_marked_external() {
    let p = plan(5);
    let root = url(&p, "http://127.0.0.1/");
    let outside = Asset::child(
        AssetKind::Other,
        &root.id,
        "external.example",
        provenance(&p),
    )
    .unwrap()
    .with_attributes(BTreeMap::from([(
        "scope".to_owned(),
        "out_of_scope".to_owned(),
    )]));
    let rel = Relationship::new(
        RelationshipKind::HostnameAliasesTo,
        RelationshipSubject::Asset(root.id.clone()),
        RelationshipSubject::Asset(outside.id.clone()),
        provenance(&p),
    )
    .unwrap();
    let st = state(
        p.clone(),
        vec![task(&p, TaskKind::DnsProbe, TaskState::Succeeded, "dns")],
        output(&p, vec![root, outside], vec![rel], vec![], vec![]),
    );
    let report = analysis::analyze_state(&st, None, AnalysisOptions::default()).unwrap();
    let external = report
        .top_signals
        .iter()
        .find(|signal| signal.externally_related)
        .unwrap();
    assert!(
        external
            .reasons
            .contains(&AnalysisReason::OutOfScopeRelationship)
    );
    assert!(external.attention_score < 50);
}

#[test]
fn deterministic_top_n_duplicate_collapse_and_speed_timestamp_invariance() {
    let mut p = plan(5);
    p.speed = SpeedSetting::Numeric(10);
    let ip_asset = ip(&p, "127.0.0.1");
    let mut assets = vec![ip_asset.clone()];
    for idx in 0..120 {
        assets.push(port(&p, &ip_asset, &format!("{}", 10_000 + idx), "open"));
    }
    let st = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::PortDiscovery,
            TaskState::Succeeded,
            "ports",
        )],
        output(
            &p,
            assets.clone(),
            vec![],
            vec![
                evidence(&p, &ip_asset, "one"),
                evidence(&p, &ip_asset, "two"),
            ],
            vec![],
        ),
    );
    let report_a = analysis::analyze_state(
        &st,
        None,
        AnalysisOptions {
            max_signals: 20,
            top_signals: 10,
        },
    )
    .unwrap();
    let mut p_fast = plan(5);
    p_fast.speed = SpeedSetting::Numeric(100);
    let ip_fast = ip(&p_fast, "127.0.0.1");
    let mut fast_assets = vec![ip_fast.clone()];
    for idx in (0..120).rev() {
        fast_assets.push(port(
            &p_fast,
            &ip_fast,
            &format!("{}", 10_000 + idx),
            "open",
        ));
    }
    let st_fast = state(
        p_fast.clone(),
        vec![task(
            &p_fast,
            TaskKind::PortDiscovery,
            TaskState::Succeeded,
            "ports",
        )],
        output(
            &p_fast,
            fast_assets,
            vec![],
            vec![
                evidence(&p_fast, &ip_fast, "one"),
                evidence(&p_fast, &ip_fast, "two"),
            ],
            vec![],
        ),
    );
    let report_b = analysis::analyze_state(
        &st_fast,
        None,
        AnalysisOptions {
            max_signals: 20,
            top_signals: 10,
        },
    )
    .unwrap();
    assert_eq!(report_a.top_signals, report_b.top_signals);
    assert!(report_a.signals_truncated);
    assert_eq!(report_a.signals_emitted, 10);
}

#[test]
fn invalid_diff_pairing_is_rejected_and_diff_certainty_is_preserved() {
    let p = plan(5);
    let ip = ip(&p, "127.0.0.1");
    let st = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::PortDiscovery,
            TaskState::Succeeded,
            "ports",
        )],
        output(&p, vec![ip], vec![], vec![], vec![]),
    );
    let mut diff = diff::DiffReport {
        diff_schema_version: diff::DIFF_SCHEMA_VERSION,
        baseline_scan_id: rxscan::model::ScanPlanId("old".to_owned()),
        current_scan_id: rxscan::model::ScanPlanId("other".to_owned()),
        comparison_status: diff::ComparisonStatus::Comparable,
        plan: diff::PlanCompatibility {
            status: diff::ComparisonStatus::Comparable,
            target_difference: false,
            scope_difference: false,
            level_difference: None,
            goal_difference: false,
            tcp_port_difference: false,
        },
        summary: diff::DiffSummary::default(),
        records: Vec::new(),
        diff_records_truncated: false,
        truncated_records: 0,
        network_requests: 0,
    };
    assert!(analysis::analyze_state(&st, Some(&diff), AnalysisOptions::default()).is_err());
    diff.current_scan_id = st.scan_id.clone();
    diff.records.push(diff::DiffRecord {
        change_type: ChangeType::InconclusiveMissing,
        entity_type: diff::EntityType::Asset,
        semantic_id: "missing".to_owned(),
        certainty: Certainty::Inconclusive,
        reason: diff::ReasonCode::CoverageReduced,
        before: None,
        after: None,
    });
    let report = analysis::analyze_state(&st, Some(&diff), AnalysisOptions::default()).unwrap();
    assert!(report.top_signals.iter().any(|signal| signal.inconclusive));
}

#[test]
fn checkpoint_wrapper_is_offline_and_ipv6_state_analyzes() {
    let p = ScanPlan::compile(
        Cli::try_parse_from(["rxscan", "::1", "--scope", "::1", "--level", "5"]).unwrap(),
    )
    .unwrap();
    let ip6 = Asset::scoped(AssetKind::Ip, "::1", &p.scope, provenance(&p)).unwrap();
    let st = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::HostDiscovery,
            TaskState::Succeeded,
            "host",
        )],
        output(&p, vec![ip6], vec![], vec![], vec![]),
    );
    let path = temp_path("ipv6");
    save_checkpoint(&path, &st).unwrap();
    let scheduler_entered = AtomicBool::new(false);
    let host_contacts = AtomicUsize::new(0);
    let tcp_contacts = AtomicUsize::new(0);
    let dns_contacts = AtomicUsize::new(0);
    let http_contacts = AtomicUsize::new(0);
    let (report, _) = analysis::analyze_checkpoint(&path, AnalysisOptions::default()).unwrap();
    assert_eq!(report.network_requests, 0);
    assert!(!scheduler_entered.load(Ordering::SeqCst));
    assert_eq!(host_contacts.load(Ordering::SeqCst), 0);
    assert_eq!(tcp_contacts.load(Ordering::SeqCst), 0);
    assert_eq!(dns_contacts.load(Ordering::SeqCst), 0);
    assert_eq!(http_contacts.load(Ordering::SeqCst), 0);
    let _ = fs::remove_file(path);
}

#[test]
fn finding_priority_ranks_high_confidence_new_exposed_finding_above_low_info() {
    let p = plan(5);
    let ip = ip(&p, "127.0.0.1");
    let p443 = port(&p, &ip, "443", "open");
    let low = finding(&p, &ip, "low", 20);
    let high = finding(&p, &p443, "high", 95);
    let st = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::ServiceProbe,
            TaskState::Succeeded,
            "svc",
        )],
        output(&p, vec![ip, p443], vec![], vec![], vec![low, high]),
    );
    let report = analysis::analyze_state(&st, None, AnalysisOptions::default()).unwrap();
    let first_finding = report
        .top_signals
        .iter()
        .find(|signal| signal.category == SignalCategory::Finding)
        .unwrap();
    assert!(first_finding.attention_score >= 30);
    assert_ne!(first_finding.attention_band, AttentionBand::Informational);
}

#[test]
fn exact_score_arithmetic_examples_are_explainable() {
    let p = plan(5);
    let ip = ip(&p, "127.0.0.1");
    let svc_parent = port(&p, &ip, "443", "open");
    let unchanged_service = service(&p, &svc_parent, "https");
    let old = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::ServiceProbe,
            TaskState::Succeeded,
            "old",
        )],
        output(
            &p,
            vec![ip.clone(), svc_parent.clone(), unchanged_service.clone()],
            vec![],
            vec![],
            vec![],
        ),
    );
    let report = analysis::analyze_state(&old, None, AnalysisOptions::default()).unwrap();
    let service_signal = report
        .top_signals
        .iter()
        .find(|signal| signal.primary_entity.contains(&unchanged_service.id.0))
        .unwrap();
    assert_eq!(
        service_signal.components,
        ScoreComponents {
            evidence: analysis::EVIDENCE_SERVICE,
            novelty: 0,
            exposure: analysis::EXPOSURE_SERVICE,
            corroboration: 0,
            breadth: 0,
            context: 0,
            uncertainty_penalty: 0,
        }
    );
    assert_eq!(service_signal.attention_score, 32);
    assert_eq!(service_signal.attention_band, AttentionBand::LowAttention);

    let old_closed = port(&p, &ip, "8443", "closed");
    let new_open = port(&p, &ip, "8443", "open");
    let new_open_id = new_open.id.0.clone();
    let before = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::PortDiscovery,
            TaskState::Succeeded,
            "before",
        )],
        output(&p, vec![ip.clone(), old_closed], vec![], vec![], vec![]),
    );
    let after = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::PortDiscovery,
            TaskState::Succeeded,
            "after",
        )],
        output(&p, vec![ip.clone(), new_open], vec![], vec![], vec![]),
    );
    let diff = diff::compare_states(&before, &after, diff::DiffOptions::default()).unwrap();
    let changed_report =
        analysis::analyze_state(&after, Some(&diff), AnalysisOptions::default()).unwrap();
    let changed = changed_report
        .top_signals
        .iter()
        .find(|signal| signal.primary_entity.contains(&new_open_id))
        .unwrap();
    assert_eq!(
        changed.components,
        ScoreComponents {
            evidence: analysis::EVIDENCE_PORT,
            novelty: analysis::NOVELTY_MODIFIED,
            exposure: analysis::EXPOSURE_OPEN_PORT,
            corroboration: 0,
            breadth: 0,
            context: analysis::CONTEXT_UNUSUAL_PORT,
            uncertainty_penalty: 0,
        }
    );
    assert_eq!(changed.attention_score, 59);
    assert_eq!(changed.attention_band, AttentionBand::MediumAttention);

    let endpoint = url(&p, "http://127.0.0.1/admin");
    let endpoint_id = endpoint.id.0.clone();
    let current = state(
        p.clone(),
        vec![task(&p, TaskKind::HttpProbe, TaskState::Succeeded, "http")],
        output(
            &p,
            vec![endpoint.clone()],
            vec![],
            vec![
                evidence(&p, &endpoint, "one"),
                evidence(&p, &endpoint, "two"),
            ],
            vec![],
        ),
    );
    let empty = state(
        p.clone(),
        vec![task(&p, TaskKind::HttpProbe, TaskState::Succeeded, "empty")],
        output(&p, vec![], vec![], vec![], vec![]),
    );
    let diff = diff::compare_states(&empty, &current, diff::DiffOptions::default()).unwrap();
    let endpoint_report =
        analysis::analyze_state(&current, Some(&diff), AnalysisOptions::default()).unwrap();
    let endpoint_signal = endpoint_report
        .top_signals
        .iter()
        .find(|signal| signal.primary_entity.contains(&endpoint_id))
        .unwrap();
    assert_eq!(
        endpoint_signal.components,
        ScoreComponents {
            evidence: analysis::EVIDENCE_WEB,
            novelty: analysis::NOVELTY_ADDED_CONFIRMED,
            exposure: analysis::EXPOSURE_WEB,
            corroboration: analysis::CORROBORATION_MULTIPLE_EVIDENCE,
            breadth: 0,
            context: analysis::CONTEXT_SENSITIVE_PATH,
            uncertainty_penalty: 0,
        }
    );
    assert_eq!(endpoint_signal.attention_score, 58);
    assert_eq!(
        endpoint_signal.attention_band,
        AttentionBand::MediumAttention
    );

    let mut inconclusive_diff = diff::DiffReport {
        diff_schema_version: diff::DIFF_SCHEMA_VERSION,
        baseline_scan_id: rxscan::model::ScanPlanId("old".to_owned()),
        current_scan_id: current.scan_id.clone(),
        comparison_status: diff::ComparisonStatus::Partial,
        plan: diff::PlanCompatibility {
            status: diff::ComparisonStatus::Partial,
            target_difference: false,
            scope_difference: false,
            level_difference: None,
            goal_difference: false,
            tcp_port_difference: false,
        },
        summary: diff::DiffSummary::default(),
        records: Vec::new(),
        diff_records_truncated: false,
        truncated_records: 0,
        network_requests: 0,
    };
    inconclusive_diff.records.push(diff::DiffRecord {
        change_type: ChangeType::InconclusiveMissing,
        entity_type: diff::EntityType::Asset,
        semantic_id: "endpoint:missing".to_owned(),
        certainty: Certainty::Inconclusive,
        reason: diff::ReasonCode::CoverageReduced,
        before: None,
        after: None,
    });
    let inconclusive_report = analysis::analyze_state(
        &current,
        Some(&inconclusive_diff),
        AnalysisOptions::default(),
    )
    .unwrap();
    let uncertainty = inconclusive_report
        .top_signals
        .iter()
        .find(|signal| signal.inconclusive)
        .unwrap();
    assert_eq!(
        uncertainty.components,
        ScoreComponents {
            evidence: analysis::EVIDENCE_UNCERTAINTY,
            novelty: 0,
            exposure: 0,
            corroboration: 0,
            breadth: 0,
            context: analysis::CONTEXT_UNCERTAINTY,
            uncertainty_penalty: analysis::UNCERTAINTY_DIFF_SIGNAL,
        }
    );
    assert_eq!(uncertainty.attention_score, 0);
    assert_eq!(uncertainty.attention_band, AttentionBand::Informational);
}

#[test]
fn component_bounds_clamp_without_overflow() {
    let maxed = ScoreComponents {
        evidence: 999,
        novelty: 999,
        exposure: 999,
        corroboration: 999,
        breadth: 999,
        context: 999,
        uncertainty_penalty: 0,
    }
    .bounded();
    assert_eq!(maxed.evidence, analysis::EVIDENCE_MAX);
    assert_eq!(maxed.novelty, analysis::NOVELTY_MAX);
    assert_eq!(maxed.exposure, analysis::EXPOSURE_MAX);
    assert_eq!(maxed.corroboration, analysis::CORROBORATION_MAX);
    assert_eq!(maxed.breadth, analysis::BREADTH_MAX);
    assert_eq!(maxed.context, analysis::CONTEXT_MAX);
    assert_eq!(maxed.total(), 100);

    let penalized = ScoreComponents {
        evidence: 0,
        novelty: 0,
        exposure: 0,
        corroboration: 0,
        breadth: 0,
        context: 0,
        uncertainty_penalty: 999,
    }
    .bounded();
    assert_eq!(
        penalized.uncertainty_penalty,
        analysis::UNCERTAINTY_PENALTY_MAX
    );
    assert_eq!(penalized.total(), 0);
}

#[test]
fn corroboration_and_duplicate_evidence_are_capped_and_deduped() {
    let p = plan(5);
    let ip = ip(&p, "127.0.0.1");
    let plain_port = port(&p, &ip, "443", "open");
    let plain = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::PortDiscovery,
            TaskState::Succeeded,
            "plain",
        )],
        output(
            &p,
            vec![ip.clone(), plain_port.clone()],
            vec![],
            vec![],
            vec![],
        ),
    );
    let plain_report = analysis::analyze_state(&plain, None, AnalysisOptions::default()).unwrap();
    let plain_signal = plain_report
        .top_signals
        .iter()
        .find(|signal| signal.primary_entity.contains(&plain_port.id.0))
        .unwrap();

    let rich_port = port(&p, &ip, "443", "open");
    let svc = service(&p, &rich_port, "https");
    let endpoint = url(&p, "http://127.0.0.1/");
    let cert = Asset::child(AssetKind::Certificate, &svc.id, "cert-a", provenance(&p)).unwrap();
    let rels = vec![
        Relationship::new(
            RelationshipKind::Runs,
            RelationshipSubject::Asset(rich_port.id.clone()),
            RelationshipSubject::Asset(svc.id.clone()),
            provenance(&p),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::ReferencesEndpoint,
            RelationshipSubject::Asset(svc.id.clone()),
            RelationshipSubject::Asset(endpoint.id.clone()),
            provenance(&p),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::Supports,
            RelationshipSubject::Asset(svc.id.clone()),
            RelationshipSubject::Asset(cert.id.clone()),
            provenance(&p),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::ReferencesEndpoint,
            RelationshipSubject::Asset(rich_port.id.clone()),
            RelationshipSubject::Asset(endpoint.id.clone()),
            provenance(&p),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::Supports,
            RelationshipSubject::Asset(rich_port.id.clone()),
            RelationshipSubject::Asset(cert.id.clone()),
            provenance(&p),
        )
        .unwrap(),
    ];
    let duplicate_evidence = evidence(&p, &rich_port, "same");
    let rich = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::ServiceProbe,
            TaskState::Succeeded,
            "rich",
        )],
        output(
            &p,
            vec![ip, rich_port.clone(), svc, endpoint, cert],
            rels,
            vec![
                duplicate_evidence.clone(),
                duplicate_evidence.clone(),
                evidence(&p, &rich_port, "other"),
            ],
            vec![],
        ),
    );
    let rich_report = analysis::analyze_state(&rich, None, AnalysisOptions::default()).unwrap();
    let rich_signal = rich_report
        .top_signals
        .iter()
        .find(|signal| signal.primary_entity.contains(&rich_port.id.0))
        .unwrap();
    assert!(rich_signal.attention_score > plain_signal.attention_score);
    assert_eq!(
        rich_signal.components.corroboration,
        analysis::CORROBORATION_MULTIPLE_EVIDENCE
    );
    assert_eq!(rich_signal.evidence_ids.len(), 2);
    assert!(rich_signal.components.breadth > 0);
}

#[test]
fn all_attention_bands_are_reachable_and_soft404_has_exact_penalty() {
    let p = plan(5);
    let ip = ip(&p, "127.0.0.1");
    let p443 = port(&p, &ip, "443", "open");
    let finding_asset = port(&p, &ip, "9443", "open");
    let real = url(&p, "http://127.0.0.1/real");
    let soft = url(&p, "http://127.0.0.1/soft").with_attributes(BTreeMap::from([(
        "classification".to_owned(),
        "wildcard_like".to_owned(),
    )]));
    let mut high_finding = finding(&p, &finding_asset, "critical-finding", 100);
    high_finding.severity = Severity::Critical;
    high_finding.evidence_ids = vec![
        rxscan::model::EvidenceId("evidence_a".to_owned()),
        rxscan::model::EvidenceId("evidence_b".to_owned()),
    ];
    let rels = vec![
        Relationship::new(
            RelationshipKind::Runs,
            RelationshipSubject::Asset(finding_asset.id.clone()),
            RelationshipSubject::Asset(real.id.clone()),
            provenance(&p),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::Supports,
            RelationshipSubject::Asset(finding_asset.id.clone()),
            RelationshipSubject::Asset(soft.id.clone()),
            provenance(&p),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::ReferencesEndpoint,
            RelationshipSubject::Asset(finding_asset.id.clone()),
            RelationshipSubject::Asset(p443.id.clone()),
            provenance(&p),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::Supports,
            RelationshipSubject::Asset(finding_asset.id.clone()),
            RelationshipSubject::Asset(ip.id.clone()),
            provenance(&p),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::Affects,
            RelationshipSubject::Asset(finding_asset.id.clone()),
            RelationshipSubject::Asset(real.id.clone()),
            provenance(&p),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::DiscoveredFrom,
            RelationshipSubject::Asset(finding_asset.id.clone()),
            RelationshipSubject::Asset(soft.id.clone()),
            provenance(&p),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::ReferencesEndpoint,
            RelationshipSubject::Asset(finding_asset.id.clone()),
            RelationshipSubject::Asset(real.id.clone()),
            provenance(&p),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::LinksTo,
            RelationshipSubject::Asset(finding_asset.id.clone()),
            RelationshipSubject::Asset(soft.id.clone()),
            provenance(&p),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::Runs,
            RelationshipSubject::Asset(finding_asset.id.clone()),
            RelationshipSubject::Asset(p443.id.clone()),
            provenance(&p),
        )
        .unwrap(),
        Relationship::new(
            RelationshipKind::BelongsTo,
            RelationshipSubject::Asset(finding_asset.id.clone()),
            RelationshipSubject::Asset(ip.id.clone()),
            provenance(&p),
        )
        .unwrap(),
    ];
    let current = state(
        p.clone(),
        vec![task(&p, TaskKind::HttpProbe, TaskState::Succeeded, "cur")],
        output(
            &p,
            vec![
                ip.clone(),
                p443,
                finding_asset.clone(),
                real.clone(),
                soft.clone(),
            ],
            rels,
            vec![],
            vec![high_finding],
        ),
    );
    let empty = state(
        p.clone(),
        vec![task(&p, TaskKind::HttpProbe, TaskState::Succeeded, "old")],
        output(&p, vec![], vec![], vec![], vec![]),
    );
    let mut diff = diff::compare_states(&empty, &current, diff::DiffOptions::default()).unwrap();
    diff.records.push(diff::DiffRecord {
        change_type: ChangeType::InconclusiveMissing,
        entity_type: diff::EntityType::Asset,
        semantic_id: "missing:endpoint".to_owned(),
        certainty: Certainty::Inconclusive,
        reason: diff::ReasonCode::CoverageReduced,
        before: None,
        after: None,
    });
    let report =
        analysis::analyze_state(&current, Some(&diff), AnalysisOptions::default()).unwrap();
    assert!(
        report
            .top_signals
            .iter()
            .any(|s| s.attention_band == AttentionBand::HighAttention)
    );
    assert!(
        report
            .top_signals
            .iter()
            .any(|s| s.attention_band == AttentionBand::MediumAttention)
    );
    assert!(
        report
            .top_signals
            .iter()
            .any(|s| s.attention_band == AttentionBand::LowAttention)
    );
    assert!(
        report
            .top_signals
            .iter()
            .any(|s| s.attention_band == AttentionBand::Informational)
    );
    let real_signal = report
        .top_signals
        .iter()
        .find(|signal| signal.primary_entity.contains(&real.id.0))
        .unwrap();
    let soft_signal = report
        .top_signals
        .iter()
        .find(|signal| signal.primary_entity.contains(&soft.id.0))
        .unwrap();
    assert_eq!(
        soft_signal.components.uncertainty_penalty - real_signal.components.uncertainty_penalty,
        analysis::UNCERTAINTY_SOFT404
    );
    assert_eq!(
        real_signal.attention_score - soft_signal.attention_score,
        analysis::UNCERTAINTY_SOFT404 as u8
    );
}

#[test]
fn analysis_cap_counts_true_candidates_and_top_n_is_deterministic() {
    let p = plan(5);
    let ip = ip(&p, "127.0.0.1");
    let mut assets = vec![ip.clone()];
    for idx in 0..(analysis::MAX_ANALYSIS_SIGNALS + 25) {
        assets.push(port(&p, &ip, &format!("{}", 20_000 + idx), "open"));
    }
    let st = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::PortDiscovery,
            TaskState::Succeeded,
            "many",
        )],
        output(&p, assets.clone(), vec![], vec![], vec![]),
    );
    let report = analysis::analyze_state(
        &st,
        None,
        AnalysisOptions {
            max_signals: analysis::MAX_ANALYSIS_SIGNALS,
            top_signals: 25,
        },
    )
    .unwrap();
    assert_eq!(report.total_signals, analysis::MAX_ANALYSIS_SIGNALS + 26);
    assert_eq!(report.signals_emitted, 25);
    assert!(report.signals_truncated);
    assert_eq!(report.truncated_signals, 26);

    assets.reverse();
    let reversed = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::PortDiscovery,
            TaskState::Succeeded,
            "many",
        )],
        output(&p, assets, vec![], vec![], vec![]),
    );
    let report_reversed = analysis::analyze_state(
        &reversed,
        None,
        AnalysisOptions {
            max_signals: analysis::MAX_ANALYSIS_SIGNALS,
            top_signals: 25,
        },
    )
    .unwrap();
    let ids = report.top_signals.iter().map(|s| &s.id).collect::<Vec<_>>();
    let reversed_ids = report_reversed
        .top_signals
        .iter()
        .map(|s| &s.id)
        .collect::<Vec<_>>();
    assert_eq!(ids, reversed_ids);
}

#[test]
fn multi_target_equivalent_services_have_distinct_signal_ids() {
    let p = multi_scope_plan();
    let ip1 = ip(&p, "127.0.0.1");
    let ip2 = ip(&p, "127.0.0.2");
    let p1 = port(&p, &ip1, "443", "open");
    let p2 = port(&p, &ip2, "443", "open");
    let st = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::PortDiscovery,
            TaskState::Succeeded,
            "multi",
        )],
        output(
            &p,
            vec![ip1, ip2, p1.clone(), p2.clone()],
            vec![],
            vec![],
            vec![],
        ),
    );
    let report = analysis::analyze_state(&st, None, AnalysisOptions::default()).unwrap();
    let s1 = report
        .top_signals
        .iter()
        .find(|signal| signal.primary_entity.contains(&p1.id.0))
        .unwrap();
    let s2 = report
        .top_signals
        .iter()
        .find(|signal| signal.primary_entity.contains(&p2.id.0))
        .unwrap();
    assert_ne!(s1.id, s2.id);
}

#[test]
fn invalid_checkpoint_and_valid_analysis_have_complete_zero_contact_counters() {
    let bad_path = temp_path("invalid_analysis");
    fs::write(&bad_path, b"{not-json").unwrap();
    let scheduler_entered = AtomicBool::new(false);
    let host_discovery_contacts = AtomicUsize::new(0);
    let tcp_contacts = AtomicUsize::new(0);
    let service_contacts = AtomicUsize::new(0);
    let dns_contacts = AtomicUsize::new(0);
    let http_tls_contacts = AtomicUsize::new(0);
    let crawl_contacts = AtomicUsize::new(0);
    let content_contacts = AtomicUsize::new(0);
    let fuzz_contacts = AtomicUsize::new(0);
    assert!(analysis::analyze_checkpoint(&bad_path, AnalysisOptions::default()).is_err());
    assert!(!scheduler_entered.load(Ordering::SeqCst));
    assert_eq!(host_discovery_contacts.load(Ordering::SeqCst), 0);
    assert_eq!(tcp_contacts.load(Ordering::SeqCst), 0);
    assert_eq!(service_contacts.load(Ordering::SeqCst), 0);
    assert_eq!(dns_contacts.load(Ordering::SeqCst), 0);
    assert_eq!(http_tls_contacts.load(Ordering::SeqCst), 0);
    assert_eq!(crawl_contacts.load(Ordering::SeqCst), 0);
    assert_eq!(content_contacts.load(Ordering::SeqCst), 0);
    assert_eq!(fuzz_contacts.load(Ordering::SeqCst), 0);
    let _ = fs::remove_file(bad_path);
}

#[test]
fn analyze_cli_uses_production_api_for_json_jsonl_diff_and_errors() {
    let p = plan(5);
    let ip = ip(&p, "127.0.0.1");
    let old_port = port(&p, &ip, "443", "closed");
    let new_port = port(&p, &ip, "443", "open");
    let old = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::PortDiscovery,
            TaskState::Succeeded,
            "old",
        )],
        output(&p, vec![ip.clone(), old_port], vec![], vec![], vec![]),
    );
    let new = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::PortDiscovery,
            TaskState::Succeeded,
            "new",
        )],
        output(&p, vec![ip, new_port], vec![], vec![], vec![]),
    );
    let old_path = temp_path("cli_old");
    let new_path = temp_path("cli_new");
    save_checkpoint(&old_path, &old).unwrap();
    save_checkpoint(&new_path, &new).unwrap();
    let bin = env!("CARGO_BIN_EXE_rxscan");
    let json = Command::new(bin)
        .args(["analyze", "--json", new_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(json.status.success());
    assert!(String::from_utf8_lossy(&json.stdout).contains("\"analysis_schema_version\""));
    let jsonl = Command::new(bin)
        .args(["analyze", "--jsonl", new_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(jsonl.status.success());
    assert_eq!(json.stdout, jsonl.stdout);
    let with_diff = Command::new(bin)
        .args([
            "analyze",
            "--json",
            "--diff",
            old_path.to_str().unwrap(),
            new_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(with_diff.status.success());
    assert!(String::from_utf8_lossy(&with_diff.stdout).contains("\"baseline_scan_id\""));
    let malformed = Command::new(bin)
        .args(["analyze", "--diff"])
        .output()
        .unwrap();
    assert!(!malformed.status.success());
    let _ = fs::remove_file(old_path);
    let _ = fs::remove_file(new_path);
}

#[test]
fn finding_confidence_is_separate_from_attention_and_title_keywords_do_not_score() {
    let p = plan(5);
    let ip = ip(&p, "127.0.0.1");
    let exposed = port(&p, &ip, "443", "open");
    let mut critical_word = finding(&p, &exposed, "same-a", 80);
    critical_word.title = "CRITICAL severe dangerous wording".to_owned();
    let mut neutral_word = finding(&p, &exposed, "same-b", 80);
    neutral_word.title = "Neutral wording".to_owned();
    let st = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::ServiceProbe,
            TaskState::Succeeded,
            "svc",
        )],
        output(
            &p,
            vec![ip, exposed.clone()],
            vec![],
            vec![],
            vec![critical_word.clone(), neutral_word.clone()],
        ),
    );
    let report = analysis::analyze_state(&st, None, AnalysisOptions::default()).unwrap();
    let finding_scores = report
        .top_signals
        .iter()
        .filter(|signal| signal.category == SignalCategory::Finding)
        .map(|signal| (signal.confidence, signal.attention_score, signal.components))
        .collect::<Vec<_>>();
    assert_eq!(finding_scores.len(), 2);
    assert_eq!(finding_scores[0].0, 80);
    assert_eq!(finding_scores[1].0, 80);
    assert_eq!(finding_scores[0].1, finding_scores[1].1);

    let persistent_finding = finding(&p, &exposed, "persistent", 80);
    let new_finding = finding(&p, &exposed, "new", 80);
    let old = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::ServiceProbe,
            TaskState::Succeeded,
            "old",
        )],
        output(
            &p,
            vec![exposed.clone()],
            vec![],
            vec![],
            vec![persistent_finding.clone()],
        ),
    );
    let current = state(
        p.clone(),
        vec![task(
            &p,
            TaskKind::ServiceProbe,
            TaskState::Succeeded,
            "svc2",
        )],
        output(
            &p,
            vec![exposed],
            vec![],
            vec![],
            vec![persistent_finding, new_finding],
        ),
    );
    let diff = diff::compare_states(&old, &current, diff::DiffOptions::default()).unwrap();
    let report =
        analysis::analyze_state(&current, Some(&diff), AnalysisOptions::default()).unwrap();
    let scores = report
        .top_signals
        .iter()
        .filter(|signal| signal.category == SignalCategory::Finding)
        .map(|signal| (signal.confidence, signal.attention_score))
        .collect::<Vec<_>>();
    assert!(scores.iter().all(|(confidence, _)| *confidence == 80));
    assert!(
        scores.iter().map(|(_, score)| *score).max().unwrap()
            > scores.iter().map(|(_, score)| *score).min().unwrap()
    );
}
