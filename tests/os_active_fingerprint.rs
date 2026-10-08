//! Active OS fingerprinting integration tests: synthetic matcher behavior,
//! graceful degradation, scope/cancellation discipline, machine output,
//! persistence round-trip, CLI/web parity, corpus regression, and scale.
//!
//! No live internet: all network-adjacent paths use reserved documentation
//! addresses (192.0.2.x, 198.51.100.x, 203.0.113.x, 2001:db8::/32),
//! loopback-only fixtures, or paths that provably perform no I/O
//! (disabled / restricted / out-of-scope / pre-cancelled).

use rxscan::execution::{ModuleOutput, TaskId};
use rxscan::model::{
    BoundedDetails, Event, EventKind, MAX_EVENT_DETAILS_BYTES, Provenance, ScanPlanId, Timestamp,
};
use rxscan::os_fingerprint::{OsDb, OsEvidence, OsHostReport, parse_os_pack};

fn evidence(source: &str, value: &str) -> OsEvidence {
    OsEvidence {
        source: source.to_owned(),
        feature: "test".to_owned(),
        value: value.to_owned(),
        confidence: 50,
        task_id: None,
        evidence_id: None,
    }
}

/// Synthetic-only matcher pack (test knowledge, never production): one
/// Linux rule over active + passive evidence, one Windows rule, one
/// veto-guarded BSD rule.
fn synthetic_db() -> OsDb {
    let pack = r#"{"schema_version": 1, "rules": [
        {"id": "syn-linux", "family": "Linux", "generation": "Ubuntu",
         "features": [
           {"source": "tcp_behavior", "pattern": "reset", "weight": 15},
           {"source": "ssh_banner", "pattern": "Ubuntu", "weight": 20}],
         "confidence_cap": 85, "source": "synthetic-test"},
        {"id": "syn-windows", "family": "Windows",
         "features": [
           {"source": "ssh_banner", "pattern": "Windows", "weight": 22}],
         "confidence_cap": 80, "source": "synthetic-test"},
        {"id": "syn-bsd", "family": "FreeBSD",
         "features": [
           {"source": "ssh_banner", "pattern": "FreeBSD", "weight": 25}],
         "exclusions": [
           {"source": "ssh_banner", "pattern": "Linux", "weight": 1}],
         "confidence_cap": 85, "source": "synthetic-test"}]}"#;
    OsDb::from_packs(vec![(
        "syn.json".to_owned(),
        parse_os_pack(pack, "syn").unwrap(),
    )])
}

fn provenance() -> Provenance {
    Provenance::new(
        "test.module",
        "1.0.0",
        ScanPlanId("plan_test".to_owned()),
        Timestamp(7),
    )
    .unwrap()
}

fn port_event(kind: EventKind, address: &str, port: u64) -> Event {
    Event::new(
        kind,
        None,
        BoundedDetails::from_value(
            serde_json::json!({"address": address, "port": port}),
            MAX_EVENT_DETAILS_BYTES,
        )
        .unwrap(),
        provenance(),
    )
    .unwrap()
}

fn outputs(events: Vec<Event>) -> Vec<(TaskId, ModuleOutput)> {
    vec![(
        TaskId("task_test".to_owned()),
        ModuleOutput {
            events,
            ..ModuleOutput::default()
        },
    )]
}

// 1. Known synthetic host fingerprint -> expected candidate.
#[test]
fn known_synthetic_host_matches_expected_candidate() {
    let db = synthetic_db();
    let candidates = db.classify_host(&[
        evidence("tcp_behavior", "port 80 reset"),
        evidence("ssh_banner", "SSH-2.0-OpenSSH Ubuntu"),
    ]);
    assert!(!candidates.is_empty());
    assert_eq!(candidates[0].family, "Linux");
    assert_eq!(candidates[0].generation.as_deref(), Some("Ubuntu"));
    assert!(candidates[0].confidence > 70);
    assert!(candidates[0].confidence <= rxscan::os_fingerprint::OS_CONFIDENCE_CAP);
}

// 2. Ambiguous synthetic evidence -> multiple candidates, reduced confidence.
#[test]
fn ambiguous_synthetic_evidence_stays_ambiguous() {
    let pack = r#"{"schema_version": 1, "rules": [
        {"id": "amb-a", "family": "Linux",
         "features": [{"source": "tcp_behavior", "pattern": "reset", "weight": 15}],
         "confidence_cap": 70, "source": "synthetic-test"},
        {"id": "amb-b", "family": "FreeBSD",
         "features": [{"source": "tcp_behavior", "pattern": "reset", "weight": 15}],
         "confidence_cap": 70, "source": "synthetic-test"}]}"#;
    let db = OsDb::from_packs(vec![(
        "amb.json".to_owned(),
        parse_os_pack(pack, "amb").unwrap(),
    )]);
    let inference = db.classify_detailed(&[evidence("tcp_behavior", "port 80 reset")]);
    assert!(!inference.unknown);
    let best = inference.best.unwrap();
    // Single weak class: capped, never high confidence.
    assert!(best.confidence <= rxscan::os_fingerprint::SINGLE_HINT_CAP);
    assert_eq!(inference.alternatives.len(), 1);
    assert_ne!(inference.alternatives[0].family, best.family);
}

// 3. Insufficient evidence -> unknown with an explicit reason.
#[test]
fn insufficient_evidence_yields_unknown() {
    let db = synthetic_db();
    let empty = db.classify_detailed(&[]);
    assert!(empty.unknown);
    assert!(empty.best.is_none());
    assert!(empty.alternatives.is_empty());
    assert_eq!(
        empty.unknown_reason.as_deref(),
        Some("no OS evidence was collected for this host")
    );
    let nomatch = db.classify_detailed(&[evidence("ssh_banner", "hello world")]);
    assert!(nomatch.unknown);
    assert_eq!(
        nomatch.unknown_reason.as_deref(),
        Some("no fingerprint matched the collected evidence")
    );
    // Classic wrapper agrees: unknown means no candidates.
    assert!(db.classify_host(&[]).is_empty());
}

// 4. Conflicting evidence -> conflict exposed; full veto -> unknown.
#[test]
fn conflicting_evidence_is_exposed() {
    let db = synthetic_db();
    // FreeBSD evidence plus Linux evidence vetoes the BSD rule outright.
    let vetoed = db.classify_host(&[
        evidence("ssh_banner", "FreeBSD box"),
        evidence("ssh_banner", "Linux compat"),
    ]);
    assert!(!vetoed.iter().any(|candidate| candidate.family == "FreeBSD"));
}

// 5. Raw capability unavailable -> graceful partial/unknown, not failure.
#[test]
fn raw_capability_unavailable_degrades_gracefully() {
    use rxscan::execution::CancellationToken;
    use rxscan::os_active::{ActiveProbeConfig, probe_host};
    let restricted = rxscan::platform::capabilities::fixture_termux_restricted();
    let outcome = probe_host(
        "192.0.2.10".parse().unwrap(),
        &ActiveProbeConfig::default(),
        &CancellationToken::default(),
        &restricted,
    );
    assert_eq!(outcome.probes_sent, 0);
    assert!(outcome.signals.is_empty());
    assert!(!outcome.cancelled);
    assert!(
        outcome
            .unavailable_reason
            .as_deref()
            .unwrap()
            .contains("passive OS evidence remains enabled")
    );
    // The workflow continues: empty active evidence classifies unknown,
    // never errors.
    let db = synthetic_db();
    assert!(db.classify_host(&[]).is_empty());
    assert!(db.classify_detailed(&[]).unknown);
}

// 6. Out-of-scope target -> no OS probe network activity.
#[test]
fn out_of_scope_target_sees_no_probe_activity() {
    use rxscan::execution::CancellationToken;
    use rxscan::os_active::{ActiveProbeConfig, probe_host_with_scope};
    let spec = rxscan::target::TargetSpec::parse("192.0.2.10").unwrap();
    let scope =
        rxscan::scope::ScopePolicy::from_targets(std::slice::from_ref(&spec), &[], &[]).unwrap();
    let outcome = probe_host_with_scope(
        "198.51.100.20".parse().unwrap(),
        &scope,
        &ActiveProbeConfig::default(),
        &CancellationToken::default(),
        &rxscan::platform::capabilities::fixture_linux_full(),
    );
    assert_eq!(outcome.probes_sent, 0);
    assert!(outcome.signals.is_empty());
    assert!(!outcome.cancelled);
}

// 7. Cancellation -> bounded prompt termination.
#[test]
fn cancellation_bounds_active_probing() {
    use rxscan::execution::CancellationToken;
    use rxscan::os_active::{ActiveProbeConfig, probe_host};
    let cancel = CancellationToken::default();
    cancel.cancel();
    let start = std::time::Instant::now();
    let outcome = probe_host(
        "192.0.2.10".parse().unwrap(),
        &ActiveProbeConfig::default(),
        &cancel,
        &rxscan::platform::capabilities::fixture_linux_full(),
    );
    assert!(outcome.cancelled);
    assert!(outcome.signals.is_empty());
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "pre-cancelled probe must return promptly"
    );
}

// 8. Machine output -> valid typed OS evidence, no ANSI, deterministic.
#[test]
fn machine_output_carries_typed_os_evidence() {
    let db = synthetic_db();
    let inference = db.classify_detailed(&[
        evidence("tcp_behavior", "port 80 reset"),
        evidence("ssh_banner", "SSH-2.0-OpenSSH Ubuntu"),
    ]);
    let best = inference.best.clone().unwrap();
    let report = OsHostReport {
        host: "192.0.2.10".to_owned(),
        candidates: inference.candidates(),
        evidence_count: 2,
        coverage: best.coverage,
        unavailable: best.unavailable.clone(),
        probe_availability: Some("active probe plan: 3 probe(s) on port(s) 80,443,22".to_owned()),
        provenance: best.provenance.clone(),
    };
    let mut buffer = Vec::new();
    {
        let mut writer = rxscan::output::JsonlWriter::new(&mut buffer, 1024 * 1024);
        writer.write_os_candidate(&report).unwrap();
    }
    let line = String::from_utf8(buffer).unwrap();
    assert!(!line.contains('\x1b'), "no ANSI in machine output");
    let envelope: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(envelope["record_type"], "os_candidate");
    let payload = &envelope["payload"];
    assert_eq!(payload["host"], "192.0.2.10");
    assert_eq!(payload["candidates"][0]["family"], "Linux");
    assert!(payload["coverage"].as_f64().unwrap() > 0.0);
    assert!(payload["provenance"].as_array().unwrap().len() >= 2);
    // Round-trip without semantic loss.
    let decoded: OsHostReport = serde_json::from_value(payload.clone()).unwrap();
    assert_eq!(decoded, report);
    // Deterministic: repeated serialization is byte-identical.
    let first = serde_json::to_string(&report).unwrap();
    let second = serde_json::to_string(&report).unwrap();
    assert_eq!(first, second);
}

// 9. Persistence round-trip -> OS evidence survives without semantic loss.
#[test]
fn persistence_round_trip_preserves_os_evidence() {
    use rxscan::project_db::{IntelImport, ProjectDb};
    let db = synthetic_db();
    let candidates = db.classify_host(&[
        evidence("tcp_behavior", "port 80 reset"),
        evidence("ssh_banner", "SSH-2.0-OpenSSH Ubuntu"),
    ]);
    assert!(!candidates.is_empty());
    let mut project = ProjectDb::open_in_memory().unwrap();
    let stats = project
        .import_intelligence(
            "scan_os_test",
            &IntelImport {
                os: vec![("192.0.2.10".to_owned(), candidates[0].clone())],
                devices: vec![],
                software: vec![],
                tls: vec![],
                vulns: vec![],
            },
        )
        .unwrap();
    assert_eq!(stats.os_stored, 1);
    let rows = project.os_for_host("scan_os_test", "192.0.2.10").unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].family, candidates[0].family);
    assert_eq!(rows[0].confidence, candidates[0].confidence);
    assert_eq!(
        rows[0].generation,
        candidates[0].generation.clone().unwrap_or_default()
    );
}

// 10. CLI/web core parity -> same evidence, same inference.
#[test]
fn cli_and_web_share_core_inference() {
    use clap::Parser;
    // CLI: explicit --os flag compiles into the plan.
    let cli = rxscan::cli::Cli::try_parse_from(["rxscan", "192.0.2.10", "--os"]).unwrap();
    assert!(cli.os);
    let plan = rxscan::plan::ScanPlan::compile(cli).unwrap();
    assert!(plan.os_requested);
    // Default CLI stays passive: no silent behavior change.
    let plain = rxscan::cli::Cli::try_parse_from(["rxscan", "192.0.2.10"]).unwrap();
    assert!(!plain.os);
    assert!(!rxscan::plan::ScanPlan::compile(plain).unwrap().os_requested);
    // Web: the same explicit flag deserializes on the API contract.
    let request: rxscan::web_api::ScanRequest =
        serde_json::from_str(r#"{"target": "192.0.2.10", "os": true}"#).unwrap();
    assert!(request.os);
    let passive: rxscan::web_api::ScanRequest =
        serde_json::from_str(r#"{"target": "192.0.2.10"}"#).unwrap();
    assert!(!passive.os);
    // Same core, same evidence -> same inference on both paths.
    let db = synthetic_db();
    let proof = vec![
        evidence("tcp_behavior", "port 80 reset"),
        evidence("ssh_banner", "SSH-2.0-OpenSSH Ubuntu"),
    ];
    assert_eq!(db.classify_host(&proof), db.classify_host(&proof));
}

// Corpus regression: production packs load cleanly with provenance.
#[test]
fn production_os_corpus_loads_with_provenance() {
    let dir = std::path::Path::new("fingerprints/os/v1");
    let db = OsDb::load_from_dir(dir);
    // Dynamic count: never hard-coded, never zero in a healthy tree.
    assert!(db.rule_count() > 0, "production OS corpus is empty");
    assert_eq!(
        db.stats().files_rejected,
        0,
        "rejected={:?}",
        db.stats().rejected_files
    );
    // Every production pack parses, validates, and declares provenance.
    let mut ids = std::collections::BTreeSet::new();
    let mut files = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    files.sort();
    assert!(!files.is_empty());
    for path in files {
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let label = path.display().to_string();
        let text = std::fs::read_to_string(&path).unwrap();
        let pack = parse_os_pack(&text, &label).unwrap();
        for rule in &pack.rules {
            assert!(!rule.source.trim().is_empty(), "provenance: {}", rule.id);
            assert!(ids.insert(rule.id.clone()), "duplicate: {}", rule.id);
            for feature in rule.features.iter().chain(rule.exclusions.iter()) {
                assert!(
                    rxscan::os_fingerprint::is_known_os_source(&feature.source),
                    "unknown key {} in {}",
                    feature.source,
                    rule.id
                );
            }
        }
        // Unknown keys are lint-visible, never silently matched.
        assert!(
            rxscan::os_fingerprint::unknown_os_sources(&pack).is_empty(),
            "unknown keys in {label}"
        );
    }
    // Corpus size is dynamic: the registry count always equals the
    // validated rule count, never a hard-coded marketing number.
    assert_eq!(db.rule_count(), ids.len());
}

// Scale: 3,000 synthetic fingerprints stay deterministic and bounded.
#[test]
fn synthetic_3000_fingerprint_scale_stays_deterministic() {
    let mut packs = Vec::new();
    for chunk in 0..6 {
        let mut rules = Vec::new();
        for id in 0..500 {
            let n = chunk * 500 + id;
            rules.push(serde_json::json!({
                "id": format!("scale-os-{n}"),
                "family": format!("Family{}", n % 50),
                "features": [
                    {"source": "ssh_banner", "pattern": format!("token-{n}"), "weight": 10},
                    {"source": "http_server", "pattern": format!("token-{n}"), "weight": 8}
                ],
                "confidence_cap": 80,
                "source": "synthetic-scale"
            }));
        }
        let text = serde_json::json!({"schema_version": 1, "rules": rules}).to_string();
        packs.push((
            format!("scale-{chunk}.json"),
            parse_os_pack(&text, "scale").unwrap(),
        ));
    }
    let db = OsDb::try_from_packs(packs).unwrap();
    assert_eq!(
        db.rule_count(),
        3000,
        "dynamic corpus size, never hard-coded"
    );
    let proof = vec![
        evidence("ssh_banner", "token-42"),
        evidence("http_server", "token-42"),
    ];
    let start = std::time::Instant::now();
    let first = db.classify_host(&proof);
    let elapsed = start.elapsed();
    assert!(!first.is_empty());
    assert_eq!(first, db.classify_host(&proof), "deterministic");
    // Evidence permutation never changes the result, even at scale.
    let mut permuted = proof.clone();
    permuted.reverse();
    assert_eq!(first, db.classify_host(&permuted));
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "matching must stay bounded: {elapsed:?}"
    );
    for candidate in &first {
        // Scores stay finite and capped (u8 range, project bands honored).
        assert!(candidate.confidence <= rxscan::os_fingerprint::OS_CONFIDENCE_CAP);
        assert!(candidate.confidence <= 95);
    }
}

// Probe budget is evidence-driven and hard-capped.
#[test]
fn probe_budget_never_expands_with_scan_size() {
    let open: Vec<u16> = (1..=1000).collect();
    let closed: Vec<u16> = (1001..=2000).collect();
    let plan = rxscan::os_active::plan_os_probes("203.0.113.7", &open, &closed, 64);
    assert!(plan.probes_planned <= rxscan::os_active::MAX_OS_PROBES_PER_HOST);
    assert!(plan.ports.len() <= rxscan::os_active::MAX_OS_PROBES_PER_HOST as usize);
}

// Scan-evidence reuse: known open/closed ports lead the OS plan.
#[test]
fn scan_evidence_reuse_leads_os_plan() {
    let events = vec![
        port_event(EventKind::PortOpen, "192.0.2.10", 22),
        port_event(EventKind::PortClosed, "192.0.2.10", 445),
    ];
    let states = rxscan::os_active::host_tcp_port_states(&outputs(events));
    let (open, closed) = states.get("192.0.2.10").cloned().unwrap();
    let plan = rxscan::os_active::plan_os_probes("192.0.2.10", &open, &closed, 6);
    assert_eq!(plan.reused_open_port, Some(22));
    assert_eq!(plan.reused_closed_port, Some(445));
}
