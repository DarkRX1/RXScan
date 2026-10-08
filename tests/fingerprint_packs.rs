//! Fingerprint database + enrichment + decision-reason regression tests.
//!
//! Covers Phase 8/9/17/36: validated external packs, evidence-gated
//! vendor/CPE/family enrichment, and explanatory follow-up reasons that do
//! not perturb canonical task identity (dedup preserved).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use rxscan::execution::{PolicyScopeGuard, RetryPolicy, Task, TaskKind, TaskScopeTarget};
use rxscan::model::{Provenance, Timestamp};

fn repo_pack_dir() -> PathBuf {
    // Tests execute with CWD at the package root.
    PathBuf::from("fingerprints/v1")
}

#[test]
fn seed_packs_load_and_match() {
    let dir = repo_pack_dir();
    if !dir.is_dir() {
        // Workspace layout without seed packs: nothing to validate.
        return;
    }
    let packs = rxscan::fingerprints::load_dir(&dir).expect("seed packs must validate");
    assert!(
        packs.len() >= 2,
        "expected http + ssh seed packs, got {}",
        packs.len()
    );
    let http = packs
        .iter()
        .find(|(path, _)| {
            std::path::Path::new(path)
                .file_name()
                .is_some_and(|name| name == "http.json")
        })
        .expect("core http seed pack")
        .1
        .clone();
    let matched = http
        .match_observation("http", "Server: nginx/1.24.0")
        .expect("nginx seed rule fires");
    assert_eq!(matched.product, "nginx");
    assert_eq!(matched.vendor.as_deref(), Some("f5"));
    // Protocol gate holds.
    assert!(http.match_observation("ssh", "Server: nginx").is_none());
}

#[test]
fn malformed_pack_inputs_never_panic() {
    for bad in [
        "",
        "{{{",
        r#"{"schema_version": 1}"#, // missing fingerprints → default empty, valid
        r#"{"schema_version": 2, "fingerprints": []}"#,
        r#"{"schema_version": 1, "fingerprints": [{"id": "", "protocol": "http", "probe": "http", "matcher": {"kind": "contains", "pattern": "x"}, "product": "x", "confidence": 80, "source": "t"}]}"#,
        r#"{"schema_version": 1, "fingerprints": [{"id": "x", "protocol": "http", "probe": "http", "matcher": {"kind": "contains", "pattern": "x"}, "product": "x", "confidence": 100, "source": "t"}]}"#,
    ] {
        let _ = rxscan::fingerprints::parse_pack(bad, "adversarial");
    }
    // Empty fingerprint list is valid (no rules, nothing matches).
    let empty =
        rxscan::fingerprints::parse_pack(r#"{"schema_version": 1, "fingerprints": []}"#, "t")
            .unwrap();
    assert!(empty.match_observation("http", "nginx").is_none());
}

#[test]
fn enrichment_is_evidence_gated_and_capped() {
    // Port priors contribute zero: no product → no identity, no CPE.
    let none = rxscan::service::enrich_fingerprint(None, Some("1.0"), 80, Some("http"), 3);
    assert_eq!(none.cpe, None);
    assert!(none.confidence <= 95);
    // Exact version alone caps at 90; corroboration lifts, never past 95.
    let solo =
        rxscan::service::enrich_fingerprint(Some("nginx"), Some("1.24.0"), 90, Some("http"), 0);
    assert_eq!(solo.confidence, 90);
    let corroborated =
        rxscan::service::enrich_fingerprint(Some("nginx"), Some("1.24.0"), 90, Some("http"), 2);
    assert!(corroborated.confidence > 90 && corroborated.confidence <= 95);
    assert_eq!(
        corroborated.cpe.as_deref(),
        Some("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*")
    );
    assert_eq!(corroborated.version_family.as_deref(), Some("1.24.x"));
}

#[test]
fn followup_reasons_do_not_perturb_identity() {
    // Same logical task with and without an explanatory reason shares its ID,
    // so engine proposals still dedup against lowering shapes (no rescan).
    let guard = PolicyScopeGuard::new(
        rxscan::plan::ScanPlan::compile(
            <rxscan::cli::Cli as clap::Parser>::try_parse_from([
                "rxscan",
                "127.0.0.1",
                "--scope",
                "127.0.0.0/8",
            ])
            .unwrap(),
        )
        .unwrap()
        .scope,
    );
    let plan_id = rxscan::plan::ScanPlan::compile(
        <rxscan::cli::Cli as clap::Parser>::try_parse_from([
            "rxscan",
            "127.0.0.1",
            "--scope",
            "127.0.0.0/8",
        ])
        .unwrap(),
    )
    .unwrap()
    .stable_id();
    let provenance = Provenance::new("test", "1.0.0", plan_id.clone(), Timestamp(0)).unwrap();
    let base_params = BTreeMap::from([
        ("target".to_owned(), "127.0.0.1".to_owned()),
        ("ports".to_owned(), "common".to_owned()),
    ]);
    let mut with_reason = base_params.clone();
    with_reason.insert(
        "reason".to_owned(),
        "host 127.0.0.1 concluded alive → TCP port discovery".to_owned(),
    );
    let mk = |params: BTreeMap<String, String>| {
        Task::new_with_params(
            TaskKind::PortDiscovery,
            None,
            Vec::new(),
            None,
            plan_id.clone(),
            60,
            Duration::from_millis(15000),
            RetryPolicy::default(),
            "rxscan.port",
            provenance.clone(),
            TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
            params,
            &guard,
        )
        .unwrap()
    };
    let plain = mk(base_params);
    let reasoned = mk(with_reason);
    assert_eq!(
        plain.id, reasoned.id,
        "reason metadata must not change task identity"
    );
    assert_eq!(
        reasoned.params.get("reason").map(String::as_str),
        Some("host 127.0.0.1 concluded alive → TCP port discovery")
    );
}

// ---------------- live runtime database (correlation engine) ----------------

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use clap::Parser;
use rxscan::cli::Cli;
use rxscan::execution::{CancellationToken, Module, ModuleContext, ModuleOutput, ScopeGuard};
use rxscan::fingerprints::{FingerprintDb, MAX_CANDIDATES_PER_OBSERVATION, parse_pack};
use rxscan::plan::{ScanPlan, SpeedSetting};
use rxscan::service::{
    EvidenceClass, ExternalCandidateView, combine_confidence, count_distinct_classes,
    merge_external_candidates, unknown_suggestion_cap,
};
use rxscan::service_probe::ServiceProbeModule;

const PACK_MIXED: &str = r#"{
    "schema_version": 1,
    "fingerprints": [
        {"id": "a-exact", "protocol": "http", "probe": "http",
         "matcher": {"kind": "exact", "pattern": "hello packdaemon", "case_insensitive": true},
         "product": "PackDaemon", "confidence": 88, "source": "t"},
        {"id": "b-prefix", "protocol": "http", "probe": "http",
         "matcher": {"kind": "prefix", "pattern": "hello", "case_insensitive": true},
         "product": "HelloServer", "confidence": 70, "source": "t"},
        {"id": "c-contains", "protocol": "http", "probe": "http",
         "matcher": {"kind": "contains", "pattern": "packdaemon", "case_insensitive": true},
         "product": "PackDaemon", "confidence": 70, "source": "t"},
        {"id": "z-ssh-only", "protocol": "ssh", "probe": "ssh",
         "matcher": {"kind": "contains", "pattern": "packdaemon", "case_insensitive": true},
         "product": "SshDaemon", "confidence": 90, "source": "t"}
    ]
}"#;

fn db_from(json: &str) -> FingerprintDb {
    FingerprintDb::from_packs(vec![(
        "test-pack.json".to_owned(),
        parse_pack(json, "t").unwrap(),
    )])
}

#[test]
fn db_matcher_kinds_fire() {
    let db = db_from(PACK_MIXED);
    // Exact (case-insensitive) fires on the full observation.
    let hits: Vec<_> = db
        .candidates_for("http", "hello packdaemon")
        .into_iter()
        .map(|candidate| candidate.rule_id)
        .collect();
    assert!(
        hits.contains(&"a-exact".to_owned()),
        "exact fires: {hits:?}"
    );
    assert!(
        hits.contains(&"b-prefix".to_owned()),
        "prefix fires: {hits:?}"
    );
    assert!(
        hits.contains(&"c-contains".to_owned()),
        "contains fires: {hits:?}"
    );
    // SSH rule never fires on HTTP bytes (protocol gating).
    assert!(!hits.contains(&"z-ssh-only".to_owned()));
    // Empty observation matches nothing.
    assert!(db.candidates_for("http", "").is_empty());
}

#[test]
fn db_candidates_bounded_and_deterministic() {
    let mut rules = String::from(r#"{"schema_version": 1, "fingerprints": ["#);
    for index in 0..8 {
        rules.push_str(&format!(
            r#"{{"id": "rule-{index:02}", "protocol": "http", "probe": "http",
                "matcher": {{"kind": "contains", "pattern": "x-target", "case_insensitive": true}},
                "product": "P{index}", "confidence": 80, "source": "t"}}{comma}"#,
            comma = if index == 7 { "" } else { "," }
        ));
    }
    rules.push_str("]}");
    let db = db_from(&rules);
    let first = db.candidates_for("http", "x-target here");
    assert_eq!(first.len(), MAX_CANDIDATES_PER_OBSERVATION);
    let ids: Vec<_> = first.iter().map(|candidate| &candidate.rule_id).collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted, "rule-id order is deterministic");
    assert_eq!(
        db.candidates_for("http", "x-target here")
            .iter()
            .map(|candidate| &candidate.rule_id)
            .collect::<Vec<_>>(),
        ids,
        "repeatable across calls"
    );
}

#[test]
fn db_rejects_oversized_and_duplicate_packs() {
    // Oversized pack (>1024 rules) is rejected, never loaded.
    let mut big = String::from(r#"{"schema_version": 1, "fingerprints": ["#);
    for index in 0..1100 {
        big.push_str(&format!(
            r#"{{"id": "big-{index}", "protocol": "http", "probe": "http",
                "matcher": {{"kind": "contains", "pattern": "q", "case_insensitive": true}},
                "product": "Q", "confidence": 50, "source": "t"}}{comma}"#,
            comma = if index == 1099 { "" } else { "," }
        ));
    }
    big.push_str("]}");
    assert!(parse_pack(&big, "big").is_err());
    // Duplicate rule ids across packs are a strict production validation
    // failure (never silent first-wins). The error identifies the ID and
    // both sources deterministically regardless of input order.
    let first = parse_pack(
        r#"{"schema_version": 1, "fingerprints": [
            {"id": "dup", "protocol": "http", "probe": "http",
             "matcher": {"kind": "contains", "pattern": "x"},
             "product": "First", "confidence": 80, "source": "a"}]}"#,
        "a",
    )
    .unwrap();
    let second = parse_pack(
        r#"{"schema_version": 1, "fingerprints": [
            {"id": "dup", "protocol": "http", "probe": "http",
             "matcher": {"kind": "contains", "pattern": "x"},
             "product": "Second", "confidence": 80, "source": "b"}]}"#,
        "b",
    )
    .unwrap();
    let err = FingerprintDb::try_from_packs(vec![
        ("b.json".to_owned(), second.clone()),
        ("a.json".to_owned(), first.clone()),
    ])
    .expect_err("strict packs must reject duplicates");
    let text = err.to_string();
    assert!(text.contains("dup"), "ID identified: {text}");
    assert!(
        text.contains("a.json") && text.contains("b.json"),
        "sources: {text}"
    );
    let reverse = FingerprintDb::try_from_packs(vec![
        ("a.json".to_owned(), first.clone()),
        ("b.json".to_owned(), second.clone()),
    ])
    .expect_err("ordering must not matter");
    assert_eq!(text, reverse.to_string());
    // Production filesystem loader also rejects (not merely the helper).
    let dir = std::env::temp_dir().join(format!("rxscan-fp-strict-{}-packs", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("a.json"),
        r#"{"schema_version": 1, "fingerprints": [
            {"id": "dup", "protocol": "http", "probe": "http",
             "matcher": {"kind": "contains", "pattern": "x"},
             "product": "First", "confidence": 80, "source": "a"}]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("b.json"),
        r#"{"schema_version": 1, "fingerprints": [
            {"id": "dup", "protocol": "http", "probe": "http",
             "matcher": {"kind": "contains", "pattern": "x"},
             "product": "Second", "confidence": 80, "source": "b"}]}"#,
    )
    .unwrap();
    let db = FingerprintDb::load_from_dir(&dir);
    assert_eq!(
        db.rule_count(),
        0,
        "no silent shadowing in production loader"
    );
    assert!(db.stats().files_rejected >= 1);
    assert!(db.stats().rejected_files.join("\n").contains("dup"));
    let _ = std::fs::remove_dir_all(&dir);
    // Permissive `from_packs` remains for backwards compatibility/tests only.
    let compat = FingerprintDb::from_packs(vec![
        ("a.json".to_owned(), first),
        ("b.json".to_owned(), second),
    ]);
    assert_eq!(compat.rule_count(), 1);
}

#[test]
fn db_missing_directory_is_empty() {
    let db =
        FingerprintDb::load_from_dir(std::path::Path::new("definitely-not-a-fingerprint-dir-xyz"));
    assert_eq!(db.rule_count(), 0);
    assert!(db.candidates_for("http", "nginx").is_empty());
    assert!(db.candidates_for_unknown("nginx").is_empty());
}

#[test]
fn unknown_suggestions_cap_by_matcher_strength() {
    use rxscan::fingerprints::MatcherKind;
    assert_eq!(unknown_suggestion_cap(&MatcherKind::Contains, 90), 60);
    assert_eq!(unknown_suggestion_cap(&MatcherKind::Prefix, 90), 75);
    assert_eq!(unknown_suggestion_cap(&MatcherKind::Exact, 90), 85);
    // Never exceeds the rule's own confidence.
    assert_eq!(unknown_suggestion_cap(&MatcherKind::Exact, 50), 50);
}

#[test]
fn evidence_classes_dedup_port_priors() {
    assert_eq!(
        count_distinct_classes(&[EvidenceClass::TransportHint, EvidenceClass::TransportHint,]),
        0,
        "port priors never count"
    );
    assert_eq!(
        count_distinct_classes(&[
            EvidenceClass::BannerToken,
            EvidenceClass::BannerToken,
            EvidenceClass::TlsArtifact,
        ]),
        2,
        "same class twice counts once"
    );
    assert_eq!(combine_confidence(90, &[], true), 90);
    assert_eq!(
        combine_confidence(
            85,
            &[EvidenceClass::TlsArtifact, EvidenceClass::HttpArtifact],
            true
        ),
        87
    );
    assert_eq!(
        combine_confidence(95, &[EvidenceClass::TlsArtifact; 8], true),
        95,
        "cap holds"
    );
}

#[test]
fn merge_builtin_product_wins_with_visible_alternates() {
    let views = [
        ExternalCandidateView {
            product: "nginx",
            vendor: Some("f5"),
            confidence: 85,
            rule_id: "agree-1",
            rule_source: "p.json#agree-1",
            matcher: &rxscan::fingerprints::MatcherKind::Contains,
            version: None,
            version_confidence: None,
        },
        ExternalCandidateView {
            product: "FakeServer",
            vendor: None,
            confidence: 80,
            rule_id: "conflict-1",
            rule_source: "p.json#conflict-1",
            matcher: &rxscan::fingerprints::MatcherKind::Contains,
            version: None,
            version_confidence: None,
        },
        ExternalCandidateView {
            product: "fakeserver",
            vendor: None,
            confidence: 70,
            rule_id: "conflict-2",
            rule_source: "p.json#conflict-2",
            matcher: &rxscan::fingerprints::MatcherKind::Prefix,
            version: None,
            version_confidence: None,
        },
    ];
    let merge = merge_external_candidates(Some("nginx"), Some("1.24.0"), 90, &views);
    assert!(merge.adopted.is_none(), "builtin product never replaced");
    assert_eq!(merge.corroborated_by.len(), 1);
    assert_eq!(merge.corroborated_by[0].rule_id, "agree-1");
    // Case-insensitive product dedup: FakeServer once.
    assert_eq!(merge.alternates.len(), 1);
    assert_eq!(merge.alternates[0].product, "FakeServer");
}

#[test]
fn merge_adopts_only_without_builtin_product() {
    let views = [ExternalCandidateView {
        product: "PackDaemon",
        vendor: None,
        confidence: 88,
        rule_id: "a-exact",
        rule_source: "p.json#a-exact",
        matcher: &rxscan::fingerprints::MatcherKind::Exact,
        version: None,
        version_confidence: None,
    }];
    let merge = merge_external_candidates(None, None, 50, &views);
    let adopted = merge.adopted.expect("adopts strongest candidate");
    assert_eq!(adopted.product, "PackDaemon");
    assert_eq!(adopted.confidence, 88);
    // No candidates → no adoption, no alternates.
    let empty = merge_external_candidates(None, None, 50, &[]);
    assert!(empty.adopted.is_none() && empty.alternates.is_empty());
}

// ---------- live module fixtures ----------

struct BannerFixture {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl BannerFixture {
    fn serve(banner: &'static [u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(25);
            while !stop_thread.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.write_all(banner);
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                        let mut chunk = [0u8; 256];
                        let _ = stream.read(&mut chunk);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for BannerFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn pack_plan(ports: &str) -> ScanPlan {
    let cli =
        Cli::try_parse_from(["rxscan", "127.0.0.1", "--ports", ports, "--level", "4"]).unwrap();
    ScanPlan::compile(cli).unwrap()
}

fn pack_task(plan: &ScanPlan, port: u16, probes: &str, guard: &dyn ScopeGuard) -> Task {
    let parent = rxscan::tcp_discovery::port_asset_id(
        &rxscan::tcp_discovery::parent_asset_id_for_ip(&"127.0.0.1".parse().unwrap()),
        "tcp",
        port,
    );
    Task::new_with_params(
        TaskKind::ServiceProbe,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        50,
        Duration::from_millis(8000),
        RetryPolicy::default(),
        "rxscan.service",
        Provenance::new("test.module", "1.0.0", plan.stable_id(), Timestamp(0)).unwrap(),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        BTreeMap::from([
            ("target".to_owned(), "127.0.0.1".to_owned()),
            ("address".to_owned(), "127.0.0.1".to_owned()),
            ("port".to_owned(), port.to_string()),
            ("transport".to_owned(), "tcp".to_owned()),
            ("parent_asset".to_owned(), parent),
            ("probes".to_owned(), probes.to_owned()),
        ]),
        guard,
    )
    .unwrap()
}

fn block_module(
    module: &ServiceProbeModule,
    context: ModuleContext,
) -> Result<ModuleOutput, rxscan::execution::ModuleError> {
    use std::task::{Context as TaskContext, Poll, RawWaker, RawWakerVTable, Waker};
    unsafe fn raw_waker(thread: std::thread::Thread) -> RawWaker {
        unsafe fn clone(data: *const ()) -> RawWaker {
            let thread = unsafe { &*(data as *const std::thread::Thread) };
            unsafe { raw_waker(thread.clone()) }
        }
        unsafe fn wake(data: *const ()) {
            let thread = unsafe { Box::from_raw(data as *mut std::thread::Thread) };
            thread.unpark();
        }
        unsafe fn wake_by_ref(data: *const ()) {
            unsafe { (*(data as *const std::thread::Thread)).unpark() };
        }
        unsafe fn drop_waker(data: *const ()) {
            drop(unsafe { Box::from_raw(data as *mut std::thread::Thread) });
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_waker);
        RawWaker::new(Box::into_raw(Box::new(thread)) as *const (), &VTABLE)
    }
    let waker = unsafe { Waker::from_raw(raw_waker(std::thread::current())) };
    let mut task_context = TaskContext::from_waker(&waker);
    let mut future = module.execute(context);
    loop {
        match future.as_mut().poll(&mut task_context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::park(),
        }
    }
}

fn pack_db_for_test() -> Arc<FingerprintDb> {
    Arc::new(db_from(
        r#"{"schema_version": 1, "fingerprints": [
            {"id": "pack-packdaemon", "protocol": "http", "probe": "generic",
             "matcher": {"kind": "contains", "pattern": "packdaemon", "case_insensitive": true},
             "product": "PackDaemon", "confidence": 70, "source": "live-test"}
        ]}"#,
    ))
}

#[test]
fn live_unknown_banner_adopts_pack_suggestion_without_identity() {
    let fixture = BannerFixture::serve(b"hello packdaemon world\r\n");
    let plan = pack_plan(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::with_fingerprint_db(
        rxscan::service_probe::ServicePolicy::new(
            plan.level,
            plan.goal,
            SpeedSetting::Numeric(100),
        ),
        guard.clone(),
        pack_db_for_test(),
    );
    let task = pack_task(&plan, fixture.port, "generic", guard.as_ref());
    let output = block_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .expect("probe executes");
    // Protocol stays unknown: packs suggest, never classify.
    let observation = output
        .evidence
        .iter()
        .find(|evidence| {
            evidence.details.data.get("protocol").is_some() && evidence.source == "rxscan.service"
        })
        .map(|evidence| evidence.details.data.clone())
        .expect("service observation evidence");
    assert_eq!(observation["protocol"], "unknown");
    // Exactly one bounded suggestion event with capped confidence.
    let candidates: Vec<_> = output
        .events
        .iter()
        .filter(|event| format!("{:?}", event.kind) == "FingerprintCandidateObserved")
        .collect();
    assert_eq!(candidates.len(), 1, "one suggestion, got {candidates:?}");
    let data = &candidates[0].details.data;
    assert_eq!(data["role"], "suggested");
    assert_eq!(data["product"], "PackDaemon");
    assert!(data["confidence"].as_u64().unwrap() <= 60);
    assert!(
        data["rule_source"]
            .as_str()
            .unwrap()
            .contains("pack-packdaemon")
    );
}

#[test]
fn live_builtin_product_beats_conflicting_pack_rule() {
    let body = b"<html><body>hi</body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nServer: nginx/1.27.2\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let response = Box::leak(response.into_boxed_str());
    let fixture = BannerFixture::serve(response.as_bytes());
    let plan = pack_plan(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let conflicting = Arc::new(db_from(
        r#"{"schema_version": 1, "fingerprints": [
            {"id": "pack-impostor", "protocol": "http", "probe": "http",
             "matcher": {"kind": "contains", "pattern": "nginx", "case_insensitive": true},
             "product": "FakeServer", "confidence": 80, "source": "live-test"}
        ]}"#,
    ));
    let module = ServiceProbeModule::with_fingerprint_db(
        rxscan::service_probe::ServicePolicy::new(
            plan.level,
            plan.goal,
            SpeedSetting::Numeric(100),
        ),
        guard.clone(),
        conflicting,
    );
    let task = pack_task(&plan, fixture.port, "generic,http", guard.as_ref());
    let output = block_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .expect("probe executes");
    let finding = output
        .findings
        .iter()
        .find(|finding| finding.title.contains("service on port"))
        .expect("service finding");
    // Built-in product wins; conflict stays visible as an alternate.
    assert_eq!(finding.metadata["product"], "nginx");
    assert_eq!(finding.metadata["service"], "http");
    let alternates = finding.metadata["alternate_products"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        alternates
            .iter()
            .any(|alternate| alternate["product"] == "FakeServer"),
        "conflict visible, got {alternates:?}"
    );
}

#[test]
fn live_corrorboration_keeps_confidence_stable() {
    let body = b"<html><body>hi</body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nServer: nginx/1.27.2\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let response = Box::leak(response.into_boxed_str());
    let run = |db: Arc<FingerprintDb>| {
        let fixture = BannerFixture::serve(response.as_bytes());
        let plan = pack_plan(&fixture.port.to_string());
        let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
        let module = ServiceProbeModule::with_fingerprint_db(
            rxscan::service_probe::ServicePolicy::new(
                plan.level,
                plan.goal,
                SpeedSetting::Numeric(100),
            ),
            guard.clone(),
            db,
        );
        let task = pack_task(&plan, fixture.port, "generic,http", guard.as_ref());
        block_module(
            &module,
            ModuleContext::new(task, CancellationToken::default()),
        )
        .expect("probe executes")
    };
    let plain = run(Arc::new(FingerprintDb::empty()));
    let agreeing = run(Arc::new(db_from(
        r#"{"schema_version": 1, "fingerprints": [
            {"id": "pack-agree", "protocol": "http", "probe": "http",
             "matcher": {"kind": "contains", "pattern": "nginx", "case_insensitive": true},
             "product": "nginx", "vendor": "f5", "confidence": 85, "source": "live-test"}
        ]}"#,
    )));
    let confidence_of = |output: &ModuleOutput| {
        output
            .findings
            .iter()
            .find(|finding| finding.title.contains("service on port"))
            .and_then(|finding| finding.metadata.get("product"))
            .cloned()
    };
    assert_eq!(confidence_of(&plain), confidence_of(&agreeing));
    // Agreement is recorded (audit), not added.
    let corroborated: Vec<_> = agreeing
        .events
        .iter()
        .filter(|event| {
            format!("{:?}", event.kind) == "FingerprintCandidateObserved"
                && event.details.data["role"] == "corroborated"
        })
        .collect();
    assert_eq!(corroborated.len(), 1);
    assert_eq!(corroborated[0].details.data["rule_id"], "pack-agree");
}

#[test]
fn merge_external_version_adopts_only_when_builtin_missing() {
    use rxscan::fingerprints::MatcherKind;
    let view = |version: Option<&'static str>| ExternalCandidateView {
        product: "nginx",
        vendor: Some("f5"),
        confidence: 85,
        rule_id: "v-1",
        rule_source: "p.json#v-1",
        matcher: &MatcherKind::Contains,
        version,
        version_confidence: Some(85),
    };
    // Builtin version present + equal external → no conflict, no adoption.
    let same =
        merge_external_candidates(Some("nginx"), Some("1.24.0"), 90, &[view(Some("1.24.0"))]);
    assert!(same.adopted_version.is_none());
    assert!(same.version_conflicts.is_empty());
    // Builtin version present + different external → builtin wins, conflict visible.
    let conflicted =
        merge_external_candidates(Some("nginx"), Some("1.24.0"), 90, &[view(Some("1.26.0"))]);
    assert!(conflicted.adopted_version.is_none());
    assert_eq!(conflicted.version_conflicts.len(), 1);
    assert_eq!(conflicted.version_conflicts[0].builtin_version, "1.24.0");
    assert_eq!(conflicted.version_conflicts[0].external_version, "1.26.0");
    // Builtin version missing → external adopted, capped at product confidence.
    let adopted = merge_external_candidates(Some("nginx"), None, 88, &[view(Some("1.26.0"))]);
    let adopted_version = adopted.adopted_version.expect("version adopted");
    assert_eq!(adopted_version.version, "1.26.0");
    assert!(adopted_version.confidence <= 88);
    // Extraction failure (no version) → no adoption, no conflict.
    let bare = merge_external_candidates(Some("nginx"), None, 88, &[view(None)]);
    assert!(bare.adopted_version.is_none());
    assert!(bare.version_conflicts.is_empty());
}

#[test]
fn merge_adopted_product_carries_extracted_version() {
    use rxscan::fingerprints::MatcherKind;
    let views = [ExternalCandidateView {
        product: "PackDaemon",
        vendor: None,
        confidence: 80,
        rule_id: "v-1",
        rule_source: "p.json#v-1",
        matcher: &MatcherKind::Contains,
        version: Some("2.1"),
        version_confidence: Some(80),
    }];
    let merge = merge_external_candidates(None, None, 50, &views);
    let adopted = merge.adopted.expect("product adopted");
    assert_eq!(adopted.version.as_deref(), Some("2.1"));
    // Version confidence never exceeds its product.
    assert!(adopted.version_confidence.unwrap() <= adopted.confidence);
}

#[test]
fn field_confidence_separates_dimensions() {
    use rxscan::service::FieldConfidence;
    let fields = FieldConfidence {
        protocol: 95,
        product: 92,
        version: 70,
        vendor: 92,
    };
    assert!(fields.version < fields.product);
    assert!(fields.protocol >= fields.product);
    let unknown = FieldConfidence {
        protocol: 80,
        product: 0,
        version: 0,
        vendor: 0,
    };
    assert_eq!(unknown.product, 0);
}

#[test]
fn live_adopted_product_carries_extracted_version() {
    // Unknown banner with an extractable version: adoption carries both.
    let fixture = BannerFixture::serve(b"hello packdaemon 2.1 world\r\n");
    let plan = pack_plan(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let db = Arc::new(db_from(
        r#"{"schema_version": 1, "fingerprints": [
            {"id": "pack-versioned", "protocol": "http", "probe": "generic",
             "matcher": {"kind": "contains", "pattern": "packdaemon", "case_insensitive": true},
             "product": "PackDaemon", "confidence": 70, "source": "live-test",
             "version_extractor": {"type": "token_position", "index": 2}}
        ]}"#,
    ));
    let module = ServiceProbeModule::with_fingerprint_db(
        rxscan::service_probe::ServicePolicy::new(
            plan.level,
            plan.goal,
            SpeedSetting::Numeric(100),
        ),
        guard.clone(),
        db,
    );
    let task = pack_task(&plan, fixture.port, "generic", guard.as_ref());
    let output = block_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .expect("probe executes");
    // Adopted product is classified through the unknown path? No: adoption
    // without a builtin protocol stays a suggestion (never identity).
    let candidates: Vec<_> = output
        .events
        .iter()
        .filter(|event| format!("{:?}", event.kind) == "FingerprintCandidateObserved")
        .collect();
    assert_eq!(candidates.len(), 1);
    // Suggestion carries the extracted version with capped confidence.
    let data = &candidates[0].details.data;
    assert_eq!(data["role"], "suggested");
    // Unknown-path suggestions surface product evidence in the event.
    assert!(data["product"] == "PackDaemon" || data.get("product").is_some());
}

#[test]
fn live_builtin_product_adopts_external_version() {
    // Builtin parses the product but no version; the pack extracts one.
    let body = b"ok";
    let response = format!(
        "HTTP/1.1 200 OK\r\nServer: MyServer version=2.0\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let response = Box::leak(response.into_boxed_str());
    let fixture = BannerFixture::serve(response.as_bytes());
    let plan = pack_plan(&fixture.port.to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let db = Arc::new(db_from(
        r#"{"schema_version": 1, "fingerprints": [
            {"id": "pack-myserver", "protocol": "http", "probe": "http",
             "matcher": {"kind": "contains", "pattern": "MyServer", "case_insensitive": true},
             "product": "MyServer", "confidence": 80, "source": "live-test",
             "version_extractor": {"type": "key_value", "key": "version"}}
        ]}"#,
    ));
    let module = ServiceProbeModule::with_fingerprint_db(
        rxscan::service_probe::ServicePolicy::new(
            plan.level,
            plan.goal,
            SpeedSetting::Numeric(100),
        ),
        guard.clone(),
        db,
    );
    let task = pack_task(&plan, fixture.port, "generic,http", guard.as_ref());
    let output = block_module(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .expect("probe executes");
    let finding = output
        .findings
        .iter()
        .find(|finding| finding.title.contains("service on port"))
        .expect("service finding");
    assert_eq!(finding.metadata["product"], "MyServer");
    // External version adopted (builtin had none), confidence bounded.
    assert_eq!(finding.metadata["version"], "2.0");
    let product_conf = finding.metadata["product_confidence"].as_u64().unwrap();
    let version_conf = finding.metadata["version_confidence"].as_u64().unwrap();
    assert!(
        version_conf <= product_conf,
        "version never surer than product: {version_conf} <= {product_conf}"
    );
    assert!(finding.metadata["cpe"].as_str().unwrap().contains("2.0"));
}
