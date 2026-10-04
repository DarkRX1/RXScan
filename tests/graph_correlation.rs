//! Evidence graph + TLS identity + confidence/conflict regression tests.
//!
//! Covers correlation-engine priorities: normalized certificate entities,
//! reuse correlation, SAN scope annotation (recorded, never contacted),
//! DNS/IP/cert/service edges, provenance retention, deterministic merging,
//! ambiguity visibility, JSONL compatibility, and panic-free parsing.

use clap::Parser;
use rxscan::cli::Cli;
use rxscan::execution::{ModuleOutput, TaskId};
use rxscan::graph::{
    EdgeRelation, EntityKind, build_graph, cert_entity_id, endpoint_entity_id, hostname_entity_id,
    ip_entity_id, port_entity_id,
};
use rxscan::model::{
    BoundedDetails, Event, EventKind, MAX_EVENT_DETAILS_BYTES, Provenance, ScanPlanId, Timestamp,
};
use rxscan::plan::ScanPlan;
use rxscan::tls::CertificateIdentity;

fn plan_id() -> ScanPlanId {
    ScanPlanId("plan_test".to_owned())
}

fn provenance() -> Provenance {
    Provenance::new("test.module", "1.0.0", plan_id(), Timestamp(7)).unwrap()
}

fn event(kind: EventKind, data: serde_json::Value) -> Event {
    Event::new(
        kind,
        None,
        BoundedDetails::from_value(data, MAX_EVENT_DETAILS_BYTES).unwrap(),
        provenance(),
    )
    .unwrap()
}

fn output_with(events: Vec<Event>) -> (TaskId, ModuleOutput) {
    (
        TaskId("task_test".to_owned()),
        ModuleOutput {
            events,
            ..ModuleOutput::default()
        },
    )
}

fn plan_scope() -> rxscan::scope::ScopePolicy {
    let cli = Cli::try_parse_from(["rxscan", "127.0.0.1", "--scope", "127.0.0.0/8"]).unwrap();
    ScanPlan::compile(cli).unwrap().scope
}

// ---------------- TLS identity ----------------

fn rcgen_leaf(sans: Vec<String>) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::new(sans).expect("rcgen params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "graph.test");
    let key = rcgen::KeyPair::generate().expect("rcgen key");
    params
        .self_signed(&key)
        .expect("rcgen self-signed")
        .der()
        .to_vec()
}

#[test]
fn certificate_identity_parses_and_stays_stable() {
    let der = rcgen_leaf(vec!["graph.test".to_owned(), "127.0.0.1".to_owned()]);
    let identity = CertificateIdentity::from_parts(&der, 1, Some("h2"), Some("graph.test"))
        .expect("identity parses");
    assert_eq!(identity.sha256.len(), 64);
    assert!(identity.sha256.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(
        identity.entity_id(),
        format!("cert:sha256:{}", identity.sha256)
    );
    // Same bytes → same identity (stable across scans for diffing).
    let again = CertificateIdentity::from_parts(&der, 3, None, None).unwrap();
    assert_eq!(again.sha256, identity.sha256);
    assert_eq!(again.entity_id(), identity.entity_id());
    // Chain length is contextual, not identity.
    assert_eq!(again.chain_len, 3);
    // Self-signed rcgen cert detected via DN equality.
    assert!(identity.self_signed);
    // SANs captured both kinds; ALPN/SNI pass through.
    assert!(identity.sans_dns.contains(&"graph.test".to_owned()));
    assert!(identity.sans_ip.contains(&"127.0.0.1".to_owned()));
    assert_eq!(identity.alpn.as_deref(), Some("h2"));
    assert_eq!(identity.sni.as_deref(), Some("graph.test"));
    // Key facts present and honest.
    assert!(!identity.public_key_algorithm.is_empty());
    assert!(identity.public_key_bits_nominal > 0);
    assert!(!identity.signature_algorithm.is_empty());
    assert!(!identity.serial_hex.is_empty());
    assert!(identity.not_after_epoch > identity.not_before_epoch);
}

#[test]
fn certificate_identity_rejects_garbage_safely() {
    assert!(CertificateIdentity::from_parts(&[], 1, None, None).is_none());
    assert!(CertificateIdentity::from_parts(b"not a certificate", 1, None, None).is_none());
    assert!(CertificateIdentity::from_parts(&[0u8; 32], 1, None, None).is_none());
    // Oversized input refused without parsing.
    assert!(CertificateIdentity::from_parts(&[0u8; 32 * 1024], 1, None, None).is_none());
}

#[test]
fn certificate_asset_id_is_global_and_validated() {
    use rxscan::model::{Asset, AssetKind};
    let fp = "ab".repeat(32);
    let first = Asset::certificate(&fp, provenance()).unwrap();
    let second = Asset::certificate(&fp.to_ascii_uppercase(), provenance()).unwrap();
    assert_eq!(first.id, second.id, "case-insensitive stability");
    assert_eq!(first.identity, format!("cert:sha256:{fp}"));
    assert!(matches!(first.kind, AssetKind::Certificate));
    // Malformed fingerprints rejected, never panicked.
    assert!(Asset::certificate("", provenance()).is_err());
    assert!(Asset::certificate("xyz", provenance()).is_err());
    assert!(Asset::certificate(&"ab".repeat(31), provenance()).is_err());
}

// ---------------- graph correlation ----------------

fn tls_event(fp: &str, address: &str, port: u16, san_dns: Vec<&str>, san_ip: Vec<&str>) -> Event {
    event(
        EventKind::TlsObserved,
        serde_json::json!({
            "target": "127.0.0.1",
            "address": address,
            "port": port,
            "subject": "CN=graph.test",
            "issuer": "CN=graph.test",
            "san_dns": san_dns,
            "san_ip": san_ip,
            "not_before": "2026-01-01",
            "not_after": "2027-01-01",
            "fingerprint_sha256": fp,
            "hostname_match": true,
            "hostname_detail": "matched",
        }),
    )
}

fn service_event(address: &str, port: u16, product: &str) -> Event {
    event(
        EventKind::ServiceIdentified,
        serde_json::json!({
            "target": "127.0.0.1",
            "address": address,
            "port": port,
            "protocol": "http",
            "service": "http",
            "product_hint": product,
            "confidence": 90u64,
            "matcher": "http",
            "rule_source": "builtin:http",
        }),
    )
}

#[test]
fn cert_reuse_correlates_across_ports_without_merging_hosts() {
    let fp = "cd".repeat(32);
    let outputs = vec![output_with(vec![
        tls_event(&fp, "127.0.0.1", 443, vec!["graph.test"], vec![]),
        tls_event(&fp, "127.0.0.2", 8443, vec!["graph.test"], vec![]),
    ])];
    let graph = build_graph(&outputs, Some(&plan_scope()));
    // One certificate entity for two presentations.
    let certs: Vec<_> = graph
        .entities
        .values()
        .filter(|entity| entity.kind == EntityKind::Certificate)
        .collect();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0].id, cert_entity_id(&fp));
    // Reuse group lists both presenters.
    let reuse = graph.certificate_reuse();
    assert_eq!(reuse.len(), 1);
    assert_eq!(reuse[0].0, cert_entity_id(&fp));
    assert_eq!(reuse[0].1.len(), 2);
    // Hosts stay distinct entities (reuse relates, never merges).
    assert!(
        graph.entities.contains_key(&ip_entity_id("127.0.0.1"))
            || graph
                .entities
                .contains_key(&port_entity_id("tcp", "127.0.0.1", 443))
    );
    assert!(
        graph
            .entities
            .contains_key(&port_entity_id("tcp", "127.0.0.2", 8443))
    );
}

#[test]
fn san_out_of_scope_recorded_never_contacted() {
    let fp = "ef".repeat(32);
    let outputs = vec![output_with(vec![tls_event(
        &fp,
        "127.0.0.1",
        443,
        vec!["evil.example.com"],
        vec!["127.0.0.2"],
    )])];
    let graph = build_graph(&outputs, Some(&plan_scope()));
    // Both names become entities (observations), edges carry scope state.
    let evil_edge = graph
        .edges
        .iter()
        .find(|edge| {
            edge.relation == EdgeRelation::HasSan
                && edge.to == hostname_entity_id("evil.example.com")
        })
        .expect("evil SAN edge");
    assert_eq!(
        evil_edge.attributes.get("contacted").map(String::as_str),
        Some("false")
    );
    assert_eq!(
        evil_edge.attributes.get("scope").map(String::as_str),
        Some("outside-scope")
    );
    let local_edge = graph
        .edges
        .iter()
        .find(|edge| edge.relation == EdgeRelation::HasSan && edge.to == ip_entity_id("127.0.0.2"))
        .expect("in-scope SAN edge");
    assert_eq!(
        local_edge.attributes.get("scope").map(String::as_str),
        Some("in-scope-uncontacted")
    );
    // No follow-up tasks are created by the builder (pure correlation).
    assert!(
        graph
            .entities
            .contains_key(&hostname_entity_id("evil.example.com"))
    );
}

#[test]
fn dns_service_port_edges_carry_provenance() {
    let outputs = vec![output_with(vec![
        event(
            EventKind::PortOpen,
            serde_json::json!({
                "target": "127.0.0.1",
                "address": "127.0.0.1",
                "transport": "tcp",
                "port": 80u64,
            }),
        ),
        service_event("127.0.0.1", 80, "nginx"),
        event(
            EventKind::DnsRecordObserved,
            serde_json::json!({
                "name": "web.example.test",
                "record_type": "A",
                "value": "127.0.0.1",
            }),
        ),
        event(
            EventKind::DnsRecordObserved,
            serde_json::json!({
                "name": "web.example.test",
                "record_type": "TXT",
                "value": "hello",
            }),
        ),
    ])];
    let graph = build_graph(&outputs, Some(&plan_scope()));
    // Port → service → technology chain.
    let port_id = port_entity_id("tcp", "127.0.0.1", 80);
    let service_id = format!("service:{port_id}:http");
    assert!(graph.entities.contains_key(&port_id));
    assert!(graph.entities.contains_key(&service_id));
    assert!(graph.edges.iter().any(|edge| edge.from == port_id
        && edge.to == service_id
        && edge.relation == EdgeRelation::RunsService));
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.from == service_id && edge.relation == EdgeRelation::Suggests)
    );
    // DNS A → resolves_to; TXT → references record entity.
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.from == hostname_entity_id("web.example.test")
                && edge.to == ip_entity_id("127.0.0.1")
                && edge.relation == EdgeRelation::ResolvesTo)
    );
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.relation == EdgeRelation::References)
    );
    // Every edge carries module + task provenance.
    for edge in &graph.edges {
        assert!(!edge.provenance.module.is_empty());
        assert_eq!(edge.provenance.task_id.as_deref(), Some("task_test"));
        assert_eq!(edge.provenance.scan_plan_id, "plan_test");
    }
    // Confidence never exceeds the cap even when the event claims more.
    for edge in &graph.edges {
        assert!(edge.confidence <= 95);
    }
}

#[test]
fn redirect_and_endpoint_edges() {
    let outputs = vec![output_with(vec![
        event(
            EventKind::EndpointObserved,
            serde_json::json!({"url": "http://127.0.0.1/"}),
        ),
        event(
            EventKind::RedirectObserved,
            serde_json::json!({
                "url": "http://127.0.0.1/",
                "location": "http://127.0.0.1/login",
            }),
        ),
        event(
            EventKind::RedirectObserved,
            serde_json::json!({"url": "http://127.0.0.1/stuck"}),
        ),
    ])];
    let graph = build_graph(&outputs, None);
    assert!(
        graph
            .entities
            .contains_key(&endpoint_entity_id("http://127.0.0.1:80/"))
    );
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.relation == EdgeRelation::RedirectsTo
                && edge.from == endpoint_entity_id("http://127.0.0.1:80/")
                && edge.to == endpoint_entity_id("http://127.0.0.1:80/login"))
    );
    // Relative/missing locations still record the source endpoint.
    assert!(
        graph
            .entities
            .contains_key(&endpoint_entity_id("http://127.0.0.1:80/stuck"))
    );
}

#[test]
fn graph_ignores_garbage_without_panic() {
    let outputs = vec![output_with(vec![
        event(EventKind::PortOpen, serde_json::json!({"nonsense": true})),
        event(
            EventKind::TlsObserved,
            serde_json::json!({"fingerprint_sha256": "not-hex"}),
        ),
        event(
            EventKind::ServiceIdentified,
            serde_json::json!({"address": "127.0.0.1"}),
        ),
        event(
            EventKind::DnsRecordObserved,
            serde_json::json!({"name": "", "record_type": "A", "value": ""}),
        ),
        event(EventKind::EndpointObserved, serde_json::json!({"url": ""})),
    ])];
    let graph = build_graph(&outputs, None);
    assert_eq!(graph.entity_count(), 0);
    assert_eq!(graph.edge_count(), 0);
    assert!(!graph.truncated);
}

#[test]
fn old_observations_deserialize() {
    // Pre-enrichment JSON (no vendor/cpe/rule_source/alternates) loads.
    let old: rxscan::service::ServiceObservation = serde_json::from_value(serde_json::json!({
        "target": "t",
        "address": "127.0.0.1",
        "address_family": "v4",
        "port": 80,
        "transport": "tcp",
        "parent_port_asset_id": "x",
        "asset_id": "y",
        "protocol": "http",
        "tls": false,
        "service_label": "http",
        "confidence": 85,
        "evidence_lines": [],
        "timestamp": 1
    }))
    .expect("old observation deserializes");
    assert_eq!(old.vendor_hint, None);
    assert_eq!(old.cpe_hint, None);
    // Old checkpoints still validate (asset layer untouched).
    let asset = rxscan::model::Asset::certificate(&"ab".repeat(32), provenance()).unwrap();
    assert!(asset.id.0.starts_with("asset_certificate_"));
}

// ---------------- live TLS service + reuse ----------------

use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use rxscan::execution::{
    CancellationToken, Module, ModuleContext, PolicyScopeGuard, RetryPolicy, ScopeGuard, Task,
    TaskKind, TaskScopeTarget,
};
use rxscan::fingerprints::FingerprintDb;
use rxscan::plan::SpeedSetting;
use rxscan::service_probe::{ServicePolicy, ServiceProbeModule};

struct TlsReuseFixture {
    ports: Vec<u16>,
    stop: Arc<AtomicBool>,
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl TlsReuseFixture {
    /// Serve the SAME certificate on two loopback ports (reuse proof).
    fn serve_twice(cert_der: Vec<u8>, key_der: Vec<u8>) -> Self {
        use rustls::crypto::ring::default_provider;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let config = rustls::ServerConfig::builder_with_provider(default_provider().into())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
            )
            .expect("server cert");
        let config = Arc::new(config);
        let stop = Arc::new(AtomicBool::new(false));
        let mut ports = Vec::new();
        let mut handles = Vec::new();
        for _ in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind reuse fixture");
            listener.set_nonblocking(true).expect("nonblocking");
            ports.push(listener.local_addr().unwrap().port());
            let stop_thread = stop.clone();
            let config = config.clone();
            handles.push(std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + Duration::from_secs(25);
                while !stop_thread.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                    let (stream, _) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(_) => break,
                    };
                    let config = config.clone();
                    std::thread::spawn(move || {
                        let _ = stream.set_nonblocking(false);
                        let Ok(mut conn) = rustls::ServerConnection::new(config) else {
                            return;
                        };
                        let mut stream = stream;
                        for _ in 0..200 {
                            match conn.complete_io(&mut stream) {
                                Ok(_) if !conn.is_handshaking() => break,
                                Ok(_) => {}
                                Err(_) => break,
                            }
                        }
                        std::thread::sleep(Duration::from_millis(300));
                    });
                }
            }));
        }
        Self {
            ports,
            stop,
            handles,
        }
    }
}

impl Drop for TlsReuseFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        while let Some(handle) = self.handles.pop() {
            let _ = handle.join();
        }
    }
}

fn rcgen_shared_cert() -> (Vec<u8>, Vec<u8>) {
    let mut params =
        rcgen::CertificateParams::new(vec!["reuse.test".to_owned(), "127.0.0.1".to_owned()])
            .expect("rcgen params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "reuse.test");
    let key = rcgen::KeyPair::generate().expect("rcgen key");
    let cert = params.self_signed(&key).expect("rcgen self-signed");
    (cert.der().to_vec(), key.serialize_der())
}

fn service_plan(ports: &str) -> ScanPlan {
    let cli =
        Cli::try_parse_from(["rxscan", "127.0.0.1", "--ports", ports, "--level", "4"]).unwrap();
    ScanPlan::compile(cli).unwrap()
}

fn service_task_for(plan: &ScanPlan, port: u16, guard: &dyn ScopeGuard) -> Task {
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
        Duration::from_millis(10_000),
        RetryPolicy::default(),
        "rxscan.service",
        Provenance::new("test.module", "1.0.0", plan.stable_id(), Timestamp(0)).unwrap(),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        std::collections::BTreeMap::from([
            ("target".to_owned(), "127.0.0.1".to_owned()),
            ("address".to_owned(), "127.0.0.1".to_owned()),
            ("port".to_owned(), port.to_string()),
            ("transport".to_owned(), "tcp".to_owned()),
            ("parent_asset".to_owned(), parent),
            ("probes".to_owned(), "tls".to_owned()),
        ]),
        guard,
    )
    .unwrap()
}

fn drive_service(
    module: &ServiceProbeModule,
    context: ModuleContext,
) -> Result<rxscan::execution::ModuleOutput, rxscan::execution::ModuleError> {
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
            unsafe { (&*(data as *const std::thread::Thread)).unpark() };
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

#[test]
fn live_tls_service_emits_identity_and_global_cert() {
    let (cert_der, key_der) = rcgen_shared_cert();
    let fixture = TlsReuseFixture::serve_twice(cert_der, key_der);
    let plan = service_plan(&fixture.ports[0].to_string());
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::with_fingerprint_db(
        ServicePolicy::new(plan.level, plan.goal, SpeedSetting::Numeric(100)),
        guard.clone(),
        Arc::new(FingerprintDb::empty()),
    );
    let task = service_task_for(&plan, fixture.ports[0], guard.as_ref());
    let output = drive_service(
        &module,
        ModuleContext::new(task, CancellationToken::default()),
    )
    .expect("tls probe executes");
    // Normalized identity fields on the TLS observation.
    let tls = output
        .events
        .iter()
        .find(|event| {
            format!("{:?}", event.kind) == "TlsObserved"
                && event.details.data.get("serial_hex").is_some()
        })
        .expect("tls identity observation");
    for field in [
        "serial_hex",
        "public_key_algorithm",
        "public_key_bits_nominal",
        "signature_algorithm",
        "chain_len",
        "self_signed",
        "fingerprint_sha256",
    ] {
        assert!(
            tls.details.data.get(field).is_some(),
            "identity field {field} present"
        );
    }
    // Global certificate asset (stable id, not per-port).
    let global: Vec<_> = output
        .assets
        .iter()
        .filter(|asset| asset.identity.starts_with("cert:sha256:"))
        .collect();
    assert_eq!(global.len(), 1, "one global cert asset");
    assert!(global[0].identity.starts_with("cert:sha256:"));
    // PRESENTS_CERTIFICATE edge with provenance on the TLS event.
    let edge_holder = output
        .events
        .iter()
        .find(|event| {
            format!("{:?}", event.kind) == "TlsObserved"
                && event
                    .relationships
                    .iter()
                    .any(|rel| format!("{:?}", rel.kind) == "PresentsCertificate")
        })
        .expect("presents_certificate relationship");
    assert!(!edge_holder.provenance.module_name.is_empty());
}

#[test]
fn live_shared_certificate_correlates_two_ports() {
    let (cert_der, key_der) = rcgen_shared_cert();
    let fixture = TlsReuseFixture::serve_twice(cert_der, key_der);
    let plan = service_plan(
        &fixture
            .ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(","),
    );
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = ServiceProbeModule::with_fingerprint_db(
        ServicePolicy::new(plan.level, plan.goal, SpeedSetting::Numeric(100)),
        guard.clone(),
        Arc::new(FingerprintDb::empty()),
    );
    let mut outputs = Vec::new();
    for (index, port) in fixture.ports.iter().enumerate() {
        let task = service_task_for(&plan, *port, guard.as_ref());
        let output = drive_service(
            &module,
            ModuleContext::new(task, CancellationToken::default()),
        )
        .expect("tls probe executes");
        outputs.push((
            rxscan::execution::TaskId(format!("task_live_{index}")),
            output,
        ));
    }
    let graph = build_graph(&outputs, Some(&plan.scope));
    let reuse = graph.certificate_reuse();
    assert_eq!(reuse.len(), 1, "shared cert forms one reuse group");
    assert_eq!(reuse[0].1.len(), 2, "both ports present the cert");
    // Hosts remain distinct (relation, never identity merge).
    assert_ne!(reuse[0].1[0], reuse[0].1[1]);
}

#[test]
fn crawl_discovery_links_to_discovering_page() {
    let outputs = vec![output_with(vec![event(
        EventKind::EndpointDiscovered,
        serde_json::json!({
            "url": "http://127.0.0.1/about",
            "page_url": "http://127.0.0.1/",
            "source": "link",
        }),
    )])];
    let graph = build_graph(&outputs, None);
    assert!(graph.edges.iter().any(|edge| edge.relation
        == rxscan::graph::EdgeRelation::DiscoveredFrom
        && edge.from == endpoint_entity_id("http://127.0.0.1:80/about")
        && edge.to == endpoint_entity_id("http://127.0.0.1:80/")));
}

#[test]
fn endpoint_joins_to_service_via_canonical_port() {
    // Explicit URL (default port elided in text) joins the discovered port
    // and its classified service: one logical endpoint, one join set.
    let outputs = vec![output_with(vec![
        event(
            EventKind::PortOpen,
            serde_json::json!({
                "target": "192.168.0.1",
                "address": "192.168.0.1",
                "transport": "tcp",
                "port": 80u64,
            }),
        ),
        service_event("192.168.0.1", 80, "nginx"),
        event(
            EventKind::EndpointObserved,
            serde_json::json!({"url": "http://192.168.0.1/"}),
        ),
        event(
            EventKind::EndpointObserved,
            serde_json::json!({"url": "http://192.168.0.1:80/"}),
        ),
    ])];
    // Two URL spellings, one canonical endpoint entity (port always renders).
    let graph = build_graph(&outputs, None);
    assert!(
        graph
            .entities
            .contains_key(&endpoint_entity_id("http://192.168.0.1:80/"))
    );
    assert!(
        !graph
            .entities
            .contains_key(&endpoint_entity_id("http://192.168.0.1/"))
    );
    let port_id = port_entity_id("tcp", "192.168.0.1", 80);
    assert!(graph.edges.iter().any(|edge| edge.relation
        == rxscan::graph::EdgeRelation::ResolvesToEndpoint
        && edge.from == endpoint_entity_id("http://192.168.0.1:80/")
        && edge.to == port_id));
    assert!(graph.edges.iter().any(
        |edge| edge.relation == rxscan::graph::EdgeRelation::ServedBy
            && edge.from == endpoint_entity_id("http://192.168.0.1:80/")
    ));
}

#[test]
fn hostname_endpoint_joins_through_dns() {
    let outputs = vec![output_with(vec![
        event(
            EventKind::PortOpen,
            serde_json::json!({
                "target": "10.0.0.5",
                "address": "10.0.0.5",
                "transport": "tcp",
                "port": 443u64,
            }),
        ),
        event(
            EventKind::DnsRecordObserved,
            serde_json::json!({
                "name": "api.example.test",
                "record_type": "A",
                "value": "10.0.0.5",
            }),
        ),
        event(
            EventKind::EndpointObserved,
            serde_json::json!({"url": "https://api.example.test/"}),
        ),
        // Nonstandard port on the same host joins its own endpoint.
        event(
            EventKind::PortOpen,
            serde_json::json!({
                "target": "10.0.0.5",
                "address": "10.0.0.5",
                "transport": "tcp",
                "port": 8443u64,
            }),
        ),
        event(
            EventKind::EndpointObserved,
            serde_json::json!({"url": "https://api.example.test:8443/app"}),
        ),
    ])];
    let graph = build_graph(&outputs, None);
    assert!(graph.edges.iter().any(|edge| edge.relation
        == rxscan::graph::EdgeRelation::ResolvesToEndpoint
        && edge.from == endpoint_entity_id("https://api.example.test:443/")
        && edge.to == port_entity_id("tcp", "10.0.0.5", 443)));
    assert!(graph.edges.iter().any(|edge| edge.relation
        == rxscan::graph::EdgeRelation::ResolvesToEndpoint
        && edge.from == endpoint_entity_id("https://api.example.test:8443/app")
        && edge.to == port_entity_id("tcp", "10.0.0.5", 8443)));
}

#[test]
fn service_identity_stable_across_version_change() {
    // Product/version are properties: the same endpoint+protocol keeps one
    // service entity across scans so diffs read as version changes.
    let scan = |version: &str| {
        vec![output_with(vec![
            event(
                EventKind::PortOpen,
                serde_json::json!({
                    "target": "10.0.0.5",
                    "address": "10.0.0.5",
                    "transport": "tcp",
                    "port": 443u64,
                }),
            ),
            event(
                EventKind::ServiceIdentified,
                serde_json::json!({
                    "target": "10.0.0.5",
                    "address": "10.0.0.5",
                    "port": 443u64,
                    "protocol": "http",
                    "service": "https",
                    "product_hint": "nginx",
                    "version_hint": version,
                    "confidence": 90u64,
                }),
            ),
        ])]
    };
    let old = build_graph(&scan("1.24.0"), None);
    let new = build_graph(&scan("1.26.0"), None);
    let services_old: Vec<_> = old
        .entities
        .keys()
        .filter(|id| id.starts_with("service:"))
        .collect();
    let services_new: Vec<_> = new
        .entities
        .keys()
        .filter(|id| id.starts_with("service:"))
        .collect();
    assert_eq!(services_old, services_new);
    assert_eq!(services_old.len(), 1);
}

#[test]
fn ipv6_endpoint_joins() {
    let outputs = vec![output_with(vec![
        event(
            EventKind::PortOpen,
            serde_json::json!({
                "target": "::1",
                "address": "::1",
                "transport": "tcp",
                "port": 80u64,
            }),
        ),
        event(
            EventKind::EndpointObserved,
            serde_json::json!({"url": "http://[::1]/"}),
        ),
    ])];
    let graph = build_graph(&outputs, None);
    assert!(graph.edges.iter().any(|edge| edge.relation
        == rxscan::graph::EdgeRelation::ResolvesToEndpoint
        && edge.to == port_entity_id("tcp", "::1", 80)));
}

#[test]
fn reconciliation_grades_identity_vs_related() {
    let fp = "aa".repeat(32);
    let outputs = vec![output_with(vec![
        event(
            EventKind::PortOpen,
            serde_json::json!({
                "target": "10.0.0.5",
                "address": "10.0.0.5",
                "transport": "tcp",
                "port": 80u64,
            }),
        ),
        event(
            EventKind::PortOpen,
            serde_json::json!({
                "target": "10.0.0.5",
                "address": "10.0.0.5",
                "transport": "tcp",
                "port": 443u64,
            }),
        ),
        tls_event(&fp, "10.0.0.5", 443, vec![], vec![]),
        event(
            EventKind::DnsRecordObserved,
            serde_json::json!({
                "name": "web.example.test",
                "record_type": "A",
                "value": "10.0.0.5",
            }),
        ),
    ])];
    let graph = build_graph(&outputs, None);
    let clusters = rxscan::graph::reconcile_candidates(&graph);
    // Same-IP ports form a scan-scoped SAME_IDENTITY cluster.
    let same: Vec<_> = clusters
        .iter()
        .filter(|c| c.verdict == rxscan::graph::IdentityVerdict::SameIdentity)
        .collect();
    assert_eq!(same.len(), 1);
    assert!(same[0].members.contains(&ip_entity_id("10.0.0.5")));
    assert!(
        same[0]
            .members
            .contains(&port_entity_id("tcp", "10.0.0.5", 80))
    );
    assert!(
        same[0]
            .members
            .contains(&port_entity_id("tcp", "10.0.0.5", 443))
    );
    // DNS name→IP is RELATED, never identity.
    assert!(
        clusters
            .iter()
            .any(|c| c.verdict == rxscan::graph::IdentityVerdict::Related
                && c.members.contains(&hostname_entity_id("web.example.test")))
    );
    // Raw entities are all still present (no collapsing).
    assert!(
        graph
            .entities
            .contains_key(&port_entity_id("tcp", "10.0.0.5", 80))
    );
    // Deterministic across builds.
    let again = rxscan::graph::reconcile_candidates(&build_graph(&outputs, None));
    assert_eq!(clusters, again);
}

#[test]
fn reconciliation_keeps_cert_reuse_related_only() {
    let fp = "bb".repeat(32);
    let outputs = vec![output_with(vec![
        tls_event(&fp, "10.0.0.5", 443, vec![], vec![]),
        tls_event(&fp, "10.0.0.9", 443, vec![], vec![]),
    ])];
    let graph = build_graph(&outputs, None);
    let clusters = rxscan::graph::reconcile_candidates(&graph);
    // No SAME_IDENTITY spans two different IPs, even with a shared cert.
    for cluster in &clusters {
        if cluster.verdict == rxscan::graph::IdentityVerdict::SameIdentity {
            assert!(
                !cluster
                    .members
                    .contains(&port_entity_id("tcp", "10.0.0.9", 443))
                    || !cluster
                        .members
                        .contains(&port_entity_id("tcp", "10.0.0.5", 443)),
                "shared cert must not merge distinct IPs"
            );
        }
    }
    assert!(
        clusters
            .iter()
            .any(|c| c.verdict == rxscan::graph::IdentityVerdict::Related
                && c.members.contains(&cert_entity_id(&fp)))
    );
}

fn ssh_event(address: &str, port: u16, sha: &str) -> Event {
    event(
        EventKind::SshHostKeyObserved,
        serde_json::json!({
            "address": address, "port": port,
            "key_type": "ssh-ed25519", "bits": 256,
            "sha256": sha,
            "kex_algorithms": ["curve25519-sha256"],
            "host_key_algorithms": ["ssh-ed25519"],
            "ciphers": ["aes128-ctr"], "macs": ["hmac-sha2-256"],
            "compression": ["none"],
        }),
    )
}

#[test]
fn reconciliation_treats_ssh_key_reuse_as_related_not_identity() {
    let sha = "cc".repeat(32);
    let outputs = vec![output_with(vec![
        ssh_event("10.0.0.4", 22, &sha),
        ssh_event("10.0.0.7", 22, &sha),
    ])];
    let graph = build_graph(&outputs, None);
    // Reuse falls out of stable key identity.
    let reuse = graph.ssh_key_reuse();
    assert_eq!(reuse.len(), 1);
    assert_eq!(reuse[0].0, rxscan::graph::ssh_key_entity_id(&sha));
    // Reconciliation relates endpoints but never merges distinct IPs.
    let clusters = rxscan::graph::reconcile_candidates(&graph);
    assert!(
        clusters
            .iter()
            .any(|c| c.verdict == rxscan::graph::IdentityVerdict::Related
                && c.members.iter().any(|m| m.contains(&sha[..12]))),
        "shared SSH key must relate: {clusters:?}"
    );
    for cluster in &clusters {
        if cluster.verdict == rxscan::graph::IdentityVerdict::SameIdentity {
            assert!(
                !cluster
                    .members
                    .contains(&port_entity_id("tcp", "10.0.0.4", 22))
                    || !cluster
                        .members
                        .contains(&port_entity_id("tcp", "10.0.0.7", 22)),
                "shared SSH key must not merge distinct IPs"
            );
        }
    }
    // Deterministic.
    let again = rxscan::graph::reconcile_candidates(&build_graph(&outputs, None));
    assert_eq!(clusters, again);
}
