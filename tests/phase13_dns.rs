//! Phase 13 DNS / asset intelligence tests: local UDP DNS fixtures only.

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use clap::Parser;
use rxscan::{
    cli::Cli,
    decision::Phase7Engine,
    dns::{
        DNS_MODULE_NAME, DnsModule, DnsOutcome, DnsPolicy, DnsRecordType, DnsRegistry,
        MAX_CNAME_HOPS, MAX_DNS_DOMAINS, MAX_DNS_RECORDS_PER_RESPONSE, MAX_DNS_RECORDS_PER_TASK,
        MAX_DNS_REGISTRY_ENTRIES, MAX_DNS_TASKS_PER_DOMAIN_HARD, canonical_hostname, domain_key,
        parse_dns_response, ptr_query_name, resolver_from_resolv_conf,
    },
    execution::{
        CancellationToken, DecisionEngine, Module, ModuleContext, ModuleError, PolicyScopeGuard,
        RetryPolicy, ScopeGuard, Task, TaskKind, TaskScopeTarget,
    },
    model::{AssetKind, EventKind, Provenance, RelationshipKind, Timestamp},
    output::JsonlWriter,
    plan::{ScanGoal, ScanPlan, SpeedSetting},
};

struct DnsFixture {
    addr: std::net::SocketAddr,
    queries: Arc<Mutex<Vec<(String, u16)>>>,
    stop: Arc<AtomicBool>,
}

impl DnsFixture {
    fn spawn(handler: impl Fn(&str, u16) -> DnsReply + Send + Sync + 'static) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind dns fixture");
        socket.set_nonblocking(true).unwrap();
        let addr = socket.local_addr().unwrap();
        let queries = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handler = Arc::new(handler);
        let queries_thread = queries.clone();
        let stop_thread = stop.clone();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            let mut buf = [0u8; 512];
            while !stop_thread.load(Ordering::SeqCst) && Instant::now() < deadline {
                match socket.recv_from(&mut buf) {
                    Ok((len, peer)) => {
                        let packet = &buf[..len];
                        if let Some((name, qtype)) = parse_question(packet) {
                            queries_thread.lock().unwrap().push((name.clone(), qtype));
                            let reply = handler(&name, qtype);
                            let response = dns_response(packet, &reply.answers, reply.rcode);
                            let _ = socket.send_to(&response, peer);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            queries,
            stop,
        }
    }

    fn queries(&self) -> Vec<(String, u16)> {
        self.queries.lock().unwrap().clone()
    }
}

impl Drop for DnsFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[derive(Clone)]
enum Answer {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(&'static str),
    Mx(u16, &'static str),
    Ns(&'static str),
    Txt(&'static str),
    Ptr(&'static str),
}

struct DnsReply {
    answers: Vec<Answer>,
    rcode: u16,
}

impl DnsReply {
    fn answers(answers: Vec<Answer>) -> Self {
        Self { answers, rcode: 0 }
    }

    fn rcode(rcode: u16) -> Self {
        Self {
            answers: Vec::new(),
            rcode,
        }
    }
}

fn parse_question(packet: &[u8]) -> Option<(String, u16)> {
    let mut pos = 12usize;
    let mut labels = Vec::new();
    loop {
        let len = *packet.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        labels.push(
            std::str::from_utf8(packet.get(pos..pos + len)?)
                .ok()?
                .to_owned(),
        );
        pos += len;
    }
    let qtype = u16::from_be_bytes([*packet.get(pos)?, *packet.get(pos + 1)?]);
    Some((labels.join(".").to_ascii_lowercase(), qtype))
}

fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn dns_response(query: &[u8], answers: &[Answer], rcode: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&query[0..2]);
    out.extend_from_slice(&(0x8180u16 | rcode).to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query[12..]);
    for answer in answers {
        out.extend_from_slice(&[0xc0, 0x0c]);
        match answer {
            Answer::A(_) => out.extend_from_slice(&1u16.to_be_bytes()),
            Answer::Aaaa(_) => out.extend_from_slice(&28u16.to_be_bytes()),
            Answer::Cname(_) => out.extend_from_slice(&5u16.to_be_bytes()),
            Answer::Mx(_, _) => out.extend_from_slice(&15u16.to_be_bytes()),
            Answer::Ns(_) => out.extend_from_slice(&2u16.to_be_bytes()),
            Answer::Txt(_) => out.extend_from_slice(&16u16.to_be_bytes()),
            Answer::Ptr(_) => out.extend_from_slice(&12u16.to_be_bytes()),
        }
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        let mut rdata = Vec::new();
        match answer {
            Answer::A(ip) => rdata.extend_from_slice(&ip.octets()),
            Answer::Aaaa(ip) => rdata.extend_from_slice(&ip.octets()),
            Answer::Cname(name) | Answer::Ns(name) | Answer::Ptr(name) => {
                encode_name(name, &mut rdata)
            }
            Answer::Mx(pref, name) => {
                rdata.extend_from_slice(&pref.to_be_bytes());
                encode_name(name, &mut rdata);
            }
            Answer::Txt(text) => {
                let bytes = text.as_bytes();
                rdata.push(bytes.len().min(255) as u8);
                rdata.extend_from_slice(&bytes[..bytes.len().min(255)]);
            }
        }
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    out
}

fn query_packet(name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x5258u16.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    encode_name(name, &mut out);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

fn response_with_answer_rdata(name: &str, qtype: u16, answer_type: u16, rdata: &[u8]) -> Vec<u8> {
    let query = query_packet(name, qtype);
    let mut out = Vec::new();
    out.extend_from_slice(&query[0..2]);
    out.extend_from_slice(&0x8180u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query[12..]);
    out.extend_from_slice(&[0xc0, 0x0c]);
    out.extend_from_slice(&answer_type.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&60u32.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

fn plan(target: &str, level: &str) -> ScanPlan {
    ScanPlan::compile(
        Cli::try_parse_from(["rxscan", target, "--scope", target, "--level", level]).unwrap(),
    )
    .unwrap()
}

fn plan_with_scopes(target: &str, level: &str, scopes: &[&str]) -> ScanPlan {
    let mut args = vec!["rxscan", target, "--level", level];
    for scope in scopes {
        args.push("--scope");
        args.push(scope);
    }
    ScanPlan::compile(Cli::try_parse_from(args).unwrap()).unwrap()
}

fn dns_task(
    plan: &ScanPlan,
    host: &str,
    resolver: &str,
    record_types: &str,
    guard: &dyn ScopeGuard,
) -> Task {
    Task::new_with_params(
        TaskKind::DnsProbe,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        30,
        Duration::from_secs(5),
        RetryPolicy::default(),
        DNS_MODULE_NAME,
        Provenance::new(DNS_MODULE_NAME, "13.0.0", plan.stable_id(), Timestamp(0)).unwrap(),
        TaskScopeTarget::Host(host.to_owned()),
        BTreeMap::from([
            ("hostname".to_owned(), host.to_owned()),
            ("resolver".to_owned(), resolver.to_owned()),
            ("record_types".to_owned(), record_types.to_owned()),
        ]),
        guard,
    )
    .unwrap()
}

fn block_on(
    module: &dyn Module,
    context: ModuleContext,
) -> Result<rxscan::execution::ModuleOutput, ModuleError> {
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
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
    let mut cx = Context::from_waker(&waker);
    let mut future = module.execute(context);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => break value,
            Poll::Pending => std::thread::park(),
        }
    }
}

#[test]
fn hostname_canonicalization_rejects_bad_names() {
    assert_eq!(
        canonical_hostname("WWW.Example.TEST.").unwrap(),
        "www.example.test"
    );
    assert!(canonical_hostname("").is_err());
    assert!(canonical_hostname("-bad.example").is_err());
    assert!(canonical_hostname("bad..example").is_err());
    assert!(canonical_hostname("www.example.test..").is_err());
    assert!(canonical_hostname(&format!("{}.example", "a".repeat(64))).is_err());
    assert!(canonical_hostname(&format!("{}.test", "a".repeat(254))).is_err());
    assert!(canonical_hostname("bad_name.example").is_err());
}

#[test]
fn resolver_config_parses_local_nameservers_without_public_fallback() {
    assert_eq!(
        resolver_from_resolv_conf("#x\n nameserver 127.0.0.53 \n").unwrap(),
        "127.0.0.53:53".parse().unwrap()
    );
    assert_eq!(
        resolver_from_resolv_conf("nameserver ::1\nnameserver 127.0.0.1").unwrap(),
        "[::1]:53".parse().unwrap()
    );
    assert!(resolver_from_resolv_conf("search example.test\nnameserver nope\n").is_err());
    assert!(resolver_from_resolv_conf("# none\n").is_err());
}

#[test]
fn ptr_reverse_names_are_canonical_for_ipv4_and_ipv6() {
    assert_eq!(
        ptr_query_name(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        "1.0.0.127.in-addr.arpa"
    );
    assert_eq!(
        ptr_query_name(std::net::IpAddr::V6(Ipv6Addr::LOCALHOST)),
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
    );
}

#[test]
fn parser_reports_truncated_udp_as_incomplete_not_resolved() {
    let query = query_packet("www.example.test", 1);
    let mut packet = Vec::new();
    packet.extend_from_slice(&query[0..2]);
    packet.extend_from_slice(&0x8380u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&query[12..]);
    packet.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
    let parsed = parse_dns_response(&packet, "www.example.test", DnsRecordType::A).unwrap();
    assert_eq!(parsed.outcome, DnsOutcome::Truncated);
    assert!(parsed.records.is_empty());
}

#[test]
fn parser_rejects_malformed_compression_and_rdata_without_panic() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "pointer-to-self",
            response_with_answer_rdata("www.example.test", 5, 5, &[0xc0, 0x21]),
        ),
        (
            "two-pointer-loop",
            response_with_answer_rdata("www.example.test", 5, 5, &[0xc0, 0x23, 0xc0, 0x21]),
        ),
        (
            "pointer-beyond-packet",
            response_with_answer_rdata("www.example.test", 5, 5, &[0xc0, 0xff]),
        ),
        (
            "pointer-into-malformed-label",
            response_with_answer_rdata("www.example.test", 5, 5, &[0xc0, 0x20]),
        ),
        (
            "truncated-pointer-byte",
            response_with_answer_rdata("www.example.test", 5, 5, &[0xc0]),
        ),
        (
            "label-over-63",
            response_with_answer_rdata("www.example.test", 5, 5, &[64, b'a', 0]),
        ),
        ("rdata-overflow", {
            let mut p = response_with_answer_rdata("www.example.test", 1, 1, &[127, 0, 0, 1]);
            let len = p.len();
            p[len - 6] = 0xff;
            p[len - 5] = 0xff;
            p
        }),
        ("answer-count-larger-than-available", {
            let mut p = dns_response(&query_packet("www.example.test", 1), &[], 0);
            p[6] = 0;
            p[7] = 1;
            p
        }),
    ];
    for (name, packet) in cases {
        let result = std::panic::catch_unwind(|| {
            parse_dns_response(&packet, "www.example.test", DnsRecordType::A)
        });
        assert!(result.is_ok(), "{name} panicked");
        assert!(result.unwrap().is_err(), "{name} parsed as valid");
    }
}

#[test]
fn parser_rejects_transaction_question_label_and_count_mismatches() {
    let mut tx = dns_response(
        &query_packet("www.example.test", 1),
        &[Answer::A(Ipv4Addr::LOCALHOST)],
        0,
    );
    tx[0] = 0;
    assert!(parse_dns_response(&tx, "www.example.test", DnsRecordType::A).is_err());

    let wrong_question = dns_response(
        &query_packet("other.example.test", 1),
        &[Answer::A(Ipv4Addr::LOCALHOST)],
        0,
    );
    assert!(parse_dns_response(&wrong_question, "www.example.test", DnsRecordType::A).is_err());

    assert!(parse_dns_response(&[0u8; 4], "www.example.test", DnsRecordType::A).is_err());

    let mut excessive_counts = dns_response(
        &query_packet("www.example.test", 1),
        &[Answer::A(Ipv4Addr::LOCALHOST)],
        0,
    );
    excessive_counts[4] = 0;
    excessive_counts[5] = 2;
    assert!(parse_dns_response(&excessive_counts, "www.example.test", DnsRecordType::A).is_err());
}

#[test]
fn txt_rdata_parsing_is_framed_and_bounded() {
    let packet = response_with_answer_rdata(
        "www.example.test",
        16,
        16,
        &[3, b'o', b'n', b'e', 3, b't', b'w', b'o'],
    );
    let parsed = parse_dns_response(&packet, "www.example.test", DnsRecordType::Txt).unwrap();
    assert_eq!(parsed.records[0].value, "onetwo");

    let empty = response_with_answer_rdata("www.example.test", 16, 16, &[0]);
    let parsed = parse_dns_response(&empty, "www.example.test", DnsRecordType::Txt).unwrap();
    assert_eq!(parsed.records[0].value, "");

    let malformed = response_with_answer_rdata("www.example.test", 16, 16, &[10, b'x']);
    assert!(parse_dns_response(&malformed, "www.example.test", DnsRecordType::Txt).is_err());
}

#[test]
fn cname_chain_loop_and_depth_are_bounded_with_query_counts() {
    let fixture = DnsFixture::spawn(|name, qtype| {
        if qtype != 1 {
            return DnsReply::answers(Vec::new());
        }
        match name {
            "www.example.test" => DnsReply::answers(vec![Answer::Cname("a.example.test")]),
            "a.example.test" => DnsReply::answers(vec![Answer::Cname("b.example.test")]),
            "b.example.test" => DnsReply::answers(vec![Answer::A(Ipv4Addr::LOCALHOST)]),
            "loop.example.test" => DnsReply::answers(vec![Answer::Cname("loop-a.example.test")]),
            "loop-a.example.test" => DnsReply::answers(vec![Answer::Cname("loop-b.example.test")]),
            "loop-b.example.test" => DnsReply::answers(vec![Answer::Cname("loop-a.example.test")]),
            name if name.starts_with("deep") => {
                let first = name
                    .strip_prefix("deep")
                    .and_then(|rest| rest.strip_suffix(".example.test"))
                    .and_then(|n| n.parse::<usize>().ok())
                    .unwrap_or(0);
                DnsReply::answers(vec![Answer::Cname(Box::leak(
                    format!("deep{}.example.test", first + 1).into_boxed_str(),
                ))])
            }
            _ => DnsReply::answers(Vec::new()),
        }
    });
    let plan = plan_with_scopes(
        "www.example.test",
        "5",
        &[
            "www.example.test",
            "loop.example.test",
            "deep0.example.test",
        ],
    );
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));

    let module = DnsModule::new(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let output = block_on(
        &module,
        ModuleContext::new(
            dns_task(
                &plan,
                "www.example.test",
                &fixture.addr.to_string(),
                "A",
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(output.events.iter().any(|event| {
        event
            .relationships
            .iter()
            .any(|rel| rel.kind == RelationshipKind::HostnameAliasesTo)
    }));
    assert_eq!(fixture.queries().len(), 3);

    let loop_module = DnsModule::new(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let before = fixture.queries().len();
    let output = block_on(
        &loop_module,
        ModuleContext::new(
            dns_task(
                &plan,
                "loop.example.test",
                &fixture.addr.to_string(),
                "A",
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(output.events.iter().any(|event| {
        event.kind == EventKind::DnsBudgetExhausted
            && event.details.data["reason"] == serde_json::json!("cname-loop")
    }));
    assert_eq!(fixture.queries().len() - before, 3);

    let depth_module = DnsModule::new(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let before = fixture.queries().len();
    let output = block_on(
        &depth_module,
        ModuleContext::new(
            dns_task(
                &plan,
                "deep0.example.test",
                &fixture.addr.to_string(),
                "A",
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(output.events.iter().any(|event| {
        event.kind == EventKind::DnsBudgetExhausted
            && event.details.data["reason"] == serde_json::json!("cname-depth")
    }));
    assert_eq!(fixture.queries().len() - before, MAX_CNAME_HOPS);
}

#[test]
fn query_dedup_cross_batch_keeps_record_types_and_transient_failures_distinct() {
    let fixture = DnsFixture::spawn(|name, qtype| match (name, qtype) {
        ("foo.example.test", 1) => DnsReply::answers(vec![Answer::A(Ipv4Addr::LOCALHOST)]),
        ("foo.example.test", 28) => DnsReply::answers(vec![Answer::Aaaa(Ipv6Addr::LOCALHOST)]),
        ("bar.example.test", 1) => DnsReply::answers(vec![Answer::A(Ipv4Addr::LOCALHOST)]),
        _ => DnsReply::answers(Vec::new()),
    });
    let plan = plan_with_scopes(
        "foo.example.test",
        "5",
        &["foo.example.test", "bar.example.test"],
    );
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let registry = DnsRegistry::new();
    let module = DnsModule::with_registry(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
        registry.clone(),
    );

    for _ in 0..2 {
        block_on(
            &module,
            ModuleContext::new(
                dns_task(
                    &plan,
                    "foo.example.test",
                    &fixture.addr.to_string(),
                    "A",
                    guard.as_ref(),
                ),
                CancellationToken::default(),
            ),
        )
        .unwrap();
    }
    assert_eq!(
        fixture
            .queries()
            .iter()
            .filter(|(name, qtype)| name == "foo.example.test" && *qtype == 1)
            .count(),
        1
    );

    block_on(
        &module,
        ModuleContext::new(
            dns_task(
                &plan,
                "foo.example.test",
                &fixture.addr.to_string(),
                "AAAA",
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    block_on(
        &module,
        ModuleContext::new(
            dns_task(
                &plan,
                "bar.example.test",
                &fixture.addr.to_string(),
                "A",
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(registry.query_count() >= 3);

    let timeout_module = DnsModule::with_registry(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
        registry.clone(),
    );
    let before = registry.query_count();
    let _ = block_on(
        &timeout_module,
        ModuleContext::new(
            dns_task(
                &plan,
                "foo.example.test",
                "127.0.0.1:9",
                "TXT",
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert_eq!(registry.query_count(), before);
}

#[test]
fn registry_capacity_and_per_domain_budget_are_bounded_and_fair() {
    let registry = DnsRegistry::new();
    let resolver = "127.0.0.1:53".parse().unwrap();
    for index in 0..MAX_DNS_REGISTRY_ENTRIES {
        assert!(registry.claim_query(
            &format!("h{index}.example.test"),
            DnsRecordType::A,
            resolver
        ));
    }
    assert_eq!(registry.query_count(), MAX_DNS_REGISTRY_ENTRIES);
    assert!(registry.claim_query("overflow.example.test", DnsRecordType::A, resolver));
    assert_eq!(registry.query_count(), MAX_DNS_REGISTRY_ENTRIES);

    for index in 0..MAX_DNS_TASKS_PER_DOMAIN_HARD {
        assert!(registry.claim_domain_task(
            "example.test",
            &format!("a{index}.example.test"),
            MAX_DNS_TASKS_PER_DOMAIN_HARD,
        ));
    }
    assert!(!registry.claim_domain_task(
        "example.test",
        "too-many.example.test",
        MAX_DNS_TASKS_PER_DOMAIN_HARD,
    ));
    assert!(registry.claim_domain_task(
        "other.test",
        "first.other.test",
        MAX_DNS_TASKS_PER_DOMAIN_HARD,
    ));
    assert_eq!(
        registry.tracked_names_for_domain("example.test"),
        MAX_DNS_TASKS_PER_DOMAIN_HARD
    );

    let domain_registry = DnsRegistry::new();
    for index in 0..MAX_DNS_DOMAINS {
        assert!(domain_registry.claim_domain_task(
            &format!("d{index}.test"),
            &format!("h.d{index}.test"),
            MAX_DNS_TASKS_PER_DOMAIN_HARD,
        ));
    }
    assert!(!domain_registry.claim_domain_task(
        "overflow.test",
        "h.overflow.test",
        MAX_DNS_TASKS_PER_DOMAIN_HARD,
    ));
    assert_eq!(domain_registry.domain_count(), MAX_DNS_DOMAINS);
}

#[test]
fn production_per_domain_budget_persists_across_batches_and_allows_other_domains() {
    let fixture = DnsFixture::spawn(|_, qtype| match qtype {
        1 => DnsReply::answers(vec![Answer::A(Ipv4Addr::LOCALHOST)]),
        _ => DnsReply::answers(Vec::new()),
    });
    let mut scopes = Vec::new();
    for index in 0..(MAX_DNS_TASKS_PER_DOMAIN_HARD + 2) {
        scopes.push(format!("h{index}.example.test"));
    }
    scopes.push("first.other.test".to_owned());
    let scope_refs = scopes.iter().map(String::as_str).collect::<Vec<_>>();
    let plan = plan_with_scopes("h0.example.test", "5", &scope_refs);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let registry = DnsRegistry::new();
    let module = DnsModule::with_registry(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
        registry.clone(),
    );

    for index in 0..MAX_DNS_TASKS_PER_DOMAIN_HARD {
        let host = format!("h{index}.example.test");
        block_on(
            &module,
            ModuleContext::new(
                dns_task(&plan, &host, &fixture.addr.to_string(), "A", guard.as_ref()),
                CancellationToken::default(),
            ),
        )
        .unwrap();
    }
    let before = fixture.queries().len();
    let exhausted = block_on(
        &module,
        ModuleContext::new(
            dns_task(
                &plan,
                &format!("h{}.example.test", MAX_DNS_TASKS_PER_DOMAIN_HARD + 1),
                &fixture.addr.to_string(),
                "A",
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert_eq!(fixture.queries().len(), before);
    assert!(exhausted.events.iter().any(|event| {
        event.kind == EventKind::DnsBudgetExhausted
            && event.details.data["reason"] == serde_json::json!("per-domain-task-budget")
            && event.details.data["domain"] == serde_json::json!("example.test")
    }));

    block_on(
        &module,
        ModuleContext::new(
            dns_task(
                &plan,
                "first.other.test",
                &fixture.addr.to_string(),
                "A",
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert_eq!(fixture.queries().len(), before + 1);
    assert_eq!(
        registry.tracked_names_for_domain(&domain_key("h0.example.test")),
        MAX_DNS_TASKS_PER_DOMAIN_HARD
    );
}

#[test]
fn records_events_evidence_and_txt_bytes_are_capped_without_unbounded_growth() {
    let answers = (0..(MAX_DNS_RECORDS_PER_RESPONSE + 8))
        .map(|i| Answer::A(Ipv4Addr::new(127, 0, 0, (i % 250 + 1) as u8)))
        .collect::<Vec<_>>();
    let fixture = DnsFixture::spawn(move |_, qtype| match qtype {
        1 => DnsReply::answers(answers.clone()),
        16 => DnsReply::answers(vec![
            Answer::Txt(Box::leak("x".repeat(300).into_boxed_str())),
            Answer::Txt(Box::leak("y".repeat(300).into_boxed_str())),
            Answer::Txt(Box::leak("z".repeat(300).into_boxed_str())),
            Answer::Txt(Box::leak("q".repeat(300).into_boxed_str())),
            Answer::Txt(Box::leak("r".repeat(300).into_boxed_str())),
        ]),
        _ => DnsReply::answers(Vec::new()),
    });
    let plan = plan("www.example.test", "5");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = DnsModule::new(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let output = block_on(
        &module,
        ModuleContext::new(
            dns_task(
                &plan,
                "www.example.test",
                &fixture.addr.to_string(),
                "A,TXT",
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(output.events.len() <= rxscan::dns::MAX_DNS_EVENTS_PER_TASK);
    assert!(output.evidence.len() <= rxscan::dns::MAX_DNS_EVIDENCE_PER_TASK);
    assert!(
        output
            .events
            .iter()
            .filter(|event| event.kind == EventKind::DnsRecordObserved)
            .count()
            <= MAX_DNS_RECORDS_PER_TASK
    );
    assert!(
        output
            .assets
            .iter()
            .filter(|asset| asset.kind == AssetKind::Ip)
            .count()
            <= MAX_DNS_RECORDS_PER_RESPONSE
    );
}

#[test]
fn ptr_records_are_observational_and_do_not_create_active_followup() {
    let ptr_name = ptr_query_name(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    let fixture = DnsFixture::spawn(move |name, qtype| match (name, qtype) {
        (name, 12) if name == ptr_name => DnsReply::answers(vec![Answer::Ptr("www.example.test")]),
        _ => DnsReply::answers(Vec::new()),
    });
    let plan = plan_with_scopes("127.0.0.1", "5", &["127.0.0.1"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = DnsModule::new(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let task = Task::new_with_params(
        TaskKind::DnsProbe,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        30,
        Duration::from_secs(5),
        RetryPolicy::default(),
        DNS_MODULE_NAME,
        Provenance::new(DNS_MODULE_NAME, "13.0.0", plan.stable_id(), Timestamp(0)).unwrap(),
        TaskScopeTarget::Ip(Ipv4Addr::new(127, 0, 0, 1).into()),
        BTreeMap::from([("resolver".to_owned(), fixture.addr.to_string())]),
        guard.as_ref(),
    )
    .unwrap();
    let output = block_on(
        &module,
        ModuleContext::new(task.clone(), CancellationToken::default()),
    )
    .unwrap();
    assert!(output.events.iter().any(|event| {
        event
            .relationships
            .iter()
            .any(|rel| rel.kind == RelationshipKind::ReverseResolvesTo)
    }));
    let engine = Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        5,
        ScanGoal::Recon,
        plan.tcp_ports.clone(),
        SpeedSetting::Numeric(100),
    );
    assert!(engine.follow_up_tasks(&task, &output).is_empty());
}

#[test]
fn ipv6_udp_dns_resolution_runs_when_loopback_ipv6_is_available() {
    let socket = match UdpSocket::bind("[::1]:0") {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("skipping IPv6 UDP DNS fixture: {error}");
            return;
        }
    };
    socket.set_nonblocking(true).unwrap();
    let addr = socket.local_addr().unwrap();
    let queries = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let queries_thread = queries.clone();
    let stop_thread = stop.clone();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut buf = [0u8; 512];
        while !stop_thread.load(Ordering::SeqCst) && Instant::now() < deadline {
            match socket.recv_from(&mut buf) {
                Ok((len, peer)) => {
                    let packet = &buf[..len];
                    if let Some((name, qtype)) = parse_question(packet) {
                        queries_thread.lock().unwrap().push((name, qtype));
                        let response =
                            dns_response(packet, &[Answer::Aaaa(Ipv6Addr::LOCALHOST)], 0);
                        let _ = socket.send_to(&response, peer);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
    });

    let plan = plan_with_scopes("v6.example.test", "5", &["v6.example.test", "::1"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = DnsModule::new(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let output = block_on(
        &module,
        ModuleContext::new(
            dns_task(
                &plan,
                "v6.example.test",
                &addr.to_string(),
                "AAAA",
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    stop.store(true, Ordering::SeqCst);
    assert_eq!(queries.lock().unwrap().len(), 1);
    assert!(output.assets.iter().any(|asset| {
        asset.kind == AssetKind::Ip && asset.identity == Ipv6Addr::LOCALHOST.to_string()
    }));
}

#[test]
fn level_speed_and_task_identity_are_semantically_stable() {
    assert_eq!(
        DnsPolicy::new(1, ScanGoal::Recon, SpeedSetting::Numeric(10))
            .record_types()
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>(),
        vec!["A", "AAAA", "CNAME"]
    );
    assert_eq!(
        DnsPolicy::new(3, ScanGoal::Recon, SpeedSetting::Numeric(10))
            .record_types()
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>(),
        vec!["A", "AAAA", "CNAME", "MX", "NS"]
    );
    assert_eq!(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(10))
            .record_types()
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>(),
        vec!["A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR"]
    );
    assert_eq!(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(10)).record_types(),
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)).record_types()
    );
    assert_eq!(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(10)).per_domain_limit(),
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)).per_domain_limit()
    );

    let plan = plan("foo.example.test", "5");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let a = dns_task(
        &plan,
        "foo.example.test",
        "127.0.0.1:53",
        "A",
        guard.as_ref(),
    );
    let b = dns_task(
        &plan,
        "foo.example.test",
        "127.0.0.1:53",
        "A",
        guard.as_ref(),
    );
    let aaaa = dns_task(
        &plan,
        "foo.example.test",
        "127.0.0.1:53",
        "AAAA",
        guard.as_ref(),
    );
    assert_eq!(a.id, b.id);
    assert_ne!(a.id, aaaa.id);
}

#[test]
fn dns_records_assets_relationships_and_jsonl_are_observed() {
    let fixture = DnsFixture::spawn(|name, qtype| {
        DnsReply::answers(match (name, qtype) {
            ("www.example.test", 1) => vec![
                Answer::Cname("edge.example.test"),
                Answer::A(Ipv4Addr::new(127, 0, 0, 1)),
                Answer::A(Ipv4Addr::new(127, 0, 0, 2)),
            ],
            ("www.example.test", 28) => vec![Answer::Aaaa(Ipv6Addr::LOCALHOST)],
            ("www.example.test", 15) => vec![Answer::Mx(10, "mail.example.test")],
            ("www.example.test", 2) => vec![Answer::Ns("ns1.example.test")],
            ("www.example.test", 16) => vec![Answer::Txt("v=example")],
            _ => Vec::new(),
        })
    });
    let plan = plan("www.example.test", "5");
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let module = DnsModule::new(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let output = block_on(
        &module,
        ModuleContext::new(
            dns_task(
                &plan,
                "www.example.test",
                &fixture.addr.to_string(),
                "A,AAAA,MX,NS,TXT",
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(
        output
            .assets
            .iter()
            .any(|asset| asset.kind == AssetKind::Host && asset.identity == "www.example.test")
    );
    assert!(
        output
            .assets
            .iter()
            .any(|asset| asset.kind == AssetKind::Ip && asset.identity == "127.0.0.1")
    );
    assert!(output.events.iter().any(|event| {
        event
            .relationships
            .iter()
            .any(|rel| rel.kind == RelationshipKind::HostnameAliasesTo)
    }));
    assert!(output.events.iter().any(|event| {
        event
            .relationships
            .iter()
            .any(|rel| rel.kind == RelationshipKind::HostnameResolvesToIp)
    }));
    assert!(output.events.iter().any(|event| {
        event
            .relationships
            .iter()
            .any(|rel| rel.kind == RelationshipKind::MailExchangeFor)
    }));
    assert!(output.events.iter().any(|event| {
        event
            .relationships
            .iter()
            .any(|rel| rel.kind == RelationshipKind::NameServerFor)
    }));
    let mut bytes = Vec::new();
    {
        let mut writer = JsonlWriter::new(&mut bytes, 1024 * 1024);
        for event in &output.events {
            writer.write_event(event).unwrap();
        }
    }
    assert!(!bytes.is_empty());
}

#[test]
fn dns_failures_dedup_cancellation_and_timeout_are_bounded() {
    let fixture = DnsFixture::spawn(|name, _| match name {
        "nx.example.test" => DnsReply::rcode(3),
        "servfail.example.test" => DnsReply::rcode(2),
        "refused.example.test" => DnsReply::rcode(5),
        _ => DnsReply::answers(Vec::new()),
    });
    let plan = plan_with_scopes(
        "nx.example.test",
        "5",
        &[
            "nx.example.test",
            "servfail.example.test",
            "refused.example.test",
            "slow.example.test",
        ],
    );
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let registry = rxscan::dns::DnsRegistry::new();
    let module = DnsModule::with_registry(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
        registry,
    );
    let cancel = CancellationToken::default();
    cancel.cancel();
    let cancelled = block_on(
        &module,
        ModuleContext::new(
            dns_task(
                &plan,
                "nx.example.test",
                &fixture.addr.to_string(),
                "A",
                guard.as_ref(),
            ),
            cancel,
        ),
    );
    assert!(matches!(cancelled, Err(ModuleError::Cancelled)));
    assert!(fixture.queries().is_empty());

    for (host, outcome) in [
        ("nx.example.test", DnsOutcome::NxDomain),
        ("servfail.example.test", DnsOutcome::ServFail),
        ("refused.example.test", DnsOutcome::Refused),
    ] {
        let output = block_on(
            &module,
            ModuleContext::new(
                dns_task(&plan, host, &fixture.addr.to_string(), "A", guard.as_ref()),
                CancellationToken::default(),
            ),
        )
        .unwrap();
        assert!(output.events.iter().any(|event| {
            matches!(event.kind, EventKind::DnsQueryFailed)
                && event.details.data["outcome"] == serde_json::json!(outcome)
        }));
    }

    let before = fixture.queries().len();
    let _ = block_on(
        &module,
        ModuleContext::new(
            dns_task(
                &plan,
                "nx.example.test",
                &fixture.addr.to_string(),
                "A",
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert_eq!(fixture.queries().len(), before);

    let timeout_module = DnsModule::new(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
    );
    let output = block_on(
        &timeout_module,
        ModuleContext::new(
            dns_task(
                &plan,
                "slow.example.test",
                "127.0.0.1:9",
                "A",
                guard.as_ref(),
            ),
            CancellationToken::default(),
        ),
    )
    .unwrap();
    assert!(output.events.iter().any(|event| {
        matches!(event.kind, EventKind::DnsQueryFailed)
            && matches!(
                event.details.data["outcome"].as_str(),
                Some("timeout" | "transport_error")
            )
    }));
}

#[test]
fn decision_engine_proposes_in_scope_host_followup_and_blocks_third_party() {
    let plan = plan_with_scopes("127.0.0.1", "5", &["127.0.0.1", "www.example.test"]);
    let guard = Arc::new(PolicyScopeGuard::new(plan.scope.clone()));
    let engine = Phase7Engine::new(
        guard.clone(),
        plan.stable_id(),
        5,
        ScanGoal::Recon,
        plan.tcp_ports.clone(),
        SpeedSetting::Numeric(100),
    );
    let provenance = Provenance::new("test", "13.0.0", plan.stable_id(), Timestamp(0)).unwrap();
    let event = |value: &str| {
        rxscan::model::Event::new(
            EventKind::DnsRecordObserved,
            None,
            rxscan::model::BoundedDetails::from_value(
                serde_json::json!({"name": "www.example.test", "record_type": "A", "value": value, "ttl": 60}),
                4096,
            )
            .unwrap(),
            provenance.clone(),
        )
        .unwrap()
    };
    let task = dns_task(
        &plan,
        "www.example.test",
        "127.0.0.1:53",
        "A",
        guard.as_ref(),
    );
    let in_scope = rxscan::execution::ModuleOutput {
        events: vec![event("127.0.0.1")],
        evidence: Vec::new(),
        findings: Vec::new(),
        assets: Vec::new(),
    };
    assert_eq!(engine.follow_up_tasks(&task, &in_scope).len(), 1);
    let out_scope = rxscan::execution::ModuleOutput {
        events: vec![event("127.0.0.2")],
        ..Default::default()
    };
    assert!(engine.follow_up_tasks(&task, &out_scope).is_empty());
}
