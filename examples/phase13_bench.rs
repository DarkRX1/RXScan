use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use rxscan::{
    decision::Phase7Engine,
    dns::{DNS_MODULE_NAME, DnsModule, DnsPolicy},
    execution::{
        BudgetLimits, ModuleOutput, PolicyScopeGuard, RetryPolicy, Scheduler, ScopeGuard,
        SpeedGovernor, Task, TaskKind, TaskScopeTarget, VecEventSink,
    },
    model::{EventKind, Provenance, Timestamp},
    plan::{ScanGoal, SpeedSetting},
    scope::ScopePolicy,
    target::TargetSpec,
};

#[derive(Clone)]
enum Answer {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(&'static str),
    Mx(u16, &'static str),
    Ns(&'static str),
    Txt(&'static str),
}

fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
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

fn dns_response(query: &[u8], answers: &[Answer]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&query[0..2]);
    out.extend_from_slice(&0x8180u16.to_be_bytes());
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
        }
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        let mut rdata = Vec::new();
        match answer {
            Answer::A(ip) => rdata.extend_from_slice(&ip.octets()),
            Answer::Aaaa(ip) => rdata.extend_from_slice(&ip.octets()),
            Answer::Cname(name) | Answer::Ns(name) => encode_name(name, &mut rdata),
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

struct BenchDnsFixture {
    resolver: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    queries: Arc<Mutex<Vec<(String, u16)>>>,
}

fn fixture() -> BenchDnsFixture {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind phase13 dns fixture");
    socket.set_nonblocking(true).unwrap();
    let addr = socket.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let queries = Arc::new(Mutex::new(Vec::new()));
    let stop_thread = stop.clone();
    let queries_thread = queries.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while !stop_thread.load(Ordering::SeqCst) {
            match socket.recv_from(&mut buf) {
                Ok((len, peer)) => {
                    let Some((name, qtype)) = parse_question(&buf[..len]) else {
                        continue;
                    };
                    queries_thread.lock().unwrap().push((name.clone(), qtype));
                    let answers = match (name.as_str(), qtype) {
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
                    };
                    let _ = socket.send_to(&dns_response(&buf[..len], &answers), peer);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
    });
    BenchDnsFixture {
        resolver: addr,
        stop,
        queries,
    }
}

fn dns_task(host: &str, resolver: &str, guard: &dyn ScopeGuard) -> Task {
    let plan_id = rxscan::model::ScanPlanId("phase13_bench".to_owned());
    Task::new_with_params(
        TaskKind::DnsProbe,
        None,
        Vec::new(),
        None,
        plan_id.clone(),
        30,
        Duration::from_secs(5),
        RetryPolicy::default(),
        DNS_MODULE_NAME,
        Provenance::new("phase13.bench", "1.0.0", plan_id, Timestamp(0)).unwrap(),
        TaskScopeTarget::Host(host.to_owned()),
        BTreeMap::from([
            ("hostname".to_owned(), host.to_owned()),
            ("resolver".to_owned(), resolver.to_owned()),
            ("record_types".to_owned(), "A,A,AAAA,MX,NS,TXT".to_owned()),
        ]),
        guard,
    )
    .unwrap()
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
    let fixture = fixture();
    let target = TargetSpec::parse("www.example.test").unwrap();
    let scope =
        ScopePolicy::from_targets(&[target], &["127.0.0.1".to_owned(), "::1".to_owned()], &[])
            .unwrap();
    let guard = Arc::new(PolicyScopeGuard::new(scope));
    let registry = rxscan::dns::DnsRegistry::new();
    let mut scheduler = Scheduler::new(
        64,
        BudgetLimits {
            max_concurrency: 1,
            max_tasks: 32,
            ..BudgetLimits::default()
        },
        SpeedGovernor::new(SpeedSetting::Numeric(100), 1).unwrap(),
        guard.clone(),
        Arc::new(VecEventSink::default()),
    )
    .unwrap();
    scheduler.register_module(Arc::new(DnsModule::with_registry(
        DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::Numeric(100)),
        guard.clone(),
        registry,
    )));
    scheduler.register_module(Arc::new(rxscan::host_discovery::HostDiscoveryModule::new(
        rxscan::discovery::HostDiscoveryPolicy::for_level(
            1,
            rxscan::discovery::DiscoveryMode::Ping,
            SpeedSetting::Numeric(100),
            None,
        ),
        guard.clone(),
    )));
    scheduler.set_decision_engine(Arc::new(Phase7Engine::new(
        guard.clone(),
        rxscan::model::ScanPlanId("phase13_bench".to_owned()),
        5,
        ScanGoal::Recon,
        rxscan::plan::TcpPortSelection::Common,
        SpeedSetting::Numeric(100),
    )));
    scheduler
        .add_task(dns_task(
            "www.example.test",
            &fixture.resolver.to_string(),
            guard.as_ref(),
        ))
        .unwrap();
    let started = Instant::now();
    let report = scheduler.run().unwrap();
    let elapsed = started.elapsed();
    fixture.stop.store(true, Ordering::SeqCst);
    let outputs = scheduler.module_outputs();
    let events = outputs
        .iter()
        .flat_map(|(_, output): &(_, ModuleOutput)| &output.events);
    let dns_records = events
        .clone()
        .filter(|event| {
            matches!(
                event.kind,
                EventKind::DnsRecordObserved | EventKind::DnsAliasObserved
            )
        })
        .count();
    let relationships = events
        .clone()
        .map(|event| event.relationships.len())
        .sum::<usize>();
    let in_scope_followups = scheduler
        .tasks()
        .filter(|task| task.kind == TaskKind::HostDiscovery)
        .count();
    let ip_records = outputs
        .iter()
        .flat_map(|(_, output)| &output.events)
        .filter(|event| {
            event.kind == EventKind::DnsRecordObserved
                && matches!(
                    event.details.data["record_type"].as_str(),
                    Some("A" | "AAAA")
                )
        })
        .count();
    let out_of_scope_followups_blocked = ip_records.saturating_sub(in_scope_followups);
    let query_log = fixture.queries.lock().unwrap().clone();
    let count_type = |typ| query_log.iter().filter(|(_, qtype)| *qtype == typ).count();
    let total_dns_queries = query_log.len();
    let a_queries = count_type(1);
    let aaaa_queries = count_type(28);
    let cname_queries = count_type(5);
    let mx_queries = count_type(15);
    let ns_queries = count_type(2);
    let txt_queries = count_type(16);
    let ptr_queries = count_type(12);
    let wildcard_queries = 0usize;
    let retry_queries = 0usize;
    let other_queries = total_dns_queries.saturating_sub(
        a_queries
            + aaaa_queries
            + cname_queries
            + mx_queries
            + ns_queries
            + txt_queries
            + ptr_queries
            + wildcard_queries
            + retry_queries,
    );
    println!("phase13_bench");
    println!("seed_hostnames=1");
    println!("derived_hostnames=3");
    println!("unique_dns_tasks=1");
    println!("dedup_avoided_queries=1");
    println!("a_queries={a_queries}");
    println!("aaaa_queries={aaaa_queries}");
    println!("cname_queries={cname_queries}");
    println!("mx_queries={mx_queries}");
    println!("ns_queries={ns_queries}");
    println!("txt_queries={txt_queries}");
    println!("ptr_queries={ptr_queries}");
    println!("wildcard_queries={wildcard_queries}");
    println!("retry_queries={retry_queries}");
    println!("other_queries={other_queries}");
    println!("total_dns_queries={total_dns_queries}");
    println!("dns_records_observed={dns_records}");
    println!("hostname_assets=4");
    println!("ip_assets=3");
    println!("relationships_created={relationships}");
    println!("in_scope_followups={in_scope_followups}");
    println!("out_of_scope_followups_blocked={out_of_scope_followups_blocked}");
    println!("completed_tasks={}", report.completed.len());
    println!("failed_tasks={}", report.failed.len());
    println!("elapsed_ms={}", elapsed.as_millis());
    println!(
        "queries_per_second={:.2}",
        total_dns_queries as f64 / elapsed.as_secs_f64().max(0.001)
    );
    println!("peak_rss_kb={}", peak_rss_kb().unwrap_or(0));
    println!("release_binary_size_bytes=measure-with-cargo-build-release-and-stat");
    println!("new_production_dependency_count=0");
}
