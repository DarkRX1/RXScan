use rxscan::assets::{certificate_id, endpoint_id, service_id, ssh_key_id};
use rxscan::discovery::{DiscoveryTechnique, HostState, ProbeRecord, conclude_state};
use rxscan::dns::{DnsRecordType, parse_dns_response};
use rxscan::neighbor::{arp_applicable, link_scope_of, nd_applicable};
use rxscan::probes::{
    ProbeCtx, mqtt_connect_request, parse_mqtt_connack, parse_rdp_confirm, parse_smb2_response,
    probe_mongodb, probe_mqtt, probe_rdp, probe_smb, rdp_connection_request,
    smb2_negotiate_request,
};
use rxscan::scan_mode::{ModeCapability, ScanMode, resolve};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

#[test]
fn ipv6_target_parses_and_lowering_is_deterministic() {
    let spec = rxscan::target::TargetSpec::parse("2001:db8::/126").unwrap();
    let scope =
        rxscan::scope::ScopePolicy::from_targets(std::slice::from_ref(&spec), &[], &[]).unwrap();
    let hosts =
        rxscan::discovery::expand_cidr_bounded("2001:db8::/126".parse().unwrap(), &scope, 100);
    assert!(!hosts.is_empty());
    assert!(hosts.iter().all(|ip| ip.is_ipv6()));
    let mut sorted = hosts.clone();
    rxscan::discovery::sort_hosts_deterministic(&mut sorted);
    assert_eq!(sorted, hosts);
}

#[test]
fn ipv6_scope_enforced() {
    let spec = rxscan::target::TargetSpec::parse("2001:db8::1").unwrap();
    let scope = rxscan::scope::ScopePolicy::from_targets(&[spec], &[], &[]).unwrap();
    assert!(scope.permits(Some("2001:db8::1".parse().unwrap()), None));
    assert!(!scope.permits(Some("2001:db8::2".parse().unwrap()), None));
}

#[test]
fn ipv6_url_target_keeps_host() {
    let spec = rxscan::target::TargetSpec::parse("https://example.test:8443/path").unwrap();
    let scope = rxscan::scope::ScopePolicy::from_targets(&[spec], &[], &[]).unwrap();
    assert!(scope.permits(None, Some("example.test")));
}

#[test]
fn ipv6_graph_ids_are_stable() {
    let loopback: IpAddr = "::1".parse().unwrap();
    assert_eq!(
        rxscan::discovery::asset_id_for_ip(&loopback),
        rxscan::discovery::asset_id_for_ip(&loopback)
    );
    assert_ne!(
        rxscan::discovery::asset_id_for_ip(&loopback),
        rxscan::discovery::asset_id_for_ip(&"127.0.0.1".parse().unwrap())
    );
    assert!(endpoint_id("::1", 80, "tcp").starts_with("endpoint_"));
    assert!(service_id(&endpoint_id("::1", 443, "tcp"), "https").starts_with("service_"));
}

#[test]
fn ipv6_neighbor_rules_hold() {
    assert!(!arp_applicable(&"::1".parse().unwrap()));
    assert!(!arp_applicable(&"fe80::1".parse().unwrap()));
    assert!(nd_applicable(&"fe80::1".parse().unwrap()));
    assert!(!nd_applicable(&"::1".parse().unwrap()));
    assert_eq!(
        link_scope_of(&"2001:db8::1".parse().unwrap()),
        rxscan::neighbor::LinkScope::Global
    );
}

#[test]
fn corroboration_caps_at_strongest_source() {
    let ip: IpAddr = "192.0.2.10".parse().unwrap();
    let probes = vec![
        ProbeRecord::success(
            DiscoveryTechnique::IcmpEcho,
            ip,
            None,
            Duration::from_millis(2),
            "echo reply",
        ),
        ProbeRecord::success(
            DiscoveryTechnique::TcpConnect,
            ip,
            Some(80),
            Duration::from_millis(1),
            "connect succeeded",
        ),
    ];
    let (state, confidence, techniques, evidence) = conclude_state(&probes);
    assert_eq!(state, HostState::Alive);
    assert!(confidence <= 95);
    assert!(techniques.contains(&DiscoveryTechnique::IcmpEcho));
    assert!(evidence.contains("corroborat"));
}

#[test]
fn syn_ack_techniques_conclude_alive() {
    let ip: IpAddr = "192.0.2.10".parse().unwrap();
    for technique in [DiscoveryTechnique::TcpSyn, DiscoveryTechnique::TcpAck] {
        let probes = vec![ProbeRecord::success(
            technique,
            ip,
            Some(80),
            Duration::from_millis(1),
            "reachability confirmed",
        )];
        let (state, confidence, _, _) = conclude_state(&probes);
        assert_eq!(state, HostState::Alive);
        assert_eq!(confidence, 88);
    }
}

#[test]
fn scan_mode_auto_is_capability_gated() {
    let syn = resolve(ScanMode::Auto, ModeCapability::test(true, true));
    assert_eq!(syn.resolved.as_str(), "syn");
    let conn = resolve(ScanMode::Auto, ModeCapability::test(false, true));
    assert_eq!(conn.resolved.as_str(), "connect");
    assert!(ScanMode::parse("bogus").is_err());
}

#[test]
fn smb_negotiate_round_trips() {
    let request = smb2_negotiate_request();
    assert_eq!(request.len(), 104);
    assert!(parse_smb2_response(&request).is_none());
    let mut response = vec![0u8; 132];
    response[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x84]);
    response[4..8].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
    response[68..70].copy_from_slice(&65u16.to_le_bytes());
    response[70] = 0x03;
    response[71..73].copy_from_slice(&0x0311u16.to_le_bytes());
    let facts = parse_smb2_response(&response).unwrap();
    assert_eq!(facts.dialect, "0x0311");
    assert!(facts.signing_required);
    assert!(parse_smb2_response(b"garbage garbage garbage").is_none());
}

#[test]
fn rdp_confirm_validates_type() {
    let request = rdp_connection_request();
    assert_eq!(request[0], 0x03);
    assert_eq!(
        parse_rdp_confirm(&[
            0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00
        ]),
        Some(true)
    );
    assert!(parse_rdp_confirm(&[0x03, 0x00]).is_none());
    assert!(parse_rdp_confirm(b"SSH-2.0-x").is_none());
}

#[test]
fn mqtt_connack_validates_header() {
    let request = mqtt_connect_request();
    assert_eq!(request[0], 0x10);
    assert_eq!(parse_mqtt_connack(&[0x20, 0x02, 0x00, 0x00]), Some(0));
    assert_eq!(parse_mqtt_connack(&[0x20, 0x02, 0x00, 0x05]), Some(5));
    assert!(parse_mqtt_connack(&[0x30, 0x02, 0x00, 0x00]).is_none());
}

#[test]
fn dns_srv_record_type_known() {
    assert_eq!(DnsRecordType::Srv.code(), 33);
    assert_eq!(DnsRecordType::Srv.as_str(), "SRV");
}

#[test]
fn dns_srv_response_parses_target_and_port() {
    let packet = srv_packet();
    let parsed = parse_dns_response(&packet, "_http._tcp.example.test", DnsRecordType::Srv)
        .expect("srv parses");
    assert_eq!(parsed.records.len(), 1);
    assert_eq!(parsed.records[0].value, "web.example.test");
    assert_eq!(parsed.records[0].preference, Some(8080));
}

#[test]
fn dns_srv_rejects_truncated_rdata() {
    let mut packet = srv_packet();
    packet.truncate(packet.len() - 4);
    assert!(parse_dns_response(&packet, "_http._tcp.example.test", DnsRecordType::Srv).is_err());
}

fn srv_packet() -> Vec<u8> {
    let mut out = vec![
        0x52, 0x58, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in ["_http", "_tcp", "example", "test"] {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0x00);
    out.extend_from_slice(&33u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0xc00cu16.to_be_bytes());
    out.extend_from_slice(&33u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&120u32.to_be_bytes());
    let target: &[u8] = b"\x03web\x07example\x04test\x00";
    let rdlen = (6 + target.len()) as u16;
    out.extend_from_slice(&rdlen.to_be_bytes());
    out.extend_from_slice(&10u16.to_be_bytes());
    out.extend_from_slice(&20u16.to_be_bytes());
    out.extend_from_slice(&8080u16.to_be_bytes());
    out.extend_from_slice(target);
    out
}

#[test]
fn asset_ids_stable_across_families() {
    assert_eq!(certificate_id("AB:CD"), certificate_id("ab:cd"));
    assert!(ssh_key_id("ab").starts_with("sshkey_"));
}

fn probe_ctx(ip: IpAddr, port: u16, cancel: &rxscan::execution::CancellationToken) -> ProbeCtx<'_> {
    ProbeCtx {
        ip,
        port,
        host_label: "127.0.0.1",
        timeout: Duration::from_secs(3),
        deadline: Instant::now() + Duration::from_secs(3),
        cancel,
        connections: Arc::new(AtomicUsize::new(0)),
        ssh_kex_capture: false,
    }
}

fn read_requested(mut stream: std::net::TcpStream) -> Vec<u8> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let mut buf = vec![0u8; 2048];
    match stream.read(&mut buf) {
        Ok(count) => buf[..count].to_vec(),
        Err(_) => Vec::new(),
    }
}

#[test]
fn live_smb_negotiate_classifies_without_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let received = read_requested(stream.try_clone().unwrap());
        let mut response = vec![0u8; 80];
        response[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x50]);
        response[4..8].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        response[68..70].copy_from_slice(&65u16.to_le_bytes());
        response[70] = 0x01;
        response[71..73].copy_from_slice(&0x0210u16.to_le_bytes());
        let _ = stream.write_all(&response);
        received
    });
    let cancel = rxscan::execution::CancellationToken::default();
    let ctx = probe_ctx("127.0.0.1".parse().unwrap(), port, &cancel);
    let attempt = probe_smb(&ctx);
    let received = handle.join().unwrap();
    assert_eq!(attempt.protocol, "smb");
    assert!(attempt.confidence >= 80);
    let upper = String::from_utf8_lossy(&received).to_ascii_uppercase();
    assert!(!upper.contains("AUTH") && !upper.contains("LOGIN"));
}

#[test]
fn live_rdp_confirm_classifies_without_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let received = read_requested(stream.try_clone().unwrap());
        let reply = [
            0x03u8, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let _ = stream.write_all(&reply);
        received
    });
    let cancel = rxscan::execution::CancellationToken::default();
    let ctx = probe_ctx("127.0.0.1".parse().unwrap(), port, &cancel);
    let attempt = probe_rdp(&ctx);
    let received = handle.join().unwrap();
    assert_eq!(attempt.protocol, "rdp");
    let upper = String::from_utf8_lossy(&received).to_ascii_uppercase();
    assert!(!upper.contains("PASSWORD") && !upper.contains("LOGIN"));
}

#[test]
fn live_mqtt_connack_classifies_without_subscription() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = read_requested(stream.try_clone().unwrap());
        let _ = stream.write_all(&[0x20u8, 0x02, 0x00, 0x00]);
    });
    let cancel = rxscan::execution::CancellationToken::default();
    let ctx = probe_ctx("127.0.0.1".parse().unwrap(), port, &cancel);
    let attempt = probe_mqtt(&ctx);
    assert_eq!(attempt.protocol, "mqtt");
    assert_eq!(attempt.protocol_version.as_deref(), Some("3.1.1"));
}

#[test]
fn live_mongodb_hello_classifies_without_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = read_requested(stream.try_clone().unwrap());
        let doc: &[u8] = b"\x16\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00";
        let total = (16 + 4 + 1 + doc.len() + 1) as u32;
        let mut reply = Vec::new();
        reply.extend_from_slice(&total.to_le_bytes());
        reply.extend_from_slice(&1u32.to_le_bytes());
        reply.extend_from_slice(&0u32.to_le_bytes());
        reply.extend_from_slice(&2013u32.to_le_bytes());
        reply.extend_from_slice(&0u32.to_le_bytes());
        reply.extend_from_slice(&(total - 16).to_le_bytes());
        reply.push(0x00);
        reply.extend_from_slice(doc);
        reply.push(0x00);
        let _ = stream.write_all(&reply);
    });
    let cancel = rxscan::execution::CancellationToken::default();
    let ctx = probe_ctx("127.0.0.1".parse().unwrap(), port, &cancel);
    let attempt = probe_mongodb(&ctx);
    assert_eq!(attempt.protocol, "mongodb");
}
