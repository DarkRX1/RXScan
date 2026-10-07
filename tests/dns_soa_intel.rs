//! Stage A — SOA authority intelligence: deterministic fixtures.
//!
//! Covers DNS type-6 (SOA) parsing, policy scheduling, and the
//! Domain -> DNS investigation transform. SOA is authority metadata
//! (primary nameserver + mailbox + serial): informational evidence only,
//! never a hostname entity or identity relationship.

use rxscan::dns::{DnsPolicy, DnsRecordType, parse_dns_response};
use rxscan::graph::EntityKind;
use rxscan::investigate::{
    FixtureDnsFetcher, FixtureProfileFetcher, FixtureSearchRunner, InvestigationConfig, SeedKind,
    run_investigation_with,
};
use rxscan::plan::{ScanGoal, SpeedSetting};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// Minimal DNS response carrying one answer record.
fn response_with_answer(name: &str, qtype: u16, answer_type: u16, rdata: &[u8]) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&0x5258u16.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    encode_name(name, &mut query);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());

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
    out.extend_from_slice(&3600u32.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

fn soa_rdata() -> Vec<u8> {
    let mut rdata = Vec::new();
    encode_name("ns1.example.test", &mut rdata);
    encode_name("hostmaster.example.test", &mut rdata);
    rdata.extend_from_slice(&2026100601u32.to_be_bytes());
    rdata.extend_from_slice(&7200u32.to_be_bytes());
    rdata.extend_from_slice(&3600u32.to_be_bytes());
    rdata.extend_from_slice(&1209600u32.to_be_bytes());
    rdata.extend_from_slice(&3600u32.to_be_bytes());
    rdata
}

#[test]
fn soa_record_type_identity() {
    assert_eq!(DnsRecordType::Soa.code(), 6);
    assert_eq!(DnsRecordType::Soa.as_str(), "SOA");
    assert!(DnsRecordType::Soa.is_informational());
    assert!(DnsRecordType::Txt.is_informational());
    assert!(!DnsRecordType::A.is_informational());
    assert!(!DnsRecordType::Mx.is_informational());
}

#[test]
fn soa_response_parses_authority_metadata() {
    let packet = response_with_answer("example.test", 6, 6, &soa_rdata());
    let parsed = parse_dns_response(&packet, "example.test", DnsRecordType::Soa).unwrap();
    assert_eq!(parsed.records.len(), 1);
    let record = &parsed.records[0];
    assert_eq!(record.record_type, DnsRecordType::Soa);
    assert_eq!(record.ttl, 3600);
    assert_eq!(
        record.value,
        "ns1.example.test hostmaster.example.test 2026100601"
    );
}

#[test]
fn soa_truncated_rdata_rejected() {
    let mut rdata = Vec::new();
    encode_name("ns1.example.test", &mut rdata);
    // Missing rname + timers: must not parse as authority metadata.
    let packet = response_with_answer("example.test", 6, 6, &rdata);
    assert!(parse_dns_response(&packet, "example.test", DnsRecordType::Soa).is_err());
}

#[test]
fn soa_scheduled_only_at_deep_levels() {
    let shallow = DnsPolicy::new(2, ScanGoal::Recon, SpeedSetting::default());
    assert!(!shallow.record_types().contains(&DnsRecordType::Soa));
    let mid = DnsPolicy::new(3, ScanGoal::Recon, SpeedSetting::default());
    assert!(!mid.record_types().contains(&DnsRecordType::Soa));
    let deep = DnsPolicy::new(5, ScanGoal::Recon, SpeedSetting::default());
    assert!(deep.record_types().contains(&DnsRecordType::Soa));
    // Core resolution records are unaffected.
    assert!(deep.record_types().contains(&DnsRecordType::A));
}

#[test]
fn soa_investigation_stays_informational() {
    let search = FixtureSearchRunner::default();
    let profile = FixtureProfileFetcher::default();
    let dns = FixtureDnsFetcher::default().with_records(
        "example.test",
        "SOA",
        &["ns1.example.test. hostmaster.example.test. 2026100601"],
    );
    let mut config = InvestigationConfig::seeded(SeedKind::Domain, "example.test");
    config.depth = 1;
    config.allow_test_loopback = true;
    config.deadline = Duration::from_secs(10);
    let cancelled = AtomicBool::new(false);
    let report = run_investigation_with(config, &search, &profile, &dns, &cancelled).unwrap();

    let records: Vec<_> = report
        .entities
        .values()
        .filter(|e| {
            e.kind == EntityKind::DnsRecord
                && e.attributes.get("record_type").is_some_and(|v| v == "SOA")
        })
        .collect();
    assert_eq!(records.len(), 1, "SOA must surface one DnsRecord entity");
    let attrs = &records[0].attributes;
    assert_eq!(
        attrs.get("soa_mname").map(String::as_str),
        Some("ns1.example.test")
    );
    assert_eq!(
        attrs.get("soa_rname").map(String::as_str),
        Some("hostmaster.example.test")
    );
    assert_eq!(
        attrs.get("soa_serial").map(String::as_str),
        Some("2026100601")
    );
    // Authority names must not become hostname entities on their own.
    assert!(
        !report
            .entities
            .values()
            .any(|e| e.kind == EntityKind::Hostname && e.canonical_value == "ns1.example.test"),
        "SOA mname must not auto-expand into a hostname entity"
    );
    report.accounting.check_invariant().unwrap();
}
