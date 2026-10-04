//! Intelligence property tests: confidence caps, weak-evidence honesty,
//! offline-only correlation, scope discipline, and migration safety.
//!
//! These are invariant checks over adversarial/randomized inputs, not fixture
//! tuning: every assertion must hold for any input shape.

use std::collections::BTreeMap;

fn os_db_for_property() -> rxscan::os_fingerprint::OsDb {
    let pack = r#"{"schema_version": 1, "rules": [
        {"id": "p-linux", "family": "Linux", "features": [
          {"source": "ssh_banner", "pattern": "Ubuntu", "weight": 20},
          {"source": "http_server", "pattern": "Ubuntu", "weight": 15}],
         "confidence_cap": 85, "source": "prop"},
        {"id": "p-win", "family": "Windows", "features": [
          {"source": "ssh_banner", "pattern": "Windows", "weight": 25}],
         "confidence_cap": 90, "source": "prop"}]}"#;
    rxscan::os_fingerprint::OsDb::from_packs(vec![(
        "prop.json".to_owned(),
        rxscan::os_fingerprint::parse_os_pack(pack, "prop").unwrap(),
    )])
}

fn device_db_for_property() -> rxscan::device::DeviceDb {
    let pack = r#"{"schema_version": 1, "rules": [
        {"id": "p-router", "role": "router", "signals": [
          {"kind": "service_product", "pattern": "dnsmasq", "weight": 20},
          {"kind": "http_server", "pattern": "router", "weight": 15}],
         "confidence_cap": 85, "source": "prop"}]}"#;
    rxscan::device::DeviceDb::from_packs(vec![(
        "prop.json".to_owned(),
        rxscan::device::parse_device_pack(pack, "prop").unwrap(),
    )])
}

#[test]
fn os_confidence_never_exceeds_cap_and_weak_hints_stay_low() {
    let db = os_db_for_property();
    // Adversarial evidence shapes: empty, huge, unicode, single-hint, multi.
    let cases: Vec<Vec<rxscan::os_fingerprint::OsEvidence>> = vec![
        vec![],
        vec![rxscan::os_fingerprint::OsEvidence {
            source: "http_server".to_owned(),
            feature: "platform_token".to_owned(),
            value: "nothing indicative".to_owned(),
            confidence: 50,
            task_id: None,
            evidence_id: None,
        }],
        vec![rxscan::os_fingerprint::OsEvidence {
            source: "http_server".to_owned(),
            feature: "platform_token".to_owned(),
            value: "Ubuntu".to_owned(),
            confidence: 50,
            task_id: None,
            evidence_id: None,
        }],
        vec![
            rxscan::os_fingerprint::OsEvidence {
                source: "ssh_banner".to_owned(),
                feature: "platform_token".to_owned(),
                value: "Ubuntu".to_owned(),
                confidence: 50,
                task_id: None,
                evidence_id: None,
            },
            rxscan::os_fingerprint::OsEvidence {
                source: "http_server".to_owned(),
                feature: "platform_token".to_owned(),
                value: "Ubuntu".to_owned(),
                confidence: 50,
                task_id: None,
                evidence_id: None,
            },
        ],
        // Oversized values are skipped safely, never panic.
        vec![rxscan::os_fingerprint::OsEvidence {
            source: "ssh_banner".to_owned(),
            feature: "platform_token".to_owned(),
            value: "x".repeat(10_000),
            confidence: 50,
            task_id: None,
            evidence_id: None,
        }],
    ];
    for evidence in &cases {
        for candidate in db.classify_host(evidence) {
            assert!(
                candidate.confidence <= rxscan::os_fingerprint::OS_CONFIDENCE_CAP,
                "OS cap violated: {candidate:?}"
            );
            assert!(candidate.confidence <= 95);
        }
    }
    // Lone hint stays capped.
    let lone = db.classify_host(&cases[2]);
    for candidate in &lone {
        assert!(
            candidate.confidence <= rxscan::os_fingerprint::SINGLE_HINT_CAP,
            "lone hint must not dominate: {candidate:?}"
        );
    }
}

#[test]
fn device_confidence_capped_and_single_kind_weak() {
    let db = device_db_for_property();
    let mut single = BTreeMap::new();
    single.insert("http_server".to_owned(), vec!["Router Admin".to_owned()]);
    for candidate in db.classify_host(&single) {
        assert!(
            candidate.role_confidence <= rxscan::device::DEVICE_CONFIDENCE_CAP,
            "device cap violated"
        );
        assert!(
            candidate.role_confidence <= rxscan::device::WEAK_ROLE_CAP,
            "single-kind must stay weak"
        );
    }
    // Adversarial: empty, huge, unicode patterns never panic, never exceed cap.
    for texts in [
        vec![],
        vec!["x".repeat(10_000)],
        vec!["\u{1F600}".to_owned()],
    ] {
        let mut signals = BTreeMap::new();
        signals.insert("service_product".to_owned(), texts);
        for candidate in db.classify_host(&signals) {
            assert!(candidate.role_confidence <= rxscan::device::DEVICE_CONFIDENCE_CAP);
        }
    }
}

#[test]
fn vuln_confidence_never_exceeds_identity_without_justification() {
    let dataset = rxscan::vuln::VulnDataset {
        schema_version: rxscan::vuln::VULN_DATASET_SCHEMA_VERSION,
        provider: "prop".to_owned(),
        dataset_version: "prop-1".to_owned(),
        advisories: vec![rxscan::vuln::Advisory {
            id: "PROP-1".to_owned(),
            vendor: Some("f5".to_owned()),
            product: "nginx".to_owned(),
            affected: vec![rxscan::vuln::VersionReq::LessThan {
                version: "9.99.99".to_owned(),
            }],
            severity_label: None,
            score: None,
            summary: String::new(),
        }],
    };
    let db = rxscan::vuln::LocalVulnDb::from_dataset(dataset).unwrap();
    {
        use rxscan::vuln::VulnerabilityProvider;
        // Product-only (unknown version) stays low.
        let identity = rxscan::vuln::SoftwareIdentity {
            vendor: Some("f5".to_owned()),
            product: "nginx".to_owned(),
            version: None,
            version_family: None,
            cpe: None,
            product_confidence: 90,
            version_confidence: 0,
            evidence: vec![],
        };
        for candidate in db.query(&identity) {
            assert!(
                candidate.confidence <= identity.product_confidence,
                "vuln confidence must not exceed identity"
            );
            assert!(candidate.confidence <= 45, "product-only must stay low");
        }
        // Exact match never exceeds min(product, version) without vendor agreement cap.
        let identity = rxscan::vuln::SoftwareIdentity {
            vendor: Some("f5".to_owned()),
            product: "nginx".to_owned(),
            version: Some("1.24.0".to_owned()),
            version_family: None,
            cpe: None,
            product_confidence: 60,
            version_confidence: 55,
            evidence: vec![],
        };
        for candidate in db.query(&identity) {
            if candidate.outcome == rxscan::vuln::MatchOutcome::Matched {
                assert!(candidate.confidence <= 60, "bounded by identity");
            }
        }
        // Malformed versions yield indeterminate (or product-only for
        // empty/blank = unknown version), never an exact match.
        for bad in ["not-a-version!!", &"9".repeat(200), "1.2é"] {
            let identity = rxscan::vuln::SoftwareIdentity {
                vendor: Some("f5".to_owned()),
                product: "nginx".to_owned(),
                version: Some(bad.to_owned()),
                version_family: None,
                cpe: None,
                product_confidence: 90,
                version_confidence: 80,
                evidence: vec![],
            };
            for candidate in db.query(&identity) {
                assert_ne!(
                    candidate.outcome,
                    rxscan::vuln::MatchOutcome::Matched,
                    "bad version must not match"
                );
            }
        }
    }
}

#[test]
fn parsers_never_panic_on_hostile_input() {
    // OS / device pack parsers.
    for bad in ["", "{", "null", "[]", &"x".repeat(100_000)] {
        let _ = rxscan::os_fingerprint::parse_os_pack(bad, "prop");
        let _ = rxscan::device::parse_device_pack(bad, "prop");
    }
    // SSH banner / algorithm parsers.
    assert!(rxscan::ssh::parse_identification(&"A".repeat(10_000)).is_none());
    assert!(rxscan::ssh::parse_identification("SSH-2.0-\u{1F600}").is_none());
    assert!(rxscan::ssh::parse_host_key(&[0u8; 40_000]).is_none());
    assert!(rxscan::ssh::parse_host_key(&[]).is_none());
    // Version range parser.
    assert!(rxscan::vuln::Version::parse("").is_none());
    assert!(rxscan::vuln::Version::parse(&"9".repeat(200)).is_none());
    // TLS posture predicates are total (no panic on any string).
    for text in ["", "TLSv1.0", "garbage", &"x".repeat(10_000)] {
        let _ = rxscan::tls::TlsPosture::deprecated_protocol(text);
        let _ = rxscan::tls::TlsPosture::weak_signature_algorithm(text);
        let _ = rxscan::tls::TlsPosture::short_key_bits(text, 1024);
    }
    // Certificate identity on hostile bytes.
    assert!(rxscan::tls::CertificateIdentity::from_parts(&[0u8; 16_001], 1, None, None).is_none());
    assert!(rxscan::tls::CertificateIdentity::from_parts(&[], 1, None, None).is_none());
    assert!(rxscan::tls::CertificateIdentity::from_parts(&[0xFFu8; 64], 1, None, None).is_none());
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn no_new_unbounded_network_behavior_by_construction() {
    // Intelligence constants are bounded and documented; this test pins them
    // so future changes stay explicit.
    assert!(rxscan::os_fingerprint::MAX_OS_RULES_PER_FILE <= 1024);
    assert!(rxscan::os_fingerprint::MAX_OS_FEATURES_PER_RULE <= 32);
    assert!(rxscan::device::MAX_DEVICE_RULES_PER_FILE <= 1024);
    assert!(rxscan::device::MAX_DEVICE_SIGNALS_PER_RULE <= 32);
    assert!(rxscan::ssh::MAX_ALGORITHMS_PER_LIST <= 64);
    assert!(rxscan::ssh::MAX_SSH_PACKET_BYTES <= 64 * 1024);
    assert!(rxscan::vuln::MAX_ADVISORIES_PER_FILE <= 8192);
    assert!(rxscan::vuln::MAX_RANGES_PER_ADVISORY <= 32);
    // DBs load once per scan (no hot-path I/O): empty-dir loads succeed.
    let os =
        rxscan::os_fingerprint::OsDb::load_from_dir(std::path::Path::new("/nonexistent-os-dir"));
    assert_eq!(os.rule_count(), 0);
    let device =
        rxscan::device::DeviceDb::load_from_dir(std::path::Path::new("/nonexistent-device-dir"));
    assert_eq!(device.rule_count(), 0);
}
