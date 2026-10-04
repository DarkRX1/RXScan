use rxscan::fingerprints::FingerprintDb;
use std::path::PathBuf;

fn db() -> FingerprintDb {
    FingerprintDb::load_from_dir(&PathBuf::from("fingerprints/v1"))
}

#[test]
fn corpus_loads_without_rejections() {
    let db = db();
    assert!(db.rule_count() >= 80, "rule_count={}", db.rule_count());
    assert!(
        db.stats().files_rejected == 0,
        "rejected={:?}",
        db.stats().rejected_files
    );
}

#[test]
fn every_rule_matches_its_own_pattern() {
    let db = db();
    let dir = PathBuf::from("fingerprints/v1");
    let packs = rxscan::fingerprints::load_dir(&dir).unwrap();
    let mut checked = 0;
    for (_, pack) in &packs {
        for rule in &pack.fingerprints {
            let observation = match rule.matcher.kind {
                rxscan::fingerprints::MatcherKind::Prefix => {
                    format!("{}_9.9", rule.matcher.pattern)
                }
                rxscan::fingerprints::MatcherKind::Exact => rule.matcher.pattern.clone(),
                rxscan::fingerprints::MatcherKind::Contains => {
                    format!("x {} y", rule.matcher.pattern)
                }
            };
            let hits = db.candidates_for(&rule.protocol, &observation);
            assert!(
                hits.iter().any(|hit| hit.rule_id == rule.id),
                "rule {} does not match its own pattern",
                rule.id
            );
            checked += 1;
        }
    }
    assert!(checked >= 80, "checked={checked}");
}

#[test]
fn expected_matches_fire() {
    let db = db();
    let hits = db.candidates_for("http", "Server: nginx/1.24.0");
    assert!(hits.iter().any(|hit| hit.product == "nginx"));
    assert_eq!(
        hits.iter()
            .find(|hit| hit.product == "nginx")
            .and_then(|hit| hit.version.clone())
            .as_deref(),
        Some("1.24.0")
    );
    let hits = db.candidates_for("ssh", "SSH-2.0-OpenSSH_9.7p1");
    assert!(hits.iter().any(|hit| hit.product == "OpenSSH"));
    let hits = db.candidates_for("ftp", "220 vsFTPd 3.0.3 ready");
    assert!(hits.iter().any(|hit| hit.product == "vsftpd"));
    let hits = db.candidates_for("smtp", "mail.example.test ESMTP Postfix 3.7");
    assert!(hits.iter().any(|hit| hit.product == "Postfix"));
    let hits = db.candidates_for("redis", "redis_version:7.2.0");
    assert!(hits.iter().any(|hit| hit.product == "Redis"));
    let hits = db.candidates_for("mysql", "8.0.36 mysql_native_password handshake");
    assert!(hits.iter().any(|hit| hit.product == "MySQL"));
    let hits = db.candidates_for("postgres", "PostgreSQL 15.2 ready");
    assert!(hits.iter().any(|hit| hit.product == "PostgreSQL"));
}

#[test]
fn expected_non_matches_stay_empty() {
    let db = db();
    assert!(db.candidates_for("http", "").is_empty());
    assert!(
        db.candidates_for("ssh", "totally unrelated banner text here")
            .is_empty()
    );
    assert!(
        db.candidates_for("http", "SSH-2.0-OpenSSH_9.7p1")
            .is_empty()
            || db
                .candidates_for("http", "SSH-2.0-OpenSSH_9.7p1")
                .iter()
                .all(|hit| hit.product != "OpenSSH")
    );
}

#[test]
fn protocol_gating_holds() {
    let db = db();
    for hit in db.candidates_for("http", "SSH-2.0-OpenSSH_9.7p1") {
        assert_ne!(hit.product, "OpenSSH", "ssh rule fired on http bytes");
    }
}

#[test]
fn malformed_inputs_never_panic() {
    let db = db();
    for input in ["", "\0\0\0", "x".repeat(5000).as_str(), "Ünïcodé \u{1f600}"] {
        let _ = db.candidates_for("http", input);
        let _ = db.candidates_for_unknown(input);
    }
}

#[test]
fn unknown_suggestions_carry_protocol_hints() {
    let db = db();
    let hits = db.candidates_for_unknown("SSH-2.0-OpenSSH_9.7p1");
    assert!(hits.iter().any(|hit| hit.suggested_protocol == "ssh"));
}

#[test]
fn version_extractors_are_deterministic_and_bounded() {
    let dir = PathBuf::from("fingerprints/v1");
    let packs = rxscan::fingerprints::load_dir(&dir).unwrap();
    let mut with_extractor = 0;
    for (_, pack) in &packs {
        for rule in &pack.fingerprints {
            let Some(extractor) = rule.version_extractor.clone() else {
                continue;
            };
            with_extractor += 1;
            for observation in [
                format!("x {} 1.2.3 y", rule.matcher.pattern),
                format!("{}9.9", rule.matcher.pattern),
                String::new(),
                "x".repeat(5000),
            ] {
                let first = extractor.extract(&observation);
                assert_eq!(first, extractor.extract(&observation));
                if let Some(version) = first {
                    assert!(!version.is_empty() && version.len() <= 32);
                    assert!(version.bytes().any(|b| b.is_ascii_digit()));
                }
            }
        }
    }
    assert!(with_extractor >= 20, "extractors={with_extractor}");
}

#[test]
fn conflicts_resolve_deterministically_by_rule_id() {
    let db = db();
    let first = db.candidates_for("http", "Server: nginx/1.24.0");
    let second = db.candidates_for("http", "Server: nginx/1.24.0");
    assert_eq!(first, second);
    assert!(first.len() <= rxscan::fingerprints::MAX_CANDIDATES_PER_OBSERVATION);
}

#[test]
fn negative_fixtures_match_nothing() {
    let db = db();
    for observation in [
        "lorem ipsum dolor sit amet",
        "200 OK",
        "hello world",
        "xxxxxxxxxx",
    ] {
        assert!(
            db.candidates_for("http", observation).is_empty(),
            "false positive on {observation:?}"
        );
        assert!(
            db.candidates_for("ssh", observation).is_empty(),
            "false positive on {observation:?}"
        );
    }
}

#[test]
fn quality_benchmark_corpus() {
    let db = db();
    let known = [
        ("http", "Server: nginx/1.24.0"),
        ("http", "Server: Apache/2.4.57 (Unix)"),
        ("http", "Server: Microsoft-IIS/10.0"),
        ("http", "Server: Caddy/2.7.6"),
        ("http", "Server: lighttpd/1.4.71"),
        ("http", "Server: openresty/1.21.4.1"),
        ("http", "Server: gunicorn/21.2.0"),
        ("http", "Server: Werkzeug/2.3.7"),
        ("http", "Server: nginx"),
        ("http", "wp-content/uploads/2024/01/img.png"),
        ("http", "drupalSettings = {};"),
        ("http", "Joomla! 4.3"),
        ("http", "Grafana v10.2.0"),
        ("http", "Prometheus 2.48"),
        ("http", "MinIO Console"),
        ("http", "SonarQube 10.2"),
        ("http", "Nextcloud 27"),
        ("http", "Pi-hole v5.17"),
        ("http", "HP LaserJet MFP"),
        ("http", "Hikvision DS-2CD"),
        ("ssh", "SSH-2.0-OpenSSH_9.3p1"),
        ("ssh", "SSH-2.0-dropbear_2022.83"),
        ("ssh", "SSH-2.0-libssh_0.10.5"),
        ("ssh", "SSH-2.0-Cisco-2.0"),
        ("ssh", "SSH-2.0-ROSSSH"),
        ("ftp", "220 vsFTPd 3.0.3 ready"),
        ("ftp", "220 ProFTPD 1.3.8 Server ready"),
        ("ftp", "220-FileZilla Server 1.7.0"),
        ("smtp", "mail.example.test ESMTP Postfix 3.7"),
        ("smtp", "220 mail.example.test ESMTP Exim 4.96"),
        ("smtp", "220 Microsoft ESMTP MAIL Service ready"),
        ("redis", "redis_version:7.2.0"),
        ("mysql", "8.0.36 mysql_native_password handshake"),
        ("mysql", "5.5.5-10.11.6-MariaDB"),
        ("postgres", "PostgreSQL 15.2 ready"),
        ("mongodb", "mongod 6.0.9 ready"),
        ("mqtt", "mosquitto version 2.0.18 listening"),
    ];
    let mut matched = 0;
    let mut candidates = 0;
    for (protocol, observation) in known {
        let hits = db.candidates_for(protocol, observation);
        if !hits.is_empty() {
            matched += 1;
        }
        candidates += hits.len();
    }
    let total = known.len();
    assert!(
        matched * 100 / total >= 80,
        "known-set coverage {matched}/{total}"
    );
    assert!(
        candidates as f64 / total as f64 <= 4.0,
        "average candidates per observation too high"
    );
}
