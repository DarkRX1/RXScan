use clap::Parser;
use rxscan::{
    cli::Cli,
    model::{
        Asset, AssetKind, BoundedDetails, Confidence, Event, EventKind, Evidence, Finding,
        JsonLine, MAX_EVIDENCE_DETAILS_BYTES, ModelError, Provenance, Relationship,
        RelationshipKind, RelationshipSubject, Severity, Timestamp,
    },
    plan::ScanPlan,
};
use serde_json::json;

fn plan() -> ScanPlan {
    ScanPlan::compile(Cli::try_parse_from(["rxscan", "https://Example.test"]).unwrap()).unwrap()
}

fn provenance(plan: &ScanPlan) -> Provenance {
    Provenance::new(
        "test.module",
        "2.0.0",
        plan.stable_id(),
        Timestamp(1_700_000_000_000),
    )
    .unwrap()
}

#[test]
fn stable_assets_correlate_across_repeated_scans_and_are_scope_checked() {
    let plan = plan();
    let repeated_plan =
        ScanPlan::compile(Cli::try_parse_from(["rxscan", "https://Example.test"]).unwrap())
            .unwrap();
    assert_eq!(plan.stable_id(), repeated_plan.stable_id());
    let first = Asset::scoped(
        AssetKind::Host,
        "EXAMPLE.TEST.",
        &plan.scope,
        provenance(&plan),
    )
    .unwrap();
    let second = Asset::scoped(
        AssetKind::Host,
        "example.test",
        &plan.scope,
        provenance(&plan),
    )
    .unwrap();
    assert_eq!(first.id, second.id);
    assert!(matches!(
        Asset::scoped(
            AssetKind::Host,
            "outside.test",
            &plan.scope,
            provenance(&plan)
        ),
        Err(ModelError::OutsideScope)
    ));

    let port_443 = Asset::child(AssetKind::Port, &first.id, "443", provenance(&plan)).unwrap();
    let other_host = Asset::scoped(
        AssetKind::Host,
        "example.test",
        &plan.scope,
        provenance(&plan),
    )
    .unwrap();
    let other_port = Asset::child(
        AssetKind::Port,
        &rxscan::model::AssetId(format!("{}-different", other_host.id.0)),
        "443",
        provenance(&plan),
    )
    .unwrap();
    assert_ne!(port_443.id, other_port.id);
}

#[test]
fn events_are_typed_provenanced_and_jsonl_serializable() {
    let plan = plan();
    let host = Asset::scoped(
        AssetKind::Host,
        "example.test",
        &plan.scope,
        provenance(&plan),
    )
    .unwrap();
    let event = Event::new(
        EventKind::HostDiscovered,
        Some(host.id),
        BoundedDetails::from_value(json!({"method":"seed"}), 1024).unwrap(),
        provenance(&plan),
    )
    .unwrap();
    let line = event.to_json_line().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(parsed["kind"], "host_discovered");
    assert_eq!(parsed["provenance"]["scan_plan_id"], plan.stable_id().0);
    assert!(!line.contains('\n'));

    for kind in [
        EventKind::HttpResponseObserved,
        EventKind::TlsInformationObserved,
        EventKind::EndpointDiscovered,
    ] {
        let event = Event::new(
            kind,
            None,
            BoundedDetails::from_value(json!({"representative": true}), 1024).unwrap(),
            provenance(&plan),
        )
        .unwrap();
        assert!(serde_json::from_str::<Event>(&event.to_json_line().unwrap()).is_ok());
    }
}

#[test]
fn findings_evidence_and_typed_relationships_round_trip() {
    let plan = plan();
    let record_provenance = provenance(&plan);
    let host = Asset::scoped(
        AssetKind::Host,
        "example.test",
        &plan.scope,
        record_provenance.clone(),
    )
    .unwrap();
    let evidence = Evidence::new(
        "http.headers",
        host.id.clone(),
        BoundedDetails::from_value(json!({"header":"X-Test"}), 1024).unwrap(),
        Confidence::new(80).unwrap(),
        record_provenance.clone(),
    )
    .unwrap();
    let mut finding = Finding::new(
        "Example finding",
        Severity::Low,
        Confidence::new(80).unwrap(),
        host.id.clone(),
        record_provenance.clone(),
    )
    .unwrap();
    finding.evidence_ids.push(evidence.id.clone());
    let relation = Relationship::new(
        RelationshipKind::Supports,
        RelationshipSubject::Evidence(evidence.id.clone()),
        RelationshipSubject::Finding(finding.id.clone()),
        record_provenance,
    )
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Finding>(&finding.to_json_line().unwrap()).unwrap(),
        finding
    );
    assert_eq!(relation.kind, RelationshipKind::Supports);
    assert!(
        Relationship::new(
            RelationshipKind::Affects,
            RelationshipSubject::Finding(finding.id.clone()),
            RelationshipSubject::Finding(finding.id),
            provenance(&plan)
        )
        .is_err()
    );
}

#[test]
fn bounded_evidence_preserves_truncation_and_rejects_oversized_structured_data() {
    let details = BoundedDetails::from_text("abcdefghij", 4);
    assert_eq!(details.data, json!("abcd"));
    assert!(details.truncated);
    assert_eq!(details.original_bytes, 10);
    assert!(matches!(
        BoundedDetails::from_value(
            json!("x".repeat(MAX_EVIDENCE_DETAILS_BYTES)),
            MAX_EVIDENCE_DETAILS_BYTES
        ),
        Err(ModelError::DetailsTooLarge { .. })
    ));
}

#[test]
fn invalid_model_data_is_rejected() {
    let plan = plan();
    assert!(Confidence::new(101).is_err());
    assert!(Provenance::new("", "1", plan.stable_id(), Timestamp(1)).is_err());
    assert!(Asset::scoped(AssetKind::Ip, "not-an-ip", &plan.scope, provenance(&plan)).is_err());
    assert!(Asset::scoped(AssetKind::Port, "443", &plan.scope, provenance(&plan)).is_err());
    assert!(
        Event::new(
            EventKind::DnsInformationObserved,
            Some(rxscan::model::AssetId(String::new())),
            BoundedDetails::from_text("ok", 2),
            provenance(&plan)
        )
        .is_err()
    );
}
