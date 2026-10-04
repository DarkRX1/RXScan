use rxscan::model::{AssetKind, ScanPlanId};
use rxscan::project::{
    EntityExplanation, ProjectEntity, ProjectState, explain_entity, render_explanation,
};
use std::collections::BTreeMap;

fn state_with_entity() -> ProjectState {
    let mut state = ProjectState {
        project_schema_version: 1,
        project_id: "test-project".to_owned(),
        revision: 1,
        fingerprint: "fp".to_owned(),
        scans: BTreeMap::new(),
        entities: BTreeMap::new(),
        relationships: BTreeMap::new(),
        observations: BTreeMap::new(),
        findings: BTreeMap::new(),
        changes: BTreeMap::new(),
        analysis_refs: BTreeMap::new(),
    };
    state.entities.insert(
        "ip:192.0.2.10".to_owned(),
        ProjectEntity {
            id: "ip:192.0.2.10".to_owned(),
            kind: AssetKind::Ip,
            identity: "192.0.2.10".to_owned(),
            attributes: BTreeMap::new(),
            first_scan_id: ScanPlanId("scan-a".to_owned()),
            last_scan_id: ScanPlanId("scan-b".to_owned()),
            observation_count: 4,
            external: false,
            observations: Vec::new(),
        },
    );
    state
}

#[test]
fn explain_reports_conclusion_and_chain() {
    let state = state_with_entity();
    let explanation: EntityExplanation =
        explain_entity(&state, "ip:192.0.2.10", 10).expect("entity exists");
    assert_eq!(explanation.entity_id, "ip:192.0.2.10");
    assert_eq!(explanation.identity, "192.0.2.10");
    assert_eq!(explanation.first_scan, "scan-a");
    assert_eq!(explanation.last_scan, "scan-b");
    let text = render_explanation(&explanation);
    assert!(text.contains("Conclusion:"));
    assert!(text.contains("Evidence:"));
    assert!(text.contains("Discovery chain:"));
    assert!(text.contains("192.0.2.10"));
}

#[test]
fn explain_missing_entity_errors() {
    let state = state_with_entity();
    assert!(explain_entity(&state, "ip:198.51.100.99", 10).is_err());
}

#[test]
fn explain_is_json_stable() {
    let state = state_with_entity();
    let first = explain_entity(&state, "ip:192.0.2.10", 10).unwrap();
    let second = explain_entity(&state, "ip:192.0.2.10", 10).unwrap();
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&second).unwrap()
    );
}
