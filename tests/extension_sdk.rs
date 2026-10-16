//! Phase 8 extension SDK: manifests, grants, packs, bounded contact.
//!
//! Loopback contact only; everything else is offline.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use rxscan::extension_sdk::{
    ExtensionContact, ExtensionContext, ExtensionOutput, ExtensionTransform, OutputEntity,
    ScopeGrant, TransformInput, parse_manifest,
};

fn manifest_text() -> String {
    std::fs::read_to_string(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/extension_example/manifest.json"),
    )
    .unwrap()
}

#[test]
fn manifest_file_loads_through_typed_loader() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/extension_example/manifest.json");
    let manifest = rxscan::extensions::load_extension_manifest(&path).unwrap();
    assert_eq!(manifest.id, "demo-rdss");
    assert_eq!(
        manifest.sdk_version,
        rxscan::extensions::EXTENSION_SDK_VERSION
    );
    assert_eq!(manifest.requires.max_requests, 4);
    // Missing file is a deterministic error, not a panic.
    assert!(rxscan::extensions::load_extension_manifest(&path.with_extension("missing")).is_err());
}

#[test]
fn fixture_fingerprint_pack_matches() {
    let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/extension_example/fingerprints");
    let loaded = rxscan::extension_sdk::load_extension_fingerprints("demo-rdss", &dir).unwrap();
    assert_eq!(loaded.extension_id, "demo-rdss");
    assert_eq!(loaded.packs.len(), 1);
    let matched = loaded.packs[0]
        .1
        .match_observation("http", "Server: SynctestServer/1.0")
        .expect("fixture rule fires");
    assert_eq!(matched.product, "SynctestServer");
    assert!(matched.confidence <= 95);
    assert!(
        loaded.packs[0]
            .1
            .match_observation("http", "Server: nginx")
            .is_none()
    );
    // Malformed packs fail deterministically (missing dirs yield empty,
    // per the shared loader contract — not an error).
    let bad = std::env::temp_dir().join(format!("rxscan-ext-bad-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&bad);
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(bad.join("bad.json"), "{not json").unwrap();
    assert!(rxscan::extension_sdk::load_extension_fingerprints("demo-rdss", &bad).is_err());
    let _ = std::fs::remove_dir_all(&bad);
}

struct LoopTransform {
    manifest: rxscan::extension_sdk::ExtensionManifest,
    port: u16,
}

impl ExtensionTransform for LoopTransform {
    fn manifest(&self) -> &rxscan::extension_sdk::ExtensionManifest {
        &self.manifest
    }

    fn execute(
        &self,
        ctx: &ExtensionContext<'_>,
        input: &TransformInput,
    ) -> Result<ExtensionOutput, ExtensionError> {
        let body = ctx.http_get("127.0.0.1", self.port, "/doc")?;
        Ok(ExtensionOutput {
            entities: vec![OutputEntity {
                id_suffix: format!("doc:{}", input.label),
                stored_kind: "document".to_owned(),
                label: body.chars().take(64).collect(),
                attributes: std::collections::BTreeMap::new(),
            }],
            relationships: vec![],
        })
    }
}

use rxscan::extension_sdk::ExtensionError;

#[test]
fn granted_contact_fetches_and_denied_rejects() {
    let manifest = parse_manifest(&manifest_text()).unwrap();
    let mut registry = rxscan::extension_sdk::ExtensionRegistry::new();
    registry.register(manifest.clone()).unwrap();
    assert_eq!(registry.len(), 1);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut head = [0u8; 512];
        let _ = stream.read(&mut head);
        let body = r#"{"ok":true}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    });

    let transform = LoopTransform {
        manifest: manifest.clone(),
        port,
    };
    let input = TransformInput {
        entity_id: "host:example.test".to_owned(),
        stored_kind: "hostname".to_owned(),
        label: "example.test".to_owned(),
        attributes: std::collections::BTreeMap::new(),
    };
    let cancelled = AtomicBool::new(false);

    // Denied grant: zero contact, permission error.
    let denied = ScopeGrant::compile(
        &manifest,
        ExtensionContact::PublicHttp,
        &["other.test".to_owned()],
    );
    match denied {
        Err(error) => assert!(matches!(error, ExtensionError::PermissionDenied(_))),
        Ok(grant) => {
            let ctx = ExtensionContext {
                grant: &grant,
                deadline: Instant::now() + Duration::from_secs(5),
                cancelled: &cancelled,
                now: 1,
            };
            let error = transform.execute(&ctx, &input).unwrap_err();
            assert!(matches!(error, ExtensionError::PermissionDenied(_)));
            assert_eq!(grant.requests_used(), 0);
        }
    }

    // Granted: exactly one request, namespaced entity out.
    let grant = ScopeGrant::compile(
        &manifest,
        ExtensionContact::PublicHttp,
        &["127.0.0.1".to_owned()],
    )
    .unwrap();
    let ctx = ExtensionContext {
        grant: &grant,
        deadline: Instant::now() + Duration::from_secs(10),
        cancelled: &cancelled,
        now: 1,
    };
    let output = transform
        .execute(&ctx, &input)
        .expect("granted run succeeds");
    server.join().unwrap();
    assert_eq!(output.entities.len(), 1);
    assert_eq!(grant.requests_used(), 1);
    let namespaced =
        rxscan::extension_sdk::extension_entity_id(&manifest.id, &output.entities[0].id_suffix);
    assert!(namespaced.starts_with("ext:demo-rdss:"));
}
