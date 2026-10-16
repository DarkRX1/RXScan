//! Extension SDK worked example: a bounded public-source transform.
//!
//! Run: `cargo run --example extension_hello`
//!
//! Spins a loopback HTTP server serving one fixed JSON document, then runs
//! a demonstration transform twice through the real SDK permission path:
//!
//! 1. with a grant that omits the loopback host → the contact is rejected
//!    before any packet moves (zero requests made);
//! 2. with the correct grant → the transform fetches, parses bounded JSON,
//!    and yields namespaced entities.
//!
//! Everything is loopback-local and deterministic; no external network.

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

use rxscan::extension_sdk::{
    ExtensionContext, ExtensionError, ExtensionManifest, ExtensionOutput, ExtensionTransform,
    OutputEntity, ScopeGrant, cap_extension_confidence, extension_entity_id, parse_manifest,
};

const MANIFEST_JSON: &str = r#"{
    "sdk_version": 1,
    "id": "demo-rdss",
    "version": "0.1.0",
    "kind": "public_transform",
    "description": "Demonstration extension: bounded public contact with declared scope.",
    "requires": {"contact": "public_http", "hosts": ["127.0.0.1"], "max_requests": 4}
}"#;

struct DemoTransform {
    manifest: ExtensionManifest,
    port: u16,
}

impl ExtensionTransform for DemoTransform {
    fn manifest(&self) -> &ExtensionManifest {
        &self.manifest
    }

    fn execute(
        &self,
        ctx: &ExtensionContext<'_>,
        input: &rxscan::extension_sdk::TransformInput,
    ) -> Result<ExtensionOutput, ExtensionError> {
        // Grant-checked fetch (rejected before contact when ungranted).
        let body = ctx.http_get("127.0.0.1", self.port, "/info")?;
        let value: serde_json::Value = serde_json::from_str(&body)
            .map_err(|error| ExtensionError::Malformed(format!("bad JSON: {error}")))?;
        let product = value
            .get("product")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| ExtensionError::Malformed("document lacks product".to_owned()))?;
        let mut attributes = BTreeMap::from([
            ("product".to_owned(), product.chars().take(64).collect()),
            ("seed".to_owned(), input.label.chars().take(128).collect()),
        ]);
        if let Some(version) = value.get("version").and_then(serde_json::Value::as_str) {
            attributes.insert("version".to_owned(), version.chars().take(32).collect());
        }
        Ok(ExtensionOutput {
            entities: vec![OutputEntity {
                id_suffix: format!("tech:{}", product.to_ascii_lowercase()),
                stored_kind: "technology".to_owned(),
                label: product.to_owned(),
                attributes,
            }],
            relationships: vec![],
        })
    }
}

fn serve_once(listener: &TcpListener) {
    let (mut stream, _) = listener.accept().expect("loopback accept");
    let mut head = [0u8; 1024];
    let _ = stream.read(&mut head);
    let body = r#"{"product":"SynctestServer","version":"1.0"}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("loopback write");
}

fn main() {
    let manifest = parse_manifest(MANIFEST_JSON).expect("example manifest parses");
    assert_eq!(manifest.id, "demo-rdss");
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    let port = listener.local_addr().expect("port").port();

    let cancelled = AtomicBool::new(false);
    let input = rxscan::extension_sdk::TransformInput {
        entity_id: "host:example.test".to_owned(),
        stored_kind: "hostname".to_owned(),
        label: "example.test".to_owned(),
        attributes: BTreeMap::new(),
    };
    let transform = DemoTransform {
        manifest: manifest.clone(),
        port,
    };

    // 1. Wrong grant (host not granted): rejected with zero contact.
    let narrow = ScopeGrant::compile(
        &manifest,
        rxscan::extension_sdk::ExtensionContact::PublicHttp,
        &["other.test".to_owned()],
    );
    match narrow {
        Err(error) => println!("narrow grant correctly refused at compile: {error}"),
        Ok(grant) => {
            let ctx = ExtensionContext {
                grant: &grant,
                deadline: Instant::now() + Duration::from_secs(5),
                cancelled: &cancelled,
                now: 1,
            };
            match transform.execute(&ctx, &input) {
                Err(error) => println!("ungranted contact correctly rejected: {error}"),
                Ok(_) => {
                    eprintln!("ERROR: ungranted contact succeeded");
                    std::process::exit(1);
                }
            }
            assert_eq!(grant.requests_used(), 0);
        }
    }

    // 2. Correct grant: fetch from the loopback server, derive entities.
    let grant = ScopeGrant::compile(
        &manifest,
        rxscan::extension_sdk::ExtensionContact::PublicHttp,
        &["127.0.0.1".to_owned()],
    )
    .expect("grant compiles");
    let server = std::thread::spawn(move || serve_once(&listener));
    let ctx = ExtensionContext {
        grant: &grant,
        deadline: Instant::now() + Duration::from_secs(10),
        cancelled: &cancelled,
        now: 1,
    };
    let output = transform
        .execute(&ctx, &input)
        .expect("granted run succeeds");
    server.join().expect("server done");
    assert_eq!(output.entities.len(), 1);
    let entity = &output.entities[0];
    let namespaced = extension_entity_id(&manifest.id, &entity.id_suffix);
    let confidence = cap_extension_confidence(95);
    println!(
        "extension entity: {namespaced} label={} confidence={confidence}",
        entity.label
    );
    println!(
        "requests used: {} (budget {})",
        grant.requests_used(),
        manifest.requires.max_requests
    );
    assert!(grant.requests_used() <= manifest.requires.max_requests as usize);
    assert!(!cancelled.load(Ordering::Acquire));
    println!("extension example complete: deny-by-default enforced, granted run derived 1 entity");
}
