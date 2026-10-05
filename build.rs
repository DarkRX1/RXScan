//! Merge the split username provider corpus into one embedded bundle.
//!
//! Source files live in `search/providers/v1/username/<category>.json`.
//! Each file carries a full pack envelope; every file must agree on
//! `schema_version` and `pack_version`. Providers are merged in sorted
//! filename order and then sorted by provider ID, so the resulting pack
//! (and therefore `rxscan search providers` output) is deterministic.
//! Duplicate IDs across files are rejected here with the file named.

use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let corpus = manifest.join("search/providers/v1/username");
    println!("cargo::rerun-if-changed={}", corpus.display());

    let mut files: Vec<PathBuf> = std::fs::read_dir(&corpus)
        .unwrap_or_else(|_| panic!("corpus directory {} is missing", corpus.display()))
        .map(|entry| entry.expect("corpus directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no provider files in {}",
        corpus.display()
    );

    let mut schema_version: Option<u64> = None;
    let mut pack_version: Option<String> = None;
    let mut providers: Vec<serde_json::Value> = Vec::new();
    for file in &files {
        println!("cargo::rerun-if-changed={}", file.display());
        let text = std::fs::read_to_string(file)
            .unwrap_or_else(|_| panic!("cannot read {}", file.display()));
        let fragment: serde_json::Value = serde_json::from_str(&text)
            .unwrap_or_else(|_| panic!("{} is not valid JSON", file.display()));
        let schema = fragment
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_else(|| panic!("{} lacks schema_version", file.display()));
        let version = fragment
            .get("pack_version")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("{} lacks pack_version", file.display()));
        if let Some(expected) = schema_version {
            assert!(
                expected == schema,
                "{} schema_version {schema} disagrees",
                file.display()
            );
        }
        if let Some(expected) = &pack_version {
            assert!(
                expected == version,
                "{} pack_version {version} disagrees",
                file.display()
            );
        }
        schema_version = Some(schema);
        pack_version = Some(version.to_owned());
        let mut chunk = fragment
            .get("providers")
            .and_then(serde_json::Value::as_array)
            .unwrap_or_else(|| panic!("{} lacks providers", file.display()))
            .clone();
        providers.append(&mut chunk);
    }
    fn provider_id(value: &serde_json::Value) -> &str {
        value
            .get("metadata")
            .and_then(|meta| meta.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
    }
    providers.sort_by(|a, b| provider_id(a).cmp(provider_id(b)));
    let mut seen = std::collections::BTreeSet::new();
    for provider in &providers {
        let id = provider
            .get("metadata")
            .and_then(|m| m.get("id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        assert!(!id.is_empty(), "provider with empty id in merged corpus");
        assert!(seen.insert(id.to_owned()), "duplicate provider id '{id}'");
    }

    let bundle = serde_json::json!({
        "schema_version": schema_version.unwrap(),
        "pack_version": pack_version.unwrap(),
        "providers": providers,
    });
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("username_pack.json");
    std::fs::write(&out, serde_json::to_string(&bundle).unwrap()).unwrap();
}
