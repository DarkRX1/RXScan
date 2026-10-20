//! Parity between the maintainer staging pack (`rxscan-icons/`, untracked)
//! and the committed copy (`app/assets/icons/`). Conditional: when the
//! staging directory is absent (CI), the test is a no-op so the suite stays
//! green on every platform.

use std::collections::BTreeSet;
use std::path::Path;

fn staging_root() -> Option<std::path::PathBuf> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rxscan-icons");
    if root.is_dir() { Some(root) } else { None }
}

fn committed_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("app/assets/icons")
}

fn collect_files(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    walk(root, root, &mut out);
    out
}

fn walk(base: &Path, dir: &Path, out: &mut BTreeSet<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk(base, &p, out);
        } else if p.is_file() {
            if let Ok(rel) = p.strip_prefix(base) {
                out.insert(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
}

#[test]
fn staging_and_committed_manifests_agree_when_present() {
    let Some(staging) = staging_root() else {
        return;
    };
    let committed = committed_root();
    let s_manifest = staging.join("manifest.json");
    let c_manifest = committed.join("manifest.json");
    if !s_manifest.is_file() || !c_manifest.is_file() {
        return;
    }
    let s_text = std::fs::read_to_string(&s_manifest).unwrap();
    let c_text = std::fs::read_to_string(&c_manifest).unwrap();
    assert_eq!(
        s_text, c_text,
        "manifest.json differs between staging and committed copy"
    );
}

#[test]
fn committed_assets_are_byte_identical_to_staging_when_present() {
    let Some(staging) = staging_root() else {
        return;
    };
    let committed = committed_root();
    let staged_files = collect_files(&staging);
    let committed_files = collect_files(&committed);
    // Every committed file must exist in staging with identical bytes.
    for rel in &committed_files {
        let s = staging.join(rel);
        if !s.is_file() {
            // Committed-only assets (none expected) are not a parity failure
            // for staging->committed direction; skip.
            continue;
        }
        let a = std::fs::read(staging.join(rel)).unwrap();
        let b = std::fs::read(committed.join(rel)).unwrap();
        assert_eq!(
            a, b,
            "asset differs between staging and committed copy: {rel}"
        );
    }
    // The committed set must be a subset of staging (no orphans in committed).
    for rel in &committed_files {
        assert!(
            staged_files.contains(rel),
            "committed asset has no staging counterpart: {rel}"
        );
    }
    let _ = (staged_files,);
}

#[test]
fn staging_has_no_missing_shared_assets_when_present() {
    let Some(staging) = staging_root() else {
        return;
    };
    let committed = committed_root();
    let committed_files = collect_files(&committed);
    // Shared subset: files present in both. Count should match committed count
    // (committed is a subset of staging).
    let shared: Vec<_> = committed_files
        .iter()
        .filter(|rel| staging.join(rel).is_file())
        .collect();
    assert_eq!(
        shared.len(),
        committed_files.len(),
        "some committed assets are absent from staging"
    );
}

#[test]
fn rust_display_kind_icons_resolve_to_shipped_glyphs() {
    use rxscan::graph_icons;
    use rxscan::graph_view::DisplayKind;
    let manifest: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(
            format!("{}/app/assets/icons/manifest.json", env!("CARGO_MANIFEST_DIR")),
        ).unwrap()).unwrap();
    let icons_dir = format!("{}/app/assets/icons", env!("CARGO_MANIFEST_DIR"));
    for kind in DisplayKind::all() {
        if let Some(icon) = graph_icons::icon_of(*kind) {
            assert!(
                manifest.contains_key(icon),
                "Rust icon '{icon}' for {kind} missing from manifest"
            );
            let path = format!("{}/glyphs/{}.svg", icons_dir, icon);
            assert!(
                std::path::Path::new(&path).is_file(),
                "Rust icon '{icon}' for {kind} has no glyph file"
            );
        }
    }
}

#[test]
fn manifest_keys_match_on_disk_glyphs() {
    let icons_dir = format!("{}/app/assets/icons", env!("CARGO_MANIFEST_DIR"));
    let manifest: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(
            format!("{}/manifest.json", icons_dir),
        ).unwrap()).unwrap();
    for (key, entry) in &manifest {
        let glyph = entry.get("glyph").and_then(|v| v.as_str()).unwrap();
        let path = format!("{}/glyphs/{}.svg", icons_dir, glyph);
        assert!(
            std::path::Path::new(&path).is_file(),
            "manifest key '{key}' glyph '{glyph}' missing on disk"
        );
    }
    // every glyph file is referenced by some manifest entry
    let mut referenced: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for entry in manifest.values() {
        if let Some(g) = entry.get("glyph").and_then(|v| v.as_str()) {
            referenced.insert(format!("{}.svg", g));
        }
    }
    let glyphs_dir = format!("{}/glyphs", icons_dir);
    for entry in std::fs::read_dir(&glyphs_dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".svg") && name != "rxscan-sprite.svg" {
            assert!(
                referenced.contains(&name),
                "orphan glyph file with no manifest reference: {name}"
            );
        }
    }
}
