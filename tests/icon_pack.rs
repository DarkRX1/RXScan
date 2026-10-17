//! Icon-pack integrity tests for the shipped `app/assets/icons/` copy.
//!
//! These tests guard the files imported from `rxscan-icons/` during 1.2.0
//! polish. They run against the committed copy (not the repo-root pack,
//! which the maintainer removes). manifest.json is the single source of
//! truth for icon names, categories, ramps, shapes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

fn icons_dir() -> String {
    format!(
        "{}/app/assets/icons",
        std::env::var("CARGO_MANIFEST_DIR").unwrap()
    )
}

/// One manifest entry: the authoritative name -> encoding mapping.
#[derive(Debug, Deserialize)]
struct IconEntry {
    glyph: String,
    #[allow(dead_code)]
    ramp: String,
    #[allow(dead_code)]
    shape: String,
    category: String,
}

fn load_manifest() -> BTreeMap<String, IconEntry> {
    let path = format!("{}/manifest.json", icons_dir());
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("manifest.json missing at {path}"));
    serde_json::from_str::<BTreeMap<String, IconEntry>>(&text)
        .unwrap_or_else(|_| panic!("manifest.json is not valid JSON: {path}"))
}

/// Every SVG under the icons dir, recursively.
fn shipped_svgs() -> Vec<String> {
    let mut out = Vec::new();
    walk_svgs(Path::new(&icons_dir()), &mut out);
    out.sort();
    out
}

fn walk_svgs(dir: &Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let p = entry.path();
        if p.is_dir() {
            walk_svgs(&p, out);
        } else if p.extension().is_some_and(|e| e == "svg") {
            out.push(p.to_string_lossy().to_string());
        }
    }
}

const PER_FILE_SIZE_CAP: u64 = 64 * 1024; // 64 KiB

fn svg_violations(text: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let lowered = text.to_ascii_lowercase();
    if lowered.contains("<script") {
        problems.push("contains <script>".to_owned());
    }
    if lowered.contains("<foreignobject") {
        problems.push("contains <foreignObject>".to_owned());
    }
    // Any <image ...> tag (inline images fetch external/embedded raster data).
    let image_re = regex_lite_image_tag(&lowered);
    if image_re {
        problems.push("contains ".to_owned());
    }
    // Event-handler attributes (on*, case-insensitive).
    for ch in b'a'..=b'z' {
        let on = format!("on{}", char::from(ch));
        if lowered.contains(&format!(" {on}=")) || lowered.contains(&format!("{on}=")) {
            problems.push(format!("event-handler attribute {on}"));
        }
    }
    // External href references.
    if lowered.contains("href=\"http")
        || lowered.contains("href='http")
        || lowered.contains("href=http")
    {
        problems.push("external href reference".to_owned());
    }
    // url( ... ) CSS references.
    if lowered.contains("url(") {
        problems.push("url(...) reference".to_owned());
    }
    problems
}

fn regex_lite_image_tag(lowered: &str) -> bool {
    // Match <image followed by whitespace, /, or > (covers <image and <image ).
    let mut i = 0;
    while let Some(pos) = lowered[i..].find("<image") {
        let abs = i + pos;
        let after = &lowered[abs + 6..];
        if after.starts_with(' ')
            || after.starts_with('/')
            || after.starts_with('>')
            || after.is_empty()
        {
            return true;
        }
        i = abs + 6;
    }
    false
}

#[test]
fn svg_safety_every_shipped_file() {
    let svgs = shipped_svgs();
    assert!(
        !svgs.is_empty(),
        "no SVG files found under app/assets/icons/"
    );
    for path in &svgs {
        let metadata = std::fs::metadata(path).unwrap();
        assert!(
            metadata.len() <= PER_FILE_SIZE_CAP,
            "{path} exceeds {} byte per-file cap ({} bytes)",
            PER_FILE_SIZE_CAP,
            metadata.len()
        );
        let text = std::fs::read_to_string(path).unwrap();
        let problems = svg_violations(&text);
        assert!(
            problems.is_empty(),
            "{path} violates SVG safety: {}",
            problems.join(", ")
        );
    }
}

/// Sprite symbol ids present in rxscan-sprite.svg.
fn sprite_symbols() -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    let path = format!("{}/glyphs/rxscan-sprite.svg", icons_dir());
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("sprite missing: {path}"));
    let mut i = 0;
    while let Some(pos) = text[i..].find(r#"id="rx-"#) {
        let abs = i + pos + r#"id="rx-"#.len();
        let end = text[abs..].find('"').unwrap();
        set.insert(text[abs..abs + end].to_owned());
        i = abs + end;
    }
    set
}

#[test]
fn manifest_entries_match_shipped_files() {
    let manifest = load_manifest();
    assert!(!manifest.is_empty(), "manifest has no entries");

    // Every category is non-empty.
    let mut cats: BTreeMap<String, usize> = BTreeMap::new();
    for entry in manifest.values() {
        *cats.entry(entry.category.clone()).or_default() += 1;
    }
    for (cat, n) in &cats {
        assert!(*n > 0, "category {cat} is empty");
    }

    // Every manifest entry's glyph and tiles exist.
    for (key, entry) in &manifest {
        let glyph_path = format!("{}/glyphs/{}.svg", icons_dir(), entry.glyph);
        assert!(
            std::fs::metadata(&glyph_path).is_ok(),
            "manifest entry {key} references missing glyph {}.svg ({glyph_path})",
            entry.glyph
        );
        for theme in ["light", "dark"] {
            let tile_path = format!("{}/tiles/{}/{}.svg", icons_dir(), theme, key);
            assert!(
                std::fs::metadata(&tile_path).is_ok(),
                "manifest entry {key} missing tile tiles/{theme}/{key}.svg ({tile_path})"
            );
        }
    }

    // No orphan glyph files: every glyphs/<name>.svg except the sprite must be a
    // manifest glyph value.
    let glyph_values: BTreeSet<_> = manifest.values().map(|e| e.glyph.clone()).collect();
    let mut glyph_files: BTreeSet<_> = std::fs::read_dir(format!("{}/glyphs", icons_dir()))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|x| x == "svg"))
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .map(|s| s.trim_end_matches(".svg").to_owned())
        })
        .collect();
    glyph_files.remove("rxscan-sprite");
    let orphan_glyphs: BTreeSet<_> = glyph_files.difference(&glyph_values).cloned().collect();
    assert!(
        orphan_glyphs.is_empty(),
        "orphan glyph files not in manifest: {:?}",
        orphan_glyphs.into_iter().collect::<Vec<_>>()
    );

    // No orphan tile files: every tiles/<theme>/<name>.svg must be a manifest key.
    let keys: BTreeSet<_> = manifest.keys().cloned().collect();
    for theme in ["light", "dark"] {
        let tile_files: BTreeSet<_> = std::fs::read_dir(format!("{}/tiles/{theme}", icons_dir()))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "svg"))
            .filter_map(|e| {
                e.file_name()
                    .to_str()
                    .map(|s| s.trim_end_matches(".svg").to_owned())
            })
            .collect();
        let orphan_tiles: BTreeSet<_> = tile_files.difference(&keys).cloned().collect();
        assert!(
            orphan_tiles.is_empty(),
            "orphan tiles/{theme} files not in manifest: {:?}",
            orphan_tiles.into_iter().collect::<Vec<_>>()
        );
    }

    // Sprite symbols match the glyph set exactly.
    let symbols = sprite_symbols();
    assert_eq!(
        symbols, glyph_values,
        "sprite symbols must equal manifest glyph set"
    );
}
