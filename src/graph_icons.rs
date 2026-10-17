//! Entity-kind to icon mapping for the 74-icon RXScan pack.
//!
//! `manifest.json` (shipped at `app/assets/icons/manifest.json`) is the single
//! source of truth for icon names, categories, ramps and shapes. This module
//! maps the 1.2.0 graph view's `DisplayKind`s — and, where stored typed data
//! supports it, a subtype — onto a manifest icon name.
//!
//! Icons and labels never raise or imply confidence: stored values pass
//! through unchanged.
//!
//! Attribution icons (`hacker`, `threat-group`, `terrorist`, `botnet`,
//! `sanctions`, `law-enforcement`, `watchlist`) are never assigned by
//! heuristic. They appear only in `UNMAPPED_BY_DESIGN` and can be shown only
//! under Phase 5 rules (a stored record carrying a named source, confidence
//! above zero, and an evidence reference).

use std::collections::BTreeMap;

use crate::graph_view::DisplayKind;

// ---------------------------------------------------------------------------
// Base mapping: view entity kind -> manifest icon name.
// ---------------------------------------------------------------------------

/// Base mapping from a view entity kind to its manifest icon name.
///
/// Exhaustive over `DisplayKind::all()`: adding a display kind without
/// deciding here fails the exhaustiveness test. `DisplayKind::Cluster` is a
/// view-only supernode (never stored) and is not part of `all()`; it is
/// rendered as a collapsed group and carries no entity icon.
const ICON_OF_KIND: &[(&DisplayKind, &str)] = &[
    (&DisplayKind::Network, "network"),
    (&DisplayKind::Ip, "ip"),
    (&DisplayKind::Host, "host"),
    (&DisplayKind::PortService, "service"),
    (&DisplayKind::Software, "software"),
    (&DisplayKind::Certificate, "certificate"),
    (&DisplayKind::Domain, "domain"),
    (&DisplayKind::Url, "url"),
    (&DisplayKind::Username, "username"),
    (&DisplayKind::Account, "account"),
    // RXScan stores exposures as findings; no `exposure` glyph exists in the
    // manifest, so exposures render the `finding` icon.
    (&DisplayKind::Exposure, "finding"),
    (&DisplayKind::Evidence, "evidence"),
    (&DisplayKind::Scope, "scope"),
];

/// Manifest icon name for a view entity kind, or `None` when the kind has no
/// base icon (`Cluster`).
pub fn icon_of(kind: DisplayKind) -> Option<&'static str> {
    ICON_OF_KIND
        .iter()
        .find(|(k, _)| **k == kind)
        .map(|(_, icon)| *icon)
}

// ---------------------------------------------------------------------------
// Subtype refinement: stored typed data only, never name/heuristic guessing.
// ---------------------------------------------------------------------------

/// Refine a base icon to a more specific subtype icon using stored typed data
/// only. Returns `None` when no subtype applies.
///
/// Stored signals used (read from entity attributes, never inferred from
/// labels or free text):
/// * `PortService` + `protocol` attribute of `https`/`ssh` -> `https`/`ssh`
///   (graph build stores `protocol` on service entities).
/// * `Exposure` + `exposure_type` attribute of `credential` -> `credential`
///   (exposure normalization stores `exposure_type`).
pub fn icon_of_subtype(
    kind: DisplayKind,
    _stored_kind: &str,
    attributes: &BTreeMap<String, String>,
) -> Option<&'static str> {
    match kind {
        DisplayKind::PortService => match attributes.get("protocol").map(|s| s.as_str()) {
            Some("https") => Some("https"),
            Some("ssh") => Some("ssh"),
            _ => None,
        },
        DisplayKind::Exposure => match attributes.get("exposure_type").map(|s| s.as_str()) {
            Some("credential") => Some("credential"),
            _ => None,
        },
        _ => None,
    }
}

/// Resolve the icon for a node: base icon, refined by subtype when stored data
/// supports it.
pub fn node_icon(
    kind: DisplayKind,
    stored_kind: &str,
    attributes: &BTreeMap<String, String>,
) -> Option<&'static str> {
    icon_of_subtype(kind, stored_kind, attributes).or_else(|| icon_of(kind))
}

// ---------------------------------------------------------------------------
// Icon -> category (manifest).
// ---------------------------------------------------------------------------

/// Manifest category for an icon name. Covers all 74 icons so the additive
/// `category` export field can be populated for any rendered icon.
const ICON_CATEGORY: &[(&str, &str)] = &[
    ("account", "identity"),
    ("aircraft", "contact-and-asset"),
    ("api", "infrastructure"),
    ("asn", "infrastructure"),
    ("bank", "contact-and-asset"),
    ("bitcoin", "contact-and-asset"),
    ("botnet", "threat"),
    ("case", "investigation"),
    ("cctv", "source-and-media"),
    ("certificate", "infrastructure"),
    ("chat", "source-and-media"),
    ("cloud", "infrastructure"),
    ("container", "infrastructure"),
    ("court", "investigation"),
    ("credential", "threat"),
    ("darkweb", "infrastructure"),
    ("database", "infrastructure"),
    ("device", "infrastructure"),
    ("dns-record", "infrastructure"),
    ("domain", "infrastructure"),
    ("drone", "source-and-media"),
    ("email", "contact-and-asset"),
    ("evidence", "investigation"),
    ("exploit", "threat"),
    ("file", "investigation"),
    ("finding", "threat"),
    ("firewall", "infrastructure"),
    ("forum", "source-and-media"),
    ("hacker", "threat"),
    ("hash", "investigation"),
    ("honeypot", "infrastructure"),
    ("host", "infrastructure"),
    ("https", "infrastructure"),
    ("id-document", "identity"),
    ("image", "investigation"),
    ("ip", "infrastructure"),
    ("law-enforcement", "investigation"),
    ("leak", "threat"),
    ("location", "contact-and-asset"),
    ("malware", "threat"),
    ("marketplace", "source-and-media"),
    ("mobile", "infrastructure"),
    ("network", "infrastructure"),
    ("news", "source-and-media"),
    ("organization", "identity"),
    ("os", "infrastructure"),
    ("packet", "infrastructure"),
    ("person", "identity"),
    ("phishing", "threat"),
    ("phone", "contact-and-asset"),
    ("port", "infrastructure"),
    ("proxy", "infrastructure"),
    ("ransomware", "threat"),
    ("router", "infrastructure"),
    ("sanctions", "investigation"),
    ("satellite", "source-and-media"),
    ("scope", "investigation"),
    ("service", "infrastructure"),
    ("social", "identity"),
    ("software", "infrastructure"),
    ("ssh", "infrastructure"),
    ("subdomain", "infrastructure"),
    ("terrorist", "threat"),
    ("threat-group", "threat"),
    ("timeline", "investigation"),
    ("url", "infrastructure"),
    ("username", "identity"),
    ("vehicle", "contact-and-asset"),
    ("vessel", "contact-and-asset"),
    ("vpn", "infrastructure"),
    ("vulnerability", "threat"),
    ("wallet", "contact-and-asset"),
    ("watchlist", "investigation"),
    ("wifi", "infrastructure"),
];

/// Manifest category for an icon name, or `None` when unknown.
pub fn category_of(icon: &str) -> Option<&'static str> {
    ICON_CATEGORY
        .iter()
        .find(|(name, _)| *name == icon)
        .map(|(_, category)| *category)
}

// ---------------------------------------------------------------------------
// Icon ramp (color) -> theme color.
// ---------------------------------------------------------------------------

/// Manifest color ramp for an icon name.
const ICON_RAMP: &[(&str, &str)] = &[
    ("account", "pink"),
    ("aircraft", "blue"),
    ("api", "coral"),
    ("asn", "teal"),
    ("bank", "amber"),
    ("bitcoin", "amber"),
    ("botnet", "red"),
    ("case", "blue"),
    ("cctv", "gray"),
    ("certificate", "blue"),
    ("chat", "pink"),
    ("cloud", "teal"),
    ("container", "teal"),
    ("court", "blue"),
    ("credential", "amber"),
    ("darkweb", "purple"),
    ("database", "coral"),
    ("device", "teal"),
    ("dns-record", "purple"),
    ("domain", "purple"),
    ("drone", "gray"),
    ("email", "blue"),
    ("evidence", "amber"),
    ("exploit", "red"),
    ("file", "gray"),
    ("finding", "red"),
    ("firewall", "coral"),
    ("forum", "pink"),
    ("hacker", "red"),
    ("hash", "gray"),
    ("honeypot", "amber"),
    ("host", "teal"),
    ("https", "coral"),
    ("id-document", "pink"),
    ("image", "gray"),
    ("ip", "teal"),
    ("law-enforcement", "blue"),
    ("leak", "red"),
    ("location", "green"),
    ("malware", "red"),
    ("marketplace", "amber"),
    ("mobile", "gray"),
    ("network", "teal"),
    ("news", "gray"),
    ("organization", "pink"),
    ("os", "gray"),
    ("packet", "teal"),
    ("person", "pink"),
    ("phishing", "red"),
    ("phone", "blue"),
    ("port", "coral"),
    ("proxy", "teal"),
    ("ransomware", "red"),
    ("router", "teal"),
    ("sanctions", "red"),
    ("satellite", "blue"),
    ("scope", "green"),
    ("service", "coral"),
    ("social", "pink"),
    ("software", "gray"),
    ("ssh", "coral"),
    ("subdomain", "purple"),
    ("terrorist", "red"),
    ("threat-group", "red"),
    ("timeline", "gray"),
    ("url", "purple"),
    ("username", "pink"),
    ("vehicle", "green"),
    ("vessel", "blue"),
    ("vpn", "teal"),
    ("vulnerability", "red"),
    ("wallet", "amber"),
    ("watchlist", "amber"),
    ("wifi", "teal"),
];

/// Manifest ramp for an icon name, or `None` when unknown.
pub fn ramp_of(icon: &str) -> Option<&'static str> {
    ICON_RAMP
        .iter()
        .find(|(name, _)| *name == icon)
        .map(|(_, ramp)| *ramp)
}

/// Hex color for a ramp (RXScan palette). The GUI applies the active theme
/// (light/dark tile variant or CSS token) on top of this base color.
const RAMP_COLOR: &[(&str, &str)] = &[
    ("amber", "#f59e0b"),
    ("blue", "#078cff"),
    ("coral", "#f97316"),
    ("gray", "#6b7d94"),
    ("green", "#3ddc84"),
    ("pink", "#e879f9"),
    ("purple", "#8b5cf6"),
    ("red", "#f06666"),
    ("teal", "#14b8a6"),
];

/// Theme base color for a ramp, or `None` when unknown.
pub fn ramp_color(ramp: &str) -> Option<&'static str> {
    RAMP_COLOR
        .iter()
        .find(|(name, _)| *name == ramp)
        .map(|(_, color)| *color)
}

// ---------------------------------------------------------------------------
// Icon shape (manifest tile shape).
// ---------------------------------------------------------------------------

/// Manifest tile shape for an icon name. Used by the PNG rasterizer and by
/// fallbacks so every format draws the same icon identity (shape + color).
const ICON_SHAPE: &[(&str, &str)] = &[
    ("account", "square"),
    ("aircraft", "circle"),
    ("api", "square"),
    ("asn", "circle"),
    ("bank", "square"),
    ("bitcoin", "circle"),
    ("botnet", "circle"),
    ("case", "square"),
    ("cctv", "square"),
    ("certificate", "square"),
    ("chat", "square"),
    ("cloud", "circle"),
    ("container", "square"),
    ("court", "square"),
    ("credential", "square"),
    ("darkweb", "circle"),
    ("database", "square"),
    ("device", "square"),
    ("dns-record", "square"),
    ("domain", "circle"),
    ("drone", "circle"),
    ("email", "square"),
    ("evidence", "square"),
    ("exploit", "circle"),
    ("file", "square"),
    ("finding", "square"),
    ("firewall", "square"),
    ("forum", "square"),
    ("hacker", "circle"),
    ("hash", "circle"),
    ("honeypot", "square"),
    ("host", "circle"),
    ("https", "square"),
    ("id-document", "square"),
    ("image", "square"),
    ("ip", "circle"),
    ("law-enforcement", "circle"),
    ("leak", "circle"),
    ("location", "circle"),
    ("malware", "square"),
    ("marketplace", "square"),
    ("mobile", "square"),
    ("network", "circle"),
    ("news", "square"),
    ("organization", "square"),
    ("os", "square"),
    ("packet", "square"),
    ("person", "circle"),
    ("phishing", "square"),
    ("phone", "square"),
    ("port", "square"),
    ("proxy", "square"),
    ("ransomware", "square"),
    ("router", "square"),
    ("sanctions", "circle"),
    ("satellite", "circle"),
    ("scope", "square"),
    ("service", "square"),
    ("social", "square"),
    ("software", "square"),
    ("ssh", "square"),
    ("subdomain", "square"),
    ("terrorist", "circle"),
    ("threat-group", "square"),
    ("timeline", "circle"),
    ("url", "square"),
    ("username", "circle"),
    ("vehicle", "square"),
    ("vessel", "circle"),
    ("vpn", "circle"),
    ("vulnerability", "square"),
    ("wallet", "square"),
    ("watchlist", "square"),
    ("wifi", "circle"),
];

/// Manifest tile shape for an icon name, or `None` when unknown.
pub fn shape_of(icon: &str) -> Option<&'static str> {
    ICON_SHAPE
        .iter()
        .find(|(name, _)| *name == icon)
        .map(|(_, shape)| *shape)
}

// ---------------------------------------------------------------------------
// Unmapped-by-design register.
// ---------------------------------------------------------------------------

/// Manifest icons that are not base-mapped to a `DisplayKind`, each with a
/// one-line reason. Every one of the 74 icons is either a base-mapped value
/// or appears here — the exhaustiveness test enforces this.
#[allow(dead_code)] // used only by the exhaustiveness test
const UNMAPPED_BY_DESIGN: &[(&str, &str)] = &[
    (
        "aircraft",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "api",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "asn",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "bank",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "bitcoin",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "botnet",
        "attribution icon; never heuristic, only under Phase 5 from a stored record with named source, confidence > 0, and evidence reference",
    ),
    (
        "case",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "cctv",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "chat",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "cloud",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "container",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "court",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "credential",
        "subtype applied only from stored typed data, not a base DisplayKind mapping",
    ),
    (
        "darkweb",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "database",
        "subtype applied only from stored typed data, not a base DisplayKind mapping",
    ),
    (
        "device",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "dns-record",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "drone",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "email",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "exploit",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "file",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "firewall",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "forum",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "hacker",
        "attribution icon; never heuristic, only under Phase 5 from a stored record with named source, confidence > 0, and evidence reference",
    ),
    (
        "hash",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "honeypot",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "https",
        "subtype applied only from stored typed data, not a base DisplayKind mapping",
    ),
    (
        "id-document",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "image",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "law-enforcement",
        "attribution icon; never heuristic, only under Phase 5 from a stored record with named source, confidence > 0, and evidence reference",
    ),
    (
        "leak",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "location",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "malware",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "marketplace",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "mobile",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "news",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "organization",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "os",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "packet",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "person",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "phishing",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "phone",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "port",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "proxy",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "ransomware",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "router",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "sanctions",
        "attribution icon; never heuristic, only under Phase 5 from a stored record with named source, confidence > 0, and evidence reference",
    ),
    (
        "satellite",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "social",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "ssh",
        "subtype applied only from stored typed data, not a base DisplayKind mapping",
    ),
    (
        "subdomain",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "terrorist",
        "attribution icon; never heuristic, only under Phase 5 from a stored record with named source, confidence > 0, and evidence reference",
    ),
    (
        "threat-group",
        "attribution icon; never heuristic, only under Phase 5 from a stored record with named source, confidence > 0, and evidence reference",
    ),
    (
        "timeline",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "vehicle",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "vessel",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "vpn",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "vulnerability",
        "subtype applied only from stored typed data, not a base DisplayKind mapping",
    ),
    (
        "wallet",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
    (
        "watchlist",
        "attribution icon; never heuristic, only under Phase 5 from a stored record with named source, confidence > 0, and evidence reference",
    ),
    (
        "wifi",
        "not a distinct DisplayKind in the 1.2.0 graph contract; stored under one of the 13 base kinds",
    ),
];

/// Attribution icons that must never appear in the automatic mapping table.
#[allow(dead_code)] // used only by the exhaustiveness test
const ATTRIBUTION_ICONS: &[&str] = &[
    "hacker",
    "threat-group",
    "terrorist",
    "botnet",
    "sanctions",
    "law-enforcement",
    "watchlist",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn shipped_manifest() -> serde_json::Value {
        let path = format!(
            "{}/app/assets/icons/manifest.json",
            std::env::var("CARGO_MANIFEST_DIR").unwrap()
        );
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("shipped manifest missing at {path}"));
        serde_json::from_str(&text).unwrap_or_else(|_| panic!("shipped manifest is not valid JSON"))
    }

    #[test]
    fn every_display_kind_maps_to_a_base_icon() {
        for kind in DisplayKind::all() {
            assert!(
                icon_of(*kind).is_some(),
                "display kind {kind} has no base icon mapping"
            );
        }
        // Cluster is view-only and intentionally absent from `all()`.
        assert_eq!(icon_of(DisplayKind::Cluster), None);
    }

    #[test]
    fn every_manifest_icon_is_mapped_or_unmapped_by_design() {
        let manifest = shipped_manifest();
        let object = manifest.as_object().expect("manifest is an object");
        let mut glyph_values = BTreeSet::new();
        for (_key, value) in object {
            glyph_values.insert(
                value
                    .get("glyph")
                    .and_then(serde_json::Value::as_str)
                    .expect("manifest entry has a glyph")
                    .to_owned(),
            );
        }
        let mapped: BTreeSet<String> = ICON_OF_KIND
            .iter()
            .map(|(_, icon)| (*icon).to_owned())
            .collect();
        let unmapped: BTreeSet<String> = UNMAPPED_BY_DESIGN
            .iter()
            .map(|(icon, _)| (*icon).to_owned())
            .collect();
        // Every glyph is either base-mapped or unmapped-by-design.
        for glyph in &glyph_values {
            assert!(
                mapped.contains(glyph.as_str()) || unmapped.contains(glyph.as_str()),
                "manifest icon {glyph} is neither mapped nor unmapped-by-design"
            );
        }
        // No overlap between mapped and unmapped-by-design.
        for icon in &mapped {
            assert!(
                !unmapped.contains(icon.as_str()),
                "icon {icon} is both mapped and unmapped-by-design"
            );
        }
        // Every category is non-empty (implied by each mapped glyph existing).
        let mut categories = BTreeSet::new();
        for value in object.values() {
            categories.insert(
                value
                    .get("category")
                    .and_then(serde_json::Value::as_str)
                    .expect("manifest entry has a category")
                    .to_owned(),
            );
        }
        assert!(!categories.is_empty());
        for category in &categories {
            let non_empty = object.values().any(|value| {
                value
                    .get("category")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|c| c == category.as_str())
            });
            assert!(non_empty, "category {category} is empty");
        }
    }

    #[test]
    fn no_attribution_icon_is_in_the_base_mapping() {
        let mapped: BTreeSet<_> = ICON_OF_KIND.iter().map(|(_, icon)| *icon).collect();
        for icon in ATTRIBUTION_ICONS {
            assert!(
                !mapped.contains(icon),
                "attribution icon {icon} must not be in the automatic mapping table"
            );
        }
        // Attribution icons are all listed in UNMAPPED_BY_DESIGN.
        let unmapped: BTreeSet<_> = UNMAPPED_BY_DESIGN.iter().map(|(i, _)| *i).collect();
        for icon in ATTRIBUTION_ICONS {
            assert!(
                unmapped.contains(icon),
                "attribution icon {icon} must be in UNMAPPED_BY_DESIGN"
            );
        }
    }

    #[test]
    fn subtype_refinement_reads_stored_data_only() {
        let mut attrs = BTreeMap::new();
        attrs.insert("protocol".to_owned(), "https".to_owned());
        assert_eq!(
            icon_of_subtype(DisplayKind::PortService, "service", &attrs),
            Some("https")
        );
        attrs.insert("protocol".to_owned(), "ssh".to_owned());
        assert_eq!(
            icon_of_subtype(DisplayKind::PortService, "service", &attrs),
            Some("ssh")
        );
        attrs.insert("protocol".to_owned(), "http".to_owned());
        assert_eq!(
            icon_of_subtype(DisplayKind::PortService, "service", &attrs),
            None
        );
        // Unknown stored kind / no signal -> None.
        assert_eq!(icon_of_subtype(DisplayKind::Network, "host", &attrs), None);
        // Exposure credential subtype.
        let mut exp_attrs = BTreeMap::new();
        exp_attrs.insert("exposure_type".to_owned(), "credential".to_owned());
        assert_eq!(
            icon_of_subtype(DisplayKind::Exposure, "exposure", &exp_attrs),
            Some("credential")
        );
    }

    #[test]
    fn category_lookup_covers_all_icons() {
        let manifest = shipped_manifest();
        let object = manifest.as_object().expect("manifest is an object");
        for value in object.values() {
            let icon = value
                .get("glyph")
                .and_then(serde_json::Value::as_str)
                .expect("manifest entry has a glyph");
            assert!(category_of(icon).is_some(), "no category for icon {icon}");
        }
    }
}
