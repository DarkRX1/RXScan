//! Maltego-style link-analysis view over the stored evidence graph.
//!
//! The stored model (`graph.rs`: 33 `EntityKind`s, 42 `EdgeRelation`s,
//! SQLite persistence in `project_db.rs`) is frozen for compatibility.
//! This module is a *view lens*: it maps stored kinds/relations onto the
//! 13 display entities and 9 display links of the 1.2.0 graph contract,
//! derives observed-vs-inferred styling and confidence thickness, and
//! serializes masked, bounded artifacts (JSON, GraphML, SVG, standalone
//! HTML, PNG) shared by the CLI (`rxscan graph`), the local API, and the
//! offline GUI report.
//!
//! Invariants:
//! * Every view node/edge traces to stored evidence with a confidence.
//!   Nothing is drawn without a source; confidence values are shown, never
//!   inflated (stored values pass through unchanged).
//! * Secret-safe: labels, ids, attributes, and evidence excerpts are
//!   masked via `exposure::mask_*` at view-build time, so CLI/API/GUI/
//!   export paths share one masking point. Masking is deterministic, so
//!   masked ids still join correctly.
//! * Bounded: node/edge caps, bounded layout iterations, bounded evidence
//!   excerpts, bounded PNG dimensions.
//! * Deterministic: sorted traversal, fixed seeds, no wall-clock input.
//!   The same stored graph always yields the same view bytes.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use serde::{Deserialize, Serialize};

/// View schema version for JSON/HTML payloads.
pub const VIEW_SCHEMA_VERSION: u16 = 1;
/// Default node cap (matches the API's historical 500-node page).
pub const DEFAULT_VIEW_NODES: usize = 500;
/// Hard node cap for any single view (bounded memory/time at 50k scale).
pub const MAX_VIEW_NODES: usize = 50_000;
/// Default edge cap.
pub const DEFAULT_VIEW_EDGES: usize = 1000;
/// Hard edge cap for any single view.
pub const MAX_VIEW_EDGES: usize = 100_000;
/// Maximum evidence excerpts surfaced per view node/edge.
pub const MAX_VIEW_EVIDENCE: usize = 4;
/// Maximum PNG dimension (width or height).
pub const MAX_PNG_DIM: u32 = 4096;

/// Embedded icon sprite: symbols defined once, referenced by `<use>` so
/// glyphs are never duplicated per node in SVG/HTML exports.
const ICON_SPRITE: &str = include_str!("../app/assets/icons/glyphs/rxscan-sprite.svg");

// ---------------------------------------------------------------------------
// Display entities.
// ---------------------------------------------------------------------------

/// The 13 display entities of the 1.2.0 graph contract plus `Cluster`
/// (a view-only supernode produced by collapsing, never stored).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayKind {
    Network,
    Ip,
    Host,
    PortService,
    Software,
    Certificate,
    Domain,
    Url,
    Username,
    Account,
    Exposure,
    Evidence,
    Scope,
    Cluster,
}

impl DisplayKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Ip => "ip",
            Self::Host => "host",
            Self::PortService => "port_service",
            Self::Software => "software",
            Self::Certificate => "certificate",
            Self::Domain => "domain",
            Self::Url => "url",
            Self::Username => "username",
            Self::Account => "account",
            Self::Exposure => "exposure",
            Self::Evidence => "evidence",
            Self::Scope => "scope",
            Self::Cluster => "cluster",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "network" => Some(Self::Network),
            "ip" => Some(Self::Ip),
            "host" => Some(Self::Host),
            "port_service" | "port/service" | "port-service" | "port" | "service" => {
                Some(Self::PortService)
            }
            "software" | "software/version" | "software-version" | "version" => {
                Some(Self::Software)
            }
            "certificate" | "cert" => Some(Self::Certificate),
            "domain" => Some(Self::Domain),
            "url" => Some(Self::Url),
            "username" | "user" => Some(Self::Username),
            "account" | "account/profile" | "account-profile" | "profile" => Some(Self::Account),
            "exposure" | "exposure_finding" | "exposure-finding" | "finding" => {
                Some(Self::Exposure)
            }
            "evidence" => Some(Self::Evidence),
            "scope" => Some(Self::Scope),
            "cluster" => Some(Self::Cluster),
            _ => None,
        }
    }

    /// All filterable kinds in stable order (legend/CLI help share this).
    pub fn all() -> &'static [DisplayKind] {
        &[
            Self::Network,
            Self::Ip,
            Self::Host,
            Self::PortService,
            Self::Software,
            Self::Certificate,
            Self::Domain,
            Self::Url,
            Self::Username,
            Self::Account,
            Self::Exposure,
            Self::Evidence,
            Self::Scope,
        ]
    }

    /// Fill color (hex). Never the sole encoding: [`DisplayKind::shape`]
    /// also distinguishes every kind.
    pub fn color(self) -> &'static str {
        match self {
            Self::Network => "#078cff",
            Self::Ip => "#00efff",
            Self::Host => "#3ddc84",
            Self::PortService => "#f0a04b",
            Self::Software => "#b07cc4",
            Self::Certificate => "#e5488f",
            Self::Domain => "#19f4ff",
            Self::Url => "#8fa9c2",
            Self::Username => "#e2e8f0",
            Self::Account => "#f4f8ff",
            Self::Exposure => "#f06666",
            Self::Evidence => "#6b7d94",
            Self::Scope => "#4a9eff",
            Self::Cluster => "#2a4a6b",
        }
    }

    /// Glyph shape: circle, square, diamond, triangle, triangle_down,
    /// hexagon, ellipse, pentagon, octagon, rounded_rect, ring, double_square.
    pub fn shape(self) -> &'static str {
        match self {
            Self::Network => "hexagon",
            Self::Ip => "circle",
            Self::Host => "square",
            Self::PortService => "diamond",
            Self::Software => "triangle",
            Self::Certificate => "pentagon",
            Self::Domain => "ellipse",
            Self::Url => "rounded_rect",
            Self::Username => "ring",
            Self::Account => "double_square",
            Self::Exposure => "triangle_down",
            Self::Evidence => "parallelogram",
            Self::Scope => "dashed_circle",
            Self::Cluster => "octagon",
        }
    }
}

impl std::fmt::Display for DisplayKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Map a stored `EntityKind` onto its display entity. Exhaustive (no
/// wildcard) so new stored kinds fail compilation until mapped.
pub fn display_kind_of(kind: crate::graph::EntityKind) -> DisplayKind {
    use crate::graph::EntityKind as K;
    match kind {
        K::NetworkPrefix | K::Asn | K::Route | K::Provider => DisplayKind::Network,
        K::IpAddress => DisplayKind::Ip,
        K::Host | K::Hostname => DisplayKind::Host,
        K::Port | K::Service | K::NetworkEndpoint => DisplayKind::PortService,
        K::Software
        | K::Technology
        | K::Package
        | K::Fingerprint
        | K::OsCandidate
        | K::DeviceCandidate => DisplayKind::Software,
        K::Certificate | K::SshHostKey | K::PublicKey => DisplayKind::Certificate,
        K::Domain | K::DnsRecord => DisplayKind::Domain,
        K::WebEndpoint | K::Document | K::ArchiveSnapshot | K::Repository => DisplayKind::Url,
        K::Username | K::EmailAddress | K::PhoneNumber => DisplayKind::Username,
        K::Account | K::Organization | K::IdentityHypothesis => DisplayKind::Account,
        K::Exposure | K::ExposureSource => DisplayKind::Exposure,
    }
}

// ---------------------------------------------------------------------------
// Display links.
// ---------------------------------------------------------------------------

/// The 9 display links of the 1.2.0 graph contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DisplayRel {
    ResolvesTo,
    Hosts,
    Runs,
    ServesCert,
    SignedBy,
    SameFingerprint,
    FoundOn,
    CorrelatedWith,
    DerivedFrom,
}

impl DisplayRel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ResolvesTo => "resolves-to",
            Self::Hosts => "hosts",
            Self::Runs => "runs",
            Self::ServesCert => "serves-cert",
            Self::SignedBy => "signed-by",
            Self::SameFingerprint => "same-fingerprint",
            Self::FoundOn => "found-on",
            Self::CorrelatedWith => "correlated-with",
            Self::DerivedFrom => "derived-from",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "resolves-to" | "resolves_to" => Some(Self::ResolvesTo),
            "hosts" => Some(Self::Hosts),
            "runs" => Some(Self::Runs),
            "serves-cert" | "serves_cert" => Some(Self::ServesCert),
            "signed-by" | "signed_by" => Some(Self::SignedBy),
            "same-fingerprint" | "same_fingerprint" => Some(Self::SameFingerprint),
            "found-on" | "found_on" => Some(Self::FoundOn),
            "correlated-with" | "correlated_with" => Some(Self::CorrelatedWith),
            "derived-from" | "derived_from" => Some(Self::DerivedFrom),
            _ => None,
        }
    }

    pub fn all() -> &'static [DisplayRel] {
        &[
            Self::ResolvesTo,
            Self::Hosts,
            Self::Runs,
            Self::ServesCert,
            Self::SignedBy,
            Self::SameFingerprint,
            Self::FoundOn,
            Self::CorrelatedWith,
            Self::DerivedFrom,
        ]
    }
}

impl std::fmt::Display for DisplayRel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Map a stored relation onto `(display link, directly observed?)`.
/// Exhaustive (no wildcard) so new stored relations fail compilation
/// until classified. Inferred links render dashed; observed render solid.
pub fn display_rel_of(relation: crate::graph::EdgeRelation) -> (DisplayRel, bool) {
    use crate::graph::EdgeRelation as R;
    match relation {
        R::ResolvesTo
        | R::ReverseResolvesTo
        | R::RedirectsTo
        | R::MailExchanger
        | R::NameServerFor
        | R::AliasOf => (DisplayRel::ResolvesTo, true),
        R::ResolvesToEndpoint => (DisplayRel::ResolvesTo, false),
        R::ListensOn | R::HasAddress | R::AnnouncesPrefix => (DisplayRel::Hosts, true),
        R::RunsService => (DisplayRel::Runs, true),
        R::ServedBy => (DisplayRel::Runs, false),
        R::PresentsCertificate | R::PresentsSshHostKey | R::HasSan => {
            (DisplayRel::ServesCert, true)
        }
        R::SignedBy => (DisplayRel::SignedBy, true),
        R::IdentifiedBy => (DisplayRel::SameFingerprint, true),
        R::ObservedAt | R::ExposedIn | R::ObservedIn => (DisplayRel::FoundOn, true),
        R::FoundBy | R::DiscoveredFrom | R::ReportedBy | R::PublishedRelease => {
            (DisplayRel::DerivedFrom, true)
        }
        R::HasAccount
        | R::UsesUsername
        | R::LinksTo
        | R::BelongsToAsn
        | R::References
        | R::ReferencesDomain
        | R::ReferencesUrl
        | R::Affects
        | R::TargetedDomain
        | R::OwnsRepository
        | R::ContributedTo
        | R::UsesPackage => (DisplayRel::CorrelatedWith, true),
        R::Suggests
        | R::ObservedAssociation
        | R::LikelyAssociation
        | R::PossibleAssociation
        | R::Ownership
        | R::Supports
        | R::Contradicts => (DisplayRel::CorrelatedWith, false),
    }
}

/// Stroke width for a confidence value: 1.0 (0%) .. 4.0 (100%).
pub fn thickness_for(confidence: u8) -> f64 {
    let clamped = confidence.min(100) as f64;
    ((1.0 + 3.0 * clamped / 100.0) * 10.0).round() / 10.0
}

// ---------------------------------------------------------------------------
// View model.
// ---------------------------------------------------------------------------

/// Scope annotation carried by a view node. Unmarked entities are
/// `Unknown` (observation only) — never assumed in-scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeState {
    InScope,
    OutOfScope,
    Unknown,
}

impl ScopeState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InScope => "in_scope",
            Self::OutOfScope => "out_of_scope",
            Self::Unknown => "scope_unknown",
        }
    }
}

/// Derive scope state from stored entity attributes. Only explicit markers
/// count; absence stays `Unknown`.
pub fn scope_state_of(attrs: &BTreeMap<String, String>) -> ScopeState {
    for (key, value) in attrs {
        let key = key.to_ascii_lowercase();
        if key == "scope" || key == "scope_state" || key == "scope-state" {
            let value = value.to_ascii_lowercase();
            if value.contains("out") || value.contains("external") {
                return ScopeState::OutOfScope;
            }
            if value.contains("in") {
                return ScopeState::InScope;
            }
        }
    }
    ScopeState::Unknown
}

/// One masked, evidence-linked display node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewNode {
    pub id: String,
    pub kind: DisplayKind,
    pub stored_kind: String,
    pub label: String,
    /// Strongest confidence among incident edges (`None` = unrated: shown
    /// as such, never defaulted). Computed, not stored.
    pub link_confidence: Option<u8>,
    pub scope: ScopeState,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub observations: u64,
    pub attributes: BTreeMap<String, String>,
    pub evidence: Vec<String>,
    /// Member count for `Cluster` supernodes (1 otherwise).
    pub member_count: usize,
}

/// One masked, evidence-linked display edge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ViewEdge {
    pub from: String,
    pub to: String,
    pub relation: DisplayRel,
    pub stored_relation: String,
    /// Solid (observed) vs dashed (inferred) rendering.
    pub observed: bool,
    pub confidence: u8,
    pub thickness: f64,
    pub module: String,
    pub scan_run: String,
    pub evidence: Vec<String>,
}

/// A bounded, deterministic, secret-masked graph view.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ViewGraph {
    pub nodes: Vec<ViewNode>,
    pub edges: Vec<ViewEdge>,
    pub truncated: bool,
    /// Totals before truncation (honest counts for "showing X of Y").
    pub total_nodes: usize,
    pub total_edges: usize,
}

impl ViewGraph {
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn node_ids(&self) -> BTreeSet<String> {
        self.nodes.iter().map(|n| n.id.clone()).collect()
    }
}

/// Scope filter for view builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScopeFilter {
    #[default]
    All,
    InScope,
    OutOfScope,
}

/// Bounded view-build options shared by CLI, API, and GUI paths.
#[derive(Debug, Clone)]
pub struct ViewOptions {
    pub types: Option<BTreeSet<DisplayKind>>,
    pub min_confidence: u8,
    pub scope: ScopeFilter,
    pub since_ms: Option<u64>,
    pub until_ms: Option<u64>,
    pub limit_nodes: usize,
    pub limit_edges: usize,
    /// Optional seed-centered BFS (`None` = bounded full graph).
    pub seed: Option<String>,
    /// BFS depth around `seed` (clamped 0..=6).
    pub depth: usize,
    /// Include per-observation `Evidence` nodes (off by default: they
    /// multiply node counts; node detail always carries the chain).
    pub include_evidence: bool,
}

impl Default for ViewOptions {
    fn default() -> Self {
        Self {
            types: None,
            min_confidence: 0,
            scope: ScopeFilter::All,
            since_ms: None,
            until_ms: None,
            limit_nodes: DEFAULT_VIEW_NODES,
            limit_edges: DEFAULT_VIEW_EDGES,
            seed: None,
            depth: 2,
            include_evidence: false,
        }
    }
}

impl ViewOptions {
    /// Clamp caller-supplied bounds so no path can request unbounded work.
    pub fn bounded(mut self) -> Self {
        self.limit_nodes = self.limit_nodes.clamp(1, MAX_VIEW_NODES);
        self.limit_edges = self.limit_edges.clamp(1, MAX_VIEW_EDGES);
        self.depth = self.depth.clamp(0, 6);
        self.min_confidence = self.min_confidence.min(100);
        if let (Some(since), Some(until)) = (self.since_ms, self.until_ms) {
            if since > until {
                self.since_ms = Some(until);
                self.until_ms = Some(since);
            }
        }
        self
    }

    pub fn allows_kind(&self, kind: DisplayKind) -> bool {
        self.types.as_ref().is_none_or(|set| set.contains(&kind))
    }
}

/// Mask one display string (labels, ids, evidence excerpts).
fn mask_text(text: &str) -> String {
    crate::exposure::scrub_text(text)
}

fn mask_evidence(items: Vec<String>) -> Vec<String> {
    items
        .into_iter()
        .take(MAX_VIEW_EVIDENCE)
        .map(|item| mask_text(&item))
        .collect()
}

fn mask_attrs(attrs: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (key, value) in attrs.iter().take(12) {
        out.insert(
            mask_text(key),
            crate::exposure::mask_value_for_key(key, value),
        );
    }
    out
}

fn in_time_window(first_ms: u64, last_ms: u64, opts: &ViewOptions) -> bool {
    if let Some(since) = opts.since_ms {
        if last_ms < since {
            return false;
        }
    }
    if let Some(until) = opts.until_ms {
        if first_ms > until {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Builders.
// ---------------------------------------------------------------------------

/// Raw source node (decouples the view from any single store).
#[derive(Debug, Clone)]
pub struct SourceNode {
    pub id: String,
    pub stored_kind: String,
    pub label: String,
    pub attributes: BTreeMap<String, String>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub observations: u64,
}

/// Raw source edge (decouples the view from any single store).
#[derive(Debug, Clone)]
pub struct SourceEdge {
    pub from: String,
    pub to: String,
    pub stored_relation: String,
    pub confidence: u8,
    pub module: String,
    pub scan_run: String,
    pub evidence: Vec<String>,
}

impl From<&crate::project_db::EntityRow> for SourceNode {
    fn from(row: &crate::project_db::EntityRow) -> Self {
        let attributes: BTreeMap<String, String> =
            serde_json::from_str(&row.attributes_json).unwrap_or_default();
        Self {
            id: row.entity_id.clone(),
            stored_kind: row.kind.clone(),
            label: row.label.clone(),
            attributes,
            first_seen_ms: row.first_seen_ms,
            last_seen_ms: row.last_seen_ms,
            observations: row.observation_count,
        }
    }
}

impl From<&crate::project_db::EdgeRow> for SourceEdge {
    fn from(row: &crate::project_db::EdgeRow) -> Self {
        Self {
            from: row.from_id.clone(),
            to: row.to_id.clone(),
            stored_relation: row.relation.clone(),
            confidence: row.confidence,
            module: row.module.clone(),
            scan_run: row.scan_run.clone(),
            evidence: row
                .evidence
                .split("; ")
                .filter(|part| !part.trim().is_empty())
                .map(str::to_owned)
                .collect(),
        }
    }
}

fn stored_kind_of(text: &str) -> Option<crate::graph::EntityKind> {
    crate::graph::EntityKind::parse(text)
}

fn stored_rel_of(text: &str) -> Option<crate::graph::EdgeRelation> {
    crate::graph::EdgeRelation::parse(text)
}

/// Assemble a masked view from raw source nodes/edges with filters, seed
/// BFS, and caps applied. Deterministic over sorted ids.
pub fn build_view(
    sources: Vec<SourceNode>,
    edges: Vec<SourceEdge>,
    opts: &ViewOptions,
) -> ViewGraph {
    let total_nodes = sources.len();
    let total_edges = edges.len();
    // Seed-centered BFS over masked ids when requested.
    let mut allowed: Option<BTreeSet<String>> = None;
    if let Some(seed) = opts.seed.as_deref() {
        let seed = mask_text(seed.trim());
        let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for edge in &edges {
            if stored_rel_of(&edge.stored_relation).is_none() {
                continue;
            }
            if edge.confidence < opts.min_confidence {
                continue;
            }
            let from = mask_text(&edge.from);
            let to = mask_text(&edge.to);
            adjacency.entry(from.clone()).or_default().push(to.clone());
            adjacency.entry(to.clone()).or_default().push(from);
        }
        let mut seen = BTreeSet::from([seed.clone()]);
        let mut frontier = VecDeque::from([(seed, 0usize)]);
        while let Some((current, depth)) = frontier.pop_front() {
            if depth >= opts.depth {
                continue;
            }
            if let Some(next) = adjacency.get(&current) {
                let mut sorted = next.clone();
                sorted.sort();
                for neighbor in sorted {
                    if seen.insert(neighbor.clone()) {
                        frontier.push_back((neighbor, depth + 1));
                    }
                }
            }
        }
        allowed = Some(seen);
    }
    // Filter + mask nodes (sorted for determinism).
    let mut nodes: Vec<ViewNode> = Vec::new();
    let mut kept: BTreeSet<String> = BTreeSet::new();
    let mut node_cap_hit = false;
    let mut sorted_sources: Vec<&SourceNode> = sources.iter().collect();
    sorted_sources.sort_by_key(|a| mask_text(&a.id));
    for source in sorted_sources {
        if nodes.len() >= opts.limit_nodes {
            node_cap_hit = true;
            break;
        }
        let id = mask_text(&source.id);
        if let Some(allowed) = &allowed {
            if !allowed.contains(&id) {
                continue;
            }
        }
        let Some(stored) = stored_kind_of(&source.stored_kind) else {
            continue;
        };
        let kind = display_kind_of(stored);
        if !opts.allows_kind(kind) {
            continue;
        }
        if !in_time_window(source.first_seen_ms, source.last_seen_ms, opts) {
            continue;
        }
        let attributes = mask_attrs(&source.attributes);
        let scope = scope_state_of(&attributes);
        if opts.scope == ScopeFilter::InScope && scope == ScopeState::OutOfScope {
            continue;
        }
        if opts.scope == ScopeFilter::OutOfScope && scope != ScopeState::OutOfScope {
            continue;
        }
        nodes.push(ViewNode {
            id: id.clone(),
            kind,
            stored_kind: source.stored_kind.clone(),
            label: mask_text(&source.label),
            link_confidence: None,
            scope,
            first_seen_ms: source.first_seen_ms,
            last_seen_ms: source.last_seen_ms,
            observations: source.observations,
            attributes,
            evidence: Vec::new(),
            member_count: 1,
        });
        kept.insert(id);
    }
    // Filter + mask edges; both ends must be kept.
    let mut view_edges: Vec<ViewEdge> = Vec::new();
    let mut edge_cap_hit = false;
    let mut sorted_edges = edges.iter().collect::<Vec<_>>();
    sorted_edges.sort_by(|a, b| {
        mask_text(&a.from)
            .cmp(&mask_text(&b.from))
            .then(mask_text(&a.to).cmp(&mask_text(&b.to)))
            .then(a.stored_relation.cmp(&b.stored_relation))
    });
    for edge in sorted_edges {
        if view_edges.len() >= opts.limit_edges {
            edge_cap_hit = true;
            break;
        }
        if edge.confidence < opts.min_confidence {
            continue;
        }
        let Some(stored) = stored_rel_of(&edge.stored_relation) else {
            continue;
        };
        let (relation, observed) = display_rel_of(stored);
        let from = mask_text(&edge.from);
        let to = mask_text(&edge.to);
        if from == to || !kept.contains(&from) || !kept.contains(&to) {
            continue;
        }
        view_edges.push(ViewEdge {
            from,
            to,
            relation,
            stored_relation: edge.stored_relation.clone(),
            observed,
            confidence: edge.confidence,
            thickness: thickness_for(edge.confidence),
            module: mask_text(&edge.module),
            scan_run: mask_text(&edge.scan_run),
            evidence: mask_evidence(edge.evidence.clone()),
        });
    }
    view_edges.sort_by(|a, b| {
        (&a.from, &a.to, a.relation.as_str()).cmp(&(&b.from, &b.to, b.relation.as_str()))
    });
    view_edges.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.relation == b.relation);
    // Link confidence per node: strongest incident edge (computed, shown
    // as "linked confidence"; nodes with no edges stay unrated).
    let mut strongest: HashMap<String, u8> = HashMap::new();
    for edge in &view_edges {
        for end in [&edge.from, &edge.to] {
            strongest
                .entry(end.clone())
                .and_modify(|value| *value = (*value).max(edge.confidence))
                .or_insert(edge.confidence);
        }
    }
    for node in &mut nodes {
        node.link_confidence = strongest.get(&node.id).copied();
    }
    // Truncation honesty: caps biting is reported; filtering is not
    // truncation (fewer nodes by request is exact, not partial).
    ViewGraph {
        nodes,
        edges: view_edges,
        truncated: node_cap_hit || edge_cap_hit,
        total_nodes,
        total_edges,
    }
}

/// Build a view from an in-memory correlation graph (CLI/tests path).
pub fn build_from_scan_graph(graph: &crate::graph::ScanGraph, opts: &ViewOptions) -> ViewGraph {
    let sources = graph
        .entities
        .values()
        .map(|entity| SourceNode {
            id: entity.id.clone(),
            stored_kind: entity.kind.to_string(),
            label: entity.label.clone(),
            attributes: entity.attributes.clone(),
            first_seen_ms: entity.provenance.timestamp,
            last_seen_ms: entity.provenance.timestamp,
            observations: u64::from(entity.observations),
        })
        .collect::<Vec<_>>();
    let edges = graph
        .edges
        .iter()
        .map(|edge| SourceEdge {
            from: edge.from.clone(),
            to: edge.to.clone(),
            stored_relation: edge.relation.to_string(),
            confidence: edge.confidence,
            module: edge.provenance.module.clone(),
            scan_run: edge.provenance.scan_plan_id.clone(),
            evidence: edge.evidence.clone(),
        })
        .collect::<Vec<_>>();
    build_view(sources, edges, opts)
}

/// Build a view from a project database (CLI/API/GUI path). Pages
/// entities in stable order and collects incident edges with global caps;
/// sets `truncated` honestly whenever caps bite.
pub fn build_from_db(
    db: &crate::project_db::ProjectDb,
    opts: &ViewOptions,
) -> Result<ViewGraph, String> {
    if opts.seed.is_some() {
        return build_from_db_seeded(db, opts);
    }
    let mut sources: Vec<SourceNode> = Vec::new();
    let mut offset = 0usize;
    loop {
        let page = db
            .entities_page(None, opts.limit_nodes.min(500), offset)
            .map_err(|error| error.to_string())?;
        if page.is_empty() {
            break;
        }
        let exhausted = page.len() < opts.limit_nodes.min(500);
        for row in &page {
            sources.push(SourceNode::from(row));
            if sources.len() >= opts.limit_nodes {
                break;
            }
        }
        if sources.len() >= opts.limit_nodes || exhausted {
            break;
        }
        offset += page.len();
        if offset > MAX_VIEW_NODES {
            break;
        }
    }
    sources.sort_by(|a, b| a.id.cmp(&b.id));
    sources.truncate(opts.limit_nodes);
    let mut edges: Vec<SourceEdge> = Vec::new();
    for source in &sources {
        if edges.len() >= opts.limit_edges {
            break;
        }
        let mut adjacent = db.edges_from(&source.id).unwrap_or_default();
        adjacent.extend(db.edges_to(&source.id).unwrap_or_default());
        for row in adjacent {
            if edges.len() >= opts.limit_edges {
                break;
            }
            edges.push(SourceEdge::from(&row));
        }
    }
    let total_hint_nodes = sources.len();
    let mut view = build_view(sources, edges, opts);
    // DB-level truncation honesty: more entities may exist beyond the page.
    if total_hint_nodes >= opts.limit_nodes {
        view.truncated = true;
    }
    Ok(view)
}

fn build_from_db_seeded(
    db: &crate::project_db::ProjectDb,
    opts: &ViewOptions,
) -> Result<ViewGraph, String> {
    let seed = opts.seed.clone().unwrap_or_default();
    let mut seen: BTreeSet<String> = BTreeSet::from([seed.clone()]);
    let mut frontier: Vec<(String, usize)> = vec![(seed, 0)];
    let mut sources: Vec<SourceNode> = Vec::new();
    let mut edges: Vec<SourceEdge> = Vec::new();
    while let Some((current, depth)) = frontier.pop() {
        if sources.len() >= opts.limit_nodes {
            break;
        }
        let row = db.entity(&current).map_err(|error| error.to_string())?;
        let Some(row) = row else {
            continue;
        };
        sources.push(SourceNode::from(&row));
        if depth >= opts.depth {
            continue;
        }
        let mut adjacent = db.edges_from(&current).unwrap_or_default();
        adjacent.extend(db.edges_to(&current).unwrap_or_default());
        for row in adjacent {
            if edges.len() >= opts.limit_edges {
                break;
            }
            let neighbor = if row.from_id == current {
                row.to_id.clone()
            } else {
                row.from_id.clone()
            };
            edges.push(SourceEdge::from(&row));
            if seen.insert(neighbor.clone()) && sources.len() + frontier.len() < opts.limit_nodes {
                frontier.push((neighbor, depth + 1));
            }
        }
    }
    Ok(build_view(sources, edges, opts))
}

// ---------------------------------------------------------------------------
// Bounded neighbor expansion (stored data only: no network, no confirm).
// ---------------------------------------------------------------------------

/// Expand `node` by one hop over an already-built view (GUI "expand
/// neighbors" over stored data). Returns at most `limit` neighbor ids in
/// stable order. Expansion that would cause network activity is a
/// different code path (scope-gated + explicit confirmation) and never
/// reaches here: this function only walks `view` edges.
pub fn expand_neighbors(view: &ViewGraph, node: &str, limit: usize) -> Vec<String> {
    let limit = limit.clamp(1, 1024);
    let mut out = BTreeSet::new();
    for edge in &view.edges {
        if edge.from == node {
            out.insert(edge.to.clone());
        } else if edge.to == node {
            out.insert(edge.from.clone());
        }
        if out.len() >= limit {
            break;
        }
    }
    out.into_iter().take(limit).collect()
}

// ---------------------------------------------------------------------------
// Node detail + evidence chain (CLI/GUI share this code path).
// ---------------------------------------------------------------------------

/// One step of an evidence chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLink {
    pub summary: String,
    pub module: String,
    pub scan_run: String,
    pub confidence: Option<u8>,
    pub observed: Option<bool>,
}

/// Full node detail: attributes, confidence, evidence chain, explanation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDetail {
    pub node: ViewNode,
    pub evidence_chain: Vec<EvidenceLink>,
    pub incident_edges: Vec<ViewEdge>,
    pub explanation: String,
}

/// Detail for one view node: incident edges (with evidence) plus
/// per-observation provenance when `observations` are supplied (DB path).
/// The GUI inspector and `rxscan explain` render from this struct.
pub fn node_detail(
    view: &ViewGraph,
    node_id: &str,
    observations: Vec<EvidenceLink>,
) -> Option<NodeDetail> {
    let node = view.nodes.iter().find(|n| n.id == node_id)?.clone();
    let mut incident: Vec<ViewEdge> = view
        .edges
        .iter()
        .filter(|e| e.from == node_id || e.to == node_id)
        .cloned()
        .collect();
    incident.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then((&a.from, &a.to, a.relation.as_str()).cmp(&(&b.from, &b.to, b.relation.as_str())))
    });
    incident.truncate(64);
    let mut chain = observations;
    for edge in &incident {
        let arrow = if edge.from == node_id { "→" } else { "←" };
        let style = if edge.observed {
            "observed"
        } else {
            "inferred"
        };
        if edge.evidence.is_empty() {
            chain.push(EvidenceLink {
                summary: format!(
                    "{arrow} {} ({style} relationship, confidence {})",
                    edge.relation.as_str(),
                    edge.confidence,
                ),
                module: edge.module.clone(),
                scan_run: edge.scan_run.clone(),
                confidence: Some(edge.confidence),
                observed: Some(edge.observed),
            });
        }
        for excerpt in &edge.evidence {
            chain.push(EvidenceLink {
                summary: format!(
                    "{arrow} {} ({style}, confidence {}): {excerpt}",
                    edge.relation.as_str(),
                    edge.confidence,
                ),
                module: edge.module.clone(),
                scan_run: edge.scan_run.clone(),
                confidence: Some(edge.confidence),
                observed: Some(edge.observed),
            });
        }
    }
    chain.truncate(64);
    let explanation = explain_node(&node, &incident);
    Some(NodeDetail {
        node,
        evidence_chain: chain,
        incident_edges: incident,
        explanation,
    })
}

/// Human explanation of what is known about a node and what would move
/// its confidence. Same text feeds CLI and GUI.
pub fn explain_node(node: &ViewNode, incident: &[ViewEdge]) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{} ({}, {})\n",
        node.label,
        node.kind.as_str(),
        node.stored_kind
    ));
    match node.link_confidence {
        Some(conf) => out.push_str(&format!(
            "linked confidence: {conf} (strongest of {} incident relationship{}; stored values, never inflated)\n",
            incident.len(),
            if incident.len() == 1 { "" } else { "s" },
        )),
        None => out.push_str("linked confidence: unrated (no incident relationships in this view)\n"),
    }
    let observed = incident.iter().filter(|e| e.observed).count();
    let inferred = incident.len().saturating_sub(observed);
    out.push_str(&format!(
        "support: {observed} directly observed, {inferred} inferred\n",
    ));
    out.push_str(&format!("scope: {}\n", node.scope.as_str()));
    out.push_str(&format!("observations: {}\n", node.observations));
    if !node.evidence.is_empty() {
        out.push_str("direct evidence:\n");
        for excerpt in &node.evidence {
            out.push_str(&format!("- {excerpt}\n"));
        }
    }
    out.push_str(
        "raising confidence: independent re-observation by another module or scan; \
         corroborating evidence on the same relationship.\n",
    );
    out.push_str(
        "lowering confidence: contradictory evidence, stale observation (recency penalty), \
         single-source derivation (independence cap).\n",
    );
    out
}

// ---------------------------------------------------------------------------
// Layouts: organic, hierarchical, circular, block, radial-from-selection.
// All deterministic (sorted input, fixed arithmetic, no randomness) and
// bounded (iteration counts scale down as graphs grow).
// ---------------------------------------------------------------------------

/// The five GUI/CLI layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LayoutKind {
    #[default]
    Organic,
    Hierarchical,
    Circular,
    Block,
    Radial,
}

impl LayoutKind {
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "organic" | "force" | "force-directed" | "force_directed" => Some(Self::Organic),
            "hierarchical" | "hierarchy" | "layered" => Some(Self::Hierarchical),
            "circular" | "circle" => Some(Self::Circular),
            "block" | "grid" => Some(Self::Block),
            "radial" | "radial-from-selection" | "radial_from_selection" => Some(Self::Radial),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Organic => "organic",
            Self::Hierarchical => "hierarchical",
            Self::Circular => "circular",
            Self::Block => "block",
            Self::Radial => "radial",
        }
    }

    pub fn all() -> &'static [LayoutKind] {
        &[
            Self::Organic,
            Self::Hierarchical,
            Self::Circular,
            Self::Block,
            Self::Radial,
        ]
    }
}

/// World size for layout coordinates (GUI scales to its canvas).
pub const LAYOUT_WIDTH: f64 = 1000.0;
pub const LAYOUT_HEIGHT: f64 = 700.0;

/// Compute `(x, y)` per node id. `seed` centers the radial layout;
/// other layouts ignore it. Always returns one position per node.
pub fn layout(
    view: &ViewGraph,
    kind: LayoutKind,
    seed: Option<&str>,
) -> BTreeMap<String, (f64, f64)> {
    match kind {
        LayoutKind::Circular => layout_circular(view),
        LayoutKind::Block => layout_block(view),
        LayoutKind::Hierarchical => layout_hierarchical(view),
        LayoutKind::Radial => layout_radial(view, seed),
        LayoutKind::Organic => layout_organic(view),
    }
}

fn sorted_ids(view: &ViewGraph) -> Vec<String> {
    let mut ids: Vec<String> = view.nodes.iter().map(|n| n.id.clone()).collect();
    ids.sort();
    ids
}

fn adjacency_of(view: &ViewGraph) -> BTreeMap<String, Vec<String>> {
    let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for node in &view.nodes {
        adjacency.entry(node.id.clone()).or_default();
    }
    for edge in &view.edges {
        adjacency
            .entry(edge.from.clone())
            .or_default()
            .push(edge.to.clone());
        adjacency
            .entry(edge.to.clone())
            .or_default()
            .push(edge.from.clone());
    }
    for neighbors in adjacency.values_mut() {
        neighbors.sort();
        neighbors.dedup();
    }
    adjacency
}

fn layout_circular(view: &ViewGraph) -> BTreeMap<String, (f64, f64)> {
    let ids = sorted_ids(view);
    let mut out = BTreeMap::new();
    let (cx, cy) = (LAYOUT_WIDTH / 2.0, LAYOUT_HEIGHT / 2.0);
    let (rx, ry) = (LAYOUT_WIDTH * 0.42, LAYOUT_HEIGHT * 0.40);
    for (i, id) in ids.iter().enumerate() {
        let angle = 2.0 * std::f64::consts::PI * i as f64 / ids.len().max(1) as f64;
        out.insert(id.clone(), (cx + rx * angle.cos(), cy + ry * angle.sin()));
    }
    out
}

fn layout_block(view: &ViewGraph) -> BTreeMap<String, (f64, f64)> {
    // One grid block per display kind (stable kind order), nodes sorted
    // within each block. Kind groups make type structure visible at scale.
    let mut by_kind: BTreeMap<DisplayKind, Vec<String>> = BTreeMap::new();
    for node in &view.nodes {
        by_kind.entry(node.kind).or_default().push(node.id.clone());
    }
    for ids in by_kind.values_mut() {
        ids.sort();
    }
    let blocks = by_kind.len().max(1);
    let cols = (blocks as f64).sqrt().ceil() as usize;
    let (block_w, block_h) = (
        LAYOUT_WIDTH / cols as f64,
        LAYOUT_HEIGHT / cols.max(1) as f64,
    );
    let mut out = BTreeMap::new();
    for (bi, ids) in by_kind.values().enumerate() {
        let (bx, by) = ((bi % cols) as f64, (bi / cols) as f64);
        let inner = (ids.len() as f64).sqrt().ceil().max(1.0) as usize;
        for (i, id) in ids.iter().enumerate() {
            let (ix, iy) = ((i % inner) as f64, (i / inner) as f64);
            out.insert(
                id.clone(),
                (
                    bx * block_w + (ix + 1.0) * block_w / (inner as f64 + 1.0),
                    by * block_h + (iy + 1.0) * block_h / (inner as f64 + 1.0),
                ),
            );
        }
    }
    out
}

/// BFS layers from the highest-degree node (ties: smallest id).
fn bfs_layers(view: &ViewGraph, root: &str) -> Vec<Vec<String>> {
    let adjacency = adjacency_of(view);
    let mut layers: Vec<Vec<String>> = Vec::new();
    let mut seen = BTreeSet::from([root.to_owned()]);
    let mut frontier = vec![root.to_owned()];
    while !frontier.is_empty() {
        frontier.sort();
        layers.push(frontier.clone());
        let mut next = Vec::new();
        for current in &frontier {
            if let Some(neighbors) = adjacency.get(current) {
                for neighbor in neighbors {
                    if seen.insert(neighbor.clone()) {
                        next.push(neighbor.clone());
                    }
                }
            }
        }
        frontier = next;
        if layers.len() > view.nodes.len() + 1 {
            break;
        }
    }
    // Disconnected remainder joins the last layer (sorted).
    let mut rest: Vec<String> = sorted_ids(view)
        .into_iter()
        .filter(|id| !seen.contains(id))
        .collect();
    if !rest.is_empty() {
        if let Some(last) = layers.last_mut() {
            last.append(&mut rest);
            last.sort();
        } else {
            layers.push(rest);
        }
    }
    layers
}

fn root_of(view: &ViewGraph, seed: Option<&str>) -> Option<String> {
    if let Some(seed) = seed {
        if view.nodes.iter().any(|n| n.id == seed) {
            return Some(seed.to_owned());
        }
    }
    let adjacency = adjacency_of(view);
    adjacency
        .iter()
        .max_by(|a, b| {
            a.1.len().cmp(&b.1.len()).then(b.0.cmp(a.0)) // smallest id wins ties
        })
        .map(|(id, _)| id.clone())
}

fn layout_hierarchical(view: &ViewGraph) -> BTreeMap<String, (f64, f64)> {
    let mut out = BTreeMap::new();
    let Some(root) = root_of(view, None) else {
        return out;
    };
    let layers = bfs_layers(view, &root);
    let depth = layers.len().max(1);
    for (li, layer) in layers.iter().enumerate() {
        for (i, id) in layer.iter().enumerate() {
            out.insert(
                id.clone(),
                (
                    (li as f64 + 1.0) * LAYOUT_WIDTH / (depth as f64 + 1.0),
                    (i as f64 + 1.0) * LAYOUT_HEIGHT / (layer.len() as f64 + 1.0),
                ),
            );
        }
    }
    out
}

fn layout_radial(view: &ViewGraph, seed: Option<&str>) -> BTreeMap<String, (f64, f64)> {
    let mut out = BTreeMap::new();
    let Some(root) = root_of(view, seed) else {
        return out;
    };
    let layers = bfs_layers(view, &root);
    let (cx, cy) = (LAYOUT_WIDTH / 2.0, LAYOUT_HEIGHT / 2.0);
    out.insert(root.clone(), (cx, cy));
    let max_r = LAYOUT_WIDTH.min(LAYOUT_HEIGHT) * 0.46;
    let rings = layers.len().saturating_sub(1).max(1);
    for (li, layer) in layers.iter().enumerate().skip(1) {
        let radius = max_r * li as f64 / rings as f64;
        for (i, id) in layer.iter().enumerate() {
            let angle = 2.0 * std::f64::consts::PI * i as f64 / layer.len().max(1) as f64;
            out.insert(
                id.clone(),
                (cx + radius * angle.cos(), cy + radius * angle.sin()),
            );
        }
    }
    out
}

/// Deterministic 64-bit FNV-1a (stable across runs/platforms).
fn fnv1a(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn layout_organic(view: &ViewGraph) -> BTreeMap<String, (f64, f64)> {
    let ids = sorted_ids(view);
    let count = ids.len();
    let mut positions: BTreeMap<String, (f64, f64)> = BTreeMap::new();
    if count == 0 {
        return positions;
    }
    // Deterministic start: circle with hash jitter (no RNG anywhere).
    let (cx, cy) = (LAYOUT_WIDTH / 2.0, LAYOUT_HEIGHT / 2.0);
    let radius = LAYOUT_WIDTH.min(LAYOUT_HEIGHT) * 0.38;
    for (i, id) in ids.iter().enumerate() {
        let angle = 2.0 * std::f64::consts::PI * i as f64 / count as f64;
        let jitter = (fnv1a(id) % 1000) as f64 / 1000.0 - 0.5;
        positions.insert(
            id.clone(),
            (
                cx + radius * (angle + jitter * 0.2).cos(),
                cy + radius * (angle + jitter * 0.2).sin(),
            ),
        );
    }
    if count == 1 {
        return positions;
    }
    let index: BTreeMap<&str, usize> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| (id.as_str(), i))
        .collect();
    let mut pos: Vec<(f64, f64)> = ids.iter().map(|id| positions[id]).collect();
    // Bounded iterations: large graphs get fewer passes.
    let iters = (600_000usize / count).clamp(6, 100);
    // Sampled repulsion: each node repels against a deterministic stride
    // sample of ≤48 others (O(V) per pass, not O(V²)).
    const SAMPLE: usize = 48;
    let stride = (count / SAMPLE.max(1)).max(1);
    let area = LAYOUT_WIDTH * LAYOUT_HEIGHT;
    let ideal = (area / count as f64).sqrt();
    let mut temperature = LAYOUT_WIDTH / 10.0;
    let cooling = temperature / iters as f64;
    let edge_list: Vec<(usize, usize)> = view
        .edges
        .iter()
        .filter_map(|e| {
            let a = *index.get(e.from.as_str())?;
            let b = *index.get(e.to.as_str())?;
            if a == b { None } else { Some((a, b)) }
        })
        .collect();
    for _ in 0..iters {
        let mut disp = vec![(0.0f64, 0.0f64); count];
        // Repulsion (sampled).
        for i in 0..count {
            let mut j = (i * 2654435761usize) % count.max(1);
            for _ in 0..SAMPLE.min(count.saturating_sub(1)) {
                j = (j + stride) % count;
                if j == i {
                    continue;
                }
                let dx = pos[i].0 - pos[j].0;
                let dy = pos[i].1 - pos[j].1;
                let dist = (dx * dx + dy * dy).sqrt().max(0.01);
                let force = ideal * ideal / dist;
                disp[i].0 += dx / dist * force;
                disp[i].1 += dy / dist * force;
            }
        }
        // Attraction along edges.
        for (a, b) in &edge_list {
            let dx = pos[*a].0 - pos[*b].0;
            let dy = pos[*a].1 - pos[*b].1;
            let dist = (dx * dx + dy * dy).sqrt().max(0.01);
            let force = dist * dist / ideal;
            let fx = dx / dist * force;
            let fy = dy / dist * force;
            disp[*a].0 -= fx;
            disp[*a].1 -= fy;
            disp[*b].0 += fx;
            disp[*b].1 += fy;
        }
        // Move (capped by temperature), then cool.
        for i in 0..count {
            let (dx, dy) = disp[i];
            let len = (dx * dx + dy * dy).sqrt().max(0.01);
            let capped = len.min(temperature) / len;
            pos[i].0 = (pos[i].0 + dx * capped).clamp(20.0, LAYOUT_WIDTH - 20.0);
            pos[i].1 = (pos[i].1 + dy * capped).clamp(20.0, LAYOUT_HEIGHT - 20.0);
        }
        temperature = (temperature - cooling).max(0.5);
    }
    for (i, id) in ids.iter().enumerate() {
        positions.insert(id.clone(), pos[i]);
    }
    positions
}

// ---------------------------------------------------------------------------
// Clustering: collapse dense components into supernodes so 10k+ nodes
// stay interactive. Deterministic union-find over sorted edges.
// ---------------------------------------------------------------------------

/// Collapse connected components until at most `budget` visible nodes
/// remain. Components of size ≤ `min_cluster` are never collapsed (small
/// structure stays exact). Returns the clustered view plus a membership
/// map (`supernode id -> member ids`) for expand/collapse UX.
pub fn cluster_beyond(
    view: &ViewGraph,
    budget: usize,
) -> (ViewGraph, BTreeMap<String, Vec<String>>) {
    let budget = budget.clamp(16, MAX_VIEW_NODES);
    if view.nodes.len() <= budget {
        return (view.clone(), BTreeMap::new());
    }
    // Union-find over sorted edges.
    let mut parent: BTreeMap<String, String> = view
        .nodes
        .iter()
        .map(|n| (n.id.clone(), n.id.clone()))
        .collect();
    fn find(parent: &mut BTreeMap<String, String>, node: &str) -> String {
        let mut root = node.to_owned();
        while parent.get(&root).is_some_and(|p| p != &root) {
            root = parent[&root].clone();
        }
        root
    }
    let mut sorted_edges = view.edges.clone();
    sorted_edges.sort_by(|a, b| (&a.from, &a.to).cmp(&(&b.from, &b.to)));
    for edge in &sorted_edges {
        let a = find(&mut parent, &edge.from);
        let b = find(&mut parent, &edge.to);
        if a != b {
            let (first, second) = if a < b { (a, b) } else { (b, a) };
            parent.insert(second, first);
        }
    }
    let mut members: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for node in &view.nodes {
        let root = find(&mut parent, &node.id);
        members.entry(root).or_default().push(node.id.clone());
    }
    for ids in members.values_mut() {
        ids.sort();
    }
    let min_cluster = (view.nodes.len() / budget).max(4);
    // Collapse largest components first until within budget.
    let mut comps: Vec<(String, Vec<String>)> = members.into_iter().collect();
    comps.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
    let mut collapsed: BTreeSet<String> = BTreeSet::new();
    let mut visible = view.nodes.len();
    for (root, ids) in &comps {
        if visible <= budget {
            break;
        }
        if ids.len() >= min_cluster {
            collapsed.insert(root.clone());
            visible = visible - ids.len() + 1;
        }
    }
    if collapsed.is_empty() {
        return (view.clone(), BTreeMap::new());
    }
    let node_by_id: BTreeMap<&str, &ViewNode> =
        view.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let mut clustered = ViewGraph {
        nodes: Vec::new(),
        edges: Vec::new(),
        truncated: view.truncated,
        total_nodes: view.total_nodes,
        total_edges: view.total_edges,
    };
    let mut membership: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut supernode_of: BTreeMap<String, String> = BTreeMap::new();
    let mut counter = 0usize;
    for (root, ids) in &comps {
        if collapsed.contains(root) {
            counter += 1;
            let super_id = format!("cluster:{counter}");
            let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
            let mut conf: Option<u8> = None;
            let (mut first, mut last) = (u64::MAX, 0u64);
            for id in ids {
                supernode_of.insert(id.clone(), super_id.clone());
                if let Some(node) = node_by_id.get(id.as_str()) {
                    *kinds.entry(node.kind.as_str().to_owned()).or_default() += 1;
                    conf = conf.max(node.link_confidence);
                    first = first.min(node.first_seen_ms);
                    last = last.max(node.last_seen_ms);
                }
            }
            let summary = kinds
                .iter()
                .map(|(kind, count)| format!("{kind}×{count}"))
                .collect::<Vec<_>>()
                .join(", ");
            membership.insert(super_id.clone(), ids.clone());
            clustered.nodes.push(ViewNode {
                id: super_id,
                kind: DisplayKind::Cluster,
                stored_kind: "cluster".to_owned(),
                label: format!("{} nodes", ids.len()),
                link_confidence: conf,
                scope: ScopeState::Unknown,
                first_seen_ms: if first == u64::MAX { 0 } else { first },
                last_seen_ms: last,
                observations: ids.len() as u64,
                attributes: BTreeMap::from([(
                    "members".to_owned(),
                    summary.chars().take(256).collect(),
                )]),
                evidence: Vec::new(),
                member_count: ids.len(),
            });
        } else {
            for id in ids {
                supernode_of.insert(id.clone(), id.clone());
                if let Some(node) = node_by_id.get(id.as_str()) {
                    clustered.nodes.push((*node).clone());
                }
            }
        }
    }
    clustered.nodes.sort_by(|a, b| a.id.cmp(&b.id));
    // Rewire edges onto supernodes; drop internal edges; dedupe keeping
    // the strongest confidence.
    let mut best: BTreeMap<(String, String, DisplayRel), ViewEdge> = BTreeMap::new();
    for edge in &view.edges {
        let from = supernode_of.get(&edge.from);
        let to = supernode_of.get(&edge.to);
        if from.is_none() || to.is_none() {
            continue;
        }
        let (from, to) = (from.unwrap().clone(), to.unwrap().clone());
        if from == to {
            continue;
        }
        let key = (from.clone(), to.clone(), edge.relation);
        best.entry(key)
            .and_modify(|kept| {
                if edge.confidence > kept.confidence {
                    kept.confidence = edge.confidence;
                    kept.thickness = thickness_for(edge.confidence);
                    kept.evidence = edge.evidence.clone();
                }
            })
            .or_insert_with(|| ViewEdge {
                from,
                to,
                relation: edge.relation,
                stored_relation: edge.stored_relation.clone(),
                observed: edge.observed,
                confidence: edge.confidence,
                thickness: edge.thickness,
                module: edge.module.clone(),
                scan_run: edge.scan_run.clone(),
                evidence: edge.evidence.clone(),
            });
    }
    clustered.edges = best.into_values().collect();
    (clustered, membership)
}

// ---------------------------------------------------------------------------
// Exports: JSON graph, GraphML, SVG, standalone HTML, PNG.
// All pass through the masked view model: no export path can leak secrets.
// ---------------------------------------------------------------------------

/// Export formats for `rxscan graph --format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GraphFormat {
    #[default]
    Json,
    Graphml,
    Svg,
    Html,
    Png,
}

impl GraphFormat {
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "graphml" => Some(Self::Graphml),
            "svg" => Some(Self::Svg),
            "html" => Some(Self::Html),
            "png" => Some(Self::Png),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Graphml => "graphml",
            Self::Svg => "svg",
            Self::Html => "html",
            Self::Png => "png",
        }
    }

    pub fn all() -> &'static [GraphFormat] {
        &[Self::Json, Self::Graphml, Self::Svg, Self::Html, Self::Png]
    }

    pub fn content_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Graphml => "application/xml",
            Self::Svg => "image/svg+xml",
            Self::Html => "text/html",
            Self::Png => "image/png",
        }
    }
}

/// Render one export from a masked view. Positions come from
/// [`layout`] (SVG/HTML/PNG need them; JSON/GraphML ignore them).
pub fn render_export(
    view: &ViewGraph,
    format: GraphFormat,
    positions: &BTreeMap<String, (f64, f64)>,
    title: &str,
) -> Result<Vec<u8>, String> {
    match format {
        GraphFormat::Json => Ok(to_json(view).into_bytes()),
        GraphFormat::Graphml => Ok(to_graphml(view).into_bytes()),
        GraphFormat::Svg => Ok(to_svg(view, positions, 1000, 700).into_bytes()),
        GraphFormat::Html => Ok(to_html(view, positions, title).into_bytes()),
        GraphFormat::Png => Ok(to_png(view, positions, 1600, 1000)),
    }
}

/// Canonical JSON graph: every node/edge carries evidence + confidence.
/// Nodes additionally carry `icon` and `category` from the icon manifest
/// (additive; existing fields are unchanged).
pub fn to_json(view: &ViewGraph) -> String {
    // Nodes stream through `NodeWithIcon`, which appends the two additive
    // fields. Building a `serde_json::Value` per node instead would
    // materialize the whole graph twice and roughly halve export speed.
    let nodes: Vec<NodeWithIcon<'_>> = view
        .nodes
        .iter()
        .map(|node| NodeWithIcon { node })
        .collect();
    let payload = serde_json::json!({
        "graph_schema_version": VIEW_SCHEMA_VERSION,
        "truncated": view.truncated,
        "total_nodes": view.total_nodes,
        "total_edges": view.total_edges,
        "nodes": nodes,
        "edges": view.edges,
    });
    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_owned())
}

/// Serializes a `ViewNode` field-for-field, then appends the additive
/// `icon` and `category` fields. Field names and order mirror the derived
/// `Serialize` on `ViewNode`; `node_json_fields_are_complete` guards against
/// the two drifting apart.
struct NodeWithIcon<'a> {
    node: &'a ViewNode,
}

impl Serialize for NodeWithIcon<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let node = self.node;
        let icon = crate::graph_icons::node_icon(node.kind, &node.stored_kind, &node.attributes);
        let category = icon.and_then(crate::graph_icons::category_of);
        let mut out = serializer.serialize_struct("ViewNode", 14)?;
        out.serialize_field("id", &node.id)?;
        out.serialize_field("kind", &node.kind)?;
        out.serialize_field("stored_kind", &node.stored_kind)?;
        out.serialize_field("label", &node.label)?;
        out.serialize_field("link_confidence", &node.link_confidence)?;
        out.serialize_field("scope", &node.scope)?;
        out.serialize_field("first_seen_ms", &node.first_seen_ms)?;
        out.serialize_field("last_seen_ms", &node.last_seen_ms)?;
        out.serialize_field("observations", &node.observations)?;
        out.serialize_field("attributes", &node.attributes)?;
        out.serialize_field("evidence", &node.evidence)?;
        out.serialize_field("member_count", &node.member_count)?;
        out.serialize_field("icon", &icon)?;
        out.serialize_field("category", &category)?;
        out.end()
    }
}

fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if c.is_control() && c != '\n' && c != '\r' && c != '\t' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

fn html_escape(text: &str) -> String {
    xml_escape(text)
}

/// GraphML (directed) with per-node/edge data keys. The `xmlns` below is
/// a namespace identifier only (never fetched) — same standing as the SVG
/// namespace constant in the GUI.
pub fn to_graphml(view: &ViewGraph) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n");
    for (key, target, kind) in [
        ("kind", "node", "string"),
        ("stored_kind", "node", "string"),
        ("label", "node", "string"),
        ("icon", "node", "string"),
        ("category", "node", "string"),
        ("confidence", "node", "int"),
        ("scope", "node", "string"),
        ("observations", "node", "int"),
        ("attributes", "node", "string"),
        ("evidence", "node", "string"),
        ("relation", "edge", "string"),
        ("stored_relation", "edge", "string"),
        ("observed", "edge", "boolean"),
        ("econfidence", "edge", "int"),
        ("module", "edge", "string"),
        ("scan_run", "edge", "string"),
        ("eevidence", "edge", "string"),
    ] {
        out.push_str(&format!(
            "<key id=\"{key}\" for=\"{target}\" attr.name=\"{key}\" attr.type=\"{kind}\"/>\n"
        ));
    }
    out.push_str("<graph id=\"rxscan\" edgedefault=\"directed\">\n");
    for node in &view.nodes {
        out.push_str(&format!("<node id=\"{}\">\n", xml_escape(&node.id)));
        out.push_str(&format!(
            "<data key=\"kind\">{}</data>\n",
            node.kind.as_str()
        ));
        out.push_str(&format!(
            "<data key=\"stored_kind\">{}</data>\n",
            xml_escape(&node.stored_kind)
        ));
        let icon = crate::graph_icons::node_icon(node.kind, &node.stored_kind, &node.attributes);
        if let Some(icon) = icon {
            out.push_str(&format!("<data key=\"icon\">{icon}</data>\n"));
            if let Some(category) = crate::graph_icons::category_of(icon) {
                out.push_str(&format!("<data key=\"category\">{category}</data>\n"));
            }
        }
        out.push_str(&format!(
            "<data key=\"label\">{}</data>\n",
            xml_escape(&node.label)
        ));
        out.push_str(&format!(
            "<data key=\"confidence\">{}</data>\n",
            node.link_confidence
                .map(|c| c.to_string())
                .unwrap_or_default()
        ));
        out.push_str(&format!(
            "<data key=\"scope\">{}</data>\n",
            node.scope.as_str()
        ));
        out.push_str(&format!(
            "<data key=\"observations\">{}</data>\n",
            node.observations
        ));
        out.push_str(&format!(
            "<data key=\"attributes\">{}</data>\n",
            xml_escape(
                &node
                    .attributes
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        ));
        out.push_str(&format!(
            "<data key=\"evidence\">{}</data>\n",
            xml_escape(&node.evidence.join(" | "))
        ));
        out.push_str("</node>\n");
    }
    for (i, edge) in view.edges.iter().enumerate() {
        out.push_str(&format!(
            "<edge id=\"e{i}\" source=\"{}\" target=\"{}\">\n",
            xml_escape(&edge.from),
            xml_escape(&edge.to)
        ));
        out.push_str(&format!(
            "<data key=\"relation\">{}</data>\n",
            edge.relation.as_str()
        ));
        out.push_str(&format!(
            "<data key=\"stored_relation\">{}</data>\n",
            xml_escape(&edge.stored_relation)
        ));
        out.push_str(&format!(
            "<data key=\"observed\">{}</data>\n",
            edge.observed
        ));
        out.push_str(&format!(
            "<data key=\"econfidence\">{}</data>\n",
            edge.confidence
        ));
        out.push_str(&format!(
            "<data key=\"module\">{}</data>\n",
            xml_escape(&edge.module)
        ));
        out.push_str(&format!(
            "<data key=\"scan_run\">{}</data>\n",
            xml_escape(&edge.scan_run)
        ));
        out.push_str(&format!(
            "<data key=\"eevidence\">{}</data>\n",
            xml_escape(&edge.evidence.join(" | "))
        ));
        out.push_str("</edge>\n");
    }
    out.push_str("</graph>\n</graphml>\n");
    out
}

fn shape_svg(out: &mut String, shape: &str, x: f64, y: f64, r: f64, fill: &str, selected: bool) {
    let stroke = "#010813";
    let width = if selected { 2.5 } else { 1.5 };
    let pts = |sides: usize, rot: f64| {
        (0..sides)
            .map(|i| {
                let a = rot + 2.0 * std::f64::consts::PI * i as f64 / sides as f64;
                format!("{:.1},{:.1}", x + r * a.cos(), y + r * a.sin())
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    match shape {
        "circle" => out.push_str(&format!(
            "<circle cx=\"{x:.1}\" cy=\"{y:.1}\" r=\"{r:.1}\" fill=\"{fill}\" stroke=\"{stroke}\" stroke-width=\"{width}\"/>\n"
        )),
        "ring" | "dashed_circle" => {
            let dash = if shape == "dashed_circle" { " stroke-dasharray=\"4 3\"" } else { "" };
            out.push_str(&format!(
                "<circle cx=\"{x:.1}\" cy=\"{y:.1}\" r=\"{r:.1}\" fill=\"none\" stroke=\"{fill}\" stroke-width=\"2.5\"{dash}/>\n"
            ));
        }
        "square" => out.push_str(&format!(
            "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" fill=\"{fill}\" stroke=\"{stroke}\" stroke-width=\"{width}\"/>\n",
            x - r * 0.85, y - r * 0.85, r * 1.7, r * 1.7
        )),
        "double_square" => {
            out.push_str(&format!(
                "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" fill=\"{fill}\" stroke=\"{stroke}\" stroke-width=\"{width}\"/>\n",
                x - r * 0.85, y - r * 0.85, r * 1.7, r * 1.7
            ));
            out.push_str(&format!(
                "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" fill=\"none\" stroke=\"{stroke}\" stroke-width=\"1\"/>\n",
                x - r * 0.55, y - r * 0.55, r * 1.1, r * 1.1
            ));
        }
        "rounded_rect" => out.push_str(&format!(
            "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" rx=\"3\" fill=\"{fill}\" stroke=\"{stroke}\" stroke-width=\"{width}\"/>\n",
            x - r, y - r * 0.7, r * 2.0, r * 1.4
        )),
        "diamond" => out.push_str(&format!(
            "<polygon points=\"{x:.1},{:.1} {:.1},{y:.1} {x:.1},{:.1} {:.1},{y:.1}\" fill=\"{fill}\" stroke=\"{stroke}\" stroke-width=\"{width}\"/>\n",
            y - r, x + r, y + r, x - r
        )),
        "triangle" => out.push_str(&format!(
            "<polygon points=\"{x:.1},{:.1} {:.1},{:.1} {:.1},{:.1}\" fill=\"{fill}\" stroke=\"{stroke}\" stroke-width=\"{width}\"/>\n",
            y - r, x - r, y + r * 0.8, x + r, y + r * 0.8
        )),
        "triangle_down" => out.push_str(&format!(
            "<polygon points=\"{x:.1},{:.1} {:.1},{:.1} {:.1},{:.1}\" fill=\"{fill}\" stroke=\"{stroke}\" stroke-width=\"{width}\"/>\n",
            y + r, x - r, y - r * 0.8, x + r, y - r * 0.8
        )),
        "ellipse" => out.push_str(&format!(
            "<ellipse cx=\"{x:.1}\" cy=\"{y:.1}\" rx=\"{:.1}\" ry=\"{:.1}\" fill=\"{fill}\" stroke=\"{stroke}\" stroke-width=\"{width}\"/>\n",
            r * 1.25, r * 0.8
        )),
        "parallelogram" => out.push_str(&format!(
            "<polygon points=\"{:.1},{:.1} {:.1},{:.1} {:.1},{:.1} {:.1},{:.1}\" fill=\"{fill}\" stroke=\"{stroke}\" stroke-width=\"{width}\"/>\n",
            x - r * 0.6, y - r * 0.8, x + r, y - r * 0.8, x + r * 0.6, y + r * 0.8, x - r, y + r * 0.8
        )),
        _ => out.push_str(&format!(
            "<polygon points=\"{}\" fill=\"{fill}\" stroke=\"{stroke}\" stroke-width=\"{width}\"/>\n",
            pts(
                match shape {
                    "hexagon" => 6,
                    "pentagon" => 5,
                    "octagon" => 8,
                    _ => 6,
                },
                -std::f64::consts::PI / 2.0
            )
        )),
    }
}

/// Standalone SVG: shapes encode kind, dash encodes inference, width
/// encodes confidence; legend + masked evidence in `<desc>` elements.
pub fn to_svg(
    view: &ViewGraph,
    positions: &BTreeMap<String, (f64, f64)>,
    width: u32,
    height: u32,
) -> String {
    let width = width.clamp(64, MAX_PNG_DIM);
    let height = height.clamp(64, MAX_PNG_DIM);
    let sx = width as f64 / LAYOUT_WIDTH;
    let sy = height as f64 / LAYOUT_HEIGHT;
    let place = |id: &str| {
        positions
            .get(id)
            .map(|(x, y)| (x * sx, y * sy))
            .unwrap_or((width as f64 / 2.0, height as f64 / 2.0))
    };
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\" viewBox=\"0 0 {width} {height}\" role=\"img\" aria-label=\"RXScan evidence graph\">\n"
    ));
    out.push_str(&format!(
        "<title>RXScan evidence graph: {} nodes, {} edges</title>\n",
        view.nodes.len(),
        view.edges.len()
    ));
    out.push_str(&format!(
        "<rect width=\"{width}\" height=\"{height}\" fill=\"#010813\"/>\n"
    ));
    // Icon symbols are defined once here and referenced by `<use>` below, so
    // glyphs are never duplicated inline per node.
    out.push_str("<defs>");
    out.push_str(ICON_SPRITE);
    out.push_str("</defs>");
    for edge in &view.edges {
        let (x1, y1) = place(&edge.from);
        let (x2, y2) = place(&edge.to);
        let dash = if edge.observed {
            ""
        } else {
            " stroke-dasharray=\"6 4\""
        };
        out.push_str(&format!(
            "<line x1=\"{x1:.1}\" y1=\"{y1:.1}\" x2=\"{x2:.1}\" y2=\"{y2:.1}\" stroke=\"#2e5a87\" stroke-width=\"{:.1}\"{dash}>\n",
            edge.thickness
        ));
        out.push_str(&format!(
            "<desc>{} ({}; confidence {}){}</desc>\n",
            xml_escape(edge.relation.as_str()),
            if edge.observed {
                "observed"
            } else {
                "inferred"
            },
            edge.confidence,
            if edge.evidence.is_empty() {
                String::new()
            } else {
                format!(": {}", xml_escape(&edge.evidence.join(" | ")))
            }
        ));
        out.push_str("</line>\n");
    }
    for node in &view.nodes {
        let (x, y) = place(&node.id);
        let r = if node.kind == DisplayKind::Cluster {
            (6.0 + (node.member_count as f64).sqrt() * 2.0).min(20.0)
        } else {
            7.0
        };
        let label = if node.label.chars().count() > 28 {
            let truncated: String = node.label.chars().take(27).collect();
            format!("{truncated}…")
        } else {
            node.label.clone()
        };
        out.push_str("<g>\n");
        // Draw the manifest icon via `<use>` when available; fall back to the
        // kind shape so every node is always marked (shape + color never alone).
        let icon = crate::graph_icons::node_icon(node.kind, &node.stored_kind, &node.attributes);
        let ramp = icon.and_then(crate::graph_icons::ramp_of);
        let color = ramp
            .and_then(crate::graph_icons::ramp_color)
            .unwrap_or(node.kind.color());
        if node.kind != DisplayKind::Cluster {
            if let Some(icon) = icon {
                out.push_str(&format!(
                    "<use href=\"#rx-{}\" x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" fill=\"none\" stroke=\"{}\" stroke-width=\"2\"/>\n",
                    icon,
                    x - r,
                    y - r,
                    2.0 * r,
                    2.0 * r,
                    color,
                ));
            } else {
                shape_svg(&mut out, node.kind.shape(), x, y, r, color, false);
            }
        } else {
            shape_svg(&mut out, node.kind.shape(), x, y, r, color, false);
        }
        out.push_str(&format!(
            "<text x=\"{:.1}\" y=\"{:.1}\" fill=\"#f4f8ff\" font-size=\"11\" font-family=\"sans-serif\">{}</text>\n",
            x + r + 3.0,
            y + 4.0,
            xml_escape(&label)
        ));
        out.push_str(&format!(
            "<desc>{} ({}; {}){}</desc>\n",
            xml_escape(&node.label),
            node.kind.as_str(),
            match node.link_confidence {
                Some(c) => format!("confidence {c}"),
                None => "unrated".to_owned(),
            },
            if node.evidence.is_empty() {
                String::new()
            } else {
                format!(": {}", xml_escape(&node.evidence.join(" | ")))
            }
        ));
        out.push_str("</g>\n");
    }
    // Legend: swatch + kind name (shape differs per kind; color never alone).
    out.push_str("<g font-family=\"sans-serif\" font-size=\"11\" fill=\"#8fa9c2\">\n");
    for (i, kind) in DisplayKind::all().iter().enumerate() {
        let y = 20.0 + i as f64 * 18.0;
        out.push_str(&format!(
            "<circle cx=\"14\" cy=\"{y}\" r=\"5\" fill=\"{}\"/>\n<text x=\"24\" y=\"{:.1}\">{} ({})</text>\n",
            kind.color(),
            y + 4.0,
            kind.as_str(),
            kind.shape(),
        ));
    }
    out.push_str("</g>\n</svg>\n");
    out
}

/// Standalone offline HTML: inlined CSS (design tokens), inlined SVG
/// scene, inlined JSON data, vanilla JS viewer (pan/zoom/select/filter/
/// search). Zero external references: works from `file://` with no
/// network. All data is pre-masked by the view model.
pub fn to_html(view: &ViewGraph, positions: &BTreeMap<String, (f64, f64)>, title: &str) -> String {
    let nodes: Vec<serde_json::Value> = view
        .nodes
        .iter()
        .map(|node| {
            let (x, y) = positions.get(&node.id).copied().unwrap_or((500.0, 350.0));
            let icon =
                crate::graph_icons::node_icon(node.kind, &node.stored_kind, &node.attributes);
            serde_json::json!({
                "id": node.id,
                "kind": node.kind.as_str(),
                "stored_kind": node.stored_kind,
                "label": node.label,
                "link_confidence": node.link_confidence,
                "scope": node.scope.as_str(),
                "observations": node.observations,
                "attributes": node.attributes,
                "evidence": node.evidence,
                "member_count": node.member_count,
                "x": x,
                "y": y,
                "icon": icon,
                "ramp": icon.and_then(crate::graph_icons::ramp_of),
                "category": icon.and_then(crate::graph_icons::category_of),
            })
        })
        .collect();
    let edges: Vec<serde_json::Value> = view
        .edges
        .iter()
        .map(|edge| {
            serde_json::json!({
                "from": edge.from,
                "to": edge.to,
                "relation": edge.relation.as_str(),
                "stored_relation": edge.stored_relation,
                "observed": edge.observed,
                "confidence": edge.confidence,
                "thickness": edge.thickness,
                "module": edge.module,
                "scan_run": edge.scan_run,
                "evidence": edge.evidence,
            })
        })
        .collect();
    // `<` is escaped so embedded labels can never break out of the script
    // block (`\u003c` is valid inside JSON strings and inside JS).
    let data = serde_json::json!({
        "graph_schema_version": VIEW_SCHEMA_VERSION,
        "truncated": view.truncated,
        "total_nodes": view.total_nodes,
        "total_edges": view.total_edges,
        "nodes": nodes,
        "edges": edges,
    })
    .to_string()
    .replace('<', "\\u003c");
    HTML_TEMPLATE
        .replace("{{TITLE}}", &html_escape(title))
        .replace(
            "{{COUNTS}}",
            &format!(
                "{} nodes, {} edges{}",
                view.nodes.len(),
                view.edges.len(),
                if view.truncated { " (truncated)" } else { "" }
            ),
        )
        .replace("{{DATA}}", &data)
        .replace("{{SPRITE}}", ICON_SPRITE)
}

const HTML_TEMPLATE: &str = r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="referrer" content="same-origin">
<title>{{TITLE}} — RXScan graph</title>
<style>
:root{--rx-bg:#020711;--rx-surface:#061426;--rx-border:#123553;--rx-cyan:#00efff;--rx-text:#f4f8ff;--rx-muted:#8fa9c2;--rx-ok:#3ddc84;--rx-warn:#f0a04b;--rx-bad:#f06666}
*{box-sizing:border-box}body{margin:0;background:var(--rx-bg);color:var(--rx-text);font-family:system-ui,sans-serif;display:flex;flex-direction:column;min-height:100vh}
header{padding:.6rem 1rem;border-bottom:1px solid var(--rx-border);display:flex;gap:1rem;align-items:baseline;flex-wrap:wrap}
h1{font-size:1.1rem;margin:0}.muted{color:var(--rx-muted);font-size:.85rem}
.toolbar{display:flex;gap:.5rem;flex-wrap:wrap;padding:.5rem 1rem;align-items:center}
.toolbar input,.toolbar select{background:var(--rx-surface);color:var(--rx-text);border:1px solid var(--rx-border);border-radius:6px;padding:.4rem .6rem;font:inherit}
.toolbar button{background:var(--rx-cyan);color:#001018;border:none;border-radius:6px;padding:.4rem .8rem;font-weight:700;cursor:pointer}
main{flex:1;display:grid;grid-template-columns:2fr 1fr;gap:.5rem;padding:.5rem 1rem;min-height:0}
#scene{background:#010813;border:1px solid var(--rx-border);border-radius:6px;width:100%;height:60vh;cursor:grab}
aside{background:var(--rx-surface);border:1px solid var(--rx-border);border-radius:6px;padding:.6rem;overflow:auto;max-height:60vh}
dl.kv{margin:0}dl.kv>div{display:flex;gap:.6rem;padding:.15rem 0}dl.kv dt{color:var(--rx-muted);min-width:7rem}dl.kv dd{margin:0;overflow-wrap:anywhere}
.legend{list-style:none;display:flex;gap:.4rem;flex-wrap:wrap;padding:.4rem 1rem;margin:0}
.legend li{font-size:.78rem;color:var(--rx-muted);border:1px solid var(--rx-border);border-radius:12px;padding:.1rem .55rem}
.glabel{fill:#f4f8ff;font-size:11px;pointer-events:none}
@media (prefers-reduced-motion: reduce){*{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<header><h1>{{TITLE}}</h1><span class="muted">{{COUNTS}} — offline RXScan evidence graph; every element links to evidence with confidence.</span></header>
<div class="toolbar">
<button type="button" id="zin">Zoom in</button>
<button type="button" id="zout">Zoom out</button>
<button type="button" id="zreset">Reset view</button>
<label for="kindf">Kind</label><select id="kindf"><option value="">all kinds</option></select>
<label for="q">Search</label><input id="q" type="text" autocomplete="off">
</div>
<main>
<svg id="scene" viewBox="0 0 1000 700" role="img" aria-label="RXScan evidence graph"></svg>{{SPRITE}}
<aside aria-live="polite"><h2>Detail</h2><p class="muted" id="empty">Select a node or edge.</p><dl class="kv" id="detail" hidden></dl></aside>
</main>
<ul class="legend" id="legend"></ul>
<script>
(function(){
"use strict";
var DATA={{DATA}};
var NS="http://www.w3.org/2000/svg";
var svg=document.getElementById("scene"),detail=document.getElementById("detail"),empty=document.getElementById("empty");
var view={x:0,y:0,k:1},kindFilter="",query="";
var byId={};DATA.nodes.forEach(function(n){byId[n.id]=n;});
function el(tag,attrs,parent){var e=document.createElementNS(NS,tag);for(var k in attrs){e.setAttribute(k,attrs[k]);}parent.appendChild(e);return e;}
function kv(k,v){var wrap=document.createElement("div");var dt=document.createElement("dt");dt.textContent=k;var dd=document.createElement("dd");dd.textContent=(v===null||v===undefined||v==="")?"—":String(v);wrap.appendChild(dt);wrap.appendChild(dd);detail.appendChild(wrap);}
function showNode(n){
  while(detail.firstChild)detail.removeChild(detail.firstChild);
  empty.hidden=true;detail.hidden=false;
  kv("label",n.label);kv("kind",n.kind+" ("+n.shape_hint+")");kv("stored kind",n.stored_kind);
  kv("confidence",n.link_confidence===null||n.link_confidence===undefined?"unrated (no incident relationships)":n.link_confidence+" (strongest linked relationship)");
  kv("scope",n.scope);kv("observations",n.observations);
  Object.keys(n.attributes).sort().forEach(function(k){kv("attr "+k,n.attributes[k]);});
  (n.evidence||[]).forEach(function(e,i){kv("evidence "+(i+1),e);});
  chain(n.id);
}
function chain(id){
  var inc=DATA.edges.filter(function(e){return e.from===id||e.to===id;}).sort(function(a,b){return b.confidence-a.confidence;}).slice(0,16);
  inc.forEach(function(e){
    var dir=e.from===id?"out":"in";
    kv("link "+dir,e.relation+" ("+(e.observed?"observed":"inferred")+", confidence "+e.confidence+") "+e.module+" "+e.scan_run);
    (e.evidence||[]).forEach(function(x){kv("link evidence",x);});
  });
  if(!inc.length)kv("links","none in this view");
}
function showEdge(e){
  while(detail.firstChild)detail.removeChild(detail.firstChild);
  empty.hidden=true;detail.hidden=false;
  kv("relationship",e.relation);kv("stored",e.stored_relation);
  kv("style",e.observed?"solid (directly observed)":"dashed (inferred)");
  kv("confidence",e.confidence);kv("thickness",e.thickness);
  kv("from",e.from);kv("to",e.to);kv("module",e.module);kv("scan run",e.scan_run);
  (e.evidence||[]).forEach(function(x,i){kv("evidence "+(i+1),x);});
}
var SHAPES={network:"hexagon",ip:"circle",host:"square",port_service:"diamond",software:"triangle",certificate:"pentagon",domain:"ellipse",url:"rounded_rect",username:"ring",account:"double_square",exposure:"triangle_down",evidence:"parallelogram",scope:"dashed_circle",cluster:"octagon"};
var COLORS={network:"#078cff",ip:"#00efff",host:"#3ddc84",port_service:"#f0a04b",software:"#b07cc4",certificate:"#e5488f",domain:"#19f4ff",url:"#8fa9c2",username:"#e2e8f0",account:"#f4f8ff",exposure:"#f06666",evidence:"#6b7d94",scope:"#4a9eff",cluster:"#2a4a6b"};
var RAMP_COLOR={amber:"#f59e0b",blue:"#078cff",coral:"#f97316",gray:"#6b7d94",green:"#3ddc84",pink:"#e879f9",purple:"#8b5cf6",red:"#f06666",teal:"#14b8a6"};
function drawPoly(g,shape,x,y,r,fill){
  function pts(n,rot){var s=[];for(var i=0;i<n;i++){var a=rot+2*Math.PI*i/n;s.push((x+r*Math.cos(a)).toFixed(1)+","+(y+r*Math.sin(a)).toFixed(1));}return s.join(" ");}
  if(shape==="circle"){return el("circle",{cx:x,cy:y,r:r,fill:fill,stroke:"#010813","stroke-width":1.5},g);}
  if(shape==="ring"||shape==="dashed_circle"){var c=el("circle",{cx:x,cy:y,r:r,fill:"none",stroke:fill,"stroke-width":2.5},g);if(shape==="dashed_circle")c.setAttribute("stroke-dasharray","4 3");return c;}
  if(shape==="square"){return el("rect",{x:x-r*.85,y:y-r*.85,width:r*1.7,height:r*1.7,fill:fill,stroke:"#010813","stroke-width":1.5},g);}
  if(shape==="double_square"){el("rect",{x:x-r*.85,y:y-r*.85,width:r*1.7,height:r*1.7,fill:fill,stroke:"#010813","stroke-width":1.5},g);return el("rect",{x:x-r*.55,y:y-r*.55,width:r*1.1,height:r*1.1,fill:"none",stroke:"#010813","stroke-width":1},g);}
  if(shape==="rounded_rect"){return el("rect",{x:x-r,y:y-r*.7,width:r*2,height:r*1.4,rx:3,fill:fill,stroke:"#010813","stroke-width":1.5},g);}
  if(shape==="diamond"){return el("polygon",{points:x+","+ (y-r)+" "+(x+r)+","+y+" "+x+","+(y+r)+" "+(x-r)+","+y,fill:fill,stroke:"#010813","stroke-width":1.5},g);}
  if(shape==="triangle"){return el("polygon",{points:x+","+(y-r)+" "+(x-r)+","+(y+r*.8)+" "+(x+r)+","+(y+r*.8),fill:fill,stroke:"#010813","stroke-width":1.5},g);}
  if(shape==="triangle_down"){return el("polygon",{points:x+","+(y+r)+" "+(x-r)+","+(y-r*.8)+" "+(x+r)+","+(y-r*.8),fill:fill,stroke:"#010813","stroke-width":1.5},g);}
  if(shape==="ellipse"){return el("ellipse",{cx:x,cy:y,rx:r*1.25,ry:r*.8,fill:fill,stroke:"#010813","stroke-width":1.5},g);}
  if(shape==="parallelogram"){return el("polygon",{points:(x-r*.6)+","+(y-r*.8)+" "+(x+r)+","+(y-r*.8)+" "+(x+r*.6)+","+(y+r*.8)+" "+(x-r)+","+(y+r*.8),fill:fill,stroke:"#010813","stroke-width":1.5},g);}
  var sides=shape==="pentagon"?5:shape==="octagon"?8:6;
  return el("polygon",{points:pts(sides,-Math.PI/2),fill:fill,stroke:"#010813","stroke-width":1.5},g);
}
function render(){
  while(svg.firstChild)svg.removeChild(svg.firstChild);
  var g=el("g",{transform:"translate("+view.x+","+view.y+") scale("+view.k+")"},svg);
  var shown=DATA.nodes.filter(function(n){return (!kindFilter||n.kind===kindFilter)&&(!query||(n.label+" "+n.id).toLowerCase().indexOf(query)>=0);});
  var vis={};shown.forEach(function(n){vis[n.id]=n;});
  DATA.edges.slice(0,4000).forEach(function(e){
    if(!vis[e.from]||!vis[e.to])return;
    var a=vis[e.from],b=vis[e.to];
    var line=el("line",{x1:a.x,y1:a.y,x2:b.x,y2:b.y,stroke:e.observed?"#2e5a87":"#7a6a9a","stroke-width":e.thickness},g);
    if(!e.observed)line.setAttribute("stroke-dasharray","6 4");
    line.style.cursor="pointer";
    line.addEventListener("click",function(){showEdge(e);});
  });
  shown.slice(0,2000).forEach(function(n){
    n.shape_hint=SHAPES[n.kind]||"hexagon";
    var r=n.kind==="cluster"?Math.min(20,6+Math.sqrt(n.member_count||1)*2):7;
    var color=n.ramp&&RAMP_COLOR[n.ramp]?RAMP_COLOR[n.ramp]:(COLORS[n.kind]||"#078cff");
    if(n.icon){
      var use=document.createElementNS(NS,"use");
      use.setAttribute("href","#rx-"+n.icon);
      use.setAttribute("x",(n.x-r).toFixed(1));
      use.setAttribute("y",(n.y-r).toFixed(1));
      use.setAttribute("width",(2*r).toFixed(1));
      use.setAttribute("height",(2*r).toFixed(1));
      use.setAttribute("fill","none");
      use.setAttribute("stroke",color);
      use.setAttribute("stroke-width","2");
      use.style.cursor="pointer";
      use.addEventListener("click",function(){showNode(n);});
      g.appendChild(use);
    } else {
      var c=drawPoly(g,n.shape_hint,n.x,n.y,r,color);
      c.style.cursor="pointer";
      c.addEventListener("click",function(){showNode(n);});
    }
    var t=el("text",{x:n.x+r+3,y:n.y+4,"class":"glabel"},g);
    var label=String(n.label||n.id);
    t.textContent=label.length>28?label.slice(0,27)+"…":label;
  });
  var legend=document.getElementById("legend");
  while(legend.firstChild)legend.removeChild(legend.firstChild);
  Object.keys(COLORS).sort().forEach(function(k){
    var li=document.createElement("li");li.textContent=k+" ("+(SHAPES[k]||"?")+")";legend.appendChild(li);
  });
}
function applyT(){var g=svg.querySelector("g");if(g)g.setAttribute("transform","translate("+view.x+","+view.y+") scale("+view.k+")");}
var sel=document.getElementById("kindf");
Object.keys(COLORS).sort().forEach(function(k){var o=document.createElement("option");o.value=k;o.textContent=k;sel.appendChild(o);});
sel.addEventListener("change",function(){kindFilter=sel.value;render();});
document.getElementById("q").addEventListener("input",function(ev){query=ev.target.value.toLowerCase();render();});
document.getElementById("zin").addEventListener("click",function(){view.k=Math.min(4,view.k*1.25);applyT();});
document.getElementById("zout").addEventListener("click",function(){view.k=Math.max(.4,view.k*.8);applyT();});
document.getElementById("zreset").addEventListener("click",function(){view.x=0;view.y=0;view.k=1;applyT();});
var drag=null;
svg.addEventListener("pointerdown",function(ev){drag={x:ev.clientX,y:ev.clientY,vx:view.x,vy:view.y};svg.setPointerCapture(ev.pointerId);});
svg.addEventListener("pointermove",function(ev){if(!drag)return;view.x=drag.vx+(ev.clientX-drag.x);view.y=drag.vy+(ev.clientY-drag.y);applyT();});
svg.addEventListener("pointerup",function(){drag=null;});
svg.addEventListener("wheel",function(ev){ev.preventDefault();view.k=Math.min(4,Math.max(.4,view.k*(ev.deltaY<0?1.1:.9)));applyT();},{passive:false});
render();
})();
</script>
</body>
</html>
"###;

// ---------------------------------------------------------------------------
// PNG: dependency-free software rasterizer + stored-deflate PNG encoder.
// Text is intentionally not rasterized (no font stack offline): the PNG
// is a structural overview (shape = kind, dash = inference, width =
// confidence); labels live in the SVG/HTML/JSON exports of the same view.
// ---------------------------------------------------------------------------

/// Rasterize the laid-out view to PNG bytes (RGB, opaque).
pub fn to_png(
    view: &ViewGraph,
    positions: &BTreeMap<String, (f64, f64)>,
    width: u32,
    height: u32,
) -> Vec<u8> {
    let width = width.clamp(64, MAX_PNG_DIM) as usize;
    let height = height.clamp(64, MAX_PNG_DIM) as usize;
    let mut canvas = PngCanvas::new(width, height);
    let sx = width as f64 / LAYOUT_WIDTH;
    let sy = height as f64 / LAYOUT_HEIGHT;
    let place = |id: &str| {
        positions
            .get(id)
            .map(|(x, y)| ((x * sx) as i32, (y * sy) as i32))
            .unwrap_or((width as i32 / 2, height as i32 / 2))
    };
    // Edges under nodes.
    for edge in view.edges.iter().take(20_000) {
        let (x0, y0) = place(&edge.from);
        let (x1, y1) = place(&edge.to);
        let color = if edge.observed {
            (0x2e, 0x5a, 0x87)
        } else {
            (0x7a, 0x6a, 0x9a)
        };
        let thick = (edge.thickness.round() as i32).clamp(1, 4);
        canvas.line((x0, y0), (x1, y1), color, thick, !edge.observed);
    }
    // Nodes over edges.
    for node in view.nodes.iter().take(MAX_VIEW_NODES) {
        let (x, y) = place(&node.id);
        let r = if node.kind == DisplayKind::Cluster {
            (6.0 + (node.member_count as f64).sqrt() * 2.0).min(20.0) as i32
        } else {
            7
        };
        let icon = crate::graph_icons::node_icon(node.kind, &node.stored_kind, &node.attributes);
        let ramp = icon.and_then(crate::graph_icons::ramp_of);
        let color_hex = ramp
            .and_then(crate::graph_icons::ramp_color)
            .unwrap_or(node.kind.color());
        let shape = icon
            .and_then(crate::graph_icons::shape_of)
            .unwrap_or_else(|| node.kind.shape());
        let color = hex_rgb(color_hex);
        let border = (color.0 / 3, color.1 / 3, color.2 / 3);
        canvas.glyph(shape, x, y, r, color, border);
    }
    encode_png(width, height, &canvas.buf)
}

fn hex_rgb(hex: &str) -> (u8, u8, u8) {
    let digits = hex.strip_prefix('#').unwrap_or(hex);
    let value = u32::from_str_radix(digits, 16).unwrap_or(0x078cff);
    (
        ((value >> 16) & 0xff) as u8,
        ((value >> 8) & 0xff) as u8,
        (value & 0xff) as u8,
    )
}

/// Tiny RGB framebuffer backing the PNG rasterizer.
struct PngCanvas {
    buf: Vec<u8>,
    width: usize,
    height: usize,
}

impl PngCanvas {
    fn new(width: usize, height: usize) -> Self {
        let mut buf = vec![0u8; width * height * 3];
        // Background #010813.
        for chunk in buf.chunks_exact_mut(3) {
            chunk[0] = 0x01;
            chunk[1] = 0x08;
            chunk[2] = 0x13;
        }
        Self { buf, width, height }
    }

    fn put(&mut self, x: i32, y: i32, color: (u8, u8, u8)) {
        if x < 0 || y < 0 || x >= self.width as i32 || y >= self.height as i32 {
            return;
        }
        let at = (y as usize * self.width + x as usize) * 3;
        if at + 2 < self.buf.len() {
            self.buf[at] = color.0;
            self.buf[at + 1] = color.1;
            self.buf[at + 2] = color.2;
        }
    }

    /// Bresenham line with square brush (`thick`) and optional dash.
    fn line(
        &mut self,
        from: (i32, i32),
        to: (i32, i32),
        color: (u8, u8, u8),
        thick: i32,
        dashed: bool,
    ) {
        let (x0, y0) = from;
        let (x1, y1) = to;
        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let (sx, sy) = (if x0 < x1 { 1 } else { -1 }, if y0 < y1 { 1 } else { -1 });
        let (mut x, mut y) = (x0, y0);
        let mut err = dx + dy;
        let mut step = 0u32;
        let half = thick / 2;
        loop {
            let on = !dashed || (step % 10) < 6;
            if on {
                for oy in -half..=half {
                    for ox in -half..=half {
                        self.put(x + ox, y + oy, color);
                    }
                }
            }
            if x == x1 && y == y1 {
                break;
            }
            let before = (x, y);
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                x += sx;
            }
            if e2 <= dx {
                err += dx;
                y += sy;
            }
            // Degenerate guard: no progress means a zero-length line.
            if (x, y) == before {
                break;
            }
            step += 1;
            if step > 100_000 {
                break;
            }
        }
    }

    fn glyph(
        &mut self,
        shape: &str,
        cx: i32,
        cy: i32,
        r: i32,
        fill: (u8, u8, u8),
        border: (u8, u8, u8),
    ) {
        // Convex polygon vertices per shape (circle handled analytically).
        let verts: Vec<(f64, f64)> = match shape {
            "square" | "double_square" => {
                vec![(-0.85, -0.85), (0.85, -0.85), (0.85, 0.85), (-0.85, 0.85)]
            }
            "rounded_rect" => vec![(-1.0, -0.7), (1.0, -0.7), (1.0, 0.7), (-1.0, 0.7)],
            "diamond" => vec![(0.0, -1.0), (1.0, 0.0), (0.0, 1.0), (-1.0, 0.0)],
            "triangle" => vec![(0.0, -1.0), (-1.0, 0.8), (1.0, 0.8)],
            "triangle_down" => vec![(0.0, 1.0), (-1.0, -0.8), (1.0, -0.8)],
            "ellipse" => vec![(-1.25, 0.0), (0.0, -0.8), (1.25, 0.0), (0.0, 0.8)],
            "parallelogram" => vec![(-0.6, -0.8), (1.0, -0.8), (0.6, 0.8), (-1.0, 0.8)],
            "pentagon" => poly_verts(5),
            "octagon" => poly_verts(8),
            _ => poly_verts(6), // hexagon default
        };
        let r = r.max(2) as f64;
        if shape == "circle" || shape == "ring" || shape == "dashed_circle" {
            let rr = (r * r) as i32;
            let inner = ((r - 2.5).max(1.0).powi(2)) as i32;
            for oy in -(r as i32)..=(r as i32) {
                for ox in -(r as i32)..=(r as i32) {
                    let d = ox * ox + oy * oy;
                    if d <= rr && (shape == "circle" || d >= inner) {
                        self.put(cx + ox, cy + oy, fill);
                    }
                }
            }
            return;
        }
        let pts: Vec<(f64, f64)> = verts
            .iter()
            .map(|(vx, vy)| (cx as f64 + vx * r, cy as f64 + vy * r))
            .collect();
        let min_y = pts
            .iter()
            .map(|p| p.1)
            .fold(f64::INFINITY, f64::min)
            .floor() as i32;
        let max_y = pts
            .iter()
            .map(|p| p.1)
            .fold(f64::NEG_INFINITY, f64::max)
            .ceil() as i32;
        for y in min_y..=max_y {
            let mut xs = Vec::new();
            for i in 0..pts.len() {
                let (x1, y1) = pts[i];
                let (x2, y2) = pts[(i + 1) % pts.len()];
                if (y1 <= y as f64) != (y2 <= y as f64) {
                    let x = x1 + (y as f64 - y1) * (x2 - x1) / (y2 - y1);
                    xs.push(x);
                }
            }
            xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            for pair in xs.chunks(2) {
                if pair.len() == 2 {
                    for x in pair[0].floor() as i32..=pair[1].ceil() as i32 {
                        self.put(x, y, fill);
                    }
                }
            }
        }
        // 1px darker outline: redraw polygon boundary ticks.
        for i in 0..pts.len() {
            let (x1, y1) = pts[i];
            let (x2, y2) = pts[(i + 1) % pts.len()];
            self.line(
                (x1.round() as i32, y1.round() as i32),
                (x2.round() as i32, y2.round() as i32),
                border,
                1,
                false,
            );
        }
    }
}

fn poly_verts(sides: usize) -> Vec<(f64, f64)> {
    (0..sides)
        .map(|i| {
            let a =
                -std::f64::consts::PI / 2.0 + 2.0 * std::f64::consts::PI * i as f64 / sides as f64;
            (a.cos(), a.sin())
        })
        .collect()
}

// --- Minimal PNG encoder (stored deflate blocks; no compression library). ---

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffffffff;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb88320 & mask);
        }
    }
    !crc
}

fn adler32(data: &[u8]) -> u32 {
    const BASE: u32 = 65521;
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for byte in chunk {
            a = (a + u32::from(*byte)) % BASE;
            b = (b + a) % BASE;
        }
    }
    (b << 16) | a
}

fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut for_crc = Vec::with_capacity(4 + data.len());
    for_crc.extend_from_slice(kind);
    for_crc.extend_from_slice(data);
    out.extend_from_slice(&crc32(&for_crc).to_be_bytes());
    out
}

fn encode_png(width: usize, height: usize, rgb: &[u8]) -> Vec<u8> {
    // Raw image: filter-0 scanlines.
    let mut raw = Vec::with_capacity(height * (1 + width * 3));
    for row in 0..height {
        raw.push(0u8);
        raw.extend_from_slice(&rgb[row * width * 3..(row + 1) * width * 3]);
    }
    // zlib wrapper with stored (uncompressed) blocks.
    let mut zlib = vec![0x78u8, 0x01];
    for (i, block) in raw.chunks(65_535).enumerate() {
        let last = i == raw.chunks(65_535).len() - 1;
        zlib.push(if last { 0x01 } else { 0x00 });
        let len = block.len() as u16;
        zlib.extend_from_slice(&len.to_le_bytes());
        zlib.extend_from_slice(&(!len).to_le_bytes());
        zlib.extend_from_slice(block);
    }
    zlib.extend_from_slice(&adler32(&raw).to_be_bytes());
    let mut png = vec![137u8, 80, 78, 71, 13, 10, 26, 10];
    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&(width as u32).to_be_bytes());
    ihdr.extend_from_slice(&(height as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB, no interlace
    png.extend_from_slice(&chunk(b"IHDR", &ihdr));
    png.extend_from_slice(&chunk(b"IDAT", &zlib));
    png.extend_from_slice(&chunk(b"IEND", &[]));
    png
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_KINDS: &[&str] = &[
        "username",
        "email_address",
        "domain",
        "account",
        "organization",
        "network_endpoint",
        "repository",
        "asn",
        "host",
        "ip_address",
        "hostname",
        "port",
        "service",
        "certificate",
        "ssh_host_key",
        "dns_record",
        "web_endpoint",
        "technology",
        "fingerprint",
        "os_candidate",
        "device_candidate",
        "exposure",
        "exposure_source",
        "network_prefix",
        "package",
        "document",
        "archive_snapshot",
        "public_key",
        "route",
        "provider",
        "identity_hypothesis",
        "software",
    ];

    const ALL_RELATIONS: &[&str] = &[
        "has_account",
        "uses_username",
        "links_to",
        "reverse_resolves_to",
        "belongs_to_asn",
        "announces_prefix",
        "found_by",
        "has_address",
        "resolves_to",
        "listens_on",
        "runs_service",
        "presents_certificate",
        "presents_ssh_host_key",
        "has_san",
        "redirects_to",
        "identified_by",
        "discovered_from",
        "observed_at",
        "suggests",
        "references",
        "served_by",
        "resolves_to_endpoint",
        "exposed_in",
        "observed_in",
        "affects",
        "reported_by",
        "targeted_domain",
        "mail_exchanger",
        "name_server_for",
        "alias_of",
        "owns_repository",
        "contributed_to",
        "published_release",
        "references_domain",
        "references_url",
        "uses_package",
        "signed_by",
        "observed_association",
        "likely_association",
        "possible_association",
        "ownership",
        "supports",
        "contradicts",
    ];

    #[test]
    fn every_stored_kind_maps_to_a_display_entity() {
        assert_eq!(ALL_KINDS.len(), 32);
        for name in ALL_KINDS {
            let stored = crate::graph::EntityKind::parse(name)
                .unwrap_or_else(|| panic!("stored kind missing: {name}"));
            let display = display_kind_of(stored);
            assert_ne!(
                display,
                DisplayKind::Cluster,
                "stored kinds never map to Cluster"
            );
            assert!(DisplayKind::all().contains(&display));
        }
    }

    #[test]
    fn every_stored_relation_maps_to_a_display_link() {
        assert_eq!(ALL_RELATIONS.len(), 43);
        for name in ALL_RELATIONS {
            let stored = crate::graph::EdgeRelation::parse(name)
                .unwrap_or_else(|| panic!("stored relation missing: {name}"));
            let (display, _) = display_rel_of(stored);
            assert!(DisplayRel::all().contains(&display));
        }
    }

    #[test]
    fn thickness_grows_with_confidence() {
        assert_eq!(thickness_for(0), 1.0);
        assert!(thickness_for(50) > thickness_for(10));
        assert_eq!(thickness_for(100), 4.0);
        assert_eq!(thickness_for(200), 4.0);
    }

    fn fixture_sources() -> (Vec<SourceNode>, Vec<SourceEdge>) {
        let node = |id: &str, kind: &str| SourceNode {
            id: id.to_owned(),
            stored_kind: kind.to_owned(),
            label: id.to_owned(),
            attributes: BTreeMap::new(),
            first_seen_ms: 1_700_000_000_000,
            last_seen_ms: 1_700_000_000_000,
            observations: 1,
        };
        let edge = |from: &str, to: &str, rel: &str, conf: u8| SourceEdge {
            from: from.to_owned(),
            to: to.to_owned(),
            stored_relation: rel.to_owned(),
            confidence: conf,
            module: "tcp_scan".to_owned(),
            scan_run: "scan1".to_owned(),
            evidence: vec![format!("evidence for {from} {rel}")],
        };
        let sources = vec![
            node("host:example.test", "hostname"),
            node("ip:192.0.2.10", "ip_address"),
            node("port:tcp:192.0.2.10:80", "port"),
            node("cert:sha256:abc", "certificate"),
        ];
        let edges = vec![
            edge("host:example.test", "ip:192.0.2.10", "resolves_to", 85),
            edge("ip:192.0.2.10", "port:tcp:192.0.2.10:80", "listens_on", 90),
            edge(
                "port:tcp:192.0.2.10:80",
                "cert:sha256:abc",
                "presents_certificate",
                90,
            ),
        ];
        (sources, edges)
    }

    #[test]
    fn view_builds_with_evidence_and_link_confidence() {
        let (sources, edges) = fixture_sources();
        let view = build_view(sources, edges, &ViewOptions::default());
        assert_eq!(view.nodes.len(), 4);
        assert_eq!(view.edges.len(), 3);
        assert!(!view.truncated);
        for edge in &view.edges {
            assert!(!edge.evidence.is_empty(), "every edge links evidence");
            assert!(edge.thickness >= 1.0);
        }
        let ip = view.nodes.iter().find(|n| n.id == "ip:192.0.2.10").unwrap();
        assert_eq!(ip.kind, DisplayKind::Ip);
        assert_eq!(ip.link_confidence, Some(90));
        assert_eq!(ip.scope, ScopeState::Unknown);
    }

    #[test]
    fn filters_apply_and_caps_report_truncation() {
        let (sources, edges) = fixture_sources();
        let opts = ViewOptions {
            min_confidence: 86,
            ..ViewOptions::default()
        }
        .bounded();
        let view = build_view(sources, edges, &opts);
        // The 85-confidence resolves_to edge drops with its evidence.
        assert_eq!(view.edges.len(), 2);
        let opts = ViewOptions {
            types: Some(BTreeSet::from([DisplayKind::Ip])),
            ..ViewOptions::default()
        }
        .bounded();
        let (sources, edges) = fixture_sources();
        let view = build_view(sources, edges, &opts);
        assert_eq!(view.nodes.len(), 1);
        // Caps bite honestly.
        let opts = ViewOptions {
            limit_nodes: 2,
            limit_edges: 1,
            ..ViewOptions::default()
        }
        .bounded();
        let (sources, edges) = fixture_sources();
        let view = build_view(sources, edges, &opts);
        assert!(view.truncated);
        assert_eq!(view.total_nodes, 4);
    }

    #[test]
    fn seed_bfs_bounds_the_view() {
        let (sources, edges) = fixture_sources();
        let opts = ViewOptions {
            seed: Some("host:example.test".to_owned()),
            depth: 1,
            ..ViewOptions::default()
        }
        .bounded();
        let view = build_view(sources, edges, &opts);
        assert_eq!(view.nodes.len(), 2);
        assert_eq!(view.edges.len(), 1);
    }

    #[test]
    fn secrets_are_masked_at_view_build() {
        let sources = vec![SourceNode {
            id: "endpoint:https://admin:s3cret@example.test/".to_owned(),
            stored_kind: "web_endpoint".to_owned(),
            label: "https://admin:s3cret@example.test/?token=abc".to_owned(),
            attributes: BTreeMap::from([
                ("url".to_owned(), "https://example.test/".to_owned()),
                ("api_key".to_owned(), "LIVE-KEY".to_owned()),
            ]),
            first_seen_ms: 1,
            last_seen_ms: 1,
            observations: 1,
        }];
        let view = build_view(sources, Vec::new(), &ViewOptions::default());
        let flat = serde_json::to_string(&view).unwrap();
        for secret in ["s3cret", "abc", "LIVE-KEY"] {
            assert!(!flat.contains(secret), "leaked: {secret}");
        }
    }

    #[test]
    fn layouts_cover_every_node_and_are_deterministic() {
        let (sources, edges) = fixture_sources();
        let view = build_view(sources, edges, &ViewOptions::default());
        for kind in LayoutKind::all() {
            let first = layout(&view, *kind, Some("host:example.test"));
            let second = layout(&view, *kind, Some("host:example.test"));
            assert_eq!(
                first,
                second,
                "layout {} must be deterministic",
                kind.as_str()
            );
            assert_eq!(first.len(), 4);
            for (x, y) in first.values() {
                assert!(x.is_finite() && y.is_finite());
                assert!((0.0..=LAYOUT_WIDTH).contains(x));
                assert!((0.0..=LAYOUT_HEIGHT).contains(y));
            }
        }
    }

    #[test]
    fn clustering_collapses_to_budget() {
        // 40-node chain, budget 16: must collapse, stay deterministic.
        let mut sources = Vec::new();
        let mut edges = Vec::new();
        for i in 0..40 {
            sources.push(SourceNode {
                id: format!("ip:192.0.2.{i}"),
                stored_kind: "ip_address".to_owned(),
                label: format!("192.0.2.{i}"),
                attributes: BTreeMap::new(),
                first_seen_ms: 1,
                last_seen_ms: 1,
                observations: 1,
            });
            if i > 0 {
                edges.push(SourceEdge {
                    from: format!("ip:192.0.2.{}", i - 1),
                    to: format!("ip:192.0.2.{i}"),
                    stored_relation: "links_to".to_owned(),
                    confidence: 70,
                    module: "t".to_owned(),
                    scan_run: "s".to_owned(),
                    evidence: vec!["linked".to_owned()],
                });
            }
        }
        let view = build_view(sources, edges, &ViewOptions::default().bounded());
        let (clustered, membership) = cluster_beyond(&view, 16);
        assert!(clustered.nodes.len() <= 16);
        assert!(!membership.is_empty());
        let members: usize = membership.values().map(Vec::len).sum();
        assert!(members > clustered.nodes.len());
    }

    #[test]
    fn exports_are_masked_and_well_formed() {
        let (sources, edges) = fixture_sources();
        let view = build_view(sources, edges, &ViewOptions::default());
        let positions = layout(&view, LayoutKind::Circular, None);
        let json = to_json(&view);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["graph_schema_version"], 1);
        assert_eq!(parsed["nodes"].as_array().unwrap().len(), 4);
        let graphml = to_graphml(&view);
        assert!(graphml.contains("<graphml"));
        assert!(graphml.contains("confidence"));
        let svg = to_svg(&view, &positions, 800, 600);
        assert!(svg.contains("<svg"));
        assert!(svg.contains("port_service"));
        let html = to_html(&view, &positions, "t");
        assert!(html.contains("<svg"));
        // Offline: the only absolute URI allowed is the SVG namespace
        // identifier (never fetched), mirroring the GUI precedent.
        let scrubbed = html.replace("http://www.w3.org/2000/svg", "");
        assert!(!scrubbed.contains("http://") && !scrubbed.contains("https://"));
    }

    #[test]
    fn png_is_a_valid_decodable_image() {
        let (sources, edges) = fixture_sources();
        let view = build_view(sources, edges, &ViewOptions::default());
        let positions = layout(&view, LayoutKind::Organic, None);
        let png = to_png(&view, &positions, 320, 200);
        assert_eq!(&png[0..8], &[137, 80, 78, 71, 13, 10, 26, 10]);
        // Walk chunks: IHDR dims must match, IEND must close, IDAT must
        // inflate (stored blocks) with a valid Adler32.
        let mut at = 8usize;
        let (mut w, mut h) = (0u32, 0u32);
        let mut idat: Vec<u8> = Vec::new();
        let mut saw_iend = false;
        while at + 8 <= png.len() {
            let len = u32::from_be_bytes([png[at], png[at + 1], png[at + 2], png[at + 3]]) as usize;
            let kind = &png[at + 4..at + 8];
            let data = &png[at + 8..at + 8 + len];
            if kind == b"IHDR" {
                w = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                h = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            } else if kind == b"IDAT" {
                idat.extend_from_slice(data);
            } else if kind == b"IEND" {
                saw_iend = true;
            }
            at += 12 + len;
        }
        assert!((w, h) == (320, 200));
        assert!(saw_iend);
        let raw = inflate_stored(&idat);
        assert_eq!(raw.len(), 200 * (1 + 320 * 3));
    }

    /// Minimal inflate for stored (uncompressed) deflate blocks only.
    fn inflate_stored(zlib: &[u8]) -> Vec<u8> {
        assert_eq!(&zlib[0..2], &[0x78, 0x01]);
        let mut at = 2usize;
        let mut out = Vec::new();
        loop {
            let header = zlib[at];
            at += 1;
            let len = u16::from_le_bytes([zlib[at], zlib[at + 1]]) as usize;
            let nlen = u16::from_le_bytes([zlib[at + 2], zlib[at + 3]]);
            assert_eq!((len as u16) ^ 0xffff, nlen);
            out.extend_from_slice(&zlib[at + 4..at + 4 + len]);
            at += 4 + len;
            if header & 1 == 1 {
                break;
            }
        }
        let expect = u32::from_be_bytes([zlib[at], zlib[at + 1], zlib[at + 2], zlib[at + 3]]);
        assert_eq!(expect, adler32(&out));
        out
    }

    /// `to_json` appends `icon`/`category` through `NodeWithIcon`, which
    /// restates every `ViewNode` field by hand. If a field is added to
    /// `ViewNode` and not mirrored there, it would silently vanish from the
    /// canonical export: `first_seen_ms`/`last_seen_ms` were lost exactly
    /// that way. This compares the two field sets directly.
    #[test]
    fn node_json_fields_are_complete() {
        let (sources, edges) = fixture_sources();
        let view = build_view(sources, edges, &ViewOptions::default());
        let exported: serde_json::Value =
            serde_json::from_str(&to_json(&view)).expect("to_json is valid JSON");
        let node = exported["nodes"][0]
            .as_object()
            .expect("first node is an object")
            .clone();
        // Every ViewNode field must appear, plus exactly the two additive
        // manifest fields.
        let expected = [
            "attributes",
            "category",
            "evidence",
            "first_seen_ms",
            "icon",
            "id",
            "kind",
            "label",
            "last_seen_ms",
            "link_confidence",
            "member_count",
            "observations",
            "scope",
            "stored_kind",
        ];
        let mut actual: Vec<&str> = node.keys().map(String::as_str).collect();
        actual.sort_unstable();
        assert_eq!(actual, expected, "to_json node fields drifted");
    }

    #[test]
    fn node_detail_links_every_incident_edge() {
        let (sources, edges) = fixture_sources();
        let view = build_view(sources, edges, &ViewOptions::default());
        let detail = node_detail(&view, "ip:192.0.2.10", Vec::new()).unwrap();
        assert_eq!(detail.incident_edges.len(), 2);
        // Both incident relationships surface in the chain with evidence.
        assert!(detail.evidence_chain.len() >= 2);
        assert!(detail.explanation.contains("90"));
        assert!(detail.explanation.contains("raising confidence"));
        assert!(node_detail(&view, "nope", Vec::new()).is_none());
    }

    #[test]
    fn expand_neighbors_is_bounded_and_sorted() {
        let (sources, edges) = fixture_sources();
        let view = build_view(sources, edges, &ViewOptions::default());
        let neighbors = expand_neighbors(&view, "ip:192.0.2.10", 100);
        assert_eq!(
            neighbors,
            vec![
                "host:example.test".to_owned(),
                "port:tcp:192.0.2.10:80".to_owned()
            ]
        );
        assert_eq!(expand_neighbors(&view, "ip:192.0.2.10", 1).len(), 1);
    }
}
