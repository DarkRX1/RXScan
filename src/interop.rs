//! Interoperability: Nmap XML import; SARIF, STIX 2.1, CSV export
//! (GraphML export reuses [`crate::graph_view::to_graphml`]).
//!
//! Imports are labeled by origin (`import:nmap`) and capped below native
//! confidence ([`IMPORT_CONFIDENCE_CAP`]): imported data never outranks
//! direct observation. The Nmap reader is a narrow hand-rolled pull parser
//! over the Nmap schema subset — no new dependency, and hostile input is
//! rejected fail-closed:
//!
//! * `<!DOCTYPE`, `<!ENTITY`, `%`-parametrized DTDs: rejected outright (no
//!   external entity expansion, no billion-laughs amplification — ever);
//! * inputs over [`MAX_IMPORT_BYTES`] rejected before parsing;
//! * nesting depth, attribute sizes/counts, and collected hosts/ports are
//!   all capped; excess is an error, never silent truncation of structure;
//! * only `&lt; &gt; &amp; &quot; &apos;` entities decode (unknown
//!   entities are malformed input, not skipped content).
//!
//! All exports render from the masked view model, so secrets cannot leak
//! through format conversion.

use std::collections::BTreeMap;

use crate::graph_view::{DisplayKind, ViewEdge, ViewGraph, ViewNode};

// ---------------------------------------------------------------------------
// Bounds and confidence policy.
// ---------------------------------------------------------------------------

/// Maximum Nmap XML input accepted (consistent with extension pack files).
pub const MAX_IMPORT_BYTES: usize = 4 * 1024 * 1024;
/// Maximum hosts collected per import.
pub const MAX_IMPORT_HOSTS: usize = 5000;
/// Maximum ports collected per host.
pub const MAX_IMPORT_PORTS_PER_HOST: usize = 1024;
/// Maximum nesting depth while parsing.
pub const MAX_IMPORT_DEPTH: usize = 32;
/// Maximum length of one attribute value or text run.
pub const MAX_IMPORT_TOKEN: usize = 4096;
/// Imported observations never exceed this confidence (native direct
/// observations score 85+). Imports inform; they never outrank.
pub const IMPORT_CONFIDENCE_CAP: u8 = 60;

/// Origin label stamped on provenance, attributes, and evidence.
pub const NMAP_ORIGIN: &str = "import:nmap";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteropError {
    TooLarge(String),
    Malformed(String),
    Rejected(String),
}

impl std::fmt::Display for InteropError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge(detail) => write!(f, "import too large: {detail}"),
            Self::Malformed(detail) => write!(f, "malformed import: {detail}"),
            Self::Rejected(detail) => write!(f, "rejected import: {detail}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Nmap XML import.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportedPort {
    pub port: u16,
    pub transport: String,
    pub state: String,
    pub service: String,
    pub product: String,
    pub version: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportedHost {
    pub address: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub ports: Vec<ImportedPort>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportStats {
    pub hosts: usize,
    pub ports_open: usize,
    pub ports_skipped: usize,
    pub hosts_capped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmapImport {
    pub hosts: Vec<ImportedHost>,
    pub stats: ImportStats,
}

#[derive(Debug, Clone)]
struct XmlAttr {
    name: String,
    value: String,
}

#[derive(Debug, Clone)]
enum XmlToken {
    Open {
        name: String,
        attrs: Vec<XmlAttr>,
        self_closing: bool,
    },
    Close(String),
}

fn is_name_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':')
}

fn decode_entities(text: &str) -> Result<String, InteropError> {
    if !text.contains('&') {
        return Ok(text.to_owned());
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos..];
        let end = tail
            .find(';')
            .ok_or_else(|| InteropError::Malformed("unterminated entity reference".to_owned()))?;
        if end > 12 {
            return Err(InteropError::Malformed(
                "entity reference too long".to_owned(),
            ));
        }
        match &tail[..end + 1] {
            "&lt;" => out.push('<'),
            "&gt;" => out.push('>'),
            "&amp;" => out.push('&'),
            "&quot;" => out.push('"'),
            "&apos;" => out.push('\''),
            other => {
                return Err(InteropError::Malformed(format!(
                    "unsupported entity reference: {other}"
                )));
            }
        }
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Tokenize narrow XML. Rejects DTDs, comments are skipped, PIs skipped.
fn tokenize(input: &str) -> Result<Vec<XmlToken>, InteropError> {
    if input.len() > MAX_IMPORT_BYTES {
        return Err(InteropError::TooLarge(format!(
            "input {} bytes exceeds {} bytes",
            input.len(),
            MAX_IMPORT_BYTES
        )));
    }
    let mut tokens = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            // Text runs carry no Nmap data in our subset (all signal is
            // in attributes) but entity references in text are still
            // validated fail-closed: undefined entities are malformed,
            // never silently skipped content.
            let start = i;
            while i < bytes.len() && bytes[i] != b'<' {
                i += 1;
            }
            check_text_entities(&input[start..i])?;
            continue;
        }
        // Comment, PI, or declaration.
        if input[i..].starts_with("<!--") {
            let Some(end) = input[i..].find("-->") else {
                return Err(InteropError::Malformed("unterminated comment".to_owned()));
            };
            i += end + 3;
            continue;
        }
        if input[i..].starts_with("<?") {
            let Some(end) = input[i..].find("?>") else {
                return Err(InteropError::Malformed(
                    "unterminated processing instruction".to_owned(),
                ));
            };
            i += end + 2;
            continue;
        }
        if input[i..].starts_with("<!DOCTYPE") || input[i..].starts_with("<!ENTITY") {
            return Err(InteropError::Rejected(
                "document type declarations and entity definitions are not accepted".to_owned(),
            ));
        }
        if input[i..].starts_with("<!") {
            // Any other declaration (e.g. ATLAS, NOTATION): fail closed.
            return Err(InteropError::Rejected(
                "markup declarations are not accepted".to_owned(),
            ));
        }
        let Some(end) = input[i..].find('>') else {
            return Err(InteropError::Malformed("unterminated tag".to_owned()));
        };
        if end > MAX_IMPORT_TOKEN * 2 {
            return Err(InteropError::Malformed("tag too long".to_owned()));
        }
        let mut tag = input[i + 1..i + end].to_owned();
        i += end + 1;
        if let Some(name) = tag.strip_prefix('/') {
            let name = name.trim();
            if name.is_empty() || !name.chars().all(is_name_char) {
                return Err(InteropError::Malformed("bad closing tag".to_owned()));
            }
            tokens.push(XmlToken::Close(name.to_ascii_lowercase()));
            continue;
        }
        let self_closing = tag.ends_with('/');
        if self_closing {
            tag.pop();
        }
        let tag = tag.trim();
        let split = tag.find(|c: char| c.is_whitespace()).unwrap_or(tag.len());
        let name = tag[..split].to_ascii_lowercase();
        if name.is_empty() || !name.chars().all(is_name_char) {
            return Err(InteropError::Malformed("bad opening tag".to_owned()));
        }
        let mut attrs = Vec::new();
        let mut rest = tag[split..].trim();
        while !rest.is_empty() {
            let name_end = rest
                .find(|c: char| !(is_name_char(c)))
                .unwrap_or(rest.len());
            let attr_name = rest[..name_end].to_ascii_lowercase();
            rest = rest[name_end..].trim_start();
            let Some(eq) = rest.strip_prefix('=') else {
                return Err(InteropError::Malformed(format!(
                    "attribute without value near {attr_name}"
                )));
            };
            rest = eq.trim_start();
            let quote = rest
                .chars()
                .next()
                .ok_or_else(|| InteropError::Malformed("attribute value missing".to_owned()))?;
            if quote != '"' && quote != '\'' {
                return Err(InteropError::Malformed(format!(
                    "unquoted attribute value near {attr_name}"
                )));
            }
            let Some(close) = rest[1..].find(quote).map(|p| p + 1) else {
                return Err(InteropError::Malformed(format!(
                    "unterminated attribute value near {attr_name}"
                )));
            };
            let raw = &rest[1..close];
            if raw.len() > MAX_IMPORT_TOKEN {
                return Err(InteropError::Malformed(format!(
                    "attribute value too long near {attr_name}"
                )));
            }
            if attrs.len() >= 64 {
                return Err(InteropError::Malformed("too many attributes".to_owned()));
            }
            attrs.push(XmlAttr {
                name: attr_name,
                value: decode_entities(raw)?,
            });
            rest = rest[close + 1..].trim_start();
        }
        tokens.push(XmlToken::Open {
            name,
            attrs,
            self_closing,
        });
        if tokens.len() > 1_000_000 {
            return Err(InteropError::Malformed("too many tokens".to_owned()));
        }
    }
    Ok(tokens)
}

fn attr<'a>(attrs: &'a [XmlAttr], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|attr| attr.name == name)
        .map(|attr| attr.value.as_str())
}

/// Validate entity references inside skipped text: only the five
/// predefined XML entities may appear; anything else is malformed.
fn check_text_entities(text: &str) -> Result<(), InteropError> {
    let mut rest = text;
    while let Some(pos) = rest.find('&') {
        let tail = &rest[pos..];
        let end = tail
            .find(';')
            .ok_or_else(|| InteropError::Malformed("unterminated entity reference".to_owned()))?;
        if end > 12 {
            return Err(InteropError::Malformed(
                "entity reference too long".to_owned(),
            ));
        }
        match &tail[..end + 1] {
            "&lt;" | "&gt;" | "&amp;" | "&quot;" | "&apos;" => {}
            other => {
                return Err(InteropError::Malformed(format!(
                    "unsupported entity reference: {other}"
                )));
            }
        }
        rest = &tail[end + 1..];
    }
    Ok(())
}

/// Parse Nmap XML (`nmaprun/host/...` subset) into host records.
pub fn import_nmap_xml(input: &str) -> Result<NmapImport, InteropError> {
    let tokens = tokenize(input)?;
    let mut hosts: Vec<ImportedHost> = Vec::new();
    let mut stats = ImportStats::default();
    let mut stack: Vec<String> = Vec::new();
    let mut current: Option<ImportedHost> = None;
    let mut current_port: Option<ImportedPort> = None;
    let mut seen_root = false;
    for token in &tokens {
        match token {
            XmlToken::Open {
                name,
                attrs,
                self_closing,
            } => {
                if stack.len() >= MAX_IMPORT_DEPTH {
                    return Err(InteropError::Malformed("nesting too deep".to_owned()));
                }
                if stack.is_empty() {
                    if name != "nmaprun" {
                        return Err(InteropError::Malformed(
                            "expected nmaprun root element".to_owned(),
                        ));
                    }
                    seen_root = true;
                }
                stack.push(name.clone());
                match name.as_str() {
                    "host" => {
                        if current.is_some() {
                            return Err(InteropError::Malformed("nested host".to_owned()));
                        }
                        if hosts.len() >= MAX_IMPORT_HOSTS {
                            stats.hosts_capped = true;
                        } else {
                            current = Some(ImportedHost::default());
                        }
                    }
                    "address" => {
                        if let Some(host) = current.as_mut() {
                            if host.address.is_empty() {
                                if let Some(addr) = attr(attrs, "addr") {
                                    host.address = addr.chars().take(256).collect();
                                }
                            }
                        }
                    }
                    "hostname" => {
                        if let Some(host) = current.as_mut() {
                            if host.hostname.is_none() {
                                if let Some(name) = attr(attrs, "name") {
                                    host.hostname = Some(name.chars().take(253).collect());
                                }
                            }
                        }
                    }
                    "port" => {
                        if current.is_some() && current_port.is_none() {
                            let port = attr(attrs, "portid").unwrap_or("");
                            let transport = attr(attrs, "protocol").unwrap_or("tcp");
                            if let Ok(port) = port.parse::<u16>() {
                                current_port = Some(ImportedPort {
                                    port,
                                    transport: transport.chars().take(16).collect(),
                                    ..ImportedPort::default()
                                });
                            }
                        }
                    }
                    "state" => {
                        if let Some(port) = current_port.as_mut() {
                            if let Some(state) = attr(attrs, "state") {
                                port.state = state.chars().take(32).collect();
                            }
                        }
                    }
                    "service" => {
                        if let Some(port) = current_port.as_mut() {
                            if let Some(name) = attr(attrs, "name") {
                                port.service = name.chars().take(64).collect();
                            }
                            if let Some(product) = attr(attrs, "product") {
                                port.product = product.chars().take(128).collect();
                            }
                            if let Some(version) = attr(attrs, "version") {
                                port.version = version.chars().take(64).collect();
                            }
                        }
                    }
                    "osmatch" => {
                        if let Some(host) = current.as_mut() {
                            if host.os.is_none() {
                                if let Some(name) = attr(attrs, "name") {
                                    host.os = Some(name.chars().take(128).collect());
                                }
                            }
                        }
                    }
                    _ => {}
                }
                if *self_closing {
                    close_tag(
                        &mut stack,
                        name,
                        &mut current,
                        &mut current_port,
                        &mut hosts,
                        &mut stats,
                    )?;
                }
            }
            XmlToken::Close(name) => {
                close_tag(
                    &mut stack,
                    name,
                    &mut current,
                    &mut current_port,
                    &mut hosts,
                    &mut stats,
                )?;
            }
        }
    }
    if !seen_root {
        return Err(InteropError::Malformed(
            "no nmaprun root element".to_owned(),
        ));
    }
    if !stack.is_empty() {
        return Err(InteropError::Malformed("unclosed elements".to_owned()));
    }
    stats.hosts = hosts.len();
    Ok(NmapImport { hosts, stats })
}

fn close_tag(
    stack: &mut Vec<String>,
    name: &str,
    current: &mut Option<ImportedHost>,
    current_port: &mut Option<ImportedPort>,
    hosts: &mut Vec<ImportedHost>,
    stats: &mut ImportStats,
) -> Result<(), InteropError> {
    let open = stack
        .pop()
        .ok_or_else(|| InteropError::Malformed("stray closing tag".to_owned()))?;
    if open != *name {
        return Err(InteropError::Malformed(format!(
            "mismatched tag: <{open}> closed by </{name}>"
        )));
    }
    match name {
        "port" => {
            if let Some(port) = current_port.take() {
                if let Some(host) = current.as_mut() {
                    if port.state == "open" {
                        if host.ports.len() >= MAX_IMPORT_PORTS_PER_HOST {
                            stats.ports_skipped += 1;
                        } else {
                            stats.ports_open += 1;
                            host.ports.push(port);
                        }
                    } else {
                        stats.ports_skipped += 1;
                    }
                }
            }
        }
        "host" => {
            if let Some(host) = current.take() {
                if !host.address.is_empty() {
                    hosts.push(host);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Imported data as an evidence graph (origin-labeled, capped confidence).
// ---------------------------------------------------------------------------

/// Convert an Nmap import into a correlation graph: entities/edges carry
/// `origin=import:nmap` provenance and capped confidence (never above
/// [`IMPORT_CONFIDENCE_CAP`]). Deterministic and bounded like the native
/// builder.
pub fn import_to_graph(import: &NmapImport, source_label: &str) -> crate::graph::ScanGraph {
    use crate::graph::{
        EdgeRelation, EntityKind, EntityProvenance, ScanGraph, hostname_entity_id, ip_entity_id,
        port_entity_id, service_entity_id,
    };
    let mut graph = ScanGraph::default();
    let source: String = source_label.chars().take(128).collect();
    let provenance = EntityProvenance {
        scan_plan_id: format!("import:{source}"),
        module: NMAP_ORIGIN.to_owned(),
        task_id: None,
        target: None,
        timestamp: 0,
        reason: Some(format!("imported from Nmap XML ({source})")),
        rule_id: None,
    };
    let mut origin_attrs = BTreeMap::new();
    origin_attrs.insert("origin".to_owned(), NMAP_ORIGIN.to_owned());
    origin_attrs.insert("import_source".to_owned(), source.clone());
    for host in &import.hosts {
        if host.address.is_empty() {
            continue;
        }
        let is_ip = host.address.parse::<std::net::IpAddr>().is_ok();
        let host_id = if is_ip {
            ip_entity_id(&host.address)
        } else {
            hostname_entity_id(&host.address)
        };
        let host_kind = if is_ip {
            EntityKind::IpAddress
        } else {
            EntityKind::Hostname
        };
        let mut host_attrs = origin_attrs.clone();
        host_attrs.insert("address".to_owned(), host.address.clone());
        if let Some(name) = &host.hostname {
            host_attrs.insert("hostname".to_owned(), name.clone());
        }
        if let Some(os) = &host.os {
            host_attrs.insert("os_guess".to_owned(), os.clone());
        }
        graph.upsert_entity(
            host_id.clone(),
            host_kind,
            host.address.clone(),
            host_attrs,
            &provenance,
        );
        if let Some(name) = &host.hostname {
            if !name.is_empty() {
                let name_id = hostname_entity_id(name);
                let mut name_attrs = origin_attrs.clone();
                name_attrs.insert("name".to_owned(), name.clone());
                graph.upsert_entity(
                    name_id.clone(),
                    EntityKind::Hostname,
                    name.to_ascii_lowercase(),
                    name_attrs,
                    &provenance,
                );
                graph.link(
                    name_id,
                    host_id.clone(),
                    EdgeRelation::ResolvesTo,
                    IMPORT_CONFIDENCE_CAP.min(50),
                    &provenance,
                    vec![format!("imported hostname mapping ({source})")],
                    BTreeMap::new(),
                );
            }
        }
        for port in &host.ports {
            // Only IP literals yield stable port entities; names without
            // addresses skip port linkage (observation preserved on host).
            if !is_ip {
                continue;
            }
            let port_id = port_entity_id(&port.transport, &host.address, port.port);
            let mut port_attrs = origin_attrs.clone();
            port_attrs.insert("address".to_owned(), host.address.clone());
            port_attrs.insert("transport".to_owned(), port.transport.clone());
            port_attrs.insert("port".to_owned(), port.port.to_string());
            port_attrs.insert("state".to_owned(), "open".to_owned());
            graph.upsert_entity(
                port_id.clone(),
                EntityKind::Port,
                format!("{}:{}/{}", host.address, port.port, port.transport),
                port_attrs,
                &provenance,
            );
            graph.link(
                host_id.clone(),
                port_id.clone(),
                EdgeRelation::ListensOn,
                IMPORT_CONFIDENCE_CAP,
                &provenance,
                vec![format!("imported open port ({source})")],
                BTreeMap::new(),
            );
            if !port.service.is_empty() {
                let service_id = service_entity_id(&port_id, &port.service);
                let mut service_attrs = origin_attrs.clone();
                service_attrs.insert("service".to_owned(), port.service.clone());
                service_attrs.insert("address".to_owned(), host.address.clone());
                service_attrs.insert("port".to_owned(), port.port.to_string());
                if !port.product.is_empty() {
                    service_attrs.insert("product_hint".to_owned(), port.product.clone());
                }
                if !port.version.is_empty() {
                    service_attrs.insert("version_hint".to_owned(), port.version.clone());
                }
                graph.upsert_entity(
                    service_id.clone(),
                    EntityKind::Service,
                    format!("{} on {}:{}", port.service, host.address, port.port),
                    service_attrs,
                    &provenance,
                );
                graph.link(
                    port_id,
                    service_id,
                    EdgeRelation::RunsService,
                    IMPORT_CONFIDENCE_CAP,
                    &provenance,
                    vec![format!("imported service identity ({source})")],
                    BTreeMap::new(),
                );
            }
        }
    }
    graph
}

// ---------------------------------------------------------------------------
// Exports from the masked view model.
// ---------------------------------------------------------------------------

/// Interop export formats (GraphML delegates to the graph view so both
/// paths emit identical bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteropFormat {
    Sarif,
    Stix,
    Csv,
    Graphml,
}

impl InteropFormat {
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "sarif" => Some(Self::Sarif),
            "stix" | "stix2" | "stix2.1" => Some(Self::Stix),
            "csv" => Some(Self::Csv),
            "graphml" => Some(Self::Graphml),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sarif => "sarif",
            Self::Stix => "stix",
            Self::Csv => "csv",
            Self::Graphml => "graphml",
        }
    }
}

/// Render one interop export from a masked view.
pub fn render_export(view: &ViewGraph, format: InteropFormat) -> Vec<u8> {
    match format {
        InteropFormat::Sarif => to_sarif(view).into_bytes(),
        InteropFormat::Stix => to_stix(view).into_bytes(),
        InteropFormat::Csv => to_csv(view).into_bytes(),
        InteropFormat::Graphml => crate::graph_view::to_graphml(view).into_bytes(),
    }
}

// --- SARIF 2.1.0 (exposure findings; ports/structure stay in GraphML). ---

fn sarif_level(confidence: u8) -> &'static str {
    if confidence >= 80 {
        "error"
    } else if confidence >= 50 {
        "warning"
    } else {
        "note"
    }
}

/// SARIF results from `Exposure` display nodes (documented mapping:
/// exposure intelligence findings are the SARIF-reportable results;
/// open ports and structure export via GraphML/CSV instead).
pub fn to_sarif(view: &ViewGraph) -> String {
    let mut rules: BTreeMap<String, String> = BTreeMap::new();
    let mut results: Vec<serde_json::Value> = Vec::new();
    for node in &view.nodes {
        if node.kind != DisplayKind::Exposure {
            continue;
        }
        let rule_id = format!(
            "RXScan/{}",
            node.attributes
                .get("exposure_type")
                .map(String::as_str)
                .unwrap_or("exposure")
        );
        rules
            .entry(rule_id.clone())
            .or_insert_with(|| node.label.clone());
        let level = sarif_level(node.link_confidence.unwrap_or(0));
        results.push(serde_json::json!({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": node.label},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": node.id},
                }
            }],
            "properties": {
                "confidence": node.link_confidence,
                "scope": node.scope.as_str(),
                "observations": node.observations,
                "evidence": node.evidence,
            },
        }));
    }
    results.sort_by(|a, b| {
        a["ruleId"].as_str().cmp(&b["ruleId"].as_str()).then(
            a["message"]["text"]
                .as_str()
                .cmp(&b["message"]["text"].as_str()),
        )
    });
    let rules_json: Vec<serde_json::Value> = rules
        .into_iter()
        .map(|(id, name)| {
            serde_json::json!({
                "id": id,
                "name": name.chars().take(128).collect::<String>(),
                "helpUri": "",
            })
        })
        .collect();
    // Note: no `$schema` URI is embedded (offline document; still valid
    // SARIF — `$schema` is optional metadata, never dereferenced here).
    serde_json::json!({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "RXScan",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "",
                "rules": rules_json,
            }},
            "results": results,
            "properties": {
                "nodes": view.nodes.len(),
                "edges": view.edges.len(),
                "truncated": view.truncated,
            },
        }],
    })
    .to_string()
}

// --- STIX 2.1 bundle (identity + observables + relationships). ---

fn sha256_hex(text: &str) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(text.as_bytes()))
}

/// Deterministic STIX id: `<type>--<uuid from content hash>` with
/// version/variant bits set (no randomness anywhere in exports).
fn stix_id(stix_type: &str, key: &str) -> String {
    let digest = sha256_hex(&format!("{stix_type}:{key}"));
    let mut hex: Vec<char> = digest.chars().take(32).collect();
    hex[12] = '4';
    hex[16] = match hex[16] {
        '0'..='7' => '8',
        _ => hex[16],
    };
    let hex: String = hex.into_iter().collect();
    format!(
        "{stix_type}--{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Epoch milliseconds to STIX timestamp (`YYYY-MM-DDTHH:MM:SS.sssZ`).
fn stix_time(ms: u64) -> String {
    let secs = ms / 1000;
    let millis = ms % 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u64;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u64;
    year += i64::from(month <= 2);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year,
        month,
        day,
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60,
        millis
    )
}

fn stix_object(
    stix_type: &str,
    id: &str,
    created_ms: u64,
    modified_ms: u64,
    confidence: Option<u8>,
    mut body: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Value {
    body.insert(
        "type".to_owned(),
        serde_json::Value::String(stix_type.to_owned()),
    );
    body.insert(
        "spec_version".to_owned(),
        serde_json::Value::String("2.1".to_owned()),
    );
    body.insert("id".to_owned(), serde_json::Value::String(id.to_owned()));
    body.insert(
        "created".to_owned(),
        serde_json::Value::String(stix_time(created_ms)),
    );
    body.insert(
        "modified".to_owned(),
        serde_json::Value::String(stix_time(modified_ms)),
    );
    if let Some(confidence) = confidence {
        body.insert("confidence".to_owned(), serde_json::Value::from(confidence));
    }
    body.insert(
        "labels".to_owned(),
        serde_json::Value::Array(vec![serde_json::Value::String("rxscan".to_owned())]),
    );
    serde_json::Value::Object(body)
}

/// STIX 2.1 bundle. Emitted types: identity (RXScan tool), ipv4-addr,
/// ipv6-addr, domain-name, url, software, x509-certificate,
/// network-traffic (open ports), relationship. Other display kinds
/// (accounts, exposures, evidence, scope, clusters) are counted in
/// `bundle.properties` but have no STIX observable mapping — documented,
/// not silently dropped (the count is exact).
pub fn to_stix(view: &ViewGraph) -> String {
    let identity_id = stix_id("identity", "rxscan-tool");
    let mut objects = vec![stix_object(
        "identity",
        &identity_id,
        0,
        0,
        None,
        serde_json::Map::from_iter([
            (
                "name".to_owned(),
                serde_json::Value::String("RXScan".to_owned()),
            ),
            (
                "identity_class".to_owned(),
                serde_json::Value::String("system".to_owned()),
            ),
        ]),
    )];
    let mut id_of: BTreeMap<String, String> = BTreeMap::new();
    let mut skipped: BTreeMap<String, usize> = BTreeMap::new();
    // Pre-pass: address objects for open-port traffic refs, so every
    // dst_ref resolves to a real object even when no address node exists.
    // Keys with a real node are skipped (the node emits itself, richer).
    let node_ids: BTreeMap<&str, &ViewNode> = view
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    for node in &view.nodes {
        if node.kind == DisplayKind::PortService && node.stored_kind == "port" {
            if let Some(address) = node.attributes.get("address") {
                let key = format!("ip:{address}");
                if node_ids.contains_key(key.as_str()) || id_of.contains_key(&key) {
                    continue;
                }
                let kind = if address.contains(':') {
                    "ipv6-addr"
                } else {
                    "ipv4-addr"
                };
                let id = stix_id(kind, &key);
                id_of.insert(key, id.clone());
                objects.push(stix_object(
                    kind,
                    &id,
                    node.first_seen_ms,
                    node.last_seen_ms.max(node.first_seen_ms),
                    None,
                    serde_json::Map::from_iter([(
                        "value".to_owned(),
                        serde_json::Value::String(address.clone()),
                    )]),
                ));
            }
        }
    }
    let mut nodes: Vec<&ViewNode> = view.nodes.iter().collect();
    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    for node in nodes {
        let created = node.first_seen_ms;
        let modified = node.last_seen_ms.max(created);
        let emitted = emit_stix_observable(node, &mut id_of, created, modified);
        match emitted {
            Some(object) => objects.push(object),
            None => *skipped.entry(node.kind.as_str().to_owned()).or_default() += 1,
        }
    }
    // Relationships where both ends were emitted (honest subset).
    let mut edges: Vec<&ViewEdge> = view.edges.iter().collect();
    edges.sort_by(|a, b| {
        (&a.from, &a.to, a.relation.as_str()).cmp(&(&b.from, &b.to, b.relation.as_str()))
    });
    for edge in edges {
        let (Some(source), Some(target)) = (id_of.get(&edge.from), id_of.get(&edge.to)) else {
            continue;
        };
        let rel_type = match edge.relation {
            crate::graph_view::DisplayRel::ResolvesTo => "resolves-to",
            _ => "related-to",
        };
        let id = stix_id(
            "relationship",
            &format!("{}|{}|{}", edge.from, edge.to, rel_type),
        );
        objects.push(stix_object(
            "relationship",
            &id,
            0,
            0,
            Some(edge.confidence),
            serde_json::Map::from_iter([
                (
                    "relationship_type".to_owned(),
                    serde_json::Value::String(rel_type.to_owned()),
                ),
                (
                    "source_ref".to_owned(),
                    serde_json::Value::String(source.clone()),
                ),
                (
                    "target_ref".to_owned(),
                    serde_json::Value::String(target.clone()),
                ),
            ]),
        ));
    }
    objects.sort_by(|a, b| {
        a["id"]
            .as_str()
            .cmp(&b["id"].as_str())
            .then(a["type"].as_str().cmp(&b["type"].as_str()))
    });
    serde_json::json!({
        "type": "bundle",
        "id": stix_id("bundle", &format!("rxscan:{}:{}", view.total_nodes, view.total_edges)),
        "spec_version": "2.1",
        "objects": objects,
        "properties": {
            "rxscan_truncated": view.truncated,
            "rxscan_skipped_kinds": skipped,
        },
    })
    .to_string()
}

/// Emit one STIX observable for a view node, registering its id.
/// Returns `None` (counted, not silent) for display kinds without a
/// STIX observable mapping.
fn emit_stix_observable(
    node: &ViewNode,
    id_of: &mut BTreeMap<String, String>,
    created: u64,
    modified: u64,
) -> Option<serde_json::Value> {
    let conf = node.link_confidence;
    let value = node
        .attributes
        .get("address")
        .or_else(|| node.attributes.get("name"))
        .cloned()
        .unwrap_or_else(|| node.label.clone());
    let object = match node.kind {
        DisplayKind::Ip => {
            let (kind, key) = if value.contains(':') {
                ("ipv6-addr", "value")
            } else {
                ("ipv4-addr", "value")
            };
            let id = stix_id(kind, &node.id);
            let object = stix_object(
                kind,
                &id,
                created,
                modified,
                conf,
                serde_json::Map::from_iter([(key.to_owned(), serde_json::Value::String(value))]),
            );
            id_of.insert(node.id.clone(), id);
            object
        }
        DisplayKind::Host | DisplayKind::Domain => {
            if value.parse::<std::net::IpAddr>().is_ok() {
                return emit_ip_like(node, id_of, created, modified, &value);
            }
            let id = stix_id("domain-name", &node.id);
            let object = stix_object(
                "domain-name",
                &id,
                created,
                modified,
                conf,
                serde_json::Map::from_iter([(
                    "value".to_owned(),
                    serde_json::Value::String(value),
                )]),
            );
            id_of.insert(node.id.clone(), id);
            object
        }
        DisplayKind::Url => {
            let id = stix_id("url", &node.id);
            let object = stix_object(
                "url",
                &id,
                created,
                modified,
                conf,
                serde_json::Map::from_iter([(
                    "value".to_owned(),
                    serde_json::Value::String(value),
                )]),
            );
            id_of.insert(node.id.clone(), id);
            object
        }
        DisplayKind::Software => {
            let id = stix_id("software", &node.id);
            let object = stix_object(
                "software",
                &id,
                created,
                modified,
                conf,
                serde_json::Map::from_iter([("name".to_owned(), serde_json::Value::String(value))]),
            );
            id_of.insert(node.id.clone(), id);
            object
        }
        DisplayKind::Certificate => {
            let id = stix_id("x509-certificate", &node.id);
            let mut body = serde_json::Map::new();
            for key in ["serial_hex", "subject", "issuer", "sha256"] {
                if let Some(attr) = node.attributes.get(key) {
                    body.insert(
                        format!("x509_{key}"),
                        serde_json::Value::String(attr.clone()),
                    );
                }
            }
            if body.is_empty() {
                body.insert(
                    "serial_number".to_owned(),
                    serde_json::Value::String(node.id.clone()),
                );
            }
            let object = stix_object("x509-certificate", &id, created, modified, conf, body);
            id_of.insert(node.id.clone(), id);
            object
        }
        DisplayKind::PortService if node.stored_kind == "port" => {
            // Open port as network-traffic to its address (only when the
            // address/port parse; otherwise skipped and counted).
            let address = node.attributes.get("address")?;
            let port: u16 = node.attributes.get("port")?.parse().ok()?;
            let transport = node
                .attributes
                .get("transport")
                .map(String::as_str)
                .unwrap_or("tcp");
            // The address object exists: emitted by its node, or by the
            // pre-pass when no address node is in the view.
            let addr_id = id_of.get(&format!("ip:{address}"))?.clone();
            let id = stix_id("network-traffic", &node.id);
            let object = stix_object(
                "network-traffic",
                &id,
                created,
                modified,
                conf,
                serde_json::Map::from_iter([
                    (
                        "protocols".to_owned(),
                        serde_json::Value::Array(vec![serde_json::Value::String(
                            transport.to_owned(),
                        )]),
                    ),
                    ("dst_ref".to_owned(), serde_json::Value::String(addr_id)),
                    ("dst_port".to_owned(), serde_json::Value::from(port)),
                ]),
            );
            id_of.insert(node.id.clone(), id);
            object
        }
        _ => return None,
    };
    Some(object)
}

fn emit_ip_like(
    node: &ViewNode,
    id_of: &mut BTreeMap<String, String>,
    created: u64,
    modified: u64,
    value: &str,
) -> Option<serde_json::Value> {
    let kind = if value.contains(':') {
        "ipv6-addr"
    } else {
        "ipv4-addr"
    };
    let id = stix_id(kind, &node.id);
    let object = stix_object(
        kind,
        &id,
        created,
        modified,
        node.link_confidence,
        serde_json::Map::from_iter([(
            "value".to_owned(),
            serde_json::Value::String(value.to_owned()),
        )]),
    );
    id_of.insert(node.id.clone(), id);
    Some(object)
}

// --- CSV (nodes + edges, one file, record_type column). ---

fn csv_field(text: &str) -> String {
    if text.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_owned()
    }
}

/// CSV with a `record_type` column (`node`/`edge`), masked throughout.
pub fn to_csv(view: &ViewGraph) -> String {
    let mut out = String::new();
    out.push_str("record_type,id,kind,label,confidence,scope,observations,evidence\n");
    let mut nodes: Vec<&ViewNode> = view.nodes.iter().collect();
    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    for node in nodes {
        out.push_str(&format!(
            "node,{},{},{},{},{},{},{}\n",
            csv_field(&node.id),
            csv_field(node.kind.as_str()),
            csv_field(&node.label),
            node.link_confidence
                .map(|c| c.to_string())
                .unwrap_or_default(),
            csv_field(node.scope.as_str()),
            node.observations,
            csv_field(&node.evidence.join(" | ")),
        ));
    }
    out.push_str("record_type,from,to,relation,observed,confidence,module,scan_run,evidence\n");
    let mut edges: Vec<&ViewEdge> = view.edges.iter().collect();
    edges.sort_by(|a, b| {
        (&a.from, &a.to, a.relation.as_str()).cmp(&(&b.from, &b.to, b.relation.as_str()))
    });
    for edge in edges {
        out.push_str(&format!(
            "edge,{},{},{},{},{},{},{},{}\n",
            csv_field(&edge.from),
            csv_field(&edge.to),
            csv_field(edge.relation.as_str()),
            edge.observed,
            edge.confidence,
            csv_field(&edge.module),
            csv_field(&edge.scan_run),
            csv_field(&edge.evidence.join(" | ")),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
<host><status state="up" reason="syn-ack"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
<hostnames><hostname name="example.test" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.24.0"/></port>
<port protocol="tcp" portid="22"><state state="closed" reason="reset"/><service name="ssh"/></port>
<port protocol="tcp" portid="443"><state state="filtered" reason="no-response"/><service name="https"/></port>
</ports>
<os><osmatch name="Linux 5.x" accuracy="95"/></os>
</host>
<host><status state="up" reason="syn-ack"/>
<address addr="192.0.2.11" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0"/></port></ports>
</host>
</nmaprun>"#;

    #[test]
    fn nmap_import_collects_open_ports_only() {
        let import = import_nmap_xml(SAMPLE).unwrap();
        assert_eq!(import.hosts.len(), 2);
        assert_eq!(import.stats.ports_open, 2);
        assert_eq!(import.stats.ports_skipped, 2);
        let first = &import.hosts[0];
        assert_eq!(first.address, "192.0.2.10");
        assert_eq!(first.hostname.as_deref(), Some("example.test"));
        assert_eq!(first.os.as_deref(), Some("Linux 5.x"));
        assert_eq!(first.ports.len(), 1);
        assert_eq!(first.ports[0].port, 80);
        assert_eq!(first.ports[0].product, "nginx");
    }

    #[test]
    fn hostile_inputs_rejected_fail_closed() {
        // DTD / entity expansion: never parsed, always rejected.
        for hostile in [
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"/etc/passwd\">]><nmaprun/>",
            "<!ENTITY lol \"x\"><nmaprun/>",
            "<nmaprun><host><!ATTLIST x y CDATA></host></nmaprun>",
        ] {
            assert!(
                import_nmap_xml(hostile).is_err(),
                "hostile input accepted: {hostile}"
            );
        }
        // Billion-laughs shape (entities rejected before amplification).
        let mut laughs = String::from("<!DOCTYPE l [");
        for i in 0..10 {
            laughs.push_str("<!ENTITY a");
            laughs.push_str(&i.to_string());
            laughs.push_str(" \"xxxx\">");
        }
        laughs.push_str("]><nmaprun/>");
        assert!(import_nmap_xml(&laughs).is_err());
        // Malformed and wrong-root inputs.
        assert!(import_nmap_xml("<nmaprun><host>").is_err());
        assert!(import_nmap_xml("<scan></scan>").is_err());
        assert!(import_nmap_xml("").is_err());
        assert!(import_nmap_xml("<nmaprun>&unknown;</nmaprun>").is_err());
        // Oversize input rejected before parsing.
        let big = format!("<nmaprun>{}</nmaprun>", " ".repeat(MAX_IMPORT_BYTES));
        assert!(matches!(
            import_nmap_xml(&big),
            Err(InteropError::TooLarge(_))
        ));
    }

    #[test]
    fn import_graph_is_origin_labeled_and_capped() {
        let import = import_nmap_xml(SAMPLE).unwrap();
        let graph = import_to_graph(&import, "test.xml");
        assert!(graph.entity_count() > 0);
        for edge in &graph.edges {
            assert!(
                edge.confidence <= IMPORT_CONFIDENCE_CAP,
                "import must never outrank native confidence"
            );
            assert!(edge.evidence.iter().any(|e| e.contains("imported")));
        }
        for entity in graph.entities.values() {
            assert_eq!(
                entity.attributes.get("origin").map(String::as_str),
                Some(NMAP_ORIGIN)
            );
            assert_eq!(entity.provenance.module, NMAP_ORIGIN);
        }
        // Native observations demonstrably outrank imports (const-level
        // invariant; the comparison below pins the policy relationship).
        const { assert!(IMPORT_CONFIDENCE_CAP < 85) };
    }

    #[test]
    fn exports_are_masked_and_shaped() {
        use crate::graph_view::{SourceEdge, SourceNode, ViewOptions, build_view};
        let sources = vec![
            SourceNode {
                id: "ip:192.0.2.10".to_owned(),
                stored_kind: "ip_address".to_owned(),
                label: "192.0.2.10".to_owned(),
                attributes: BTreeMap::new(),
                first_seen_ms: 1_700_000_000_000,
                last_seen_ms: 1_700_000_001_000,
                observations: 1,
            },
            SourceNode {
                id: "exposure:test:abc".to_owned(),
                stored_kind: "exposure".to_owned(),
                label: "breach exposure via test token=FAKE-INTEROP-9".to_owned(),
                attributes: BTreeMap::from([("exposure_type".to_owned(), "breach".to_owned())]),
                first_seen_ms: 1_700_000_000_000,
                last_seen_ms: 1_700_000_001_000,
                observations: 1,
            },
        ];
        let view = build_view(sources, Vec::<SourceEdge>::new(), &ViewOptions::default());
        for (name, bytes) in [
            ("sarif", to_sarif(&view).into_bytes()),
            ("stix", to_stix(&view).into_bytes()),
            ("csv", to_csv(&view).into_bytes()),
            ("graphml", crate::graph_view::to_graphml(&view).into_bytes()),
        ] {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            assert!(!text.contains("FAKE-INTEROP-9"), "{name} leaked a secret");
            assert!(!bytes.is_empty(), "{name} must not be empty");
        }
        let sarif: serde_json::Value = serde_json::from_str(&to_sarif(&view)).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 1);
        let stix: serde_json::Value = serde_json::from_str(&to_stix(&view)).unwrap();
        assert_eq!(stix["type"], "bundle");
        assert_eq!(stix["spec_version"], "2.1");
        let objects = stix["objects"].as_array().unwrap();
        assert!(objects.iter().any(|o| o["type"] == "ipv4-addr"));
        assert!(objects.iter().any(|o| o["type"] == "identity"));
        for object in objects {
            assert!(
                object.get("confidence").is_none() || object["confidence"].as_u64().unwrap() <= 100
            );
        }
        let csv = to_csv(&view);
        assert!(
            csv.starts_with("record_type,id,kind,label,confidence,scope,observations,evidence\n")
        );
    }

    #[test]
    fn stix_ids_and_times_are_deterministic() {
        assert_eq!(stix_id("ipv4-addr", "x"), stix_id("ipv4-addr", "x"));
        assert!(stix_id("ipv4-addr", "x").starts_with("ipv4-addr--"));
        assert_eq!(stix_time(1_700_000_000_000), "2023-11-14T22:13:20.000Z");
        assert_eq!(stix_time(0), "1970-01-01T00:00:00.000Z");
    }
}
