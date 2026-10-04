use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::model::EventKind;
use crate::persistence::{PersistenceError, load_checkpoint};

pub const DEFAULT_UNKNOWN_LIMIT: usize = 100;
pub const MAX_UNKNOWN_LIMIT: usize = 1000;
pub const MAX_UNKNOWN_SAMPLE_CHARS: usize = 160;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownServiceRecord {
    pub endpoint: String,
    pub transport: String,
    pub banner_hash: String,
    pub sample: String,
    pub truncated_sample: bool,
    pub protocol_hints: Vec<String>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownExport {
    pub records: Vec<UnknownServiceRecord>,
    pub returned: usize,
    pub total_before_cap: usize,
    pub limit: usize,
    pub truncated: bool,
}

fn sanitize_sample(banner: &str) -> (String, bool) {
    let lossy: String = banner
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect();
    let mut end = lossy.len().min(MAX_UNKNOWN_SAMPLE_CHARS);
    while end > 0 && !lossy.is_char_boundary(end) {
        end -= 1;
    }
    (lossy[..end].to_owned(), lossy.len() > end)
}

pub fn export_unknown(
    checkpoint_path: &Path,
    limit: usize,
) -> Result<UnknownExport, PersistenceError> {
    let limit = limit.clamp(1, MAX_UNKNOWN_LIMIT);
    let loaded = load_checkpoint(checkpoint_path)?;
    let mut by_endpoint: BTreeMap<String, UnknownServiceRecord> = BTreeMap::new();
    let mut hints: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for output in &loaded.state.outputs {
        for event in &output.output.events {
            if event.kind == EventKind::FingerprintCandidateObserved {
                let data = &event.details.data;
                let asset = event
                    .asset_id
                    .as_ref()
                    .map(|id| id.0.clone())
                    .unwrap_or_default();
                if asset.is_empty() {
                    continue;
                }
                if let Some(product) = data.get("product").and_then(|v| v.as_str()) {
                    if !product.is_empty() {
                        hints.entry(asset).or_default().push(product.to_owned());
                    }
                }
            }
        }
    }
    for output in &loaded.state.outputs {
        for event in &output.output.events {
            if event.kind != EventKind::BannerObserved {
                continue;
            }
            let data = &event.details.data;
            if data.get("protocol").and_then(|v| v.as_str()) != Some("unknown") {
                continue;
            }
            let address = data.get("address").and_then(|v| v.as_str()).unwrap_or("");
            let port = data.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
            if address.is_empty() || port == 0 {
                continue;
            }
            let endpoint = format!("{address}:{port}");
            let banner = data.get("banner").and_then(|v| v.as_str()).unwrap_or("");
            if banner.is_empty() {
                continue;
            }
            let fingerprint = crate::service::UnknownFingerprint::compute(
                banner.as_bytes(),
                false,
                "banner",
                banner.len() > MAX_UNKNOWN_SAMPLE_CHARS,
            )
            .map(|fp| fp.hash16)
            .unwrap_or_default();
            let (sample, truncated_sample) = sanitize_sample(banner);
            let asset_id = event
                .asset_id
                .as_ref()
                .map(|id| id.0.clone())
                .unwrap_or_default();
            let mut protocol_hints = hints.get(&asset_id).cloned().unwrap_or_default();
            protocol_hints.sort();
            protocol_hints.dedup();
            protocol_hints.truncate(4);
            let mut evidence_ids = vec![asset_id];
            evidence_ids.retain(|id| !id.is_empty());
            by_endpoint
                .entry(endpoint.clone())
                .and_modify(|record| {
                    if !record
                        .protocol_hints
                        .iter()
                        .any(|h| protocol_hints.contains(h))
                    {
                        record.protocol_hints.extend(protocol_hints.clone());
                        record.protocol_hints.sort();
                        record.protocol_hints.dedup();
                        record.protocol_hints.truncate(4);
                    }
                    for id in &evidence_ids {
                        if !record.evidence_ids.contains(id) {
                            record.evidence_ids.push(id.clone());
                        }
                    }
                })
                .or_insert(UnknownServiceRecord {
                    endpoint,
                    transport: "tcp".to_owned(),
                    banner_hash: fingerprint,
                    sample,
                    truncated_sample,
                    protocol_hints,
                    evidence_ids,
                });
        }
    }
    let total_before_cap = by_endpoint.len();
    let mut records: Vec<UnknownServiceRecord> = by_endpoint.into_values().collect();
    let truncated = records.len() > limit;
    records.truncate(limit);
    Ok(UnknownExport {
        returned: records.len(),
        total_before_cap,
        limit,
        truncated,
        records,
    })
}

pub fn render_human(export: &UnknownExport) -> String {
    let mut out = format!(
        "unknown services total={} emitted={} truncated={} network_requests=0\n",
        export.total_before_cap, export.returned, export.truncated
    );
    for record in &export.records {
        out.push_str(&format!(
            "- {} ({}) hash={} hints=[{}]\n  sample: {}\n",
            record.endpoint,
            record.transport,
            record.banner_hash,
            record.protocol_hints.join(", "),
            record.sample.lines().next().unwrap_or(""),
        ));
    }
    out.push_str("Unknown evidence stays local; nothing is uploaded.\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_is_bounded_and_char_safe() {
        let (sample, truncated) = sanitize_sample(&"A".repeat(500));
        assert!(sample.len() <= MAX_UNKNOWN_SAMPLE_CHARS);
        assert!(truncated);
        let (sample, truncated) = sanitize_sample("short");
        assert_eq!(sample, "short");
        assert!(!truncated);
    }

    #[test]
    fn control_characters_stripped() {
        let (sample, _) = sanitize_sample("ab\x00\x07cd");
        assert_eq!(sample, "abcd");
    }

    #[test]
    fn export_missing_file_errors() {
        assert!(export_unknown(Path::new("/nonexistent/rxscan-unknown-test.rxscan"), 10).is_err());
    }
}
