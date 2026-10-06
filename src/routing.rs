//! Bounded ASN / routing intelligence (timestamped, never current-only).
//!
//! Represents `IP -> prefix`, `prefix -> ASN`, `ASN -> organization` plus
//! timestamped route observations with RPKI state. Routing state changes
//! over time: historical observations keep their timestamps and are never
//! presented as permanently current. Allocation (`IP allocated to org`)
//! stays distinct from operation (`service operated by org`).

use std::collections::BTreeMap;

/// RPKI validation state (bounded vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpkiState {
    Valid,
    Invalid,
    Unknown,
    NotChecked,
}

impl RpkiState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Unknown => "unknown",
            Self::NotChecked => "not_checked",
        }
    }

    pub fn parse(text: &str) -> Self {
        match text.trim().to_ascii_lowercase().as_str() {
            "valid" => Self::Valid,
            "invalid" => Self::Invalid,
            "unknown" => Self::Unknown,
            _ => Self::NotChecked,
        }
    }
}

/// One timestamped route observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteObservation {
    pub prefix: String,
    pub asn: String,
    pub rpki: RpkiState,
    pub observed_at: Option<String>,
    pub retrieved_at: u64,
    pub source: String,
}

fn bounded_str(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty() && s.len() <= 128)
}

/// Parse a routing provider response into observations.
/// Accepts `{observations: [{prefix, asn, rpki, observed_at}]}` or a single
/// object. Malformed entries skipped; never error on partial data.
pub fn parse_routing_response(
    value: &serde_json::Value,
    retrieved_at: u64,
) -> Vec<RouteObservation> {
    let items: Vec<&serde_json::Value> = match value.as_array() {
        Some(arr) => arr.iter().take(64).collect(),
        None => match value.get("observations").and_then(|v| v.as_array()) {
            Some(arr) => arr.iter().take(64).collect(),
            None => vec![value],
        },
    };
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for item in items.into_iter().take(64) {
        let prefix = match bounded_str(item, "prefix") {
            Some(p) => p.to_ascii_lowercase(),
            None => continue,
        };
        // Prefix must parse as IpNet with host bits zero (no
        // `192.0.2.1/24` fabrications).
        let Ok(net) = prefix.parse::<ipnet::IpNet>() else {
            continue;
        };
        let canonical_host_zero = match net {
            ipnet::IpNet::V4(v4) => v4.addr() == v4.network(),
            ipnet::IpNet::V6(v6) => v6.addr() == v6.network(),
        };
        if !canonical_host_zero {
            continue;
        }
        let asn_raw = match bounded_str(item, "asn") {
            Some(a) => a,
            None => continue,
        };
        let Some(asn) = crate::search::canonical_asn_value(&asn_raw) else {
            continue;
        };
        let rpki = item
            .get("rpki")
            .and_then(|v| v.as_str())
            .map(RpkiState::parse)
            .unwrap_or(RpkiState::NotChecked);
        let observed_at =
            bounded_str(item, "observed_at").or_else(|| bounded_str(item, "observedAt"));
        let source = bounded_str(item, "source").unwrap_or_else(|| "passive".to_owned());
        if !seen.insert((prefix.clone(), asn.clone())) {
            continue;
        }
        out.push(RouteObservation {
            prefix,
            asn,
            rpki,
            observed_at,
            retrieved_at,
            source,
        });
        if out.len() >= 32 {
            break;
        }
    }
    out.sort_by(|a, b| a.prefix.cmp(&b.prefix).then(a.asn.cmp(&b.asn)));
    out
}

/// Attributes for a route relationship (timestamped, RPKI-carrying).
pub fn route_attributes(obs: &RouteObservation) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::from([
        ("prefix".to_owned(), obs.prefix.clone()),
        ("asn".to_owned(), obs.asn.clone()),
        ("rpki".to_owned(), obs.rpki.as_str().to_owned()),
        ("retrieved_at".to_owned(), obs.retrieved_at.to_string()),
        ("source".to_owned(), obs.source.clone()),
    ]);
    if let Some(when) = obs.observed_at.clone() {
        attrs.insert("observed_at".to_owned(), when);
    }
    attrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_asn_org_chain_parses() {
        let value = serde_json::json!({
            "observations": [
                {"prefix": "192.0.2.0/24", "asn": "AS64500", "rpki": "valid",
                 "observed_at": "2024-01-01T00:00:00Z", "source": "fixture"},
                {"prefix": "192.0.2.0/24", "asn": "AS64500", "rpki": "valid",
                 "observed_at": "2024-01-01T00:00:00Z", "source": "fixture"}
            ]
        });
        let obs = parse_routing_response(&value, 1_700_000_000);
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].rpki, RpkiState::Valid);
        assert_eq!(obs[0].observed_at.as_deref(), Some("2024-01-01T00:00:00Z"));
    }

    #[test]
    fn noncanonical_prefix_and_bad_asn_skipped() {
        let value = serde_json::json!([
            {"prefix": "192.0.2.1/24", "asn": "AS64500"},
            {"prefix": "192.0.2.0/24", "asn": "AS0"}
        ]);
        assert!(parse_routing_response(&value, 0).is_empty());
    }
}
