//! Run-to-run project diff for the GUI timeline (Phase 3).
//!
//! Compares two scans (`old`, `new`) inside one project database using
//! stored per-scan observations plus the new scan's coverage snapshot:
//!
//! * in new, not old → `Added` (green);
//! * in both, fingerprint differs → `Changed` (amber);
//! * in old, not new, and the new scan demonstrably covered the entity
//!   (host attempted, port attempted, name queried — and the run was not
//!   truncated) → `Removed` (red, confirmed);
//! * in old, not new, without that coverage → `NotCovered` (gray).
//!
//! A coverage gap is NEVER reported as a removal: absence without
//! coverage is inconclusive, full stop. This mirrors the checkpoint
//! `diff.rs` taxonomy (`InconclusiveMissing`) at the stored-observation
//! layer. Read-only, bounded, deterministic, secret-masked.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::project_db::{CoverageSnapshot, ObservationRow, ProjectDb};

/// Maximum diff rows returned (bounded output).
pub const MAX_DIFF_ROWS: usize = 2000;

/// Per-entity run-to-run status. `NotCovered` is visually gray and must
/// never be rendered as `Removed` (red) by any consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffStatus {
    Added,
    Removed,
    Changed,
    NotCovered,
    Unchanged,
}

impl DiffStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Changed => "changed",
            Self::NotCovered => "not_covered",
            Self::Unchanged => "unchanged",
        }
    }

    /// GUI color token (paired with a text label everywhere; never alone).
    pub fn color_token(self) -> &'static str {
        match self {
            Self::Added => "var(--ok)",
            Self::Removed => "var(--bad)",
            Self::Changed => "var(--warn)",
            Self::NotCovered => "var(--neutral)",
            Self::Unchanged => "var(--muted)",
        }
    }
}

/// One entity's run-to-run verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntityDiff {
    pub entity_id: String,
    pub kind: String,
    pub label: String,
    pub status: DiffStatus,
    pub detail: String,
}

/// Diff counts (rows carry only non-unchanged entities; counts are exact).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffSummary {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    pub not_covered: usize,
    pub unchanged: usize,
}

/// Bounded run-to-run diff result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDiff {
    pub old_scan: String,
    pub new_scan: String,
    pub rows: Vec<EntityDiff>,
    pub summary: DiffSummary,
    pub truncated: bool,
}

/// Compare two scans in one project database. `limit` caps rows
/// (1..=`MAX_DIFF_ROWS`); counts stay exact regardless.
pub fn diff_scans(
    db: &ProjectDb,
    old_scan: &str,
    new_scan: &str,
    limit: usize,
) -> Result<ScanDiff, String> {
    let limit = limit.clamp(1, MAX_DIFF_ROWS);
    let old_rows = db
        .observations_for_scan(old_scan, MAX_DIFF_ROWS * 4)
        .map_err(|error| error.to_string())?;
    if old_rows.is_empty()
        && db
            .scan_ids()
            .map_err(|error| error.to_string())?
            .iter()
            .all(|id| id != old_scan)
    {
        return Err(format!("unknown scan: {old_scan}"));
    }
    let new_rows = db
        .observations_for_scan(new_scan, MAX_DIFF_ROWS * 4)
        .map_err(|error| error.to_string())?;
    if new_rows.is_empty()
        && db
            .scan_ids()
            .map_err(|error| error.to_string())?
            .iter()
            .all(|id| id != new_scan)
    {
        return Err(format!("unknown scan: {new_scan}"));
    }
    let coverage = db
        .coverage_of(new_scan)
        .map_err(|error| error.to_string())?;
    let mut old_map: BTreeMap<String, &ObservationRow> = BTreeMap::new();
    for row in &old_rows {
        old_map.entry(row.entity_id.clone()).or_insert(row);
    }
    let mut new_map: BTreeMap<String, &ObservationRow> = BTreeMap::new();
    for row in &new_rows {
        new_map.entry(row.entity_id.clone()).or_insert(row);
    }
    let mut ids = BTreeSet::new();
    ids.extend(old_map.keys().cloned());
    ids.extend(new_map.keys().cloned());
    let mut summary = DiffSummary::default();
    let mut rows = Vec::new();
    for id in ids {
        let status = classify(old_map.get(&id), new_map.get(&id), &coverage);
        match status {
            DiffStatus::Unchanged => summary.unchanged += 1,
            DiffStatus::Added => {
                summary.added += 1;
                push_row(
                    &mut rows,
                    limit,
                    &id,
                    new_map[&id],
                    status,
                    "observed in the new run only",
                );
            }
            DiffStatus::Removed => {
                summary.removed += 1;
                push_row(
                    &mut rows,
                    limit,
                    &id,
                    old_map[&id],
                    status,
                    "covered by the new run, no longer observed",
                );
            }
            DiffStatus::Changed => {
                summary.changed += 1;
                push_row(
                    &mut rows,
                    limit,
                    &id,
                    new_map[&id],
                    status,
                    "observed in both runs with different label, attributes, or confidence",
                );
            }
            DiffStatus::NotCovered => {
                summary.not_covered += 1;
                push_row(
                    &mut rows,
                    limit,
                    &id,
                    old_map[&id],
                    status,
                    "not observed in the new run without comparable coverage — inconclusive, not a removal",
                );
            }
        }
    }
    let changed_total = summary.added + summary.removed + summary.changed + summary.not_covered;
    Ok(ScanDiff {
        old_scan: old_scan.to_owned(),
        new_scan: new_scan.to_owned(),
        rows,
        summary,
        truncated: changed_total > limit,
    })
}

fn push_row(
    rows: &mut Vec<EntityDiff>,
    limit: usize,
    id: &str,
    row: &ObservationRow,
    status: DiffStatus,
    detail: &str,
) {
    if rows.len() >= limit {
        return;
    }
    rows.push(EntityDiff {
        entity_id: crate::exposure::scrub_text(id),
        kind: row.kind.clone(),
        label: crate::exposure::scrub_text(&row.label),
        status,
        detail: detail.to_owned(),
    });
}

fn fingerprint(row: &ObservationRow) -> String {
    format!("{}|{}|{}", row.label, row.attrs_json, row.confidence)
}

fn classify(
    old: Option<&&ObservationRow>,
    new: Option<&&ObservationRow>,
    coverage: &CoverageSnapshot,
) -> DiffStatus {
    match (old, new) {
        (None, Some(_)) => DiffStatus::Added,
        (Some(_), None) => {
            // Absence is a confirmed removal only with demonstrable
            // coverage; otherwise it is inconclusive (never a removal).
            let covered = old.is_some_and(|row| {
                !coverage.truncated && covered_entity(&row.entity_id, &row.kind, coverage)
            });
            if covered {
                DiffStatus::Removed
            } else {
                DiffStatus::NotCovered
            }
        }
        (Some(old), Some(new)) if fingerprint(old) == fingerprint(new) => DiffStatus::Unchanged,
        (Some(_), Some(_)) => DiffStatus::Changed,
        (None, None) => DiffStatus::Unchanged,
    }
}

/// True when the new scan demonstrably covered this entity: the
/// producing observation could not have been missed by a complete run.
fn covered_entity(entity_id: &str, kind: &str, coverage: &CoverageSnapshot) -> bool {
    match kind {
        "port" => port_covered(entity_id, coverage),
        "service" => {
            // `service:<port-id>:<label>`: coverage follows the socket.
            entity_id
                .strip_prefix("service:")
                .and_then(|rest| rest.rsplit_once(':').map(|(port, _)| port))
                .is_some_and(|port_id| port_covered(port_id, coverage))
        }
        "ip_address" | "host" => coverage
            .hosts_attempted
            .iter()
            .any(|host| entity_id == format!("ip:{host}") || entity_id == format!("host:{host}")),
        "hostname" | "domain" | "dns_record" => {
            let name = entity_id
                .split(':')
                .nth(1)
                .unwrap_or("")
                .trim_end_matches('.')
                .to_ascii_lowercase();
            !name.is_empty()
                && coverage.dns_queried.iter().any(|queried| {
                    queried
                        .trim_end_matches('.')
                        .eq_ignore_ascii_case(name.trim_end_matches('.'))
                })
        }
        "web_endpoint" => {
            let url = entity_id.strip_prefix("endpoint:").unwrap_or("");
            if let Some(host) = url_host(url) {
                if host.parse::<std::net::IpAddr>().is_ok() {
                    coverage
                        .hosts_attempted
                        .iter()
                        .any(|attempted| attempted == &host)
                } else {
                    coverage.dns_queried.iter().any(|queried| {
                        queried
                            .trim_end_matches('.')
                            .eq_ignore_ascii_case(host.trim_end_matches('.'))
                    })
                }
            } else {
                false
            }
        }
        _ => false,
    }
}

/// `port:<transport>:<ip>:<port>` covered by attempted intervals.
/// IPv6 literal ids keep their colons (the port is the last segment).
fn port_covered(port_id: &str, coverage: &CoverageSnapshot) -> bool {
    let rest = match port_id.strip_prefix("port:") {
        Some(rest) => rest,
        None => return false,
    };
    let (transport, rest) = match rest.split_once(':') {
        Some(pair) => pair,
        None => return false,
    };
    // IPv6 addresses contain colons; the port is the last segment.
    let (ip, port) = match rest.rsplit_once(':') {
        Some(pair) => pair,
        None => return false,
    };
    let Ok(port) = port.parse::<u16>() else {
        return false;
    };
    let map = if transport.eq_ignore_ascii_case("udp") {
        &coverage.udp_attempted
    } else {
        &coverage.tcp_attempted
    };
    map.get(ip).is_some_and(|ranges| {
        ranges
            .iter()
            .any(|(start, end)| *start <= port && port <= *end)
    })
}

/// Lowercase host of an `http(s)://host[:port]/...` URL (no parsing
/// library needed for this narrow shape; `None` when unrecognized).
fn url_host(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    let host_port = after_scheme.split('/').next()?;
    let host = host_port.split('@').next_back()?;
    let host = host.split(':').next().unwrap_or(host);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_serialize_stably() {
        assert_eq!(DiffStatus::NotCovered.as_str(), "not_covered");
        let json = serde_json::to_string(&DiffStatus::NotCovered).unwrap();
        assert_eq!(json, "\"not_covered\"");
    }

    #[test]
    fn port_coverage_parses_ids() {
        let coverage = CoverageSnapshot {
            hosts_attempted: vec!["192.0.2.10".to_owned()],
            tcp_attempted: std::collections::BTreeMap::from([(
                "192.0.2.10".to_owned(),
                vec![(1, 1000)],
            )]),
            ..CoverageSnapshot::default()
        };
        assert!(port_covered("port:tcp:192.0.2.10:80", &coverage));
        assert!(!port_covered("port:tcp:192.0.2.10:8080", &coverage));
        assert!(!port_covered("port:tcp:192.0.2.11:80", &coverage));
        assert!(!port_covered("garbage", &coverage));
    }

    #[test]
    fn url_host_extracts_narrowly() {
        assert_eq!(
            url_host("https://example.test:443/a"),
            Some("example.test".to_owned())
        );
        assert_eq!(
            url_host("http://192.0.2.10/x"),
            Some("192.0.2.10".to_owned())
        );
        assert_eq!(url_host("not a url"), None);
    }
}
