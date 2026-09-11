use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::target::{TargetError, TargetKind, TargetSpec};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeRule {
    Ip(IpAddr),
    Network(IpNet),
    Hostname(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopePolicy {
    pub allowed: Vec<ScopeRule>,
    pub exclusions: Vec<ScopeRule>,
}

#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("invalid scope rule '{value}': {source}")]
    InvalidRule { value: String, source: TargetError },
    #[error("seed target '{0}' is excluded by the effective scope policy")]
    SeedExcluded(String),
}

impl ScopePolicy {
    pub fn from_targets(
        targets: &[TargetSpec],
        additional_scope: &[String],
        exclusions: &[String],
    ) -> Result<Self, ScopeError> {
        let mut allowed = targets
            .iter()
            .flat_map(rules_for_target)
            .collect::<Vec<_>>();
        for value in additional_scope {
            allowed.extend(parse_rule(value)?);
        }
        let mut excluded = Vec::new();
        for value in exclusions {
            excluded.extend(parse_rule(value)?);
        }
        allowed.sort_by_key(|rule| format!("{rule:?}"));
        allowed.dedup();
        excluded.sort_by_key(|rule| format!("{rule:?}"));
        excluded.dedup();
        let policy = Self {
            allowed,
            exclusions: excluded,
        };
        for target in targets {
            if !rules_for_target(target).iter().all(|rule| match rule {
                ScopeRule::Ip(address) => policy.permits(Some(*address), None),
                ScopeRule::Network(network) => {
                    policy
                        .allowed
                        .iter()
                        .any(|allowed| allowed == &ScopeRule::Network(*network))
                        && !policy
                            .exclusions
                            .iter()
                            .any(|excluded| excluded == &ScopeRule::Network(*network))
                }
                ScopeRule::Hostname(hostname) => policy.permits(None, Some(hostname)),
            }) {
                return Err(ScopeError::SeedExcluded(target.original_input.clone()));
            }
        }
        Ok(policy)
    }

    /// A discovery is permitted only when it matches an allowed rule and no exclusion.
    pub fn permits(&self, address: Option<IpAddr>, hostname: Option<&str>) -> bool {
        let hostname = hostname.map(|value| value.trim_end_matches('.').to_ascii_lowercase());
        let matches = |rule: &ScopeRule| match rule {
            ScopeRule::Ip(ip) => address.is_some_and(|candidate| candidate == *ip),
            ScopeRule::Network(network) => {
                address.is_some_and(|candidate| network.contains(&candidate))
            }
            ScopeRule::Hostname(expected) => hostname
                .as_deref()
                .is_some_and(|candidate| candidate == expected),
        };
        self.allowed.iter().any(matches) && !self.exclusions.iter().any(matches)
    }
}

fn parse_rule(value: &str) -> Result<Vec<ScopeRule>, ScopeError> {
    let target = TargetSpec::parse(value).map_err(|source| ScopeError::InvalidRule {
        value: value.to_owned(),
        source,
    })?;
    Ok(rules_for_target(&target))
}

fn rules_for_target(target: &TargetSpec) -> Vec<ScopeRule> {
    match target.kind {
        TargetKind::Cidr => target.cidr.into_iter().map(ScopeRule::Network).collect(),
        _ => target
            .normalized_addresses
            .iter()
            .copied()
            .map(ScopeRule::Ip)
            .chain(target.hostnames.iter().cloned().map(ScopeRule::Hostname))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scope_is_exact_and_exclusions_win() {
        let target = TargetSpec::parse("192.0.2.0/24").unwrap();
        let policy = ScopePolicy::from_targets(&[target], &[], &["192.0.2.8".to_owned()]).unwrap();
        assert!(policy.permits(Some("192.0.2.9".parse().unwrap()), None));
        assert!(!policy.permits(Some("192.0.2.8".parse().unwrap()), None));
        assert!(!policy.permits(Some("198.51.100.1".parse().unwrap()), None));
    }

    #[test]
    fn hostname_scope_does_not_expand_to_subdomains() {
        let target = TargetSpec::parse("example.test").unwrap();
        let policy = ScopePolicy::from_targets(&[target], &[], &[]).unwrap();
        assert!(policy.permits(None, Some("example.test")));
        assert!(!policy.permits(None, Some("api.example.test")));
    }
}
