use std::{io::Read, net::IpAddr, path::Path};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Ipv4,
    Ipv6,
    Hostname,
    Url,
    Cidr,
}

/// The canonical target representation shared by every RXScan subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetSpec {
    pub original_input: String,
    pub kind: TargetKind,
    pub normalized_addresses: Vec<IpAddr>,
    pub hostnames: Vec<String>,
    pub schemes: Vec<String>,
    pub explicit_ports: Vec<u16>,
    pub cidr: Option<IpNet>,
}

#[derive(Debug, Error)]
pub enum TargetError {
    #[error("target is empty")]
    Empty,
    #[error("use either TARGET or --targets, not both")]
    MultipleSources,
    #[error("invalid URL target '{0}'")]
    InvalidUrl(String),
    #[error("invalid hostname '{0}'")]
    InvalidHostname(String),
    #[error("invalid port in target '{0}'")]
    InvalidPort(String),
    #[error("could not read target file '{path}': {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("could not read standard input: {0}")]
    ReadStdin(std::io::Error),
}

impl TargetSpec {
    pub fn parse(input: impl AsRef<str>) -> Result<Self, TargetError> {
        let original_input = input.as_ref().trim().to_owned();
        if original_input.is_empty() {
            return Err(TargetError::Empty);
        }

        if let Ok(network) = original_input.parse::<IpNet>() {
            return Ok(Self {
                original_input,
                kind: TargetKind::Cidr,
                normalized_addresses: vec![network.network()],
                hostnames: Vec::new(),
                schemes: Vec::new(),
                explicit_ports: Vec::new(),
                cidr: Some(network),
            });
        }

        if let Ok(address) = original_input.parse::<IpAddr>() {
            return Ok(Self::from_ip(original_input, address));
        }

        if original_input.contains("://") {
            return Self::from_url(original_input);
        }

        Self::from_host_or_socket(original_input)
    }

    fn from_ip(original_input: String, address: IpAddr) -> Self {
        let kind = if address.is_ipv4() {
            TargetKind::Ipv4
        } else {
            TargetKind::Ipv6
        };
        Self {
            original_input,
            kind,
            normalized_addresses: vec![address],
            hostnames: Vec::new(),
            schemes: Vec::new(),
            explicit_ports: Vec::new(),
            cidr: None,
        }
    }

    fn from_url(original_input: String) -> Result<Self, TargetError> {
        let url = Url::parse(&original_input)
            .map_err(|_| TargetError::InvalidUrl(original_input.clone()))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(TargetError::InvalidUrl(original_input));
        }
        let host = url
            .host_str()
            .ok_or_else(|| TargetError::InvalidUrl(original_input.clone()))?;
        let port = url.port();
        if let Ok(address) = host.parse::<IpAddr>() {
            let mut target = Self::from_ip(original_input, address);
            target.kind = TargetKind::Url;
            target.schemes.push(url.scheme().to_owned());
            target.explicit_ports = port.into_iter().collect();
            return Ok(target);
        }
        let hostname = normalize_hostname(host)?;
        Ok(Self {
            original_input,
            kind: TargetKind::Url,
            normalized_addresses: Vec::new(),
            hostnames: vec![hostname],
            schemes: vec![url.scheme().to_owned()],
            explicit_ports: port.into_iter().collect(),
            cidr: None,
        })
    }

    fn from_host_or_socket(original_input: String) -> Result<Self, TargetError> {
        if let Some((host, port)) = split_host_port(&original_input) {
            let port = port
                .parse::<u16>()
                .map_err(|_| TargetError::InvalidPort(original_input.clone()))?;
            if port == 0 {
                return Err(TargetError::InvalidPort(original_input));
            }
            if let Ok(address) = host.parse::<IpAddr>() {
                let mut target = Self::from_ip(original_input, address);
                target.explicit_ports.push(port);
                return Ok(target);
            }
            let hostname = normalize_hostname(host)?;
            return Ok(Self {
                original_input,
                kind: TargetKind::Hostname,
                normalized_addresses: Vec::new(),
                hostnames: vec![hostname],
                schemes: Vec::new(),
                explicit_ports: vec![port],
                cidr: None,
            });
        }
        let hostname = normalize_hostname(&original_input)?;
        Ok(Self {
            original_input,
            kind: TargetKind::Hostname,
            normalized_addresses: Vec::new(),
            hostnames: vec![hostname],
            schemes: Vec::new(),
            explicit_ports: Vec::new(),
            cidr: None,
        })
    }
}

pub fn read_target_source(
    target: Option<&str>,
    file: Option<&Path>,
) -> Result<Vec<TargetSpec>, TargetError> {
    let raw_targets = match (target, file) {
        (Some(_), Some(_)) => return Err(TargetError::MultipleSources),
        (Some("-"), None) => {
            let mut input = String::new();
            std::io::stdin()
                .read_to_string(&mut input)
                .map_err(TargetError::ReadStdin)?;
            target_lines(&input)
        }
        (Some(value), None) => vec![value.to_owned()],
        (None, Some(path)) => {
            let input = std::fs::read_to_string(path).map_err(|source| TargetError::ReadFile {
                path: path.display().to_string(),
                source,
            })?;
            target_lines(&input)
        }
        (None, None) => return Err(TargetError::Empty),
    };
    raw_targets.into_iter().map(TargetSpec::parse).collect()
}

fn target_lines(input: &str) -> Vec<String> {
    input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect()
}

fn split_host_port(input: &str) -> Option<(&str, &str)> {
    if let Some(stripped) = input.strip_prefix('[') {
        let (host, port) = stripped.split_once("]:")?;
        return Some((host, port));
    }
    let (host, port) = input.rsplit_once(':')?;
    (!host.contains(':')).then_some((host, port))
}

fn normalize_hostname(input: &str) -> Result<String, TargetError> {
    let hostname = input.trim_end_matches('.').to_ascii_lowercase();
    let valid = !hostname.is_empty()
        && hostname.len() <= 253
        && hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    valid
        .then_some(hostname)
        .ok_or_else(|| TargetError::InvalidHostname(input.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_supported_target_kinds() {
        let ipv4 = TargetSpec::parse("192.0.2.10").unwrap();
        assert_eq!(ipv4.kind, TargetKind::Ipv4);
        assert_eq!(
            ipv4.normalized_addresses,
            vec!["192.0.2.10".parse::<IpAddr>().unwrap()]
        );

        let ipv6 = TargetSpec::parse("2001:db8::10").unwrap();
        assert_eq!(ipv6.kind, TargetKind::Ipv6);

        let url = TargetSpec::parse("HTTPS://Example.COM:8443/a?b=c").unwrap();
        assert_eq!(url.hostnames, ["example.com"]);
        assert_eq!(url.schemes, ["https"]);
        assert_eq!(url.explicit_ports, [8443]);

        let cidr = TargetSpec::parse("192.0.2.0/24").unwrap();
        assert_eq!(cidr.kind, TargetKind::Cidr);
    }

    #[test]
    fn supports_host_port_and_rejects_bad_hostnames() {
        let target = TargetSpec::parse("Scan.Example.test:443").unwrap();
        assert_eq!(target.hostnames, ["scan.example.test"]);
        assert_eq!(target.explicit_ports, [443]);
        assert!(TargetSpec::parse("bad_host!").is_err());
    }
}
