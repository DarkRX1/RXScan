//! Configuration loading and deterministic precedence (Phases 1+4).
//!
//! Precedence: built-in defaults < global config < project config < CLI.
//! CLI always wins. Invalid budget values fail fast.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::plan::{ScanGoal, SpeedSetting};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConfigLayer {
    pub goal: Option<ScanGoal>,
    pub level: Option<u8>,
    pub speed: Option<SpeedSetting>,
    pub profile: Option<String>,
    pub scope: Vec<String>,
    pub exclude: Vec<String>,
    pub ports: Option<String>,
    pub all_ports: Option<bool>,
    pub max_tasks: Option<u64>,
    pub max_retries: Option<u64>,
    pub max_concurrency: Option<u64>,
    /// Duration for max execution time. TOML accepts `"60s"`, `"5m"`,
    /// `"1h"`, `"500ms"`, or an integer (seconds). CLI accepts the same forms.
    #[serde(deserialize_with = "deserialize_optional_stringy", default)]
    pub max_execution_time: Option<String>,
    /// Evidence cap. TOML/CLI accept `"67108864"`, `"64MiB"`, `"10MB"`, etc.
    #[serde(deserialize_with = "deserialize_optional_stringy", default)]
    pub max_evidence_bytes: Option<String>,
    /// Phase 5: cap on hosts generated from CIDR targets (1..=100000).
    /// Defaults to 256. CLI `--max-hosts` wins when present.
    pub max_hosts: Option<u64>,
    /// Phase 5: small configurable TCP reachability set for host discovery
    /// (e.g. `"80,443"`). Bounded to 8 ports. Level-derived defaults apply
    /// when unset. Configuration/profile only; no CLI flag by design.
    pub discovery_ports: Option<String>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read configuration file '{path}': {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("could not parse configuration file '{path}': {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },
    #[error("configuration level must be in the range 1..=5, got {0}")]
    InvalidLevel(u8),
    #[error("invalid budget value for '{field}': {reason}")]
    InvalidBudget { field: String, reason: String },
}

fn deserialize_optional_stringy<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    struct StringyVisitor;
    impl<'de> Visitor<'de> for StringyVisitor {
        type Value = Option<String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or integer")
        }
        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
        where
            D2: Deserializer<'de>,
        {
            deserializer.deserialize_any(StringyInnerVisitor).map(Some)
        }
    }
    struct StringyInnerVisitor;
    impl Visitor<'_> for StringyInnerVisitor {
        type Value = String;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or integer")
        }
        fn visit_str<E: de::Error>(self, value: &str) -> Result<String, E> {
            Ok(value.to_owned())
        }
        fn visit_string<E: de::Error>(self, value: String) -> Result<String, E> {
            Ok(value)
        }
        fn visit_i64<E: de::Error>(self, value: i64) -> Result<String, E> {
            Ok(value.to_string())
        }
        fn visit_u64<E: de::Error>(self, value: u64) -> Result<String, E> {
            Ok(value.to_string())
        }
        fn visit_bool<E: de::Error>(self, value: bool) -> Result<String, E> {
            Ok(value.to_string())
        }
    }
    deserializer.deserialize_option(StringyVisitor)
}

impl ConfigLayer {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let config: Self = toml::from_str(&contents).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(level) = self.level.filter(|level| !(1..=5).contains(level)) {
            return Err(ConfigError::InvalidLevel(level));
        }
        // Fail fast on malformed budget strings (range checks happen when
        // building BudgetLimits so hard limits are enforced in one place).
        if let Some(value) = self.max_execution_time.as_deref() {
            parse_duration_ms(value).map_err(|reason| ConfigError::InvalidBudget {
                field: "max_execution_time".to_owned(),
                reason,
            })?;
        }
        if let Some(value) = self.max_evidence_bytes.as_deref() {
            parse_bytes(value).map_err(|reason| ConfigError::InvalidBudget {
                field: "max_evidence_bytes".to_owned(),
                reason,
            })?;
        }
        if let Some(value) = self.max_hosts.filter(|value| *value == 0) {
            return Err(ConfigError::InvalidBudget {
                field: "max_hosts".to_owned(),
                reason: format!("must be positive, got {value}"),
            });
        }
        if let Some(value) = self.discovery_ports.as_deref() {
            crate::discovery::parse_discovery_ports(value).map_err(|reason| {
                ConfigError::InvalidBudget {
                    field: "discovery_ports".to_owned(),
                    reason,
                }
            })?;
        }
        Ok(())
    }

    pub fn overlay(&mut self, higher: Self) {
        self.goal = higher.goal.or(self.goal);
        self.level = higher.level.or(self.level);
        self.speed = higher.speed.or(self.speed);
        self.profile = higher.profile.or(self.profile.take());
        if !higher.scope.is_empty() {
            self.scope = higher.scope;
        }
        if !higher.exclude.is_empty() {
            self.exclude = higher.exclude;
        }
        self.ports = higher.ports.or(self.ports.take());
        self.all_ports = higher.all_ports.or(self.all_ports);
        self.max_tasks = higher.max_tasks.or(self.max_tasks);
        self.max_retries = higher.max_retries.or(self.max_retries);
        self.max_concurrency = higher.max_concurrency.or(self.max_concurrency);
        self.max_execution_time = higher.max_execution_time.or(self.max_execution_time.take());
        self.max_evidence_bytes = higher.max_evidence_bytes.or(self.max_evidence_bytes.take());
        self.max_hosts = higher.max_hosts.or(self.max_hosts);
        self.discovery_ports = higher.discovery_ports.or(self.discovery_ports.take());
    }
}

/// Parse a duration string into milliseconds.
///
/// Accepted: `<n>ms`, `<n>s`, `<n>m`, `<n>h` (case-insensitive, whitespace
/// trimmed), or a bare number meaning seconds. Must be positive.
pub fn parse_duration_ms(value: &str) -> Result<u64, String> {
    let trimmed = value.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err(format!("empty duration '{value}'"));
    }
    let (number, multiplier): (&str, u64) = if let Some(number) = trimmed.strip_suffix("ms") {
        (number, 1)
    } else if let Some(number) = trimmed.strip_suffix('h') {
        (number, 3_600_000)
    } else if let Some(number) = trimmed.strip_suffix('m') {
        (number, 60_000)
    } else if let Some(number) = trimmed.strip_suffix('s') {
        (number, 1_000)
    } else {
        (trimmed.as_str(), 1_000)
    };
    let number = number.trim();
    let amount: u64 = number
        .parse()
        .map_err(|_| format!("malformed duration '{value}' (expected e.g. 60s, 5m, 1h, 500ms)"))?;
    if amount == 0 {
        return Err(format!("duration must be positive, got '{value}'"));
    }
    amount
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration '{value}' overflows"))
}

/// Parse a byte-size string into bytes.
///
/// Accepted: bare integers (bytes) or `<n><suffix>` where suffix is B, KB,
/// MB, GB (1000-based) or KiB, MiB, GiB (1024-based), case-insensitive.
/// Must be positive.
pub fn parse_bytes(value: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("empty byte size '{value}'"));
    }
    let lower = trimmed.to_ascii_lowercase();
    let (number, multiplier): (&str, u64) = if lower.ends_with("gib") {
        (&trimmed[..trimmed.len() - 3], 1024 * 1024 * 1024)
    } else if lower.ends_with("mib") {
        (&trimmed[..trimmed.len() - 3], 1024 * 1024)
    } else if lower.ends_with("kib") {
        (&trimmed[..trimmed.len() - 3], 1024)
    } else if lower.ends_with("gb") {
        (&trimmed[..trimmed.len() - 2], 1_000_000_000)
    } else if lower.ends_with("mb") {
        (&trimmed[..trimmed.len() - 2], 1_000_000)
    } else if lower.ends_with("kb") {
        (&trimmed[..trimmed.len() - 2], 1_000)
    } else if lower.ends_with('b') {
        (&trimmed[..trimmed.len() - 1], 1)
    } else {
        (trimmed, 1)
    };
    let number = number.trim();
    let amount: u64 = number.parse().map_err(|_| {
        format!("malformed byte size '{value}' (expected e.g. 67108864, 64MiB, 10MB)")
    })?;
    if amount == 0 {
        return Err(format!("byte size must be positive, got '{value}'"));
    }
    amount
        .checked_mul(multiplier)
        .ok_or_else(|| format!("byte size '{value}' overflows"))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveConfig {
    pub layer: ConfigLayer,
    pub sources: Vec<PathBuf>,
}

impl EffectiveConfig {
    pub fn load(global: Option<&Path>, project: Option<&Path>) -> Result<Self, ConfigError> {
        let mut result = Self::default();
        for path in [global, project].into_iter().flatten() {
            result.layer.overlay(ConfigLayer::load(path)?);
            result.sources.push(path.to_path_buf());
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn higher_layer_overrides_scalar_values() {
        let mut defaults = ConfigLayer {
            level: Some(2),
            scope: vec!["example.test".to_owned()],
            ..ConfigLayer::default()
        };
        defaults.overlay(ConfigLayer {
            level: Some(4),
            scope: vec!["project.test".to_owned()],
            ..ConfigLayer::default()
        });
        assert_eq!(defaults.level, Some(4));
        assert_eq!(defaults.scope, ["project.test"]);
    }
}
