//! Configuration loading and deterministic precedence for Phase 1.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
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
    }
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
