//! Configuration management: plugins, toggles, shortcuts, workspace layouts.
//!
//! JSON-based schemas with validation. Invalid configs fail with helpful
//! errors. Migration helpers handle older formats.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigManagerError {
    Parse(String),
    Validation(String),
    Migration(String),
}

impl std::fmt::Display for ConfigManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(s) => write!(f, "config parse error: {s}"),
            Self::Validation(s) => write!(f, "config validation error: {s}"),
            Self::Migration(s) => write!(f, "config migration error: {s}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Plugins
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginEntry {
    pub id: String,
    pub enabled: bool,
    pub pinned_version: Option<String>,
    pub dependencies: Vec<String>,
}

impl Default for PluginEntry {
    fn default() -> Self {
        Self {
            id: String::new(),
            enabled: true,
            pinned_version: None,
            dependencies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginsConfig {
    pub schema_version: u32,
    pub plugins: Vec<PluginEntry>,
}

impl Default for PluginsConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            plugins: Vec::new(),
        }
    }
}

impl PluginsConfig {
    pub fn parse(text: &str) -> Result<Self, ConfigManagerError> {
        serde_json::from_str(text).map_err(|e| ConfigManagerError::Parse(e.to_string()))
    }

    pub fn validate(&self) -> Result<(), ConfigManagerError> {
        if self.schema_version == 0 {
            return Err(ConfigManagerError::Validation(
                "schema_version must be >= 1".into(),
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for p in &self.plugins {
            if p.id.trim().is_empty() {
                return Err(ConfigManagerError::Validation(
                    "plugin id must not be empty".into(),
                ));
            }
            if !ids.insert(p.id.clone()) {
                return Err(ConfigManagerError::Validation(format!(
                    "duplicate plugin id: {}",
                    p.id
                )));
            }
        }
        // dependency existence
        let idset: std::collections::BTreeSet<String> =
            self.plugins.iter().map(|p| p.id.clone()).collect();
        for p in &self.plugins {
            for dep in &p.dependencies {
                if !idset.contains(dep) {
                    return Err(ConfigManagerError::Validation(format!(
                        "plugin {} references missing dependency {}",
                        p.id, dep
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn load(text: &str) -> Result<Self, ConfigManagerError> {
        let cfg = Self::parse(text)?;
        cfg.validate()?;
        Ok(cfg)
    }
}

// ---------------------------------------------------------------------------
// Toggles
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TogglesConfig {
    pub schema_version: u32,
    pub admin_override: bool,
    pub toggles: BTreeMap<String, bool>,
}

impl Default for TogglesConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            admin_override: false,
            toggles: BTreeMap::new(),
        }
    }
}

impl TogglesConfig {
    pub fn parse(text: &str) -> Result<Self, ConfigManagerError> {
        serde_json::from_str(text).map_err(|e| ConfigManagerError::Parse(e.to_string()))
    }
    pub fn validate(&self) -> Result<(), ConfigManagerError> {
        if self.schema_version == 0 {
            return Err(ConfigManagerError::Validation(
                "schema_version must be >= 1".into(),
            ));
        }
        Ok(())
    }
    pub fn load(text: &str) -> Result<Self, ConfigManagerError> {
        let cfg = Self::parse(text)?;
        cfg.validate()?;
        Ok(cfg)
    }
    pub fn is_enabled(&self, key: &str) -> bool {
        self.toggles.get(key).copied().unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Shortcuts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShortcutEntry {
    pub action: String,
    pub keys: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShortcutsConfig {
    pub schema_version: u32,
    pub profile: String,
    pub shortcuts: Vec<ShortcutEntry>,
}

impl Default for ShortcutsConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            profile: "analyst".to_owned(),
            shortcuts: Vec::new(),
        }
    }
}

impl ShortcutsConfig {
    pub fn parse(text: &str) -> Result<Self, ConfigManagerError> {
        serde_json::from_str(text).map_err(|e| ConfigManagerError::Parse(e.to_string()))
    }
    pub fn validate(&self) -> Result<(), ConfigManagerError> {
        if self.schema_version == 0 {
            return Err(ConfigManagerError::Validation(
                "schema_version must be >= 1".into(),
            ));
        }
        let mut actions = std::collections::BTreeSet::new();
        for s in &self.shortcuts {
            if s.action.trim().is_empty() {
                return Err(ConfigManagerError::Validation(
                    "shortcut action must not be empty".into(),
                ));
            }
            if s.keys.trim().is_empty() {
                return Err(ConfigManagerError::Validation(format!(
                    "shortcut {} has empty keys",
                    s.action
                )));
            }
            if !actions.insert(s.action.clone()) {
                return Err(ConfigManagerError::Validation(format!(
                    "duplicate shortcut action: {}",
                    s.action
                )));
            }
        }
        Ok(())
    }
    pub fn load(text: &str) -> Result<Self, ConfigManagerError> {
        let cfg = Self::parse(text)?;
        cfg.validate()?;
        Ok(cfg)
    }
}

// ---------------------------------------------------------------------------
// Workspace
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PaneState {
    pub id: String,
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

impl Default for PaneState {
    fn default() -> Self {
        Self {
            id: String::new(),
            x: 0.0,
            y: 0.0,
            w: 0.0,
            h: 0.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkspaceConfig {
    pub schema_version: u32,
    pub profile: String,
    pub zoom: f64,
    pub panes: Vec<PaneState>,
    pub filters: BTreeMap<String, String>,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            profile: "default".to_owned(),
            zoom: 1.0,
            panes: Vec::new(),
            filters: BTreeMap::new(),
        }
    }
}

impl WorkspaceConfig {
    pub fn parse(text: &str) -> Result<Self, ConfigManagerError> {
        serde_json::from_str(text).map_err(|e| ConfigManagerError::Parse(e.to_string()))
    }
    pub fn validate(&self) -> Result<(), ConfigManagerError> {
        if self.schema_version == 0 {
            return Err(ConfigManagerError::Validation(
                "schema_version must be >= 1".into(),
            ));
        }
        if self.zoom <= 0.0 || !self.zoom.is_finite() {
            return Err(ConfigManagerError::Validation(
                "zoom must be positive finite".into(),
            ));
        }
        Ok(())
    }
    pub fn load(text: &str) -> Result<Self, ConfigManagerError> {
        let cfg = Self::parse(text)?;
        cfg.validate()?;
        Ok(cfg)
    }
}

// ---------------------------------------------------------------------------
// Migration
// ---------------------------------------------------------------------------

pub fn migrate_plugins(text: &str) -> Result<PluginsConfig, ConfigManagerError> {
    // Older format: bare array of ids.
    if let Ok(ids) = serde_json::from_str::<Vec<String>>(text) {
        let plugins = ids
            .into_iter()
            .map(|id| PluginEntry {
                id,
                enabled: true,
                pinned_version: None,
                dependencies: Vec::new(),
            })
            .collect();
        return Ok(PluginsConfig {
            schema_version: 1,
            plugins,
        });
    }
    PluginsConfig::load(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugins_valid() {
        let text =
            r#"{"schema_version":1,"plugins":[{"id":"a","enabled":true,"dependencies":[]}]}"#;
        let cfg = PluginsConfig::load(text).unwrap();
        assert_eq!(cfg.plugins.len(), 1);
    }

    #[test]
    fn plugins_invalid_duplicate() {
        let text = r#"{"schema_version":1,"plugins":[{"id":"a"},{"id":"a"}]}"#;
        assert!(PluginsConfig::load(text).is_err());
    }

    #[test]
    fn plugins_missing_dep() {
        let text = r#"{"schema_version":1,"plugins":[{"id":"a","dependencies":["b"]}]}"#;
        assert!(PluginsConfig::load(text).is_err());
    }

    #[test]
    fn toggles_default_false() {
        let cfg = TogglesConfig::default();
        assert!(!cfg.is_enabled("clustering"));
    }

    #[test]
    fn shortcuts_duplicate_action() {
        let text = r#"{"schema_version":1,"profile":"analyst","shortcuts":[{"action":"x","keys":"Ctrl+X"},{"action":"x","keys":"Ctrl+Y"}]}"#;
        assert!(ShortcutsConfig::load(text).is_err());
    }

    #[test]
    fn workspace_zoom_validation() {
        let text = r#"{"schema_version":1,"profile":"default","zoom":0,"panes":[],"filters":{}}"#;
        assert!(WorkspaceConfig::load(text).is_err());
    }

    #[test]
    fn migration_bare_array() {
        let text = r#"["a","b"]"#;
        let cfg = migrate_plugins(text).unwrap();
        assert_eq!(cfg.plugins.len(), 2);
    }

    #[test]
    fn parse_error_helpful() {
        let err = PluginsConfig::parse("{not json").unwrap_err();
        assert!(err.to_string().contains("parse"));
    }
}
