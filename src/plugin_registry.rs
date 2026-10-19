//! Plugin registry: enables/disables plugins, builds transform menus,
//! pins versions, declares dependencies and detects conflicts.
//!
//! Thin, in-process registry. No dynamic loading: plugins are registered
//! as values and gated by the registry's enable/disable state.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginError {
    NotFound(String),
    DuplicateId(String),
    DependencyMissing {
        plugin: String,
        dependency: String,
    },
    VersionMismatch {
        plugin: String,
        expected: String,
        found: String,
    },
    Conflict(String),
    Disabled(String),
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "plugin not found: {id}"),
            Self::DuplicateId(id) => write!(f, "duplicate plugin id: {id}"),
            Self::DependencyMissing { plugin, dependency } => {
                write!(f, "plugin {plugin} missing dependency {dependency}")
            }
            Self::VersionMismatch {
                plugin,
                expected,
                found,
            } => write!(f, "plugin {plugin} version {found} != pinned {expected}"),
            Self::Conflict(detail) => write!(f, "plugin conflict: {detail}"),
            Self::Disabled(id) => write!(f, "plugin disabled: {id}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformAction {
    pub id: String,
    pub label: String,
    pub target: String,
    pub plugin: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plugin {
    pub id: String,
    pub name: String,
    pub version: String,
    pub enabled: bool,
    pub pinned_version: Option<String>,
    pub dependencies: BTreeSet<String>,
    pub transforms: Vec<TransformAction>,
    pub conflicts_with: BTreeSet<String>,
}

impl Plugin {
    pub fn new(id: impl Into<String>, version: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            name: id.clone(),
            id,
            version: version.into(),
            enabled: true,
            pinned_version: None,
            dependencies: BTreeSet::new(),
            transforms: Vec::new(),
            conflicts_with: BTreeSet::new(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    pub fn with_transform(mut self, transform: TransformAction) -> Self {
        self.transforms.push(transform);
        self
    }

    pub fn depends_on(mut self, dep: impl Into<String>) -> Self {
        self.dependencies.insert(dep.into());
        self
    }
}

#[derive(Debug, Default, Clone)]
pub struct PluginRegistry {
    plugins: BTreeMap<String, Plugin>,
    order: Vec<String>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, plugin: Plugin) -> Result<(), PluginError> {
        if self.plugins.contains_key(&plugin.id) {
            return Err(PluginError::DuplicateId(plugin.id));
        }
        self.order.push(plugin.id.clone());
        self.plugins.insert(plugin.id.clone(), plugin);
        Ok(())
    }

    pub fn unregister(&mut self, id: &str) -> Result<(), PluginError> {
        if self.plugins.remove(id).is_none() {
            return Err(PluginError::NotFound(id.to_owned()));
        }
        self.order.retain(|x| x != id);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Plugin> {
        self.plugins.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Plugin> {
        self.plugins.get_mut(id)
    }

    pub fn list(&self) -> Vec<&Plugin> {
        self.order
            .iter()
            .filter_map(|id| self.plugins.get(id))
            .collect()
    }

    pub fn plugins(&self) -> Vec<&Plugin> {
        self.list()
    }

    pub fn ids(&self) -> Vec<String> {
        self.order.clone()
    }

    pub fn is_enabled(&self, id: &str) -> bool {
        self.plugins.get(id).map(|p| p.enabled).unwrap_or(false)
    }

    pub fn enable(&mut self, id: &str) -> Result<(), PluginError> {
        let deps: Vec<String> = self
            .plugins
            .get(id)
            .map(|p| p.dependencies.iter().cloned().collect())
            .unwrap_or_default();
        let pinned = self.plugins.get(id).and_then(|p| p.pinned_version.clone());
        let version = self
            .plugins
            .get(id)
            .map(|p| p.version.clone())
            .unwrap_or_default();
        if let Some(pinned) = pinned {
            if version != pinned {
                return Err(PluginError::VersionMismatch {
                    plugin: id.to_owned(),
                    expected: pinned,
                    found: version,
                });
            }
        }
        for dep in &deps {
            if !self.is_enabled(dep) {
                return Err(PluginError::DependencyMissing {
                    plugin: id.to_owned(),
                    dependency: dep.clone(),
                });
            }
        }
        let p = self
            .plugins
            .get_mut(id)
            .ok_or_else(|| PluginError::NotFound(id.to_owned()))?;
        p.enabled = true;
        Ok(())
    }

    pub fn disable(&mut self, id: &str) -> Result<(), PluginError> {
        let p = self
            .plugins
            .get_mut(id)
            .ok_or_else(|| PluginError::NotFound(id.to_owned()))?;
        p.enabled = false;
        Ok(())
    }

    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> Result<(), PluginError> {
        if enabled {
            self.enable(id)
        } else {
            self.disable(id)
        }
    }

    pub fn pin(&mut self, id: &str, version: impl Into<String>) -> Result<(), PluginError> {
        self.pin_version(id, version)
    }

    pub fn pin_version(&mut self, id: &str, version: impl Into<String>) -> Result<(), PluginError> {
        let p = self
            .plugins
            .get_mut(id)
            .ok_or_else(|| PluginError::NotFound(id.to_owned()))?;
        p.pinned_version = Some(version.into());
        Ok(())
    }

    pub fn pinned_version(&self, id: &str) -> Option<String> {
        self.plugins.get(id).and_then(|p| p.pinned_version.clone())
    }

    pub fn is_pinned(&self, id: &str) -> bool {
        self.pinned_version(id).is_some()
    }

    pub fn add_dependency(&mut self, plugin: &str, dependency: &str) -> Result<(), PluginError> {
        self.declare_dependency(plugin, dependency)
    }

    pub fn declare_dependency(
        &mut self,
        plugin: &str,
        dependency: &str,
    ) -> Result<(), PluginError> {
        let p = self
            .plugins
            .get_mut(plugin)
            .ok_or_else(|| PluginError::NotFound(plugin.to_owned()))?;
        p.dependencies.insert(dependency.to_owned());
        Ok(())
    }

    pub fn dependencies(&self, id: &str) -> Vec<String> {
        self.plugins
            .get(id)
            .map(|p| p.dependencies.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn transform_menu(&self, _context: &str) -> Vec<TransformAction> {
        self.transforms_for(_context)
    }

    pub fn transforms_for(&self, _context: &str) -> Vec<TransformAction> {
        let mut out = Vec::new();
        for p in self.list() {
            if !p.enabled {
                continue;
            }
            for t in &p.transforms {
                out.push(t.clone());
            }
        }
        out
    }

    pub fn menu_for(&self, context: &str) -> Vec<TransformAction> {
        self.transform_menu(context)
    }

    pub fn transforms(&self) -> Vec<TransformAction> {
        self.transforms_for("")
    }

    pub fn detect_conflicts(&self) -> Vec<String> {
        self.conflicts()
    }

    pub fn conflicts(&self) -> Vec<String> {
        let mut out = Vec::new();
        // duplicate transform ids
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        for p in self.list() {
            for t in &p.transforms {
                if let Some(other) = seen.get(&t.id) {
                    if other != &p.id {
                        out.push(format!(
                            "transform '{}' declared by both {} and {}",
                            t.id, other, p.id
                        ));
                    }
                } else {
                    seen.insert(t.id.clone(), p.id.clone());
                }
            }
        }
        // explicit conflicts_with
        for p in self.list() {
            for other in &p.conflicts_with {
                if self.plugins.contains_key(other) {
                    out.push(format!("{} conflicts with {}", p.id, other));
                }
            }
        }
        // missing dependencies
        for p in self.list() {
            for dep in &p.dependencies {
                if !self.plugins.contains_key(dep) {
                    out.push(format!("{} missing dependency {}", p.id, dep));
                }
            }
        }
        out
    }

    pub fn has_conflict(&self, a: &str, b: &str) -> bool {
        self.plugins
            .get(a)
            .map(|p| p.conflicts_with.contains(b))
            .unwrap_or(false)
            || self
                .plugins
                .get(b)
                .map(|p| p.conflicts_with.contains(a))
                .unwrap_or(false)
    }

    pub fn enabled_plugins(&self) -> Vec<&Plugin> {
        self.list().into_iter().filter(|p| p.enabled).collect()
    }

    pub fn disabled_plugins(&self) -> Vec<&Plugin> {
        self.list().into_iter().filter(|p| !p.enabled).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_enable_disable() {
        let mut reg = PluginRegistry::new();
        reg.register(Plugin::new("a", "1.0")).unwrap();
        assert!(reg.is_enabled("a"));
        reg.disable("a").unwrap();
        assert!(!reg.is_enabled("a"));
        reg.enable("a").unwrap();
        assert!(reg.is_enabled("a"));
    }

    #[test]
    fn duplicate_and_not_found() {
        let mut reg = PluginRegistry::new();
        reg.register(Plugin::new("a", "1.0")).unwrap();
        assert!(reg.register(Plugin::new("a", "1.0")).is_err());
        assert!(reg.unregister("nope").is_err());
    }

    #[test]
    fn pin_and_dependency() {
        let mut reg = PluginRegistry::new();
        let mut p = Plugin::new("a", "1.0");
        p = p.depends_on("b");
        reg.register(p).unwrap();
        reg.register(Plugin::new("b", "1.0")).unwrap();
        reg.pin("a", "1.0").unwrap();
        assert!(reg.is_pinned("a"));
        assert_eq!(reg.pinned_version("a").unwrap(), "1.0");
        // enable b first
        reg.enable("b").unwrap();
        reg.enable("a").unwrap();
        assert!(reg.is_enabled("a"));
    }

    #[test]
    fn transform_menu_and_conflicts() {
        let mut reg = PluginRegistry::new();
        let t = TransformAction {
            id: "t1".into(),
            label: "Link".into(),
            target: "node".into(),
            plugin: "a".into(),
        };
        reg.register(Plugin::new("a", "1.0").with_transform(t))
            .unwrap();
        let menu = reg.transform_menu("node");
        assert_eq!(menu.len(), 1);
        // duplicate transform id conflict
        let t2 = TransformAction {
            id: "t1".into(),
            label: "Link2".into(),
            target: "node".into(),
            plugin: "b".into(),
        };
        reg.register(Plugin::new("b", "1.0").with_transform(t2))
            .unwrap();
        let c = reg.detect_conflicts();
        assert!(!c.is_empty());
    }
}
