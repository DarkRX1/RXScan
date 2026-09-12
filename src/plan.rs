use std::{collections::BTreeSet, fmt, str::FromStr};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::ScanPlanId;
use crate::{
    cli::Cli,
    config::{ConfigError, EffectiveConfig},
    scope::{ScopeError, ScopePolicy},
    target::{TargetError, TargetSpec, read_target_source},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ScanGoal {
    #[default]
    Recon,
    Discovery,
    ServiceMap,
    Web,
    WebDiscovery,
    Api,
    ApiDiscovery,
    Content,
    Fuzz,
    Inventory,
    Baseline,
    Monitoring,
    Research,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NamedSpeed {
    Slow,
    Balanced,
    Fast,
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SpeedSetting {
    Named(NamedSpeed),
    Numeric(u8),
}
impl Default for SpeedSetting {
    fn default() -> Self {
        Self::Named(NamedSpeed::Balanced)
    }
}
impl fmt::Display for SpeedSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(value) => write!(f, "{:?}", value),
            Self::Numeric(value) => write!(f, "{value}"),
        }
    }
}
impl FromStr for SpeedSetting {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "slow" => Ok(Self::Named(NamedSpeed::Slow)),
            "balanced" => Ok(Self::Named(NamedSpeed::Balanced)),
            "fast" => Ok(Self::Named(NamedSpeed::Fast)),
            "auto" => Ok(Self::Named(NamedSpeed::Auto)),
            _ => value
                .parse::<u8>()
                .ok()
                .filter(|value| *value <= 100)
                .map(Self::Numeric)
                .ok_or_else(|| {
                    "speed must be slow, balanced, fast, auto, or an integer from 0 to 100"
                        .to_owned()
                }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannedModule {
    TargetNormalization,
    ScopeGuard,
    PlanCompilation,
    HostDiscovery,
    TcpDiscovery,
    UdpDiscovery,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpPortSelection {
    Common,
    Explicit(Vec<u16>),
    All,
}

/// Immutable, inspectable policy input. Execution is introduced in later phases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanPlan {
    pub targets: Vec<TargetSpec>,
    pub scope: ScopePolicy,
    pub goal: ScanGoal,
    pub level: u8,
    pub speed: SpeedSetting,
    pub profile: Option<String>,
    pub config_sources: Vec<String>,
    pub modules: Vec<PlannedModule>,
    pub tcp_ports: TcpPortSelection,
    pub udp_requested: bool,
    pub explain_requested: bool,
    pub reasons: Vec<String>,
    pub skipped: Vec<String>,
}

#[derive(Debug, Error)]
pub enum PlanError {
    #[error(transparent)]
    Target(#[from] TargetError),
    #[error(transparent)]
    Scope(#[from] ScopeError),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("invalid --ports value '{0}'")]
    InvalidPorts(String),
    #[error("--all-ports conflicts with a configured port selection")]
    AllPortsConflict,
}

impl ScanPlan {
    /// A deterministic identifier for correlating records generated from this plan.
    pub fn stable_id(&self) -> ScanPlanId {
        ScanPlanId::from_serializable(self)
    }

    pub fn compile(cli: Cli) -> Result<Self, PlanError> {
        let effective =
            EffectiveConfig::load(cli.config.as_deref(), cli.project_config.as_deref())?;
        let config = effective.layer;
        let targets = read_target_source(cli.target.as_deref(), cli.targets.as_deref())?;
        let scope_rules = if cli.scope.is_empty() {
            config.scope
        } else {
            cli.scope
        };
        let exclusions = if cli.exclude.is_empty() {
            config.exclude
        } else {
            cli.exclude
        };
        let scope = ScopePolicy::from_targets(&targets, &scope_rules, &exclusions)?;
        let configured_ports = if cli.ports.is_some() {
            cli.ports
        } else {
            config.ports
        };
        let all_ports = cli.all_ports || config.all_ports.unwrap_or(false);
        if all_ports && configured_ports.is_some() {
            return Err(PlanError::AllPortsConflict);
        }
        let tcp_ports = if all_ports {
            TcpPortSelection::All
        } else if let Some(value) = configured_ports.as_deref() {
            TcpPortSelection::Explicit(parse_ports(value)?)
        } else {
            TcpPortSelection::Common
        };
        let goal = cli.goal.or(config.goal).unwrap_or_default();
        let level = cli.level.or(config.level).unwrap_or(2);
        let speed = cli.speed.or(config.speed).unwrap_or_default();
        let profile_name = cli.profile.or(config.profile);
        let mut modules = vec![
            PlannedModule::TargetNormalization,
            PlannedModule::ScopeGuard,
            PlannedModule::PlanCompilation,
            PlannedModule::TcpDiscovery,
        ];
        if cli.ping || cli.discover {
            modules.push(PlannedModule::HostDiscovery);
        }
        if cli.udp {
            modules.push(PlannedModule::UdpDiscovery);
        }
        let mut reasons = vec!["Every input is normalized into TargetSpec before planning.".to_owned(), "Scope is deny-by-default: seed targets and explicit --scope rules are the only permitted expansion.".to_owned(), format!("Goal {:?}, level {level}, and speed {speed} remain independent policy controls.", goal)];
        if !effective.sources.is_empty() {
            reasons.push(format!(
                "Configuration loaded in precedence order: {}.",
                effective
                    .sources
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            ));
        }
        reasons.push(match tcp_ports { TcpPortSelection::Common => "No port selection supplied; a later executor will use its conservative common TCP set.".to_owned(), TcpPortSelection::Explicit(_) => "An explicit TCP port selection was retained in the plan.".to_owned(), TcpPortSelection::All => "--all-ports selected the complete TCP range for future execution.".to_owned() });
        Ok(Self { targets, scope, goal, level, speed, profile: profile_name, config_sources: effective.sources.into_iter().map(|path| path.display().to_string()).collect(), modules, tcp_ports, udp_requested: cli.udp, explain_requested: cli.explain, reasons, skipped: vec!["Phases 0–1 do not open sockets, resolve DNS, scan ports, or expand discoveries.".to_owned(), "Scheduler, budgets, speed adaptation, probes, web discovery, and reporting remain intentionally deferred.".to_owned()] })
    }
    pub fn explain(&self) -> String {
        let targets = self
            .targets
            .iter()
            .map(|target| format!("  - {} ({:?})", target.original_input, target.kind))
            .collect::<Vec<_>>()
            .join("\n");
        let modules = self
            .modules
            .iter()
            .map(|module| format!("  - {module:?}"))
            .collect::<Vec<_>>()
            .join("\n");
        let reasons = self
            .reasons
            .iter()
            .map(|reason| format!("  - {reason}"))
            .collect::<Vec<_>>()
            .join("\n");
        let skipped = self
            .skipped
            .iter()
            .map(|item| format!("  - {item}"))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "RXScan Phase 1 plan\ngoal: {:?}\nlevel: {}\nspeed: {}\nprofile: {}\ntargets:\n{targets}\nmodules:\n{modules}\ntcp ports: {:?}\nscope: {} allow rule(s), {} exclusion(s)\nwhy:\n{reasons}\nskipped:\n{skipped}",
            self.goal,
            self.level,
            self.speed,
            self.profile.as_deref().unwrap_or("default"),
            self.tcp_ports,
            self.scope.allowed.len(),
            self.scope.exclusions.len()
        )
    }
}

fn parse_ports(value: &str) -> Result<Vec<u16>, PlanError> {
    let mut ports = BTreeSet::new();
    for component in value.split(',') {
        let component = component.trim();
        if component.is_empty() {
            return Err(PlanError::InvalidPorts(value.to_owned()));
        }
        if let Some((start, end)) = component.split_once('-') {
            let start = start
                .parse::<u16>()
                .map_err(|_| PlanError::InvalidPorts(value.to_owned()))?;
            let end = end
                .parse::<u16>()
                .map_err(|_| PlanError::InvalidPorts(value.to_owned()))?;
            if start == 0 || end == 0 || start > end {
                return Err(PlanError::InvalidPorts(value.to_owned()));
            }
            ports.extend(start..=end);
        } else {
            let port = component
                .parse::<u16>()
                .map_err(|_| PlanError::InvalidPorts(value.to_owned()))?;
            if port == 0 {
                return Err(PlanError::InvalidPorts(value.to_owned()));
            }
            ports.insert(port);
        }
    }
    Ok(ports.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[test]
    fn compiles_an_inspectable_explicit_plan() {
        let cli = Cli::try_parse_from([
            "rxscan",
            "https://example.test:8443",
            "--ports",
            "443,80,8000-8002",
            "--level",
            "4",
            "--speed",
            "30",
            "--goal",
            "web",
            "--explain",
        ])
        .unwrap();
        let plan = ScanPlan::compile(cli).unwrap();
        assert_eq!(
            plan.tcp_ports,
            TcpPortSelection::Explicit(vec![80, 443, 8000, 8001, 8002])
        );
        assert_eq!(plan.goal, ScanGoal::Web);
        assert_eq!(plan.speed, SpeedSetting::Numeric(30));
        assert!(plan.explain().contains("Scope is deny-by-default"));
    }
    #[test]
    fn rejects_zero_and_reversed_port_ranges() {
        assert!(parse_ports("0,80").is_err());
        assert!(parse_ports("90-80").is_err());
    }
    #[test]
    fn parses_named_and_numeric_speed() {
        assert_eq!(
            "auto".parse::<SpeedSetting>().unwrap(),
            SpeedSetting::Named(NamedSpeed::Auto)
        );
        assert_eq!(
            "100".parse::<SpeedSetting>().unwrap(),
            SpeedSetting::Numeric(100)
        );
        assert!("101".parse::<SpeedSetting>().is_err());
    }
}
