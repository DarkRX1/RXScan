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

/// Immutable, inspectable policy input. Phase 4 wires it to execution.
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
    /// Effective budgets (defaults < global < project < CLI). Phase 4.
    #[serde(default)]
    pub budgets: crate::execution::BudgetLimits,
    /// Phase 5: how host discovery was requested (centralized policy input).
    #[serde(default)]
    pub discovery_mode: crate::discovery::DiscoveryMode,
    /// Phase 5: explicit TCP reachability set for host discovery
    /// (configuration/profile only). `None` means level-derived defaults.
    #[serde(default)]
    pub discovery_ports: Option<Vec<u16>>,
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
    #[error("invalid budget for '{field}': {reason}")]
    InvalidBudget { field: String, reason: String },
    #[error("invalid --format '{0}': only 'jsonl' is supported in Phase 4")]
    InvalidFormat(String),
}

impl ScanPlan {
    /// A deterministic identifier for correlating records generated from this plan.
    pub fn stable_id(&self) -> ScanPlanId {
        ScanPlanId::from_serializable(self)
    }

    pub fn compile(cli: Cli) -> Result<Self, PlanError> {
        if let Some(format) = cli.format.as_deref() {
            if !format.eq_ignore_ascii_case("jsonl") {
                return Err(PlanError::InvalidFormat(format.to_owned()));
            }
        }
        let effective =
            EffectiveConfig::load(cli.config.as_deref(), cli.project_config.as_deref())?;
        let config = effective.layer;
        let targets = read_target_source(cli.target.as_deref(), cli.targets.as_deref())?;
        let scope_rules = if cli.scope.is_empty() {
            config.scope.clone()
        } else {
            cli.scope.clone()
        };
        let exclusions = if cli.exclude.is_empty() {
            config.exclude.clone()
        } else {
            cli.exclude.clone()
        };
        let scope = ScopePolicy::from_targets(&targets, &scope_rules, &exclusions)?;
        let configured_ports = if cli.ports.is_some() {
            cli.ports.clone()
        } else {
            config.ports.clone()
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
        let profile_name = cli.profile.clone().or(config.profile.clone());
        let host_requested = cli.ping || cli.discover;
        let udp_requested = cli.udp;
        let ports_requested = cli.ports.is_some()
            || cli.all_ports
            || config.ports.is_some()
            || config.all_ports.unwrap_or(false);
        let (modules, mut level_reasons, level_skipped) = crate::level::select_planned_modules(
            goal,
            level,
            host_requested,
            udp_requested,
            ports_requested,
        );
        let budgets = build_budgets(&config, &cli)?;
        // Validate budgets fail-fast (positive + hard safety ceilings).
        budgets
            .validate()
            .map_err(|error| PlanError::InvalidBudget {
                field: "budgets".to_owned(),
                reason: error.to_string(),
            })?;
        // Phase 5 discovery inputs (centralized; CLI handlers stay thin).
        let discovery_mode = crate::discovery::DiscoveryMode::from_flags(cli.ping, cli.discover);
        let discovery_ports =
            match config.discovery_ports.as_deref() {
                Some(raw) => Some(crate::discovery::parse_discovery_ports(raw).map_err(
                    |reason| PlanError::InvalidBudget {
                        field: "discovery_ports".to_owned(),
                        reason,
                    },
                )?),
                None => None,
            };
        let discovery_policy = crate::discovery::HostDiscoveryPolicy::for_level(
            level,
            discovery_mode,
            speed,
            discovery_ports.as_deref(),
        );
        let mut reasons = vec!["Every input is normalized into TargetSpec before planning.".to_owned(), "Scope is deny-by-default: seed targets and explicit --scope rules are the only permitted expansion.".to_owned(), format!("Goal {goal:?}, level {level}, and speed {speed} remain independent policy controls.", )];
        reasons.append(&mut level_reasons);
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
        reasons.push(match tcp_ports { TcpPortSelection::Common => "No port selection supplied; port tasks use a conservative common-set intent without expanding ports.".to_owned(), TcpPortSelection::Explicit(_) => "An explicit TCP port selection was retained in the plan and propagates to port tasks via params.".to_owned(), TcpPortSelection::All => "--all-ports is represented as ONE port task with params ports=all (65535); it never expands to 65k tasks.".to_owned() });
        let governor = crate::execution::SpeedGovernor::new(speed, budgets.max_concurrency)
            .map_err(|error| PlanError::InvalidBudget {
                field: "max_concurrency".to_owned(),
                reason: error.to_string(),
            })?;
        reasons.push(format!("Speed policy: {}.", governor.describe()));
        reasons.push(format!(
            "Budgets: max_tasks {}, max_retries {}, max_concurrency {} (effective {}), max_execution_time_ms {}, max_evidence_bytes {}, max_hosts {}.",
            budgets.max_tasks,
            budgets.max_retries,
            budgets.max_concurrency,
            governor.concurrency(),
            budgets.max_execution_time_ms,
            budgets.max_evidence_bytes,
            budgets.max_hosts,
        ));
        reasons.push(format!(
            "Host discovery policy: {}.",
            discovery_policy.describe()
        ));
        let tcp_policy =
            crate::tcp_discovery::TcpScanPolicy::new(level, goal, tcp_ports.clone(), speed);
        reasons.push(format!("TCP port policy: {}.", tcp_policy.describe()));
        let mut skipped = level_skipped;
        skipped.push(
            "Phase 6 runs real bounded host discovery plus native TCP connect port scanning (one task per target, bounded internal window); ARP/ND, UDP, HTTP/TLS/DNS, fuzzing, and service fingerprinting remain deferred."
                .to_owned(),
        );
        Ok(Self {
            targets,
            scope,
            goal,
            level,
            speed,
            profile: profile_name,
            config_sources: effective
                .sources
                .into_iter()
                .map(|path| path.display().to_string())
                .collect(),
            modules,
            tcp_ports,
            udp_requested,
            explain_requested: cli.explain,
            reasons,
            skipped,
            budgets,
            discovery_mode,
            discovery_ports,
        })
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
        let governor =
            crate::execution::SpeedGovernor::new(self.speed, self.budgets.max_concurrency)
                .map(|governor| governor.describe())
                .unwrap_or_else(|_| "invalid speed/budget combination".to_owned());
        let effective_concurrency =
            crate::execution::SpeedGovernor::new(self.speed, self.budgets.max_concurrency)
                .map(|governor| governor.concurrency())
                .unwrap_or(0);
        let retry_limit =
            crate::execution::SpeedGovernor::new(self.speed, self.budgets.max_concurrency)
                .map(|governor| governor.retry_limit())
                .unwrap_or(0);
        format!(
            "RXScan Phase 6 plan\ngoal: {:?}\nlevel: {}\nspeed: {}\nprofile: {}\ndiscovery: {}\nspeed policy: {governor}\neffective concurrency: {effective_concurrency}\nretry limit: {retry_limit}\ntask budget: {}\nretry budget: {}\nevidence budget (bytes): {}\nexecution timeout (ms): {}\nhost budget: {}\nqueue capacity: {}\ntargets:\n{targets}\nmodules:\n{modules}\ntcp ports: {:?}\ndiscovery policy: {}\ntcp policy: {}\nscope: {} allow rule(s), {} exclusion(s)\nwhy:\n{reasons}\nskipped:\n{skipped}",
            self.goal,
            self.level,
            self.speed,
            self.profile.as_deref().unwrap_or("default"),
            self.discovery_mode.as_str(),
            self.budgets.max_tasks,
            self.budgets.max_retries,
            self.budgets.max_evidence_bytes,
            self.budgets.max_execution_time_ms,
            self.budgets.max_hosts,
            self.budgets.queue_capacity(),
            self.tcp_ports,
            crate::discovery::HostDiscoveryPolicy::for_level(
                self.level,
                self.discovery_mode,
                self.speed,
                self.discovery_ports.as_deref(),
            )
            .describe(),
            crate::tcp_discovery::TcpScanPolicy::new(
                self.level,
                self.goal,
                self.tcp_ports.clone(),
                self.speed,
            )
            .describe(),
            self.scope.allowed.len(),
            self.scope.exclusions.len()
        )
    }
}

fn build_budgets(
    config: &crate::config::ConfigLayer,
    cli: &Cli,
) -> Result<crate::execution::BudgetLimits, PlanError> {
    use crate::config::{parse_bytes, parse_duration_ms};
    let mut budgets = crate::execution::BudgetLimits::default();
    let invalid = |field: &str, reason: String| PlanError::InvalidBudget {
        field: field.to_owned(),
        reason,
    };
    if let Some(value) = config.max_tasks.or(cli.max_tasks) {
        // CLI wins: if CLI present use it, else config.
        let effective = cli.max_tasks.or(config.max_tasks).unwrap_or(value);
        if effective == 0 {
            return Err(invalid("max_tasks", "must be positive".to_owned()));
        }
        budgets.max_tasks = effective;
    }
    if let Some(value) = config.max_retries.or(cli.max_retries) {
        let effective = cli.max_retries.or(config.max_retries).unwrap_or(value);
        if effective == 0 {
            return Err(invalid("max_retries", "must be positive".to_owned()));
        }
        budgets.max_retries = effective;
    }
    if let Some(value) = config.max_concurrency.or(cli.max_concurrency) {
        let effective = cli
            .max_concurrency
            .or(config.max_concurrency)
            .unwrap_or(value);
        if effective == 0 {
            return Err(invalid("max_concurrency", "must be positive".to_owned()));
        }
        let converted: usize = usize::try_from(effective)
            .map_err(|_| invalid("max_concurrency", "value too large".to_owned()))?;
        if converted == 0 {
            return Err(invalid("max_concurrency", "must be positive".to_owned()));
        }
        budgets.max_concurrency = converted;
    }
    // Duration/bytes: CLI string wins over config string.
    let execution_time_raw = cli
        .max_execution_time
        .as_deref()
        .or(config.max_execution_time.as_deref());
    if let Some(raw) = execution_time_raw {
        let millis =
            parse_duration_ms(raw).map_err(|reason| invalid("max_execution_time", reason))?;
        budgets.max_execution_time_ms = millis;
    }
    let evidence_raw = cli
        .max_evidence_bytes
        .as_deref()
        .or(config.max_evidence_bytes.as_deref());
    if let Some(raw) = evidence_raw {
        let bytes = parse_bytes(raw).map_err(|reason| invalid("max_evidence_bytes", reason))?;
        budgets.max_evidence_bytes = bytes;
    }
    if let Some(value) = config.max_hosts.or(cli.max_hosts) {
        let effective = cli.max_hosts.or(config.max_hosts).unwrap_or(value);
        if effective == 0 {
            return Err(invalid("max_hosts", "must be positive".to_owned()));
        }
        budgets.max_hosts = effective;
    }
    Ok(budgets)
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
