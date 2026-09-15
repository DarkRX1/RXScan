use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::ScanPlanId;
use crate::{
    cli::Cli,
    config::{ConfigError, EffectiveConfig},
    scope::{ScopeError, ScopePolicy},
    target::{TargetError, TargetSpec, read_target_source},
};

/// Canonical operator workflows.
///
/// Six concepts, each with distinct execution semantics (see `level.rs` for
/// initial-task selection and `decision.rs` for evidence-triggered
/// follow-up gating):
///
/// * `Recon` (default): general reconnaissance — host + port discovery,
///   service identification, and evidence-driven web/content follow-ups.
/// * `Discover`: host and network discovery — host + port discovery and DNS
///   observations, but never service identification or deeper follow-ups.
/// * `Ports`: port discovery only — host + port discovery, no follow-ups
///   beyond the port scan itself.
/// * `Services`: port discovery + service identification — service
///   follow-ups, but no web/content/crawl derivation.
/// * `Web`: web-focused reconnaissance — initial HTTP roots plus
///   evidence-driven web/content follow-ups.
/// * `Full`: broadest bounded reconnaissance — every executable module plus
///   fuzz follow-ups where evidence permits.
///
/// Historical goal names remain accepted as compatibility aliases and map
/// to canonical workflows (shown by `--explain`):
/// `inventory`→`recon`; `service-map`/`service`→`services`;
/// `discovery`/`baseline`/`monitoring`→`discover`;
/// `web-discovery`/`api`/`api-discovery`/`content`→`web`;
/// `custom`/`research`/`fuzz`→`full`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ScanGoal {
    #[default]
    #[serde(alias = "inventory")]
    Recon,
    #[serde(alias = "discovery", alias = "baseline", alias = "monitoring")]
    Discover,
    #[serde(alias = "port")]
    Ports,
    #[serde(alias = "service-map", alias = "service", alias = "servicemap")]
    Services,
    #[serde(
        alias = "web-discovery",
        alias = "webdiscovery",
        alias = "api",
        alias = "api-discovery",
        alias = "apidiscovery",
        alias = "content"
    )]
    Web,
    #[serde(alias = "custom", alias = "research", alias = "fuzz")]
    Full,
}

impl ScanGoal {
    /// Canonical workflow names shown in help and `--explain`.
    pub const CANONICAL: &'static [&'static str] =
        &["recon", "discover", "ports", "services", "web", "full"];

    /// Compatibility aliases accepted wherever a goal is parsed.
    pub const ALIASES: &'static [(&'static str, &'static str)] = &[
        ("inventory", "recon"),
        ("discovery", "discover"),
        ("baseline", "discover"),
        ("monitoring", "discover"),
        ("port", "ports"),
        ("service-map", "services"),
        ("service", "services"),
        ("web-discovery", "web"),
        ("api", "web"),
        ("api-discovery", "web"),
        ("content", "web"),
        ("custom", "full"),
        ("research", "full"),
        ("fuzz", "full"),
    ];

    /// Parse a goal name (canonical or alias) as the CLI/TOML layers accept it.
    pub fn parse(value: &str) -> Result<Self, String> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "recon" | "inventory" => Ok(Self::Recon),
            "discover" | "discovery" | "baseline" | "monitoring" => Ok(Self::Discover),
            "ports" | "port" => Ok(Self::Ports),
            "services" | "service" | "service-map" | "servicemap" => Ok(Self::Services),
            "web" | "web-discovery" | "webdiscovery" | "api" | "api-discovery" | "apidiscovery"
            | "content" => Ok(Self::Web),
            "full" | "custom" | "research" | "fuzz" => Ok(Self::Full),
            _ => Err(format!(
                "invalid goal '{value}': expected one of {} (aliases: {})",
                Self::CANONICAL.join(", "),
                Self::ALIASES
                    .iter()
                    .map(|(alias, _)| *alias)
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }

    /// Canonical kebab-case name (matches serde serialization).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recon => "recon",
            Self::Discover => "discover",
            Self::Ports => "ports",
            Self::Services => "services",
            Self::Web => "web",
            Self::Full => "full",
        }
    }

    /// Whether `raw` was an alias (returns its canonical target).
    pub fn alias_target(raw: &str) -> Option<&'static str> {
        let normalized = raw.trim().to_ascii_lowercase();
        Self::ALIASES
            .iter()
            .find(|(alias, _)| *alias == normalized)
            .map(|(_, canonical)| *canonical)
    }
}

impl std::str::FromStr for ScanGoal {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl std::fmt::Display for ScanGoal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
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
    /// Raw `--goal` text when the operator used a compatibility alias
    /// (e.g. `service-map` for canonical `services`). `None` for canonical
    /// names, config-supplied goals, and resumed plans. `--explain` shows it.
    /// Skipped on the wire when absent so pre-alias checkpoints keep the
    /// exact bytes (and plan IDs) they were saved with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal_alias: Option<String>,
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
    /// Phase 11: optional streamed managed content candidate file.
    #[serde(default)]
    pub content_wordlist: Option<std::path::PathBuf>,
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
    #[error(
        "invalid goal '{0}': expected a canonical workflow (recon, discover, ports, services, web, full) or a documented alias"
    )]
    InvalidGoal(String),
    #[error(
        "--udp requests UDP discovery, which is not implemented in this build (TCP-only scanner); omit --udp"
    )]
    UdpNotImplemented,
    #[error("--all-ports conflicts with a configured port selection")]
    AllPortsConflict,
    #[error("invalid budget for '{field}': {reason}")]
    InvalidBudget { field: String, reason: String },
    #[error("invalid --format '{0}': only 'jsonl' is supported in Phase 4")]
    InvalidFormat(String),
    #[error("unreadable --wordlist file '{0}': provide a readable candidate file")]
    UnreadableWordlist(String),
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
        let (goal, goal_alias) = match (cli.goal.as_deref(), config.goal) {
            (Some(raw), _) => {
                let parsed =
                    ScanGoal::parse(raw).map_err(|_| PlanError::InvalidGoal(raw.to_owned()))?;
                let alias = ScanGoal::alias_target(raw).map(|_| raw.to_owned());
                (parsed, alias)
            }
            (None, Some(configured)) => (configured, None),
            (None, None) => (ScanGoal::default(), None),
        };
        let level = cli.level.or(config.level).unwrap_or(3);
        let speed = cli.speed.or(config.speed).unwrap_or_default();
        let profile_name = cli.profile.clone().or(config.profile.clone());
        let content_wordlist = cli.wordlist.clone().or(config.wordlist.clone());
        // Phase 20: fail fast on an unreadable candidate file. Without this
        // a typo'd path degrades to zero content tasks with zero feedback
        // whenever no web surface proposes content work. A directory or
        // missing path is rejected here (exit 2); read errors mid-stream
        // remain bounded task failures.
        if let Some(path) = &content_wordlist {
            let readable = std::fs::metadata(path)
                .map(|meta| meta.is_file())
                .unwrap_or(false);
            if !readable {
                return Err(PlanError::UnreadableWordlist(path.display().to_string()));
            }
        }
        let host_requested = cli.ping || cli.discover;
        let udp_requested = cli.udp;
        if udp_requested {
            // Fail fast: the scheduler has no UDP executor, so planning a
            // UDP intent task would only produce a predictable `Skipped`.
            return Err(PlanError::UdpNotImplemented);
        }
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
        let mut reasons = vec!["Every input is normalized into TargetSpec before planning.".to_owned(), "Scope is deny-by-default: seed targets and explicit --scope rules are the only permitted expansion.".to_owned(), format!("Workflow {goal} (level {level}) and speed {speed} remain independent policy controls.", )];
        if let Some(alias) = goal_alias.as_deref() {
            reasons.push(format!(
                "Requested goal '{alias}' is a compatibility alias for canonical workflow '{goal}'; execution uses '{goal}'."
            ));
        }
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
        reasons.push(match tcp_ports { TcpPortSelection::Common => "No port selection supplied; TCP discovery uses the conservative level-derived common-port policy.".to_owned(), TcpPortSelection::Explicit(_) => "An explicit TCP port selection is retained exactly and overrides goal/default port policy.".to_owned(), TcpPortSelection::All => "--all-ports is represented as ONE port task with params ports=all (65535); it never expands to 65k tasks.".to_owned() });
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
        let service_policy = crate::service_probe::ServicePolicy::new(level, goal, speed);
        reasons.push(format!(
            "Service probe policy: {}.",
            service_policy.describe()
        ));
        reasons.push(format!(
            "Web probe policy: {}.",
            crate::web::WebPolicy::new(level, goal, speed).describe()
        ));
        reasons.push(format!(
            "Content discovery policy: {}.",
            crate::content::ContentDiscoveryPolicy::new(level, goal, speed).describe()
        ));
        let mut skipped = level_skipped;
        skipped.push(
            "Current execution includes bounded host discovery, TCP connect port scanning, service probing, DNS observations, HTTP/1.1 web observations, crawling, baseline checks, managed content discovery, and inert contextual GET query fuzzing where evidence permits. UDP scanning, OS/device fingerprinting, POST workflows, JavaScript execution, browser-assisted inspection, cipher-suite enumeration, and vulnerability assessment are not implemented in this build."
                .to_owned(),
        );
        Ok(Self {
            targets,
            scope,
            goal,
            goal_alias,
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
            content_wordlist,
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
        let initial = crate::level::describe_initial_tasks(self.goal, self.level);
        let followups = crate::level::describe_followups(self.goal, self.level);
        let unavailable = crate::level::describe_unavailable();
        format!(
            "RXScan plan\nworkflow: {}{}\nlevel: {}\nspeed: {}\nprofile: {}\ndiscovery: {}\nspeed policy: {governor}\neffective concurrency: {effective_concurrency}\nretry limit: {retry_limit}\ntask budget: {}\nretry budget: {}\nevidence budget (bytes): {}\nexecution timeout (ms): {}\nhost budget: {}\nqueue capacity: {}\ntargets:\n{targets}\nmodules:\n{modules}\ninitial tasks (selected and executable):\n{initial}\nevidence-triggered follow-ups:\n{followups}\nunavailable (not implemented in this build):\n{unavailable}\ntcp ports: {:?}\ndiscovery policy: {}\ntcp policy: {}\nservice policy: {}\nweb policy: {}\ncontent policy: {}\nscope: {} allow rule(s), {} exclusion(s)\nwhy:\n{reasons}\nskipped:\n{skipped}",
            self.goal,
            self.goal_alias
                .as_deref()
                .map_or(String::new(), |alias| format!(
                    " (requested '{alias}' mapped here)"
                )),
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
            crate::service_probe::ServicePolicy::new(self.level, self.goal, self.speed).describe(),
            crate::web::WebPolicy::new(self.level, self.goal, self.speed).describe(),
            crate::content::ContentDiscoveryPolicy::new(self.level, self.goal, self.speed)
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
