use clap::Parser;

use crate::plan::SpeedSetting;

/// Operator-facing scanner controls.
#[derive(Debug, Clone, Parser)]
#[command(name = "rxscan", version, about = "Reactive Recon Scanner")]
pub struct Cli {
    /// A target: IPv4, IPv6, hostname, URL, CIDR, or '-' for standard input.
    #[arg(value_name = "TARGET", allow_hyphen_values = true)]
    pub target: Option<String>,

    /// Read one target per line from a file. Blank lines and # comments are ignored.
    #[arg(long, value_name = "FILE")]
    pub targets: Option<std::path::PathBuf>,

    /// Load a global RXScan TOML configuration file.
    #[arg(long, value_name = "FILE")]
    pub config: Option<std::path::PathBuf>,

    /// Load a project RXScan TOML configuration file. It overrides --config.
    #[arg(long, value_name = "FILE")]
    pub project_config: Option<std::path::PathBuf>,

    /// State the operator's intended workflow: one of
    /// recon, discover, ports, services, web, full.
    /// Historical names (discovery, service-map, inventory, baseline,
    /// monitoring, web-discovery, api, api-discovery, content, fuzz,
    /// research, custom) remain accepted as aliases and map to the
    /// canonical workflow shown by --explain.
    #[arg(long, value_name = "GOAL", value_parser = parse_goal)]
    pub goal: Option<String>,

    /// Investigation breadth and depth, from 1 (minimal) to 5 (deep).
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=5))]
    pub level: Option<u8>,

    /// Execution pressure; independent from --level.
    #[arg(long, value_parser = parse_speed)]
    pub speed: Option<SpeedSetting>,

    /// Select a named profile from configuration.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Permit an additional exact host, IP, URL host, or CIDR scope.
    #[arg(long = "scope", value_name = "TARGET_OR_CIDR")]
    pub scope: Vec<String>,

    /// Exclude an exact host, IP, URL host, or CIDR from scope.
    #[arg(long, value_name = "TARGET_OR_CIDR")]
    pub exclude: Vec<String>,

    /// Select TCP ports (for example: 22,80,443 or 8000-8100).
    #[arg(long, value_name = "PORTS", conflicts_with = "all_ports")]
    pub ports: Option<String>,

    /// Scan all TCP ports as one bounded TCP scan task.
    #[arg(long)]
    pub all_ports: bool,

    /// Request ICMP-focused host discovery.
    #[arg(long)]
    pub ping: bool,

    /// Request multi-probe host discovery.
    #[arg(long, conflicts_with = "ping")]
    pub discover: bool,

    /// Request UDP discovery. Not implemented: rejected fail-fast with a
    /// clear error instead of planning work that could never execute.
    #[arg(long)]
    pub udp: bool,

    /// Stream a managed content-discovery candidate file.
    #[arg(short = 'w', long = "wordlist", value_name = "FILE")]
    pub wordlist: Option<std::path::PathBuf>,

    /// Print the chosen plan, reasons, budgets, and excluded capabilities.
    #[arg(long)]
    pub explain: bool,

    /// Cap the number of admitted tasks (1..=100000). CLI wins over configs.
    #[arg(long, value_name = "N", value_parser = parse_positive_u64)]
    pub max_tasks: Option<u64>,

    /// Cap the number of retries (1..=100000).
    #[arg(long, value_name = "N", value_parser = parse_positive_u64)]
    pub max_retries: Option<u64>,

    /// Cap scheduler concurrency (1..=64).
    #[arg(long, value_name = "N", value_parser = parse_positive_u64)]
    pub max_concurrency: Option<u64>,

    /// Cap hosts generated from CIDR targets (1..=100000, default 256).
    /// Large scopes stay bounded; Level 5 never means unbounded.
    #[arg(long, value_name = "N", value_parser = parse_positive_u64)]
    pub max_hosts: Option<u64>,

    /// Cap total execution time (e.g. 60s, 5m, 1h, 500ms, or bare seconds).
    #[arg(long, value_name = "DURATION")]
    pub max_execution_time: Option<String>,

    /// Cap retained evidence bytes (e.g. 67108864, 64MiB, 10MB).
    #[arg(long, value_name = "BYTES")]
    pub max_evidence_bytes: Option<String>,

    /// Write typed JSONL output to a file (created/truncated; errors are reported, never panicked).
    #[arg(long, value_name = "PATH")]
    pub output: Option<std::path::PathBuf>,

    /// Save a bounded checkpoint after execution.
    #[arg(long, value_name = "PATH")]
    pub checkpoint: Option<std::path::PathBuf>,

    /// Resume from a bounded checkpoint. Target/scope/level/goal come from the checkpoint.
    #[arg(long, value_name = "PATH")]
    pub resume: Option<std::path::PathBuf>,

    /// Output format. Only `jsonl` is supported for scan streams.
    #[arg(long, value_name = "FORMAT")]
    pub format: Option<String>,
}

fn parse_goal(value: &str) -> Result<String, String> {
    // Validate eagerly so typos fail fast with the canonical list; the
    // raw text is retained so --explain can show alias mapping.
    crate::plan::ScanGoal::parse(value)?;
    Ok(value.to_owned())
}

fn parse_speed(value: &str) -> Result<SpeedSetting, String> {
    value.parse()
}

fn parse_positive_u64(value: &str) -> Result<u64, String> {
    let parsed: u64 = value
        .parse()
        .map_err(|_| format!("expected a positive integer, got '{value}'"))?;
    if parsed == 0 {
        return Err(format!("value must be positive, got '{value}'"));
    }
    Ok(parsed)
}
