use clap::Parser;

use crate::plan::{ScanGoal, SpeedSetting};

/// Simple operator-facing controls. M0 compiles these into an inspectable plan.
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

    /// State the operator's intended workflow.
    #[arg(long, value_enum)]
    pub goal: Option<ScanGoal>,

    /// Investigation breadth and depth, from 1 (minimal) to 5 (deep).
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=5))]
    pub level: Option<u8>,

    /// Execution pressure; independent from --level.
    #[arg(long, value_parser = parse_speed)]
    pub speed: Option<SpeedSetting>,

    /// Select a named profile. Profile loading is introduced with the pack system.
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

    /// Plan all TCP ports. Execution arrives in M1.
    #[arg(long)]
    pub all_ports: bool,

    /// Request ICMP-focused host discovery in the future network stage.
    #[arg(long)]
    pub ping: bool,

    /// Request multi-probe host discovery in the future network stage.
    #[arg(long, conflicts_with = "ping")]
    pub discover: bool,

    /// Include selected UDP discovery in the future network stage.
    #[arg(long)]
    pub udp: bool,

    /// Print the chosen plan, reasons, and M0 limitations.
    #[arg(long)]
    pub explain: bool,
}

fn parse_speed(value: &str) -> Result<SpeedSetting, String> {
    value.parse()
}
