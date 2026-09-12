use clap::Parser;
use rxscan::{cli::Cli, plan::ScanPlan, run};

fn main() {
    let cli = Cli::parse();
    let explain_only = cli.explain;
    if explain_only {
        match ScanPlan::compile(cli) {
            Ok(plan) => {
                println!("{}", plan.explain());
            }
            Err(error) => {
                eprintln!("rxscan: {error}");
                std::process::exit(2);
            }
        }
        return;
    }
    match run::execute(cli) {
        Ok(report) => {
            // If JSONL went to stdout via --format jsonl, the JSONL is already
            // on stdout; still print the human summary to stderr to keep
            // stdout pure JSONL.
            if report.jsonl_bytes > 0 && report.output_path.is_none() {
                eprintln!("{}", run::human_summary(&report));
            } else {
                println!("{}", run::human_summary(&report));
                if report.output_path.is_none() {
                    println!("Run with --explain to inspect the effective Phase 8 plan.");
                    println!(
                        "Service probing uses bounded native handshakes (no auth); use --output <path> for typed JSONL."
                    );
                }
            }
        }
        Err(error) => {
            eprintln!("rxscan: {error}");
            std::process::exit(error.exit_code());
        }
    }
}
