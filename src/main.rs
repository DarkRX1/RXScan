use clap::Parser;
use rxscan::{cli::Cli, plan::ScanPlan};

fn main() {
    let cli = Cli::parse();
    match ScanPlan::compile(cli) {
        Ok(plan) => {
            if plan.explain_requested {
                println!("{}", plan.explain());
            } else {
                println!("RXScan plan compiled for {} target(s).", plan.targets.len());
                println!("Run with --explain to inspect the selected M0 plan.");
                println!("Network execution is introduced in M1.");
            }
        }
        Err(error) => {
            eprintln!("rxscan: {error}");
            std::process::exit(2);
        }
    }
}
