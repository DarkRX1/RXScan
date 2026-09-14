use clap::Parser;
use rxscan::{cli::Cli, diff, plan::ScanPlan, run};

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).is_some_and(|arg| arg == "diff") {
        run_diff(&args);
        return;
    }
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

fn run_diff(args: &[String]) {
    let mut json = false;
    let mut summary_only = false;
    let mut paths = Vec::new();
    for arg in &args[2..] {
        match arg.as_str() {
            "--json" => json = true,
            "--summary-only" => summary_only = true,
            "--jsonl" => json = true,
            value => paths.push(value.to_owned()),
        }
    }
    if paths.len() != 2 {
        eprintln!(
            "rxscan diff: usage: rxscan diff [--json|--jsonl] [--summary-only] <old.rxscan> <new.rxscan>"
        );
        std::process::exit(2);
    }
    let options = diff::DiffOptions {
        summary_only,
        max_records: diff::MAX_DIFF_RECORDS,
    };
    match diff::diff_checkpoints(
        std::path::Path::new(&paths[0]),
        std::path::Path::new(&paths[1]),
        options,
    ) {
        Ok((report, _, _, _)) if json => match diff::to_json(&report) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("rxscan diff: {error}");
                std::process::exit(1);
            }
        },
        Ok((report, _, _, _)) => println!("{}", diff::human_summary(&report)),
        Err(error) => {
            eprintln!("rxscan diff: {error}");
            std::process::exit(1);
        }
    }
}
