use clap::Parser;
use rxscan::{analysis, cli::Cli, diff, plan::ScanPlan, report, run};

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).is_some_and(|arg| arg == "diff") {
        run_diff(&args);
        return;
    }
    if args.get(1).is_some_and(|arg| arg == "analyze") {
        run_analyze(&args);
        return;
    }
    if args.get(1).is_some_and(|arg| arg == "report") {
        run_report(&args);
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

fn run_report(args: &[String]) {
    let mut format = report::ReportFormat::Human;
    let mut summary_only = false;
    let mut analysis = false;
    let mut diff_path: Option<String> = None;
    let mut output_path: Option<String> = None;
    let mut top = report::DEFAULT_REPORT_TOP_N;
    let mut checkpoint: Option<String> = None;
    let mut iter = args[2..].iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!(
                    "rxscan report [--format human|json|jsonl|raw] [--summary-only] [--top N] [--diff <old.rxscan>] [--analysis] [--output <path>] <scan.rxscan>"
                );
                return;
            }
            "--format" => {
                let Some(value) = iter.next() else {
                    eprintln!("rxscan report: --format requires a value");
                    std::process::exit(2);
                };
                match report::ReportFormat::parse(value) {
                    Ok(parsed) => format = parsed,
                    Err(error) => {
                        eprintln!("rxscan report: {error}");
                        std::process::exit(2);
                    }
                }
            }
            "--json" => format = report::ReportFormat::Json,
            "--jsonl" => format = report::ReportFormat::Jsonl,
            "--raw" => format = report::ReportFormat::Raw,
            "--summary-only" => summary_only = true,
            "--analysis" => analysis = true,
            "--diff" => {
                let Some(path) = iter.next() else {
                    eprintln!("rxscan report: --diff requires a baseline checkpoint path");
                    std::process::exit(2);
                };
                diff_path = Some(path.to_owned());
            }
            "--output" => {
                let Some(path) = iter.next() else {
                    eprintln!("rxscan report: --output requires a path");
                    std::process::exit(2);
                };
                output_path = Some(path.to_owned());
            }
            "--top" => {
                let Some(value) = iter.next() else {
                    eprintln!("rxscan report: --top requires a value");
                    std::process::exit(2);
                };
                match value.parse::<usize>() {
                    Ok(value) if value <= report::MAX_REPORT_TOP_N => top = value,
                    _ => {
                        eprintln!(
                            "rxscan report: --top must be an integer from 0 to {}",
                            report::MAX_REPORT_TOP_N
                        );
                        std::process::exit(2);
                    }
                }
            }
            value if checkpoint.is_none() => checkpoint = Some(value.to_owned()),
            _ => {
                eprintln!(
                    "rxscan report: usage: rxscan report [--format human|json|jsonl|raw] [--summary-only] [--top N] [--diff <old.rxscan>] [--analysis] [--output <path>] <scan.rxscan>"
                );
                std::process::exit(2);
            }
        }
    }
    let Some(current) = checkpoint else {
        eprintln!(
            "rxscan report: usage: rxscan report [--format human|json|jsonl|raw] [--summary-only] [--top N] [--diff <old.rxscan>] [--analysis] [--output <path>] <scan.rxscan>"
        );
        std::process::exit(2);
    };
    let options = report::ReportOptions {
        format,
        summary_only,
        top_n: top,
    };
    let current_path = std::path::Path::new(&current);
    let diff_path_ref = diff_path.as_deref().map(std::path::Path::new);
    let model =
        match report::report_checkpoint(current_path, diff_path_ref, analysis, options.clone()) {
            Ok(model) => model,
            Err(error) => {
                eprintln!("rxscan report: {error}");
                std::process::exit(1);
            }
        };
    let bytes = match report::render_to_bytes(&model, &options) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("rxscan report: {error}");
            std::process::exit(1);
        }
    };
    if let Some(path) = output_path {
        let mut inputs = vec![current_path];
        if let Some(diff_path) = diff_path_ref {
            inputs.push(diff_path);
        }
        if let Err(error) = report::write_output(std::path::Path::new(&path), &bytes, &inputs) {
            eprintln!("rxscan report: {error}");
            std::process::exit(1);
        }
    } else if let Err(error) = std::io::Write::write_all(&mut std::io::stdout(), &bytes) {
        if error.kind() != std::io::ErrorKind::BrokenPipe {
            eprintln!("rxscan report: {error}");
            std::process::exit(1);
        }
    }
}

fn run_analyze(args: &[String]) {
    let mut json = false;
    let mut diff_path: Option<String> = None;
    let mut checkpoint: Option<String> = None;
    let mut iter = args[2..].iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" | "--jsonl" => json = true,
            "--diff" => {
                let Some(path) = iter.next() else {
                    eprintln!("rxscan analyze: --diff requires a baseline checkpoint path");
                    std::process::exit(2);
                };
                diff_path = Some(path.to_owned());
            }
            value if checkpoint.is_none() => checkpoint = Some(value.to_owned()),
            _ => {
                eprintln!(
                    "rxscan analyze: usage: rxscan analyze [--json|--jsonl] [--diff <old.rxscan>] <current.rxscan>"
                );
                std::process::exit(2);
            }
        }
    }
    let Some(current) = checkpoint else {
        eprintln!(
            "rxscan analyze: usage: rxscan analyze [--json|--jsonl] [--diff <old.rxscan>] <current.rxscan>"
        );
        std::process::exit(2);
    };
    let options = analysis::AnalysisOptions::default();
    let result = if let Some(old) = diff_path {
        match diff::diff_checkpoints(
            std::path::Path::new(&old),
            std::path::Path::new(&current),
            diff::DiffOptions::default(),
        ) {
            Ok((diff_report, _, _, _)) => analysis::analyze_checkpoint_with_diff(
                std::path::Path::new(&current),
                &diff_report,
                options,
            )
            .map(|(report, _)| report),
            Err(error) => {
                eprintln!("rxscan analyze: {error}");
                std::process::exit(1);
            }
        }
    } else {
        analysis::analyze_checkpoint(std::path::Path::new(&current), options)
            .map(|(report, _)| report)
    };
    match result {
        Ok(report) if json => match analysis::to_json(&report) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("rxscan analyze: {error}");
                std::process::exit(1);
            }
        },
        Ok(report) => println!("{}", analysis::human_summary(&report)),
        Err(error) => {
            eprintln!("rxscan analyze: {error}");
            std::process::exit(1);
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
