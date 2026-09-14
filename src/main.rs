use clap::Parser;
use rxscan::{analysis, cli::Cli, diff, plan::ScanPlan, project, report, run};

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
    if args.get(1).is_some_and(|arg| arg == "project") {
        run_project(&args);
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

fn run_project(args: &[String]) {
    let Some(command) = args.get(2).map(String::as_str) else {
        eprintln!(
            "rxscan project: usage: rxscan project create|add|summary|show|neighbors|scans|findings|changes|attention ..."
        );
        std::process::exit(2);
    };
    match command {
        "--help" | "-h" => {
            println!(
                "rxscan project create <project.rxproj>\nrxscan project add <project.rxproj> <scan.rxscan>\nrxscan project summary <project.rxproj> [--json]\nrxscan project show <project.rxproj> <entity> [--json]\nrxscan project neighbors <project.rxproj> <entity> [--depth N] [--limit N] [--json|--jsonl]\nrxscan project scans <project.rxproj> [--json]\nrxscan project findings <project.rxproj> [entity] [--limit N] [--json|--jsonl]\nrxscan project changes <project.rxproj> [entity] [--limit N] [--json|--jsonl]\nrxscan project attention <project.rxproj> [entity] [--limit N] [--json|--jsonl]"
            );
        }
        "create" => {
            let Some(path) = args.get(3) else {
                eprintln!("rxscan project create: missing project path");
                std::process::exit(2);
            };
            match project::create_project(std::path::Path::new(path)) {
                Ok(state) => println!(
                    "project created: {} revision={} network_requests=0",
                    state.project_id, state.revision
                ),
                Err(error) => {
                    eprintln!("rxscan project create: {error}");
                    std::process::exit(1);
                }
            }
        }
        "add" => {
            let (Some(project_path), Some(scan_path)) = (args.get(3), args.get(4)) else {
                eprintln!("rxscan project add: usage: rxscan project add <project> <scan>");
                std::process::exit(2);
            };
            match project::add_checkpoint(
                std::path::Path::new(project_path),
                std::path::Path::new(scan_path),
            ) {
                Ok(summary) => println!(
                    "project import duplicate={} entities_added={} relationships_added={} observations_added={} findings_added={} network_requests=0",
                    summary.duplicate_scan,
                    summary.entities_added,
                    summary.relationships_added,
                    summary.observations_added,
                    summary.findings_added
                ),
                Err(error) => {
                    eprintln!("rxscan project add: {error}");
                    std::process::exit(1);
                }
            }
        }
        "summary" => {
            let Some(path) = args.get(3) else {
                eprintln!("rxscan project summary: missing project path");
                std::process::exit(2);
            };
            let json = args[4..].iter().any(|a| a == "--json");
            match project::load_project_with_timing(std::path::Path::new(path)) {
                Ok((state, _, bytes)) if json => {
                    let summary = state.summary(bytes);
                    println!("{}", serde_json::to_string_pretty(&summary).unwrap());
                }
                Ok((state, _, bytes)) => println!("{}", project::render_summary(&state, bytes)),
                Err(error) => {
                    eprintln!("rxscan project summary: {error}");
                    std::process::exit(1);
                }
            }
        }
        "show" => {
            let (Some(path), Some(entity)) = (args.get(3), args.get(4)) else {
                eprintln!("rxscan project show: usage: rxscan project show <project> <entity>");
                std::process::exit(2);
            };
            if entity.starts_with("--") {
                eprintln!(
                    "rxscan project show: usage: rxscan project show <project> <entity> [--json]"
                );
                std::process::exit(2);
            }
            let json = args[5..].iter().any(|a| a == "--json");
            match project::load_project(std::path::Path::new(path)) {
                Ok(state) if json => match state.entities.get(entity) {
                    Some(found) => println!("{}", serde_json::to_string_pretty(found).unwrap()),
                    None => {
                        eprintln!("rxscan project show: project entity not found: {entity}");
                        std::process::exit(1);
                    }
                },
                Ok(state) => match project::render_entity(&state, entity) {
                    Ok(text) => println!("{text}"),
                    Err(error) => {
                        eprintln!("rxscan project show: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("rxscan project show: {error}");
                    std::process::exit(1);
                }
            }
        }
        "neighbors" => {
            let (Some(path), Some(entity)) = (args.get(3), args.get(4)) else {
                eprintln!(
                    "rxscan project neighbors: usage: rxscan project neighbors <project> <entity> [--depth N] [--limit N] [--json|--jsonl]"
                );
                std::process::exit(2);
            };
            let mut depth = project::DEFAULT_QUERY_DEPTH;
            let mut limit = project::DEFAULT_QUERY_LIMIT;
            let mut json = false;
            let mut jsonl = false;
            let mut iter = args[5..].iter();
            while let Some(arg) = iter.next() {
                match arg.as_str() {
                    "--depth" => {
                        let Some(value) = iter.next() else {
                            eprintln!("rxscan project neighbors: --depth requires a value");
                            std::process::exit(2);
                        };
                        depth = value.parse().unwrap_or(project::DEFAULT_QUERY_DEPTH);
                    }
                    "--limit" => {
                        let Some(value) = iter.next() else {
                            eprintln!("rxscan project neighbors: --limit requires a value");
                            std::process::exit(2);
                        };
                        limit = value.parse().unwrap_or(project::DEFAULT_QUERY_LIMIT);
                    }
                    "--json" => json = true,
                    "--jsonl" => jsonl = true,
                    _ => {
                        eprintln!("rxscan project neighbors: unsupported option {arg}");
                        std::process::exit(2);
                    }
                }
            }
            match project::load_project(std::path::Path::new(path)) {
                Ok(state) if jsonl => {
                    if let Err(error) = project::render_neighbors_jsonl(
                        &state,
                        entity,
                        depth,
                        limit,
                        std::io::stdout(),
                    ) {
                        eprintln!("rxscan project neighbors: {error}");
                        std::process::exit(1);
                    }
                }
                Ok(state) if json => match state.neighbors(entity, depth, limit) {
                    Ok(result) => println!("{}", serde_json::to_string_pretty(&result).unwrap()),
                    Err(error) => {
                        eprintln!("rxscan project neighbors: {error}");
                        std::process::exit(1);
                    }
                },
                Ok(state) => match state.neighbors(entity, depth, limit) {
                    Ok(result) => {
                        println!(
                            "neighbors total={} emitted={} truncated={} network_requests=0",
                            result.results_total, result.results_emitted, result.truncated
                        );
                        for record in result.records {
                            println!(
                                "{} {:?} {}",
                                record.depth, record.relationship_kind, record.entity_id
                            );
                        }
                    }
                    Err(error) => {
                        eprintln!("rxscan project neighbors: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("rxscan project neighbors: {error}");
                    std::process::exit(1);
                }
            }
        }
        "scans" => {
            let Some(path) = args.get(3) else {
                eprintln!("rxscan project scans: missing project path");
                std::process::exit(2);
            };
            let json = args[4..].iter().any(|a| a == "--json");
            match project::load_project(std::path::Path::new(path)) {
                Ok(state) if json => {
                    let scans: Vec<_> = state.scans.values().collect();
                    println!("{}", serde_json::to_string_pretty(&scans).unwrap());
                }
                Ok(state) => {
                    for scan in state.scans.values() {
                        println!(
                            "{} sequence={} entities={} relationships={}",
                            scan.scan_id.0,
                            scan.import_sequence,
                            scan.entity_count,
                            scan.relationship_count
                        );
                    }
                }
                Err(error) => {
                    eprintln!("rxscan project scans: {error}");
                    std::process::exit(1);
                }
            }
        }
        "findings" | "changes" | "attention" => {
            let Some(path) = args.get(3) else {
                eprintln!("rxscan project {command}: missing project path");
                std::process::exit(2);
            };
            // Optional entity filter: args[4] when present and not a flag.
            let entity: Option<String> = args.get(4).and_then(|v| {
                if v.starts_with("--") {
                    None
                } else {
                    Some(v.clone())
                }
            });
            let start = if entity.is_some() { 5 } else { 4 };
            let mut limit = project::DEFAULT_QUERY_LIMIT;
            let mut json = false;
            let mut jsonl = false;
            let mut iter = args.get(start..).unwrap_or(&[]).iter();
            while let Some(arg) = iter.next() {
                match arg.as_str() {
                    "--limit" => {
                        let Some(value) = iter.next() else {
                            eprintln!("rxscan project {command}: --limit requires a value");
                            std::process::exit(2);
                        };
                        limit = value.parse().unwrap_or(project::DEFAULT_QUERY_LIMIT);
                    }
                    "--json" => json = true,
                    "--jsonl" => jsonl = true,
                    other if other.starts_with("--") && entity.is_none() && start == 4 => {
                        // Already handled flags above; unknown flags rejected.
                        eprintln!("rxscan project {command}: unsupported option {other}");
                        std::process::exit(2);
                    }
                    other => {
                        eprintln!("rxscan project {command}: unsupported option {other}");
                        std::process::exit(2);
                    }
                }
            }
            let state = match project::load_project(std::path::Path::new(path)) {
                Ok(state) => state,
                Err(error) => {
                    eprintln!("rxscan project {command}: {error}");
                    std::process::exit(1);
                }
            };
            let entity_ref = entity.as_deref();
            match command {
                "findings" => {
                    if jsonl {
                        match state.findings_query(entity_ref, limit) {
                            Ok(result) => {
                                if let Err(error) = project::render_records_jsonl(
                                    "project_finding",
                                    &result,
                                    std::io::stdout(),
                                ) {
                                    eprintln!("rxscan project findings: {error}");
                                    std::process::exit(1);
                                }
                            }
                            Err(error) => {
                                eprintln!("rxscan project findings: {error}");
                                std::process::exit(1);
                            }
                        }
                    } else if json {
                        match state.findings_query(entity_ref, limit) {
                            Ok(result) => {
                                println!("{}", serde_json::to_string_pretty(&result).unwrap())
                            }
                            Err(error) => {
                                eprintln!("rxscan project findings: {error}");
                                std::process::exit(1);
                            }
                        }
                    } else {
                        match project::render_findings(&state, entity_ref, limit) {
                            Ok(text) => print!("{text}"),
                            Err(error) => {
                                eprintln!("rxscan project findings: {error}");
                                std::process::exit(1);
                            }
                        }
                    }
                }
                "changes" => {
                    if jsonl {
                        match state.changes_query(entity_ref, limit) {
                            Ok(result) => {
                                if let Err(error) = project::render_records_jsonl(
                                    "project_change",
                                    &result,
                                    std::io::stdout(),
                                ) {
                                    eprintln!("rxscan project changes: {error}");
                                    std::process::exit(1);
                                }
                            }
                            Err(error) => {
                                eprintln!("rxscan project changes: {error}");
                                std::process::exit(1);
                            }
                        }
                    } else if json {
                        match state.changes_query(entity_ref, limit) {
                            Ok(result) => {
                                println!("{}", serde_json::to_string_pretty(&result).unwrap())
                            }
                            Err(error) => {
                                eprintln!("rxscan project changes: {error}");
                                std::process::exit(1);
                            }
                        }
                    } else {
                        match project::render_changes(&state, entity_ref, limit) {
                            Ok(text) => print!("{text}"),
                            Err(error) => {
                                eprintln!("rxscan project changes: {error}");
                                std::process::exit(1);
                            }
                        }
                    }
                }
                _ => {
                    if jsonl {
                        match state.attention_query(entity_ref, limit) {
                            Ok(result) => {
                                if let Err(error) = project::render_records_jsonl(
                                    "project_attention",
                                    &result,
                                    std::io::stdout(),
                                ) {
                                    eprintln!("rxscan project attention: {error}");
                                    std::process::exit(1);
                                }
                            }
                            Err(error) => {
                                eprintln!("rxscan project attention: {error}");
                                std::process::exit(1);
                            }
                        }
                    } else if json {
                        match state.attention_query(entity_ref, limit) {
                            Ok(result) => {
                                println!("{}", serde_json::to_string_pretty(&result).unwrap())
                            }
                            Err(error) => {
                                eprintln!("rxscan project attention: {error}");
                                std::process::exit(1);
                            }
                        }
                    } else {
                        match project::render_attention(&state, entity_ref, limit) {
                            Ok(text) => print!("{text}"),
                            Err(error) => {
                                eprintln!("rxscan project attention: {error}");
                                std::process::exit(1);
                            }
                        }
                    }
                }
            }
        }
        _ => {
            eprintln!("rxscan project: unknown command {command}");
            std::process::exit(2);
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
