use clap::Parser;
use rxscan::{analysis, cli::Cli, diff, plan::ScanPlan, project, report, run};

/// Phase 20 stdio contract.
///
/// * Machine-readable stdout (`--json`/`--jsonl`/`--raw`, JSONL streams) is
///   never polluted by diagnostics; warnings/errors go to stderr.
/// * A closed stdout pipe (e.g. `rxscan ... | head -c 100`) exits silently
///   with status 0 instead of panicking with "failed printing to stdout".
///   Other stdout errors report to stderr and exit 1.
/// * Diagnostics themselves never panic, even if stderr is closed.
/// * Exit codes: 0 success; 2 CLI/configuration/usage error; 1 invalid
///   input/state or runtime failure. Death by SIGINT is the OS default
///   (shell reports 128+SIGINT); scans use atomic file replacement so an
///   interrupted run cannot corrupt prior valid outputs.
macro_rules! out_line {
    ($($arg:tt)*) => {{
        $crate::stdout_write(&format!("{}\n", format!($($arg)*)));
    }};
}
macro_rules! out {
    ($($arg:tt)*) => {{
        $crate::stdout_write(&format!($($arg)*));
    }};
}
macro_rules! err {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

#[doc(hidden)]
pub fn stdout_write(text: &str) {
    use std::io::Write as _;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    if let Err(error) = handle
        .write_all(text.as_bytes())
        .and_then(|()| handle.flush())
    {
        if error.kind() == std::io::ErrorKind::BrokenPipe {
            // Consumer went away (e.g. `| head`): silent clean exit.
            std::process::exit(0);
        }
        let _ = writeln!(std::io::stderr(), "rxscan: failed to write stdout: {error}");
        std::process::exit(1);
    }
}

/// Shared stdout-stream error policy for project JSONL renderers: a closed
/// pipe exits silently with status 0 (like [`stdout_write`]); any other
/// output failure reports to stderr and exits 1. Never panics.
fn exit_on_output_error(context: &str, error: project::ProjectError) -> ! {
    if let project::ProjectError::Io(io) = &error {
        if io.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(0);
        }
    }
    err!("{context}: {error}");
    std::process::exit(1);
}

fn main() {
    // Phase 20: `std::env::args()` panics on non-UTF-8 input (exit 101 +
    // backtrace). Collect as `OsString` and fail cleanly instead; clap
    // itself already handles non-UTF-8 safely once we get past dispatch.
    let args = std::env::args_os().collect::<Vec<_>>();
    let args = match args
        .into_iter()
        .map(|arg| {
            arg.into_string()
                .map_err(|_| "command-line argument is not valid UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(args) => args,
        Err(error) => {
            err!("rxscan: {error}");
            std::process::exit(2);
        }
    };
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
                out_line!("{}", plan.explain());
            }
            Err(error) => {
                err!("rxscan: {error}");
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
                err!("{}", run::human_summary(&report));
            } else {
                out_line!("{}", run::human_summary(&report));
                if report.output_path.is_none() {
                    out_line!("Run with --explain to inspect the effective Phase 8 plan.");
                    out_line!(
                        "Service probing uses bounded native handshakes (no auth); use --output <path> for typed JSONL."
                    );
                }
            }
        }
        Err(error) => {
            err!("rxscan: {error}");
            std::process::exit(error.exit_code());
        }
    }
}

fn run_project(args: &[String]) {
    let Some(command) = args.get(2).map(String::as_str) else {
        err!(
            "rxscan project: usage: rxscan project create|add|summary|show|neighbors|scans|findings|changes|attention ..."
        );
        std::process::exit(2);
    };
    match command {
        "--help" | "-h" => {
            out_line!(
                "rxscan project create <project.rxproj>\nrxscan project add <project.rxproj> <scan.rxscan>\nrxscan project summary <project.rxproj> [--json]\nrxscan project show <project.rxproj> <entity> [--json]\nrxscan project neighbors <project.rxproj> <entity> [--depth N] [--limit N] [--json|--jsonl]\nrxscan project scans <project.rxproj> [--json]\nrxscan project findings <project.rxproj> [entity] [--limit N] [--json|--jsonl]\nrxscan project changes <project.rxproj> [entity] [--limit N] [--json|--jsonl]\nrxscan project attention <project.rxproj> [entity] [--limit N] [--json|--jsonl]"
            );
        }
        "create" => {
            let Some(path) = args.get(3) else {
                err!("rxscan project create: missing project path");
                std::process::exit(2);
            };
            match project::create_project(std::path::Path::new(path)) {
                Ok(state) => out_line!(
                    "project created: {} revision={} network_requests=0",
                    state.project_id,
                    state.revision
                ),
                Err(error) => {
                    err!("rxscan project create: {error}");
                    std::process::exit(1);
                }
            }
        }
        "add" => {
            let (Some(project_path), Some(scan_path)) = (args.get(3), args.get(4)) else {
                err!("rxscan project add: usage: rxscan project add <project> <scan>");
                std::process::exit(2);
            };
            match project::add_checkpoint(
                std::path::Path::new(project_path),
                std::path::Path::new(scan_path),
            ) {
                Ok(summary) => out_line!(
                    "project import duplicate={} entities_added={} relationships_added={} observations_added={} findings_added={} network_requests=0",
                    summary.duplicate_scan,
                    summary.entities_added,
                    summary.relationships_added,
                    summary.observations_added,
                    summary.findings_added
                ),
                Err(error) => {
                    err!("rxscan project add: {error}");
                    std::process::exit(1);
                }
            }
        }
        "summary" => {
            let Some(path) = args.get(3) else {
                err!("rxscan project summary: missing project path");
                std::process::exit(2);
            };
            let json = args[4..].iter().any(|a| a == "--json");
            match project::load_project_with_timing(std::path::Path::new(path)) {
                Ok((state, _, bytes)) if json => {
                    let summary = state.summary(bytes);
                    out_line!("{}", serde_json::to_string_pretty(&summary).unwrap());
                }
                Ok((state, _, bytes)) => out_line!("{}", project::render_summary(&state, bytes)),
                Err(error) => {
                    err!("rxscan project summary: {error}");
                    std::process::exit(1);
                }
            }
        }
        "show" => {
            let (Some(path), Some(entity)) = (args.get(3), args.get(4)) else {
                err!("rxscan project show: usage: rxscan project show <project> <entity>");
                std::process::exit(2);
            };
            if entity.starts_with("--") {
                err!("rxscan project show: usage: rxscan project show <project> <entity> [--json]");
                std::process::exit(2);
            }
            let json = args[5..].iter().any(|a| a == "--json");
            match project::load_project(std::path::Path::new(path)) {
                Ok(state) if json => match state.entities.get(entity) {
                    Some(found) => out_line!("{}", serde_json::to_string_pretty(found).unwrap()),
                    None => {
                        err!("rxscan project show: project entity not found: {entity}");
                        std::process::exit(1);
                    }
                },
                Ok(state) => match project::render_entity(&state, entity) {
                    Ok(text) => out_line!("{text}"),
                    Err(error) => {
                        err!("rxscan project show: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    err!("rxscan project show: {error}");
                    std::process::exit(1);
                }
            }
        }
        "neighbors" => {
            let (Some(path), Some(entity)) = (args.get(3), args.get(4)) else {
                err!(
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
                            err!("rxscan project neighbors: --depth requires a value");
                            std::process::exit(2);
                        };
                        depth = value.parse().unwrap_or(project::DEFAULT_QUERY_DEPTH);
                    }
                    "--limit" => {
                        let Some(value) = iter.next() else {
                            err!("rxscan project neighbors: --limit requires a value");
                            std::process::exit(2);
                        };
                        limit = value.parse().unwrap_or(project::DEFAULT_QUERY_LIMIT);
                    }
                    "--json" => json = true,
                    "--jsonl" => jsonl = true,
                    _ => {
                        err!("rxscan project neighbors: unsupported option {arg}");
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
                        exit_on_output_error("rxscan project neighbors", error);
                    }
                }
                Ok(state) if json => match state.neighbors(entity, depth, limit) {
                    Ok(result) => out_line!("{}", serde_json::to_string_pretty(&result).unwrap()),
                    Err(error) => {
                        err!("rxscan project neighbors: {error}");
                        std::process::exit(1);
                    }
                },
                Ok(state) => match state.neighbors(entity, depth, limit) {
                    Ok(result) => {
                        out_line!(
                            "neighbors total={} emitted={} truncated={} network_requests=0",
                            result.results_total,
                            result.results_emitted,
                            result.truncated
                        );
                        for record in result.records {
                            out_line!(
                                "{} {:?} {}",
                                record.depth,
                                record.relationship_kind,
                                record.entity_id
                            );
                        }
                    }
                    Err(error) => {
                        err!("rxscan project neighbors: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    err!("rxscan project neighbors: {error}");
                    std::process::exit(1);
                }
            }
        }
        "scans" => {
            let Some(path) = args.get(3) else {
                err!("rxscan project scans: missing project path");
                std::process::exit(2);
            };
            let json = args[4..].iter().any(|a| a == "--json");
            match project::load_project(std::path::Path::new(path)) {
                Ok(state) if json => {
                    let scans: Vec<_> = state.scans.values().collect();
                    out_line!("{}", serde_json::to_string_pretty(&scans).unwrap());
                }
                Ok(state) => {
                    for scan in state.scans.values() {
                        out_line!(
                            "{} sequence={} entities={} relationships={}",
                            scan.scan_id.0,
                            scan.import_sequence,
                            scan.entity_count,
                            scan.relationship_count
                        );
                    }
                }
                Err(error) => {
                    err!("rxscan project scans: {error}");
                    std::process::exit(1);
                }
            }
        }
        "findings" | "changes" | "attention" => {
            let Some(path) = args.get(3) else {
                err!("rxscan project {command}: missing project path");
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
                            err!("rxscan project {command}: --limit requires a value");
                            std::process::exit(2);
                        };
                        limit = value.parse().unwrap_or(project::DEFAULT_QUERY_LIMIT);
                    }
                    "--json" => json = true,
                    "--jsonl" => jsonl = true,
                    other if other.starts_with("--") && entity.is_none() && start == 4 => {
                        // Already handled flags above; unknown flags rejected.
                        err!("rxscan project {command}: unsupported option {other}");
                        std::process::exit(2);
                    }
                    other => {
                        err!("rxscan project {command}: unsupported option {other}");
                        std::process::exit(2);
                    }
                }
            }
            let state = match project::load_project(std::path::Path::new(path)) {
                Ok(state) => state,
                Err(error) => {
                    err!("rxscan project {command}: {error}");
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
                                    exit_on_output_error("rxscan project findings", error);
                                }
                            }
                            Err(error) => {
                                err!("rxscan project findings: {error}");
                                std::process::exit(1);
                            }
                        }
                    } else if json {
                        match state.findings_query(entity_ref, limit) {
                            Ok(result) => {
                                out_line!("{}", serde_json::to_string_pretty(&result).unwrap())
                            }
                            Err(error) => {
                                err!("rxscan project findings: {error}");
                                std::process::exit(1);
                            }
                        }
                    } else {
                        match project::render_findings(&state, entity_ref, limit) {
                            Ok(text) => out!("{text}"),
                            Err(error) => {
                                err!("rxscan project findings: {error}");
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
                                    exit_on_output_error("rxscan project changes", error);
                                }
                            }
                            Err(error) => {
                                err!("rxscan project changes: {error}");
                                std::process::exit(1);
                            }
                        }
                    } else if json {
                        match state.changes_query(entity_ref, limit) {
                            Ok(result) => {
                                out_line!("{}", serde_json::to_string_pretty(&result).unwrap())
                            }
                            Err(error) => {
                                err!("rxscan project changes: {error}");
                                std::process::exit(1);
                            }
                        }
                    } else {
                        match project::render_changes(&state, entity_ref, limit) {
                            Ok(text) => out!("{text}"),
                            Err(error) => {
                                err!("rxscan project changes: {error}");
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
                                    exit_on_output_error("rxscan project attention", error);
                                }
                            }
                            Err(error) => {
                                err!("rxscan project attention: {error}");
                                std::process::exit(1);
                            }
                        }
                    } else if json {
                        match state.attention_query(entity_ref, limit) {
                            Ok(result) => {
                                out_line!("{}", serde_json::to_string_pretty(&result).unwrap())
                            }
                            Err(error) => {
                                err!("rxscan project attention: {error}");
                                std::process::exit(1);
                            }
                        }
                    } else {
                        match project::render_attention(&state, entity_ref, limit) {
                            Ok(text) => out!("{text}"),
                            Err(error) => {
                                err!("rxscan project attention: {error}");
                                std::process::exit(1);
                            }
                        }
                    }
                }
            }
        }
        _ => {
            err!("rxscan project: unknown command {command}");
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
                out_line!(
                    "rxscan report [--format human|json|jsonl|raw] [--summary-only] [--top N] [--diff <old.rxscan>] [--analysis] [--output <path>] <scan.rxscan>"
                );
                return;
            }
            "--format" => {
                let Some(value) = iter.next() else {
                    err!("rxscan report: --format requires a value");
                    std::process::exit(2);
                };
                match report::ReportFormat::parse(value) {
                    Ok(parsed) => format = parsed,
                    Err(error) => {
                        err!("rxscan report: {error}");
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
                    err!("rxscan report: --diff requires a baseline checkpoint path");
                    std::process::exit(2);
                };
                diff_path = Some(path.to_owned());
            }
            "--output" => {
                let Some(path) = iter.next() else {
                    err!("rxscan report: --output requires a path");
                    std::process::exit(2);
                };
                output_path = Some(path.to_owned());
            }
            "--top" => {
                let Some(value) = iter.next() else {
                    err!("rxscan report: --top requires a value");
                    std::process::exit(2);
                };
                match value.parse::<usize>() {
                    Ok(value) if value <= report::MAX_REPORT_TOP_N => top = value,
                    _ => {
                        err!(
                            "rxscan report: --top must be an integer from 0 to {}",
                            report::MAX_REPORT_TOP_N
                        );
                        std::process::exit(2);
                    }
                }
            }
            value if checkpoint.is_none() => checkpoint = Some(value.to_owned()),
            _ => {
                err!(
                    "rxscan report: usage: rxscan report [--format human|json|jsonl|raw] [--summary-only] [--top N] [--diff <old.rxscan>] [--analysis] [--output <path>] <scan.rxscan>"
                );
                std::process::exit(2);
            }
        }
    }
    let Some(current) = checkpoint else {
        err!(
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
                err!("rxscan report: {error}");
                std::process::exit(1);
            }
        };
    let bytes = match report::render_to_bytes(&model, &options) {
        Ok(bytes) => bytes,
        Err(error) => {
            err!("rxscan report: {error}");
            std::process::exit(1);
        }
    };
    if let Some(path) = output_path {
        let mut inputs = vec![current_path];
        if let Some(diff_path) = diff_path_ref {
            inputs.push(diff_path);
        }
        if let Err(error) = report::write_output(std::path::Path::new(&path), &bytes, &inputs) {
            err!("rxscan report: {error}");
            std::process::exit(1);
        }
    } else if let Err(error) = std::io::Write::write_all(&mut std::io::stdout(), &bytes) {
        if error.kind() != std::io::ErrorKind::BrokenPipe {
            err!("rxscan report: {error}");
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
                    err!("rxscan analyze: --diff requires a baseline checkpoint path");
                    std::process::exit(2);
                };
                diff_path = Some(path.to_owned());
            }
            value if checkpoint.is_none() => checkpoint = Some(value.to_owned()),
            _ => {
                err!(
                    "rxscan analyze: usage: rxscan analyze [--json|--jsonl] [--diff <old.rxscan>] <current.rxscan>"
                );
                std::process::exit(2);
            }
        }
    }
    let Some(current) = checkpoint else {
        err!(
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
                err!("rxscan analyze: {error}");
                std::process::exit(1);
            }
        }
    } else {
        analysis::analyze_checkpoint(std::path::Path::new(&current), options)
            .map(|(report, _)| report)
    };
    match result {
        Ok(report) if json => match analysis::to_json(&report) {
            Ok(text) => out_line!("{text}"),
            Err(error) => {
                err!("rxscan analyze: {error}");
                std::process::exit(1);
            }
        },
        Ok(report) => out_line!("{}", analysis::human_summary(&report)),
        Err(error) => {
            err!("rxscan analyze: {error}");
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
        err!(
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
            Ok(text) => out_line!("{text}"),
            Err(error) => {
                err!("rxscan diff: {error}");
                std::process::exit(1);
            }
        },
        Ok((report, _, _, _)) => out_line!("{}", diff::human_summary(&report)),
        Err(error) => {
            err!("rxscan diff: {error}");
            std::process::exit(1);
        }
    }
}
