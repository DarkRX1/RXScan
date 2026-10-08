use clap::Parser;
use rxscan::{
    analysis, capabilities, cli::Cli, diff, plan::ScanPlan, project, report, run,
    search::SearchStatus, unknown,
};

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

/// Print machine-readable JSON. Serialization of a derived report
/// practically never fails, but if it does the completed work must not be
/// discarded with a panic: report to stderr and exit 1 instead.
fn emit_json_pretty(value: &impl serde::Serialize) {
    match serde_json::to_string_pretty(value) {
        Ok(text) => out_line!("{text}"),
        Err(error) => {
            err!("error: cannot encode output: {error}");
            std::process::exit(1);
        }
    }
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
    // Accept a global `--color MODE` before the subcommand
    // (`rxscan --color always search ...`): relocate color flags to the end
    // so subcommand dispatch sees the workflow first. Color resolution
    // scans all args and manual parsers accept `--color` anywhere, so the
    // relocation preserves semantics (relative color-flag order kept).
    let args = normalize_global_color(args);
    // Friendly root: `rxscan` with no arguments shows a compact
    // welcome/help screen, never a confusing `target is empty` error.
    // Only `--color` flags are ignored for emptiness so
    // `rxscan --color always` still welcomes (styled).
    if is_empty_invocation(&args) {
        let caps = resolve_human_caps(&args);
        out!("{}", render_welcome(caps));
        return;
    }
    // Obsolete/wrong form that strongly resembles an existing workflow:
    // suggest the correct form instead of a generic Clap error.
    // Never silently reinterprets; only suggests.
    if args.iter().any(|arg| arg == "--investigate") {
        err!("error: `--investigate` is not a flag");
        err!("");
        err!("Try:");
        err!("  rxscan investigate --username exampleuser");
        std::process::exit(2);
    }
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
    if args.get(1).is_some_and(|arg| arg == "project-db") {
        run_project_db(&args);
        return;
    }
    if args.get(1).is_some_and(|arg| arg == "capabilities") {
        validate_color_flags("capabilities", &args);
        if args.iter().any(|arg| arg == "--help" || arg == "-h") {
            out_line!(
                "RXSCAN\nReconnaissance / Evidence Engine\n\nUSAGE\n  rxscan capabilities [--explain] [--json] [--color MODE]\n\nEXAMPLES\n  rxscan capabilities\n\nOPTIONS\n  --explain      Show exact runtime reasons (default explains plainly)\n  --json         Machine output (never styled)\n  --color MODE   auto (TTY only), always, or never"
            );
            return;
        }
        let json = args.iter().any(|arg| arg == "--json");
        let explain = args.iter().any(|arg| arg == "--explain");
        // Only --json/--explain/--color/--help are accepted here.
        {
            let mut idx = 2usize;
            let mut prev_was_color = false;
            while idx < args.len() {
                let arg = args[idx].as_str();
                if prev_was_color && ["auto", "always", "never"].contains(&arg) {
                    prev_was_color = false;
                    idx += 1;
                    continue;
                }
                prev_was_color = false;
                if arg == "--json" || arg == "--explain" || arg == "--help" || arg == "-h" {
                    idx += 1;
                    continue;
                }
                if arg == "--color" {
                    prev_was_color = true;
                    idx += 1;
                    continue;
                }
                if arg.starts_with("--color=") {
                    idx += 1;
                    continue;
                }
                err!("rxscan capabilities: unknown option '{arg}'");
                std::process::exit(2);
            }
            if prev_was_color {
                err!("rxscan capabilities: --color requires one of auto, always, never");
                std::process::exit(2);
            }
        }
        let report = capabilities::probe();
        if json {
            emit_json_pretty(&report);
        } else if explain {
            let caps = resolve_human_caps(&args);
            out!("{}", capabilities::render_human_explain_caps(&report, caps));
        } else {
            let caps = resolve_human_caps(&args);
            out!("{}", capabilities::render_human_caps(&report, caps));
        }
        return;
    }
    if args.get(1).is_some_and(|arg| arg == "unknown") {
        run_unknown(&args);
        return;
    }
    if args
        .get(1)
        .is_some_and(|arg| arg == "search" || arg == "--username")
    {
        run_search(&args);
        return;
    }
    if args.get(1).is_some_and(|arg| arg == "investigate") {
        run_investigate(&args);
        return;
    }
    if args.get(1).is_some_and(|arg| arg == "exposure") {
        run_exposure_cli(&args);
        return;
    }
    if args.get(1).is_some_and(|arg| arg == "os-lab") {
        run_os_lab(&args);
        return;
    }
    if args.get(1).is_some_and(|arg| arg == "web") {
        run_web(&args);
        return;
    }
    // Deterministic command suggestions: a bare first argument that
    // strongly resembles a known subcommand is treated as a typo, not a
    // scan target. Suggestions never execute automatically.
    if let Some(first) = args.get(1) {
        if !first.starts_with('-')
            && !first.contains('.')
            && !first.contains('/')
            && !first.contains(':')
            && !first.contains('@')
        {
            if let Some(suggestion) = suggest_command(first) {
                // Don't shadow real subcommands (already dispatched above).
                if first != &suggestion {
                    err!("Unknown command `{first}`.");
                    err!("");
                    err!("Did you mean?");
                    err!("  rxscan {suggestion}");
                    std::process::exit(2);
                }
            }
        }
    }
    // `rxscan scan <target> ...` is an explicit alias for the default
    // network-recon workflow (`rxscan <target> ...`).
    let mut owned_args: Vec<String> = Vec::new();
    let args: &[String] = if args.get(1).is_some_and(|arg| arg == "scan") {
        owned_args.extend_from_slice(&args[..1]);
        owned_args.extend_from_slice(&args[2..]);
        &owned_args
    } else {
        &args
    };
    let cli = Cli::parse_from(args);
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
    // Human capabilities resolve once from `--color` + TTY + environment.
    // The scan report carries its own `RXSCAN / RECON` header; no separate
    // startup mark is printed.
    let scan_caps: rxscan::terminal::TerminalCapabilities = {
        let mode = match cli.color.as_deref() {
            Some("always") => rxscan::terminal::ColorMode::Always,
            Some("never") => rxscan::terminal::ColorMode::Never,
            _ => rxscan::terminal::ColorMode::Auto,
        };
        let tty = rxscan::terminal::stdout_is_tty();
        rxscan::terminal::TerminalCapabilities {
            color: rxscan::terminal::color_enabled(mode, rxscan::terminal::no_color_env(), tty),
            ascii: !rxscan::terminal::unicode_supported(),
            width: rxscan::terminal::terminal_width(),
            tty,
        }
    };
    match run::execute(cli) {
        Ok(report) => {
            // If JSONL went to stdout via --format jsonl, the JSONL is already
            // on stdout; still print the human summary to stderr to keep
            // stdout pure JSONL. Default human output is concise and
            // findings-first; `--explain` (plan) and JSONL carry engineering
            // detail. No tutorial footer after every invocation.
            if report.jsonl_bytes > 0 && report.output_path.is_none() {
                err!("{}", run::human_summary_caps(&report, scan_caps, None));
            } else {
                out_line!("{}", run::human_summary_caps(&report, scan_caps, None));
            }
        }
        Err(error) => {
            err!("rxscan: {error}");
            std::process::exit(error.exit_code());
        }
    }
}

/// Whether this invocation carries no workflow and no target.
///
/// Only `--color` flags (with values) are ignored for emptiness so
/// `rxscan --color always` still welcomes. `--help`/`-h` are not empty:
/// they fall through to Clap's full help.
fn is_empty_invocation(args: &[String]) -> bool {
    let mut index = 1usize;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--color" {
            index += 1;
            // Skip the value when present (`--color always`).
            if args.get(index).is_some_and(|v| {
                !v.starts_with('-') || ["auto", "always", "never"].contains(&v.as_str())
            }) {
                index += 1;
            }
            continue;
        }
        if arg.starts_with("--color=") {
            index += 1;
            continue;
        }
        return false;
    }
    true
}

/// Compact welcome/help for an empty invocation.
///
/// Never dumps the full Clap reference; points at workflows and examples.
/// Respects terminal capabilities: styled only when color is enabled,
/// plain when piped.
fn render_welcome(caps: rxscan::terminal::TerminalCapabilities) -> String {
    use rxscan::terminal::{Style, paint};
    let color = caps.color;
    let brand = paint(color, Style::Accent, "RXSCAN");
    let tagline = paint(color, Style::Muted, "Reconnaissance & Evidence Engine");
    let mut out = String::new();
    out.push_str(&brand);
    out.push('\n');
    out.push_str(&tagline);
    out.push_str("\n\nUsage\n");
    out.push_str("  rxscan <target>                     Scan a host or network\n");
    out.push_str("  rxscan search --username <name>    Search public sources\n");
    out.push_str("  rxscan investigate --username <name>  Correlate public evidence\n");
    out.push_str("  rxscan web                            Serve the local console + API\n");
    out.push_str("  rxscan capabilities                Show available capabilities\n");
    out.push_str("\nExamples\n");
    out.push_str("  rxscan example.test\n");
    out.push_str("  rxscan 192.0.2.10 --ports 22,80,443\n");
    out.push_str("  rxscan search --username exampleuser\n");
    out.push_str("  rxscan investigate --username exampleuser\n");
    out.push_str("\nRun `rxscan --help` for all options.\n");
    out
}

/// Deterministic command suggestion for a likely typo.
///
/// Returns the suggested subcommand name (e.g. `capabilities` for
/// `capability`). Pure suggestion: callers print it and exit, never
/// execute automatically. Returns `None` when the input is not close to
/// any known subcommand.
fn suggest_command(input: &str) -> Option<String> {
    const KNOWN: &[&str] = &[
        "search",
        "investigate",
        "exposure",
        "project",
        "project-db",
        "capabilities",
        "report",
        "analyze",
        "diff",
        "unknown",
        "scan",
        "web",
    ];
    // Fast path for the most common singular/plural mistake.
    if input == "capability" {
        return Some("capabilities".to_owned());
    }
    if input == "searches" {
        return Some("search".to_owned());
    }
    let lowered = input.to_ascii_lowercase();
    let mut best: Option<(&str, usize)> = None;
    for candidate in KNOWN {
        let distance = edit_distance(&lowered, candidate);
        // Thresholds are deliberately tight so suggestions stay
        // predictable and never trigger on hostnames.
        let allowed = if candidate.len() >= 10 { 3 } else { 2 };
        if distance <= allowed && distance > 0 && best.is_none_or(|(_, d)| distance < d) {
            best = Some((candidate, distance));
        }
    }
    best.map(|(name, _)| name.to_owned())
}

/// Small deterministic Levenshtein distance over bytes.
///
/// Inputs are short CLI tokens; quadratic time is irrelevant.
fn edit_distance(a: &str, b: &str) -> usize {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j] + cost).min((curr[j] + 1).min(prev[j + 1] + 1));
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// Relocate `--color` flags to the end of `args` so a global color flag
/// may precede the subcommand. Preserves the relative order of color
/// flags; all other args keep their order.
fn normalize_global_color(args: Vec<String>) -> Vec<String> {
    let mut rest: Vec<String> = Vec::with_capacity(args.len());
    let mut colors: Vec<String> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--color" {
            colors.push(arg.clone());
            if let Some(next) = args.get(index + 1) {
                if !next.starts_with('-') {
                    colors.push(next.clone());
                    index += 1;
                }
            }
        } else if arg.starts_with("--color=") {
            colors.push(arg.clone());
        } else {
            rest.push(arg.clone());
        }
        index += 1;
    }
    // Program name stays first; color flags trail the command.
    if rest.is_empty() {
        return args;
    }
    let mut out = Vec::with_capacity(args.len());
    out.push(rest[0].clone());
    out.extend(rest.into_iter().skip(1));
    out.extend(colors);
    out
}

/// Strict `--color` validation for manual subcommand paths: only `auto`,
/// `always`, and `never` are accepted. Anything else (e.g. `--color green`)
/// is a usage error (exit 2). `--color` selects *whether* to style, never
/// the palette; the theme owns the palette internally.
fn validate_color_flags(command: &str, args: &[String]) {
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--color" {
            if !args
                .get(index + 1)
                .is_some_and(|value| matches!(value.as_str(), "auto" | "always" | "never"))
            {
                err!("rxscan {command}: --color requires one of auto, always, never");
                std::process::exit(2);
            }
            index += 1;
        } else if let Some(value) = arg.strip_prefix("--color=") {
            if !matches!(value, "auto" | "always" | "never") {
                err!("rxscan {command}: --color must be one of auto, always, never");
                std::process::exit(2);
            }
        }
        index += 1;
    }
}

/// Resolve human-output capabilities from `--color` + environment.
///
/// Human output uses ANSI only when appropriate: `--color always` forces
/// it, `--color never` disables it, `auto` (default) enables it on an
/// interactive TTY unless `NO_COLOR` is set. Machine output (JSON/JSONL)
/// never passes through here.
fn resolve_human_caps(args: &[String]) -> rxscan::terminal::TerminalCapabilities {
    let mode = rxscan::terminal::parse_color_mode(args);
    let tty = rxscan::terminal::stdout_is_tty();
    rxscan::terminal::TerminalCapabilities {
        color: rxscan::terminal::color_enabled(mode, rxscan::terminal::no_color_env(), tty),
        ascii: !rxscan::terminal::unicode_supported(),
        width: rxscan::terminal::terminal_width(),
        tty,
    }
}

/// Parse flags for the `providers`/`stats` leaf subcommands. Only `--json`
/// and `--color` are accepted; anything else is a usage error.
fn parse_leaf_search_flags(subcommand: &str, rest: &[&String]) -> bool {
    let mut json = false;
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--json" => json = true,
            "--color" => {
                index += 1;
                if !rest
                    .get(index)
                    .is_some_and(|value| matches!(value.as_str(), "auto" | "always" | "never"))
                {
                    err!("rxscan search {subcommand}: --color requires one of auto, always, never");
                    std::process::exit(2);
                }
            }
            arg if arg.starts_with("--color=") => {
                if !matches!(
                    arg.trim_start_matches("--color="),
                    "auto" | "always" | "never"
                ) {
                    err!("rxscan search {subcommand}: --color must be one of auto, always, never");
                    std::process::exit(2);
                }
            }
            _ => {
                err!("rxscan search {subcommand}: only --json and --color are supported");
                std::process::exit(2);
            }
        }
        index += 1;
    }
    json
}

/// Review-queue filters for `rxscan search providers`: `--health STATE`
/// (repeatable), `--category NAME` (repeatable), and `--stale` (live
/// verifications older than 180 days). Unknown states exit 2; unknown
/// categories exit 2 with the valid set listed.
struct ProviderFilter {
    health: std::collections::BTreeSet<String>,
    categories: std::collections::BTreeSet<String>,
    stale_only: bool,
}

fn parse_provider_filters(rest: &[&String]) -> (bool, ProviderFilter) {
    let mut json = false;
    let mut filter = ProviderFilter {
        health: std::collections::BTreeSet::new(),
        categories: std::collections::BTreeSet::new(),
        stale_only: false,
    };
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--json" => json = true,
            "--stale" => filter.stale_only = true,
            "--health" => {
                index += 1;
                let Some(state) = rest.get(index) else {
                    err!("rxscan search providers: --health requires a state");
                    std::process::exit(2);
                };
                if !matches!(
                    state.as_str(),
                    "fixture_verified" | "live_verified" | "needs_review" | "disabled"
                ) {
                    err!("rxscan search providers: unknown health state '{state}'");
                    std::process::exit(2);
                }
                filter.health.insert((*state).clone());
            }
            "--category" => {
                index += 1;
                let Some(category) = rest.get(index) else {
                    err!("rxscan search providers: --category requires a value");
                    std::process::exit(2);
                };
                filter.categories.insert((*category).clone());
            }
            "--color" => {
                index += 1;
                if !rest
                    .get(index)
                    .is_some_and(|value| matches!(value.as_str(), "auto" | "always" | "never"))
                {
                    err!("rxscan search providers: --color requires one of auto, always, never");
                    std::process::exit(2);
                }
            }
            arg if arg.starts_with("--color=") => {
                if !matches!(
                    arg.trim_start_matches("--color="),
                    "auto" | "always" | "never"
                ) {
                    err!("rxscan search providers: --color must be one of auto, always, never");
                    std::process::exit(2);
                }
            }
            unknown => {
                err!("rxscan search providers: unknown option '{unknown}'");
                std::process::exit(2);
            }
        }
        index += 1;
    }
    (json, filter)
}

/// Generated corpus statistics. Values come from the loaded provider pack,
/// never from hard-coded marketing numbers.
fn run_search_stats(args: &[String], offset: usize) {
    let rest: Vec<&String> = args.iter().skip(offset + 1).collect();
    let json = parse_leaf_search_flags("stats", &rest);
    let pack = match rxscan::search::embedded_username_pack() {
        Ok(pack) => pack,
        Err(error) => {
            err!("rxscan search stats: {error}");
            std::process::exit(1);
        }
    };
    let mut fixture_verified = 0usize;
    let mut live_verified = 0usize;
    let mut needs_review = 0usize;
    let mut disabled = 0usize;
    let mut categories: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for provider in &pack.providers {
        match provider.health_state {
            rxscan::search::HealthState::FixtureVerified => fixture_verified += 1,
            rxscan::search::HealthState::LiveVerified => live_verified += 1,
            rxscan::search::HealthState::NeedsReview => needs_review += 1,
            rxscan::search::HealthState::Disabled => disabled += 1,
        }
        *categories.entry(provider.category.clone()).or_default() += 1;
    }
    let enabled = pack.providers.len().saturating_sub(disabled);
    let rules_curated = pack
        .providers
        .iter()
        .filter(|provider| provider.username_rules.is_some())
        .count();
    let absence_handled = pack
        .providers
        .iter()
        .filter(|provider| rxscan::search::has_absence_handling(provider))
        .count();
    // A definition counts as API-backed when its lookup URL targets a
    // documented API path; everything else is page scraping. Heuristic,
    // documented in the corpus README, generated from the pack.
    let api_backed = pack
        .providers
        .iter()
        .filter(|provider| provider.profile_url.contains("/api/"))
        .count();
    let cutoff = rxscan::search::stale_cutoff(180);
    let stale = pack
        .providers
        .iter()
        .filter(|provider| {
            rxscan::search::verification_stale(
                &provider.health_state,
                provider.verified_at.as_deref(),
                &cutoff,
            )
        })
        .count();
    let oldest: Option<&String> = pack
        .providers
        .iter()
        .filter_map(|provider| provider.verified_at.as_ref())
        .min();
    // Review-queue signals, all generated from the loaded pack (never
    // hard-coded): providers without rules are queried unconditionally;
    // ceilings are custom body budgets below the global maximum; blocking
    // susceptibility means a block-marker list is present.
    let without_rules = pack.providers.len().saturating_sub(rules_curated);
    let with_ceiling = pack
        .providers
        .iter()
        .filter(|provider| provider.max_body_bytes < rxscan::search::MAX_SEARCH_BODY_BYTES)
        .count();
    let blocking_susceptible = pack
        .providers
        .iter()
        .filter(|provider| !provider.blocked_markers.is_empty())
        .count();
    // Provider vs vector counts from the shared core registry model.
    // Vectors == providers 1:1 today; both reported so growth in either
    // dimension stays honest. Email vectors are honestly zero until real
    // email lookup vectors land under the same quality bar.
    let registry = rxscan::search::username_registry_counts(&pack);
    let email = rxscan::search::email_registry_counts();
    if json {
        emit_json_pretty(&serde_json::json!({
            "pack_version": pack.pack_version,
            "providers_loaded": pack.providers.len(),
            "username_vectors": registry.vectors_registered,
            "username_providers": registry.providers_configured,
            "email_vectors": email.vectors_registered,
            "email_providers": email.providers_configured,
            "enabled": enabled,
            "fixture_verified": fixture_verified,
            "live_verified": live_verified,
            "needs_review": needs_review,
            "disabled": disabled,
            "stale_verification": stale,
            "oldest_verification": oldest,
            "username_rules_curated": rules_curated,
            "username_rules_missing": without_rules,
            "absence_handling": absence_handled,
            "api_backed": api_backed,
            "html_backed": pack.providers.len() - api_backed,
            "blocking_susceptible": blocking_susceptible,
            "confirmation_ceilings": with_ceiling,
            "categories": categories,
        }));
        return;
    }
    let caps = resolve_human_caps(args);
    out_line!(
        "{}",
        rxscan::terminal::workflow_header(caps, "SEARCH CORPUS", None)
    );
    out_line!("");
    out_line!("Providers loaded       {}", pack.providers.len());
    out_line!("Username vectors       {}", registry.vectors_registered);
    out_line!("Username providers     {}", registry.providers_configured);
    out_line!("Email vectors          {}", email.vectors_registered);
    out_line!("Email providers        {}", email.providers_configured);
    out_line!("Enabled                {enabled}");
    out_line!("Fixture verified       {fixture_verified}");
    out_line!("Live verified          {live_verified}");
    out_line!("Needs review           {needs_review}");
    out_line!("Disabled               {disabled}");
    out_line!("");
    out_line!("Username rules curated {rules_curated}");
    out_line!("Without rules          {without_rules}");
    out_line!(
        "Absence handling       {absence_handled}/{}",
        pack.providers.len()
    );
    out_line!("API backed             {api_backed}");
    out_line!(
        "HTML backed            {}",
        pack.providers.len() - api_backed
    );
    out_line!("Blocking susceptible   {blocking_susceptible}");
    out_line!("Confirmation ceilings  {with_ceiling}");
    out_line!("Stale verification    {stale}");
    if let Some(date) = oldest {
        out_line!("Oldest verification    {date}");
    }
    out_line!("");
    out_line!("Categories");
    for (category, count) in &categories {
        out_line!("  {category:<22}{count}");
    }
}

/// SIGINT reaches the real search scheduler via the shared platform
/// process-cancellation state (no new dependency, no second handler).
///
/// Process-lifetime latch lives in `rxscan::platform::process`: the OS
/// handler performs exactly one atomic store (never allocates, locks,
/// formats, or does I/O) on a `'static` `AtomicBool`. Completed evidence
/// survives via the normal scheduler drain path. Installed once per
/// process; re-installs only reset state so a previous search never leaks
/// into the next one.
fn install_search_cancel() {
    rxscan::platform::process::install_process_cancellation();
}

/// Build terminal enrichment + per-category coverage from the same core
/// evidence (registry categories, observation attributes, evidence,
/// provenance). No invented values: absent data renders as absent.
fn build_search_enrichment(
    report: &rxscan::search::UsernameSearchReport,
    pack: &rxscan::search::UsernameProviderPack,
    effective: &std::collections::BTreeSet<String>,
) -> (
    rxscan::terminal::SearchEnrichment,
    Vec<rxscan::terminal::SearchCategoryCoverage>,
) {
    use std::collections::{BTreeMap, BTreeSet};
    let mut provider_to_category: BTreeMap<String, String> = BTreeMap::new();
    let mut provider_to_label: BTreeMap<String, String> = BTreeMap::new();
    for definition in &pack.providers {
        provider_to_category.insert(definition.metadata.id.clone(), definition.category.clone());
        provider_to_label.insert(
            definition.metadata.id.clone(),
            rxscan::search::category_label(&definition.category).to_owned(),
        );
    }
    let mut enrichment = rxscan::terminal::SearchEnrichment::default();
    // Categories for every scheduled provider (including unscanned) so
    // `--all` rows carry honest category labels.
    for provider in effective {
        if let Some(category) = provider_to_category.get(provider) {
            enrichment
                .categories
                .insert(provider.clone(), category.clone());
            if let Some(label) = provider_to_label.get(provider) {
                enrichment
                    .category_labels
                    .insert(provider.clone(), label.clone());
            }
        }
    }
    for result in &report.results {
        let category = result
            .attributes
            .get("category")
            .cloned()
            .or_else(|| provider_to_category.get(&result.provider_id).cloned())
            .unwrap_or_default();
        if !category.is_empty() {
            enrichment
                .categories
                .insert(result.provider_id.clone(), category.clone());
            let label = result
                .attributes
                .get("category_label")
                .cloned()
                .unwrap_or_else(|| rxscan::search::category_label(&category).to_owned());
            enrichment
                .category_labels
                .insert(result.provider_id.clone(), label);
        }
        // Bounded public metadata subset with hidden count.
        let (ordered, _) = rxscan::search::prioritized_public_metadata(&result.attributes, 100);
        if !ordered.is_empty() {
            let hidden = ordered.len().saturating_sub(4);
            enrichment.metadata.insert(
                result.provider_id.clone(),
                ordered.into_iter().take(8).collect(),
            );
            if hidden > 0 {
                enrichment
                    .metadata_hidden
                    .insert(result.provider_id.clone(), hidden);
            }
        }
        if !result.evidence.is_empty() {
            enrichment
                .evidence
                .insert(result.provider_id.clone(), result.evidence.clone());
        }
        enrichment.provenance.insert(
            result.provider_id.clone(),
            format!("{}@{}", result.provider_id, result.provider_version),
        );
        enrichment
            .observed_at
            .insert(result.provider_id.clone(), result.timestamp);
    }
    // Coverage by category from the REAL plan + REAL results.
    let core_coverage =
        rxscan::search::coverage_by_category(effective, &provider_to_category, &report.results);
    let coverage = core_coverage
        .into_iter()
        .map(|entry| rxscan::terminal::SearchCategoryCoverage {
            category: entry.category,
            label: entry.label,
            scheduled: entry.scheduled,
            complete: entry.complete,
            remaining: entry.remaining,
        })
        .collect();
    // Ensure every requested provider without an observation still has a
    // category entry for `--all` greppability (unscanned stays honest).
    let _ = provider_to_label;
    let _ = BTreeSet::<String>::new();
    (enrichment, coverage)
}

fn search_status_key(status: &SearchStatus) -> &'static str {
    match status {
        SearchStatus::Confirmed => "confirmed",
        SearchStatus::Probable => "probable",
        SearchStatus::Possible => "possible",
        SearchStatus::NotFound => "not_found",
        SearchStatus::Unknown => "unknown",
        SearchStatus::RateLimited => "rate_limited",
        SearchStatus::Blocked => "blocked",
        SearchStatus::AuthenticationRequired => "authentication_required",
        SearchStatus::Error => "error",
        SearchStatus::Cancelled => "cancelled",
        SearchStatus::Unscanned => "unscanned",
    }
}

/// Map a search report onto presentation rows. The terminal renderer only
/// ever sees these plain rows, never search internals.
///
/// Presentation view-model: exposes the useful honest URL without changing
/// detection semantics, confidence, or machine schemas. Ranking is
/// deterministic: observed identity-specific public profile >
/// observed identity-specific API/resource > candidate identity-specific
/// profile > no default URL. Generic provider/API endpoints are never
/// preferred merely because they were the final HTTP URL; they are omitted
/// from the default URL (renderer states the honest absence).
fn search_report_rows(
    report: &rxscan::search::UsernameSearchReport,
) -> Vec<rxscan::terminal::SearchRow> {
    use rxscan::terminal::{RowTier, SearchRow, is_api_resource_url, is_identity_specific_url};
    let username = report.seed.display_value.as_str();
    report
        .results
        .iter()
        .map(|result| {
            let key = search_status_key(&result.status);
            let profile_url = result
                .attributes
                .get("profile_url")
                .map(String::as_str)
                .unwrap_or("");
            let final_url = result
                .attributes
                .get("final_url")
                .map(String::as_str)
                .unwrap_or("");
            let profile_trim = profile_url.trim();
            let final_trim = final_url.trim();
            let final_identity = is_identity_specific_url(final_trim, username);
            let profile_identity = is_identity_specific_url(profile_trim, username);
            let final_api = is_api_resource_url(final_trim);
            let profile_api = is_api_resource_url(profile_trim);
            match key {
                "confirmed" | "probable" => {
                    // Honest observed selection: prefer identity-specific
                    // public profile over API resource; never prefer a
                    // generic endpoint merely because it was final.
                    let (url, detail) = if final_identity && !final_api {
                        (final_trim.to_owned(), "public profile".to_owned())
                    } else if profile_identity && !profile_api {
                        (profile_trim.to_owned(), "public profile".to_owned())
                    } else if final_identity && final_api {
                        (final_trim.to_owned(), "public account resource".to_owned())
                    } else if profile_identity && profile_api {
                        (
                            profile_trim.to_owned(),
                            "public account resource".to_owned(),
                        )
                    } else {
                        // No identity-specific URL: omit (renderer states
                        // the honest absence). Never invent or show generic.
                        (String::new(), "public profile".to_owned())
                    };
                    let observed = !url.is_empty();
                    SearchRow {
                        status: key,
                        provider: result.provider_id.clone(),
                        confidence: result.confidence,
                        detail,
                        tier: RowTier::Positive,
                        url,
                        url_observed: observed,
                    }
                }
                "possible" => {
                    // Candidate only: evidence does not establish the
                    // account. Prefer the canonical candidate profile;
                    // never show a generic endpoint as the candidate.
                    let url = if profile_identity {
                        profile_trim.to_owned()
                    } else if final_identity {
                        final_trim.to_owned()
                    } else {
                        String::new()
                    };
                    SearchRow {
                        status: key,
                        provider: result.provider_id.clone(),
                        confidence: result.confidence,
                        detail: "weak evidence".to_owned(),
                        tier: RowTier::Positive,
                        // Candidate: fetched URL exists but does not establish the
                        // account. Renderer must not label it as observed.
                        url,
                        url_observed: false,
                    }
                }
                "blocked" | "rate_limited" | "error" | "authentication_required" | "unknown" => {
                    SearchRow {
                        status: key,
                        provider: result.provider_id.clone(),
                        confidence: result.confidence,
                        detail: result.evidence.first().cloned().unwrap_or_default(),
                        tier: RowTier::Attention,
                        url: String::new(),
                        url_observed: false,
                    }
                }
                _ => SearchRow {
                    status: key,
                    provider: result.provider_id.clone(),
                    confidence: result.confidence,
                    detail: String::new(),
                    tier: RowTier::Quiet,
                    url: String::new(),
                    url_observed: false,
                },
            }
        })
        .collect()
}

/// Maintainer corpus lint. Deterministic and offline; never performs
/// network requests. Exits 1 when lint errors exist.
fn run_search_lint(args: &[String], offset: usize) {
    let mut json = false;
    let mut corpus_root: Option<std::path::PathBuf> = None;
    let mut index = offset + 1;
    while index < args.len() {
        match args[index].as_str() {
            "--json" => {
                json = true;
            }
            "--corpus-root" => {
                index += 1;
                let Some(root) = args.get(index) else {
                    err!("rxscan search lint: --corpus-root requires a directory");
                    std::process::exit(2);
                };
                corpus_root = Some(root.into());
            }
            "--color" => {
                index += 1;
                if !args
                    .get(index)
                    .is_some_and(|value| matches!(value.as_str(), "auto" | "always" | "never"))
                {
                    err!("rxscan search lint: --color requires one of auto, always, never");
                    std::process::exit(2);
                }
            }
            arg if arg.starts_with("--color=") => {
                if !matches!(
                    arg.trim_start_matches("--color="),
                    "auto" | "always" | "never"
                ) {
                    err!("rxscan search lint: --color must be one of auto, always, never");
                    std::process::exit(2);
                }
            }
            "--help" | "-h" => {
                out_line!(
                    "rxscan search lint [--json] [--corpus-root DIR] [--color MODE]\n\nLint the username provider corpus: duplicate IDs/templates, version drift, classifier sanity, absence handling, username rules, fixture completeness, and generic-200 protection. Exits 1 when errors exist."
                );
                return;
            }
            unknown => {
                err!("rxscan search lint: unknown option '{unknown}'");
                std::process::exit(2);
            }
        }
        index += 1;
    }
    let root = corpus_root.unwrap_or_else(|| std::path::PathBuf::from("."));
    let report = {
        let corpus_dir = root.join("search/providers/v1/username");
        let fixture_root = root.join("search/fixtures/username");
        if corpus_dir.is_dir() {
            rxscan::search::lint_corpus_files(&corpus_dir, &fixture_root)
        } else {
            rxscan::search::lint_embedded_pack()
        }
    };
    if json {
        emit_json_pretty(&report);
    } else {
        let caps = resolve_human_caps(args);
        out_line!(
            "{}",
            rxscan::terminal::workflow_header(caps, "CORPUS LINT", None)
        );
        out_line!("");
        out_line!("providers checked    {}", report.providers_checked);
        out_line!("vectors checked      {}", report.vectors_checked);
        out_line!("files checked        {}", report.files_checked);
        out_line!("fixture complete     {}", report.fixture_complete);
        out_line!("disabled             {}", report.disabled_count);
        out_line!("needs review         {}", report.needs_review_count);
        out_line!("stale verification   {}", report.stale_count);
        out_line!("errors               {}", report.errors.len());
        out_line!("warnings             {}", report.warnings.len());
        for error in &report.errors {
            out_line!("error: {error}");
        }
        for warning in &report.warnings {
            out_line!("warning: {warning}");
        }
    }
    if !report.is_clean() {
        std::process::exit(1);
    }
}

/// Category discovery from the real provider registry (no hardcoded counts).
fn run_search_categories(args: &[String], offset: usize) {
    let rest: Vec<&String> = args.iter().skip(offset + 1).collect();
    let mut json = false;
    let mut explain = false;
    for arg in &rest {
        match arg.as_str() {
            "--json" => json = true,
            "--explain" => explain = true,
            "--color" => {}
            _ if arg.as_str().starts_with("--color") => {}
            _ if arg.as_str() == "--help" || arg.as_str() == "-h" => {
                out_line!(
                    "rxscan search categories [--json] [--explain] [--color MODE]\n\nList username provider categories from the registry with real provider counts."
                );
                return;
            }
            _ => {
                err!("rxscan search categories: only --json, --explain and --color are supported");
                std::process::exit(2);
            }
        }
    }
    // Validate --color values strictly.
    validate_color_flags("search categories", args);
    let pack = match rxscan::search::embedded_username_pack() {
        Ok(pack) => pack,
        Err(error) => {
            err!("rxscan search categories: {error}");
            std::process::exit(1);
        }
    };
    let summary = rxscan::search::username_category_summary(&pack);
    if json {
        emit_json_pretty(&serde_json::json!({
            "pack_version": pack.pack_version,
            "categories": summary,
        }));
        return;
    }
    let caps = resolve_human_caps(args);
    out_line!(
        "{}",
        rxscan::terminal::workflow_header(caps, "SEARCH CATEGORIES", None)
    );
    out_line!("");
    out_line!("  CATEGORY              PROVIDERS   USABLE");
    for entry in &summary {
        // Human label + machine ID both visible; counts from registry only.
        let label = if entry.label.to_ascii_lowercase() == entry.category {
            entry.label.clone()
        } else {
            format!("{} [{}]", entry.label, entry.category)
        };
        out_line!("  {:<24}{:<11}{}", label, entry.configured, entry.usable);
    }
    if explain {
        out_line!("");
        out_line!(
            "Use --explain detail: unavailable providers need review; disabled never schedule."
        );
        for entry in &summary {
            if entry.unavailable > 0 || entry.disabled > 0 {
                out_line!(
                    "  {}: {} unavailable, {} disabled",
                    entry.category,
                    entry.unavailable,
                    entry.disabled
                );
            }
        }
    }
}

fn run_search(args: &[String]) {
    let offset = usize::from(args.get(1).is_some_and(|arg| arg == "search")) + 1;
    if args.get(offset).is_some_and(|arg| arg == "stats") {
        run_search_stats(args, offset);
        return;
    }
    if args.get(offset).is_some_and(|arg| arg == "lint") {
        run_search_lint(args, offset);
        return;
    }
    if args
        .get(offset)
        .is_some_and(|arg| arg == "categories" || arg == "category")
    {
        run_search_categories(args, offset);
        return;
    }
    if args.get(offset).is_some_and(|arg| arg == "providers") {
        let rest: Vec<&String> = args.iter().skip(offset + 1).collect();
        let (json, filter) = parse_provider_filters(&rest);
        let pack = match rxscan::search::embedded_username_pack() {
            Ok(pack) => pack,
            Err(error) => {
                err!("rxscan search providers: {error}");
                std::process::exit(1);
            }
        };
        if !filter.categories.is_empty() {
            // Shared vocabulary: known categories include empty ones (e.g.
            // `adult` with zero providers today honestly schedules zero).
            let known: std::collections::BTreeSet<&str> =
                rxscan::search::known_username_categories()
                    .into_iter()
                    .collect();
            let unknown: Vec<&String> = filter
                .categories
                .iter()
                .filter(|category| !known.contains(category.as_str()))
                .collect();
            if !unknown.is_empty() {
                let mut known_list: Vec<&str> = known.into_iter().collect();
                known_list.sort();
                err!(
                    "rxscan search providers: unknown categor{}: {}; known: {}",
                    if unknown.len() == 1 { "y" } else { "ies" },
                    unknown
                        .iter()
                        .map(|category| category.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    known_list.join(", "),
                );
                std::process::exit(2);
            }
        }
        let stale_cutoff = filter.stale_only.then(|| rxscan::search::stale_cutoff(180));
        let shown: Vec<&rxscan::search::UsernameProviderDefinition> = pack
            .providers
            .iter()
            .filter(|provider| {
                (filter.health.is_empty() || filter.health.contains(provider.health_state.as_str()))
                    && (filter.categories.is_empty()
                        || filter.categories.contains(&provider.category))
                    && stale_cutoff.as_deref().is_none_or(|cutoff| {
                        rxscan::search::verification_stale(
                            &provider.health_state,
                            provider.verified_at.as_deref(),
                            cutoff,
                        )
                    })
            })
            .collect();
        if json {
            let providers = shown
                .iter()
                .map(|provider| {
                    serde_json::json!({
                        "id": provider.metadata.id,
                        "name": provider.platform,
                        "category": provider.category,
                        "category_label": rxscan::search::category_label(&provider.category),
                        "state": rxscan::search::provider_state(provider),
                        "type": "profile",
                        "contact_class": provider.metadata.contact_class,
                        "authentication_required": provider.metadata.requires_authentication,
                        "health_state": provider.health_state.as_str(),
                        "verified_at": provider.verified_at,
                    })
                })
                .collect::<Vec<_>>();
            emit_json_pretty(&serde_json::json!({
                "pack_version": pack.pack_version,
                "total_providers": pack.providers.len(),
                "active_providers": providers.len(),
                "providers": providers
            }));
        } else {
            let caps = resolve_human_caps(args);
            // Show filtered category in header when present (e.g. PROVIDERS social).
            let header_detail = if filter.categories.len() == 1 {
                filter.categories.iter().next().cloned()
            } else {
                None
            };
            out_line!(
                "{}",
                rxscan::terminal::workflow_header(caps, "SEARCH PROVIDERS", None)
            );
            if let Some(detail) = header_detail {
                out_line!("");
                out_line!("PROVIDERS  {detail}");
            }
            out_line!("");
            // Human table: PROVIDER STATE TYPE (STATE = usable/unavailable/disabled).
            out_line!("PROVIDER             STATE        TYPE");
            for provider in &shown {
                let state = rxscan::search::provider_state(provider);
                out_line!("  {:<20}{:<12}profile", provider.metadata.id, state,);
            }
            out_line!("");
            let usable = shown
                .iter()
                .filter(|p| rxscan::search::provider_state(p) == "usable")
                .count();
            let unavailable = shown
                .iter()
                .filter(|p| rxscan::search::provider_state(p) == "unavailable")
                .count();
            let disabled = shown
                .iter()
                .filter(|p| rxscan::search::provider_state(p) == "disabled")
                .count();
            out_line!("Summary:");
            out_line!("");
            out_line!(
                "  {} configured · {} usable · {} unavailable · {} disabled",
                shown.len(),
                usable,
                unavailable,
                disabled
            );
            // Legacy greppable detail (ID/NAME/CATEGORY/HEALTH) stays below
            // for scripts that parsed the old tab-separated rows.
            out_line!("");
            out_line!("ID\tNAME\tCATEGORY\tCONTACT\tAUTH\tHEALTH");
            for provider in shown {
                out_line!(
                    "{}\t{}\t{}\tpublic_http\t{}\t{}",
                    provider.metadata.id,
                    provider.platform,
                    provider.category,
                    if provider.metadata.requires_authentication {
                        "yes"
                    } else {
                        "no"
                    },
                    provider.health_state.as_str(),
                );
            }
        }
        return;
    }
    let mut username: Option<String> = None;
    // Passive local entity seeds (Phase 1 expansion, zero network).
    let mut email: Option<String> = None;
    let mut domain: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut ip: Option<String> = None;
    let mut asn: Option<String> = None;
    let mut url: Option<String> = None;
    let mut repo: Option<String> = None;
    let mut org: Option<String> = None;
    let mut json = false;
    let mut jsonl = false;
    let mut show_all = false;
    let mut explain = false;
    let mut deadline = std::time::Duration::from_secs(30);
    let mut deadline_set = false;
    let mut selected: Option<std::collections::BTreeSet<String>> = None;
    let mut excluded = std::collections::BTreeSet::<String>::new();
    let mut categories = std::collections::BTreeSet::<String>::new();
    let mut project_db: Option<std::path::PathBuf> = None;
    let mut index = offset;
    // Helper: ensure only one entity type is selected (additive; username
    // path keeps its exact prior semantics).
    macro_rules! set_passive {
        ($slot:ident, $value:expr, $flag:expr) => {{
            if username.is_some()
                || email.is_some()
                || domain.is_some()
                || hostname.is_some()
                || ip.is_some()
                || asn.is_some()
                || url.is_some()
                || repo.is_some()
                || org.is_some()
            {
                err!("rxscan search: only one of --username, --email, --domain, --hostname, --ip, --asn, --url, --repo, --org");
                std::process::exit(2);
            }
            if $slot.is_some() {
                err!("rxscan search: duplicate value for {}", $flag);
                std::process::exit(2);
            }
            $slot = Some($value);
        }};
    }
    while index < args.len() {
        match args[index].as_str() {
            "--username" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan search: --username requires a value");
                    std::process::exit(2);
                };
                if username.is_some()
                    || email.is_some()
                    || domain.is_some()
                    || hostname.is_some()
                    || ip.is_some()
                    || asn.is_some()
                    || url.is_some()
                    || repo.is_some()
                    || org.is_some()
                {
                    err!(
                        "rxscan search: only one of --username, --email, --domain, --hostname, --ip, --asn, --url, --repo, --org"
                    );
                    std::process::exit(2);
                }
                username = Some(value);
            }
            "username" => {
                // Positional form: `rxscan search username <name>`.
                index += 1;
                let Some(name) = args.get(index).cloned() else {
                    err!("rxscan search username: requires a username value");
                    std::process::exit(2);
                };
                if username.is_some()
                    || email.is_some()
                    || domain.is_some()
                    || hostname.is_some()
                    || ip.is_some()
                    || asn.is_some()
                    || url.is_some()
                    || repo.is_some()
                    || org.is_some()
                {
                    err!(
                        "rxscan search: only one of --username, --email, --domain, --hostname, --ip, --asn, --url, --repo, --org"
                    );
                    std::process::exit(2);
                }
                username = Some(name);
            }
            "--email" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan search: --email requires a value");
                    std::process::exit(2);
                };
                set_passive!(email, value, "--email");
            }
            "--domain" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan search: --domain requires a value");
                    std::process::exit(2);
                };
                set_passive!(domain, value, "--domain");
            }
            "--hostname" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan search: --hostname requires a value");
                    std::process::exit(2);
                };
                set_passive!(hostname, value, "--hostname");
            }
            "--ip" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan search: --ip requires a value");
                    std::process::exit(2);
                };
                set_passive!(ip, value, "--ip");
            }
            "--asn" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan search: --asn requires a value");
                    std::process::exit(2);
                };
                set_passive!(asn, value, "--asn");
            }
            "--url" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan search: --url requires a value");
                    std::process::exit(2);
                };
                set_passive!(url, value, "--url");
            }
            "--repo" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan search: --repo requires a value");
                    std::process::exit(2);
                };
                set_passive!(repo, value, "--repo");
            }
            "--org" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan search: --org requires a value");
                    std::process::exit(2);
                };
                set_passive!(org, value, "--org");
            }
            "email" | "domain" | "hostname" | "ip" | "asn" | "url" | "repo" | "org" => {
                // Positional form: `rxscan search domain example.test`.
                let kind = args[index].clone();
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan search {kind}: requires a value");
                    std::process::exit(2);
                };
                match kind.as_str() {
                    "email" => set_passive!(email, value, "email"),
                    "domain" => set_passive!(domain, value, "domain"),
                    "hostname" => set_passive!(hostname, value, "hostname"),
                    "ip" => set_passive!(ip, value, "ip"),
                    "asn" => set_passive!(asn, value, "asn"),
                    "url" => set_passive!(url, value, "url"),
                    "repo" => set_passive!(repo, value, "repo"),
                    _ => set_passive!(org, value, "org"),
                }
            }
            "--color" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan search: --color requires one of auto, always, never");
                    std::process::exit(2);
                };
                if !matches!(value.as_str(), "auto" | "always" | "never") {
                    err!("rxscan search: --color must be one of auto, always, never");
                    std::process::exit(2);
                }
            }
            arg if arg.starts_with("--color=") => {
                let value = arg.trim_start_matches("--color=");
                if !matches!(value, "auto" | "always" | "never") {
                    err!("rxscan search: --color must be one of auto, always, never");
                    std::process::exit(2);
                }
            }
            "--json" => json = true,
            "--jsonl" => jsonl = true,
            "--all" => show_all = true,
            "--explain" => explain = true,
            "--deadline" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan search: --deadline requires a duration");
                    std::process::exit(2);
                };
                deadline = match rxscan::config::parse_duration_ms(value) {
                    Ok(ms) => std::time::Duration::from_millis(ms),
                    Err(error) => {
                        err!("rxscan search: invalid deadline: {error}");
                        std::process::exit(2);
                    }
                };
                deadline_set = true;
            }
            "--providers" | "--provider" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan search: --provider requires a comma-separated list");
                    std::process::exit(2);
                };
                // Repeatable and comma-separated: multiple flags merge (same
                // plan as the web multi-select).
                let ids = value
                    .split(',')
                    .map(str::trim)
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                match &mut selected {
                    Some(existing) => {
                        existing.extend(ids);
                    }
                    None => {
                        selected = Some(ids.into_iter().collect());
                    }
                }
            }
            "--exclude-provider" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan search: --exclude-provider requires a comma-separated list");
                    std::process::exit(2);
                };
                excluded.extend(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|id| !id.is_empty())
                        .map(str::to_owned),
                );
            }
            "--category" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan search: --category requires a comma-separated list");
                    std::process::exit(2);
                };
                categories.extend(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|category| !category.is_empty())
                        .map(str::to_owned),
                );
            }
            "--project-db" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan search: --project-db requires a path");
                    std::process::exit(2);
                };
                project_db = Some(value.into());
            }
            "--help" | "-h" => {
                out_line!(
                    "RXSCAN\nReconnaissance / Evidence Engine\n\nUSAGE\n  rxscan search --username NAME [options]\n  rxscan search username NAME [options]\n  rxscan search --email EMAIL [--json|--jsonl] [--all] [--explain] [--project-db PATH]\n  rxscan search --domain DOMAIN [--json|--jsonl] [--all] [--explain] [--project-db PATH]\n  rxscan search --hostname HOST [--json|--jsonl] [--all] [--explain] [--project-db PATH]\n  rxscan search --ip IP [--json|--jsonl] [--all] [--explain] [--project-db PATH]\n  rxscan search --asn ASN [--json|--jsonl] [--all] [--explain] [--project-db PATH]\n  rxscan search --url URL [--json|--jsonl] [--all] [--explain] [--project-db PATH]\n  rxscan search --repo OWNER/NAME [--json|--jsonl] [--all] [--explain] [--project-db PATH]\n  rxscan search --org ORG [--json|--jsonl] [--all] [--explain] [--project-db PATH]\n\nWORKFLOWS\n  search         Public-source search\n\nEXAMPLES\n  rxscan search --username exampleuser\n  rxscan search --username exampleuser --all\n  rxscan search --email user@example.test\n  rxscan search --domain example.test\n  rxscan search --ip 192.0.2.10\n  rxscan search --asn AS64500\n  rxscan search --url https://example.test\n  rxscan search --repo example-org/example-project\n  rxscan search --org example-org\n\nOPTIONS\n  --username NAME            Target username (or `search username NAME`)\n  --email EMAIL              Passive local email canonicalization (no network)\n  --domain DOMAIN            Passive local domain canonicalization (no network)\n  --hostname HOST            Passive local hostname canonicalization (no network)\n  --ip IP                    Passive local IP canonicalization (no network)\n  --asn ASN                  Passive local ASN canonicalization (no network)\n  --url URL                  Passive local URL canonicalization (no network)\n  --repo OWNER/NAME          Passive local repository identity (no network, nothing cloned)\n  --org ORG                  Passive local organization identity (no network)\n  --provider IDS, --providers IDS  Comma-separated provider allowlist, repeatable (username search only)\n  --exclude-provider IDS     Comma-separated provider denylist (username search only)\n  --category CATEGORIES      Comma-separated category filter, repeatable (username search only, same plan as web Sources)\n  --deadline 30s             Per-search deadline (username search only)\n  --project-db PATH          Persist the report to a project database\n  --all                      Show complete human detail (all findings + provider notes)\n  --color MODE               auto (TTY only), always, or never\n  --json | --jsonl           Machine output (never styled, always complete)\n  --explain                  Show the search plan (alone, offline) or classification evidence with --all\n\nLEAF COMMANDS\n  rxscan search categories [--json] [--explain] [--color MODE]\n  rxscan search providers [--json] [--health STATE] [--category CAT] [--stale] [--color MODE]\n  rxscan search stats [--json] [--color MODE]\n  rxscan search lint [--json] [--corpus-root DIR] [--color MODE]\n  rxscan --username NAME [same options]"
                );
                return;
            }
            unknown => {
                // Friendly guidance: a bare positional like
                // `rxscan search exampleuser` strongly resembles the
                // username workflow. Suggest the correct form instead of
                // a bare "unknown option". Never silently reinterprets.
                let no_seed = username.is_none()
                    && email.is_none()
                    && domain.is_none()
                    && hostname.is_none()
                    && ip.is_none()
                    && asn.is_none()
                    && url.is_none()
                    && repo.is_none()
                    && org.is_none();
                if !unknown.starts_with('-') && no_seed && unknown != "username" {
                    err!("error: search needs a search type");
                    err!("");
                    err!("Try:");
                    err!("  rxscan search --username exampleuser");
                    err!("");
                    err!("Other types:");
                    err!("  --domain");
                    err!("  --email");
                    err!("  --hostname");
                    err!("  --url");
                    err!("  --ip");
                    err!("  --asn");
                    err!("  --repo");
                    err!("  --org");
                    std::process::exit(2);
                }
                err!("rxscan search: unknown option '{unknown}'");
                std::process::exit(2);
            }
        }
        index += 1;
    }
    if json && jsonl {
        err!("rxscan search: --json and --jsonl conflict");
        std::process::exit(2);
    }
    // Passive local entity path (additive; zero network). Provider and
    // deadline flags apply only to the username provider search.
    if email.is_some()
        || domain.is_some()
        || hostname.is_some()
        || ip.is_some()
        || asn.is_some()
        || url.is_some()
        || repo.is_some()
        || org.is_some()
    {
        if selected.is_some() || !excluded.is_empty() || !categories.is_empty() || deadline_set {
            err!(
                "rxscan search: --providers/--exclude-provider/--category/--deadline apply only to --username search; entity search is local-only"
            );
            std::process::exit(2);
        }
        run_entity_search(
            args, email, domain, hostname, ip, asn, url, repo, org, json, jsonl, show_all, explain,
            project_db,
        );
        return;
    }
    let Some(username) = username else {
        err!("Missing username.");
        err!("");
        err!("Try:");
        err!("  rxscan search --username exampleuser");
        err!("");
        err!("Other types:");
        err!("  --domain example.test");
        err!("  --email user@example.test");
        err!("  --hostname api.example.test");
        err!("  --url https://example.test");
        err!("  --ip 192.0.2.10");
        err!("  --asn AS64500");
        err!("  --repo example-org/example-project");
        err!("  --org example-org");
        std::process::exit(2);
    };
    let pack = match rxscan::search::embedded_username_pack() {
        Ok(pack) => pack,
        Err(error) => {
            err!("rxscan search: {error}");
            std::process::exit(1);
        }
    };
    // Shared core planning (same as web API): validates unknown
    // providers/categories and returns the REAL execution plan.
    let effective = match rxscan::search::plan_username_providers(
        &pack,
        selected.as_ref(),
        &excluded,
        &categories,
    ) {
        Ok(effective) => effective,
        Err(message) => {
            err!("rxscan search: {message}");
            std::process::exit(2);
        }
    };
    let selected_count = effective.len();
    if selected_count == 0 {
        err!("rxscan search: provider selection matched no providers");
        std::process::exit(2);
    }
    // --explain prints the deterministic plan (offline, no network) AND,
    // for human output, continues to run the search so classification
    // evidence/provenance becomes visible. Machine output (--json/--jsonl)
    // stays pure JSONL when requested.
    // --explain alone shows the deterministic offline plan (no network).
    // --explain with --all runs the search and shows classification
    // evidence/provenance (online). This keeps planning offline-deterministic
    // while still exposing WHY behind --explain when full detail is asked.
    let show_plan_only = explain && !show_all && !json && !jsonl;
    let show_plan = explain && !json && !jsonl;
    if show_plan_only {
        // Fall through to plan printing below, then return early (no network).
    }
    if show_plan {
        out_line!("Username search plan");
        out_line!("seed: username:{username}");
        out_line!("providers selected: {selected_count}");
        let mut validity_skipped: Vec<(String, String)> = pack
            .providers
            .iter()
            .filter(|provider| {
                selected
                    .as_ref()
                    .is_none_or(|ids| ids.contains(&provider.metadata.id))
                    && !excluded.contains(&provider.metadata.id)
                    && (categories.is_empty() || categories.contains(&provider.category))
            })
            .filter_map(|provider| {
                rxscan::search::username_skip_reason(provider, &username)
                    .map(|reason| (provider.metadata.id.clone(), reason))
            })
            .collect();
        validity_skipped.sort();
        for (id, reason) in &validity_skipped {
            out_line!("skipped: {id} ({reason})");
        }
        out_line!(
            "categories: {}",
            if categories.is_empty() {
                "all".to_owned()
            } else {
                categories.iter().cloned().collect::<Vec<_>>().join(",")
            }
        );
        out_line!("global concurrency: 4");
        out_line!("per-host concurrency: 1");
        out_line!("deadline: {}ms", deadline.as_millis());
        out_line!("contact class: public_http");
        out_line!(
            "project persistence: {}",
            project_db
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "disabled".to_owned())
        );
        out_line!("direct network scanning: disabled");
        out_line!("network scans: 0");
        out_line!("");
    }
    if show_plan_only {
        return;
    }
    // Cancellation reaches the real scheduler: SIGINT sets the
    // process-lifetime atomic the core polls; completed evidence survives.
    install_search_cancel();
    let cancelled = rxscan::platform::process::process_cancel_flag();
    // Restrained TTY progress (never into pipes/machine output, never faked).
    let progress_caps = resolve_human_caps(args);
    let show_progress = progress_caps.tty && progress_caps.color && !json && !jsonl;
    let username_owned = username.clone();
    let progress_hook = |completed: usize, total: usize| {
        if show_progress {
            use std::io::Write as _;
            let _ = write!(
                std::io::stderr(),
                "\rSEARCHING  {}  {}/{} complete",
                username_owned,
                completed,
                total
            );
            let _ = std::io::stderr().flush();
        }
    };
    if show_progress {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "SEARCHING  {username}");
    }
    let report = match rxscan::search::execute_username_search_full(
        &username,
        rxscan::search::DEFAULT_SEARCH_CONCURRENCY,
        rxscan::search::MAX_SEARCH_PER_HOST,
        deadline,
        Some(&effective),
        &excluded,
        &categories,
        cancelled,
        Some(&progress_hook),
    ) {
        Ok(report) => report,
        Err(error) => {
            err!("rxscan search: {error}");
            std::process::exit(1);
        }
    };
    if show_progress {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr());
    }
    let was_cancelled = cancelled.load(std::sync::atomic::Ordering::Acquire);
    if let Some(path) = project_db {
        let mut db = match rxscan::project_db::ProjectDb::open(&path) {
            Ok(db) => db,
            Err(error) => {
                err!("rxscan search: could not open project database: {error}");
                std::process::exit(1);
            }
        };
        if let Err(error) = rxscan::search::persist_username_report(&mut db, &report) {
            err!("rxscan search: could not persist search report: {error}");
            std::process::exit(1);
        }
    }
    if json {
        emit_json_pretty(&report);
    } else if jsonl {
        out!("{}", rxscan::search::render_username_jsonl(&report));
    } else {
        let caps = resolve_human_caps(args);
        let mut rows = search_report_rows(&report);
        // --all makes unscanned/skipped providers visible (honest, never
        // invented observations): synthesize quiet rows for scheduled
        // providers without an observation.
        {
            use rxscan::terminal::{RowTier, SearchRow};
            let completed: std::collections::BTreeSet<&str> = report
                .results
                .iter()
                .map(|result| result.provider_id.as_str())
                .collect();
            let mut missing: Vec<(&String, String)> = Vec::new();
            for provider in &effective {
                if !completed.contains(provider.as_str()) {
                    // Distinguish skip reasons (disabled/rules) from
                    // deadline/cancel unscanned.
                    let reason = pack
                        .providers
                        .iter()
                        .find(|definition| &definition.metadata.id == provider)
                        .and_then(|definition| {
                            rxscan::search::username_skip_reason(definition, &username)
                        })
                        .unwrap_or_else(|| {
                            if was_cancelled || report.accounting.cancelled > 0 {
                                "cancelled".to_owned()
                            } else {
                                "deadline reached".to_owned()
                            }
                        });
                    let status: &'static str = if reason == "provider is disabled" {
                        "unscanned"
                    } else if reason.contains("cancelled") {
                        "cancelled"
                    } else if reason.contains("shorter")
                        || reason.contains("exceeds")
                        || reason.contains("characters")
                    {
                        "skipped"
                    } else {
                        "unscanned"
                    };
                    // Leak a 'static status via known set.
                    let key: &'static str = match status {
                        "cancelled" => "cancelled",
                        "skipped" => "skipped",
                        _ => "unscanned",
                    };
                    rows.push(SearchRow {
                        status: key,
                        provider: (*provider).clone(),
                        confidence: 0,
                        detail: reason.clone(),
                        tier: RowTier::Quiet,
                        url: String::new(),
                        url_observed: false,
                    });
                    missing.push((provider, reason));
                }
            }
            let _ = missing;
        }
        let summary = rxscan::terminal::SearchSummary {
            requested: report.accounting.providers_requested,
            completed: report.accounting.providers_completed,
            skipped: report.accounting.skipped,
            cancelled: report.accounting.cancelled,
            unscanned: report.accounting.unscanned,
            truncated: report.accounting.truncated,
        };
        // Enrichment from the same core evidence (categories, metadata,
        // evidence, provenance) + per-category coverage from the real plan.
        let (enrichment, category_coverage) = build_search_enrichment(&report, &pack, &effective);
        // Registry-wide denominators stay distinct from the per-run
        // scheduled set, so the header is honest at any corpus size.
        let registry = rxscan::search::username_registry_counts(&pack);
        let scale = rxscan::terminal::SearchScaleHeader {
            vectors_registered: registry.vectors_registered,
            providers_usable: registry.usable,
        };
        out!(
            "{}",
            rxscan::terminal::render_search_report_full(
                &report.seed.display_value,
                report.accounting.providers_requested,
                &rows,
                &summary,
                show_all,
                explain,
                was_cancelled || summary.cancelled > 0,
                caps,
                Some(&enrichment),
                Some(&category_coverage),
                Some(&scale),
            )
        );
    }
}

/// Passive local entity search (`rxscan search --email/--domain/...`).
///
/// Zero network contact. Canonicalizes one identifier, derives directly
/// implied local entities (email->domain, url->domain, repo->org), and
/// renders human/JSON/JSONL with `network_scans: 0`. DNS/profile
/// enrichment lives in `rxscan investigate`, never here.
#[allow(clippy::too_many_arguments)]
fn run_entity_search(
    args: &[String],
    email: Option<String>,
    domain: Option<String>,
    hostname: Option<String>,
    ip: Option<String>,
    asn: Option<String>,
    url: Option<String>,
    repo: Option<String>,
    org: Option<String>,
    json: bool,
    jsonl: bool,
    show_all: bool,
    explain: bool,
    project_db: Option<std::path::PathBuf>,
) {
    use rxscan::search::SearchEntityKind;
    let (kind, value) = if let Some(v) = email {
        (SearchEntityKind::EmailAddress, v)
    } else if let Some(v) = domain {
        (SearchEntityKind::Domain, v)
    } else if let Some(v) = hostname {
        (SearchEntityKind::Hostname, v)
    } else if let Some(v) = ip {
        (SearchEntityKind::IpAddress, v)
    } else if let Some(v) = asn {
        (SearchEntityKind::Asn, v)
    } else if let Some(v) = url {
        (SearchEntityKind::Url, v)
    } else if let Some(v) = repo {
        (SearchEntityKind::Repository, v)
    } else if let Some(v) = org {
        (SearchEntityKind::Organization, v)
    } else {
        err!("rxscan search: missing entity value");
        std::process::exit(2);
    };
    if explain {
        out_line!(
            "{}",
            rxscan::entity_search::explain_entity_plan(kind, &value)
        );
        out_line!(
            "project persistence: {}",
            project_db
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "disabled".to_owned())
        );
        return;
    }
    let report = match rxscan::entity_search::execute_entity_search(kind, &value) {
        Ok(report) => report,
        Err(error) => {
            err!("rxscan search: {error}");
            std::process::exit(1);
        }
    };
    if let Some(path) = project_db {
        let mut db = match rxscan::project_db::ProjectDb::open(&path) {
            Ok(db) => db,
            Err(error) => {
                err!("rxscan search: could not open project database: {error}");
                std::process::exit(1);
            }
        };
        if let Err(error) = rxscan::entity_search::persist_entity_report(&mut db, &report) {
            err!("rxscan search: could not persist search report: {error}");
            std::process::exit(1);
        }
    }
    if json {
        emit_json_pretty(&report);
    } else if jsonl {
        out!("{}", rxscan::entity_search::render_entity_jsonl(&report));
    } else {
        let caps = resolve_human_caps(args);
        out_line!(
            "{}",
            rxscan::terminal::workflow_header(caps, "ENTITY SEARCH", None)
        );
        out_line!("");
        out!(
            "{}",
            rxscan::entity_search::render_entity_human(&report, show_all)
        );
    }
}

fn run_project(args: &[String]) {
    let Some(command) = args.get(2).map(String::as_str) else {
        err!(
            "rxscan project: usage: rxscan project create|add|summary|show|neighbors|related|path|scans|findings|changes|timeline|attention|graph|explain|diff ..."
        );
        std::process::exit(2);
    };
    match command {
        "--help" | "-h" => {
            out_line!(
                "rxscan project create <project.rxproj>\nrxscan project add <project.rxproj> <scan.rxscan>\nrxscan project summary <project.rxproj> [--json]\nrxscan project graph <project.rxproj> [--json]\nrxscan project show <project.rxproj> <entity> [--json]\nrxscan project explain <project.rxproj> <entity> [--limit N] [--json]\nrxscan project neighbors <project.rxproj> <entity> [--depth N] [--limit N] [--json|--jsonl]\nrxscan project related <project.rxproj> <entity> [--depth N] [--limit N] [--json|--jsonl]\nrxscan project path <project.rxproj> <from> <to> [--json]\nrxscan project scans <project.rxproj> [--json]\nrxscan project findings <project.rxproj> [entity] [--limit N] [--json|--jsonl]\nrxscan project changes <project.rxproj> [entity] [--limit N] [--json|--jsonl]\nrxscan project timeline <project.rxproj> [entity] [--limit N] [--json|--jsonl]\nrxscan project attention <project.rxproj> [entity] [--limit N] [--json|--jsonl]\nrxscan project diff <old.rxscan> <new.rxscan> [--json] [--summary-only]"
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
                    emit_json_pretty(&summary);
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
                    Some(found) => emit_json_pretty(&found),
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
        "explain" => {
            let (Some(path), Some(entity)) = (args.get(3), args.get(4)) else {
                err!(
                    "rxscan project explain: usage: rxscan project explain <project> <entity> [--limit N] [--json]"
                );
                std::process::exit(2);
            };
            let mut limit = project::DEFAULT_QUERY_LIMIT;
            let mut json = false;
            let mut iter = args[5..].iter();
            while let Some(arg) = iter.next() {
                match arg.as_str() {
                    "--limit" => {
                        let Some(value) = iter.next() else {
                            err!("rxscan project explain: --limit requires a value");
                            std::process::exit(2);
                        };
                        limit = value.parse().unwrap_or(project::DEFAULT_QUERY_LIMIT);
                    }
                    "--json" => json = true,
                    other => {
                        err!("rxscan project explain: unsupported option {other}");
                        std::process::exit(2);
                    }
                }
            }
            match project::load_project(std::path::Path::new(path)) {
                Ok(state) => match project::explain_entity(&state, entity, limit) {
                    Ok(explanation) if json => emit_json_pretty(&explanation),
                    Ok(explanation) => out_line!("{}", project::render_explanation(&explanation)),
                    Err(error) => {
                        err!("rxscan project explain: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    err!("rxscan project explain: {error}");
                    std::process::exit(1);
                }
            }
        }
        // `related` is an additive alias for `neighbors` (same bounded
        // traversal, same output shape, no second implementation).
        "neighbors" | "related" => {
            let (Some(path), Some(entity)) = (args.get(3), args.get(4)) else {
                err!(
                    "rxscan project {command}: usage: rxscan project {command} <project> <entity> [--depth N] [--limit N] [--json|--jsonl]"
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
                            err!("rxscan project {command}: --depth requires a value");
                            std::process::exit(2);
                        };
                        depth = value.parse().unwrap_or(project::DEFAULT_QUERY_DEPTH);
                    }
                    "--limit" => {
                        let Some(value) = iter.next() else {
                            err!("rxscan project {command}: --limit requires a value");
                            std::process::exit(2);
                        };
                        limit = value.parse().unwrap_or(project::DEFAULT_QUERY_LIMIT);
                    }
                    "--json" => json = true,
                    "--jsonl" => jsonl = true,
                    _ => {
                        err!("rxscan project {command}: unsupported option {arg}");
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
                    Ok(result) => emit_json_pretty(&result),
                    Err(error) => {
                        err!("rxscan project {command}: {error}");
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
                        err!("rxscan project {command}: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    err!("rxscan project {command}: {error}");
                    std::process::exit(1);
                }
            }
        }
        // `path` answers "why are these connected?" with the evidence
        // chain (bounded BFS, deterministic, cycle-safe).
        "path" => {
            let (Some(path), Some(from), Some(to)) = (args.get(3), args.get(4), args.get(5)) else {
                err!(
                    "rxscan project path: usage: rxscan project path <project.rxproj> <from> <to> [--json]"
                );
                std::process::exit(2);
            };
            let json = args[6..].iter().any(|a| a == "--json");
            match project::load_project(std::path::Path::new(path)) {
                Ok(state) => match state.path(from, to, project::MAX_QUERY_DEPTH) {
                    Ok(chain) if json => emit_json_pretty(&chain),
                    Ok(chain) if chain.is_empty() => {
                        out_line!("path {from} -> {to}: same entity (0 hops) network_requests=0")
                    }
                    Ok(chain) => {
                        out_line!(
                            "path {from} -> {to}: {} hops network_requests=0",
                            chain.len()
                        );
                        for rel in chain {
                            out_line!(
                                "  {} --{:?}--> {}",
                                rel.from_entity,
                                rel.kind,
                                rel.to_entity
                            );
                        }
                    }
                    Err(error) => {
                        err!("rxscan project path: {error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    err!("rxscan project path: {error}");
                    std::process::exit(1);
                }
            }
        }
        // `graph` is an additive summary view over the same project state
        // (no second graph implementation): counts plus bounded listing.
        "graph" => {
            let Some(path) = args.get(3) else {
                err!("rxscan project graph: usage: rxscan project graph <project.rxproj> [--json]");
                std::process::exit(2);
            };
            let json = args[4..].iter().any(|a| a == "--json");
            match project::load_project_with_timing(std::path::Path::new(path)) {
                Ok((state, _, bytes)) if json => {
                    let summary = state.summary(bytes);
                    emit_json_pretty(&summary);
                }
                Ok((state, _, bytes)) => {
                    out_line!("{}", project::render_summary(&state, bytes));
                    out_line!(
                        "graph entities={} relationships={} network_requests=0",
                        state.entities.len(),
                        state.relationships.len()
                    );
                }
                Err(error) => {
                    err!("rxscan project graph: {error}");
                    std::process::exit(1);
                }
            }
        }
        // `diff` is an additive alias for checkpoint diffing over two
        // scan files (same `rxscan diff` engine, no second implementation).
        "diff" => {
            let mut json = false;
            let mut summary_only = false;
            let mut paths: Vec<String> = Vec::new();
            for arg in &args[3..] {
                match arg.as_str() {
                    "--json" | "--jsonl" => json = true,
                    "--summary-only" => summary_only = true,
                    value => paths.push(value.to_owned()),
                }
            }
            if paths.len() != 2 {
                err!(
                    "rxscan project diff: usage: rxscan project diff <old.rxscan> <new.rxscan> [--json] [--summary-only]"
                );
                std::process::exit(2);
            }
            let options = rxscan::diff::DiffOptions {
                summary_only,
                max_records: rxscan::diff::MAX_DIFF_RECORDS,
            };
            match rxscan::diff::diff_checkpoints(
                std::path::Path::new(&paths[0]),
                std::path::Path::new(&paths[1]),
                options,
            ) {
                Ok((report, _, _, _)) if json => match rxscan::diff::to_json(&report) {
                    Ok(text) => out_line!("{text}"),
                    Err(error) => {
                        err!("rxscan project diff: {error}");
                        std::process::exit(1);
                    }
                },
                Ok((report, _, _, _)) => out_line!("{}", rxscan::diff::human_summary(&report)),
                Err(error) => {
                    err!("rxscan project diff: {error}");
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
                    emit_json_pretty(&scans);
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
        // `timeline` is an additive alias for `changes` (same
        // coverage-aware query, no second implementation).
        "findings" | "changes" | "timeline" | "attention" => {
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
                            Ok(result) => emit_json_pretty(&result),
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
                "changes" | "timeline" => {
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
                                err!("rxscan project {command}: {error}");
                                std::process::exit(1);
                            }
                        }
                    } else if json {
                        match state.changes_query(entity_ref, limit) {
                            Ok(result) => emit_json_pretty(&result),
                            Err(error) => {
                                err!("rxscan project {command}: {error}");
                                std::process::exit(1);
                            }
                        }
                    } else {
                        match project::render_changes(&state, entity_ref, limit) {
                            Ok(text) => out!("{text}"),
                            Err(error) => {
                                err!("rxscan project {command}: {error}");
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
                            Ok(result) => emit_json_pretty(&result),
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

/// SQLite project graph commands (`--project-db` import target).
///
/// Usage:
/// `rxscan project-db scans --db <path> [--json]`
/// `rxscan project-db summary --db <path> [--json]`
/// `rxscan project-db changes --db <path> <scan> [--json] [--limit N]`
/// `rxscan project-db diff --db <path> <old-scan> <new-scan> [--json] [--limit N]`
///
/// Read-only except `diff`, which persists computed changes for the scan
/// pair. Never touches the network; scope already enforced at scan time.
fn run_project_db(args: &[String]) {
    use rxscan::project_db::ProjectDb;
    let usage = "rxscan project-db scans|summary|changes|diff|explain --db <path> ...";
    let command = args.get(2).map(String::as_str).unwrap_or("--help");
    if command == "--help" || command == "-h" {
        out_line!(
            "rxscan project-db scans --db <path> [--json]\nrxscan project-db summary --db <path> [--json]\nrxscan project-db changes --db <path> <scan> [--json] [--limit N]\nrxscan project-db diff --db <path> <old-scan> <new-scan> [--json] [--limit N] [--check]\nrxscan project-db explain --db <path> <entity> [--json] [--limit N]"
        );
        return;
    }
    // Minimal flag parsing: --db <path>, --json, --limit N, --check, positionals.
    let mut db_path: Option<&str> = None;
    let mut json = false;
    let mut check = false;
    let mut limit = 100usize;
    let mut positionals: Vec<&str> = Vec::new();
    let mut iter = args[3..].iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--db" => {
                db_path = iter.next().map(String::as_str);
            }
            "--json" => json = true,
            // Automation foundation (Stage 7): `--check` turns diff into
            // a change detector for scheduled runs — exit 0 when the two
            // runs agree, exit 3 when changes exist. Default output and
            // exit codes are unchanged without the flag.
            "--check" => check = true,
            "--limit" => {
                limit = iter
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(100)
                    .min(10_000);
            }
            other => positionals.push(other),
        }
    }
    let Some(db_path) = db_path else {
        err!("rxscan project-db {command}: missing --db <path> ({usage})");
        std::process::exit(2);
    };
    let db = match ProjectDb::open(std::path::Path::new(db_path)) {
        Ok(db) => db,
        Err(error) => {
            err!("rxscan project-db {command}: {error}");
            std::process::exit(1);
        }
    };
    match command {
        "scans" => {
            let scans = db.scan_ids().unwrap_or_default();
            if json {
                emit_json_pretty(&scans);
            } else if scans.is_empty() {
                out_line!("no scans imported");
            } else {
                for scan in scans {
                    out_line!("{}", scan);
                }
            }
        }
        "summary" => {
            let scans = db.scan_ids().unwrap_or_default();
            if json {
                out_line!(
                    "{}",
                    serde_json::json!({
                        "scans": scans.len(),
                        "scan_ids": scans,
                    })
                );
            } else {
                out_line!("project scans: {}", scans.len());
                for scan in scans {
                    out_line!("  {scan}");
                }
            }
        }
        "changes" => {
            let Some(scan) = positionals.first() else {
                err!(
                    "rxscan project-db changes: usage: rxscan project-db changes --db <path> <scan> [--json] [--limit N]"
                );
                std::process::exit(2);
            };
            let stored = db.changes_since(scan, limit).unwrap_or_default();
            if json {
                emit_json_pretty(&stored);
            } else if stored.is_empty() {
                out_line!("no recorded changes for {scan}");
            } else {
                let changes: Vec<rxscan::project_db::GraphChange> = stored
                    .into_iter()
                    .map(|record| rxscan::project_db::GraphChange {
                        change_type: rxscan::project_db::ChangeType::parse(&record.change_type)
                            .unwrap_or(rxscan::project_db::ChangeType::Changed),
                        entity_id: record.entity_id,
                        old_value: record.old_value,
                        new_value: record.new_value,
                        confidence: record.confidence,
                        evidence: record.evidence,
                    })
                    .collect();
                out_line!("{}", rxscan::project_db::human_changes_summary(&changes));
            }
        }
        "diff" => {
            if positionals.len() < 2 {
                err!(
                    "rxscan project-db diff: usage: rxscan project-db diff --db <path> <old-scan> <new-scan> [--json] [--limit N]"
                );
                std::process::exit(2);
            }
            let (old_scan, new_scan) = (positionals[0], positionals[1]);
            let changes = match db.diff_scan_runs(old_scan, new_scan) {
                Ok(changes) => changes,
                Err(error) => {
                    err!("rxscan project-db diff: {error}");
                    std::process::exit(1);
                }
            };
            let changes: Vec<_> = changes.into_iter().take(limit).collect();
            // Persist for later `changes` queries (same transaction batch).
            let mut db = db;
            if let Err(error) = db.record_changes(new_scan, old_scan, &changes) {
                err!("rxscan project-db diff: {error}");
                std::process::exit(1);
            }
            if json {
                emit_json_pretty(&changes);
            } else {
                out_line!("{}", rxscan::project_db::human_changes_summary(&changes));
            }
            if check {
                std::process::exit(i32::from(!changes.is_empty()) * 3);
            }
        }
        "explain" => {
            let Some(entity) = positionals.first() else {
                err!(
                    "rxscan project-db explain: usage: rxscan project-db explain --db <path> <entity> [--json] [--limit N]"
                );
                std::process::exit(2);
            };
            let observations = match db.provenance_chain(entity) {
                Ok(rows) => rows,
                Err(error) => {
                    err!("rxscan project-db explain: {error}");
                    std::process::exit(1);
                }
            };
            if observations.is_empty() {
                err!("rxscan project-db explain: unknown entity {entity}");
                std::process::exit(1);
            }
            // Bounded inbound walk toward the seed (cycle-guarded).
            let mut chain: Vec<String> = Vec::new();
            let mut current = (*entity).to_owned();
            let mut seen = std::collections::BTreeSet::new();
            seen.insert(current.clone());
            for _ in 0..8 {
                let inbound = match db.edges_to(&current) {
                    Ok(edges) => edges,
                    Err(error) => {
                        err!("rxscan project-db explain: {error}");
                        std::process::exit(1);
                    }
                };
                let Some(edge) = inbound.first() else { break };
                chain.push(format!(
                    "{} --{}--> {} ({})",
                    edge.from_id,
                    edge.relation,
                    edge.to_id,
                    edge.evidence.chars().take(120).collect::<String>()
                ));
                if !seen.insert(edge.from_id.clone()) {
                    break;
                }
                current = edge.from_id.clone();
            }
            if json {
                emit_json_pretty(&serde_json::json!({
                    "entity": entity,
                    "chain": chain,
                    "observations": observations,
                }));
            } else {
                out_line!("Why is {entity} present?");
                out_line!("");
                for (index, step) in chain.iter().enumerate() {
                    out_line!("{}. {step}", index + 1);
                }
                if chain.is_empty() {
                    out_line!("(seed entity: no inbound relationships)");
                }
                out_line!("");
                out_line!("observations: {}", observations.len());
                for observation in observations.iter().take(limit) {
                    out_line!(
                        "  {} via {}: {}",
                        observation.scan_run,
                        observation.module,
                        observation
                            .evidence_excerpt
                            .chars()
                            .take(100)
                            .collect::<String>()
                    );
                }
            }
        }
        _ => {
            err!("rxscan project-db: unknown command {command} ({usage})");
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

fn run_unknown(args: &[String]) {
    let mut limit = unknown::DEFAULT_UNKNOWN_LIMIT;
    let mut json = false;
    let mut checkpoint: Option<String> = None;
    let mut iter = args[2..].iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                out_line!(
                    "rxscan unknown [--limit N] [--json] <scan.rxscan>\nExport bounded sanitized unknown-service fingerprints for future rule development. Local only; nothing is uploaded."
                );
                return;
            }
            "--limit" => {
                let Some(value) = iter.next() else {
                    err!("rxscan unknown: --limit requires a value");
                    std::process::exit(2);
                };
                limit = value
                    .parse()
                    .unwrap_or(unknown::DEFAULT_UNKNOWN_LIMIT)
                    .min(unknown::MAX_UNKNOWN_LIMIT);
            }
            "--json" => json = true,
            value if checkpoint.is_none() => checkpoint = Some(value.to_owned()),
            _ => {
                err!("rxscan unknown: usage: rxscan unknown [--limit N] [--json] <scan.rxscan>");
                std::process::exit(2);
            }
        }
    }
    let Some(current) = checkpoint else {
        err!("rxscan unknown: usage: rxscan unknown [--limit N] [--json] <scan.rxscan>");
        std::process::exit(2);
    };
    match unknown::export_unknown(std::path::Path::new(&current), limit) {
        Ok(export) if json => emit_json_pretty(&export),
        Ok(export) => out!("{}", unknown::render_human(&export)),
        Err(error) => {
            err!("rxscan unknown: {error}");
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

/// Passive investigation workflow (`rxscan investigate ...`).
///
/// PUBLIC/PASSIVE by default: never invokes the network scanner, never
/// uses `DirectNetwork`, never activates authenticated APIs. Entity
/// creation is not contact; only bounded public transforms contact
/// anything, and unsafe destinations are observed-as-text at most.
///
/// Usage:
/// `rxscan investigate --username NAME [--depth N] [--explain] [--json|--jsonl] [--project-db PATH] [--all] ...`
/// `rxscan investigate --domain NAME ...`
/// `rxscan investigate --url URL ...`
/// `rxscan investigate transforms [--json]`
fn run_investigate(args: &[String]) {
    use rxscan::investigate as inv;
    // Transform listing: `rxscan investigate transforms [--json]`.
    if args.get(2).is_some_and(|arg| arg == "transforms") {
        let json = args[3..].iter().any(|a| a == "--json");
        validate_color_flags("investigate transforms", args);
        for arg in &args[3..] {
            if arg != "--json" && !arg.starts_with("--color") {
                err!("rxscan investigate transforms: only --json and --color are supported");
                std::process::exit(2);
            }
        }
        let registry = inv::TransformRegistry::new();
        if json {
            emit_json_pretty(&registry.infos());
        } else {
            let caps = resolve_human_caps(args);
            out_line!(
                "{}",
                rxscan::terminal::workflow_header(caps, "INVESTIGATE TRANSFORMS", None)
            );
            out_line!("");
            for info in registry.infos() {
                out_line!(
                    "  {:<20} accepts {} [{}]",
                    info.id,
                    info.accepts.join(","),
                    inv::contact_class_as_str(info.contact_class)
                );
            }
            out_line!("");
            out_line!(
                "DirectNetwork: disabled by default; passive investigation never port scans."
            );
        }
        return;
    }
    let mut username: Option<String> = None;
    let mut domain: Option<String> = None;
    let mut url: Option<String> = None;
    let mut email: Option<String> = None;
    let mut ip: Option<String> = None;
    let mut asn: Option<String> = None;
    let mut repo: Option<String> = None;
    let mut org: Option<String> = None;
    let mut depth: u8 = inv::DEFAULT_DEPTH;
    let mut explain = false;
    let mut json = false;
    let mut jsonl = false;
    let mut show_all = false;
    let mut deadline = inv::DEFAULT_INVESTIGATION_DEADLINE;
    let mut max_entities = inv::DEFAULT_MAX_ENTITIES;
    let mut max_relationships = inv::DEFAULT_MAX_RELATIONSHIPS;
    let mut max_http = inv::DEFAULT_MAX_HTTP_REQUESTS;
    let mut max_dns = inv::DEFAULT_MAX_DNS_QUERIES;
    let mut max_providers = inv::DEFAULT_MAX_PROVIDERS;
    let mut selected: Option<std::collections::BTreeSet<String>> = None;
    let mut excluded = std::collections::BTreeSet::<String>::new();
    let mut categories = std::collections::BTreeSet::<String>::new();
    let mut project_db: Option<std::path::PathBuf> = None;
    let mut exposure = false;
    let mut exposure_dataset: Option<std::path::PathBuf> = None;
    let mut network = false;
    let mut scopes: Vec<String> = Vec::new();
    let mut scope_exclusions: Vec<String> = Vec::new();
    let mut max_network_pivots = inv::DEFAULT_MAX_NETWORK_PIVOTS;
    let mut index = 2usize;
    while index < args.len() {
        match args[index].as_str() {
            "--username" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan investigate: --username requires a value");
                    std::process::exit(2);
                };
                if username.is_some()
                    || domain.is_some()
                    || url.is_some()
                    || email.is_some()
                    || ip.is_some()
                    || asn.is_some()
                    || repo.is_some()
                    || org.is_some()
                {
                    err!(
                        "rxscan investigate: only one of --username, --domain, --url, --email, --ip, --asn, --repo, --org"
                    );
                    std::process::exit(2);
                }
                username = Some(value);
            }
            "--domain" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan investigate: --domain requires a value");
                    std::process::exit(2);
                };
                if username.is_some()
                    || domain.is_some()
                    || url.is_some()
                    || email.is_some()
                    || ip.is_some()
                    || asn.is_some()
                    || repo.is_some()
                    || org.is_some()
                {
                    err!(
                        "rxscan investigate: only one of --username, --domain, --url, --email, --ip, --asn, --repo, --org"
                    );
                    std::process::exit(2);
                }
                domain = Some(value);
            }
            "--url" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan investigate: --url requires a value");
                    std::process::exit(2);
                };
                if username.is_some()
                    || domain.is_some()
                    || url.is_some()
                    || email.is_some()
                    || ip.is_some()
                    || asn.is_some()
                    || repo.is_some()
                    || org.is_some()
                {
                    err!(
                        "rxscan investigate: only one of --username, --domain, --url, --email, --ip, --asn, --repo, --org"
                    );
                    std::process::exit(2);
                }
                url = Some(value);
            }
            "--email" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan investigate: --email requires a value");
                    std::process::exit(2);
                };
                if username.is_some()
                    || domain.is_some()
                    || url.is_some()
                    || email.is_some()
                    || ip.is_some()
                    || asn.is_some()
                    || repo.is_some()
                    || org.is_some()
                {
                    err!(
                        "rxscan investigate: only one of --username, --domain, --url, --email, --ip, --asn, --repo, --org"
                    );
                    std::process::exit(2);
                }
                email = Some(value);
            }
            "--ip" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan investigate: --ip requires a value");
                    std::process::exit(2);
                };
                if username.is_some()
                    || domain.is_some()
                    || url.is_some()
                    || email.is_some()
                    || ip.is_some()
                    || asn.is_some()
                    || repo.is_some()
                    || org.is_some()
                {
                    err!(
                        "rxscan investigate: only one of --username, --domain, --url, --email, --ip, --asn, --repo, --org"
                    );
                    std::process::exit(2);
                }
                ip = Some(value);
            }
            "--asn" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan investigate: --asn requires a value");
                    std::process::exit(2);
                };
                if username.is_some()
                    || domain.is_some()
                    || url.is_some()
                    || email.is_some()
                    || ip.is_some()
                    || asn.is_some()
                    || repo.is_some()
                    || org.is_some()
                {
                    err!(
                        "rxscan investigate: only one of --username, --domain, --url, --email, --ip, --asn, --repo, --org"
                    );
                    std::process::exit(2);
                }
                asn = Some(value);
            }
            "--repo" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan investigate: --repo requires a value");
                    std::process::exit(2);
                };
                if username.is_some()
                    || domain.is_some()
                    || url.is_some()
                    || email.is_some()
                    || ip.is_some()
                    || asn.is_some()
                    || repo.is_some()
                    || org.is_some()
                {
                    err!(
                        "rxscan investigate: only one of --username, --domain, --url, --email, --ip, --asn, --repo, --org"
                    );
                    std::process::exit(2);
                }
                repo = Some(value);
            }
            "--org" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan investigate: --org requires a value");
                    std::process::exit(2);
                };
                if username.is_some()
                    || domain.is_some()
                    || url.is_some()
                    || email.is_some()
                    || ip.is_some()
                    || asn.is_some()
                    || repo.is_some()
                    || org.is_some()
                {
                    err!(
                        "rxscan investigate: only one of --username, --domain, --url, --email, --ip, --asn, --repo, --org"
                    );
                    std::process::exit(2);
                }
                org = Some(value);
            }
            "--depth" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --depth requires a value");
                    std::process::exit(2);
                };
                match value.parse::<u8>() {
                    Ok(parsed) if parsed <= inv::MAX_DEPTH => depth = parsed,
                    _ => {
                        err!(
                            "rxscan investigate: --depth must be an integer from 0 to {}",
                            inv::MAX_DEPTH
                        );
                        std::process::exit(2);
                    }
                }
            }
            "--explain" => explain = true,
            "--json" => json = true,
            "--jsonl" => jsonl = true,
            "--all" => show_all = true,
            "--deadline" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --deadline requires a duration");
                    std::process::exit(2);
                };
                deadline = match rxscan::config::parse_duration_ms(value) {
                    Ok(ms) => std::time::Duration::from_millis(ms),
                    Err(error) => {
                        err!("rxscan investigate: invalid deadline: {error}");
                        std::process::exit(2);
                    }
                };
            }
            "--max-entities" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --max-entities requires a value");
                    std::process::exit(2);
                };
                match value.parse::<usize>() {
                    Ok(parsed) if (1..=inv::HARD_MAX_ENTITIES).contains(&parsed) => {
                        max_entities = parsed;
                    }
                    _ => {
                        err!(
                            "rxscan investigate: --max-entities must be 1..={}",
                            inv::HARD_MAX_ENTITIES
                        );
                        std::process::exit(2);
                    }
                }
            }
            "--max-relationships" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --max-relationships requires a value");
                    std::process::exit(2);
                };
                match value.parse::<usize>() {
                    Ok(parsed) if (1..=inv::HARD_MAX_RELATIONSHIPS).contains(&parsed) => {
                        max_relationships = parsed;
                    }
                    _ => {
                        err!("rxscan investigate: --max-relationships out of range");
                        std::process::exit(2);
                    }
                }
            }
            "--max-http-requests" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --max-http-requests requires a value");
                    std::process::exit(2);
                };
                match value.parse::<usize>() {
                    Ok(parsed) if parsed <= inv::HARD_MAX_HTTP_REQUESTS => {
                        max_http = parsed;
                    }
                    _ => {
                        err!("rxscan investigate: --max-http-requests out of range");
                        std::process::exit(2);
                    }
                }
            }
            "--max-dns-queries" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --max-dns-queries requires a value");
                    std::process::exit(2);
                };
                match value.parse::<usize>() {
                    Ok(parsed) if parsed <= inv::HARD_MAX_DNS_QUERIES => {
                        max_dns = parsed;
                    }
                    _ => {
                        err!("rxscan investigate: --max-dns-queries out of range");
                        std::process::exit(2);
                    }
                }
            }
            "--max-providers" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --max-providers requires a value");
                    std::process::exit(2);
                };
                match value.parse::<usize>() {
                    Ok(parsed) if parsed >= 1 => max_providers = parsed,
                    _ => {
                        err!("rxscan investigate: --max-providers must be positive");
                        std::process::exit(2);
                    }
                }
            }
            "--providers" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --providers requires a comma-separated list");
                    std::process::exit(2);
                };
                selected = Some(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|id| !id.is_empty())
                        .map(str::to_owned)
                        .collect(),
                );
            }
            "--exclude-provider" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --exclude-provider requires a comma-separated list");
                    std::process::exit(2);
                };
                excluded.extend(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|id| !id.is_empty())
                        .map(str::to_owned),
                );
            }
            "--category" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --category requires a comma-separated list");
                    std::process::exit(2);
                };
                categories.extend(
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|category| !category.is_empty())
                        .map(str::to_owned),
                );
            }
            "--project-db" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --project-db requires a path");
                    std::process::exit(2);
                };
                project_db = Some(value.into());
            }
            "--exposure" => exposure = true,
            "--exposure-dataset" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --exposure-dataset requires a path");
                    std::process::exit(2);
                };
                exposure_dataset = Some(value.into());
            }
            "--network" => network = true,
            "--scope" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --scope requires a target or CIDR");
                    std::process::exit(2);
                };
                scopes.push(value.clone());
            }
            "--exclude" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --exclude requires a target or CIDR");
                    std::process::exit(2);
                };
                scope_exclusions.push(value.clone());
            }
            "--max-network-pivots" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --max-network-pivots requires a value");
                    std::process::exit(2);
                };
                match value.parse::<usize>() {
                    Ok(parsed) if parsed <= inv::HARD_MAX_NETWORK_PIVOTS => {
                        max_network_pivots = parsed;
                    }
                    _ => {
                        err!(
                            "rxscan investigate: --max-network-pivots must be 0..={}",
                            inv::HARD_MAX_NETWORK_PIVOTS
                        );
                        std::process::exit(2);
                    }
                }
            }
            "--color" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan investigate: --color requires one of auto, always, never");
                    std::process::exit(2);
                };
                if !matches!(value.as_str(), "auto" | "always" | "never") {
                    err!("rxscan investigate: --color must be one of auto, always, never");
                    std::process::exit(2);
                }
            }
            arg if arg.starts_with("--color=") => {
                if !matches!(
                    arg.trim_start_matches("--color="),
                    "auto" | "always" | "never"
                ) {
                    err!("rxscan investigate: --color must be one of auto, always, never");
                    std::process::exit(2);
                }
            }
            "--help" | "-h" => {
                out_line!(
                    "RXSCAN\nReconnaissance / Evidence Engine\n\nUSAGE\n  rxscan investigate --username NAME [options]\n  rxscan investigate --domain NAME [options]\n  rxscan investigate --url URL [options]\n  rxscan investigate --email EMAIL [options]\n  rxscan investigate --ip IP [options]\n  rxscan investigate --asn ASN [options]\n  rxscan investigate --repo OWNER/NAME [options]\n  rxscan investigate --org ORG [options]\n\nWORKFLOWS\n  investigate    Evidence investigation\n\nEXAMPLES\n  rxscan investigate --username exampleuser\n  rxscan investigate --username exampleuser --depth 3\n  rxscan investigate --domain example.test\n  rxscan investigate --email user@example.test\n\nOPTIONS\n  --depth 0-{}               Graph-transform depth (default 2)\n  --deadline 60s             Global investigation deadline\n  --max-entities N           Entity budget\n  --max-relationships N      Relationship budget\n  --max-http-requests N      HTTP budget\n  --max-dns-queries N        DNS budget\n  --providers IDS            Provider allowlist\n  --project-db PATH          Persist to a project database\n  --exposure                 Opt-in defensive exposure enrichment\n  --network --scope CIDR     Explicit authorized network pivots\n  --max-network-pivots N     Cap network pivots (default 10, max 100)\n  --all                      Show complete (untruncated) detail\n  --color MODE               auto (TTY only), always, or never\n  --json | --jsonl           Machine output (never styled)\n  --explain                  Show the plan without contacting anything\n\nPassive by default: never port scans discovered infrastructure. Exposure lookups run only with --exposure. Network pivots run only with explicit --network and valid --scope.",
                    inv::MAX_DEPTH
                );
                return;
            }
            unknown => {
                // Friendly guidance for a bare positional like
                // `rxscan investigate exampleuser`.
                if !unknown.starts_with('-')
                    && username.is_none()
                    && domain.is_none()
                    && url.is_none()
                    && email.is_none()
                    && ip.is_none()
                    && asn.is_none()
                    && repo.is_none()
                    && org.is_none()
                {
                    err!("error: investigate needs a seed type");
                    err!("");
                    err!("Try:");
                    err!("  rxscan investigate --username exampleuser");
                    err!("");
                    err!("Other types:");
                    err!("  --domain");
                    err!("  --url");
                    err!("  --email");
                    err!("  --ip");
                    err!("  --asn");
                    err!("  --repo");
                    err!("  --org");
                    std::process::exit(2);
                }
                err!("rxscan investigate: unknown option '{unknown}'");
                std::process::exit(2);
            }
        }
        index += 1;
    }
    if json && jsonl {
        err!("rxscan investigate: --json and --jsonl conflict");
        std::process::exit(2);
    }
    let (seed_kind, seed_value) = match (username, domain, url, email, ip, asn, repo, org) {
        (Some(value), None, None, None, None, None, None, None) => (inv::SeedKind::Username, value),
        (None, Some(value), None, None, None, None, None, None) => (inv::SeedKind::Domain, value),
        (None, None, Some(value), None, None, None, None, None) => (inv::SeedKind::Url, value),
        (None, None, None, Some(value), None, None, None, None) => (inv::SeedKind::Email, value),
        (None, None, None, None, Some(value), None, None, None) => (inv::SeedKind::Ip, value),
        (None, None, None, None, None, Some(value), None, None) => (inv::SeedKind::Asn, value),
        (None, None, None, None, None, None, Some(value), None) => {
            (inv::SeedKind::Repository, value)
        }
        (None, None, None, None, None, None, None, Some(value)) => {
            (inv::SeedKind::Organization, value)
        }
        _ => {
            // Preserve historical wording ("Missing username.") for
            // existing consumers; additional seed types listed below.
            err!("Missing username.");
            err!("");
            err!("Try:");
            err!("  rxscan investigate --username exampleuser");
            err!("  rxscan investigate --domain example.test");
            std::process::exit(2);
        }
    };
    let mut config = match seed_kind {
        inv::SeedKind::Username => inv::InvestigationConfig::username(&seed_value),
        _ => inv::InvestigationConfig::seeded(seed_kind, &seed_value),
    };
    config.depth = depth;
    config.deadline = deadline;
    config.max_entities = max_entities;
    config.max_relationships = max_relationships;
    config.max_http_requests = max_http;
    config.max_dns_queries = max_dns;
    config.max_providers = max_providers;
    config.selected_providers = selected;
    config.excluded_providers = excluded;
    config.categories = categories;
    config.exposure = exposure;
    config.exposure_dataset = exposure_dataset;
    config.network = network;
    config.scopes = scopes;
    config.scope_exclusions = scope_exclusions;
    config.max_network_pivots = max_network_pivots;
    if let Err(error) = config.validate() {
        err!("rxscan investigate: {error}");
        std::process::exit(2);
    }
    if explain {
        // Plan-only: no provider contact.
        if json {
            emit_json_pretty(&serde_json::json!({
                "seed_kind": config.seed_kind,
                "seed": config.seed_value,
                "depth": config.depth,
                "max_depth": inv::MAX_DEPTH,
                "budgets": {
                    "max_entities": config.max_entities,
                    "max_relationships": config.max_relationships,
                    "max_http_requests": config.max_http_requests,
                    "max_dns_queries": config.max_dns_queries,
                    "max_providers": config.max_providers,
                },
                "transforms": inv::TransformRegistry::new().infos(),
                "direct_network": false,
                "network_scans": 0,
            }));
        } else {
            out_line!("{}", inv::explain_plan(&config));
        }
        return;
    }
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let report = match inv::run_investigation(config, &cancelled) {
        Ok(report) => report,
        Err(error) => {
            err!("rxscan investigate: {error}");
            std::process::exit(1);
        }
    };
    if let Err(error) = report.accounting.check_invariant() {
        err!("rxscan investigate: {error}");
        std::process::exit(1);
    }
    if let Some(path) = project_db {
        let mut db = match rxscan::project_db::ProjectDb::open(&path) {
            Ok(db) => db,
            Err(error) => {
                err!("rxscan investigate: could not open project database: {error}");
                std::process::exit(1);
            }
        };
        if let Err(error) = inv::persist_investigation(&mut db, &report) {
            err!("rxscan investigate: could not persist investigation: {error}");
            std::process::exit(1);
        }
    }
    if json {
        emit_json_pretty(&report);
    } else if jsonl {
        out!("{}", inv::render_jsonl(&report));
    } else {
        let caps = resolve_human_caps(args);
        out!("{}", inv::render_human_caps(&report, show_all, caps));
    }
}

/// Local Web/API front-end (`rxscan web ...`).
///
/// Starts the loopback-only HTTP server that serves the RXScan GUI and the
/// versioned typed API from one origin (`/` is the application, not a
/// marketing page). Uses the same core as the CLI (scanner, investigation
/// engine, project database); HTTP handlers only validate and translate.
/// The browser is opened automatically when interactive unless `--no-open`
/// is given; open failures never prevent the server from starting.
fn run_web(args: &[String]) {
    let mut bind = "127.0.0.1".to_owned();
    let mut port: u16 = 8080;
    let mut data_dir: Option<std::path::PathBuf> = None;
    let mut allow_remote = false;
    let mut no_open = false;
    let mut index = 2usize;
    while index < args.len() {
        match args[index].as_str() {
            "--help" | "-h" => {
                out_line!(
                    "RXSCAN\nLocal Web GUI & API\n\nUSAGE\n  rxscan web [--bind ADDR] [--port PORT] [--data-dir DIR] [--allow-remote] [--no-open]\n\nEXAMPLES\n  rxscan web\n  rxscan web --port 8901\n  rxscan web --no-open\n\nOPTIONS\n  --bind ADDR    Loopback bind address (default 127.0.0.1)\n  --port PORT    Local port 0..=65535 (default 8080; 0 = OS-assigned)\n  --data-dir DIR Project database directory (default .rxscan-web)\n  --allow-remote DANGEROUS: permit a non-loopback bind. The API stays\n                 unauthenticated; never expose this to a network.\n  --no-open      Do not open the default browser automatically\n                 (--no-browser is an alias)\n\nThe RXScan application lives at / and the typed API at /api/v1 (same origin, loopback only)."
                );
                return;
            }
            "--bind" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan web: --bind requires an address");
                    std::process::exit(2);
                };
                bind = value;
            }
            "--port" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan web: --port requires a value");
                    std::process::exit(2);
                };
                match value.parse::<u16>() {
                    Ok(value) => port = value,
                    _ => {
                        err!("rxscan web: --port must be 0..=65535");
                        std::process::exit(2);
                    }
                }
            }
            "--data-dir" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan web: --data-dir requires a directory");
                    std::process::exit(2);
                };
                data_dir = Some(value.into());
            }
            "--allow-remote" => allow_remote = true,
            "--no-open" | "--no-browser" => no_open = true,
            unknown => {
                err!("rxscan web: unknown option '{unknown}'");
                std::process::exit(2);
            }
        }
        index += 1;
    }
    let options = rxscan::web_api::WebOptions {
        bind,
        port,
        data_dir: rxscan::platform::paths::resolve_web_data_dir(data_dir),
        allow_remote,
        fixture_investigation: false,
    };
    match rxscan::web_api::serve(options) {
        Ok(handle) => {
            out_line!("RXScan Web UI");
            out_line!("Listening on {}", handle.base_url());
            out_line!("Press Ctrl+C to stop.");
            // Best-effort browser open: interactive sessions get the GUI
            // immediately; failures (headless, missing opener) never stop
            // the loopback server. Opt out with `rxscan web --no-open`.
            if !no_open {
                maybe_open_browser(handle.base_url());
            }
            // Park the main thread on the server. Termination relies on
            // process exit; project writes commit atomically (SQLite
            // transactions), so an interrupted run cannot corrupt stored
            // evidence. `ServerHandle::shutdown` (used by tests/embedders)
            // performs the bounded graceful drain.
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        Err(error) => {
            err!("rxscan web: {error}");
            std::process::exit(1);
        }
    }
}

/// Best-effort default-browser open for `rxscan web`.
///
/// Delegates to the portable platform opener (macOS `open`, Windows
/// `cmd /c start`, Linux openers, WSL powershell fallback, Termux
/// opener). Only attempts on interactive terminals; any failure is
/// silent since the server is already usable.
#[allow(clippy::zombie_processes)]
fn maybe_open_browser(base_url: &str) {
    rxscan::platform::process::open_browser(base_url);
}

/// Defensive exposure intelligence (`rxscan exposure ...`).
///
/// Queries legitimate configured exposure sources for one identifier.
/// External queries that send identifiers to third parties are explicit:
/// this command IS the opt-in. `--explain` discloses identifier-sending
/// before any contact. Secret material is never retained or displayed.
fn run_exposure_cli(args: &[String]) {
    use rxscan::exposure as exp;
    let mut email: Option<String> = None;
    let mut username: Option<String> = None;
    let mut domain: Option<String> = None;
    let mut dataset: Option<std::path::PathBuf> = None;
    let mut explain = false;
    let mut json = false;
    let mut jsonl = false;
    let mut deadline = std::time::Duration::from_secs(30);
    let mut project_db: Option<std::path::PathBuf> = None;
    let mut index = 2usize;
    while index < args.len() {
        match args[index].as_str() {
            "--email" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan exposure: --email requires a value");
                    std::process::exit(2);
                };
                if email.is_some() || username.is_some() || domain.is_some() {
                    err!("rxscan exposure: only one of --email, --username, --domain");
                    std::process::exit(2);
                }
                email = Some(value);
            }
            "--username" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan exposure: --username requires a value");
                    std::process::exit(2);
                };
                if email.is_some() || username.is_some() || domain.is_some() {
                    err!("rxscan exposure: only one of --email, --username, --domain");
                    std::process::exit(2);
                }
                username = Some(value);
            }
            "--domain" => {
                index += 1;
                let Some(value) = args.get(index).cloned() else {
                    err!("rxscan exposure: --domain requires a value");
                    std::process::exit(2);
                };
                if email.is_some() || username.is_some() || domain.is_some() {
                    err!("rxscan exposure: only one of --email, --username, --domain");
                    std::process::exit(2);
                }
                domain = Some(value);
            }
            "--dataset" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan exposure: --dataset requires a path");
                    std::process::exit(2);
                };
                dataset = Some(value.into());
            }
            "--deadline" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan exposure: --deadline requires a duration");
                    std::process::exit(2);
                };
                deadline = match rxscan::config::parse_duration_ms(value) {
                    Ok(ms) => std::time::Duration::from_millis(ms),
                    Err(error) => {
                        err!("rxscan exposure: invalid deadline: {error}");
                        std::process::exit(2);
                    }
                };
            }
            "--project-db" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan exposure: --project-db requires a path");
                    std::process::exit(2);
                };
                project_db = Some(value.into());
            }
            "--explain" => explain = true,
            "--json" => json = true,
            "--jsonl" => jsonl = true,
            "--color" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan exposure: --color requires one of auto, always, never");
                    std::process::exit(2);
                };
                if !matches!(value.as_str(), "auto" | "always" | "never") {
                    err!("rxscan exposure: --color must be one of auto, always, never");
                    std::process::exit(2);
                }
            }
            arg if arg.starts_with("--color=") => {
                if !matches!(
                    arg.trim_start_matches("--color="),
                    "auto" | "always" | "never"
                ) {
                    err!("rxscan exposure: --color must be one of auto, always, never");
                    std::process::exit(2);
                }
            }
            "--help" | "-h" => {
                out_line!(
                    "RXSCAN\nReconnaissance / Evidence Engine\n\nUSAGE\n  rxscan exposure --email ADDR [options]\n  rxscan exposure --username NAME [options]\n  rxscan exposure --domain NAME [options]\n\nWORKFLOWS\n  exposure       Defensive exposure lookup\n\nEXAMPLES\n  rxscan exposure --username exampleuser\n\nOPTIONS\n  --dataset PATH             Operator-supplied local dataset (sends nothing)\n  --deadline 30s             Lookup deadline\n  --project-db PATH          Persist normalized metadata (never secrets)\n  --color MODE               auto (TTY only), always, or never\n  --json | --jsonl           Machine output (never styled)\n  --explain                  Disclose identifier-sending before any contact\n\nDefensive exposure lookup. External providers that receive identifiers run only here (explicit opt-in), never during ordinary passive investigation. Secrets are never retained or displayed."
                );
                return;
            }
            unknown => {
                err!("rxscan exposure: unknown option '{unknown}'");
                std::process::exit(2);
            }
        }
        index += 1;
    }
    if json && jsonl {
        err!("rxscan exposure: --json and --jsonl conflict");
        std::process::exit(2);
    }
    let (kind, identifier) = match (email, username, domain) {
        (Some(value), None, None) => {
            if !value.contains('@') || value.len() > 320 {
                err!("rxscan exposure: invalid email address");
                std::process::exit(2);
            }
            (exp::IdentifierKind::Email, value)
        }
        (None, Some(value), None) => {
            if value.trim().is_empty() || value.len() > 128 {
                err!("rxscan exposure: invalid username");
                std::process::exit(2);
            }
            (exp::IdentifierKind::Username, value)
        }
        (None, None, Some(value)) => {
            if rxscan::investigate::canonical_domain(&value).is_none() {
                err!("rxscan exposure: invalid domain");
                std::process::exit(2);
            }
            (exp::IdentifierKind::Domain, value)
        }
        _ => {
            err!("rxscan exposure: exactly one of --email, --username, --domain is required");
            std::process::exit(2);
        }
    };
    let mut providers: Vec<Box<dyn exp::ExposureProvider>> = Vec::new();
    if let Some(path) = dataset {
        providers.push(Box::new(exp::LocalDatasetProvider {
            label: "operator-dataset".to_owned(),
            path,
            max_entries: exp::LocalDatasetProvider::MAX_ENTRIES,
        }));
    }
    providers.push(Box::new(exp::HttpApiProvider {
        name: "configured-api".to_owned(),
    }));
    if explain {
        out_line!("{}", exp::explain_exposure(kind, &providers));
        return;
    }
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let report = exp::run_exposure(&identifier, kind, &providers, deadline, &cancelled);
    if let Err(error) = report.accounting.check_invariant() {
        err!("rxscan exposure: {error}");
        std::process::exit(1);
    }
    if let Some(path) = project_db {
        // Persist normalized exposure metadata only (never raw responses,
        // never secrets) through the versioned project graph.
        let mut graph = rxscan::graph::ScanGraph::default();
        let anchor = format!(
            "{}:{}",
            kind.as_str(),
            exp::identifier_hash(&identifier)
                .chars()
                .take(16)
                .collect::<String>()
        );
        let proof = rxscan::graph::EntityProvenance {
            scan_plan_id: report.run_id.clone(),
            module: "exposure.lookup".to_owned(),
            task_id: None,
            target: Some(anchor.clone()),
            timestamp: report.started_at,
            reason: Some("operator-supplied exposure lookup".to_owned()),
            rule_id: None,
        };
        let (entities, edges) = exp::to_graph_items(
            &anchor,
            match kind {
                exp::IdentifierKind::Email => rxscan::graph::EntityKind::EmailAddress,
                exp::IdentifierKind::Username => rxscan::graph::EntityKind::Username,
                exp::IdentifierKind::Domain => rxscan::graph::EntityKind::Domain,
            },
            &report.exposures,
            report.started_at,
            1,
        );
        graph.upsert_entity(
            anchor.clone(),
            match kind {
                exp::IdentifierKind::Email => rxscan::graph::EntityKind::EmailAddress,
                exp::IdentifierKind::Username => rxscan::graph::EntityKind::Username,
                exp::IdentifierKind::Domain => rxscan::graph::EntityKind::Domain,
            },
            identifier.clone(),
            std::collections::BTreeMap::from([(
                "identifier_hash".to_owned(),
                report.identifier_hash.clone(),
            )]),
            &proof,
        );
        for entity in entities {
            graph.upsert_entity(
                entity.id.clone(),
                entity.kind,
                entity.label.clone(),
                entity.attributes.clone(),
                &entity.provenance.to_graph(&report.run_id),
            );
        }
        for edge in edges {
            graph.link(
                edge.from.clone(),
                edge.to.clone(),
                edge.relation,
                edge.confidence,
                &edge.provenance.to_graph(&report.run_id),
                edge.evidence.clone(),
                edge.attributes.clone(),
            );
        }
        let mut db = match rxscan::project_db::ProjectDb::open(&path) {
            Ok(db) => db,
            Err(error) => {
                err!("rxscan exposure: could not open project database: {error}");
                std::process::exit(1);
            }
        };
        let import = rxscan::project_db::ScanImport {
            scan_id: report.run_id.clone(),
            plan_id: rxscan::assets::public_entity_id("exposure_plan", kind.as_str()),
            started_at_ms: report.started_at.saturating_mul(1_000),
            finished_at_ms: report.completed_at.saturating_mul(1_000),
            scope_json: serde_json::json!({
                "contact_class": "exposure_lookup",
                "direct_network": false,
                "identifier_type": kind.as_str(),
            })
            .to_string(),
            workflow: "exposure".to_owned(),
            level: 0,
            termination: if report.accounting.truncated {
                "deadline_or_budget"
            } else {
                "complete"
            }
            .to_owned(),
            tasks_admitted: report.accounting.providers_requested as u64,
            tasks_completed: report.accounting.providers_completed as u64,
            coverage: rxscan::project_db::CoverageSnapshot {
                modules_completed: report
                    .observations
                    .iter()
                    .map(|o| format!("exposure.{}", o.provider_id))
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                truncated: report.accounting.truncated,
                ..rxscan::project_db::CoverageSnapshot::default()
            },
            classifier: rxscan::project_db::ClassifierProvenance {
                tool_version: rxscan::project_db::TOOL_VERSION.to_owned(),
                packs: vec![rxscan::project_db::PackProvenance {
                    path: "internal:exposure/providers".to_owned(),
                    schema_version: 1,
                    rule_count: providers.len(),
                }],
                rules_used: report
                    .observations
                    .iter()
                    .map(|o| o.provider_id.clone())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            },
            retention: rxscan::project_db::RetentionMode::Standard,
        };
        if let Err(error) = db.import_scan(&import, &graph) {
            err!("rxscan exposure: could not persist exposure: {error}");
            std::process::exit(1);
        }
    }
    if json {
        emit_json_pretty(&report);
    } else if jsonl {
        out!("{}", exp::render_jsonl(&report));
    } else {
        let caps = resolve_human_caps(args);
        out!("{}", exp::render_human_caps(&report, caps));
    }
}

fn run_os_lab(args: &[String]) {
    let mut json = false;
    let mut fixture_path: Option<&str> = None;
    for arg in args[2..].iter() {
        match arg.as_str() {
            "--json" => json = true,
            "analyze" => {}
            path if fixture_path.is_none() => fixture_path = Some(path),
            _ => {
                err!("rxscan os-lab analyze: usage: rxscan os-lab analyze [--json] <fixture.json>");
                std::process::exit(2);
            }
        }
    }
    let fixture_path = match fixture_path {
        Some(path) => path,
        None => {
            err!("rxscan os-lab analyze: usage: rxscan os-lab analyze [--json] <fixture.json>");
            std::process::exit(2);
        }
    };
    let fixture_std = if std::path::Path::new(fixture_path).exists() {
        std::fs::read_to_string(fixture_path).unwrap_or_else(|error| {
            err!("rxscan os-lab analyze: cannot read fixture: {error}");
            std::process::exit(2);
        })
    } else {
        err!("rxscan os-lab analyze: usage: rxscan os-lab analyze [--json] <fixture.json>");
        std::process::exit(2);
    };
    let fixture = rxscan::os_lab::OsLabFixture::from_json(&fixture_std).unwrap_or_else(|error| {
        err!("rxscan os-lab analyze: invalid fixture: {error}");
        std::process::exit(2);
    });
    let analysis = fixture.analyze().unwrap_or_else(|error| {
        err!("rxscan os-lab analyze: analysis failed: {error}");
        std::process::exit(2);
    });
    if json {
        let text = serde_json::to_string_pretty(&analysis).unwrap_or_else(|error| {
            err!("rxscan os-lab analyze: cannot serialize: {error}");
            std::process::exit(2);
        });
        out_line!("{}", text);
    } else {
        out!(
            "{}",
            serde_json::to_string(&analysis).unwrap_or_else(|error| {
                err!("rxscan os-lab analyze: cannot serialize: {error}");
                std::process::exit(2);
            })
        );
    }
}
