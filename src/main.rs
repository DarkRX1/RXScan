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
    if args.get(1).is_some_and(|arg| arg == "project-db") {
        run_project_db(&args);
        return;
    }
    if args.get(1).is_some_and(|arg| arg == "capabilities") {
        let json = args.iter().any(|arg| arg == "--json");
        let report = capabilities::probe();
        if json {
            out_line!("{}", serde_json::to_string_pretty(&report).unwrap());
        } else {
            out!("{}", capabilities::render_human(&report));
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
    // Compact RXScan identity for interactive human scans only. Computed
    // before `cli` moves into the executor; printed only on the human
    // stdout path below, never for JSONL streams or piped output (unless
    // --color always forces interactive rendering).
    let scan_mark: Option<String> = {
        let mode = match cli.color.as_deref() {
            Some("always") => rxscan::terminal::ColorMode::Always,
            Some("never") => rxscan::terminal::ColorMode::Never,
            _ => rxscan::terminal::ColorMode::Auto,
        };
        let tty = rxscan::terminal::stdout_is_tty();
        if tty || mode == rxscan::terminal::ColorMode::Always {
            let color =
                rxscan::terminal::color_enabled(mode, rxscan::terminal::no_color_env(), tty);
            Some(rxscan::terminal::startup_mark(color))
        } else {
            None
        }
    };
    match run::execute(cli) {
        Ok(report) => {
            // If JSONL went to stdout via --format jsonl, the JSONL is already
            // on stdout; still print the human summary to stderr to keep
            // stdout pure JSONL.
            if report.jsonl_bytes > 0 && report.output_path.is_none() {
                err!("{}", run::human_summary(&report));
            } else {
                if let Some(mark) = &scan_mark {
                    out_line!("{mark}");
                }
                out_line!("{}", run::human_summary(&report));
                if report.output_path.is_none() {
                    out_line!("Run with --explain to inspect the effective scan plan.");
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

/// Print the compact RXScan startup mark for interactive human output.
///
/// Hidden for `--json`/`--jsonl` and when stdout is not a TTY unless the
/// operator forced color with `--color always`.
fn maybe_search_startup_mark(args: &[String], machine_output: bool) {
    if machine_output {
        return;
    }
    let mode = rxscan::terminal::parse_color_mode(args);
    let tty = rxscan::terminal::stdout_is_tty();
    if !tty && mode != rxscan::terminal::ColorMode::Always {
        return;
    }
    let color = rxscan::terminal::color_enabled(mode, rxscan::terminal::no_color_env(), tty);
    out_line!("{}", rxscan::terminal::startup_mark(color));
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
    if json {
        out_line!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "pack_version": pack.pack_version,
                "providers_loaded": pack.providers.len(),
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
            }))
            .unwrap()
        );
        return;
    }
    maybe_search_startup_mark(args, false);
    out_line!("RXScan Search Corpus");
    out_line!("");
    out_line!("Providers loaded       {}", pack.providers.len());
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
fn search_report_rows(
    report: &rxscan::search::UsernameSearchReport,
) -> Vec<rxscan::terminal::SearchRow> {
    use rxscan::terminal::{RowTier, SearchRow};
    report
        .results
        .iter()
        .map(|result| {
            let key = search_status_key(&result.status);
            let (tier, detail) = match key {
                "confirmed" | "probable" => (RowTier::Positive, "profile".to_owned()),
                "possible" => (RowTier::Positive, "weak evidence".to_owned()),
                "blocked" | "rate_limited" | "error" | "authentication_required" | "unknown" => (
                    RowTier::Attention,
                    result.evidence.first().cloned().unwrap_or_default(),
                ),
                _ => (RowTier::Quiet, String::new()),
            };
            SearchRow {
                status: key,
                provider: result.provider_id.clone(),
                confidence: result.confidence,
                detail,
                tier,
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
        out_line!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        maybe_search_startup_mark(args, false);
        out_line!("RXScan Corpus Lint");
        out_line!("");
        out_line!("providers checked    {}", report.providers_checked);
        out_line!("files checked        {}", report.files_checked);
        out_line!("fixture complete     {}", report.fixture_complete);
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
            let known: std::collections::BTreeSet<&str> = pack
                .providers
                .iter()
                .map(|provider| provider.category.as_str())
                .collect();
            let unknown: Vec<&String> = filter
                .categories
                .iter()
                .filter(|category| !known.contains(category.as_str()))
                .collect();
            if !unknown.is_empty() {
                let known_list: Vec<&&str> = known.iter().collect();
                err!(
                    "rxscan search providers: unknown categor{}: {}; known: {}",
                    if unknown.len() == 1 { "y" } else { "ies" },
                    unknown
                        .iter()
                        .map(|category| category.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    known_list
                        .iter()
                        .map(|category| **category)
                        .collect::<Vec<_>>()
                        .join(", "),
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
        maybe_search_startup_mark(args, json);
        if json {
            let providers = shown
                .iter()
                .map(|provider| {
                    serde_json::json!({
                        "id": provider.metadata.id,
                        "name": provider.platform,
                        "category": provider.category,
                        "contact_class": provider.metadata.contact_class,
                        "authentication_required": provider.metadata.requires_authentication,
                        "health_state": provider.health_state.as_str(),
                        "verified_at": provider.verified_at,
                    })
                })
                .collect::<Vec<_>>();
            out_line!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "pack_version": pack.pack_version,
                    "total_providers": pack.providers.len(),
                    "active_providers": providers.len(),
                    "providers": providers
                }))
                .unwrap()
            );
        } else {
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
    let mut json = false;
    let mut jsonl = false;
    let mut show_all = false;
    let mut explain = false;
    let mut deadline = std::time::Duration::from_secs(30);
    let mut selected: Option<std::collections::BTreeSet<String>> = None;
    let mut excluded = std::collections::BTreeSet::<String>::new();
    let mut categories = std::collections::BTreeSet::<String>::new();
    let mut project_db: Option<std::path::PathBuf> = None;
    let mut index = offset;
    while index < args.len() {
        match args[index].as_str() {
            "--username" => {
                index += 1;
                username = args.get(index).cloned();
                if username.is_none() {
                    err!("rxscan search: --username requires a value");
                    std::process::exit(2);
                }
            }
            "username" => {
                // Positional form: `rxscan search username <name>`.
                index += 1;
                let Some(name) = args.get(index).cloned() else {
                    err!("rxscan search username: requires a username value");
                    std::process::exit(2);
                };
                if username.is_some() {
                    err!("rxscan search: duplicate username value");
                    std::process::exit(2);
                }
                username = Some(name);
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
            }
            "--providers" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    err!("rxscan search: --providers requires a comma-separated list");
                    std::process::exit(2);
                };
                let ids = value
                    .split(',')
                    .map(str::trim)
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .collect::<std::collections::BTreeSet<_>>();
                selected = Some(ids);
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
                    "rxscan search --username NAME [--providers IDS] [--exclude-provider IDS] [--category CATEGORIES] [--deadline 30s] [--project-db PATH] [--all] [--color MODE] [--json|--jsonl] [--explain]\nrxscan search username NAME [same options]\nrxscan search providers [--json] [--health STATE] [--category CAT] [--stale] [--color MODE]\nrxscan search stats [--json] [--color MODE]\nrxscan search lint [--json] [--corpus-root DIR] [--color MODE]\nrxscan --username NAME [same options]"
                );
                return;
            }
            unknown => {
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
    let Some(username) = username else {
        err!("rxscan search: --username is required");
        std::process::exit(2);
    };
    let pack = match rxscan::search::embedded_username_pack() {
        Ok(pack) => pack,
        Err(error) => {
            err!("rxscan search: {error}");
            std::process::exit(1);
        }
    };
    let available = pack
        .providers
        .iter()
        .map(|provider| provider.metadata.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for requested in selected.iter().flatten().chain(excluded.iter()) {
        if !available.contains(requested.as_str()) {
            err!("rxscan search: unknown provider: {requested}");
            std::process::exit(2);
        }
    }
    let available_categories = pack
        .providers
        .iter()
        .map(|provider| provider.category.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let unknown_categories = categories
        .iter()
        .filter(|category| !available_categories.contains(category.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown_categories.is_empty() {
        err!(
            "rxscan search: unknown categor{}: {}",
            if unknown_categories.len() == 1 {
                "y"
            } else {
                "ies"
            },
            unknown_categories.join(", ")
        );
        std::process::exit(2);
    }
    let effective = pack
        .providers
        .iter()
        .filter(|provider| {
            selected
                .as_ref()
                .is_none_or(|ids| ids.contains(&provider.metadata.id))
                && !excluded.contains(&provider.metadata.id)
                && (categories.is_empty() || categories.contains(&provider.category))
        })
        .map(|provider| provider.metadata.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let selected_count = effective.len();
    if selected_count == 0 {
        err!("rxscan search: provider selection matched no providers");
        std::process::exit(2);
    }
    if explain {
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
        return;
    }
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let report = match rxscan::search::execute_username_search(
        &username,
        4,
        1,
        deadline,
        Some(&effective),
        &cancelled,
    ) {
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
        if let Err(error) = rxscan::search::persist_username_report(&mut db, &report) {
            err!("rxscan search: could not persist search report: {error}");
            std::process::exit(1);
        }
    }
    if json {
        out_line!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else if jsonl {
        out!("{}", rxscan::search::render_username_jsonl(&report));
    } else {
        let mode = rxscan::terminal::parse_color_mode(args);
        let tty = rxscan::terminal::stdout_is_tty();
        let color = rxscan::terminal::color_enabled(mode, rxscan::terminal::no_color_env(), tty);
        let rows = search_report_rows(&report);
        let summary = rxscan::terminal::SearchSummary {
            requested: report.accounting.providers_requested,
            completed: report.accounting.providers_completed,
            skipped: report.accounting.skipped,
            cancelled: report.accounting.cancelled,
            unscanned: report.accounting.unscanned,
            truncated: report.accounting.truncated,
        };
        out!(
            "{}",
            rxscan::terminal::render_search_report(
                &report.seed.display_value,
                report.accounting.providers_requested,
                &rows,
                summary,
                show_all,
                color,
                !rxscan::terminal::unicode_supported(),
            )
        );
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
                "rxscan project create <project.rxproj>\nrxscan project add <project.rxproj> <scan.rxscan>\nrxscan project summary <project.rxproj> [--json]\nrxscan project show <project.rxproj> <entity> [--json]\nrxscan project explain <project.rxproj> <entity> [--limit N] [--json]\nrxscan project neighbors <project.rxproj> <entity> [--depth N] [--limit N] [--json|--jsonl]\nrxscan project scans <project.rxproj> [--json]\nrxscan project findings <project.rxproj> [entity] [--limit N] [--json|--jsonl]\nrxscan project changes <project.rxproj> [entity] [--limit N] [--json|--jsonl]\nrxscan project attention <project.rxproj> [entity] [--limit N] [--json|--jsonl]"
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
                    Ok(explanation) if json => {
                        out_line!("{}", serde_json::to_string_pretty(&explanation).unwrap())
                    }
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
                out_line!("{}", serde_json::to_string_pretty(&scans).unwrap());
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
                out_line!("{}", serde_json::to_string_pretty(&stored).unwrap());
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
                out_line!("{}", serde_json::to_string_pretty(&changes).unwrap());
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
                out_line!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "entity": entity,
                        "chain": chain,
                        "observations": observations,
                    }))
                    .unwrap()
                );
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
        Ok(export) if json => {
            out_line!("{}", serde_json::to_string_pretty(&export).unwrap())
        }
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
        for arg in &args[3..] {
            if arg != "--json" && !arg.starts_with("--color") {
                err!("rxscan investigate transforms: only --json and --color are supported");
                std::process::exit(2);
            }
        }
        let registry = inv::TransformRegistry::new();
        if json {
            out_line!(
                "{}",
                serde_json::to_string_pretty(&registry.infos()).unwrap()
            );
        } else {
            maybe_search_startup_mark(args, false);
            out_line!("RXScan Investigation Transforms");
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
                if username.is_some() || domain.is_some() || url.is_some() {
                    err!("rxscan investigate: only one of --username, --domain, --url");
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
                if username.is_some() || domain.is_some() || url.is_some() {
                    err!("rxscan investigate: only one of --username, --domain, --url");
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
                if username.is_some() || domain.is_some() || url.is_some() {
                    err!("rxscan investigate: only one of --username, --domain, --url");
                    std::process::exit(2);
                }
                url = Some(value);
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
                    "rxscan investigate --username NAME [--depth 0-{}] [--deadline 60s] [--max-entities N] [--max-relationships N] [--max-http-requests N] [--max-dns-queries N] [--max-providers N] [--providers IDS] [--exclude-provider IDS] [--category CATS] [--project-db PATH] [--exposure] [--exposure-dataset PATH] [--network] [--scope CIDR-OR-HOST] [--exclude CIDR-OR-HOST] [--max-network-pivots N] [--all] [--color MODE] [--json|--jsonl] [--explain]\nrxscan investigate --domain NAME [same options]\nrxscan investigate --url URL [same options]\nrxscan investigate transforms [--json]\n\nPassive by default: never port scans discovered infrastructure. DNS queries are DnsQuery, not DirectNetwork. Exposure lookups that send identifiers to third parties run only with --exposure. Direct network pivots run only with explicit --network and valid --scope.",
                    inv::MAX_DEPTH
                );
                return;
            }
            unknown => {
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
    let (seed_kind, seed_value) = match (username, domain, url) {
        (Some(value), None, None) => (inv::SeedKind::Username, value),
        (None, Some(value), None) => (inv::SeedKind::Domain, value),
        (None, None, Some(value)) => (inv::SeedKind::Url, value),
        _ => {
            err!("rxscan investigate: exactly one of --username, --domain, --url is required");
            std::process::exit(2);
        }
    };
    let mut config = match seed_kind {
        inv::SeedKind::Username => inv::InvestigationConfig::username(&seed_value),
        inv::SeedKind::Domain => inv::InvestigationConfig::seeded(seed_kind, &seed_value),
        inv::SeedKind::Url => inv::InvestigationConfig::seeded(seed_kind, &seed_value),
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
            out_line!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
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
                }))
                .unwrap()
            );
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
        out_line!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else if jsonl {
        out!("{}", inv::render_jsonl(&report));
    } else {
        maybe_search_startup_mark(args, false);
        let mode = rxscan::terminal::parse_color_mode(args);
        let tty = rxscan::terminal::stdout_is_tty();
        let color = rxscan::terminal::color_enabled(mode, rxscan::terminal::no_color_env(), tty);
        out!(
            "{}",
            inv::render_human(
                &report,
                show_all,
                color,
                !rxscan::terminal::unicode_supported()
            )
        );
    }
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
                    "rxscan exposure --email ADDR|--username NAME|--domain NAME [--dataset PATH] [--deadline 30s] [--project-db PATH] [--color MODE] [--json|--jsonl] [--explain]\n\nDefensive exposure lookup. External providers that receive identifiers run only here (explicit opt-in), never during ordinary passive investigation. Secrets are never retained or displayed."
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
        out_line!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else if jsonl {
        out!("{}", exp::render_jsonl(&report));
    } else {
        let mode = rxscan::terminal::parse_color_mode(args);
        let tty = rxscan::terminal::stdout_is_tty();
        let color = rxscan::terminal::color_enabled(mode, rxscan::terminal::no_color_env(), tty);
        maybe_search_startup_mark(args, false);
        out!(
            "{}",
            exp::render_human(&report, color, !rxscan::terminal::unicode_supported())
        );
    }
}
