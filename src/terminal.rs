//! Minimal RXScan terminal presentation layer.
//!
//! Business logic (scanner, search) knows nothing about ANSI styling.
//! Presentation maps semantic styles to terminal output in one place.
//!
//! Rules:
//! * JSON/JSONL output must never contain ANSI escape codes.
//! * Piped (non-TTY) output defaults to plain text.
//! * `NO_COLOR` disables styling unless `--color always` is explicit.
//! * The startup mark is compact (2 lines), immediate, and hidden for
//!   machine-readable or non-interactive output.

use std::io::IsTerminal;

/// How the operator wants color handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

/// Semantic styles. Business logic never references ANSI codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Accent,
    Success,
    Probable,
    Warning,
    Danger,
    Muted,
    Heading,
    Value,
}

/// Parse `--color <mode>` / `--color=<mode>` from raw CLI args.
///
/// Unknown or absent values fall back to [`ColorMode::Auto`]; strict CLI
/// validation happens at the call site where exit codes matter.
pub fn parse_color_mode(args: &[String]) -> ColorMode {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if let Some(value) = arg.strip_prefix("--color=") {
            return color_mode_from_str(value);
        }
        if arg == "--color" {
            if let Some(next) = iter.peek() {
                if !next.starts_with('-') {
                    return color_mode_from_str(next);
                }
            }
            return ColorMode::Auto;
        }
    }
    ColorMode::Auto
}

fn color_mode_from_str(value: &str) -> ColorMode {
    match value {
        "always" => ColorMode::Always,
        "never" => ColorMode::Never,
        _ => ColorMode::Auto,
    }
}

/// Whether `NO_COLOR` is set in the environment (any value, even empty).
pub fn no_color_env() -> bool {
    std::env::var("NO_COLOR").is_ok()
}

/// Pure color decision used by tests and the CLI.
///
/// * `Never` always disables.
/// * `NO_COLOR` disables unless the mode is explicitly `Always`.
/// * `Auto` enables only on a TTY.
/// * `Always` enables even when piped.
pub fn color_enabled(mode: ColorMode, no_color: bool, is_tty: bool) -> bool {
    match mode {
        ColorMode::Never => false,
        ColorMode::Always => true,
        ColorMode::Auto => !no_color && is_tty,
    }
}

/// Whether stdout is a terminal. Kept separate so tests can inject `false`.
pub fn stdout_is_tty() -> bool {
    std::io::stdout().is_terminal()
}

/// Compact RXScan startup mark (2 lines, no animation, no network).
///
/// Callers must hide it for `--json`/`--jsonl` and when stdout is not a
/// TTY (unless color was forced with `--color always`).
pub fn startup_mark(color: bool) -> String {
    let brand = paint(color, Style::Accent, "RXSCAN");
    let tagline = paint(color, Style::Muted, "Reactive Recon / Evidence Engine");
    format!("{brand}\n{tagline}")
}

/// Render `text` in a semantic style. With `color == false` the text is
/// returned unchanged (never emits escape codes).
pub fn paint(color: bool, style: Style, text: &str) -> String {
    if !color {
        return text.to_owned();
    }
    let code = match style {
        Style::Accent => "\x1b[36;1m",
        Style::Success => "\x1b[32m",
        Style::Probable => "\x1b[36m",
        Style::Warning => "\x1b[33m",
        Style::Danger => "\x1b[31m",
        Style::Muted => "\x1b[2m",
        Style::Heading => "\x1b[1m",
        Style::Value => "\x1b[0m",
    };
    format!("{code}{text}\x1b[0m")
}

/// Glyph for a username-search status. ASCII fallback for limited terminals.
/// Every row also prints its status label, so glyphs are decorative.
pub fn search_status_glyph(status: &str, ascii: bool) -> char {
    if ascii {
        return match status {
            "confirmed" => '+',
            "probable" => '~',
            "possible" => '?',
            "not_found" => '.',
            "blocked" => '!',
            "rate_limited" => '%',
            "error" => 'x',
            "skipped" => '-',
            "authentication_required" => 'A',
            "cancelled" => '#',
            _ => '.',
        };
    }
    match status {
        "confirmed" => '✓',
        "probable" => '◆',
        "possible" => '?',
        "not_found" => '·',
        "blocked" => '!',
        "rate_limited" => '↻',
        "error" => '×',
        "skipped" => '○',
        "authentication_required" => '⚠',
        "cancelled" => '■',
        _ => '·',
    }
}

/// Whether the terminal likely supports Unicode glyphs and rules.
///
/// Explicit `NO_UNICODE` always forces ASCII. Otherwise a `C`/`POSIX`
/// locale without a UTF-8 suffix forces ASCII; anything else (including
/// unset locale variables) assumes Unicode.
pub fn unicode_supported() -> bool {
    if std::env::var("NO_UNICODE").is_ok() {
        return false;
    }
    for key in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Ok(value) = std::env::var(key) {
            if value.is_empty() {
                continue;
            }
            let lower = value.to_ascii_lowercase();
            if lower == "c" || lower == "posix" {
                return false;
            }
            return lower.contains("utf-8") || lower.contains("utf8");
        }
    }
    true
}

/// Returns true when `text` contains an ANSI escape introducer.
pub fn contains_ansi(text: &str) -> bool {
    text.contains('\x1b')
}

/// Visibility tier of one rendered search finding. Plain data only: the
/// search engine never constructs these; the CLI maps its report onto rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowTier {
    /// Confirmed/probable/possible: aligned table, always shown.
    Positive,
    /// Blocked/rate-limited/errors: reason lines, always shown.
    Attention,
    /// Negatives: only with `--all`.
    Quiet,
}

/// One rendered search finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRow {
    /// Lowercase status key (`confirmed`, `blocked`, `not_found`, ...).
    pub status: &'static str,
    pub provider: String,
    pub confidence: u8,
    /// Short evidence kind (`profile`, `weak evidence`) or a reason.
    pub detail: String,
    pub tier: RowTier,
}

/// Totals for the search summary line. Always complete, even when rows
/// were visually suppressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchSummary {
    pub requested: usize,
    pub completed: usize,
    pub skipped: usize,
    pub cancelled: usize,
    pub unscanned: usize,
    pub truncated: bool,
}

/// Render an interactive username-search report.
///
/// * Positive findings first, then attention-worthy rows (blocked,
///   rate-limited, errors), then negatives only when `show_all`.
/// * Colors are semantic; with `color == false` the output is plain text
///   without escape codes. Unicode rules/glyphs follow `ascii`.
pub fn render_search_report(
    target: &str,
    requested: usize,
    rows: &[SearchRow],
    summary: SearchSummary,
    show_all: bool,
    color: bool,
    ascii: bool,
) -> String {
    let mut out = String::new();
    let rule: String = if ascii {
        "-".repeat(45)
    } else {
        "─".repeat(45)
    };
    let sep = if ascii { "-" } else { "·" };
    out.push_str(&format!(
        "{} {}\n",
        paint(color, Style::Accent, "RXSCAN"),
        paint(color, Style::Muted, "PUBLIC SEARCH - passive evidence mode")
    ));
    out.push_str(&format!(
        "\n  {:<10} {}\n  {:<10} {} requested\n  {:<10} disabled\n",
        "target", target, "providers", requested, "network",
    ));
    let width = rows
        .iter()
        .filter(|row| row.tier == RowTier::Positive)
        .map(|row| row.provider.len())
        .max()
        .unwrap_or(10)
        .max(10);
    let mut shown = 0usize;
    for row in rows.iter().filter(|row| row.tier == RowTier::Positive) {
        if shown == 0 {
            out.push('\n');
        }
        shown += 1;
        out.push_str(&format!(
            "  {} {:<9} {:<width$} {:>3}%   {}\n",
            paint(color, style_for(row.status), &glyph(row.status, ascii)),
            paint(color, style_for(row.status), &row.status.to_uppercase()),
            row.provider,
            row.confidence,
            row.detail,
            width = width,
        ));
    }
    for row in rows.iter().filter(|row| row.tier == RowTier::Attention) {
        if shown == 0 {
            out.push('\n');
            shown += 1;
        }
        let short: String = row.detail.chars().take(64).collect();
        out.push_str(&format!(
            "  {} {}  {} - {short}\n",
            paint(color, style_for(row.status), &glyph(row.status, ascii)),
            paint(
                color,
                style_for(row.status),
                &row.status.to_uppercase().replace('_', " ")
            ),
            row.provider,
        ));
    }
    if show_all {
        let mut quiet = false;
        for row in rows.iter().filter(|row| row.tier == RowTier::Quiet) {
            if !quiet {
                out.push('\n');
                quiet = true;
            }
            out.push_str(&format!(
                "  {} {}  {}\n",
                paint(color, Style::Muted, &glyph(row.status, ascii)),
                paint(
                    color,
                    Style::Muted,
                    &row.status.to_uppercase().replace('_', " ")
                ),
                row.provider,
            ));
        }
        shown += usize::from(quiet);
    }
    if shown == 0 {
        out.push_str(&format!(
            "\n  {}\n",
            paint(
                color,
                Style::Muted,
                "no public accounts found - use --all to list negative results"
            )
        ));
    }
    out.push_str(&format!(
        "\n  {rule}\n  {} requested {sep} {} completed {sep} {} skipped {sep} {} cancelled {sep} {} unscanned {sep} 0 network scans{}\n",
        summary.requested,
        summary.completed,
        summary.skipped,
        summary.cancelled,
        summary.unscanned,
        if summary.truncated {
            " (truncated)"
        } else {
            ""
        },
    ));
    out
}

fn glyph(status: &str, ascii: bool) -> String {
    search_status_glyph(status, ascii).to_string()
}

fn style_for(status: &str) -> Style {
    match status {
        "confirmed" => Style::Success,
        "probable" => Style::Probable,
        "possible" | "blocked" | "rate_limited" | "authentication_required" => Style::Warning,
        "error" => Style::Danger,
        _ => Style::Muted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn color_mode_parses_long_forms() {
        let args = ["rxscan".to_owned(), "--color=always".to_owned()];
        assert_eq!(parse_color_mode(&args), ColorMode::Always);
        let args = ["rxscan".to_owned(), "--color=never".to_owned()];
        assert_eq!(parse_color_mode(&args), ColorMode::Never);
        let args = ["rxscan".to_owned(), "--color=auto".to_owned()];
        assert_eq!(parse_color_mode(&args), ColorMode::Auto);
    }

    #[test]
    fn color_mode_parses_space_form_and_defaults() {
        let args = [
            "rxscan".to_owned(),
            "--color".to_owned(),
            "never".to_owned(),
        ];
        assert_eq!(parse_color_mode(&args), ColorMode::Never);
        let args = ["rxscan".to_owned()];
        assert_eq!(parse_color_mode(&args), ColorMode::Auto);
        let args = ["rxscan".to_owned(), "--color=bogus".to_owned()];
        assert_eq!(parse_color_mode(&args), ColorMode::Auto);
    }

    #[test]
    fn color_decision_matrix() {
        use ColorMode::{Always, Auto, Never};
        assert!(color_enabled(Always, true, false));
        assert!(!color_enabled(Never, false, true));
        assert!(!color_enabled(Auto, true, true));
        assert!(color_enabled(Auto, false, true));
        assert!(!color_enabled(Auto, false, false));
        assert!(!color_enabled(Auto, true, false));
    }

    #[test]
    fn paint_without_color_never_emits_ansi() {
        for style in [
            Style::Accent,
            Style::Success,
            Style::Probable,
            Style::Warning,
            Style::Danger,
            Style::Muted,
            Style::Heading,
            Style::Value,
        ] {
            let rendered = paint(false, style, "exampleuser");
            assert_eq!(rendered, "exampleuser");
            assert!(!contains_ansi(&rendered));
        }
    }

    #[test]
    fn paint_with_color_uses_semantic_codes() {
        assert!(paint(true, Style::Success, "x").starts_with("\x1b[32m"));
        assert!(paint(true, Style::Danger, "x").starts_with("\x1b[31m"));
        assert!(paint(true, Style::Probable, "x").starts_with("\x1b[36m"));
        assert!(paint(true, Style::Warning, "x").starts_with("\x1b[33m"));
        for style in [Style::Success, Style::Danger, Style::Muted] {
            assert!(paint(true, style, "x").ends_with("\x1b[0m"));
        }
    }

    #[test]
    fn startup_mark_is_compact_and_plain_without_color() {
        let mark = startup_mark(false);
        assert_eq!(mark.lines().count(), 2);
        assert!(mark.contains("RXSCAN"));
        assert!(!contains_ansi(&mark));
    }

    #[test]
    fn glyphs_have_ascii_fallbacks() {
        assert_eq!(search_status_glyph("confirmed", true), '+');
        assert_eq!(search_status_glyph("confirmed", false), '✓');
        assert_eq!(search_status_glyph("error", true), 'x');
        assert_eq!(search_status_glyph("error", false), '×');
        assert_eq!(search_status_glyph("authentication_required", true), 'A');
        assert_eq!(search_status_glyph("bogus", true), '.');
    }

    #[test]
    fn paint_never_emits_ansi_without_color_even_for_glyphs() {
        let glyph: String = search_status_glyph("confirmed", false).into();
        assert!(!contains_ansi(&glyph));
        assert!(!contains_ansi(&startup_mark(false)));
    }

    fn sample_rows() -> Vec<SearchRow> {
        vec![
            SearchRow {
                status: "confirmed",
                provider: "provider-a".to_owned(),
                confidence: 94,
                detail: "profile".to_owned(),
                tier: RowTier::Positive,
            },
            SearchRow {
                status: "possible",
                provider: "provider-b".to_owned(),
                confidence: 25,
                detail: "weak evidence".to_owned(),
                tier: RowTier::Positive,
            },
            SearchRow {
                status: "blocked",
                provider: "provider-d".to_owned(),
                confidence: 0,
                detail: "provider rejected request".to_owned(),
                tier: RowTier::Attention,
            },
            SearchRow {
                status: "not_found",
                provider: "provider-e".to_owned(),
                confidence: 0,
                detail: String::new(),
                tier: RowTier::Quiet,
            },
        ]
    }

    fn sample_summary() -> SearchSummary {
        SearchSummary {
            requested: 4,
            completed: 4,
            skipped: 0,
            cancelled: 0,
            unscanned: 0,
            truncated: false,
        }
    }

    #[test]
    fn search_report_hides_negatives_by_default() {
        let text = render_search_report(
            "exampleuser",
            4,
            &sample_rows(),
            sample_summary(),
            false,
            false,
            true,
        );
        assert!(text.contains("RXSCAN"));
        assert!(text.contains("CONFIRMED"));
        assert!(text.contains("provider-a"));
        assert!(text.contains("BLOCKED"));
        assert!(text.contains("0 network scans"));
        assert!(!text.contains("provider-e"), "negatives need --all");
        assert!(!contains_ansi(&text));
    }

    #[test]
    fn search_report_all_lists_negatives_and_summary_reconciles() {
        let text = render_search_report(
            "exampleuser",
            4,
            &sample_rows(),
            sample_summary(),
            true,
            false,
            true,
        );
        assert!(text.contains("provider-e"));
        assert!(text.contains("NOT FOUND"));
        assert!(text.contains("4 requested - 4 completed"));
    }

    #[test]
    fn search_report_empty_shows_hint_and_unicode_when_enabled() {
        let text = render_search_report(
            "exampleuser",
            0,
            &[],
            SearchSummary {
                requested: 0,
                completed: 0,
                skipped: 0,
                cancelled: 0,
                unscanned: 0,
                truncated: false,
            },
            false,
            false,
            false,
        );
        assert!(text.contains("no public accounts found"));
        assert!(text.contains('─'), "unicode rules by default");
        let ascii = render_search_report(
            "a-very-long-username-that-keeps-going",
            0,
            &[],
            SearchSummary {
                requested: 0,
                completed: 0,
                skipped: 0,
                cancelled: 0,
                unscanned: 0,
                truncated: true,
            },
            false,
            true,
            true,
        );
        assert!(!ascii.contains('─'));
        assert!(ascii.contains("(truncated)"));
    }

    #[test]
    fn search_report_color_uses_semantic_codes_and_plain_stays_clean() {
        let colored = render_search_report(
            "exampleuser",
            1,
            &sample_rows()[..1],
            sample_summary(),
            false,
            true,
            true,
        );
        assert!(contains_ansi(&colored));
        assert!(colored.contains("\x1b[32m"), "confirmed is green");
        let plain = render_search_report(
            "exampleuser",
            1,
            &sample_rows()[..1],
            sample_summary(),
            false,
            false,
            true,
        );
        assert!(!contains_ansi(&plain));
    }
}
