//! RXScan terminal presentation layer.
//!
//! Business logic (scanner, search, investigation) knows nothing about ANSI
//! styling. Presentation maps semantic styles to terminal output in one place.
//!
//! Design language (dark-terminal friendly, monospace-first):
//! * One compact workflow header (`RXSCAN / <WORKFLOW>` + mode badge).
//! * Uppercase section headings with deliberate spacing.
//! * Reusable tables (ANSI-aware widths), key/value rows, warning blocks.
//! * Unicode line drawing with ASCII fallback; no Nerd Fonts, no fake bold
//!   alphabets, no font installation.
//!
//! Rules:
//! * JSON/JSONL output must never contain ANSI escape codes.
//! * Piped (non-TTY) output defaults to plain text.
//! * `NO_COLOR` disables styling unless `--color always` is explicit.
//! * Color is never the sole signal: every styled state also carries a text
//!   label, symbol, or structural distinction.

use std::io::IsTerminal;

/// How the operator wants color handled.
///
/// `auto` detects an interactive TTY, `always` forces ANSI, `never`
/// disables it. This flag never selects a palette; the theme does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

/// Semantic style roles. Business logic never references ANSI codes or
/// literal color names; the theme maps roles to codes in [`paint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Accent,
    Heading,
    Primary,
    Secondary,
    Muted,
    Success,
    Warning,
    Error,
    Info,
    Border,
    Identifier,
    Value,
    /// Legacy alias for [`Style::Info`]; kept for compatibility.
    Probable,
    /// Legacy alias for [`Style::Error`]; kept for compatibility.
    Danger,
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
/// Kept for compatibility; new renderers prefer [`workflow_header`] which
/// carries the workflow + mode badge. Callers must hide it for
/// `--json`/`--jsonl` and when stdout is not a TTY (unless color was
/// forced with `--color always`).
pub fn startup_mark(color: bool) -> String {
    let brand = paint(color, Style::Accent, "RXSCAN");
    let tagline = paint(color, Style::Muted, "Reconnaissance / Evidence Engine");
    format!("{brand}\n{tagline}")
}

/// Render `text` in a semantic style. With `color == false` the text is
/// returned unchanged (never emits escape codes).
///
/// Default dark-terminal palette:
/// * Accent: bright cyan, bold — brand + workflow separators.
/// * Heading: bold bright cyan — section titles.
/// * Primary: terminal default — body text.
/// * Secondary: dim white — labels, recap text.
/// * Muted: dim — hints, secondary explanations.
/// * Success: bright green, bold — open / confirmed / high.
/// * Warning: bright yellow — filtered / possible / degraded.
/// * Error/Danger: bright red — errors.
/// * Info/Probable: bright blue — informational / medium confidence.
/// * Border: dim cyan — rules and separators.
/// * Identifier: cyan — entity names, URLs, provider names.
/// * Value: bold default — emphasized values.
pub fn paint(color: bool, style: Style, text: &str) -> String {
    if !color {
        return text.to_owned();
    }
    let code = match style {
        Style::Accent => "\x1b[96;1m",
        Style::Heading => "\x1b[1;96m",
        Style::Primary => "\x1b[39m",
        Style::Secondary => "\x1b[37m",
        Style::Muted => "\x1b[2m",
        Style::Success => "\x1b[92;1m",
        Style::Warning => "\x1b[93m",
        Style::Error | Style::Danger => "\x1b[91m",
        Style::Info | Style::Probable => "\x1b[94m",
        Style::Border => "\x1b[2;36m",
        Style::Identifier => "\x1b[96m",
        Style::Value => "\x1b[1m",
    };
    format!("{code}{text}\x1b[0m")
}

/// Strip ANSI CSI sequences (`ESC [ ... <final-byte>`) from `text`.
/// Used to compare styled vs plain renderings and to measure visible width.
pub fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                // Consume parameter bytes + intermediates until final byte.
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
                continue;
            }
            // Lone ESC without CSI: drop it.
            continue;
        }
        out.push(ch);
    }
    out
}

/// Visible terminal columns of `text`, excluding ANSI escapes.
/// Unicode line-drawing glyphs count as one column each; this is a
/// reasonable approximation for monospace terminals.
pub fn visible_width(text: &str) -> usize {
    strip_ansi(text).chars().count()
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

// ============================================================
// Central presentation layer.
//
// All human-facing terminal output shares this vocabulary:
// semantic styles (never raw ANSI at call sites), terminal
// capabilities (color / unicode / width / TTY), number and
// duration formatting, rules, sections, tables, and status
// tokens. Domain code asks for `style_for_*` / `symbol_*` /
// `Table` / `section_heading`; only `paint` knows the codes.
//
// Rules:
// * JSON/JSONL must never pass through here.
// * Color is never the sole signal: every styled state also
//   carries a text label, symbol, or structural distinction.
// * Piped / redirected output stays plain and copy/paste safe.
// ============================================================

/// Crate version for the single deliberate report header.
pub const RXSCAN_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Semantic theme: each role names a [`Style`], never a literal
/// color, so call sites read as `theme.success` rather than green.
///
/// Structured for future themes; [`Theme::default_dark`] is the current
/// dark-terminal mapping. No `--theme` flag is exposed yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub accent: Style,
    pub heading: Style,
    pub primary: Style,
    pub secondary: Style,
    pub muted: Style,
    pub success: Style,
    pub warning: Style,
    pub error: Style,
    pub info: Style,
    pub border: Style,
    pub identifier: Style,
    pub value: Style,
    // Legacy aliases kept so older call sites keep compiling.
    pub danger: Style,
}

impl Theme {
    pub const DEFAULT: Theme = Theme {
        accent: Style::Accent,
        heading: Style::Heading,
        primary: Style::Primary,
        secondary: Style::Secondary,
        muted: Style::Muted,
        success: Style::Success,
        warning: Style::Warning,
        error: Style::Error,
        info: Style::Info,
        border: Style::Border,
        identifier: Style::Identifier,
        value: Style::Value,
        danger: Style::Error,
    };

    /// Default dark-terminal theme. Equivalent to [`Theme::DEFAULT`];
    /// provided as the named constructor the design calls for so future
    /// themes (light, high-contrast) have a place to live.
    pub fn default_dark() -> Self {
        Self::DEFAULT
    }
}

impl Default for Theme {
    fn default() -> Self {
        Theme::DEFAULT
    }
}

/// How much horizontal room the layout has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidthMode {
    /// `>= 100` columns: full tables with optional columns.
    Wide,
    /// `70..=99` columns: optional columns dropped.
    Normal,
    /// `< 70` columns: findings render vertically, never truncated.
    Compact,
}

impl WidthMode {
    pub fn for_width(width: usize) -> Self {
        if width >= 100 {
            WidthMode::Wide
        } else if width >= 70 {
            WidthMode::Normal
        } else {
            WidthMode::Compact
        }
    }
}

/// Resolved output capabilities for one human rendering pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalCapabilities {
    /// Emit ANSI styling.
    pub color: bool,
    /// `true` forces ASCII-only decoration.
    pub ascii: bool,
    /// Assumed terminal width in columns.
    pub width: usize,
    /// Whether stdout is an interactive terminal.
    pub tty: bool,
}

impl TerminalCapabilities {
    /// Deterministic plain capabilities for tests and piped output:
    /// no color, ASCII rules, 80 columns, not a TTY.
    pub fn plain() -> Self {
        Self {
            color: false,
            ascii: true,
            width: 80,
            tty: false,
        }
    }

    /// Resolve capabilities from a color mode plus environment.
    /// `NO_COLOR` / non-TTY disable styling per [`color_enabled`];
    /// Unicode follows [`unicode_supported`]; width follows
    /// [`terminal_width`].
    pub fn resolve(mode: ColorMode, no_color: bool, tty: bool) -> Self {
        Self {
            color: color_enabled(mode, no_color, tty),
            ascii: !unicode_supported(),
            width: terminal_width(),
            tty,
        }
    }

    pub fn width_mode(self) -> WidthMode {
        WidthMode::for_width(self.width)
    }

    pub fn rule_char(self) -> char {
        if self.ascii { '-' } else { '─' }
    }

    pub fn frame_char(self) -> char {
        if self.ascii { '-' } else { '━' }
    }
}

/// Detect the terminal width in columns.
///
/// Honors `RXSCAN_COLUMNS` first (deterministic override for tests),
/// then `COLUMNS`; falls back to 100 on a TTY and 80 otherwise.
/// Values are clamped to `40..=240`.
pub fn terminal_width() -> usize {
    for key in ["RXSCAN_COLUMNS", "COLUMNS"] {
        if let Ok(raw) = std::env::var(key) {
            if let Ok(parsed) = raw.trim().parse::<usize>() {
                if (10..=1000).contains(&parsed) {
                    return parsed.clamp(40, 240);
                }
            }
        }
    }
    if stdout_is_tty() { 100 } else { 80 }
}

/// Format a count with thousands separators for human output
/// (`65535` -> `65,535`). Machine output keeps raw values.
pub fn format_count(value: usize) -> String {
    format_count_u64(value as u64)
}

/// `u64` variant of [`format_count`].
pub fn format_count_u64(mut value: u64) -> String {
    if value < 1000 {
        return value.to_string();
    }
    let mut groups: Vec<String> = Vec::new();
    while value >= 1000 {
        groups.push(format!("{:03}", value % 1000));
        value /= 1000;
    }
    let mut out = value.to_string();
    for group in groups.iter().rev() {
        out.push(',');
        out.push_str(group);
    }
    out
}

/// Humanize a millisecond duration for human output
/// (`88` -> `88ms`, `2090` -> `2.09s`, `74000` -> `1m 14s`).
/// Machine output keeps exact millisecond values.
pub fn humanize_duration_ms(ms: u64) -> String {
    if ms < 1000 {
        return format!("{ms}ms");
    }
    let secs = ms as f64 / 1000.0;
    if ms < 60_000 {
        let text = format!("{secs:.2}");
        let trimmed = text.trim_end_matches('0').trim_end_matches('.');
        return format!("{trimmed}s");
    }
    let total_secs = ms / 1000;
    let minutes = total_secs / 60;
    let rest = total_secs % 60;
    if rest == 0 {
        return format!("{minutes}m");
    }
    format!("{minutes}m {rest}s")
}

/// Truncate `text` to at most `max_chars` characters, appending
/// `...` when truncated. Never splits meaning silently: the
/// ellipsis marks the bound.
pub fn truncate_chars(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let count = text.chars().count();
    if count <= max_chars {
        return text.to_owned();
    }
    if max_chars <= 3 {
        return text.chars().take(max_chars).collect();
    }
    let kept: String = text.chars().take(max_chars - 3).collect();
    format!("{kept}...")
}

/// Full-width rule line (`━━━` / `---`), capped at the terminal
/// width. Frame rules open/close a report; inner separators use
/// [`inner_rule`].
pub fn frame_rule(caps: TerminalCapabilities) -> String {
    let width = caps.width.clamp(40, 120).min(72);
    paint(
        caps.color,
        Theme::DEFAULT.border,
        &caps.frame_char().to_string().repeat(width),
    )
}

/// Short inner separator under a table header.
pub fn inner_rule(caps: TerminalCapabilities, len: usize) -> String {
    let width = len.clamp(8, caps.width.min(100));
    paint(
        caps.color,
        Theme::DEFAULT.border,
        &caps.rule_char().to_string().repeat(width),
    )
}

/// `TITLE` section heading: bold bright-cyan, uppercase label, no boxes.
/// Whitespace around sections is part of the design system: callers emit
/// a blank line before the heading and indent body rows by two spaces.
pub fn section_heading(caps: TerminalCapabilities, title: &str) -> String {
    paint(caps.color, Style::Heading, &title.to_ascii_uppercase())
}

/// `  Key        value` row with a stable label column.
///
/// Labels use the muted/secondary role; values are rendered as given
/// (callers may pre-style important values with [`paint`]).
pub fn key_value(caps: TerminalCapabilities, key: &str, value: &str, key_width: usize) -> String {
    let width = key_width.max(visible_width(key)).max(8);
    // Pad on the visible width: the styled key carries ANSI that must not
    // affect alignment.
    let styled_key = paint(caps.color, Theme::DEFAULT.secondary, key);
    let pad = width.saturating_sub(visible_width(key));
    format!("  {styled_key}{}  {value}", " ".repeat(pad))
}

/// Warning block: `!` + primary warning text, dim secondary explanation.
///
/// ```text
/// ! Deadline reached after 2s
///   Partial evidence was preserved.
/// ```
pub fn warning_block(caps: TerminalCapabilities, title: &str, detail: Option<&str>) -> String {
    let mark = paint(caps.color, Style::Warning, "!");
    let head = paint(caps.color, Style::Warning, title);
    let mut out = format!("  {mark} {head}");
    if let Some(body) = detail {
        let soft = paint(caps.color, Style::Muted, body);
        out.push('\n');
        out.push_str(&format!("    {soft}"));
    }
    out
}

/// Error block: `×` + error text, dim secondary explanation.
pub fn error_block(caps: TerminalCapabilities, title: &str, detail: Option<&str>) -> String {
    let glyph = if caps.ascii { 'x' } else { '×' };
    let mark = paint(caps.color, Style::Error, &glyph.to_string());
    let head = paint(caps.color, Style::Error, title);
    let mut out = format!("  {mark} {head}");
    if let Some(body) = detail {
        let soft = paint(caps.color, Style::Muted, body);
        out.push('\n');
        out.push_str(&format!("    {soft}"));
    }
    out
}

/// One compact workflow header shared by every command:
///
/// ```text
/// RXSCAN  /  INVESTIGATE                          PASSIVE
/// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
/// ```
///
/// `RXSCAN` is bold accent, the workflow is bold primary, the `/`
/// separator and mode badge are muted (or a semantic status when the
/// mode needs attention, e.g. `NETWORK ENABLED` in warning). No giant
/// ASCII art, no redundant tagline: the single header replaces the old
/// `RXSCAN` + `Reactive Recon / Evidence Engine` + `RXSCAN INVESTIGATION`
/// stack.
pub fn workflow_header(
    caps: TerminalCapabilities,
    workflow: &str,
    mode: Option<WorkflowMode>,
) -> String {
    let brand = paint(caps.color, Style::Accent, "RXSCAN");
    let slash = paint(caps.color, Style::Muted, "/");
    let flow = paint(caps.color, Style::Value, &workflow.to_ascii_uppercase());
    let mut first = format!("{brand}  {slash}  {flow}");
    if let Some(badge) = mode {
        let label = badge.label();
        let styled = match badge {
            WorkflowMode::Passive => paint(caps.color, Style::Muted, label),
            WorkflowMode::NetworkEnabled => paint(caps.color, Style::Warning, label),
            WorkflowMode::Custom(_) => paint(caps.color, Style::Muted, label),
        };
        // Right-align the badge on the visible width.
        let plain_len = visible_width(&strip_ansi(&first)) + 2 + label.len();
        let target = caps.width.clamp(40, 120).min(72);
        let pad = target.saturating_sub(plain_len).max(2);
        first.push_str(&" ".repeat(pad));
        first.push_str(&styled);
    }
    let mut out = String::new();
    out.push_str(&first);
    out.push('\n');
    out.push_str(&frame_rule(caps));
    out
}

/// Mode badge for [`workflow_header`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowMode {
    /// Passive evidence only; muted badge.
    Passive,
    /// Explicit authorized network work; warning badge.
    NetworkEnabled,
    /// Caller-styled plain label (rendered muted).
    Custom(String),
}

impl WorkflowMode {
    pub fn label(&self) -> &str {
        match self {
            Self::Passive => "PASSIVE",
            Self::NetworkEnabled => "NETWORK ENABLED",
            Self::Custom(label) => label,
        }
    }
}

/// Backwards-compatible header: `RXSCAN / <KIND>` with no mode badge.
/// New code should prefer [`workflow_header`] with an explicit mode.
pub fn header_block(caps: TerminalCapabilities, kind: &str) -> String {
    let workflow = if kind.is_empty() {
        "RXSCAN".to_owned()
    } else {
        kind.to_owned()
    };
    if workflow.eq_ignore_ascii_case("RXSCAN") {
        workflow_header(caps, "RECON", None)
    } else {
        workflow_header(caps, &workflow, None)
    }
}

/// Closing rule plus one-line recap (`3 services · 64 ports ...`).
///
/// `recap` is rendered as given so callers can emphasize important values
/// with [`paint`]; the frame rule uses the dim border role. With color
/// disabled the recap passes through unchanged.
pub fn footer_block(caps: TerminalCapabilities, recap: &str) -> String {
    let mut out = String::new();
    out.push_str(&frame_rule(caps));
    out.push('\n');
    out.push_str(recap);
    out
}

/// Dim recap line: paints the whole line secondary. Prefer pre-styled
/// recaps with [`footer_block`] when important values need emphasis.
pub fn recap_dim(caps: TerminalCapabilities, text: &str) -> String {
    paint(caps.color, Style::Secondary, text)
}

// --- Tiny semantic symbol vocabulary (§12) -------------------------------
// Every symbol is decorative: the adjacent text label carries the
// meaning, so output stays professional when copied into reports,
// Markdown, CI logs, or terminals without Unicode support.

/// Positive/completed marker: `✓` / `+`.
pub fn symbol_ok(ascii: bool) -> char {
    if ascii { '+' } else { '✓' }
}

/// Warning/partial marker: `!` in both modes (universally safe).
pub fn symbol_warning(_ascii: bool) -> char {
    '!'
}

/// Error marker: `×` / `x`.
pub fn symbol_error(ascii: bool) -> char {
    if ascii { 'x' } else { '×' }
}

/// Relationship/pivot marker: `→` / `->`.
pub fn symbol_arrow(ascii: bool) -> &'static str {
    if ascii { "->" } else { "→" }
}

/// Secondary-item bullet: `·` / `-`.
pub fn symbol_bullet(ascii: bool) -> char {
    if ascii { '-' } else { '·' }
}

// --- Semantic status vocabulary (§23) -----------------------------------
// Display text may use friendly labels; serialized values elsewhere
// stay compatible. Styles are semantic roles, never decoration.

/// Style for a TCP/UDP port state (`open`, `closed`, ...).
pub fn style_for_port_state(state: &str) -> Style {
    match state {
        "open" => Style::Success,
        "closed" => Style::Muted,
        "filtered" | "open|filtered" | "open_or_filtered" => Style::Warning,
        "unknown" => Style::Warning,
        "error" => Style::Error,
        "unscanned" | "cancelled" => Style::Muted,
        _ => Style::Primary,
    }
}

/// Glyph accompanying a port state (text label carries meaning).
pub fn symbol_for_port_state(state: &str, ascii: bool) -> char {
    match state {
        "open" => symbol_ok(ascii),
        "closed" => symbol_bullet(ascii),
        "filtered" | "open|filtered" | "open_or_filtered" | "unknown" => symbol_warning(ascii),
        "error" => symbol_error(ascii),
        _ => symbol_bullet(ascii),
    }
}

/// Confidence label for a 0-100 score: `high` / `medium` / `low`.
/// Exact scores stay in JSON; human output shows the label, with the
/// numeric value alongside only where it aids interpretation.
pub fn confidence_label(score: u8) -> &'static str {
    if score >= 75 {
        "high"
    } else if score >= 40 {
        "medium"
    } else {
        "low"
    }
}

/// Style for a confidence label.
pub fn style_for_confidence(score: u8) -> Style {
    match confidence_label(score) {
        "high" => Style::Success,
        "medium" => Style::Info,
        _ => Style::Warning,
    }
}

/// Diff change marker: `+` new, `-` removed, `~` changed,
/// `?` unknown due to missing coverage. Never uses `-` for
/// merely-unavailable evidence.
pub fn diff_change_glyph(change: &str) -> char {
    match change {
        "added" | "new" => '+',
        "removed" => '-',
        "modified" | "changed" => '~',
        _ => '?',
    }
}

/// Coverage-aware diff marker description (text, never color alone).
pub fn diff_change_label(change: &str) -> &'static str {
    match change {
        "added" | "new" => "new observation",
        "removed" => "removed observation",
        "modified" | "changed" => "changed observation",
        _ => "unknown due to missing coverage",
    }
}

// --- Tables ---------------------------------------------------------------
// Minimal aligned-column renderer. No boxes, no nested frames:
// one header row, one inner rule, then rows. Long cells are
// bounded with [`truncate_chars`]; narrow terminals drop optional
// columns or fall back to vertical blocks (decided by callers via
// [`WidthMode`]). All width math uses [`visible_width`] so ANSI
// styling never affects alignment.

/// Column alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Align {
    #[default]
    Left,
    Right,
}

/// One aligned table. `headers` and every row share the same width.
pub struct Table {
    /// Column headers (rendered dim + uppercase).
    pub headers: Vec<String>,
    /// Data rows; short rows are padded with empty cells.
    pub rows: Vec<Vec<String>>,
    /// Per-column maximum display width (visible chars). `0` = unbounded.
    pub max_widths: Vec<usize>,
    /// Per-column alignment.
    pub aligns: Vec<Align>,
    /// Minimum gap between columns.
    pub gap: usize,
}

impl Table {
    pub fn new(headers: &[&str]) -> Self {
        Self {
            headers: headers.iter().map(|h| h.to_string()).collect(),
            rows: Vec::new(),
            max_widths: vec![0; headers.len()],
            aligns: vec![Align::Left; headers.len()],
            gap: 2,
        }
    }

    pub fn with_align(headers: &[&str], aligns: &[Align]) -> Self {
        let mut table = Self::new(headers);
        for (index, align) in aligns.iter().enumerate() {
            if index < table.aligns.len() {
                table.aligns[index] = *align;
            }
        }
        table
    }

    pub fn row(&mut self, cells: &[&str]) {
        self.cells(cells.iter().map(|c| c.to_string()).collect());
    }

    pub fn cells(&mut self, cells: Vec<String>) {
        self.rows.push(cells);
    }

    /// Pad `cell` to `width` visible columns, preserving embedded ANSI.
    fn pad_cell(cell: &str, width: usize, align: Align) -> String {
        let vis = visible_width(cell);
        if vis >= width {
            return cell.to_owned();
        }
        let pad = width - vis;
        match align {
            Align::Left => format!("{cell}{}", " ".repeat(pad)),
            Align::Right => format!("{}{cell}", " ".repeat(pad)),
        }
    }

    /// Truncate to `width` visible columns, preserving embedded ANSI
    /// styling: escape sequences are copied verbatim (never split or
    /// counted), visible text truncates with an ellipsis, and an open
    /// style is closed with a reset so no styling leaks into neighbors.
    /// Plain cells truncate exactly via [`truncate_chars`].
    fn fit_cell(cell: &str, width: usize) -> String {
        if visible_width(cell) <= width {
            return cell.to_owned();
        }
        if !contains_ansi(cell) {
            return truncate_chars(cell, width);
        }
        if width <= 3 {
            return strip_ansi(cell).chars().take(width).collect();
        }
        let budget = width - 3;
        let mut out = String::with_capacity(cell.len());
        let mut taken = 0usize;
        let mut styled = false;
        let mut chars = cell.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' {
                if chars.peek() == Some(&'[') {
                    out.push(ch);
                    out.push(chars.next().unwrap_or('['));
                    for c in chars.by_ref() {
                        out.push(c);
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                    styled = true;
                    continue;
                }
                continue;
            }
            if taken >= budget {
                break;
            }
            out.push(ch);
            taken += 1;
        }
        out.push_str("...");
        if styled {
            out.push_str("\x1b[0m");
        }
        out
    }

    /// Render with 2-space left margin, dim header + inner rule.
    /// ANSI-aware: styled cells (e.g. green `OPEN`) occupy their visible
    /// width only. Deterministic: same input always renders the same text
    /// for the same capabilities.
    pub fn render(&self, caps: TerminalCapabilities) -> String {
        let cols = self.headers.len();
        if cols == 0 {
            return String::new();
        }
        // Bound long cells before measuring (visible widths).
        let mut grid: Vec<Vec<String>> = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            let mut line = Vec::with_capacity(cols);
            for index in 0..cols {
                let cell = row.get(index).cloned().unwrap_or_default();
                let max = self.max_widths.get(index).copied().unwrap_or(0);
                // Bound over-long cells early with ANSI-preserving
                // truncation so widths measure what will render.
                if max > 0 && visible_width(&cell) > max {
                    line.push(Self::fit_cell(&cell, max));
                } else {
                    line.push(cell);
                }
            }
            grid.push(line);
        }
        let mut widths = vec![0usize; cols];
        for (index, header) in self.headers.iter().enumerate() {
            widths[index] = visible_width(header);
        }
        for row in &grid {
            for (index, cell) in row.iter().enumerate() {
                widths[index] = widths[index].max(visible_width(cell));
            }
        }
        // Shrink to fit: trim unbounded trailing columns first.
        let available = caps.width.saturating_sub(2).max(40);
        let gap = self.gap.max(1);
        let mut total: usize = widths.iter().sum::<usize>() + gap * cols.saturating_sub(1);
        if total > available {
            for index in (0..cols).rev() {
                if total <= available {
                    break;
                }
                if self.max_widths.get(index).copied().unwrap_or(0) == 0 && widths[index] > 12 {
                    let over = total - available;
                    let cut = over.min(widths[index] - 12);
                    widths[index] -= cut;
                    total -= cut;
                }
            }
            // Still too wide: hard-truncate the last column.
            if total > available {
                if let Some(last) = widths.last_mut() {
                    *last = (*last).saturating_sub(total - available).max(8);
                }
            }
        }
        let mut out = String::new();
        let head: Vec<String> = self
            .headers
            .iter()
            .enumerate()
            .map(|(i, h)| {
                let align = self.aligns.get(i).copied().unwrap_or(Align::Left);
                Self::pad_cell(&Self::fit_cell(h, widths[i]), widths[i], align)
            })
            .collect();
        out.push_str("  ");
        out.push_str(&paint(
            caps.color,
            Theme::DEFAULT.secondary,
            &head.join(&" ".repeat(gap)),
        ));
        out.push('\n');
        let sep: Vec<String> = widths
            .iter()
            .map(|w| caps.rule_char().to_string().repeat((*w).max(2)))
            .collect();
        out.push_str("  ");
        out.push_str(&paint(
            caps.color,
            Theme::DEFAULT.border,
            &sep.join(&" ".repeat(gap)),
        ));
        out.push('\n');
        for row in &grid {
            let line: Vec<String> = row
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    let align = self.aligns.get(i).copied().unwrap_or(Align::Left);
                    Self::pad_cell(&Self::fit_cell(c, widths[i]), widths[i], align)
                })
                .collect();
            out.push_str("  ");
            // Trim trailing filler spaces but never ANSI resets: rtrim
            // spaces only after stripping? Simplest: trim_end spaces from
            // the joined plain layout, then re-join styled cells with the
            // same widths. Since padding is trailing spaces, trim_end is
            // safe (reset codes are not spaces).
            let joined = line.join(&" ".repeat(gap));
            out.push_str(joined.trim_end());
            out.push('\n');
        }
        // Trim the trailing newline for composability; callers add
        // their own section spacing.
        out.trim_end_matches('\n').to_owned()
    }
}

// --- Progress ---------------------------------------------------------------
// One restrained updating line for interactive TTYs only. Callers
// must never emit this into JSON/JSONL, pipes, redirected files,
// or non-TTY logs. When the denominator is unknown, show counts
// and elapsed time with no invented percentage.

/// Render one progress line, or `None` when progress must stay
/// hidden (not a TTY, no color path, or unknown totals and no
/// counts worth showing). `done`/`total` use `None` for unknown.
pub fn progress_line(
    label: &str,
    done: Option<u64>,
    total: Option<u64>,
    elapsed_ms: u64,
    caps: TerminalCapabilities,
) -> Option<String> {
    if !caps.tty || !caps.color {
        return None;
    }
    let elapsed = humanize_duration_ms(elapsed_ms);
    let bar_width = 16usize;
    match (done, total) {
        (Some(done), Some(total)) if total > 0 => {
            let ratio = (done as f64 / total as f64).clamp(0.0, 1.0);
            let filled = (ratio * bar_width as f64).round() as usize;
            let (fill, empty) = if caps.ascii {
                ("#".repeat(filled), "-".repeat(bar_width - filled))
            } else {
                ("█".repeat(filled), "░".repeat(bar_width - filled))
            };
            Some(format!(
                "{} [{fill}{empty}] {:>3}%  {}/{}  {}",
                label,
                (ratio * 100.0).round() as u64,
                format_count_u64(done),
                format_count_u64(total),
                elapsed,
            ))
        }
        (Some(done), _) => Some(format!(
            "{}  {} done  {}",
            label,
            format_count_u64(done),
            elapsed
        )),
        _ => Some(format!("{label}  {elapsed}")),
    }
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
/// Designed interface: workflow header, `TARGET` metadata, `FINDINGS`
/// table (`STATUS / PROVIDER / CONFIDENCE / EVIDENCE`), `COVERAGE`
/// accounting, then a bottom summary bar. Colors are semantic; with
/// `color == false` the output is plain text without escape codes.
/// Unicode rules/glyphs follow `ascii`. Fixed 80-column layout; see
/// [`render_search_report_responsive`] for width-adaptive rendering.
pub fn render_search_report(
    target: &str,
    requested: usize,
    rows: &[SearchRow],
    summary: SearchSummary,
    show_all: bool,
    color: bool,
    ascii: bool,
) -> String {
    render_search_report_responsive(target, requested, rows, summary, show_all, color, ascii, 80)
}

/// Width-adaptive search report: wide terminals show the full
/// `STATUS / PROVIDER / CONFIDENCE / EVIDENCE` table; normal mode drops
/// the evidence column; compact mode renders each finding vertically so
/// identity and state are never truncated.
#[allow(clippy::too_many_arguments)]
pub fn render_search_report_responsive(
    target: &str,
    requested: usize,
    rows: &[SearchRow],
    summary: SearchSummary,
    show_all: bool,
    color: bool,
    ascii: bool,
    width: usize,
) -> String {
    let caps = TerminalCapabilities {
        color,
        ascii,
        width: width.clamp(40, 240),
        tty: false,
    };
    render_search_report_caps(target, requested, rows, &summary, show_all, caps)
}

/// Plain detailed search rendering for `--explain` (80 columns, no caps).
pub fn render_search_report_explain(
    target: &str,
    requested: usize,
    rows: &[SearchRow],
    summary: SearchSummary,
    show_all: bool,
    color: bool,
    ascii: bool,
) -> String {
    let caps = TerminalCapabilities {
        color,
        ascii,
        width: 80,
        tty: false,
    };
    render_search_report_explain_caps(target, requested, rows, &summary, show_all, caps)
}

/// Capabilities-based search renderer. `requested` is the provider count
/// the operator asked for; per-status counts come from `rows` + `summary`.
///
/// Default human output is concise: header, `TARGET`, `FINDINGS`,
/// `COVERAGE`, incomplete-coverage warnings, and the footer recap
/// (`2 confirmed · 0 possible · 2/2 completed`). The raw provider
/// accounting line lives only in the explain rendering
/// ([`render_search_report_explain_caps`]); see `--explain`.
pub fn render_search_report_caps(
    target: &str,
    requested: usize,
    rows: &[SearchRow],
    summary: &SearchSummary,
    show_all: bool,
    caps: TerminalCapabilities,
) -> String {
    render_search_report_inner(target, requested, rows, summary, show_all, caps, false)
}

/// Detailed provider accounting for `--explain`.
///
/// Contains everything default shows plus the raw accounting line
/// (`N requested · N completed · … · 0 network scans`) and truncation
/// detail. The model is unchanged; only presentation differs.
pub fn render_search_report_explain_caps(
    target: &str,
    requested: usize,
    rows: &[SearchRow],
    summary: &SearchSummary,
    show_all: bool,
    caps: TerminalCapabilities,
) -> String {
    render_search_report_inner(target, requested, rows, summary, show_all, caps, true)
}

fn render_search_report_inner(
    target: &str,
    requested: usize,
    rows: &[SearchRow],
    summary: &SearchSummary,
    show_all: bool,
    caps: TerminalCapabilities,
    explain: bool,
) -> String {
    let mode = caps.width_mode();
    let color = caps.color;
    let mut out = String::new();
    out.push_str(&workflow_header(
        caps,
        "PUBLIC SEARCH",
        Some(WorkflowMode::Passive),
    ));
    out.push('\n');

    // TARGET -----------------------------------------------------------
    out.push('\n');
    out.push_str(&section_heading(caps, "Target"));
    out.push('\n');
    let target_value = paint(color, Style::Identifier, target);
    out.push('\n');
    out.push_str(&key_value(caps, "Username", &target_value, 10));
    out.push('\n');
    out.push_str(&key_value(
        caps,
        "Providers",
        &paint(color, Style::Value, &format_count(requested)),
        10,
    ));
    out.push('\n');
    out.push_str(&key_value(
        caps,
        "Network",
        &paint(color, Style::Muted, "Disabled"),
        10,
    ));
    out.push('\n');

    // Progressive disclosure: default human output shows ONE findings
    // table with ONE total display budget (10 rows). Confirmed findings
    // sort before possible findings; up to 2 rows are reserved for
    // possible findings when they exist, and unused confirmed capacity
    // flows to possible findings. Blocked/unknown/rate-limited/error
    // rows are secondary: they stay in COVERAGE totals and JSON/JSONL,
    // and show individually only with `--all` (or `--explain` for
    // reasoning). Presentation limits never affect execution or the
    // evidence model.
    const DEFAULT_FINDINGS_BUDGET: usize = 10;
    const POSSIBLE_RESERVE: usize = 2;
    let mut confirmed: Vec<&SearchRow> = rows
        .iter()
        .filter(|row| row.status == "confirmed")
        .collect();
    confirmed.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(a.provider.cmp(&b.provider))
    });
    let mut possible: Vec<&SearchRow> = rows
        .iter()
        .filter(|row| row.status == "possible" || row.status == "probable")
        .collect();
    possible.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(a.provider.cmp(&b.provider))
    });
    let attention: Vec<&SearchRow> = rows
        .iter()
        .filter(|row| row.tier == RowTier::Attention)
        .collect();
    let quiet: Vec<&SearchRow> = rows
        .iter()
        .filter(|row| row.tier == RowTier::Quiet)
        .collect();
    // Whether any primary finding exists (used for the empty hint).
    let has_primary = !confirmed.is_empty() || !possible.is_empty();
    // Whether attention/quiet detail is visible in this rendering.
    // Default hides secondary rows; `--all` reveals full human detail;
    // `--explain` reveals provider reasoning (attention) plus raw
    // accounting below.
    let show_attention = show_all || explain;
    let show_quiet = show_all;

    // FINDINGS ---------------------------------------------------------
    out.push('\n');
    out.push_str(&section_heading(caps, "Findings"));
    out.push('\n');
    if !has_primary && !show_attention && (!show_quiet || quiet.is_empty()) {
        // No primary findings and secondary detail hidden: concise hint.
        // When secondary rows exist but are hidden, COVERAGE below still
        // carries their totals plus a plain-language warning.
        out.push('\n');
        out.push_str(&format!(
            "  {}\n",
            paint(
                color,
                Style::Muted,
                "no public accounts found - use --all to list negative results"
            )
        ));
    } else if !has_primary
        && show_attention
        && attention.is_empty()
        && (!show_quiet || quiet.is_empty())
    {
        out.push('\n');
        out.push_str(&format!(
            "  {}\n",
            paint(
                color,
                Style::Muted,
                "no public accounts found - use --all to list negative results"
            )
        ));
    } else {
        out.push('\n');
        // One FINDINGS table: confirmed first, then possible, under one
        // total budget unless `--all`. The header renders exactly once
        // because the two status groups share a single table.
        let (shown_confirmed, shown_possible): (&[&SearchRow], &[&SearchRow]) = if show_all {
            (confirmed.as_slice(), possible.as_slice())
        } else if possible.is_empty() {
            let take = confirmed.len().min(DEFAULT_FINDINGS_BUDGET);
            (&confirmed[..take], &[][..])
        } else {
            let reserve = possible.len().min(POSSIBLE_RESERVE);
            let take_confirmed = confirmed
                .len()
                .min(DEFAULT_FINDINGS_BUDGET.saturating_sub(reserve));
            let remaining = DEFAULT_FINDINGS_BUDGET.saturating_sub(take_confirmed);
            let take_possible = possible.len().min(remaining);
            (&confirmed[..take_confirmed], &possible[..take_possible])
        };
        let mut combined: Vec<&SearchRow> =
            Vec::with_capacity(shown_confirmed.len() + shown_possible.len());
        combined.extend_from_slice(shown_confirmed);
        combined.extend_from_slice(shown_possible);
        out.push_str(&render_search_table(caps, mode, &combined));
        let total_primary = confirmed.len() + possible.len();
        let hidden_findings = total_primary.saturating_sub(combined.len());
        if hidden_findings > 0 {
            out.push_str(&format!(
                "  {}\n",
                paint(
                    color,
                    Style::Muted,
                    &format!("+ {hidden_findings} additional findings"),
                )
            ));
        }
        if show_attention {
            out.push_str(&render_search_table(caps, mode, &attention));
        }
        if show_quiet {
            out.push_str(&render_search_rows_muted(caps, &quiet));
        }
    }

    // COVERAGE ---------------------------------------------------------
    // Preserves exact provider accounting even when rows were visually
    // suppressed.
    out.push('\n');
    out.push_str(&section_heading(caps, "Coverage"));
    out.push('\n');
    out.push('\n');
    let counts = SearchCoverage::from_rows(rows, summary);
    for (label, value) in counts.rows() {
        let styled = if label == "Confirmed" {
            paint(color, Style::Success, &value)
        } else if label == "Possible" || label == "Rate limited" {
            paint(color, Style::Warning, &value)
        } else if label == "Errors" {
            paint(color, Style::Error, &value)
        } else if label == "Blocked" || label == "Unknown" {
            paint(color, Style::Muted, &value)
        } else {
            paint(color, Style::Value, &value)
        };
        out.push_str(&key_value(caps, label, &styled, 13));
        out.push('\n');
    }
    let counts_for_warning = SearchCoverage::from_rows(rows, summary);
    let secondary_failures = counts_for_warning.blocked
        + counts_for_warning.unknown
        + counts_for_warning.rate_limited
        + counts_for_warning.errors
        + summary.unscanned;
    let incomplete =
        summary.unscanned > 0 || summary.truncated || summary.completed < summary.requested;
    if secondary_failures > 0 || incomplete {
        // Plain language for first-time users; internal accounting stays in
        // COVERAGE totals, `--explain`, and machine output.
        out.push('\n');
        out.push_str(&warning_block(
            caps,
            "Some providers could not be verified.",
            None,
        ));
        out.push('\n');
    }

    // Footer summary bar ------------------------------------------------
    out.push('\n');
    let confirmed = rows.iter().filter(|r| r.status == "confirmed").count();
    let possible = rows
        .iter()
        .filter(|r| r.status == "possible" || r.status == "probable")
        .count();
    let recap = format!(
        "{}  ·  {}  ·  {}",
        paint(color, Style::Success, &format!("{confirmed} confirmed")),
        paint(color, Style::Warning, &format!("{possible} possible")),
        paint(
            color,
            Style::Secondary,
            &format!(
                "{}/{} completed",
                format_count(summary.completed),
                format_count(summary.requested)
            )
        ),
    );
    // Machine-agnostic plain line for tests/pipes; styled line keeps the
    // same words so stripping ANSI reproduces the plain text.
    out.push_str(&footer_block(caps, &recap));
    out.push('\n');
    // Detailed provider accounting lives only in `--explain`. Default
    // output already communicates completeness via COVERAGE, the
    // incomplete-coverage warning, and the footer recap; the raw line
    // below would duplicate that. When coverage is incomplete, default
    // still visibly warns (above), so no uncertainty is hidden.
    if explain {
        out.push_str(&format!(
            "  {} requested · {} completed · {} skipped · {} cancelled · {} unscanned · 0 network scans{}",
            summary.requested,
            summary.completed,
            summary.skipped,
            summary.cancelled,
            summary.unscanned,
            if summary.truncated { " (truncated)" } else { "" },
        ));
        out.push('\n');
    }
    out
}

/// Coverage numbers derived from the same rows the table shows, so
/// coverage and findings cannot disagree. `summary` supplies the
/// authoritative requested/completed/skipped/cancelled/unscanned counts.
struct SearchCoverage {
    completed: String,
    confirmed: usize,
    possible: usize,
    blocked: usize,
    unknown: usize,
    rate_limited: usize,
    errors: usize,
    unscanned: usize,
}

impl SearchCoverage {
    fn from_rows(rows: &[SearchRow], summary: &SearchSummary) -> Self {
        let mut confirmed = 0usize;
        let mut possible = 0usize;
        let mut blocked = 0usize;
        let mut unknown = 0usize;
        let mut rate_limited = 0usize;
        let mut errors = 0usize;
        for row in rows {
            match row.status {
                "confirmed" => confirmed += 1,
                "probable" | "possible" => possible += 1,
                "blocked" | "authentication_required" => blocked += 1,
                "not_found" | "unknown" | "skipped" => unknown += 1,
                "rate_limited" => rate_limited += 1,
                "error" => errors += 1,
                _ => unknown += 1,
            }
        }
        Self {
            completed: format!(
                "{} / {}",
                format_count(summary.completed),
                format_count(summary.requested)
            ),
            confirmed,
            possible,
            blocked,
            unknown,
            rate_limited,
            errors,
            unscanned: summary.unscanned,
        }
    }

    fn rows(&self) -> Vec<(&'static str, String)> {
        vec![
            ("Completed", self.completed.clone()),
            ("Confirmed", format_count(self.confirmed)),
            ("Possible", format_count(self.possible)),
            ("Blocked", format_count(self.blocked)),
            ("Unknown", format_count(self.unknown)),
            ("Rate limited", format_count(self.rate_limited)),
            ("Errors", format_count(self.errors)),
            ("Unscanned", format_count(self.unscanned)),
        ]
    }
}

/// Findings table via the shared [`Table`] renderer (ANSI-aware).
/// Wide shows STATUS / PROVIDER / CONFIDENCE / EVIDENCE; normal drops
/// EVIDENCE; compact renders vertical blocks.
fn render_search_table(caps: TerminalCapabilities, mode: WidthMode, rows: &[&SearchRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    if mode == WidthMode::Compact {
        let mut out = String::new();
        for row in rows {
            let status = search_status_label(row.status);
            out.push_str(&format!(
                "  {} {}\n",
                paint(
                    caps.color,
                    style_for(row.status),
                    &glyph(row.status, caps.ascii)
                ),
                paint(caps.color, style_for(row.status), &status),
            ));
            out.push_str(&format!(
                "    Provider    {}\n",
                paint(caps.color, Style::Identifier, &row.provider)
            ));
            let conf = format!("{} {}%", confidence_label(row.confidence), row.confidence);
            out.push_str(&format!(
                "    Confidence  {}\n",
                paint(caps.color, style_for_confidence(row.confidence), &conf)
            ));
            if !row.detail.is_empty() {
                let short = truncate_chars(&row.detail, 48);
                out.push_str(&format!("    Evidence    {short}\n"));
            }
        }
        return out;
    }
    let show_detail = mode == WidthMode::Wide;
    let mut table = if show_detail {
        Table::new(&["STATUS", "PROVIDER", "CONFIDENCE", "EVIDENCE"])
    } else {
        Table::new(&["STATUS", "PROVIDER", "CONFIDENCE"])
    };
    if show_detail {
        table.max_widths = vec![12, 24, 12, 36];
    } else {
        table.max_widths = vec![12, 28, 14];
    }
    for row in rows {
        let status_label = search_status_label(row.status);
        let glyph_text = glyph(row.status, caps.ascii);
        let status_cell = format!(
            "{} {}",
            paint(caps.color, style_for(row.status), &glyph_text),
            paint(caps.color, style_for(row.status), &status_label),
        );
        let provider_cell = paint(caps.color, Style::Identifier, &row.provider);
        let conf_text = format!("{} {}%", confidence_label(row.confidence), row.confidence);
        let conf_cell = paint(caps.color, style_for_confidence(row.confidence), &conf_text);
        if show_detail {
            let evidence = if row.detail.is_empty() {
                paint(caps.color, Style::Muted, "-")
            } else {
                truncate_chars(&row.detail, 36)
            };
            table.cells(vec![status_cell, provider_cell, conf_cell, evidence]);
        } else {
            table.cells(vec![status_cell, provider_cell, conf_cell]);
        }
    }
    let mut rendered = table.render(caps);
    rendered.push('\n');
    rendered
}

/// Human-readable status label for search findings.
fn search_status_label(status: &str) -> String {
    match status {
        "confirmed" => "CONFIRMED".to_owned(),
        "probable" => "PROBABLE".to_owned(),
        "possible" => "POSSIBLE".to_owned(),
        "not_found" => "NOT FOUND".to_owned(),
        "unknown" => "UNKNOWN".to_owned(),
        "rate_limited" => "RATE LIMITED".to_owned(),
        "blocked" => "BLOCKED".to_owned(),
        "authentication_required" => "AUTH REQUIRED".to_owned(),
        "error" => "ERROR".to_owned(),
        "cancelled" => "CANCELLED".to_owned(),
        "unscanned" => "UNSCANNED".to_owned(),
        "skipped" => "SKIPPED".to_owned(),
        other => other.to_uppercase().replace('_', " "),
    }
}

/// Quiet (negative) rows, muted, only with `show_all`.
fn render_search_rows_muted(caps: TerminalCapabilities, rows: &[&SearchRow]) -> String {
    let mut out = String::new();
    for row in rows {
        out.push_str(&format!(
            "  {} {}  {}\n",
            paint(caps.color, Style::Muted, &glyph(row.status, caps.ascii)),
            paint(caps.color, Style::Muted, &search_status_label(row.status)),
            row.provider,
        ));
    }
    out
}

fn glyph(status: &str, ascii: bool) -> String {
    search_status_glyph(status, ascii).to_string()
}

fn style_for(status: &str) -> Style {
    match status {
        "confirmed" => Style::Success,
        "probable" => Style::Info,
        "possible" => Style::Warning,
        "rate_limited" => Style::Warning,
        "blocked" | "authentication_required" => Style::Warning,
        "error" => Style::Error,
        _ => Style::Muted,
    }
}

/// Strip ANSI from `styled` and compare semantic text to `plain`.
/// Returns true when both carry the same words in order (whitespace
/// normalized). Used by color-proof tests: styling must not change meaning.
pub fn styled_matches_plain(styled: &str, plain: &str) -> bool {
    fn normalize(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }
    normalize(&strip_ansi(styled)) == normalize(plain)
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
            Style::Heading,
            Style::Primary,
            Style::Secondary,
            Style::Muted,
            Style::Success,
            Style::Warning,
            Style::Error,
            Style::Info,
            Style::Border,
            Style::Identifier,
            Style::Value,
            Style::Probable,
            Style::Danger,
        ] {
            let rendered = paint(false, style, "exampleuser");
            assert_eq!(rendered, "exampleuser");
            assert!(!contains_ansi(&rendered));
        }
    }

    #[test]
    fn paint_with_color_uses_semantic_codes() {
        // Bright semantic palette for dark terminals.
        assert!(paint(true, Style::Success, "x").starts_with("\x1b[92"));
        assert!(paint(true, Style::Error, "x").starts_with("\x1b[91"));
        assert!(paint(true, Style::Danger, "x").starts_with("\x1b[91"));
        assert!(paint(true, Style::Info, "x").starts_with("\x1b[94"));
        assert!(paint(true, Style::Probable, "x").starts_with("\x1b[94"));
        assert!(paint(true, Style::Warning, "x").starts_with("\x1b[93"));
        assert!(paint(true, Style::Accent, "x").contains("96"));
        assert!(paint(true, Style::Heading, "x").contains("96"));
        assert!(paint(true, Style::Identifier, "x").contains("96"));
        assert!(paint(true, Style::Border, "x").contains("36"));
        for style in [Style::Success, Style::Error, Style::Muted, Style::Accent] {
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
        assert!(text.contains("PUBLIC SEARCH"));
        assert!(text.contains("TARGET"));
        assert!(text.contains("FINDINGS"));
        assert!(text.contains("COVERAGE"));
        assert!(text.contains("CONFIRMED"));
        assert!(text.contains("provider-a"));
        // First-time UX: blocked/unknown/rate-limited rows are secondary.
        // Default hides individual failure rows; COVERAGE totals plus a
        // plain-language warning carry the signal.
        assert!(
            !text.contains("BLOCKED"),
            "blocked rows need --all, coverage carries totals"
        );
        assert!(!text.contains("provider-d"), "attention needs --all");
        assert!(text.contains("Blocked"), "coverage preserves blocked total");
        assert!(text.contains("Some providers could not be verified."));
        // Default is concise: footer recap stays, raw accounting moves to --explain.
        assert!(text.contains("2/2") || text.contains("4 / 4") || text.contains("completed"));
        assert!(
            !text.contains("0 network scans"),
            "raw accounting lives in --explain"
        );
        assert!(
            !text.contains("4 requested"),
            "raw accounting lives in --explain"
        );
        assert!(!text.contains("provider-e"), "negatives need --all");
        assert!(!contains_ansi(&text));
        // `--all` reveals full human provider detail.
        let all = render_search_report(
            "exampleuser",
            4,
            &sample_rows(),
            sample_summary(),
            true,
            false,
            true,
        );
        assert!(all.contains("BLOCKED"));
        assert!(all.contains("provider-d"));
        assert!(all.contains("provider-e"));
        // Explain retains the full provider accounting.
        let explained = render_search_report_explain(
            "exampleuser",
            4,
            &sample_rows(),
            sample_summary(),
            false,
            false,
            true,
        );
        assert!(explained.contains("0 network scans"));
        assert!(explained.contains("4 requested"));
        assert!(explained.contains("4 completed"));
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
        // Default keeps the footer recap; raw counts live in --explain.
        assert!(text.contains("completed"));
        assert!(
            !text.contains("4 requested"),
            "raw accounting lives in --explain"
        );
        let explained = render_search_report_explain(
            "exampleuser",
            4,
            &sample_rows(),
            sample_summary(),
            true,
            false,
            true,
        );
        assert!(explained.contains("4 requested"));
        assert!(explained.contains("4 completed"));
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
        // Frame rules use heavy Unicode by default.
        assert!(
            text.contains('━') || text.contains('─'),
            "unicode rules by default"
        );
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
        assert!(!ascii.contains('━'));
        // Default signals truncation via a plain-language warning;
        // the raw "(truncated)" marker lives in --explain.
        assert!(ascii.contains("Some providers could not be verified."));
        assert!(
            !ascii.contains("(truncated)"),
            "raw marker lives in --explain"
        );
        let ascii_explained = render_search_report_explain(
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
        assert!(ascii_explained.contains("(truncated)"));
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
        // Confirmed renders bright green; the header carries bright cyan.
        assert!(colored.contains("\x1b[92"), "confirmed is bright green");
        assert!(colored.contains("\x1b[96"), "brand is cyan");
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

    #[test]
    fn color_always_emits_ansi_and_never_stays_plain() {
        // Proof: forced color produces real ANSI; never produces none.
        let styled = render_search_report(
            "exampleuser",
            1,
            &sample_rows()[..1],
            sample_summary(),
            false,
            true,
            true,
        );
        assert!(contains_ansi(&styled));
        assert!(styled.contains("\x1b["));
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
        assert!(!plain.contains("\x1b["));
    }

    #[test]
    fn stripping_styled_search_matches_plain_semantics() {
        let styled = render_search_report(
            "exampleuser",
            4,
            &sample_rows(),
            sample_summary(),
            false,
            true,
            true,
        );
        let plain = render_search_report(
            "exampleuser",
            4,
            &sample_rows(),
            sample_summary(),
            false,
            false,
            true,
        );
        assert!(contains_ansi(&styled));
        assert!(styled_matches_plain(&styled, &plain));
        assert_eq!(strip_ansi(&styled), strip_ansi(&plain));
    }

    #[test]
    fn ansi_aware_width_ignores_escapes() {
        let styled = paint(true, Style::Success, "OPEN");
        assert_eq!(visible_width(&styled), 4);
        assert_eq!(visible_width("OPEN"), 4);
        let mut table = Table::new(&["PORT", "STATE"]);
        table.cells(vec![styled.clone(), "x".to_owned()]);
        let caps = TerminalCapabilities {
            color: true,
            ascii: true,
            width: 80,
            tty: false,
        };
        let rendered = table.render(caps);
        // The styled OPEN cell must align exactly like plain OPEN.
        let mut plain_table = Table::new(&["PORT", "STATE"]);
        plain_table.cells(vec!["OPEN".to_owned(), "x".to_owned()]);
        let plain = plain_table.render(TerminalCapabilities::plain());
        assert_eq!(
            visible_width(&rendered),
            visible_width(&plain),
            "ANSI must not affect layout width"
        );
        assert_eq!(strip_ansi(&rendered), strip_ansi(&plain));
    }

    #[test]
    fn workflow_header_shows_mode_and_frame() {
        let caps = TerminalCapabilities {
            color: false,
            ascii: false,
            width: 72,
            tty: true,
        };
        let passive = workflow_header(caps, "INVESTIGATE", Some(WorkflowMode::Passive));
        assert!(passive.contains("RXSCAN"));
        assert!(passive.contains("INVESTIGATE"));
        assert!(passive.contains("PASSIVE"));
        assert!(passive.contains('━'));
        let net = workflow_header(caps, "INVESTIGATE", Some(WorkflowMode::NetworkEnabled));
        assert!(net.contains("NETWORK ENABLED"));
        let colored = workflow_header(
            TerminalCapabilities {
                color: true,
                ascii: false,
                width: 72,
                tty: true,
            },
            "RECON",
            None,
        );
        assert!(contains_ansi(&colored));
    }

    #[test]
    fn table_reports_zero_ansi_when_plain() {
        let mut table = Table::new(&["A", "B"]);
        table.row(&["x", "y"]);
        let plain = table.render(TerminalCapabilities::plain());
        assert!(!contains_ansi(&plain));
        let styled = table.render(TerminalCapabilities {
            color: true,
            ascii: true,
            width: 80,
            tty: true,
        });
        assert!(contains_ansi(&styled));
        assert!(styled_matches_plain(&styled, &plain));
    }

    #[test]
    fn truncated_styled_cells_keep_their_styling() {
        // A styled cell that overflows its column must truncate the visible
        // text without dropping its ANSI codes or leaking style.
        let styled = paint(true, Style::Identifier, "investigation_project_persistence");
        let mut table = Table::new(&["CAPABILITY", "STATUS"]);
        table.max_widths = vec![32, 12];
        table.cells(vec![styled, "AVAILABLE".to_owned()]);
        let caps = TerminalCapabilities {
            color: true,
            ascii: true,
            width: 80,
            tty: false,
        };
        let rendered = table.render(caps);
        let row = rendered.lines().nth(2).expect("data row renders");
        assert!(contains_ansi(row), "truncated cell keeps its style");
        assert!(
            row.contains("...\x1b[0m"),
            "open style is closed right after the ellipsis"
        );
        // Column widths derive from content: 32 + gap 2 + 9 ("AVAILABLE").
        assert_eq!(visible_width(row.trim_start()), 32 + 2 + 9);
        // Stripped text matches the plain truncation exactly.
        let plain_truncated = truncate_chars("investigation_project_persistence", 32);
        assert!(strip_ansi(row).contains(&plain_truncated));
    }
}
