//! Terminal color contract: `--color always` forces ANSI in human output,
//! `--color never` disables it, `NO_COLOR` disables `auto`, and machine
//! output (JSON/JSONL) never contains ANSI regardless of flags.
//!
//! All cases are offline and use synthetic identities only.

use std::path::PathBuf;
use std::process::Command;

fn rxscan_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rxscan"))
}

fn run_cli(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(rxscan_bin())
        .args(args)
        .output()
        .expect("spawn rxscan");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn run_cli_env(args: &[&str], key: &str, value: &str) -> (i32, String, String) {
    let output = Command::new(rxscan_bin())
        .args(args)
        .env(key, value)
        .output()
        .expect("spawn rxscan");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn color_always_forces_ansi_in_human_stats() {
    let (code, stdout, _) = run_cli(&["search", "stats", "--color", "always"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("RXSCAN"), "styled header present");
    assert!(
        stdout.contains('\x1b'),
        "--color always must emit ANSI in human output"
    );
}

#[test]
fn color_never_produces_zero_ansi_in_human_stats() {
    let (code, stdout, _) = run_cli(&["search", "stats", "--color", "never"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("RXSCAN"), "header stays structural");
    assert!(
        !stdout.contains('\x1b'),
        "--color never must emit zero ANSI escapes"
    );
}

#[test]
fn color_always_forces_ansi_in_capabilities() {
    let (code, stdout, _) = run_cli(&["capabilities", "--color", "always"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("RXSCAN"));
    assert!(
        stdout.contains('\x1b'),
        "capabilities --color always must emit ANSI"
    );
}

#[test]
fn color_never_produces_zero_ansi_in_capabilities() {
    let (code, stdout, _) = run_cli(&["capabilities", "--color", "never"]);
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'), "capabilities must stay plain");
}

#[test]
fn color_always_forces_ansi_in_search_human() {
    // Single provider + 1ms deadline keeps this offline-deterministic.
    let (code, stdout, _) = run_cli(&[
        "search",
        "--username",
        "exampleuser",
        "--providers",
        "github",
        "--deadline",
        "1ms",
        "--color",
        "always",
    ]);
    assert_eq!(code, 0);
    assert!(stdout.contains("RXSCAN"));
    assert!(
        stdout.contains('\x1b'),
        "search human --color always must emit ANSI"
    );
}

#[test]
fn color_never_produces_zero_ansi_in_search_human() {
    let (code, stdout, _) = run_cli(&[
        "search",
        "--username",
        "exampleuser",
        "--providers",
        "github",
        "--deadline",
        "1ms",
        "--color",
        "never",
    ]);
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'), "search human must stay plain");
}

#[test]
fn color_always_forces_ansi_in_investigate_transforms() {
    let (code, stdout, _) = run_cli(&["investigate", "transforms", "--color=always"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("RXSCAN"));
    assert!(
        stdout.contains('\x1b'),
        "investigate --color always must emit ANSI"
    );
}

#[test]
fn no_color_disables_ansi_in_automatic_mode() {
    // Documented behavior: NO_COLOR disables styling unless explicitly
    // overridden with `--color always`.
    let (code, stdout, _) = run_cli_env(&["search", "stats"], "NO_COLOR", "1");
    assert_eq!(code, 0);
    assert!(
        !stdout.contains('\x1b'),
        "NO_COLOR must disable ANSI in auto mode"
    );
    let (code, stdout, _) = run_cli_env(&["search", "stats", "--color", "always"], "NO_COLOR", "1");
    assert_eq!(code, 0);
    assert!(stdout.contains('\x1b'), "--color always overrides NO_COLOR");
}

#[test]
fn machine_output_contains_zero_ansi_even_when_forced() {
    // JSON stays clean even with --color always.
    let (code, stdout, _) = run_cli(&["search", "stats", "--json", "--color", "always"]);
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'), "JSON must never contain ANSI");
    serde_json::from_str::<serde_json::Value>(&stdout).expect("valid JSON");

    let (code, stdout, _) = run_cli(&["capabilities", "--json"]);
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'), "capabilities JSON stays clean");

    // JSONL stays clean.
    let (code, stdout, _) = run_cli(&[
        "search",
        "--username",
        "exampleuser",
        "--providers",
        "github",
        "--jsonl",
        "--deadline",
        "1ms",
    ]);
    assert_eq!(code, 0);
    assert!(!stdout.contains('\x1b'), "JSONL must never contain ANSI");
    for line in stdout.lines() {
        serde_json::from_str::<serde_json::Value>(line).expect("every JSONL line parses");
    }
}

#[test]
fn scan_color_modes_differ_in_human_output() {
    // Bounded loopback scan (level 1 = no TCP discovery, immediate).
    let (code, styled, _) = run_cli(&[
        "127.0.0.1",
        "--scope",
        "127.0.0.1",
        "--level",
        "1",
        "--ports",
        "9",
        "--color",
        "always",
    ]);
    assert_eq!(code, 0);
    assert!(styled.contains("RXSCAN"), "scan header present");
    assert!(
        styled.contains('\x1b'),
        "scan --color always must emit ANSI"
    );
    let (code, plain, _) = run_cli(&[
        "127.0.0.1",
        "--scope",
        "127.0.0.1",
        "--level",
        "1",
        "--ports",
        "9",
        "--color",
        "never",
    ]);
    assert_eq!(code, 0);
    assert!(!plain.contains('\x1b'), "scan --color never stays plain");
    // Same semantics, different rendering: stripping ANSI reproduces the
    // same words (modulo styling).
    let stripped: String = stripped_ansi(&styled);
    assert!(
        stripped.contains("TARGET") && plain.contains("TARGET"),
        "both modes carry the same structure"
    );
}

#[test]
fn color_palette_values_are_rejected_everywhere() {
    // `--color` selects *whether* to style, never the palette: palette
    // words such as `green` are usage errors (exit 2) on every path.
    for args in [
        vec!["capabilities", "--color", "green"],
        vec!["capabilities", "--color=green"],
        vec!["--color", "green", "capabilities"],
        vec!["search", "stats", "--color", "green"],
        vec!["search", "providers", "--color=green"],
        vec!["investigate", "transforms", "--color", "green"],
        vec!["investigate", "transforms", "--color=green"],
    ] {
        let (code, _, _) = run_cli(&args);
        assert_eq!(code, 2, "--color green must fail: {args:?}");
    }
}

fn stripped_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
                continue;
            }
            continue;
        }
        out.push(ch);
    }
    out
}
