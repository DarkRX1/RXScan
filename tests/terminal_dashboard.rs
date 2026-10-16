//! Phase 4 terminal dashboard: TTY live view, plain fallback, cancel key.
//!
//! The dashboard replaces only the transient progress line on color
//! TTYs. Pipes, `--color never`, and machine formats stay byte-pure.
//! A pty (`script(1)`) proves the live path without any network: the
//! email workflow is local-only.

use std::process::Command;

fn bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_rxscan"))
}

#[test]
fn piped_machine_output_stays_pure() {
    // Piped stdout: no ANSI, valid JSON, success.
    let out = Command::new(bin())
        .arg("search")
        .arg("--email")
        .arg("user@example.test")
        .arg("--json")
        .output()
        .expect("runs");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!text.contains('\x1b'), "piped JSON must carry no ANSI");
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(
        value.get("seed").is_some() || value.get("results").is_some(),
        "shape: {value}"
    );
    // Human piped output: no ANSI either.
    let out = Command::new(bin())
        .arg("search")
        .arg("--email")
        .arg("user@example.test")
        .arg("--color")
        .arg("never")
        .output()
        .expect("runs");
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!text.contains('\x1b'), "color=never must carry no ANSI");
    assert!(
        !text.contains("Findings feed"),
        "dashboard must not render off-TTY"
    );
}

#[test]
fn pty_session_stays_clean_on_instant_workflows() {
    // Instant local workflows finish without waves: no dashboard frames,
    // no raw-mode side effects, no hang — even on a real TTY.
    let probe = Command::new("script").arg("--version").output();
    if probe.is_err() || !probe.unwrap().status.success() {
        eprintln!("script(1) unavailable: skipping pty test");
        return;
    }
    let out = Command::new("timeout")
        .arg("60")
        .arg("script")
        .arg("-qec")
        .arg(format!(
            "{} search --email user@example.test",
            bin().display()
        ))
        .arg("/dev/null")
        .output()
        .expect("script runs");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        !text.contains("Findings feed"),
        "instant runs must not draw frames"
    );
    assert!(
        text.contains("Entity search"),
        "report must print normally:\n{text}"
    );
}
