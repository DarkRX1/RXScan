//! Phase 6 monitoring: scope gates, thresholds, masked sinks, live loop.
//!
//! Loopback scans only (127.0.0.1, closed port) — never external.

use std::io::Read;
use std::net::TcpListener;
use std::process::Command;
use std::time::Duration;

fn bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_rxscan"))
}

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("rxscan-monitor6-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn monitor(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(bin());
    cmd.arg("monitor");
    for arg in args {
        cmd.arg(arg);
    }
    cmd.env("NO_COLOR", "1");
    cmd.current_dir(dir);
    cmd.output().expect("rxscan monitor runs")
}

#[test]
fn out_of_scope_schedule_refuses_before_network() {
    // Same gate as manual runs: excluding the seed removes it from the
    // effective scope, so planning fails and no scan ever starts.
    let dir = tmp("scope");
    let state = dir.join("state");
    let started = std::time::Instant::now();
    let out = monitor(
        &dir,
        &[
            "192.0.2.10",
            "--exclude",
            "192.0.2.10",
            "--state-dir",
            state.to_str().unwrap(),
            "--repeat",
            "1",
        ],
    );
    assert!(
        !out.status.success(),
        "out-of-scope schedule must be refused"
    );
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "refusal must precede any network activity"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("scope") || err.contains("Scope") || err.contains("excluded"),
        "refusal must name scope: {err}"
    );
    // No checkpoints from a refused schedule.
    assert!(!state.join("scan-0.rxscan").exists());
}

#[test]
fn loopback_baseline_then_no_change() {
    let dir = tmp("loop");
    let state = dir.join("state");
    let base = [
        "127.0.0.1",
        "--ports",
        "1",
        "--level",
        "1",
        "--max-tasks",
        "20",
        "--deadline",
        "60",
        "--state-dir",
        state.to_str().unwrap(),
        "--repeat",
        "1",
    ];
    let args: Vec<&str> = base.to_vec();
    let first = monitor(&dir, &args);
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        state.join("scan-0.rxscan").exists(),
        "checkpoint must be written"
    );
    let text = String::from_utf8_lossy(&first.stdout).into_owned()
        + &String::from_utf8_lossy(&first.stderr);
    assert!(
        text.contains("baseline"),
        "first run establishes baseline: {text}"
    );
    // Second identical run: same closed port, no meaningful change.
    let second = monitor(&dir, &args);
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        second.status.code(),
        Some(0),
        "no change means exit 0, not 3"
    );
    assert!(state.join("scan-1.rxscan").exists());
    // Absurd thresholds suppress everything (gating works end to end).
    let strict: Vec<String> = base
        .iter()
        .map(|s| s.to_string())
        .chain(["--min-added".to_owned(), "9999".to_owned()])
        .collect();
    let strict_ref: Vec<&str> = strict.iter().map(String::as_str).collect();
    let third = monitor(&dir, &strict_ref);
    assert!(third.status.success());
    assert_eq!(third.status.code(), Some(0));
}

#[test]
fn alert_file_and_webhook_are_masked() {
    use rxscan::monitor_run::{MonitorAlert, append_alert_file, post_webhook, webhook_payload};
    let alert = MonitorAlert {
        scan_id: "scan-9".to_owned(),
        previous_scan_id: "scan-8".to_owned(),
        reasons: vec!["exposure token=FAKE-MON-6 reported".to_owned()],
        added: 1,
        removed: 0,
        changed: 0,
        inconclusive: 0,
        at_unix: 1_700_000_000,
    };
    // File sink.
    let dir = tmp("sinks");
    let file = dir.join("alerts.jsonl");
    append_alert_file(&file, &alert).unwrap();
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(!text.contains("FAKE-MON-6"), "alert file leaked a secret");
    assert!(text.contains("\"added\":1"));
    // Webhook sink against a loopback listener.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let received_inner = received.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        // Read headers, then the exact body length.
        loop {
            let n = stream.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&raw).into_owned();
                let len: usize = head
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("Content-Length:")
                            .or_else(|| line.strip_prefix("content-length:"))
                    })
                    .and_then(|value| value.trim().parse().ok())
                    .unwrap_or(0);
                let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                while raw.len() < split + len {
                    let n = stream.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..n]);
                }
                break;
            }
        }
        *received_inner.lock().unwrap() = raw;
        // Minimal 200 response so the client sees success.
    });
    // Fire the webhook in the background while the fake server reads.
    let payload = webhook_payload(&alert);
    let url = format!("http://127.0.0.1:{port}/hook");
    // Read the request concurrently: spawn the POST, then join the reader.
    let poster = std::thread::spawn(move || post_webhook(&url, &payload));
    server.join().unwrap();
    // The minimal server above never writes a response, so the POST
    // errors on read — but the request bytes must have arrived masked.
    let _ = poster.join().unwrap();
    let raw = received.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&raw).into_owned();
    assert!(text.contains("POST /hook"), "webhook request malformed");
    assert!(
        !text.contains("FAKE-MON-6"),
        "webhook payload leaked a secret"
    );
    let split = text.find("\r\n\r\n").unwrap() + 4;
    let body: serde_json::Value = serde_json::from_str(&text[split..]).unwrap();
    assert_eq!(body["event"], "monitor_alert");
    assert_eq!(body["added"], 1);
}

#[test]
fn monitor_usage_errors_are_typed() {
    let dir = tmp("usage");
    // Missing --state-dir.
    let out = monitor(&dir, &["127.0.0.1"]);
    assert_eq!(out.status.code(), Some(2));
    // Bad webhook.
    let out = monitor(
        &dir,
        &["127.0.0.1", "--state-dir", "s", "--webhook", "ftp://x/y"],
    );
    assert!(!out.status.success());
    // Zero repeat.
    let out = monitor(&dir, &["127.0.0.1", "--state-dir", "s", "--repeat", "0"]);
    assert!(!out.status.success());
}
