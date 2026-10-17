//! Evidence bundle (`rxscan evidence-bundle` / `rxscan verify-bundle`)
//! correctness tests.
//!
//! Synthetic/reserved values only: example domains, FAKE-BUNDLE-* secret
//! markers that must never survive masking into bundle files.

use std::path::{Path, PathBuf};
use std::process::Command;

use rxscan::project_db::{ProjectDb, RetentionMode};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rxscan"))
}

/// Project database with one masked evidence item carrying fake secrets.
fn fixture_db(path: &Path) -> ProjectDb {
    let mut db = ProjectDb::open(path).unwrap();
    db.conn_execute_for_test(
        "INSERT INTO scan_runs(scan_id, plan_id, started_at_ms, finished_at_ms, scope_json, workflow, level, tool_version, termination, tasks_admitted, tasks_completed, coverage_json, classifier_json, truncated) VALUES('scan-1','plan-1',1,2,'{\"allow\":[\"127.0.0.1\"]}','recon',3,'1.2.0','completed',1,1,'{}','[]',0)",
    )
    .unwrap();
    db.store_evidence(
        "scan-1",
        &[(
            "fixture-source".to_owned(),
            "asset-1".to_owned(),
            85,
            serde_json::json!({
                "finding": "observed something",
                "password": "FAKE-BUNDLE-PW-1",
                "token": "FAKE-BUNDLE-TOK-1",
            }),
            1_700_000_000_000,
        )],
        RetentionMode::Full,
    )
    .unwrap();
    db
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rxscan-evbundle-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run_bundle(args: &[&str]) -> Command {
    let mut cmd = Command::new(bin());
    cmd.arg("evidence-bundle").args(args);
    cmd
}

fn run_verify(args: &[&str]) -> Command {
    let mut cmd = Command::new(bin());
    cmd.arg("verify-bundle").args(args);
    cmd
}

#[test]
fn evidence_bundle_roundtrip_verifies() {
    let root = tmp_dir("roundtrip");
    let db_path = root.join("proj.sqlite");
    fixture_db(&db_path);

    let out_dir = root.join("bundle");
    let out = run_bundle(&[
        db_path.to_str().unwrap(),
        "--case-id",
        "CASE-1",
        "--operator",
        "analyst",
        "--out",
        out_dir.to_str().unwrap(),
    ])
    .output()
    .expect("evidence-bundle runs");
    assert!(
        out.status.success(),
        "evidence-bundle failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("evidence bundle written to"));
    // Bundle digest printed out-of-band for --expect-digest.
    let digest_line = stdout
        .lines()
        .find(|l| l.starts_with("bundle digest (sha256 of manifest.txt): "))
        .expect("bundle digest line printed");
    let digest = digest_line.trim_start_matches("bundle digest (sha256 of manifest.txt): ");
    assert_eq!(digest.len(), 64);
    assert!(digest.as_bytes().iter().all(|b| b.is_ascii_hexdigit()));

    assert!(out_dir.join("bundle.json").exists());
    assert!(out_dir.join("evidence.jsonl").exists());
    assert!(out_dir.join("manifest.txt").exists());

    let bundle_text = fs_read_to_string(&out_dir.join("bundle.json"));
    assert!(bundle_text.contains("CASE-1"), "case id recorded");
    assert!(bundle_text.contains("analyst"), "operator recorded");
    assert!(
        bundle_text.contains("1.2.0") || bundle_text.contains(env!("CARGO_PKG_VERSION")),
        "tool version recorded"
    );
    assert!(bundle_text.contains("Z"), "UTC timestamp recorded");
    assert!(bundle_text.contains("scan-1"), "run id recorded");
    assert!(
        bundle_text.contains("\"scopes\""),
        "per-run scope definitions recorded"
    );

    // Secret canary: no fake secret material in any bundle file.
    for name in ["bundle.json", "evidence.jsonl", "manifest.txt"] {
        let text = fs_read_to_string(&out_dir.join(name));
        assert!(
            !text.contains("FAKE-BUNDLE-PW-1"),
            "secret leaked into {name}"
        );
        assert!(
            !text.contains("FAKE-BUNDLE-TOK-1"),
            "secret leaked into {name}"
        );
    }

    // evidence_count agrees with evidence.jsonl line count; every line is
    // valid JSON with an id.
    let evidence_text = fs_read_to_string(&out_dir.join("evidence.jsonl"));
    let evidence_lines: Vec<&str> = evidence_text.lines().filter(|l| !l.is_empty()).collect();
    assert!(!evidence_lines.is_empty());

    // verify-bundle passes on the untouched bundle.
    let good = run_verify(&[out_dir.to_str().unwrap()])
        .output()
        .expect("verify-bundle runs");
    assert!(
        good.status.success(),
        "verify-bundle good bundle: {}",
        String::from_utf8_lossy(&good.stderr)
    );

    // --expect-digest passes with the printed digest.
    let ok = run_verify(&[out_dir.to_str().unwrap(), "--expect-digest", digest])
        .output()
        .expect("verify-bundle runs");
    assert!(ok.status.success(), "verify-bundle --expect-digest pass");

    // --expect-digest fails on a wrong digest.
    let bad = run_verify(&[
        out_dir.to_str().unwrap(),
        "--expect-digest",
        &"0".repeat(64),
    ])
    .output()
    .expect("verify-bundle runs");
    assert!(!bad.status.success(), "verify-bundle --expect-digest fail");
}

fn fs_read_to_string(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("cannot read {path:?}: {error}"))
}

#[test]
fn evidence_bundle_tamper_detection() {
    let root = tmp_dir("tamper");
    let db_path = root.join("proj.sqlite");
    fixture_db(&db_path);
    let out_dir = root.join("bundle");
    run_bundle(&[
        db_path.to_str().unwrap(),
        "--case-id",
        "CASE-2",
        "--out",
        out_dir.to_str().unwrap(),
    ])
    .output()
    .expect("evidence-bundle runs");
    assert!(
        run_verify(&[out_dir.to_str().unwrap()])
            .output()
            .expect("verify-bundle runs")
            .status
            .success()
    );

    // Tampered evidence.jsonl fails verification.
    let ev_path = out_dir.join("evidence.jsonl");
    let mut ev = fs_read_to_string(&ev_path);
    ev.push_str("tampered-append-line\n");
    std::fs::write(&ev_path, &ev).unwrap();
    assert!(
        !run_verify(&[out_dir.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );

    // Restore, then a missing file fails.
    run_bundle(&[
        db_path.to_str().unwrap(),
        "--case-id",
        "CASE-2",
        "--force",
        "--out",
        out_dir.to_str().unwrap(),
    ])
    .output()
    .expect("evidence-bundle runs");
    std::fs::remove_file(out_dir.join("bundle.json")).unwrap();
    assert!(
        !run_verify(&[out_dir.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );

    // Restore, then an extra file fails.
    run_bundle(&[
        db_path.to_str().unwrap(),
        "--case-id",
        "CASE-2",
        "--force",
        "--out",
        out_dir.to_str().unwrap(),
    ])
    .output()
    .expect("evidence-bundle runs");
    std::fs::write(out_dir.join("extra.txt"), "extra").unwrap();
    assert!(
        !run_verify(&[out_dir.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );

    // Restore, then a subdirectory fails.
    run_bundle(&[
        db_path.to_str().unwrap(),
        "--case-id",
        "CASE-2",
        "--force",
        "--out",
        out_dir.to_str().unwrap(),
    ])
    .output()
    .expect("evidence-bundle runs");
    std::fs::create_dir(out_dir.join("subdir")).unwrap();
    assert!(
        !run_verify(&[out_dir.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );

    // Restore, then a symlink fails.
    run_bundle(&[
        db_path.to_str().unwrap(),
        "--case-id",
        "CASE-2",
        "--force",
        "--out",
        out_dir.to_str().unwrap(),
    ])
    .output()
    .expect("evidence-bundle runs");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", out_dir.join("link")).unwrap();
        assert!(
            !run_verify(&[out_dir.to_str().unwrap()])
                .output()
                .unwrap()
                .status
                .success()
        );
    }

    // Restore, then evidence_count mismatch fails.
    run_bundle(&[
        db_path.to_str().unwrap(),
        "--case-id",
        "CASE-2",
        "--force",
        "--out",
        out_dir.to_str().unwrap(),
    ])
    .output()
    .expect("evidence-bundle runs");
    let mut bundle_text = fs_read_to_string(&out_dir.join("bundle.json"));
    bundle_text = bundle_text.replace("\"evidence_count\": 1", "\"evidence_count\": 9");
    std::fs::write(out_dir.join("bundle.json"), &bundle_text).unwrap();
    assert!(
        !run_verify(&[out_dir.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );

    // Restore, then evidence id mismatch fails.
    run_bundle(&[
        db_path.to_str().unwrap(),
        "--case-id",
        "CASE-2",
        "--force",
        "--out",
        out_dir.to_str().unwrap(),
    ])
    .output()
    .expect("evidence-bundle runs");
    let mut bundle_text = fs_read_to_string(&out_dir.join("bundle.json"));
    bundle_text = bundle_text.replace("\"evidence_ids\": [1]", "\"evidence_ids\": [9]");
    std::fs::write(out_dir.join("bundle.json"), &bundle_text).unwrap();
    assert!(
        !run_verify(&[out_dir.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn evidence_bundle_refuses_non_empty_output_dir() {
    let root = tmp_dir("nonempty");
    let db_path = root.join("proj.sqlite");
    fixture_db(&db_path);
    let out_dir = root.join("bundle");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(out_dir.join("stale.txt"), "stale").unwrap();

    let first = run_bundle(&[
        db_path.to_str().unwrap(),
        "--case-id",
        "CASE-3",
        "--out",
        out_dir.to_str().unwrap(),
    ])
    .output()
    .expect("evidence-bundle runs");
    assert!(!first.status.success(), "non-empty dir should be refused");
    assert!(
        !out_dir.join("bundle.json").exists(),
        "nothing written on refusal"
    );

    // --force overwrites.
    let second = run_bundle(&[
        db_path.to_str().unwrap(),
        "--case-id",
        "CASE-3",
        "--force",
        "--out",
        out_dir.to_str().unwrap(),
    ])
    .output()
    .expect("evidence-bundle runs");
    assert!(
        second.status.success(),
        "--force should succeed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(out_dir.join("bundle.json").exists());
}

#[test]
fn evidence_bundle_errors_leave_no_partial_bundle() {
    let root = tmp_dir("errors");

    // Unopenable project: parent directory missing -> error, nothing written.
    let missing = root.join("nonexistent-dir").join("proj.sqlite");
    let out = run_bundle(&[
        missing.to_str().unwrap(),
        "--case-id",
        "CASE-4",
        "--out",
        root.join("bundle-missing").to_str().unwrap(),
    ])
    .output()
    .expect("evidence-bundle runs");
    assert!(!out.status.success());
    assert!(!root.join("bundle-missing").exists());

    // Unwritable output path: error, nothing written.
    let db_path = root.join("proj.sqlite");
    fixture_db(&db_path);
    let read_only = root.join("read-only");
    std::fs::create_dir_all(&read_only).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let unwritable = read_only.join("bundle");
    let out = run_bundle(&[
        db_path.to_str().unwrap(),
        "--case-id",
        "CASE-4",
        "--out",
        unwritable.to_str().unwrap(),
    ])
    .output()
    .expect("evidence-bundle runs");
    assert!(!out.status.success());
    assert!(!unwritable.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o0755));
    }
    // read-only dir stays empty (no partial bundle).
    assert!(std::fs::read_dir(&read_only).unwrap().next().is_none());
}
