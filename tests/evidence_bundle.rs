//! Evidence bundle (`rxscan evidence-bundle` / `rxscan verify-bundle`)
//! correctness tests.
//!
//! Synthetic/reserved values only: example domains, FAKE-BUNDLE-* secret
//! markers that must never survive masking into bundle files.

use std::path::{Path, PathBuf};
use std::process::Command;

use rxscan::project_db::{ProjectDb, RetentionMode};
use sha2::{Digest, Sha256};

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

/// Re-hash `name` inside manifest.txt so a deliberately edited bundle file
/// still passes the hash check, letting a deeper structural check be reached.
fn rewrite_manifest_hash(bundle_dir: &Path, name: &str, contents: &str) {
    let manifest_path = bundle_dir.join("manifest.txt");
    let manifest = fs_read_to_string(&manifest_path);
    let new_hash = format!("{:x}", Sha256::digest(contents.as_bytes()));
    let mut rewritten = String::new();
    for line in manifest.lines() {
        let mut parts = line.splitn(2, char::is_whitespace);
        let _hash = parts.next().unwrap_or("");
        let entry = parts.next().unwrap_or("").trim();
        if entry == name {
            rewritten.push_str(&format!("{new_hash}  {entry}\n"));
        } else if !entry.is_empty() {
            rewritten.push_str(line);
            rewritten.push('\n');
        }
    }
    std::fs::write(&manifest_path, rewritten).unwrap();
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

    // Tampered evidence.jsonl fails verification, and the reported cause is the
    // hash mismatch rather than an unrelated structural error.
    let ev_path = out_dir.join("evidence.jsonl");
    let mut ev = fs_read_to_string(&ev_path);
    ev.push_str("tampered-append-line\n");
    std::fs::write(&ev_path, &ev).unwrap();
    let out = run_verify(&[out_dir.to_str().unwrap()])
        .output()
        .expect("verify-bundle runs");
    assert!(!out.status.success(), "tampered evidence.jsonl must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("hash mismatch for 'evidence.jsonl'"),
        "expected hash mismatch, got: {}",
        String::from_utf8_lossy(&out.stderr)
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
    let out = run_verify(&[out_dir.to_str().unwrap()])
        .output()
        .expect("verify-bundle runs");
    assert!(!out.status.success(), "extra file must fail verification");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("extra file 'extra.txt'"),
        "extra file must be the reported cause, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Remove it explicitly: --force refuses a directory holding entries the
    // bundle does not own, so it can no longer act as a cleanup.
    std::fs::remove_file(out_dir.join("extra.txt")).unwrap();

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
    let out = run_verify(&[out_dir.to_str().unwrap()])
        .output()
        .expect("verify-bundle runs");
    assert!(!out.status.success(), "subdirectory must fail verification");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("subdirectory 'subdir'"),
        "subdirectory must be the reported cause, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::remove_dir(out_dir.join("subdir")).unwrap();

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
        let out = run_verify(&[out_dir.to_str().unwrap()])
            .output()
            .expect("verify-bundle runs");
        assert!(!out.status.success(), "symlink must fail verification");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("symlink 'link'"),
            "symlink must be the reported cause, got: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        std::fs::remove_file(out_dir.join("link")).unwrap();
    }

    // Restore, then evidence_count mismatch fails. Rewritten through the JSON
    // value so the assertion cannot pass on an unrelated extra-file error.
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
    let mut value: serde_json::Value =
        serde_json::from_str(&fs_read_to_string(&out_dir.join("bundle.json"))).unwrap();
    value["evidence_count"] = serde_json::json!(9);
    let rewritten = serde_json::to_string_pretty(&value).unwrap();
    std::fs::write(out_dir.join("bundle.json"), &rewritten).unwrap();
    // Keep manifest.txt consistent with the edited file, so the count check
    // is reached instead of the (earlier) hash check.
    rewrite_manifest_hash(&out_dir, "bundle.json", &rewritten);
    let out = run_verify(&[out_dir.to_str().unwrap()])
        .output()
        .expect("verify-bundle runs");
    assert!(
        !out.status.success(),
        "evidence_count mismatch must fail verification"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("does not match evidence.jsonl line count"),
        "count mismatch must be the reported cause, got: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Restore, then evidence id mismatch fails. Parse and rewrite the JSON
    // rather than string-replacing: bundle.json is pretty-printed and ids are
    // strings, so a `"evidence_ids": [1]` literal never appears in it.
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
    let mut value: serde_json::Value =
        serde_json::from_str(&fs_read_to_string(&out_dir.join("bundle.json"))).unwrap();
    let original_ids = value["evidence_ids"].clone();
    assert!(
        !original_ids.as_array().unwrap().is_empty(),
        "fixture must record evidence ids for this check to mean anything"
    );
    value["evidence_ids"] = serde_json::json!(["not-a-real-id"]);
    let rewritten = serde_json::to_string_pretty(&value).unwrap();
    std::fs::write(out_dir.join("bundle.json"), &rewritten).unwrap();
    rewrite_manifest_hash(&out_dir, "bundle.json", &rewritten);
    let out = run_verify(&[out_dir.to_str().unwrap()])
        .output()
        .expect("verify-bundle runs");
    assert!(
        !out.status.success(),
        "evidence id mismatch must fail verification"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("evidence ids in bundle.json do not match evidence.jsonl"),
        "id mismatch must be the reported cause, got: {}",
        String::from_utf8_lossy(&out.stderr)
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
    assert!(
        out_dir.join("stale.txt").exists(),
        "the pre-existing file is left untouched"
    );

    // --force does not buy its way past a file it does not own; see
    // evidence_bundle_force_refuses_unrelated_entries for the full matrix.
    let forced = run_bundle(&[
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
        !forced.status.success(),
        "--force must not delete an unrelated file"
    );
    assert!(out_dir.join("stale.txt").exists(), "stale file survives");
}

#[test]
fn evidence_bundle_force_refuses_unrelated_entries() {
    // --force means "replace the bundle this command wrote", never "empty
    // this directory". A mistyped --out must not destroy unrelated data.
    let root = tmp_dir("force-foreign");
    let db_path = root.join("proj.sqlite");
    fixture_db(&db_path);

    // (label, seed closure, name expected in the refusal)
    type ForeignCase = (&'static str, fn(&Path), &'static str);
    let mut cases: Vec<ForeignCase> = Vec::new();
    cases.push((
        "unrelated file",
        |d: &Path| {
            std::fs::write(d.join("notes.txt"), "keep me").unwrap();
        },
        "notes.txt",
    ));
    cases.push((
        "subdirectory",
        |d: &Path| {
            std::fs::create_dir(d.join("archive")).unwrap();
            std::fs::write(d.join("archive").join("old.json"), "{}").unwrap();
        },
        "archive",
    ));
    // Appended, not gated in place: an inline `#[cfg(unix)]` inside the
    // closure would leave the case present on Windows with an empty body, and
    // the test would then assert a refusal against a directory holding
    // nothing. Symlinks are a unix concept here, so the case is unix-only.
    #[cfg(unix)]
    cases.push((
        "symlink",
        |d: &Path| {
            std::os::unix::fs::symlink("/etc/passwd", d.join("link")).unwrap();
        },
        "link",
    ));

    for (label, seed, expect_name) in cases {
        let out_dir = root.join(label.replace(' ', "-"));
        std::fs::create_dir_all(&out_dir).unwrap();
        seed(&out_dir);

        let out = run_bundle(&[
            db_path.to_str().unwrap(),
            "--case-id",
            "CASE-5",
            "--force",
            "--out",
            out_dir.to_str().unwrap(),
        ])
        .output()
        .expect("evidence-bundle runs");

        assert!(
            !out.status.success(),
            "--force must refuse a directory holding a {label}"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(expect_name) && stderr.contains("does not own"),
            "refusal for {label} should name {expect_name}, got: {stderr}"
        );
        assert!(
            !out_dir.join("bundle.json").exists(),
            "nothing written when refusing a {label}"
        );
        assert!(
            out_dir.join(expect_name).exists(),
            "the {label} must survive the refusal"
        );
    }
}

#[test]
fn evidence_bundle_force_replaces_only_its_own_files() {
    // A directory holding only a previous bundle is replaceable by --force,
    // and the result still verifies.
    let root = tmp_dir("force-owned");
    let db_path = root.join("proj.sqlite");
    fixture_db(&db_path);
    let out_dir = root.join("bundle");

    let first = run_bundle(&[
        db_path.to_str().unwrap(),
        "--case-id",
        "CASE-6",
        "--out",
        out_dir.to_str().unwrap(),
    ])
    .output()
    .expect("evidence-bundle runs");
    assert!(first.status.success());

    // Without --force the existing bundle is refused.
    let no_force = run_bundle(&[
        db_path.to_str().unwrap(),
        "--case-id",
        "CASE-6",
        "--out",
        out_dir.to_str().unwrap(),
    ])
    .output()
    .expect("evidence-bundle runs");
    assert!(
        !no_force.status.success(),
        "an existing bundle needs --force"
    );
    assert!(
        String::from_utf8_lossy(&no_force.stderr).contains("already holds a bundle"),
        "refusal should say the directory already holds a bundle, got: {}",
        String::from_utf8_lossy(&no_force.stderr)
    );

    // With --force the previous bundle's files are replaced in place.
    let forced = run_bundle(&[
        db_path.to_str().unwrap(),
        "--case-id",
        "CASE-7",
        "--force",
        "--out",
        out_dir.to_str().unwrap(),
    ])
    .output()
    .expect("evidence-bundle runs");
    assert!(
        forced.status.success(),
        "--force must replace a bundle-only directory: {}",
        String::from_utf8_lossy(&forced.stderr)
    );
    assert!(fs_read_to_string(&out_dir.join("bundle.json")).contains("CASE-7"));

    let verified = run_verify(&[out_dir.to_str().unwrap()])
        .output()
        .expect("verify-bundle runs");
    assert!(
        verified.status.success(),
        "bundle written with --force must verify: {}",
        String::from_utf8_lossy(&verified.stderr)
    );
}

#[test]
fn verify_bundle_rejects_manifest_names_outside_the_bundle() {
    // A rewritten manifest must not be able to make verification hash files
    // outside the bundle directory. Rejection is by name and happens before
    // any file is opened, so the hash is irrelevant here and the names below
    // are never resolved against the filesystem -- which also keeps this
    // test free of /etc/passwd and of any path-separator assumption.
    // `..\outside.txt` is included because a Windows manifest can use a
    // backslash separator, and the check must not care which one it is.
    let hostile = [
        "../outside.txt",
        "..\\outside.txt",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "sub/child.json",
        "sub\\child.json",
    ];
    for name in hostile {
        let root = tmp_dir("traversal");
        let out_dir = root.join("bundle");
        std::fs::create_dir_all(&out_dir).unwrap();
        std::fs::write(
            out_dir.join("bundle.json"),
            "{\"evidence_count\":0,\"evidence_ids\":[]}\n",
        )
        .unwrap();
        std::fs::write(out_dir.join("evidence.jsonl"), "").unwrap();
        std::fs::write(
            out_dir.join("manifest.txt"),
            format!("{}  {name}\n", "a".repeat(64)),
        )
        .unwrap();

        let out = run_verify(&[out_dir.to_str().unwrap()])
            .output()
            .expect("verify-bundle runs");
        assert!(
            !out.status.success(),
            "manifest naming '{name}' must be rejected"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("not a bundle file") && stderr.contains(name),
            "refusal for '{name}' should name it as not a bundle file, got: {stderr}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
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
}

/// Unwritable output path: error, and no partial bundle.
///
/// Unix-only for two reasons, not one. Windows has no POSIX mode bits, so
/// `from_mode(0o000)` does not exist and an ACL is required instead. And on
/// unix, root bypasses discretionary access control, so the directory stays
/// writable for uid 0 and the run would succeed, inverting the assertion.
/// Gating the whole case avoids both a compile error and a runtime failure
/// that looks like a product bug.
#[cfg(unix)]
#[test]
fn evidence_bundle_unwritable_output_path_writes_nothing() {
    use std::os::unix::fs::PermissionsExt;

    let root = tmp_dir("unwritable");
    let db_path = root.join("proj.sqlite");
    fixture_db(&db_path);
    let read_only = root.join("read-only");
    std::fs::create_dir_all(&read_only).unwrap();

    std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o000)).unwrap();

    // Verify the precondition instead of assuming it: root bypasses mode
    // bits, so for uid 0 the directory stays writable, the run succeeds and
    // the assertion inverts. Probing is exact and needs no FFI.
    let probe = read_only.join("probe");
    if std::fs::write(&probe, "x").is_ok() {
        let _ = std::fs::remove_file(&probe);
        std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o0755)).unwrap();
        eprintln!(
            "skipping unwritable-output-path test: mode 000 did not deny writes (privileged user)"
        );
        return;
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

    // Restore before asserting so the temp dir can be cleaned up later.
    let _ = std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o0755));

    assert!(
        !out.status.success(),
        "an unwritable output path must fail: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !unwritable.exists(),
        "nothing may be created under an unwritable directory"
    );
    assert!(
        std::fs::read_dir(&read_only).unwrap().next().is_none(),
        "read-only dir stays empty (no partial bundle)"
    );
}
