//! Tamper-evident evidence bundles (`rxscan evidence-bundle` /
//! `rxscan verify-bundle`).
//!
//! A bundle is a masked, redacted copy of the evidence stored in a project
//! database: `bundle.json` (UTC timestamps, tool version, scope/run ids,
//! operator-supplied case id and operator name), `evidence.jsonl` (masked
//! evidence items) and `manifest.txt` (SHA-256 of every bundle file). The
//! originals stay in the project database; the bundle supports integrity
//! checking only. RXScan does not provide or claim legal admissibility,
//! signing, or operator authentication.

use crate::exposure::{mask_json, scrub_text};
use crate::project_db::ProjectDb;
use serde_json::Map;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Files a bundle may contain. Manifest entries are matched against this
/// list, so a rewritten manifest cannot make verification read a path
/// outside the bundle (`../outside.txt`, `/etc/passwd`).
const MANIFEST_FILES: [&str; 2] = ["bundle.json", "evidence.jsonl"];

/// Every file a bundle writes, including manifest.txt. `--force` may replace
/// exactly these and nothing else.
const OWNED_FILES: [&str; 3] = ["bundle.json", "evidence.jsonl", "manifest.txt"];

macro_rules! err_out {
    ($($arg:tt)*) => {{
        eprintln!($($arg)*);
    }};
}
macro_rules! out_line {
    ($($arg:tt)*) => {{
        println!($($arg)*);
    }};
}

pub fn run_evidence_bundle(args: &[String]) {
    let usage =
        "rxscan evidence-bundle <project> --case-id ID [--operator NAME] [--force] --out <path>";
    if args
        .get(2)
        .map(String::as_str)
        .is_some_and(|s| s == "--help" || s == "-h")
    {
        out_line!("{usage}");
        return;
    }
    let mut iter = args[2..].iter().peekable();
    let mut project: Option<&str> = None;
    let mut case_id: Option<&str> = None;
    let mut operator: Option<&str> = None;
    let mut out_dir: Option<&str> = None;
    let mut force = false;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--case-id" => match iter.next() {
                Some(v) => case_id = Some(v),
                None => {
                    err_out!("rxscan evidence-bundle: missing value for --case-id ({usage})");
                    std::process::exit(2);
                }
            },
            "--operator" => match iter.next() {
                Some(v) => operator = Some(v),
                None => {
                    err_out!("rxscan evidence-bundle: missing value for --operator ({usage})");
                    std::process::exit(2);
                }
            },
            "--out" => match iter.next() {
                Some(v) => out_dir = Some(v),
                None => {
                    err_out!("rxscan evidence-bundle: missing value for --out ({usage})");
                    std::process::exit(2);
                }
            },
            "--force" => force = true,
            other if project.is_none() => project = Some(other),
            _ => {
                err_out!("rxscan evidence-bundle: unexpected argument '{arg}' ({usage})");
                std::process::exit(2);
            }
        }
    }
    let project = match project {
        Some(p) => p,
        None => {
            err_out!("rxscan evidence-bundle: missing <project> ({usage})");
            std::process::exit(2);
        }
    };
    let case_id = match case_id {
        Some(c) => c,
        None => {
            err_out!("rxscan evidence-bundle: missing --case-id ({usage})");
            std::process::exit(2);
        }
    };
    let out_dir = match out_dir {
        Some(o) => o,
        None => {
            err_out!("rxscan evidence-bundle: missing --out ({usage})");
            std::process::exit(2);
        }
    };
    if let Err(error) = run_evidence_bundle_inner(project, case_id, operator, out_dir, force) {
        err_out!("rxscan evidence-bundle: {error}");
        std::process::exit(1);
    }
}

/// Build a masked, tamper-evident evidence bundle for a project.
///
/// Writes into a temporary directory beside the target and renames each
/// file into place, so a failure never leaves a partial bundle behind.
/// Fails when the project cannot be opened, evidence cannot be read, or
/// any file cannot be written and verified. Refuses a non-empty output
/// directory unless `--force` is given; `--force` replaces only the files
/// this command owns and refuses the directory if it holds anything else.
fn run_evidence_bundle_inner(
    project: &str,
    case_id: &str,
    operator: Option<&str>,
    out_dir: &str,
    force: bool,
) -> Result<(), String> {
    let db = ProjectDb::open(Path::new(project))
        .map_err(|error| format!("cannot open project '{project}': {error}"))?;
    let evidence_items = db
        .evidence_items()
        .map_err(|error| format!("cannot read evidence items: {error}"))?;
    let run_ids = db
        .scan_ids()
        .map_err(|error| format!("cannot read scan ids: {error}"))?;

    // Record the stored scope definition per run, not just run ids.
    let mut scopes = Map::new();
    for run in &run_ids {
        let scope = db
            .scope_of(run)
            .map_err(|error| format!("cannot read scope for run '{run}': {error}"))?;
        scopes.insert(
            run.clone(),
            scope.map_or(serde_json::Value::Null, |s| serde_json::json!(s)),
        );
    }

    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let created_iso = format_utc(created);

    let out_path = PathBuf::from(out_dir);
    // Checked before any work: `--force` replaces only the files this
    // command owns, so a mistyped `--out` cannot delete unrelated data.
    let replaceable = if out_path.is_dir() {
        owned_files_to_replace(&out_path, out_dir, force)?
    } else if out_path.exists() {
        return Err(format!(
            "output path '{out_dir}' exists and is not a directory"
        ));
    } else {
        Vec::new()
    };

    // Build in a sibling temp directory; rename into place only once every
    // file is written and verified, so a failure leaves nothing partial.
    let parent = out_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let temp_dir = parent.join(format!(".rxscan-bundle-tmp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir)
        .map_err(|error| format!("cannot create temp directory: {error}"))?;

    let mut evidence_jsonl = String::new();
    let mut evidence_ids = Vec::new();
    for item in &evidence_items {
        evidence_ids.push(item.id.to_string());
        let details: serde_json::Value = serde_json::from_str(&item.details_json)
            .unwrap_or_else(|_| serde_json::json!(item.details_json));
        let masked_details = mask_json(&details);
        let record = serde_json::json!({
            "id": item.id.to_string(),
            "scan_run": scrub_text(&item.scan_run),
            "source": scrub_text(&item.source),
            "asset_id": scrub_text(&item.asset_id),
            "confidence": item.confidence,
            "details": masked_details,
            "timestamp_ms": item.timestamp_ms,
        });
        let line = serde_json::to_string(&record)
            .map_err(|error| format!("cannot serialize evidence record: {error}"))?;
        evidence_jsonl.push_str(&line);
        evidence_jsonl.push('\n');
    }

    let bundle = serde_json::json!({
        "bundle_schema_version": 1,
        "tool": "rxscan",
        "tool_version": env!("CARGO_PKG_VERSION"),
        "created_at": created_iso,
        "created_at_epoch": created,
        "case_id": case_id,
        "operator": operator,
        "run_ids": run_ids,
        "scopes": scopes,
        "evidence_count": evidence_items.len(),
        "evidence_ids": evidence_ids,
        "note": "masked redacted copy of stored evidence; originals remain in the project database. RXScan does not claim legal admissibility, signing, or operator authentication."
    });
    let bundle_json = serde_json::to_string_pretty(&bundle)
        .map_err(|_| "cannot serialize bundle.json".to_string())?;

    write_verified(&temp_dir.join("evidence.jsonl"), evidence_jsonl.as_bytes())?;
    write_verified(&temp_dir.join("bundle.json"), bundle_json.as_bytes())?;

    let mut entries: Vec<(String, String)> = Vec::new();
    for name in MANIFEST_FILES {
        let hash = sha256_file(&temp_dir.join(name))
            .map_err(|error| format!("cannot hash {name}: {error}"))?;
        entries.push((hash, name.to_owned()));
    }
    entries.sort();
    let mut manifest = String::new();
    for (hash, name) in &entries {
        manifest.push_str(&format!("{hash}  {name}\n"));
    }
    write_verified(&temp_dir.join("manifest.txt"), manifest.as_bytes())?;

    // Bundle digest (sha256 of manifest.txt): record out-of-band to detect
    // deliberate rewriting of manifest.txt plus files.
    let digest = sha256_bytes(manifest.as_bytes());

    // manifest.txt is moved into place too, but it cannot list its own hash.
    entries.push((
        sha256_file(&temp_dir.join("manifest.txt"))
            .map_err(|error| format!("cannot hash manifest.txt: {error}"))?,
        "manifest.txt".to_owned(),
    ));
    entries.sort_by(|a, b| a.1.cmp(&b.1));

    if !out_path.is_dir() {
        std::fs::create_dir_all(&out_path)
            .map_err(|error| format!("cannot create output directory '{out_dir}': {error}"))?;
    }
    // Only files this command owns are removed; `owned_files_to_replace`
    // already refused the directory if anything else was present.
    for path in &replaceable {
        std::fs::remove_file(path)
            .map_err(|error| format!("cannot replace '{}': {error}", path.display()))?;
    }
    for (_, name) in &entries {
        std::fs::rename(temp_dir.join(name), out_path.join(name))
            .map_err(|error| format!("cannot move {name} into place: {error}"))?;
    }
    let _ = std::fs::remove_dir_all(&temp_dir);

    out_line!(
        "evidence bundle written to {} ({} evidence items, {} runs)",
        out_path.display(),
        evidence_items.len(),
        run_ids.len()
    );
    out_line!("bundle digest (sha256 of manifest.txt): {digest}");
    out_line!(
        "record this digest out-of-band (case file/ticket); `verify-bundle --expect-digest` \
         compares against it to detect deliberate tampering"
    );
    Ok(())
}

/// Decides which files an existing output directory may have replaced.
///
/// Returns the owned files present when writing may proceed. Refuses the
/// directory outright when it holds anything this command did not create —
/// unrelated files, subdirectories, or symlinks — because `--force` means
/// "replace the previous bundle", never "empty this directory". Refusing
/// keeps a mistyped `--out` from destroying data.
fn owned_files_to_replace(dir: &Path, out_dir: &str, force: bool) -> Result<Vec<PathBuf>, String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|error| format!("cannot read output directory '{out_dir}': {error}"))?;
    let mut owned = Vec::new();
    let mut foreign: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read entry in '{out_dir}': {error}"))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot stat '{}': {error}", path.display()))?;
        // Only a regular file with one of our own names is replaceable. A
        // directory or symlink that borrows a bundle name is still refused,
        // so nothing is ever removed recursively or through a link.
        if OWNED_FILES.contains(&name.as_str()) && meta.file_type().is_file() {
            owned.push(path);
        } else {
            let kind = if meta.file_type().is_dir() {
                "subdirectory"
            } else {
                "entry"
            };
            foreign.push(format!("{kind} '{name}'"));
        }
    }
    if !foreign.is_empty() {
        foreign.sort();
        return Err(format!(
            "output directory '{out_dir}' holds {} this bundle does not own; \
             point --out at a directory used only for bundles, or move them first",
            foreign.join(", ")
        ));
    }
    if !owned.is_empty() && !force {
        return Err(format!(
            "output directory '{out_dir}' already holds a bundle; \
             use --force to replace it"
        ));
    }
    Ok(owned)
}

/// Write `contents` to `path` and re-read to verify, so a silent write
/// failure cannot produce a partial bundle.
fn write_verified(path: &Path, contents: &[u8]) -> Result<(), String> {
    std::fs::write(path, contents)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    let back = std::fs::read(path)
        .map_err(|error| format!("cannot verify write of {}: {error}", path.display()))?;
    if back != contents {
        return Err(format!("write verification failed for {}", path.display()));
    }
    Ok(())
}

pub fn run_verify_bundle(args: &[String]) {
    let usage = "rxscan verify-bundle <path> [--expect-digest <hex>]";
    if args
        .get(2)
        .map(String::as_str)
        .is_some_and(|s| s == "--help" || s == "-h")
    {
        out_line!("{usage}");
        return;
    }
    let mut iter = args[2..].iter().peekable();
    let mut bundle_path: Option<&str> = None;
    let mut expect_digest: Option<&str> = None;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--expect-digest" => match iter.next() {
                Some(v) => expect_digest = Some(v),
                None => {
                    err_out!("rxscan verify-bundle: missing value for --expect-digest ({usage})");
                    std::process::exit(2);
                }
            },
            other if bundle_path.is_none() => bundle_path = Some(other),
            _ => {
                err_out!("rxscan verify-bundle: unexpected argument '{arg}' ({usage})");
                std::process::exit(2);
            }
        }
    }
    let bundle_path = match bundle_path {
        Some(p) => p,
        None => {
            err_out!("rxscan verify-bundle: missing <path> ({usage})");
            std::process::exit(2);
        }
    };
    if let Err(error) = run_verify_bundle_inner(bundle_path, expect_digest) {
        err_out!("rxscan verify-bundle: {error}");
        std::process::exit(1);
    }
}

/// Recomputes every hash in manifest.txt and fails on any mismatch, missing
/// file, extra file, subdirectory, or symlink inside the bundle. Also checks
/// bundle.json against evidence.jsonl (evidence_count and evidence ids) and,
/// when `--expect-digest` is given, the sha256 of manifest.txt.
fn run_verify_bundle_inner(bundle_path: &str, expect_digest: Option<&str>) -> Result<(), String> {
    use std::collections::BTreeSet;

    let bundle_path = PathBuf::from(bundle_path);
    let manifest_path = bundle_path.join("manifest.txt");
    let manifest = std::fs::read_to_string(&manifest_path)
        .map_err(|_| format!("manifest.txt missing in {bundle_path:?}"))?;

    let mut expected: Vec<(String, String)> = Vec::new();
    for (lineno, line) in manifest.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let hash = parts.next().unwrap_or("").to_owned();
        let name = parts.next().unwrap_or("").trim().to_owned();
        if hash.is_empty() || name.is_empty() {
            return Err(format!("malformed manifest line {lineno}: {line}"));
        }
        if hash.len() != 64 || hash.as_bytes().iter().any(|b| !b.is_ascii_hexdigit()) {
            return Err(format!("malformed manifest hash on line {lineno}: {hash}"));
        }
        // Without this, a rewritten manifest could name `../outside.txt` or
        // `/etc/passwd` and verification would hash files outside the bundle.
        if !MANIFEST_FILES.contains(&name.as_str()) {
            return Err(format!(
                "manifest line {lineno} names '{name}', which is not a bundle file"
            ));
        }
        expected.push((hash, name));
    }

    // Reject subdirectories and symlinks; never follow symlinks.
    let mut actual: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&bundle_path)
        .map_err(|_| format!("cannot read bundle directory {bundle_path:?}"))?
    {
        let entry = entry.map_err(|_| "cannot read bundle directory entry".to_string())?;
        let meta = std::fs::symlink_metadata(entry.path()).map_err(|_| {
            format!(
                "cannot stat bundle entry '{}'",
                entry.file_name().to_string_lossy()
            )
        })?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "bundle contains symlink '{}'; refused",
                entry.file_name().to_string_lossy()
            ));
        }
        if meta.file_type().is_dir() {
            return Err(format!(
                "bundle contains subdirectory '{}'; refused",
                entry.file_name().to_string_lossy()
            ));
        }
        if !meta.file_type().is_file() {
            return Err(format!(
                "bundle entry '{}' is not a regular file; refused",
                entry.file_name().to_string_lossy()
            ));
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name != "manifest.txt" {
            actual.push(name);
        }
    }
    actual.sort();

    let expected_names: BTreeSet<&str> = expected.iter().map(|(_, n)| n.as_str()).collect();
    for (hash, name) in &expected {
        let p = bundle_path.join(name);
        let data = match std::fs::read(&p) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(format!("missing file '{name}'"));
            }
            Err(error) => return Err(format!("cannot read file '{name}': {error}")),
        };
        if sha256_bytes(&data) != *hash {
            return Err(format!("hash mismatch for '{name}'"));
        }
    }
    for name in &actual {
        if !expected_names.contains(name.as_str()) {
            return Err(format!("extra file '{name}'"));
        }
    }

    // bundle.json must agree with evidence.jsonl.
    let bundle_text = std::fs::read_to_string(bundle_path.join("bundle.json"))
        .map_err(|_| "bundle.json missing or unreadable")?;
    let bundle: serde_json::Value = serde_json::from_str(&bundle_text)
        .map_err(|_| "bundle.json is not valid JSON".to_string())?;
    let evidence_count = bundle
        .get("evidence_count")
        .and_then(|v| v.as_u64())
        .ok_or("bundle.json lacks evidence_count")?;
    let evidence_ids: Vec<String> = bundle
        .get("evidence_ids")
        .and_then(|v| v.as_array())
        .ok_or("bundle.json lacks evidence_ids")?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let evidence_text = std::fs::read_to_string(bundle_path.join("evidence.jsonl"))
        .map_err(|_| "evidence.jsonl missing or unreadable")?;
    let lines: Vec<&str> = evidence_text.lines().filter(|l| !l.is_empty()).collect();
    if lines.len() != evidence_count as usize {
        return Err(format!(
            "evidence_count {evidence_count} does not match evidence.jsonl line count {}",
            lines.len()
        ));
    }
    let mut ids = Vec::new();
    for line in &lines {
        let record: serde_json::Value = serde_json::from_str(line)
            .map_err(|_| "evidence.jsonl line is not valid JSON".to_string())?;
        ids.push(
            record
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or("evidence record lacks id")?
                .to_string(),
        );
    }
    let expected_set: BTreeSet<&str> = evidence_ids.iter().map(|s| s.as_str()).collect();
    let actual_set: BTreeSet<&str> = ids.iter().map(|s| s.as_str()).collect();
    if expected_set != actual_set {
        return Err("evidence ids in bundle.json do not match evidence.jsonl".to_string());
    }

    if let Some(expected_digest) = expect_digest {
        let manifest_bytes =
            std::fs::read(&manifest_path).map_err(|_| "manifest.txt missing or unreadable")?;
        let actual = sha256_bytes(&manifest_bytes);
        if actual != expected_digest {
            return Err(format!(
                "bundle digest mismatch: expected {expected_digest}, got {actual}"
            ));
        }
    }

    out_line!("verify-bundle: {} file(s) verified OK", expected.len());
    Ok(())
}

pub(crate) fn format_utc(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let rem = epoch_secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u64;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u64;
    let year = year + i64::from(month <= 2);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        month,
        day,
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let data = std::fs::read(path)?;
    Ok(sha256_bytes(&data))
}

fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::format_utc;

    #[test]
    fn format_utc_covers_epoch_leap_day_year_end_and_past_2038() {
        let cases = [
            (0u64, "1970-01-01T00:00:00Z"),
            (1_709_164_800, "2024-02-29T00:00:00Z"),
            (1_735_689_599, "2024-12-31T23:59:59Z"),
            (2_177_452_800, "2039-01-01T00:00:00Z"),
            (1_792_243_740, "2026-10-17T13:29:00Z"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                format_utc(input),
                expected,
                "format_utc({input}) should be {expected}"
            );
        }
    }
}
