//! Scheduled monitoring runs (Phase 6): re-scan, diff, alert.
//!
//! Each iteration runs a real scan through the same [`crate::cli::Cli`]
//! parsing and [`crate::run::execute`] path as a manual run, so scope
//! gates (seed exclusion), budgets, and deadlines apply identically —
//! there is no privileged monitor path. The fresh checkpoint is diffed
//! against the previous one with [`crate::diff::diff_checkpoints`]; only
//! threshold-meeting *confirmed* changes alert (inconclusive records
//! never alert). Sinks: console, append-only JSONL file, webhook POST
//! with a secret-masked payload.
//!
//! The first iteration establishes the baseline and never alerts.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::diff::{DiffOptions, DiffSummary};
use crate::monitoring::{AlertThresholds, meaningful_changes};

/// Maximum scheduled iterations per invocation (bounded unattended work).
pub const MAX_MONITOR_REPEAT: usize = 10_000;
/// Maximum seconds between iterations.
pub const MAX_MONITOR_INTERVAL_SECS: u64 = 86_400;
/// Webhook POST timeout.
pub const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct MonitorConfig {
    pub targets: Vec<String>,
    pub scope: Vec<String>,
    pub exclude: Vec<String>,
    pub ports: Option<String>,
    pub all_ports: bool,
    pub level: Option<u8>,
    pub goal: Option<String>,
    pub max_tasks: Option<u64>,
    pub max_hosts: Option<u64>,
    pub max_concurrency: Option<u64>,
    pub deadline_secs: Option<u64>,
    pub state_dir: PathBuf,
    pub interval_secs: u64,
    pub repeat: usize,
    pub thresholds: AlertThresholds,
    pub alert_file: Option<PathBuf>,
    pub webhook_url: Option<String>,
}

#[derive(Debug, Clone)]
pub enum IterationOutcome {
    BaselineEstablished { scan: String },
    NoChange { scan: String },
    Alerted { alert: MonitorAlert },
    ScanFailed { detail: String },
}

#[derive(Debug, Clone)]
pub struct MonitorAlert {
    pub scan_id: String,
    pub previous_scan_id: String,
    pub reasons: Vec<String>,
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    pub inconclusive: usize,
    pub at_unix: u64,
}

#[derive(Debug)]
pub enum MonitorError {
    Usage(String),
    Refused(String),
    Failed(String),
}

impl std::fmt::Display for MonitorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(detail) => write!(f, "usage: {detail}"),
            Self::Refused(detail) => write!(f, "refused: {detail}"),
            Self::Failed(detail) => write!(f, "failed: {detail}"),
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Build the scan CLI exactly as a manual invocation (same parser, same
/// validation, same scope gates). Any out-of-scope target fails here,
/// before any network activity — identical to manual runs.
pub fn build_scan_cli(
    config: &MonitorConfig,
    checkpoint: &Path,
) -> Result<crate::cli::Cli, MonitorError> {
    use clap::Parser as _;
    let mut argv: Vec<String> = vec!["rxscan".to_owned()];
    if config.targets.is_empty() {
        return Err(MonitorError::Usage(
            "at least one target is required".to_owned(),
        ));
    }
    argv.extend(config.targets.iter().cloned());
    for scope in &config.scope {
        argv.push("--scope".to_owned());
        argv.push(scope.clone());
    }
    for exclude in &config.exclude {
        argv.push("--exclude".to_owned());
        argv.push(exclude.clone());
    }
    if config.all_ports {
        argv.push("--all-ports".to_owned());
    } else if let Some(ports) = &config.ports {
        argv.push("--ports".to_owned());
        argv.push(ports.clone());
    }
    if let Some(level) = config.level {
        argv.push("--level".to_owned());
        argv.push(level.to_string());
    }
    if let Some(goal) = &config.goal {
        argv.push("--goal".to_owned());
        argv.push(goal.clone());
    }
    if let Some(max_tasks) = config.max_tasks {
        argv.push("--max-tasks".to_owned());
        argv.push(max_tasks.to_string());
    }
    if let Some(max_hosts) = config.max_hosts {
        argv.push("--max-hosts".to_owned());
        argv.push(max_hosts.to_string());
    }
    if let Some(max_concurrency) = config.max_concurrency {
        argv.push("--max-concurrency".to_owned());
        argv.push(max_concurrency.to_string());
    }
    if let Some(deadline) = config.deadline_secs {
        argv.push("--max-execution-time".to_owned());
        argv.push(format!("{deadline}s"));
    }
    argv.push("--checkpoint".to_owned());
    argv.push(checkpoint.display().to_string());
    crate::cli::Cli::try_parse_from(argv).map_err(|error| MonitorError::Usage(error.to_string()))
}

/// Validate a webhook URL (explicit opt-in; http/https only).
pub fn validate_webhook(url: &str) -> Result<(), MonitorError> {
    let parsed = url::Url::parse(url)
        .map_err(|_| MonitorError::Usage("webhook must be a valid URL".to_owned()))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(MonitorError::Usage(
            "webhook must use http or https".to_owned(),
        ));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(MonitorError::Usage("webhook needs a host".to_owned()));
    }
    Ok(())
}

/// Masked webhook payload (secret-safe by construction: every free
/// string passes through the display masker).
pub fn webhook_payload(alert: &MonitorAlert) -> serde_json::Value {
    let raw = serde_json::json!({
        "tool": "rxscan",
        "event": "monitor_alert",
        "scan_id": alert.scan_id,
        "previous_scan_id": alert.previous_scan_id,
        "reasons": alert.reasons,
        "added": alert.added,
        "removed_confirmed": alert.removed,
        "changed": alert.changed,
        "inconclusive_not_covered": alert.inconclusive,
        "observed_at": alert.at_unix,
        "network_requests": 0,
    });
    crate::exposure::mask_json(&raw)
}

/// POST the masked payload (bounded timeout). Network errors are
/// reported, never panicked on.
pub fn post_webhook(url: &str, payload: &serde_json::Value) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(WEBHOOK_TIMEOUT)
        .no_proxy()
        .build()
        .map_err(|error| error.to_string())?;
    let body = serde_json::to_string(payload).map_err(|error| error.to_string())?;
    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .map_err(|error| error.to_string())?;
    if !(200..300).contains(&response.status().as_u16()) {
        return Err(format!("webhook HTTP {}", response.status()));
    }
    Ok(())
}

/// Human console line for an alert (masked).
pub fn format_alert_console(alert: &MonitorAlert) -> String {
    use crate::exposure::scrub_text;
    format!(
        "RXScan monitor ALERT scan={} previous={} added={} removed_confirmed={} changed={} inconclusive={} network_requests=0\n  {}",
        scrub_text(&alert.scan_id),
        scrub_text(&alert.previous_scan_id),
        alert.added,
        alert.removed,
        alert.changed,
        alert.inconclusive,
        alert
            .reasons
            .iter()
            .map(|reason| scrub_text(reason))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

/// Append one masked JSONL alert record to a file.
pub fn append_alert_file(path: &Path, alert: &MonitorAlert) -> Result<(), String> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("could not open alert file: {error}"))?;
    serde_json::to_writer(&mut file, &webhook_payload(alert)).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    Ok(())
}

fn summarize(summary: &DiffSummary) -> (usize, usize, usize, usize) {
    let added = summary.assets_added + summary.relationships_added + summary.findings_added;
    let removed = summary.assets_removed_confirmed
        + summary.relationships_removed_confirmed
        + summary.findings_removed_confirmed;
    let changed = summary.assets_modified + summary.findings_modified;
    let inconclusive = summary.assets_missing_inconclusive
        + summary.relationships_missing_inconclusive
        + summary.findings_missing_inconclusive;
    (added, removed, changed, inconclusive)
}

/// Run one scheduled iteration: scan → checkpoint → diff → thresholds →
/// sinks. Returns the outcome (alerts are emitted to sinks inside).
pub fn run_iteration(
    config: &MonitorConfig,
    index: usize,
    previous: Option<&Path>,
    cancelled: &AtomicBool,
) -> Result<(IterationOutcome, PathBuf), MonitorError> {
    if cancelled.load(Ordering::Acquire) {
        return Err(MonitorError::Failed("cancelled".to_owned()));
    }
    std::fs::create_dir_all(&config.state_dir)
        .map_err(|error| MonitorError::Failed(format!("state dir: {error}")))?;
    let checkpoint = config.state_dir.join(format!("scan-{index}.rxscan"));
    let cli = build_scan_cli(config, &checkpoint)?;
    // Same execution path as a manual run (scope gates, budgets).
    let report = crate::run::execute(cli).map_err(|error| {
        if cancelled.load(Ordering::Acquire) {
            MonitorError::Failed("cancelled".to_owned())
        } else {
            MonitorError::Failed(error.to_string())
        }
    })?;
    let _ = report;
    let Some(previous) = previous else {
        return Ok((
            IterationOutcome::BaselineEstablished {
                scan: checkpoint.display().to_string(),
            },
            checkpoint,
        ));
    };
    let (diff_report, _, _, _) =
        crate::diff::diff_checkpoints(previous, &checkpoint, DiffOptions::default())
            .map_err(|error| MonitorError::Failed(format!("diff failed: {error}")))?;
    let reasons = meaningful_changes(&diff_report.summary, &config.thresholds);
    if reasons.is_empty() {
        return Ok((
            IterationOutcome::NoChange {
                scan: checkpoint.display().to_string(),
            },
            checkpoint,
        ));
    }
    let (added, removed, changed, inconclusive) = summarize(&diff_report.summary);
    let alert = MonitorAlert {
        scan_id: diff_report.current_scan_id.0.clone(),
        previous_scan_id: diff_report.baseline_scan_id.0.clone(),
        reasons,
        added,
        removed,
        changed,
        inconclusive,
        at_unix: unix_now(),
    };
    if let Some(path) = &config.alert_file {
        append_alert_file(path, &alert).map_err(MonitorError::Failed)?;
    }
    if let Some(url) = &config.webhook_url {
        post_webhook(url, &webhook_payload(&alert)).map_err(MonitorError::Failed)?;
    }
    Ok((IterationOutcome::Alerted { alert }, checkpoint))
}

/// Run the schedule: `repeat` iterations (≥1) spaced by `interval_secs`.
/// Sleeps in 1 s slices so cancellation lands promptly.
pub fn run_schedule(
    config: &MonitorConfig,
    cancelled: &AtomicBool,
) -> Result<Vec<IterationOutcome>, MonitorError> {
    if config.repeat == 0 || config.repeat > MAX_MONITOR_REPEAT {
        return Err(MonitorError::Usage(format!(
            "repeat must be 1..={MAX_MONITOR_REPEAT}"
        )));
    }
    if config.interval_secs > MAX_MONITOR_INTERVAL_SECS {
        return Err(MonitorError::Usage(format!(
            "interval must be 0..={MAX_MONITOR_INTERVAL_SECS}s"
        )));
    }
    if let Some(url) = &config.webhook_url {
        validate_webhook(url)?;
    }
    // Resume: the newest existing checkpoint becomes the baseline so a
    // restarted schedule never re-alerts on old history.
    let mut previous: Option<PathBuf> = newest_checkpoint(&config.state_dir);
    let mut outcomes = Vec::new();
    // Index continues past existing checkpoints (never overwrites).
    for index in (next_index(&config.state_dir)..).take(config.repeat) {
        if cancelled.load(Ordering::Acquire) {
            break;
        }
        match run_iteration(config, index, previous.as_deref(), cancelled) {
            Ok((outcome, checkpoint)) => {
                previous = Some(checkpoint);
                outcomes.push(outcome);
            }
            Err(MonitorError::Failed(detail)) if cancelled.load(Ordering::Acquire) => {
                outcomes.push(IterationOutcome::ScanFailed { detail });
                break;
            }
            Err(error) => return Err(error),
        }
        if outcomes.len() >= config.repeat {
            break;
        }
        sleep_interval(config.interval_secs, cancelled);
    }
    Ok(outcomes)
}

fn newest_checkpoint(dir: &Path) -> Option<PathBuf> {
    let mut candidates: Vec<(usize, PathBuf)> = Vec::new();
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name()?.to_str()?;
        if let Some(index) = name
            .strip_prefix("scan-")
            .and_then(|rest| rest.strip_suffix(".rxscan"))
        {
            if let Ok(index) = index.parse::<usize>() {
                candidates.push((index, path));
            }
        }
    }
    candidates.sort();
    candidates.pop().map(|(_, path)| path)
}

fn next_index(dir: &Path) -> usize {
    let mut max: Option<usize> = None;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                if let Some(index) = name
                    .strip_prefix("scan-")
                    .and_then(|rest| rest.strip_suffix(".rxscan"))
                    .and_then(|index| index.parse::<usize>().ok())
                {
                    max = Some(max.map_or(index, |m: usize| m.max(index)));
                }
            }
        }
    }
    max.map_or(0, |m| m + 1)
}

fn sleep_interval(secs: u64, cancelled: &AtomicBool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if cancelled.load(Ordering::Acquire) {
            break;
        }
        std::thread::sleep(
            Duration::from_secs(1).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(targets: Vec<&str>) -> MonitorConfig {
        MonitorConfig {
            targets: targets.into_iter().map(str::to_owned).collect(),
            scope: vec![],
            exclude: vec![],
            ports: Some("22,80,443".to_owned()),
            all_ports: false,
            level: Some(1),
            goal: Some("recon".to_owned()),
            max_tasks: Some(50),
            max_hosts: Some(8),
            max_concurrency: Some(4),
            deadline_secs: Some(30),
            state_dir: std::env::temp_dir().join("rxscan-monitor-test"),
            interval_secs: 0,
            repeat: 1,
            thresholds: AlertThresholds::default(),
            alert_file: None,
            webhook_url: None,
        }
    }

    #[test]
    fn scan_cli_builds_with_budgets() {
        let config = config(vec!["192.0.2.10"]);
        let cli = build_scan_cli(&config, Path::new("/tmp/scan-0.rxscan")).unwrap();
        assert_eq!(cli.max_tasks, Some(50));
        assert_eq!(cli.level, Some(1));
        assert_eq!(cli.checkpoint, Some(PathBuf::from("/tmp/scan-0.rxscan")));
    }

    #[test]
    fn out_of_scope_targets_refuse_before_network() {
        // Same gate as manual runs: excluding the seed removes it from the
        // effective scope, so planning fails and no scan ever starts.
        let mut cfg = config(vec!["192.0.2.10"]);
        cfg.exclude = vec!["192.0.2.10".to_owned()];
        let cli = build_scan_cli(&cfg, Path::new("/tmp/scan-0.rxscan")).unwrap();
        let plan = crate::plan::ScanPlan::compile(cli);
        assert!(plan.is_err(), "out-of-scope seed must be refused");
    }

    #[test]
    fn webhook_payload_is_masked() {
        let alert = MonitorAlert {
            scan_id: "scan-2".to_owned(),
            previous_scan_id: "scan-1".to_owned(),
            reasons: vec!["login token=FAKE-MON-1 for admin".to_owned()],
            added: 1,
            removed: 0,
            changed: 0,
            inconclusive: 0,
            at_unix: 1_700_000_000,
        };
        let payload = webhook_payload(&alert);
        let flat = payload.to_string();
        assert!(!flat.contains("FAKE-MON-1"));
        assert!(flat.contains("\"added\":1"));
        let console = format_alert_console(&alert);
        assert!(!console.contains("FAKE-MON-1"));
    }

    #[test]
    fn webhook_urls_validated() {
        assert!(validate_webhook("https://example.test/hook").is_ok());
        assert!(validate_webhook("http://127.0.0.1:9/hook").is_ok());
        assert!(validate_webhook("ftp://example.test/hook").is_err());
        assert!(validate_webhook("not a url").is_err());
    }

    #[test]
    fn schedule_bounds_checked() {
        let mut cfg = config(vec!["192.0.2.10"]);
        cfg.repeat = 0;
        let cancelled = AtomicBool::new(false);
        assert!(run_schedule(&cfg, &cancelled).is_err());
        cfg.repeat = 1;
        cfg.interval_secs = MAX_MONITOR_INTERVAL_SECS + 1;
        assert!(run_schedule(&cfg, &cancelled).is_err());
    }
}
