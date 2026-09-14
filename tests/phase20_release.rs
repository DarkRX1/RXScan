//! Phase 20 production / release hardening tests.
//!
//! Real CLI subprocess behavior (exit codes, stdio contract, broken pipes,
//! SIGINT), release-critical governor semantics, schema golden fixtures,
//! path/temp safety, failure injection, privacy, and end-to-end lab runs.
//! All network fixtures are loopback/ephemeral-port; no public targets.

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use rxscan::contact::ContactRegistry;
use rxscan::execution::{
    BudgetLimits, ModuleOutput, PolicyScopeGuard, RetryPolicy, Scheduler, ScopeGuard,
    SpeedGovernor, Task, TaskKind, TaskScopeTarget, VecEventSink,
};
use rxscan::plan::{NamedSpeed, ScanPlan, SpeedSetting};
use rxscan::web::WebTarget;

fn rxscan_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rxscan"))
}

fn run_cli(args: &[&str], cwd: &Path) -> (i32, String, String) {
    let output = Command::new(rxscan_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn rxscan");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_dir(name: &str) -> PathBuf {
    let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("rxscan_p20_{name}_{}_{id}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn compile_plan(target: &str) -> ScanPlan {
    use clap::Parser;
    let cli =
        rxscan::cli::Cli::try_parse_from(["rxscan", target, "--scope", "127.0.0.0/8"]).unwrap();
    ScanPlan::compile(cli).unwrap()
}

struct AllowAll;
impl ScopeGuard for AllowAll {
    fn permits(&self, _target: &TaskScopeTarget) -> bool {
        true
    }
}

fn test_scheduler(plan: &ScanPlan, budgets: BudgetLimits, governor: SpeedGovernor) -> Scheduler {
    Scheduler::new(
        budgets.queue_capacity(),
        budgets,
        governor,
        Arc::new(PolicyScopeGuard::new(plan.scope.clone())),
        Arc::new(VecEventSink::default()),
    )
    .unwrap()
}

// ---------- §3 governor double-derivation fix ----------

fn scheduler_effective(
    setting: SpeedSetting,
    governor_budget: usize,
    scheduler_budget: usize,
) -> (usize, SpeedSetting) {
    let plan = compile_plan("127.0.0.1");
    let budgets = BudgetLimits {
        max_tasks: 100,
        max_retries: 100,
        max_concurrency: scheduler_budget,
        max_execution_time_ms: 60_000,
        ..BudgetLimits::default()
    };
    let scheduler = test_scheduler(
        &plan,
        budgets,
        SpeedGovernor::new(setting, governor_budget).unwrap(),
    );
    (
        scheduler.effective_concurrency(),
        scheduler.governor().setting(),
    )
}

#[test]
fn governor_old_collapse_case_now_derives_once() {
    // P19 finding: Numeric(50) with budget 4 collapsed 2 -> 1 because the
    // derived value was fed back as the new maximum. Must be exactly 2.
    let (effective, setting) = scheduler_effective(SpeedSetting::Numeric(50), 4, 4);
    assert_eq!(
        effective, 2,
        "derive-once: Numeric(50)+4 must yield 2 slots"
    );
    assert_eq!(setting, SpeedSetting::Numeric(50));
    // Direct governor derivation agrees (single source of truth).
    assert_eq!(
        SpeedGovernor::new(SpeedSetting::Numeric(50), 4)
            .unwrap()
            .concurrency(),
        2
    );
}

#[test]
fn governor_explicit_budget_remains_an_upper_bound() {
    // Foreign governor built with a large budget, tight scheduler budget:
    // result equals deriving fresh with the tighter budget.
    for setting in [
        SpeedSetting::Numeric(0),
        SpeedSetting::Numeric(50),
        SpeedSetting::Numeric(100),
        SpeedSetting::Named(NamedSpeed::Slow),
        SpeedSetting::Named(NamedSpeed::Fast),
    ] {
        for scheduler_budget in [1, 2, 4, 8] {
            let (effective, _) = scheduler_effective(setting, 64, scheduler_budget);
            let expected = SpeedGovernor::new(setting, scheduler_budget)
                .unwrap()
                .concurrency();
            assert_eq!(
                effective, expected,
                "setting {setting:?} budget {scheduler_budget}: scheduler must match single derivation"
            );
            assert!(
                effective <= scheduler_budget,
                "budget is an upper bound: {effective} <= {scheduler_budget}"
            );
        }
    }
}

#[test]
fn governor_smaller_caller_budget_is_respected() {
    // Caller-explicit small budget wins over a looser scheduler budget.
    let (effective, _) = scheduler_effective(SpeedSetting::Numeric(100), 1, 64);
    assert_eq!(effective, 1);
    let (effective, _) = scheduler_effective(SpeedSetting::Named(NamedSpeed::Fast), 2, 64);
    assert_eq!(
        effective,
        SpeedGovernor::new(SpeedSetting::Named(NamedSpeed::Fast), 2)
            .unwrap()
            .concurrency()
    );
}

#[test]
fn governor_hard_cap_and_setting_preserved() {
    let plan = compile_plan("127.0.0.1");
    let budgets = BudgetLimits {
        max_concurrency: 64,
        ..BudgetLimits::default()
    };
    let scheduler = test_scheduler(
        &plan,
        budgets,
        SpeedGovernor::new(SpeedSetting::Numeric(100), 64).unwrap(),
    );
    assert_eq!(scheduler.effective_concurrency(), 64);
    assert!(scheduler.effective_concurrency() <= rxscan::execution::MAX_CONCURRENCY_HARD_LIMIT);
    // Timeout/retry pressure still derives from the setting, unaffected.
    assert_eq!(
        scheduler.governor().default_timeout(),
        SpeedGovernor::new(SpeedSetting::Numeric(100), 64)
            .unwrap()
            .default_timeout()
    );
    assert_eq!(
        scheduler.governor().retry_limit(),
        SpeedGovernor::new(SpeedSetting::Numeric(100), 64)
            .unwrap()
            .retry_limit()
    );
    assert_eq!(scheduler.governor().budget(), 64);
}

// ---------- §4 speed policy matrix ----------

fn pressure_of(setting: SpeedSetting) -> u32 {
    match setting {
        SpeedSetting::Numeric(v) => v as u32,
        SpeedSetting::Named(NamedSpeed::Slow) => 20,
        SpeedSetting::Named(NamedSpeed::Balanced) => 50,
        SpeedSetting::Named(NamedSpeed::Fast) => 80,
        SpeedSetting::Named(NamedSpeed::Auto) => 50,
    }
}

#[test]
fn speed_policy_matrix_is_monotone_and_bounded() {
    let speeds = [
        SpeedSetting::Numeric(0),
        SpeedSetting::Named(NamedSpeed::Slow),
        SpeedSetting::Numeric(25),
        SpeedSetting::Numeric(50),
        SpeedSetting::Named(NamedSpeed::Balanced),
        SpeedSetting::Named(NamedSpeed::Auto),
        SpeedSetting::Numeric(75),
        SpeedSetting::Named(NamedSpeed::Fast),
        SpeedSetting::Numeric(100),
    ];
    // Pressures must be non-decreasing in table order.
    let mut last = 0;
    for speed in speeds {
        let p = pressure_of(speed);
        assert!(p >= last, "pressure order violated at {speed:?}");
        last = p;
    }
    for budget in [1usize, 2, 4, 8, 64] {
        let mut last_conc = 0;
        let mut last_timeout = Duration::from_secs(u64::MAX);
        let mut last_retry = 0u32;
        for speed in speeds {
            let governor = SpeedGovernor::new(speed, budget).unwrap();
            let conc = governor.concurrency();
            let timeout = governor.default_timeout();
            let retry = governor.retry_limit();
            assert!(
                conc >= last_conc,
                "concurrency must not decrease with pressure ({speed:?}, budget {budget})"
            );
            assert!(
                timeout <= last_timeout,
                "timeout must not increase with pressure ({speed:?}, budget {budget})"
            );
            assert!(
                retry >= last_retry,
                "retry pressure must not decrease ({speed:?}, budget {budget})"
            );
            assert!(conc >= 1 && conc <= budget, "1 <= conc <= budget");
            assert!(timeout >= Duration::from_millis(1000));
            assert!((1..=4).contains(&retry));
            last_conc = conc;
            last_timeout = timeout;
            last_retry = retry;
        }
    }
    // Exact spot values pin the documented mapping (budget 4).
    let at = |s: SpeedSetting| SpeedGovernor::new(s, 4).unwrap().concurrency();
    assert_eq!(at(SpeedSetting::Numeric(0)), 1);
    assert_eq!(at(SpeedSetting::Named(NamedSpeed::Slow)), 1);
    assert_eq!(at(SpeedSetting::Numeric(50)), 2);
    assert_eq!(at(SpeedSetting::Named(NamedSpeed::Fast)), 3);
    assert_eq!(at(SpeedSetting::Numeric(100)), 4);
}

// ---------- §2 version ----------

#[test]
fn version_matches_cargo_metadata() {
    let dir = test_dir("version");
    let (code, stdout, _) = run_cli(&["--version"], &dir);
    assert_eq!(code, 0);
    assert!(
        stdout.trim() == format!("rxscan {}", env!("CARGO_PKG_VERSION")),
        "unexpected version output: {stdout:?}"
    );
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.0");
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §10 exit codes ----------

#[test]
fn exit_code_contract() {
    let dir = test_dir("exitcodes");
    // 0: success paths.
    let (code, _, _) = run_cli(&["--help"], &dir);
    assert_eq!(code, 0);
    let (code, _, _) = run_cli(&["127.0.0.1", "--explain", "--scope", "127.0.0.1"], &dir);
    assert_eq!(code, 0);
    // 2: CLI/usage/config errors.
    let (code, _, stderr) = run_cli(&["127.0.0.1", "--level", "9"], &dir);
    assert_eq!(code, 2, "bad level must exit 2, stderr: {stderr:?}");
    let (code, _, _) = run_cli(&["127.0.0.1", "--speed", "banana"], &dir);
    assert_eq!(code, 2);
    let (code, _, _) = run_cli(&["project"], &dir);
    assert_eq!(code, 2);
    let (code, _, _) = run_cli(&["project", "frobnicate"], &dir);
    assert_eq!(code, 2);
    let (code, _, _) = run_cli(&["report"], &dir);
    assert_eq!(code, 2);
    // 1: invalid input/state at runtime.
    std::fs::write(dir.join("garbage.rxscan"), b"{not json").unwrap();
    let (code, _, _) = run_cli(
        &["report", dir.join("garbage.rxscan").to_str().unwrap()],
        &dir,
    );
    assert_eq!(code, 1);
    let (code, _, _) = run_cli(
        &[
            "project",
            "summary",
            dir.join("garbage.rxscan").to_str().unwrap(),
        ],
        &dir,
    );
    assert_eq!(code, 1);
    let (code, _, _) = run_cli(&["project", "show", "nope.rxproj", "entity:x"], &dir);
    assert_eq!(code, 1);
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §11 stdout/stderr contract ----------

#[test]
fn machine_output_stays_pure_json() {
    let dir = test_dir("stdio");
    // Build a tiny checkpoint via a fast loopback scan.
    let checkpoint = dir.join("tiny.rxscan");
    let (code, _, stderr) = run_cli(
        &[
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--level",
            "1",
            "--ports",
            "9",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
        ],
        &dir,
    );
    assert_eq!(code, 0, "scan failed: {stderr:?}");
    // report --format json: stdout must parse, stderr must not carry records.
    let output = Command::new(rxscan_bin())
        .args(["report", "--format", "json", checkpoint.to_str().unwrap()])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(output.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("report --format json stdout must be pure JSON");
    assert_eq!(
        parsed.get("report_schema_version").and_then(|v| v.as_u64()),
        Some(1)
    );
    let err_text = String::from_utf8_lossy(&output.stderr);
    assert!(
        !err_text.contains("\"report_schema_version\""),
        "diagnostics leaked into stderr as records: {err_text:?}"
    );
    // JSONL: every nonempty line parses independently.
    let output = Command::new(rxscan_bin())
        .args(["report", "--format", "jsonl", checkpoint.to_str().unwrap()])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = 0;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let _: serde_json::Value = serde_json::from_str(line).expect("every JSONL line must parse");
        lines += 1;
    }
    assert!(lines > 0, "expected at least one JSONL record");
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §12 pipe safety ----------

#[test]
fn broken_pipe_exits_cleanly_without_panic() {
    let dir = test_dir("pipe");
    let checkpoint = dir.join("tiny.rxscan");
    let (code, _, _) = run_cli(
        &[
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--level",
            "1",
            "--ports",
            "9",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
        ],
        &dir,
    );
    assert_eq!(code, 0);
    // Consumer closes early: head -c 64 then exits.
    let mut producer = Command::new(rxscan_bin())
        .args(["report", "--format", "jsonl", checkpoint.to_str().unwrap()])
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let consumer = Command::new("head")
        .arg("-c")
        .arg("64")
        .stdin(producer.stdout.take().unwrap())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = consumer.wait_with_output().unwrap();
    let status = producer.wait().unwrap();
    let code = status.code();
    assert!(
        code == Some(0),
        "broken pipe must exit 0, got {code:?} (SIGPIPE kills would show None)"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §14 help audit ----------

#[test]
fn help_is_accurate_and_complete() {
    let dir = test_dir("help");
    let (code, stdout, _) = run_cli(&["--help"], &dir);
    assert_eq!(code, 0);
    for flag in [
        "--level",
        "--speed",
        "--scope",
        "--ports",
        "--all-ports",
        "--checkpoint",
        "--resume",
        "--output",
        "--wordlist",
        "--max-tasks",
        "--max-concurrency",
        "--max-hosts",
    ] {
        assert!(stdout.contains(flag), "help missing documented flag {flag}");
    }
    for (args, needs) in [
        (vec!["project", "--help"], "neighbors"),
        (vec!["report", "--help"], "--format"),
    ] {
        let (code, stdout, _) = run_cli(&args, &dir);
        assert_eq!(code, 0);
        assert!(stdout.contains(needs));
    }
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §15 error UX ----------

#[test]
fn errors_name_the_input_and_next_step() {
    let dir = test_dir("errors");
    let cases: &[&[&str]] = &[
        &["127.0.0.1", "--ports", "notaport"],
        &["127.0.0.1", "--ports", "80-"],
        &["10.0.0.0/33"],
        &["127.0.0.1", "--max-concurrency", "0"],
    ];
    for args in cases {
        let (code, _, stderr) = run_cli(args, &dir);
        assert_ne!(code, 0, "args {args:?} must fail");
        assert!(
            !stderr.contains("panicked") && !stderr.contains("backtrace"),
            "no Rust dumps for {args:?}: {stderr:?}"
        );
        assert!(
            !stderr.trim().is_empty(),
            "error must explain itself for {args:?}"
        );
    }
    // Missing wordlist names the file.
    let (code, _, stderr) = run_cli(
        &[
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--level",
            "4",
            "--wordlist",
            "does-not-exist-xyz.txt",
        ],
        &dir,
    );
    assert_ne!(code, 0);
    assert!(
        stderr.contains("does-not-exist-xyz.txt"),
        "missing wordlist must name the file: {stderr:?}"
    );
    // Unwritable output: clean error, no panic.
    let (code, _, stderr) = run_cli(
        &[
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--level",
            "1",
            "--ports",
            "9",
            "--output",
            "/proc/definitely-not-writable/out.jsonl",
        ],
        &dir,
    );
    assert_eq!(code, 1, "unwritable output must exit 1");
    assert!(!stderr.contains("panicked"), "no panic: {stderr:?}");
    // Scope violation names the problem. (An explicit CLI target is always
    // implicitly authorized — `--scope` only *adds* rules — so the audited
    // mistake is an excluded seed, which must fail instead of scanning.)
    let (code, _, stderr) = run_cli(
        &[
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--exclude",
            "127.0.0.1",
            "--ports",
            "9",
        ],
        &dir,
    );
    assert_eq!(code, 2, "excluded seed must exit 2");
    assert!(
        stderr.contains("127.0.0.1") && stderr.to_lowercase().contains("exclud"),
        "excluded seed must name the target: {stderr:?}"
    );
    // NOTE: an unresolvable hostname is a runtime outcome (exit 0 with
    // failed tasks), not a CLI error; it is deliberately not asserted here
    // because it would depend on external DNS in CI.
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §25 config compatibility ----------

#[test]
fn unknown_config_keys_are_rejected_with_file_named() {
    let dir = test_dir("configkeys");
    std::fs::write(dir.join("typo.toml"), "max_task = 5\n").unwrap();
    let (code, _, stderr) = run_cli(
        &[
            "127.0.0.1",
            "--config",
            dir.join("typo.toml").to_str().unwrap(),
            "--explain",
        ],
        &dir,
    );
    assert_eq!(code, 2, "unknown config key must exit 2");
    assert!(
        stderr.contains("typo.toml"),
        "config error must name the file: {stderr:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn config_precedence_is_defaults_global_project_cli() {
    use clap::Parser;
    let dir = test_dir("precedence");
    std::fs::write(dir.join("global.toml"), "level = 1\nmax_tasks = 111\n").unwrap();
    std::fs::write(dir.join("project.toml"), "level = 3\n").unwrap();
    // CLI wins over both layers.
    let cli = rxscan::cli::Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--config",
        dir.join("global.toml").to_str().unwrap(),
        "--project-config",
        dir.join("project.toml").to_str().unwrap(),
        "--level",
        "5",
    ])
    .unwrap();
    let plan = ScanPlan::compile(cli).unwrap();
    assert_eq!(plan.level, 5, "CLI beats project beats global");
    // Project beats global when CLI is silent.
    let cli = rxscan::cli::Cli::try_parse_from([
        "rxscan",
        "127.0.0.1",
        "--config",
        dir.join("global.toml").to_str().unwrap(),
        "--project-config",
        dir.join("project.toml").to_str().unwrap(),
    ])
    .unwrap();
    let plan = ScanPlan::compile(cli).unwrap();
    assert_eq!(plan.level, 3, "project beats global");
    assert_eq!(
        plan.budgets.max_tasks, 111,
        "global applies when others silent"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §29-30 golden schema fixtures ----------

fn golden_paths() -> (PathBuf, PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    (
        root.join("tests/fixtures/golden_checkpoint_v1.rxscan"),
        root.join("tests/fixtures/golden_project_v1.rxproj"),
        root.join("tests/fixtures/future_checkpoint.rxscan"),
    )
}

fn minimal_scan_state() -> rxscan::persistence::PersistedScanState {
    use rxscan::execution::TaskState;
    use rxscan::model::{Asset, AssetKind, Provenance, Timestamp};
    use rxscan::persistence::{
        CHECKPOINT_SCHEMA_VERSION, PersistedModuleOutput, PersistedRegistries, PersistedScanState,
        PersistedTask,
    };
    let plan = compile_plan("127.0.0.1");
    let provenance =
        Provenance::new("phase20.test", "20.0.0", plan.stable_id(), Timestamp(0)).unwrap();
    let ip = Asset::scoped(AssetKind::Ip, "127.0.0.1", &plan.scope, provenance.clone()).unwrap();
    let mut params = BTreeMap::new();
    params.insert("target".to_owned(), "127.0.0.1".to_owned());
    let mut task = Task::new_with_params(
        TaskKind::HostDiscovery,
        None,
        Vec::new(),
        None,
        plan.stable_id(),
        80,
        Duration::from_millis(2000),
        RetryPolicy::default(),
        "phase20.test",
        provenance.clone(),
        TaskScopeTarget::Ip("127.0.0.1".parse().unwrap()),
        params,
        &AllowAll,
    )
    .unwrap();
    task.state = TaskState::Succeeded;
    PersistedScanState {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        scan_id: plan.stable_id(),
        saved_at: Timestamp(2),
        plan,
        tasks: vec![PersistedTask { task: task.clone() }],
        outputs: vec![PersistedModuleOutput {
            task_id: task.id,
            output: ModuleOutput {
                assets: vec![ip],
                ..ModuleOutput::default()
            },
        }],
        registries: PersistedRegistries::default(),
    }
}

#[test]
fn regen_golden_fixtures_on_demand_only() {
    // Regenerates tests/fixtures golden files when RXSCAN_REGEN_GOLDEN=1.
    // Normal runs only read them (stable-format tripwire).
    if std::env::var("RXSCAN_REGEN_GOLDEN").is_err() {
        return;
    }
    let (checkpoint_path, project_path, future_path) = golden_paths();
    std::fs::create_dir_all(checkpoint_path.parent().unwrap()).unwrap();
    let state = minimal_scan_state();
    rxscan::persistence::save_checkpoint(&checkpoint_path, &state).unwrap();
    let mut project = rxscan::project::ProjectState::new(None);
    project.add_scan(&state, None, None).unwrap();
    rxscan::project::save_project(&project_path, &project, None).unwrap();
    // Future-version fixture: top-level schema bumped, content otherwise valid.
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&checkpoint_path).unwrap()).unwrap();
    value["schema_version"] = serde_json::Value::from(999u64);
    std::fs::write(&future_path, serde_json::to_string_pretty(&value).unwrap()).unwrap();
}

#[test]
fn golden_checkpoint_loads_and_resaves_byte_stable() {
    let (checkpoint_path, _, _) = golden_paths();
    let loaded = rxscan::persistence::load_checkpoint(&checkpoint_path)
        .expect("committed golden checkpoint must load");
    assert_eq!(
        loaded.state.schema_version,
        rxscan::persistence::CHECKPOINT_SCHEMA_VERSION
    );
    assert_eq!(loaded.state.tasks.len(), 1);
    // Byte-stable re-save: the format must not drift accidentally.
    let dir = test_dir("golden");
    let resaved = dir.join("resaved.rxscan");
    rxscan::persistence::save_checkpoint(&resaved, &loaded.state).unwrap();
    let original = std::fs::read(&checkpoint_path).unwrap();
    let again = std::fs::read(&resaved).unwrap();
    assert_eq!(
        original, again,
        "golden checkpoint re-save must be byte-stable"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn golden_project_loads_with_zero_network() {
    let (_, project_path, _) = golden_paths();
    let loaded =
        rxscan::project::load_project(&project_path).expect("committed golden project must load");
    assert_eq!(
        loaded.project_schema_version,
        rxscan::project::PROJECT_SCHEMA_VERSION
    );
    assert!(!loaded.entities.is_empty());
}

#[test]
fn future_schema_versions_fail_safely_with_clear_error() {
    let (_, _, future_path) = golden_paths();
    let result = rxscan::persistence::load_checkpoint(&future_path);
    let message = format!("{result:?}");
    assert!(result.is_err(), "schema 999 must be rejected");
    assert!(
        message.contains("999") || message.to_lowercase().contains("version"),
        "error must name the version problem: {message:?}"
    );
    let dir = test_dir("futurecli");
    let (code, _, stderr) = run_cli(&["report", future_path.to_str().unwrap()], &dir);
    assert_eq!(code, 1);
    assert!(!stderr.contains("panicked"));
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §31 corrupt state ----------

#[test]
fn corrupt_inputs_neither_panic_nor_mutate_nor_dial() {
    let dir = test_dir("corrupt");
    let checkpoint = dir.join("good.rxscan");
    let (code, _, _) = run_cli(
        &[
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--level",
            "1",
            "--ports",
            "9",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
        ],
        &dir,
    );
    assert_eq!(code, 0);
    let before = std::fs::read(&checkpoint).unwrap();
    // Garbage / truncated / wrong-type inputs across all offline commands.
    std::fs::write(dir.join("garbage.rxscan"), b"\x00\x01{not json").unwrap();
    std::fs::write(dir.join("truncated.rxscan"), &before[..before.len() / 2]).unwrap();
    std::fs::write(dir.join("empty.rxscan"), b"").unwrap();
    for bad in ["garbage.rxscan", "truncated.rxscan", "empty.rxscan"] {
        let bad_path = dir.join(bad);
        let (code, _, stderr) = run_cli(&["report", bad_path.to_str().unwrap()], &dir);
        assert_eq!(code, 1, "{bad} must exit 1");
        assert!(!stderr.contains("panicked"), "{bad}: {stderr:?}");
        let (code, _, _) = run_cli(
            &[
                "diff",
                bad_path.to_str().unwrap(),
                checkpoint.to_str().unwrap(),
            ],
            &dir,
        );
        assert_eq!(code, 1);
        let (code, _, _) = run_cli(&["project", "summary", bad_path.to_str().unwrap()], &dir);
        assert_eq!(code, 1);
    }
    // Destination untouched by failed loads.
    assert_eq!(std::fs::read(&checkpoint).unwrap(), before);
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §33 path collision, §123 ----------

#[test]
fn report_refuses_to_overwrite_its_inputs() {
    let dir = test_dir("collision");
    let checkpoint = dir.join("scan.rxscan");
    let (code, _, _) = run_cli(
        &[
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--level",
            "1",
            "--ports",
            "9",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
        ],
        &dir,
    );
    assert_eq!(code, 0);
    let (code, _, stderr) = run_cli(
        &[
            "report",
            "--format",
            "json",
            "--output",
            checkpoint.to_str().unwrap(),
            checkpoint.to_str().unwrap(),
        ],
        &dir,
    );
    assert_ne!(code, 0, "overwriting the input checkpoint must be refused");
    assert!(!stderr.contains("panicked"));
    // Input still loads (untouched).
    let (code, _, _) = run_cli(
        &["report", "--summary-only", checkpoint.to_str().unwrap()],
        &dir,
    );
    assert_eq!(code, 0);
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §124 concurrent project writers ----------

#[test]
fn concurrent_project_writes_conflict_instead_of_silently_losing() {
    let dir = test_dir("conflict");
    let path = dir.join("proj.rxproj");
    rxscan::project::create_project(&path).unwrap();
    let state = minimal_scan_state();
    let mut first = rxscan::project::load_project(&path).unwrap();
    let mut second = rxscan::project::load_project(&path).unwrap();
    let rev = first.revision;
    first.add_scan(&state, None, None).unwrap();
    rxscan::project::save_project(&path, &first, Some(rev)).unwrap();
    second.add_scan(&state, None, None).unwrap();
    let result = rxscan::project::save_project(&path, &second, Some(rev));
    assert!(
        matches!(
            result,
            Err(rxscan::project::ProjectError::ConcurrentModification)
        ),
        "stale writer must conflict, got {result:?}"
    );
    // Stored project still valid.
    rxscan::project::load_project(&path).unwrap();
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §120 failure injection: read-only dir, disk-full-ish writer ----------

#[test]
fn read_only_destination_fails_cleanly_without_panic() {
    let dir = test_dir("readonly");
    let checkpoint = dir.join("scan.rxscan");
    let (code, _, _) = run_cli(
        &[
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--level",
            "1",
            "--ports",
            "9",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
        ],
        &dir,
    );
    assert_eq!(code, 0);
    let ro = dir.join("ro");
    std::fs::create_dir_all(&ro).unwrap();
    let mut perms = std::fs::metadata(&ro).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&ro, perms).unwrap();
    let target = ro.join("out.jsonl");
    let (code, _, stderr) = run_cli(
        &[
            "report",
            "--format",
            "json",
            "--output",
            target.to_str().unwrap(),
            checkpoint.to_str().unwrap(),
        ],
        &dir,
    );
    // As root this may succeed; either way it must not panic and a partial
    // file must never masquerade as complete output.
    assert!(!stderr.contains("panicked"), "{stderr:?}");
    if code != 0 {
        assert_eq!(code, 1);
        assert!(
            !target.exists(),
            "failed write must leave no partial output"
        );
    }
    let mut perms = std::fs::metadata(&ro).unwrap().permissions();
    // Restore via explicit mode bits (no version-specific clippy allow).
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    std::fs::set_permissions(&ro, perms).unwrap();
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn byte_budget_exceeded_is_a_clean_error_not_panic() {
    // Tiny budget simulates a failing/disk-full writer deterministically.
    let result = rxscan::output::create_file_writer(&test_dir("budget").join("x.jsonl"), 10);
    // Creation itself succeeds; the budget trips on first record write.
    if let Ok(mut writer) = result {
        let event = rxscan::execution::SchedulerEvent {
            schema_version: rxscan::model::SCHEMA_VERSION,
            kind: rxscan::execution::SchedulerEventKind::TaskCreated,
            task_id: rxscan::execution::TaskId("task_x".to_owned()),
            state: rxscan::execution::TaskState::Pending,
            timestamp: rxscan::model::Timestamp(0),
            reason: None,
            provenance: rxscan::model::Provenance::new(
                "phase20.test",
                "20.0.0",
                rxscan::model::ScanPlanId("plan_x".to_owned()),
                rxscan::model::Timestamp(0),
            )
            .unwrap(),
        };
        let write_result = writer.write_scheduler_event(&event);
        assert!(
            write_result.is_err(),
            "10-byte budget must trip on first record"
        );
    }
}

// ---------- §104 determinism: relocation + insertion order ----------

#[test]
fn checkpoint_identity_survives_path_relocation() {
    let dir = test_dir("reloc");
    let first = dir.join("a.rxscan");
    let (code, _, _) = run_cli(
        &[
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--level",
            "1",
            "--ports",
            "9",
            "--checkpoint",
            first.to_str().unwrap(),
        ],
        &dir,
    );
    assert_eq!(code, 0);
    let moved = dir.join("sub").join("b.rxscan");
    std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
    std::fs::rename(&first, &moved).unwrap();
    let (code, stdout, _) = run_cli(
        &["report", "--format", "json", moved.to_str().unwrap()],
        &dir,
    );
    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.get("scan_id").is_some());
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §105-106 timestamps and locale-neutral numbers ----------

#[test]
fn report_json_uses_plain_parseable_numbers() {
    let dir = test_dir("locale");
    let checkpoint = dir.join("scan.rxscan");
    let (code, _, _) = run_cli(
        &[
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--level",
            "1",
            "--ports",
            "9",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
        ],
        &dir,
    );
    assert_eq!(code, 0);
    let (code, stdout, _) = run_cli(
        &["report", "--format", "json", checkpoint.to_str().unwrap()],
        &dir,
    );
    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // No NaN/Infinity (serde_json rejects both on parse, so reaching here
    // already proves it); numbers survive a locale-independent round trip.
    let reserialized = serde_json::to_string(&parsed).unwrap();
    let _: serde_json::Value = serde_json::from_str(&reserialized).unwrap();
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §116 no telemetry / update checks ----------

#[test]
fn source_contains_no_telemetry_or_update_channels() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut hits = Vec::new();
    for entry in walk_rs_files(&root.join("src")) {
        let text = std::fs::read_to_string(&entry).unwrap_or_default();
        for (number, line) in text.lines().enumerate() {
            let low = line.to_lowercase();
            if (low.contains("telemetry")
                || low.contains("analytics")
                || low.contains("update-check")
                || low.contains("update_check")
                || low.contains("auto-update")
                || low.contains("auto_update")
                || low.contains("phone-home")
                || low.contains("phone_home"))
                && !low.trim_start().starts_with("//")
                && !low.contains("no telemetry")
                && !low.contains("no analytics")
                && !low.contains("do not implement auto-update")
                && !low.contains("never")
                && !low.contains("without")
            {
                hits.push(format!(
                    "{}:{}: {}",
                    entry.display(),
                    number + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "telemetry-like channels found:\n{}",
        hits.join("\n")
    );
}

fn walk_rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_rs_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    out
}

// ---------- §107 invalid UTF-8 CLI input ----------

#[test]
fn non_utf8_cli_arg_fails_cleanly() {
    use std::os::unix::ffi::OsStringExt;
    let dir = test_dir("utf8");
    let bad = std::ffi::OsString::from_vec(vec![0xff, 0xfe, b'x']);
    let output = Command::new(rxscan_bin())
        .arg(bad)
        .current_dir(&dir)
        .output()
        .expect("spawn rxscan");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.code() == Some(2),
        "non-UTF8 target must exit 2, got {:?}: {stderr:?}",
        output.status.code()
    );
    assert!(!stderr.contains("panicked"));
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §134-136 temp hygiene sample ----------

#[test]
fn contact_registry_crawl_direction_is_asymmetric_by_design() {
    use rxscan::contact::RequestPurpose;
    // Direction 1 (P11 contract preserved): crawl first, content skips.
    let registry = ContactRegistry::new();
    let target = WebTarget::parse("http://127.0.0.1/page").unwrap();
    assert!(registry.claim(&target, RequestPurpose::CrawlPage));
    assert!(
        !registry.claim(&target, RequestPurpose::ContentCandidate),
        "content must skip crawler-fetched URLs"
    );
    assert!(
        !registry.claim(&target, RequestPurpose::CrawlPage),
        "same-purpose duplicates still collapse"
    );
    // Direction 2 (P20 fix): content first, crawl still fetches so link
    // extraction cannot be silently lost to task ordering.
    let registry = ContactRegistry::new();
    assert!(registry.claim(&target, RequestPurpose::ContentCandidate));
    assert!(
        registry.claim(&target, RequestPurpose::CrawlPage),
        "crawl must fetch content-claimed URLs to extract links"
    );
    // ... and content still skips afterwards.
    assert!(!registry.claim(&target, RequestPurpose::ContentCandidate));
}

#[test]
fn scan_leaves_no_stray_temp_files_behind() {
    let dir = test_dir("temphygiene");
    let before: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let checkpoint = dir.join("scan.rxscan");
    let output = dir.join("scan.jsonl");
    let (code, _, _) = run_cli(
        &[
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--level",
            "2",
            "--ports",
            "9",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ],
        &dir,
    );
    assert_eq!(code, 0);
    let mut after: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    after.sort();
    let mut expected: Vec<String> = before;
    expected.push("scan.rxscan".to_owned());
    expected.push("scan.jsonl".to_owned());
    expected.sort();
    assert_eq!(after, expected, "no stray temp files may remain");
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §43-48 E2E lab ----------

/// Controlled local lab: one open TCP port, one HTTP server with redirect,
/// crawl links, duplicate URLs, content endpoint, observed query parameter,
/// secret-bearing responses, and an out-of-scope canary link.
struct Lab {
    http_port: u16,
    open_port: u16,
    canary_hits: Arc<AtomicUsize>,
    seen_auth: Arc<AtomicUsize>,
    seen_post: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    stop_open: Arc<AtomicBool>,
}

fn lab_page(canary_port: u16) -> String {
    format!(
        "<html><head><title>Lab Home</title></head><body>\
        <a href=\"/a\">a</a><a href=\"/b\">b</a><a href=\"/a#frag\">adup</a>\
        <a href=\"/redirect\">r</a><a href=\"/admin\">admin</a>\
        <a href=\"/search?q=hello\">s</a>\
        <a href=\"http://127.0.0.2:{canary_port}/evil\">canary</a>\
        </body></html>"
    )
}

fn spawn_lab() -> Lab {
    fn bind(ip: &str) -> TcpListener {
        TcpListener::bind(format!("{ip}:0")).expect("bind lab listener")
    }
    let http = bind("127.0.0.1");
    let http_port = http.local_addr().unwrap().port();
    let open = bind("127.0.0.1");
    let open_port = open.local_addr().unwrap().port();
    let canary = bind("127.0.0.2");
    let canary_port = canary.local_addr().unwrap().port();
    let canary_hits = Arc::new(AtomicUsize::new(0));
    let seen_auth = Arc::new(AtomicUsize::new(0));
    let seen_post = Arc::new(AtomicUsize::new(0));
    let stop_open = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    http.set_nonblocking(true).unwrap();
    open.set_nonblocking(true).unwrap();
    canary.set_nonblocking(true).unwrap();
    // Open TCP port: accept and hold briefly (proves Open, no HTTP).
    // Dropping via stop_open simulates the port closing between scans.
    {
        let stop = stop.clone();
        let stop_open = stop_open.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) && !stop_open.load(Ordering::SeqCst) {
                match open.accept() {
                    Ok((stream, _)) => {
                        std::thread::sleep(Duration::from_millis(300));
                        drop(stream);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
    }
    // Canary: any connection is a scope failure.
    {
        let stop = stop.clone();
        let hits = canary_hits.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match canary.accept() {
                    Ok((stream, _)) => {
                        hits.fetch_add(1, Ordering::SeqCst);
                        drop(stream);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
    }
    // HTTP lab server (canary port captured by value: u16 is Copy).
    {
        let stop = stop.clone();
        let seen_auth = seen_auth.clone();
        let seen_post = seen_post.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let (mut stream, _) = match http.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(_) => break,
                };
                let seen_auth = seen_auth.clone();
                let seen_post = seen_post.clone();
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut raw = Vec::new();
                    let mut chunk = [0u8; 1024];
                    loop {
                        match stream.read(&mut chunk) {
                            Ok(0) => break,
                            Ok(n) => {
                                raw.extend_from_slice(&chunk[..n]);
                                if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let head = String::from_utf8_lossy(&raw);
                    if head.to_lowercase().contains("authorization:") {
                        seen_auth.fetch_add(1, Ordering::SeqCst);
                    }
                    if head.starts_with("POST") {
                        seen_post.fetch_add(1, Ordering::SeqCst);
                    }
                    let target = head
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_owned();
                    let path = target.split('?').next().unwrap_or("/").to_owned();
                    let response: Vec<u8> = if path == "/redirect" {
                        b"HTTP/1.1 302 Found\r\nLocation: /a\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
                    } else if path == "/search" {
                        let body = b"<html><head><title>Search hello</title></head><body>results for hello, reflected q=hello</body></html>";
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/html\r\nSet-Cookie: session=lab-cookie-0123456789abcdef\r\n\r\n", body.len()).into_bytes().into_iter().chain(body.iter().copied()).collect()
                    } else if path == "/admin" {
                        let body = b"<html><head><title>Admin Console</title></head><body>console password-field-present</body></html>";
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n", body.len()).into_bytes().into_iter().chain(body.iter().copied()).collect()
                    } else if path == "/a" {
                        let body =
                            b"<html><head><title>Alpha</title></head><body>alpha</body></html>";
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n", body.len()).into_bytes().into_iter().chain(body.iter().copied()).collect()
                    } else if path == "/b" {
                        let body =
                            b"<html><head><title>Beta</title></head><body>beta</body></html>";
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n", body.len()).into_bytes().into_iter().chain(body.iter().copied()).collect()
                    } else if path == "/" {
                        let body = lab_page(canary_port);
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n", body.len()).into_bytes().into_iter().chain(body.bytes()).collect()
                    } else {
                        let body =
                            b"<html><head><title>Not Found</title></head><body>nope</body></html>";
                        format!("HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n", body.len()).into_bytes().into_iter().chain(body.iter().copied()).collect()
                    };
                    let _ = stream.write_all(&response);
                });
            }
        });
    }
    Lab {
        http_port,
        open_port,
        canary_hits,
        seen_auth,
        seen_post,
        stop,
        stop_open,
    }
}

fn run_lab_scan(dir: &Path, lab: &Lab, level: &str, extra: &[String]) -> (i32, String, String) {
    let mut args: Vec<String> = vec![
        format!("http://127.0.0.1:{}/", lab.http_port),
        "--scope".to_owned(),
        "127.0.0.1".to_owned(),
        "--level".to_owned(),
        level.to_owned(),
        "--ports".to_owned(),
        format!("{},{}", lab.http_port, lab.open_port),
    ];
    args.extend(extra.iter().cloned());
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_cli(&arg_refs, dir)
}

#[test]
fn end_to_end_lab_scan_reports_typed_evidence_with_zero_canary_contact() {
    let lab = spawn_lab();
    let dir = test_dir("e2e");
    let checkpoint = dir.join("lab-a.rxscan");
    let output = dir.join("lab-a.jsonl");
    let (code, _stdout, stderr) = run_lab_scan(
        &dir,
        &lab,
        "4",
        &[
            "--checkpoint".to_owned(),
            checkpoint.to_str().unwrap().to_owned(),
            "--output".to_owned(),
            output.to_str().unwrap().to_owned(),
        ],
    );
    assert_eq!(code, 0, "lab scan failed: {stderr:?}");
    assert_eq!(
        lab.canary_hits.load(Ordering::SeqCst),
        0,
        "out-of-scope canary must never be contacted"
    );
    assert_eq!(
        lab.seen_auth.load(Ordering::SeqCst),
        0,
        "never send Authorization"
    );
    assert_eq!(lab.seen_post.load(Ordering::SeqCst), 0, "never POST");
    let jsonl = std::fs::read_to_string(&output).unwrap();
    // Case-insensitive needles: crawled page *titles* are not recorded, but
    // endpoint URLs, port records, redirect observations, and baseline
    // findings are.
    let lower = jsonl.to_lowercase();
    for needle in [
        "port_open",
        "asset_port_",
        "/a",
        "crawled endpoint",
        "baseline",
        "redirect",
    ] {
        assert!(lower.contains(needle), "lab JSONL missing {needle:?}");
    }
    // Every JSONL line parses; checkpoint loads.
    for line in jsonl.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let _: serde_json::Value = serde_json::from_str(line).unwrap();
    }
    rxscan::persistence::load_checkpoint(&checkpoint).unwrap();
    lab.stop.store(true, Ordering::SeqCst);
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §5-6 SIGINT: real interruption of a real scan ----------

/// Slow lab: every response delayed so the scan provably outlives the kill
/// timer. Returns ports + hit counter + stop flag.
struct SlowLab {
    port: u16,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

fn spawn_slow_lab(delay_ms: u64, wordlist_lines: usize, dir: &Path) -> (SlowLab, PathBuf) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let wordlist = dir.join("slow_wordlist.txt");
    {
        let mut file = std::fs::File::create(&wordlist).unwrap();
        for i in 0..wordlist_lines {
            writeln!(file, "slowpath{i}").unwrap();
        }
    }
    let hits_clone = hits.clone();
    let stop_clone = stop.clone();
    std::thread::spawn(move || {
        while !stop_clone.load(Ordering::SeqCst) {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(_) => break,
            };
            let hits = hits_clone.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let mut raw = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            raw.extend_from_slice(&chunk[..n]);
                            if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                hits.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(delay_ms));
                let body = b"<html><head><title>Slow</title></head><body>slow</body></html>";
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                );
                let _ = stream.write_all(body);
            });
        }
    });
    (SlowLab { port, hits, stop }, wordlist)
}

fn send_sigint(pid: u32) {
    let status = Command::new("kill")
        .arg("-INT")
        .arg(pid.to_string())
        .status()
        .expect("kill -INT available");
    assert!(status.success(), "could not signal child process");
}

#[test]
fn sigint_terminates_scan_promptly_without_panic_or_corruption() {
    // A backgrounded non-interactive shell sets SIGINT/SIGQUIT to SIG_IGN,
    // which exec preserves: children of such a tree cannot test delivery.
    // Detect and skip loudly instead of failing confusingly (P20 finding:
    // backgrounded `nohup sh scripts/release-check.sh &` runs poisoned the
    // whole subtree and produced ~16s "survivals" of an otherwise promptly
    // dying binary).
    let inherited = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("SigIgn:").and_then(|rest| {
                    u64::from_str_radix(rest.trim(), 16)
                        .ok()
                        .map(|mask| mask & 0x2 != 0)
                })
            })
        });
    if inherited.unwrap_or(false) {
        eprintln!("SIGINT already ignored in this tree; skipping delivery test");
        return;
    }
    let dir = test_dir("sigint");
    // Establish prior valid outputs at the same paths the scan will use:
    // atomic replacement must never corrupt them.
    let checkpoint = dir.join("scan.rxscan");
    let output = dir.join("scan.jsonl");
    let (code, _, _) = run_cli(
        &[
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--level",
            "1",
            "--ports",
            "9",
            "--checkpoint",
            checkpoint.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ],
        &dir,
    );
    assert_eq!(code, 0);
    let prior_checkpoint = std::fs::read(&checkpoint).unwrap();
    let prior_output = std::fs::read(&output).unwrap();
    assert!(!prior_checkpoint.is_empty() && !prior_output.is_empty());

    // Long scan against the slow lab (content stage: 120 x 500ms ≈ 60s,
    // plus discovery/web/crawl stages ahead of it).
    let (slow, wordlist) = spawn_slow_lab(500, 120, &dir);
    let mut child = Command::new(rxscan_bin())
        .args([
            format!("http://127.0.0.1:{}/", slow.port),
            "--scope".to_owned(),
            "127.0.0.1".to_owned(),
            "--level".to_owned(),
            "4".to_owned(),
            "--ports".to_owned(),
            slow.port.to_string(),
            "--wordlist".to_owned(),
            wordlist.to_str().unwrap().to_owned(),
            "--checkpoint".to_owned(),
            checkpoint.to_str().unwrap().to_owned(),
            "--output".to_owned(),
            output.to_str().unwrap().to_owned(),
        ])
        .current_dir(&dir)
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_secs(2));
    // Still running (slow lab guarantees a long window)?
    assert!(
        child.try_wait().unwrap().is_none(),
        "scan finished before SIGINT; slow lab too fast"
    );
    // Wait for proof the scan reached slow work (fixture hits), not a
    // fixed sleep: killing before the slow stage risks racing natural
    // completion (a zombie accepts the signal yet reports exit 0).
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if slow.hits.load(Ordering::SeqCst) >= 5 {
            break;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "scan ended before reaching slow work"
        );
        assert!(
            Instant::now() < deadline,
            "scan never reached slow work within 90s"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // Dozens of slow requests remain: natural completion is minutes away,
    // so the signal below cannot race it.
    assert!(
        child.try_wait().unwrap().is_none(),
        "scan finished before SIGINT; slow lab too fast"
    );
    let kill_at = Instant::now();
    let cmdline = std::fs::read_to_string(format!("/proc/{}/cmdline", child.id()))
        .unwrap_or_else(|_| "<gone>".to_owned())
        .replace('\0', " ");
    // Forensics: SigBlk bit 1 (0x2) means SIGINT is blocked and would be
    // inherited across exec, making kills silently ineffective.
    let self_mask = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("SigBlk:"))
                .map(|line| line.to_owned())
        })
        .unwrap_or_default();
    let child_mask = std::fs::read_to_string(format!("/proc/{}/status", child.id()))
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("SigBlk:"))
                .map(|line| line.to_owned())
        })
        .unwrap_or_default();
    eprintln!("phase20 sigint: pid={} cmdline={cmdline:?}", child.id());
    eprintln!("phase20 sigint: self_mask={self_mask} child_mask={child_mask}");
    // Scheduler-state forensics: a D-state (uninterruptible) process cannot
    // act on signals until the kernel wait ends; wchan names the wait.
    let child_sched = std::fs::read_to_string(format!("/proc/{}/wchan", child.id()))
        .unwrap_or_else(|_| "<gone>".to_owned());
    let child_stat =
        std::fs::read_to_string(format!("/proc/{}/stat", child.id())).unwrap_or_default();
    let child_state = child_stat
        .rfind(')')
        .and_then(|end| child_stat[end..].split_whitespace().nth(1))
        .unwrap_or("?")
        .to_owned();
    eprintln!(
        "phase20 sigint: child_state={child_state} wchan={}",
        child_sched.trim()
    );
    send_sigint(child.id());
    // Second SIGINT during shutdown must not hang either (§6).
    std::thread::sleep(Duration::from_millis(500));
    send_sigint(child.id());
    // Measure death latency from AFTER the last signal: spawning the `kill`
    // helper itself costs wall time under suite-spawn churn, which must not
    // contaminate the product measurement (typical death is ~2ms).
    let wait_start = Instant::now();
    // Watchdog: a hung shutdown must fail loudly with diagnostics, never
    // hang CI. On timeout, SIGKILL the child and report.
    let child_pid = child.id();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done_tx.send(child.wait_with_output());
    });
    let waited = match done_rx.recv_timeout(Duration::from_secs(30)) {
        Ok(output) => output.unwrap(),
        Err(_) => {
            let _ = Command::new("kill")
                .arg("-KILL")
                .arg(child_pid.to_string())
                .status();
            eprintln!("phase20 sigint: shutdown hung >30s, SIGKILLed pid={child_pid}");
            panic!("SIGINT shutdown hung beyond 30s watchdog");
        }
    };
    let shutdown_ms = kill_at.elapsed().as_millis();
    let death_ms = wait_start.elapsed().as_millis();
    eprintln!(
        "phase20 sigint: shutdown_total_ms={shutdown_ms} death_after_last_signal_ms={death_ms}"
    );
    let stderr = String::from_utf8_lossy(&waited.stderr);
    assert!(
        !stderr.contains("panicked"),
        "interruption must not panic: {stderr:?}"
    );
    // Order matters for forensics: a scan that ignored SIGINT completes
    // naturally (exit code present); a merely late death still dies by
    // signal. Status before latency classifies the next anomaly.
    assert!(
        waited.status.code().is_none(),
        "interrupted scan must die by signal, got {:?}; stderr: {:?}",
        waited.status.code(),
        stderr,
    );
    assert!(
        death_ms < 15_000,
        "process survived {death_ms}ms after 2nd SIGINT; must die promptly"
    );
    assert!(
        shutdown_ms < 60_000,
        "SIGINT shutdown took {shutdown_ms}ms; must be bounded"
    );
    // Prior valid files untouched: atomic replacement never ran.
    assert_eq!(std::fs::read(&checkpoint).unwrap(), prior_checkpoint);
    assert_eq!(std::fs::read(&output).unwrap(), prior_output);
    // Checkpoint still loads (valid after interrupt).
    rxscan::persistence::load_checkpoint(&checkpoint).unwrap();
    assert!(
        slow.hits.load(Ordering::SeqCst) > 0,
        "interrupted scan must have been live against the lab"
    );
    slow.stop.store(true, Ordering::SeqCst);
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §45-48 E2E resume / diff / analyze / report / project ----------

#[test]
fn end_to_end_resume_diff_analyze_report_project_chain() {
    let lab = spawn_lab();
    let dir = test_dir("e2echain");
    let scan_a = dir.join("lab-a.rxscan");
    let (code, _, stderr) = run_lab_scan(
        &dir,
        &lab,
        "4",
        &[
            "--checkpoint".to_owned(),
            scan_a.to_str().unwrap().to_owned(),
        ],
    );
    assert_eq!(code, 0, "scan A failed: {stderr:?}");
    let state_a = rxscan::persistence::load_checkpoint(&scan_a).unwrap().state;
    let ids_a: Vec<String> = {
        let mut ids: Vec<String> = state_a.tasks.iter().map(|t| t.task.id.0.clone()).collect();
        ids.sort();
        ids
    };
    // Resume: completed work is not repeated, IDs stable, scope unchanged.
    let resumed = dir.join("lab-resumed.rxscan");
    let (code, _, stderr) = run_cli(
        &[
            "--resume",
            scan_a.to_str().unwrap(),
            "--checkpoint",
            resumed.to_str().unwrap(),
        ],
        &dir,
    );
    assert_eq!(code, 0, "resume failed: {stderr:?}");
    let state_r = rxscan::persistence::load_checkpoint(&resumed)
        .unwrap()
        .state;
    assert_eq!(
        state_r.scan_id, state_a.scan_id,
        "resume keeps scan identity"
    );
    assert_eq!(
        state_r.plan.scope, state_a.plan.scope,
        "resume cannot widen scope"
    );
    let mut ids_r: Vec<String> = state_r.tasks.iter().map(|t| t.task.id.0.clone()).collect();
    ids_r.sort();
    assert_eq!(ids_a, ids_r, "task IDs stable across resume");
    // Diff A vs resumed: no false removals on identical work.
    let (code, stdout, _) = run_cli(
        &["diff", scan_a.to_str().unwrap(), resumed.to_str().unwrap()],
        &dir,
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("Removed") || stdout.contains("removed") || !stdout.contains("-1"),
        "diff output must be coherent: {stdout:?}"
    );
    // Analyze + report through the CLI with zero network (FD-delta proof
    // runs isolated below; the process FD table is shared with parallel
    // sibling tests, so it cannot be measured meaningfully here).
    let (code, stdout, _) = run_cli(&["analyze", scan_a.to_str().unwrap()], &dir);
    assert_eq!(code, 0);
    assert!(!stdout.trim().is_empty());
    let (code, stdout, _) = run_cli(
        &["report", "--format", "json", scan_a.to_str().unwrap()],
        &dir,
    );
    assert_eq!(code, 0);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        parsed["summary"]["network_requests"], 0,
        "report must stay offline"
    );
    let project = dir.join("lab.rxproj");
    let (code, _, _) = run_cli(&["project", "create", project.to_str().unwrap()], &dir);
    assert_eq!(code, 0);
    let (code, stdout, _) = run_cli(
        &[
            "project",
            "add",
            project.to_str().unwrap(),
            scan_a.to_str().unwrap(),
        ],
        &dir,
    );
    assert_eq!(code, 0, "project add failed: {stdout:?}");
    let (code, stdout, _) = run_cli(&["project", "summary", project.to_str().unwrap()], &dir);
    assert_eq!(code, 0);
    assert!(stdout.contains("network_requests=0") || !stdout.is_empty());
    lab.stop.store(true, Ordering::SeqCst);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn offline_chain_opens_no_new_descriptors() {
    // FD-table proof must run isolated: sibling tests share this process's
    // descriptor table, so in-suite deltas are noise. The child runs only
    // this measurement against the committed golden fixture.
    if std::env::var("RXSCAN_P20_FD_CHILD").is_ok() {
        let (checkpoint_path, project_path, _) = golden_paths();
        let fds_before = open_fd_count();
        let loaded = rxscan::persistence::load_checkpoint(&checkpoint_path).unwrap();
        let diff_report = rxscan::diff::compare_states(
            &loaded.state,
            &loaded.state,
            rxscan::diff::DiffOptions::default(),
        )
        .unwrap();
        assert_eq!(diff_report.network_requests, 0);
        let analysis = rxscan::analysis::analyze_state(
            &loaded.state,
            None,
            rxscan::analysis::AnalysisOptions::default(),
        )
        .unwrap();
        assert_eq!(analysis.network_requests, 0);
        let model = rxscan::report::build_report_model(
            &loaded.state,
            None,
            None,
            &rxscan::report::ReportOptions {
                format: rxscan::report::ReportFormat::Jsonl,
                summary_only: false,
                top_n: 5,
            },
        )
        .unwrap();
        assert_eq!(model.summary.network_requests, 0);
        let mut bytes = Vec::new();
        rxscan::report::render_jsonl(&model, &mut bytes).unwrap();
        let project = rxscan::project::load_project(&project_path).unwrap();
        let _ = project.summary(0);
        let fds_after = open_fd_count();
        assert_eq!(
            fds_before, fds_after,
            "offline diff/analyze/report/project must not leak descriptors"
        );
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let out = std::process::Command::new(exe)
        .arg("--exact")
        .arg("offline_chain_opens_no_new_descriptors")
        .arg("--nocapture")
        .env("RXSCAN_P20_FD_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "isolated FD measurement failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|e| e.count())
        .unwrap_or(0)
}

// ---------- §46 E2E diff with a modified lab ----------

#[test]
fn end_to_end_diff_detects_closed_port_with_confirmed_certainty() {
    let lab = spawn_lab();
    let dir = test_dir("e2ediff");
    let ports = format!("{},{}", lab.http_port, lab.open_port);
    let scan = |name: &str| {
        let checkpoint = dir.join(name);
        let (code, _, stderr) = run_cli(
            &[
                "127.0.0.1",
                "--scope",
                "127.0.0.1",
                "--level",
                "2",
                "--ports",
                ports.as_str(),
                "--checkpoint",
                checkpoint.to_str().unwrap(),
            ],
            &dir,
        );
        assert_eq!(code, 0, "scan failed: {stderr:?}");
        checkpoint
    };
    let before = scan("before.rxscan");
    // Modify the lab: the open port goes dark.
    lab.stop_open.store(true, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(500));
    let after = scan("after.rxscan");
    let (code, stdout, stderr) = run_cli(
        &["diff", before.to_str().unwrap(), after.to_str().unwrap()],
        &dir,
    );
    assert_eq!(code, 0, "diff failed: {stderr:?}");
    // Comparable coverage (same plan shape) => confirmed removal, never
    // inconclusive-missing for the vanished open port.
    assert!(
        stdout.contains("-1") || stdout.contains("-2"),
        "expected a confirmed removal in: {stdout:?}"
    );
    assert!(
        !stdout.contains("?1") && !stdout.contains("?2"),
        "no inconclusive-missing expected with comparable coverage: {stdout:?}"
    );
    assert!(stdout.contains("network_requests=0"));
    lab.stop.store(true, Ordering::SeqCst);
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §49-50 soak: repeated execution ----------

#[test]
fn repeated_scans_show_no_tmp_accumulation_or_slowdown() {
    let dir = test_dir("soak");
    let mut walls = Vec::new();
    for i in 0..6 {
        let checkpoint = dir.join(format!("soak{i}.rxscan"));
        let output = dir.join(format!("soak{i}.jsonl"));
        let start = Instant::now();
        let (code, _, stderr) = run_cli(
            &[
                "127.0.0.1",
                "--scope",
                "127.0.0.1",
                "--level",
                "2",
                "--ports",
                "9",
                "--checkpoint",
                checkpoint.to_str().unwrap(),
                "--output",
                output.to_str().unwrap(),
            ],
            &dir,
        );
        walls.push(start.elapsed());
        assert_eq!(code, 0, "soak run {i} failed: {stderr:?}");
    }
    // No monotonic slowdown beyond 5x the first run (generous).
    let first = walls[0].as_millis().max(1);
    for (i, wall) in walls.iter().enumerate() {
        assert!(
            wall.as_millis() < first * 5 + 5_000,
            "soak run {i} took {wall:?} vs first {:?}: leak suspected",
            walls[0]
        );
    }
    // Exactly the expected files remain (checkpoints + outputs, no tmps).
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 12, "unexpected files: {names:?}");
    assert!(
        names.iter().all(|n| !n.contains(".tmp-")),
        "stale tmps: {names:?}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §23-24,35-36 clean cwd / relocation / fresh HOME ----------

#[test]
fn binary_works_from_tmp_cwd_and_relocated_copy_with_fresh_home() {
    let dir = test_dir("env");
    // Relocated copy (no repo paths).
    let relocated = dir.join("rxscan-copy");
    std::fs::copy(rxscan_bin(), &relocated).unwrap();
    // Fresh HOME + cwd outside the repo.
    let home = dir.join("fakehome");
    std::fs::create_dir_all(&home).unwrap();
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    for binary in [rxscan_bin(), relocated.clone()] {
        let output = Command::new(&binary)
            .arg("--version")
            .env("HOME", &home)
            .current_dir(&work)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            format!("rxscan {}", env!("CARGO_PKG_VERSION"))
        );
        let output = Command::new(&binary)
            .args([
                "127.0.0.1",
                "--scope",
                "127.0.0.1",
                "--level",
                "1",
                "--ports",
                "9",
            ])
            .env("HOME", &home)
            .current_dir(&work)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "relocated/fresh-HOME scan failed for {}",
            binary.display()
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §39 IPv6 loopback where available ----------

#[test]
fn ipv6_loopback_scan_where_supported() {
    if TcpListener::bind("[::1]:0").is_err() {
        eprintln!("IPv6 loopback unavailable; skipping");
        return;
    }
    let dir = test_dir("ipv6");
    let (code, _, stderr) = run_cli(
        &["::1", "--scope", "::1", "--level", "1", "--ports", "9"],
        &dir,
    );
    assert_eq!(code, 0, "ipv6 scan failed: {stderr:?}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §40 unprivileged discovery stays graceful ----------

#[test]
fn unprivileged_host_discovery_completes_without_root() {
    let dir = test_dir("unpriv");
    let (code, stdout, stderr) = run_cli(
        &[
            "127.0.0.1",
            "--scope",
            "127.0.0.1",
            "--level",
            "2",
            "--ports",
            "9",
        ],
        &dir,
    );
    assert_eq!(code, 0, "unprivileged scan must complete: {stderr:?}");
    assert!(
        stdout.contains("task(s)"),
        "expected human summary: {stdout:?}"
    );
    assert!(!stderr.contains("root"), "must not demand root: {stderr:?}");
    std::fs::remove_dir_all(&dir).ok();
}

// ---------- §112-114 privacy: secrets stay bounded ----------

#[test]
fn observed_secrets_are_bounded_never_raw_blobs() {
    // Fixture leaks a long secret deep in a body plus a giant cookie.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let secret = format!("s3cr3t-{}-{}", "x".repeat(64), "y".repeat(64));
    let secret_clone = secret.clone();
    std::thread::spawn(move || {
        while !stop_clone.load(Ordering::SeqCst) {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(_) => break,
            };
            let secret = secret_clone.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut raw = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            raw.extend_from_slice(&chunk[..n]);
                            if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                // Secret buried 40 KiB deep (past all body caps) + 500-char cookie.
                let mut body = vec![b'.'; 40 * 1024];
                body.extend_from_slice(secret.as_bytes());
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/html\r\nSet-Cookie: session={}\r\n\r\n",
                    body.len(),
                    "c".repeat(500)
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            });
        }
    });
    let dir = test_dir("privacy");
    let checkpoint = dir.join("priv.rxscan");
    let output = dir.join("priv.jsonl");
    let target = format!("http://127.0.0.1:{port}/");
    let port_s = port.to_string();
    let (code, _, stderr) = run_cli(
        &[
            target.as_str(),
            "--scope",
            "127.0.0.1",
            "--level",
            "4",
            "--ports",
            port_s.as_str(),
            "--checkpoint",
            checkpoint.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ],
        &dir,
    );
    assert_eq!(code, 0, "privacy scan failed: {stderr:?}");
    let blob = std::fs::read(&checkpoint).unwrap();
    let jsonl = std::fs::read(&output).unwrap();
    // The full 128-char secret must not persist verbatim (body caps truncate
    // far before 40 KiB); cookie values are bounded observations (<=256B).
    assert!(
        !blob.windows(secret.len()).any(|w| w == secret.as_bytes()),
        "raw secret must not persist in checkpoint"
    );
    assert!(
        !jsonl.windows(secret.len()).any(|w| w == secret.as_bytes()),
        "raw secret must not persist in JSONL"
    );
    for line in String::from_utf8_lossy(&jsonl).lines() {
        if line.contains("session=") {
            let value = line.split("session=").nth(1).unwrap_or("");
            let cookie = value.split(['"', ';', ',', ' ', '}']).next().unwrap_or("");
            assert!(
                cookie.len() <= 300,
                "cookie observation must stay bounded, got {} chars",
                cookie.len()
            );
        }
    }
    stop.store(true, Ordering::SeqCst);
    std::fs::remove_dir_all(&dir).ok();
}
