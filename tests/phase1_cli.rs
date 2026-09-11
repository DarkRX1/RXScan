use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use rxscan::{
    cli::Cli,
    plan::{ScanGoal, ScanPlan, SpeedSetting},
};

#[test]
fn cli_overrides_project_and_global_configuration() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("rxscan-phase1-{stamp}"));
    fs::create_dir_all(&directory).unwrap();
    let global = directory.join("global.toml");
    let project = directory.join("project.toml");
    fs::write(
        &global,
        "goal = 'inventory'\nlevel = 1\nspeed = 'slow'\nports = '80'\n",
    )
    .unwrap();
    fs::write(
        &project,
        "goal = 'web'\nlevel = 3\nspeed = 40\nports = '443'\n",
    )
    .unwrap();
    let cli = Cli::try_parse_from([
        "rxscan",
        "example.test",
        "--config",
        global.to_str().unwrap(),
        "--project-config",
        project.to_str().unwrap(),
        "--level",
        "5",
        "--speed",
        "90",
    ])
    .unwrap();
    let plan = ScanPlan::compile(cli).unwrap();
    assert_eq!(plan.goal, ScanGoal::Web);
    assert_eq!(plan.level, 5);
    assert_eq!(plan.speed, SpeedSetting::Numeric(90));
    assert_eq!(plan.config_sources.len(), 2);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn an_excluded_seed_is_rejected_before_execution() {
    let cli = Cli::try_parse_from(["rxscan", "192.0.2.10", "--exclude", "192.0.2.10"]).unwrap();
    assert!(ScanPlan::compile(cli).is_err());
}
