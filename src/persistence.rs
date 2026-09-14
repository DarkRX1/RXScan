//! Phase 14 lightweight checkpoint / resume support.
//!
//! Checkpoints persist semantic scan state as bounded versioned JSON. Runtime
//! machinery such as threads, sockets, channels, file descriptors, and raw
//! network buffers is never serialized.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    baseline::OriginBaselineRegistry,
    contact::{ContactRegistry, ContactRegistryEntry},
    dns::{DnsDomainRegistryEntry, DnsQueryRegistryEntry, DnsRegistry},
    execution::{
        ModuleOutput, PolicyScopeGuard, Scheduler, SchedulerError, ScopeGuard, Task, TaskState,
    },
    fuzz::FuzzOriginBudget,
    model::{Asset, AssetId, ScanPlanId, Timestamp},
    plan::ScanPlan,
};

pub const CHECKPOINT_SCHEMA_VERSION: u32 = 1;
pub const MAX_CHECKPOINT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_PERSISTED_TASKS: usize = 100_000;
pub const MAX_PERSISTED_OUTPUTS: usize = 100_000;
pub const MAX_PERSISTED_ASSETS: usize = 100_000;
pub const MAX_PERSISTED_RELATIONSHIPS: usize = 100_000;
pub const MAX_PERSISTED_EVENTS: usize = 100_000;
pub const MAX_PERSISTED_EVIDENCE: usize = 100_000;
pub const MAX_PERSISTED_FINDINGS: usize = 10_000;
pub const MAX_ID_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersistedScanState {
    pub schema_version: u32,
    pub scan_id: ScanPlanId,
    pub saved_at: Timestamp,
    pub plan: ScanPlan,
    pub tasks: Vec<PersistedTask>,
    pub outputs: Vec<PersistedModuleOutput>,
    #[serde(default)]
    pub registries: PersistedRegistries,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersistedTask {
    pub task: Task,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersistedModuleOutput {
    pub task_id: crate::execution::TaskId,
    pub output: ModuleOutput,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PersistedRegistries {
    #[serde(default)]
    pub contacts: Vec<ContactRegistryEntry>,
    #[serde(default)]
    pub origin_baselines: Vec<(String, String)>,
    #[serde(default)]
    pub fuzz_origin_budgets: Vec<(String, Vec<String>)>,
    #[serde(default)]
    pub dns_queries: Vec<DnsQueryRegistryEntry>,
    #[serde(default)]
    pub dns_domains: Vec<DnsDomainRegistryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointMetrics {
    pub assets_persisted: usize,
    pub relationships_persisted: usize,
    pub evidence_persisted: usize,
    pub findings_persisted: usize,
    pub completed_tasks_persisted: usize,
    pub pending_tasks_persisted: usize,
    pub registry_entries_persisted: usize,
    pub checkpoint_bytes: u64,
    pub elapsed_ms: u128,
}

#[derive(Debug, Error)]
pub enum PersistenceError {
    #[error("checkpoint IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("checkpoint parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported checkpoint schema version {0}")]
    UnsupportedVersion(u32),
    #[error("checkpoint exceeds hard size cap")]
    SizeLimit,
    #[error("invalid checkpoint: {0}")]
    Invalid(String),
    #[error("scheduler restore failed: {0}")]
    Scheduler(#[from] SchedulerError),
}

#[derive(Debug)]
pub struct LoadedCheckpoint {
    pub state: PersistedScanState,
    pub load_ms: u128,
    pub checkpoint_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PersistedCollectionCounts {
    pub tasks: usize,
    pub outputs: usize,
    pub assets: usize,
    pub relationships: usize,
    pub events: usize,
    pub evidence: usize,
    pub findings: usize,
}

impl PersistedScanState {
    pub fn from_scheduler(
        plan: ScanPlan,
        scheduler: &Scheduler,
        registries: PersistedRegistries,
    ) -> Self {
        let outputs = scheduler
            .module_outputs()
            .into_iter()
            .map(|(task_id, output)| PersistedModuleOutput { task_id, output })
            .collect::<Vec<_>>();
        let tasks = scheduler
            .tasks()
            .map(|task| {
                let mut task = task.clone();
                if matches!(task.state, TaskState::Running | TaskState::Ready) {
                    task.state = TaskState::Pending;
                    task.cancel_requested = false;
                }
                PersistedTask { task }
            })
            .collect();
        Self {
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            scan_id: plan.stable_id(),
            saved_at: Timestamp::now(),
            plan,
            tasks,
            outputs,
            registries,
        }
    }

    pub fn validate(&self) -> Result<(), PersistenceError> {
        if self.schema_version != CHECKPOINT_SCHEMA_VERSION {
            return Err(PersistenceError::UnsupportedVersion(self.schema_version));
        }
        if self.scan_id.0 != self.plan.stable_id().0 {
            return Err(PersistenceError::Invalid(
                "scan id does not match plan".to_owned(),
            ));
        }
        validate_persisted_collection_counts(PersistedCollectionCounts {
            tasks: self.tasks.len(),
            outputs: self.outputs.len(),
            ..PersistedCollectionCounts::default()
        })?;
        validate_id(&self.scan_id.0, "scan id")?;
        self.plan.budgets.validate()?;
        let guard = PolicyScopeGuard::new(self.plan.scope.clone());
        let mut task_ids = BTreeSet::new();
        for persisted in &self.tasks {
            validate_task(&persisted.task, &guard, &mut task_ids)?;
        }
        let global_assets = collect_global_assets(&self.outputs)?;
        let mut output_ids = BTreeSet::new();
        for output in &self.outputs {
            if !task_ids.contains(&output.task_id) {
                return Err(PersistenceError::Invalid(
                    "output for unknown task".to_owned(),
                ));
            }
            if !output_ids.insert(output.task_id.clone()) {
                return Err(PersistenceError::Invalid(
                    "duplicate task output".to_owned(),
                ));
            }
            validate_output(&output.output, &global_assets)?;
        }
        validate_registries(&self.registries)?;
        Ok(())
    }

    pub fn metrics(&self, checkpoint_bytes: u64, elapsed_ms: u128) -> CheckpointMetrics {
        let mut assets = BTreeSet::new();
        let mut relationships = 0usize;
        let mut evidence = 0usize;
        let mut findings = 0usize;
        for output in &self.outputs {
            for asset in &output.output.assets {
                assets.insert(asset.id.clone());
            }
            relationships += output
                .output
                .events
                .iter()
                .map(|event| event.relationships.len())
                .sum::<usize>();
            evidence += output.output.evidence.len();
            findings += output.output.findings.len();
        }
        let completed = self
            .tasks
            .iter()
            .filter(|task| matches!(task.task.state, TaskState::Succeeded))
            .count();
        let pending = self
            .tasks
            .iter()
            .filter(|task| !matches!(task.task.state, TaskState::Succeeded))
            .count();
        CheckpointMetrics {
            assets_persisted: assets.len(),
            relationships_persisted: relationships,
            evidence_persisted: evidence,
            findings_persisted: findings,
            completed_tasks_persisted: completed,
            pending_tasks_persisted: pending,
            registry_entries_persisted: self.registries.entry_count(),
            checkpoint_bytes,
            elapsed_ms,
        }
    }
}

impl PersistedRegistries {
    pub fn from_runtime(
        contacts: &ContactRegistry,
        baselines: &OriginBaselineRegistry,
        fuzz: &FuzzOriginBudget,
        dns: &DnsRegistry,
    ) -> Self {
        Self {
            contacts: contacts.snapshot(),
            origin_baselines: baselines.snapshot(),
            fuzz_origin_budgets: fuzz.snapshot(),
            dns_queries: dns.snapshot_queries(),
            dns_domains: dns.snapshot_domains(),
        }
    }

    pub fn entry_count(&self) -> usize {
        self.contacts.len()
            + self.origin_baselines.len()
            + self
                .fuzz_origin_budgets
                .iter()
                .map(|(_, v)| v.len())
                .sum::<usize>()
            + self.dns_queries.len()
            + self
                .dns_domains
                .iter()
                .map(|d| d.names.len())
                .sum::<usize>()
    }

    pub fn restore_contact_registry(&self) -> Result<ContactRegistry, PersistenceError> {
        ContactRegistry::restore(&self.contacts).map_err(PersistenceError::Invalid)
    }

    pub fn restore_origin_baselines(&self) -> Result<OriginBaselineRegistry, PersistenceError> {
        OriginBaselineRegistry::restore(&self.origin_baselines).map_err(PersistenceError::Invalid)
    }

    pub fn restore_fuzz_budget(&self) -> Result<FuzzOriginBudget, PersistenceError> {
        FuzzOriginBudget::restore(&self.fuzz_origin_budgets).map_err(PersistenceError::Invalid)
    }

    pub fn restore_dns_registry(&self) -> Result<DnsRegistry, PersistenceError> {
        DnsRegistry::restore(&self.dns_queries, &self.dns_domains)
            .map_err(PersistenceError::Invalid)
    }
}

pub fn save_checkpoint(
    path: &Path,
    state: &PersistedScanState,
) -> Result<CheckpointMetrics, PersistenceError> {
    state.validate()?;
    let started = Instant::now();
    // Phase 19: stream serialization straight to the temp file instead of
    // materializing the whole checkpoint as an in-RAM `Vec<u8>` first.
    // `to_writer_pretty` uses the same pretty formatter as `to_vec_pretty`,
    // so on-disk bytes are unchanged; peak save memory drops from
    // O(checkpoint) buffer + file write to an 8 KiB stream buffer.
    // The size cap is enforced from the finished temp file (removed on
    // overflow) instead of from the former intermediate buffer.
    let tmp = temp_path(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    {
        let file = File::create(&tmp)?;
        let mut writer = std::io::BufWriter::with_capacity(8192, file);
        if let Err(error) = serde_json::to_writer_pretty(&mut writer, state) {
            drop(writer);
            let _ = fs::remove_file(&tmp);
            return Err(PersistenceError::Json(error));
        }
        if let Err(error) = writer.flush().and_then(|()| writer.get_ref().sync_all()) {
            drop(writer);
            let _ = fs::remove_file(&tmp);
            return Err(PersistenceError::Io(error));
        }
    }
    let size = fs::metadata(&tmp).map(|meta| meta.len()).unwrap_or(0);
    if size > MAX_CHECKPOINT_BYTES {
        let _ = fs::remove_file(&tmp);
        return Err(PersistenceError::SizeLimit);
    }
    fs::rename(&tmp, path)?;
    Ok(state.metrics(size, started.elapsed().as_millis()))
}

pub fn load_checkpoint(path: &Path) -> Result<LoadedCheckpoint, PersistenceError> {
    let started = Instant::now();
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_CHECKPOINT_BYTES {
        return Err(PersistenceError::SizeLimit);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(MAX_CHECKPOINT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CHECKPOINT_BYTES {
        return Err(PersistenceError::SizeLimit);
    }
    let state: PersistedScanState = serde_json::from_slice(&bytes)?;
    state.validate()?;
    Ok(LoadedCheckpoint {
        state,
        load_ms: started.elapsed().as_millis(),
        checkpoint_bytes: bytes.len() as u64,
    })
}

pub fn restore_scheduler_state(
    scheduler: &mut Scheduler,
    state: &PersistedScanState,
) -> Result<(usize, usize), PersistenceError> {
    state.validate()?;
    let outputs = state
        .outputs
        .iter()
        .map(|output| (output.task_id.clone(), output.output.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut restored = 0usize;
    let mut completed = 0usize;
    for persisted in &state.tasks {
        let output = outputs.get(&persisted.task.id).cloned();
        if matches!(persisted.task.state, TaskState::Succeeded) {
            completed += 1;
        }
        scheduler.restore_task(persisted.task.clone(), output)?;
        restored += 1;
    }
    Ok((restored, completed))
}

fn validate_task(
    task: &Task,
    guard: &PolicyScopeGuard,
    seen: &mut BTreeSet<crate::execution::TaskId>,
) -> Result<(), PersistenceError> {
    validate_id(&task.id.0, "task id")?;
    validate_id(&task.module_name, "module name")?;
    if !task.identity_is_valid() {
        return Err(PersistenceError::Invalid(
            "task identity mismatch".to_owned(),
        ));
    }
    if !seen.insert(task.id.clone()) {
        return Err(PersistenceError::Invalid("duplicate task id".to_owned()));
    }
    if !guard.permits(&task.scope_target) {
        return Err(PersistenceError::Invalid(
            "task outside persisted scope".to_owned(),
        ));
    }
    if task.scan_plan_id.0.len() > MAX_ID_BYTES || task.params.len() > 64 {
        return Err(PersistenceError::Invalid(
            "task payload too large".to_owned(),
        ));
    }
    for (key, value) in &task.params {
        if key.len() > 128 || value.len() > 4096 || key.contains('\0') || value.contains('\0') {
            return Err(PersistenceError::Invalid("invalid task param".to_owned()));
        }
        if contains_forbidden_persisted_marker(key) || contains_forbidden_persisted_marker(value) {
            return Err(PersistenceError::Invalid(
                "sensitive task param cannot be checkpointed".to_owned(),
            ));
        }
    }
    Ok(())
}

fn collect_global_assets(
    outputs: &[PersistedModuleOutput],
) -> Result<BTreeMap<AssetId, Asset>, PersistenceError> {
    let mut assets: BTreeMap<AssetId, Asset> = BTreeMap::new();
    for persisted in outputs {
        for asset in &persisted.output.assets {
            validate_id(&asset.id.0, "asset id")?;
            if contains_forbidden_persisted_marker(&asset.identity) {
                return Err(PersistenceError::Invalid(
                    "sensitive asset identity cannot be checkpointed".to_owned(),
                ));
            }
            if let Some(existing) = assets.get(&asset.id) {
                // Phase 20: same stable ID re-observed (overlapping port
                // tasks, same URL seen by http/baseline/content modules) is
                // the engine's normal follow-up behavior, not spoofing.
                // Merge deterministically: first record wins for
                // kind/identity/attributes/provenance (outputs iterate in
                // task-ID order), timestamps span the observations. A
                // different KIND under one ID is still rejected: asset IDs
                // embed their kind, so that shape cannot arise legitimately.
                if existing.kind != asset.kind {
                    return Err(PersistenceError::Invalid(
                        "conflicting duplicate asset id".to_owned(),
                    ));
                }
                let mut merged = existing.clone();
                merged.first_seen = merged.first_seen.min(asset.first_seen);
                merged.last_seen = merged.last_seen.max(asset.last_seen);
                for (key, value) in &asset.attributes {
                    merged
                        .attributes
                        .entry(key.clone())
                        .or_insert_with(|| value.clone());
                }
                assets.insert(asset.id.clone(), merged);
            } else {
                assets.insert(asset.id.clone(), asset.clone());
            }
        }
    }
    validate_persisted_collection_counts(PersistedCollectionCounts {
        assets: assets.len(),
        ..PersistedCollectionCounts::default()
    })?;
    Ok(assets)
}

fn validate_output(
    output: &ModuleOutput,
    global_assets: &BTreeMap<AssetId, Asset>,
) -> Result<(), PersistenceError> {
    let relationship_count = output
        .events
        .iter()
        .map(|event| event.relationships.len())
        .sum::<usize>();
    validate_persisted_collection_counts(PersistedCollectionCounts {
        assets: output.assets.len(),
        relationships: relationship_count,
        events: output.events.len(),
        evidence: output.evidence.len(),
        findings: output.findings.len(),
        ..PersistedCollectionCounts::default()
    })?;
    let assets = output
        .assets
        .iter()
        .map(|asset| asset.id.clone())
        .collect::<BTreeSet<AssetId>>();
    if assets.len() != output.assets.len() {
        return Err(PersistenceError::Invalid("duplicate asset id".to_owned()));
    }
    for event in &output.events {
        validate_details_for_persistence(&event.details.data)?;
        if let Some(asset_id) = &event.asset_id {
            if !global_assets.contains_key(asset_id) {
                return Err(PersistenceError::Invalid("event asset missing".to_owned()));
            }
        }
    }
    for event in &output.events {
        for rel in &event.relationships {
            if let (
                crate::model::RelationshipSubject::Asset(source),
                crate::model::RelationshipSubject::Asset(target),
            ) = (&rel.from, &rel.to)
            {
                if !global_assets.contains_key(source) || !global_assets.contains_key(target) {
                    return Err(PersistenceError::Invalid(
                        "dangling asset relationship".to_owned(),
                    ));
                }
            }
        }
    }
    for evidence in &output.evidence {
        validate_details_for_persistence(&evidence.details.data)?;
        if !global_assets.contains_key(&evidence.asset_id) {
            return Err(PersistenceError::Invalid(
                "evidence asset missing".to_owned(),
            ));
        }
    }
    for finding in &output.findings {
        if contains_forbidden_persisted_marker(&finding.title)
            || finding.metadata.values().any(|value| {
                serde_json::to_string(value).is_ok_and(|s| contains_forbidden_persisted_marker(&s))
            })
        {
            return Err(PersistenceError::Invalid(
                "sensitive finding data cannot be checkpointed".to_owned(),
            ));
        }
        if !global_assets.contains_key(&finding.affected_asset_id) {
            return Err(PersistenceError::Invalid(
                "finding asset missing".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_registries(registries: &PersistedRegistries) -> Result<(), PersistenceError> {
    registries.restore_contact_registry()?;
    registries.restore_origin_baselines()?;
    registries.restore_fuzz_budget()?;
    registries.restore_dns_registry()?;
    Ok(())
}

pub fn validate_persisted_collection_counts(
    counts: PersistedCollectionCounts,
) -> Result<(), PersistenceError> {
    let checks = [
        ("tasks", counts.tasks, MAX_PERSISTED_TASKS),
        ("outputs", counts.outputs, MAX_PERSISTED_OUTPUTS),
        ("assets", counts.assets, MAX_PERSISTED_ASSETS),
        (
            "relationships",
            counts.relationships,
            MAX_PERSISTED_RELATIONSHIPS,
        ),
        ("events", counts.events, MAX_PERSISTED_EVENTS),
        ("evidence", counts.evidence, MAX_PERSISTED_EVIDENCE),
        ("findings", counts.findings, MAX_PERSISTED_FINDINGS),
    ];
    for (label, actual, limit) in checks {
        if actual > limit {
            return Err(PersistenceError::Invalid(format!(
                "too many persisted {label}"
            )));
        }
    }
    Ok(())
}

fn validate_id(value: &str, label: &str) -> Result<(), PersistenceError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES || value.contains('\0') {
        return Err(PersistenceError::Invalid(format!("invalid {label}")));
    }
    Ok(())
}

fn validate_details_for_persistence(value: &serde_json::Value) -> Result<(), PersistenceError> {
    let serialized = serde_json::to_string(value)?;
    if contains_forbidden_persisted_marker(&serialized) {
        return Err(PersistenceError::Invalid(
            "sensitive or raw marker cannot be checkpointed".to_owned(),
        ));
    }
    Ok(())
}

fn contains_forbidden_persisted_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "authorization:",
        "cookie:",
        "password=",
        "csrf",
        "raw_http_body_marker",
        "raw_dns_packet_marker",
        "phase14_secret",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_else(|| "checkpoint".into());
    name.push(".tmp");
    path.with_file_name(name)
}
