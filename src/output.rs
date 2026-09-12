//! Phase 4 runtime JSONL output.
//!
//! Reuses the Phase 2 typed data model; no second serialization model.
//! Every line is valid JSON, carries `schema_version`, carries provenance,
//! is bounded (writer byte cap), reports I/O errors cleanly, and never
//! panics on filesystem errors.
//!
//! Supported records: `SchedulerEvent`, `Event`, `Evidence`, `Finding`,
//! `Relationship`, `Asset`. Each is written as an envelope:
//!
//! ```json
//! {"schema_version":1,"record_type":"scheduler_event","payload":{...}}
//! ```
//!
//! The envelope guarantees a uniform `schema_version` even for records
//! whose inner struct predates versioning, while `payload` round-trips to
//! the original typed struct.

use std::{
    fs::File,
    io::{self, BufWriter, Write},
    path::Path,
};

use serde::Serialize;
use thiserror::Error;

use crate::{
    execution::SchedulerEvent,
    model::{Asset, Event, Evidence, Finding, Relationship, SCHEMA_VERSION},
};

#[derive(Debug, Error)]
pub enum OutputError {
    #[error("could not create output file '{path}': {source}")]
    Create { path: String, source: io::Error },
    #[error("could not write JSONL output: {0}")]
    Write(String),
    #[error("output byte budget exceeded ({actual} > {limit})")]
    BudgetExceeded { actual: u64, limit: u64 },
    #[error("could not serialize record: {0}")]
    Serialization(String),
}

/// Envelope shared by every JSONL line.
#[derive(Debug, Clone, Serialize)]
struct Envelope<T: Serialize> {
    schema_version: u16,
    record_type: &'static str,
    payload: T,
}

/// Bounded JSONL writer over any `Write`.
pub struct JsonlWriter<W: Write> {
    inner: BufWriter<W>,
    bytes_written: u64,
    max_bytes: u64,
}

impl<W: Write> JsonlWriter<W> {
    pub fn new(writer: W, max_bytes: u64) -> Self {
        Self {
            inner: BufWriter::new(writer),
            bytes_written: 0,
            max_bytes: max_bytes.max(1),
        }
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    fn write_envelope<T: Serialize>(
        &mut self,
        record_type: &'static str,
        payload: &T,
    ) -> Result<(), OutputError> {
        let envelope = Envelope {
            schema_version: SCHEMA_VERSION,
            record_type,
            payload,
        };
        let mut line = serde_json::to_string(&envelope)
            .map_err(|error| OutputError::Serialization(error.to_string()))?;
        if line.contains('\n') {
            return Err(OutputError::Serialization(
                "record serialized with embedded newline".to_owned(),
            ));
        }
        line.push('\n');
        let next = self.bytes_written.saturating_add(line.len() as u64);
        if next > self.max_bytes {
            return Err(OutputError::BudgetExceeded {
                actual: next,
                limit: self.max_bytes,
            });
        }
        self.inner
            .write_all(line.as_bytes())
            .map_err(|error| OutputError::Write(error.to_string()))?;
        self.bytes_written = next;
        Ok(())
    }

    pub fn write_scheduler_event(&mut self, event: &SchedulerEvent) -> Result<(), OutputError> {
        self.write_envelope("scheduler_event", event)
    }
    pub fn write_event(&mut self, event: &Event) -> Result<(), OutputError> {
        self.write_envelope("event", event)
    }
    pub fn write_evidence(&mut self, evidence: &Evidence) -> Result<(), OutputError> {
        self.write_envelope("evidence", evidence)
    }
    pub fn write_finding(&mut self, finding: &Finding) -> Result<(), OutputError> {
        self.write_envelope("finding", finding)
    }
    pub fn write_relationship(&mut self, relationship: &Relationship) -> Result<(), OutputError> {
        self.write_envelope("relationship", relationship)
    }
    pub fn write_asset(&mut self, asset: &Asset) -> Result<(), OutputError> {
        self.write_envelope("asset", asset)
    }

    pub fn flush(&mut self) -> Result<(), OutputError> {
        self.inner
            .flush()
            .map_err(|error| OutputError::Write(error.to_string()))
    }
}

/// Create a file-backed JSONL writer. Never panics; filesystem errors are
/// returned as [`OutputError::Create`].
pub fn create_file_writer(path: &Path, max_bytes: u64) -> Result<JsonlWriter<File>, OutputError> {
    let file = File::create(path).map_err(|source| OutputError::Create {
        path: path.display().to_string(),
        source,
    })?;
    Ok(JsonlWriter::new(file, max_bytes))
}

/// Parse one envelope line back into its payload type. Used by round-trip tests.
pub fn parse_envelope_payload<T>(line: &str) -> Result<(u16, String, T), String>
where
    T: serde::de::DeserializeOwned,
{
    let value: serde_json::Value = serde_json::from_str(line).map_err(|error| error.to_string())?;
    let schema_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "missing schema_version".to_owned())? as u16;
    let record_type = value
        .get("record_type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing record_type".to_owned())?
        .to_owned();
    let payload_value = value
        .get("payload")
        .ok_or_else(|| "missing payload".to_owned())?
        .clone();
    let payload: T = serde_json::from_value(payload_value).map_err(|error| error.to_string())?;
    Ok((schema_version, record_type, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_carries_version_and_round_trips() {
        let event = SchedulerEvent {
            schema_version: SCHEMA_VERSION,
            kind: crate::execution::SchedulerEventKind::TaskCreated,
            task_id: crate::execution::TaskId("task_abc".to_owned()),
            state: crate::execution::TaskState::Pending,
            timestamp: crate::model::Timestamp(1),
            provenance: crate::model::Provenance::new(
                "test",
                "4.0.0",
                crate::model::ScanPlanId("plan_x".to_owned()),
                crate::model::Timestamp(1),
            )
            .unwrap(),
            reason: None,
        };
        let mut buffer = Vec::new();
        {
            let mut writer = JsonlWriter::new(&mut buffer, 1024 * 1024);
            writer.write_scheduler_event(&event).unwrap();
            writer.flush().unwrap();
        }
        let line = String::from_utf8(buffer).unwrap();
        assert!(!line.trim_end().contains('\n'));
        let (version, record_type, parsed): (u16, String, SchedulerEvent) =
            parse_envelope_payload(line.trim_end()).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        assert_eq!(record_type, "scheduler_event");
        assert_eq!(parsed, event);
    }
}
