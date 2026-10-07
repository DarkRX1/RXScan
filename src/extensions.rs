//! Typed extension architecture: prevents the core from becoming an
//! enormous match statement without allowing arbitrary unsafe code loading.
//!
//! Extension types:
//! * service fingerprint packs (`fingerprints/v1/*.json`)
//! * OS packs (`fingerprints/os/v1/*.json`)
//! * device packs (`fingerprints/device/v1/*.json`)
//! * search provider packs (`search/providers/v1/*/*.json`)
//! * passive intelligence datasets (vuln `RXSCAN_VULN_DIR`, exposure local)
//!
//! Loading is typed/validated: schema version check, deterministic errors,
//! provenance preserved, version compatibility enforced. No dynamic library
//! loading, no `dlopen`, no WASM execution by default.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionMeta {
    pub kind: String,
    pub schema_version: u32,
    pub pack_version: Option<String>,
    pub path: String,
    pub items: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionError {
    MissingDirectory(String),
    MalformedFile {
        path: String,
        detail: String,
    },
    SchemaMismatch {
        path: String,
        expected: u32,
        found: u32,
    },
    DuplicateId {
        path: String,
        id: String,
    },
}

impl std::fmt::Display for ExtensionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingDirectory(path) => write!(f, "extension directory missing: {path}"),
            Self::MalformedFile { path, detail } => {
                write!(f, "extension file {path} malformed: {detail}")
            }
            Self::SchemaMismatch {
                path,
                expected,
                found,
            } => {
                write!(
                    f,
                    "extension file {path} schema {found} != expected {expected}"
                )
            }
            Self::DuplicateId { path, id } => {
                write!(f, "extension file {path} duplicate id '{id}'")
            }
        }
    }
}

/// Validate a directory of JSON packs deterministically: sorted filenames,
///
/// bounded reads, per-file schema check via `check` callback. Returns
/// per-file metadata in sorted order. Missing dir yields empty (not an
/// error); malformed files are reported deterministically.
pub fn validate_pack_dir(
    dir: &Path,
    expected_schema: u32,
    check: impl Fn(&serde_json::Value) -> Result<(u32, usize), String>,
) -> (Vec<ExtensionMeta>, Vec<ExtensionError>) {
    let mut metas = Vec::new();
    let mut errors = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return (metas, errors),
    };
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            files.push(path);
        }
    }
    files.sort();
    for path in files {
        let label = path.display().to_string();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                errors.push(ExtensionError::MalformedFile {
                    path: label,
                    detail: error.to_string(),
                });
                continue;
            }
        };
        if text.len() > 4 * 1024 * 1024 {
            errors.push(ExtensionError::MalformedFile {
                path: label,
                detail: "file exceeds 4 MiB".to_owned(),
            });
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(error) => {
                errors.push(ExtensionError::MalformedFile {
                    path: label,
                    detail: error.to_string(),
                });
                continue;
            }
        };
        match check(&value) {
            Ok((schema, items)) => {
                if schema != expected_schema {
                    errors.push(ExtensionError::SchemaMismatch {
                        path: label,
                        expected: expected_schema,
                        found: schema,
                    });
                    continue;
                }
                let pack_version = value
                    .get("pack_version")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                metas.push(ExtensionMeta {
                    kind: dir
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    schema_version: schema,
                    pack_version,
                    path: label,
                    items,
                });
            }
            Err(detail) => errors.push(ExtensionError::MalformedFile {
                path: label,
                detail,
            }),
        }
    }
    (metas, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_dir_is_empty_not_error() {
        let (metas, errors) =
            validate_pack_dir(Path::new("/nonexistent/rxscan-ext-test"), 1, |_| Ok((1, 0)));
        assert!(metas.is_empty());
        assert!(errors.is_empty());
    }

    #[test]
    fn malformed_and_schema_mismatch_are_deterministic() {
        let base =
            std::env::temp_dir().join(format!("rxscan-ext-{}-{}", std::process::id(), "validate"));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("a.json"), b"{bad").unwrap();
        std::fs::write(
            base.join("b.json"),
            serde_json::json!({"schema_version": 99}).to_string(),
        )
        .unwrap();
        std::fs::write(
            base.join("c.json"),
            serde_json::json!({"schema_version": 1}).to_string(),
        )
        .unwrap();
        let (metas, errors) = validate_pack_dir(&base, 1, |v| {
            let schema = v
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
                .ok_or("missing schema_version".to_owned())?;
            Ok((schema as u32, 0))
        });
        assert_eq!(metas.len(), 1);
        assert_eq!(errors.len(), 2);
        // Deterministic: sorted filenames, a.json error before b.json.
        assert!(errors[0].to_string().contains("a.json"));
        assert!(errors[1].to_string().contains("b.json"));
        let _ = std::fs::remove_dir_all(&base);
    }
}
