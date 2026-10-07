//! Portable filesystem / config / state locations.
//!
//! Never hardcodes Unix home directories or string-concatenates paths.
//! Uses XDG on Linux, known folders on Windows/macOS, and Termux-accessible
//! locations on Android. Existing state is never silently abandoned:
//! `resolve_web_data_dir` prefers an explicit path, then migrates or reuses
//! the legacy `.rxscan-web` directory when present.

use std::path::{Path, PathBuf};

fn home_dir() -> Option<PathBuf> {
    // Portable HOME lookup without a new dependency: Unix HOME, Windows
    // USERPROFILE, then HOMEDRIVE+HOMEPATH.
    if let Some(home) = std::env::var_os("HOME") {
        let path = PathBuf::from(home);
        if !path.as_os_str().is_empty() {
            return Some(path);
        }
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        let path = PathBuf::from(profile);
        if !path.as_os_str().is_empty() {
            return Some(path);
        }
    }
    match (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH")) {
        (Some(drive), Some(path)) => {
            let mut full = PathBuf::from(drive);
            full.push(path);
            if !full.as_os_str().is_empty() {
                return Some(full);
            }
            None
        }
        _ => None,
    }
}

/// Legacy web data directory (current default). Preserved for migration.
pub fn legacy_web_data_dir() -> PathBuf {
    PathBuf::from(".rxscan-web")
}

pub fn app_name() -> &'static str {
    "rxscan"
}

/// XDG-compatible config dir on Linux, known folders elsewhere.
pub fn config_dir() -> Option<PathBuf> {
    if crate::platform::network::is_termux() {
        if let Some(home) = home_dir() {
            return Some(home.join(".config").join(app_name()));
        }
        return None;
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(base) = std::env::var_os("APPDATA").map(PathBuf::from) {
            return Some(base.join("rxscan"));
        }
        if let Some(home) = home_dir() {
            return Some(home.join("AppData").join("Roaming").join("rxscan"));
        }
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = home_dir() {
            return Some(
                home.join("Library")
                    .join("Application Support")
                    .join("rxscan"),
            );
        }
        return None;
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.trim().is_empty() {
                return Some(PathBuf::from(xdg).join(app_name()));
            }
        }
        home_dir().map(|h| h.join(".config").join(app_name()))
    }
}

/// Writable data dir (projects, history). Never abandons legacy state.
pub fn data_dir() -> Option<PathBuf> {
    if crate::platform::network::is_termux() {
        if let Some(home) = home_dir() {
            return Some(home.join(".local").join("share").join(app_name()));
        }
        return None;
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(base) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            return Some(base.join("rxscan"));
        }
        if let Some(home) = home_dir() {
            return Some(home.join("AppData").join("Local").join("rxscan"));
        }
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = home_dir() {
            return Some(
                home.join("Library")
                    .join("Application Support")
                    .join("rxscan"),
            );
        }
        return None;
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            if !xdg.trim().is_empty() {
                return Some(PathBuf::from(xdg).join(app_name()));
            }
        }
        home_dir().map(|h| h.join(".local").join("share").join(app_name()))
    }
}

pub fn cache_dir() -> Option<PathBuf> {
    if crate::platform::network::is_termux() {
        if let Some(home) = home_dir() {
            return Some(home.join(".cache").join(app_name()));
        }
        return None;
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(base) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            return Some(base.join("rxscan").join("cache"));
        }
        return data_dir().map(|d| d.join("cache"));
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = home_dir() {
            return Some(home.join("Library").join("Caches").join("rxscan"));
        }
        return None;
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
            if !xdg.trim().is_empty() {
                return Some(PathBuf::from(xdg).join(app_name()));
            }
        }
        home_dir().map(|h| h.join(".cache").join(app_name()))
    }
}

/// Resolve the web data directory: explicit `--data-dir` wins; otherwise
/// reuse legacy `.rxscan-web` when it already exists (never abandon
/// projects), else use the platform data dir, else legacy.
pub fn resolve_web_data_dir(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(dir) = explicit {
        return dir;
    }
    let legacy = legacy_web_data_dir();
    if legacy.exists() {
        return legacy;
    }
    if let Some(mut base) = data_dir() {
        base.push("web");
        return base;
    }
    legacy
}

/// Migrate legacy state to the platform location when safe:
/// detect old, copy-or-move safely, preserve source until success.
/// Returns the active directory. Never deletes the source on failure.
pub fn migrate_web_data_dir(old: &Path, new: &Path) -> std::io::Result<PathBuf> {
    if !old.exists() || new.exists() {
        return Ok(if new.exists() {
            new.to_path_buf()
        } else {
            old.to_path_buf()
        });
    }
    if let Some(parent) = new.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Best-effort recursive copy; source preserved until rename/copy ok.
    copy_dir_recursive(old, new)?;
    Ok(new.to_path_buf())
}

fn copy_dir_recursive(old: &Path, new: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(new)?;
    for entry in std::fs::read_dir(old)? {
        let entry = entry?;
        let target = new.join(entry.file_name());
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_construction_uses_pathbuf_never_string_concat() {
        let explicit = PathBuf::from("custom-dir");
        assert_eq!(resolve_web_data_dir(Some(explicit.clone())), explicit);
        // No explicit: returns a valid path, never empty.
        let resolved = resolve_web_data_dir(None);
        assert!(!resolved.as_os_str().is_empty());
    }

    #[test]
    fn dirs_never_panic() {
        let _ = config_dir();
        let _ = data_dir();
        let _ = cache_dir();
        assert!(!legacy_web_data_dir().as_os_str().is_empty());
    }

    #[test]
    fn migration_preserves_source_on_success() {
        let base = std::env::temp_dir().join(format!(
            "rxscan-migrate-{}-{}",
            std::process::id(),
            "portable"
        ));
        let old = base.join("old");
        let new = base.join("new");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("keep.txt"), b"evidence").unwrap();
        let active = migrate_web_data_dir(&old, &new).unwrap();
        assert_eq!(active, new);
        // Source preserved until successful (copy semantics).
        assert!(old.join("keep.txt").exists());
        assert!(new.join("keep.txt").exists());
        let _ = std::fs::remove_dir_all(&base);
    }
}
