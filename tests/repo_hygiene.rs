//! Repository hygiene regression tests (offline, deterministic).
//!
//! Guards the remediation pass: no unrelated portfolio content is tracked
//! or packaged, runtime state is excluded, provider verification
//! contradictions fail lint, and documentation local links resolve.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn tracked_files() -> Vec<String> {
    let output = Command::new("git")
        .args(["ls-files"])
        .current_dir(repo_root())
        .output()
        .expect("git ls-files runs");
    assert!(
        output.status.success(),
        "git ls-files must succeed in the repository checkout"
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn no_portfolio_files_are_tracked() {
    let tracked = tracked_files();
    let forbidden_prefixes = [
        "index.html",
        "js/",
        "css/",
        "_headers",
        "certificates/",
        "portfolio/",
        "site/",
    ];
    for path in &tracked {
        for prefix in forbidden_prefixes {
            assert!(
                !path.starts_with(prefix),
                "portfolio/personal-site path must not be tracked: {path}"
            );
        }
    }
    // The RXScan GUI is the only web UI and it stays.
    assert!(
        tracked.iter().any(|p| p == "app/index.html"),
        "RXScan GUI app/index.html must remain tracked"
    );
    assert!(
        tracked.iter().any(|p| p == "app/rxscan.js"),
        "RXScan GUI app/rxscan.js must remain tracked"
    );
    assert!(
        tracked.iter().any(|p| p == "app/rxscan.css"),
        "RXScan GUI app/rxscan.css must remain tracked"
    );
}

#[test]
fn no_runtime_state_or_env_is_tracked() {
    let tracked = tracked_files();
    for path in &tracked {
        assert!(
            !path.starts_with(".rxscan-web/"),
            "runtime GUI state must not be tracked: {path}"
        );
        assert!(
            !path.ends_with(".sqlite")
                && !path.ends_with(".sqlite-journal")
                && !path.ends_with(".db")
                && !path.ends_with(".log"),
            "runtime database/log state must not be tracked: {path}"
        );
        assert!(
            Path::new(path)
                .file_name()
                .map(|n| n != ".env")
                .unwrap_or(true),
            ".env files must never be tracked: {path}"
        );
    }
}

#[test]
fn machine_specific_absolute_paths_are_forbidden_lists_only() {
    // Tests/docs may mention absolute-path markers only as forbidden-path
    // fixtures or redaction assertions — never as real operator paths.
    // This is a smoke check that the markers stay synthetic.
    let content = std::fs::read_to_string(repo_root().join("tests/web_api.rs"))
        .expect("tests/web_api.rs reads");
    assert!(
        content.contains("/home/") || content.contains("/Users/"),
        "web API tests must keep asserting machine-path redaction"
    );
}

#[test]
fn cargo_packaging_policy_exists() {
    let manifest =
        std::fs::read_to_string(repo_root().join("Cargo.toml")).expect("Cargo.toml reads");
    assert!(
        manifest.contains("include = ["),
        "Cargo.toml must declare an explicit packaging include policy"
    );
    assert!(
        manifest.contains("\"app/**/*\""),
        "packaging must include the RXScan GUI"
    );
    assert!(
        manifest.contains("\"search/**/*\""),
        "packaging must include the provider corpus"
    );
    assert!(
        manifest.contains("\"fingerprints/**/*\""),
        "packaging must include fingerprint packs"
    );
    assert!(
        manifest.contains("\"CONTRIBUTING.md\""),
        "packaging must include the root contribution guide"
    );
    assert!(
        manifest.contains(".rxscan-web/**"),
        "packaging must exclude runtime GUI state"
    );
    for forbidden in [
        "index.html",
        "js/**",
        "css/**",
        "_headers",
        "certificates/**",
    ] {
        assert!(
            manifest.contains(forbidden),
            "packaging must exclude portfolio remnant {forbidden}"
        );
    }
}

#[test]
fn documentation_local_links_resolve() {
    // README links.
    for link in ["docs/ROADMAP.md", "CONTRIBUTING.md", "LICENSE"] {
        assert!(
            repo_root().join(link).exists(),
            "README link target must exist: {link}"
        );
    }
    // The canonical guide lives at root; no stale docs/ copy may remain.
    assert!(
        !repo_root().join("docs/CONTRIBUTING.md").exists(),
        "stale docs/CONTRIBUTING.md must not remain after the root move"
    );
    // Every docs/benchmark-results reference in planning docs must resolve.
    let planning = [
        "docs/ROADMAP.md",
        "docs/IMPLEMENTATION_STATUS.md",
        "docs/BENCHMARK_PLAN.md",
    ];
    for doc in planning {
        let text = std::fs::read_to_string(repo_root().join(doc)).expect("planning doc reads");
        for line in text.lines() {
            for token in line.split_whitespace() {
                let token = token.trim_matches(|c| "(),[]\"'`".contains(c));
                if token.starts_with("docs/benchmark-results/") && token.ends_with(".md") {
                    assert!(
                        repo_root().join(token).exists(),
                        "{doc} references missing benchmark path: {token}"
                    );
                }
            }
        }
    }
    // GUI logo referenced by the embedded app must exist on disk.
    assert!(
        repo_root().join("app/assets/RXScanlogo.png").exists(),
        "embedded GUI logo must exist"
    );
    assert!(
        repo_root().join("RXScanlogo.png").exists(),
        "repository branding logo must exist"
    );
}
#[test]
fn provider_contradictions_fail_lint() {
    // A live_verified claim with provisional notes must be a lint error,
    // not a warning. This mirrors the unit coverage in src/search.rs and
    // pins the behavior at the repository-gate level.
    let output = Command::new(env!("CARGO_BIN_EXE_rxscan"))
        .args(["search", "lint"])
        .current_dir(repo_root())
        .output()
        .expect("rxscan search lint runs");
    assert!(output.status.success(), "embedded corpus lint must pass");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("errors") && stdout.contains("0"),
        "lint must report zero errors on the remediated corpus: {stdout}"
    );
}

#[test]
fn search_sigint_cancellation_has_process_lifetime() {
    // The SIGINT handler is process-global and permanent, so the flag it
    // touches must outlive every stack frame: a raw pointer to a
    // search-local AtomicBool dangles once run_search returns, and the
    // pointer itself races the async handler. The fix is a process-lifetime
    // static atomic in platform::process reused by main.rs — pin that design.
    let platform = std::fs::read_to_string(repo_root().join("src/platform/process.rs"))
        .expect("process.rs reads")
        // Windows checkouts may carry CRLF (no eol attribute pins these
        // sources); normalize so brace-boundary parsing is portable.
        .replace("\r\n", "\n");
    assert!(
        platform.contains("static PROCESS_CANCELLED: AtomicBool"),
        "process cancellation must use a process-lifetime static atomic"
    );
    assert!(
        !platform.contains("static mut "),
        "unsynchronized mutable raw-pointer cancellation state must not return"
    );
    assert!(
        !platform.contains("AtomicPtr"),
        "casual AtomicPtr<Arc> must not appear in signal state"
    );
    assert!(
        !platform.contains("HANDLER_FLAG") || platform.contains("PROCESS_CANCELLED"),
        "legacy mirror flag must be gone"
    );
    assert!(
        !platform.contains("OnceLock<Arc<AtomicBool>>"),
        "Windows OnceLock-first-flag bug must not return"
    );
    // Handler bodies must stay a single atomic store.
    for marker in [
        "extern \"C\" fn unix_cancel_handler",
        "windows_cancel_handler",
    ] {
        let start = platform
            .find(marker)
            .unwrap_or_else(|| panic!("handler {marker} exists"));
        let body = &platform[start..];
        let end = body.find("\n}\n").expect("handler body ends") + 3;
        let body = &body[..end];
        assert!(
            body.contains("PROCESS_CANCELLED.store(true"),
            "handler must set process state: {body}"
        );
        for forbidden in ["format!", "println!", "Mutex", "write!", "Box::", "Arc::"] {
            assert!(
                !body.contains(forbidden),
                "signal handler must not contain {forbidden}: {body}"
            );
        }
    }
    // main.rs must reuse the platform state, not duplicate handlers.
    let cli = std::fs::read_to_string(repo_root().join("src/main.rs"))
        .expect("src/main.rs reads")
        .replace("\r\n", "\n");
    assert!(
        !cli.contains("static SEARCH_CANCELLED"),
        "main.rs must not duplicate process state"
    );
    assert!(
        !cli.contains("SEARCH_CANCEL_FLAG"),
        "no raw-pointer cancellation state may remain"
    );
    assert!(
        !cli.contains("fn search_cancel_handler"),
        "main.rs must not duplicate the signal handler"
    );
    assert!(
        cli.contains("platform::process::install_process_cancellation")
            || cli.contains("install_process_cancellation"),
        "main.rs must reuse platform cancellation"
    );
    assert!(
        cli.contains("process_cancel_flag"),
        "search must consume process state directly"
    );
}
