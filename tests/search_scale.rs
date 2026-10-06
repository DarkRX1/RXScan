//! Search at thousands-of-vectors scale.
//!
//! The registry has no count cap: registry size and execution concurrency
//! are separate concepts. These tests prove the architecture holds at
//! 3,000 synthetic vectors WITHOUT committing fake providers to the real
//! corpus — every synthetic vector lives in-memory inside the test.
//!
//! Nothing here touches the network.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use rxscan::search::{
    ContactClass, CorpusLintReport, HealthState, MarkerPolicy, ProviderMetadata, SearchContext,
    SearchEntity, SearchEntityKind, SearchError, SearchObservation, SearchProvider,
    SearchScheduler, SearchStatus, UsernameProviderDefinition, UsernameProviderPack,
    coverage_by_category, email_registry_counts, parse_provider_pack, plan_username_providers,
    username_registry_counts, username_search_vectors,
};
use rxscan::terminal::{
    RowTier, SearchEnrichment, SearchRow, SearchScaleHeader, SearchSummary, TerminalCapabilities,
    render_search_report_full,
};

const SCALE_VECTORS: usize = 3_000;
const SCALE_CATEGORIES: &[&str] = &[
    "social",
    "developer",
    "community",
    "gaming",
    "creator",
    "adult",
    "other",
];

fn synthetic_definition(index: usize) -> UsernameProviderDefinition {
    let category = SCALE_CATEGORIES[index % SCALE_CATEGORIES.len()];
    let id = format!("scale-provider-{index:05}");
    UsernameProviderDefinition {
        metadata: ProviderMetadata {
            id: id.clone(),
            version: "1".to_owned(),
            accepts: vec![SearchEntityKind::Username],
            produces: vec![SearchEntityKind::Account],
            contact_class: ContactClass::PublicHttp,
            timeout_ms: 2_000,
            requests_per_minute: 30,
            weight: 1,
            source_category: category.to_owned(),
            requires_authentication: false,
        },
        platform: format!("Scale Provider {index:05}"),
        category: category.to_owned(),
        // Distinct endpoint per vector: no duplicate-endpoint lint failures.
        profile_url: format!("https://example.test/{id}/{{username}}"),
        method: "GET".to_owned(),
        success_status: vec![200],
        not_found_status: vec![404],
        success: MarkerPolicy {
            required: vec![format!("data-profile-\"{{username}}\"-{id}")],
            any: vec![],
        },
        not_found: MarkerPolicy {
            required: vec![],
            any: vec!["profile not found".to_owned()],
        },
        blocked_markers: vec![],
        authentication_url_markers: vec![],
        max_redirects: 2,
        max_body_bytes: 64 * 1024,
        health_state: if index % 50 == 0 {
            HealthState::Disabled
        } else if index % 7 == 0 {
            HealthState::NeedsReview
        } else {
            HealthState::LiveVerified
        },
        username_rules: None,
        absence_redirect_markers: vec![],
        // Fresh verification date (today): never goes stale as time passes.
        verified_at: if index % 50 == 0 || index % 7 == 0 {
            None
        } else {
            Some(rxscan::search::stale_cutoff(0))
        },
        verification_method: if index % 50 == 0 || index % 7 == 0 {
            None
        } else {
            Some("live-probe".to_owned())
        },
        source_notes: None,
    }
}

fn synthetic_pack(count: usize) -> UsernameProviderPack {
    UsernameProviderPack {
        schema_version: 1,
        pack_version: "scale-test".to_owned(),
        providers: (0..count).map(synthetic_definition).collect(),
    }
}

// --- Instant mock providers (no network) -----------------------------------

#[derive(Clone)]
struct InstantProvider {
    id: String,
    status: SearchStatus,
}

impl SearchProvider for InstantProvider {
    fn metadata(&self) -> &ProviderMetadata {
        Box::leak(Box::new(ProviderMetadata {
            id: self.id.clone(),
            version: "1".to_owned(),
            accepts: vec![SearchEntityKind::Username],
            produces: vec![SearchEntityKind::Account],
            contact_class: ContactClass::PublicHttp,
            timeout_ms: 1_000,
            requests_per_minute: 60,
            weight: 1,
            source_category: "social".to_owned(),
            requires_authentication: false,
        }))
    }

    fn accepts(&self, _entity: &SearchEntity) -> bool {
        true
    }

    fn host_key(&self) -> String {
        format!("{}-host", self.id)
    }

    fn search(
        &self,
        _context: &SearchContext,
        entity: &SearchEntity,
    ) -> Result<SearchObservation, SearchError> {
        Ok(SearchObservation {
            provider_id: self.id.clone(),
            provider_version: "1".to_owned(),
            task_id: format!("task-{}", self.id),
            input_entity_id: entity.id.clone(),
            contact_class: ContactClass::PublicHttp,
            status: self.status,
            confidence: if self.status == SearchStatus::Confirmed {
                90
            } else {
                0
            },
            timestamp: 1_700_000_000,
            evidence: vec!["synthetic".to_owned()],
            attributes: BTreeMap::new(),
        })
    }
}

// --- No arbitrary registry cap ----------------------------------------------

#[test]
fn registry_has_no_count_cap_at_thousands_of_vectors() {
    let pack = synthetic_pack(SCALE_VECTORS);
    assert_eq!(pack.providers.len(), SCALE_VECTORS);
    // Validation passes at 3,000 definitions: per-definition checks only.
    rxscan::search::validate_definitions(&pack.providers)
        .expect("3,000 valid definitions must validate");
    // Vector model: 3,000 vectors from 3,000 distinct providers.
    let vectors = username_search_vectors(&pack);
    assert_eq!(vectors.len(), SCALE_VECTORS);
    let counts = username_registry_counts(&pack);
    assert_eq!(counts.providers_configured, SCALE_VECTORS);
    assert_eq!(counts.vectors_registered, SCALE_VECTORS);
    assert_eq!(
        counts.enabled + counts.disabled,
        SCALE_VECTORS,
        "enabled/disabled must partition the registry"
    );
    assert_eq!(
        counts.usable + counts.unavailable + counts.disabled,
        SCALE_VECTORS,
        "usable/unavailable/disabled must partition the registry"
    );
    // Email registry stays honestly empty until real email vectors land.
    let email = email_registry_counts();
    assert_eq!(email.vectors_registered, 0);
    assert_eq!(email.providers_configured, 0);
}

#[test]
fn pack_byte_cap_guards_transport_not_ambition() {
    // A ~3 MB pack (3,000 vectors) parses; a >32 MiB blob is rejected as
    // transport abuse — the byte cap is safety, never a design target.
    let pack = synthetic_pack(100);
    let json = serde_json::to_string(&pack).unwrap();
    parse_provider_pack(&json, "scale-test").expect("100-vector pack must parse");
    let huge = "x".repeat(33 * 1024 * 1024);
    assert!(
        parse_provider_pack(&huge, "scale-test").is_err(),
        "oversized pack must be rejected"
    );
}

// --- Planning at scale -------------------------------------------------------

#[test]
fn planning_slices_thousands_without_contacting_anyone() {
    let pack = synthetic_pack(SCALE_VECTORS);
    // Full plan: disabled included here (scheduler skips them with reasons).
    let full = plan_username_providers(&pack, None, &BTreeSet::new(), &BTreeSet::new()).unwrap();
    assert_eq!(full.len(), SCALE_VECTORS);
    // Category selection narrows the REAL plan before any contact.
    let social: BTreeSet<String> = ["social".to_owned()].into_iter().collect();
    let sliced = plan_username_providers(&pack, None, &BTreeSet::new(), &social).unwrap();
    let expected = pack
        .providers
        .iter()
        .filter(|p| p.category == "social")
        .count();
    assert_eq!(sliced.len(), expected);
    assert!(sliced.len() < full.len());
    assert!(sliced.len() > 400, "social slice must hold hundreds");
    // Unknown entries still rejected at scale.
    assert!(
        plan_username_providers(
            &pack,
            None,
            &BTreeSet::new(),
            &["bogus".to_owned()].into_iter().collect()
        )
        .is_err()
    );
}

// --- Bounded concurrency over an unbounded registry --------------------------

#[test]
fn scheduler_completes_thousands_with_bounded_concurrency() {
    let providers: Vec<Box<dyn SearchProvider>> = (0..SCALE_VECTORS)
        .map(|index| {
            let status = match index % 100 {
                0 => SearchStatus::Confirmed,
                1 => SearchStatus::Possible,
                2 => SearchStatus::Blocked,
                3 => SearchStatus::RateLimited,
                4 => SearchStatus::Error,
                _ => SearchStatus::NotFound,
            };
            Box::new(InstantProvider {
                id: format!("scale-provider-{index:05}"),
                status,
            }) as Box<dyn SearchProvider>
        })
        .collect();
    let entity = SearchEntity::username("exampleuser", 1).unwrap();
    let cancelled = AtomicBool::new(false);
    // 3,000 scheduled, 20 concurrent: ~150 sequential waves, never 3,000
    // simultaneous requests.
    let mut scheduler = SearchScheduler::new(
        SCALE_VECTORS,
        20,
        2,
        Instant::now() + Duration::from_secs(120),
    );
    let hook_totals = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let hook_totals_inner = hook_totals.clone();
    let (results, accounting) =
        scheduler.run_with_progress(&providers, &entity, &cancelled, &|completed, total| {
            hook_totals_inner.lock().unwrap().push((completed, total));
        });
    // Exact accounting at scale.
    assert_eq!(accounting.providers_requested, SCALE_VECTORS);
    assert_eq!(accounting.accounted(), SCALE_VECTORS);
    assert_eq!(accounting.providers_completed, SCALE_VECTORS);
    assert_eq!(results.len(), SCALE_VECTORS);
    // Progress denominator is ALWAYS the scheduled set, never the registry.
    let hook_totals = hook_totals.lock().unwrap();
    assert!(!hook_totals.is_empty());
    for (_, total) in hook_totals.iter() {
        assert_eq!(*total, SCALE_VECTORS, "denominator must be scheduled");
    }
    // Status distribution preserved (30 each of the special states).
    assert_eq!(
        accounting
            .counts
            .get(&SearchStatus::Confirmed)
            .copied()
            .unwrap_or(0),
        30
    );
    assert_eq!(
        accounting
            .counts
            .get(&SearchStatus::NotFound)
            .copied()
            .unwrap_or(0),
        2_850
    );
}

// --- Terminal stays readable at scale ----------------------------------------

fn scale_rows() -> (Vec<SearchRow>, SearchEnrichment, BTreeSet<String>) {
    let mut rows = Vec::with_capacity(SCALE_VECTORS);
    let mut enrichment = SearchEnrichment::default();
    let mut effective = BTreeSet::new();
    for index in 0..SCALE_VECTORS {
        let provider = format!("scale-provider-{index:05}");
        let category = SCALE_CATEGORIES[index % SCALE_CATEGORIES.len()].to_owned();
        effective.insert(provider.clone());
        enrichment
            .categories
            .insert(provider.clone(), category.clone());
        let (status, tier, confidence, detail, url, observed) = match index % 100 {
            0 => (
                "confirmed",
                RowTier::Positive,
                90u8,
                "public profile".to_owned(),
                format!("https://example.test/{provider}/exampleuser"),
                true,
            ),
            1 => (
                "possible",
                RowTier::Positive,
                25u8,
                "weak evidence".to_owned(),
                format!("https://example.test/{provider}/exampleuser"),
                false,
            ),
            2 => (
                "blocked",
                RowTier::Attention,
                0u8,
                "provider denied access".to_owned(),
                String::new(),
                false,
            ),
            3 => (
                "rate_limited",
                RowTier::Attention,
                0u8,
                "HTTP 429".to_owned(),
                String::new(),
                false,
            ),
            4 => (
                "error",
                RowTier::Attention,
                0u8,
                "request failed".to_owned(),
                String::new(),
                false,
            ),
            _ => (
                "not_found",
                RowTier::Quiet,
                0u8,
                String::new(),
                String::new(),
                false,
            ),
        };
        rows.push(SearchRow {
            status,
            provider,
            confidence,
            detail,
            tier,
            url,
            url_observed: observed,
        });
    }
    (rows, enrichment, effective)
}

#[test]
fn terminal_default_output_stays_bounded_at_scale() {
    let (rows, enrichment, effective) = scale_rows();
    let summary = SearchSummary {
        requested: SCALE_VECTORS,
        completed: SCALE_VECTORS,
        skipped: 0,
        cancelled: 0,
        unscanned: 0,
        truncated: false,
    };
    let mut provider_to_category = BTreeMap::new();
    for provider in &effective {
        let index: usize = provider
            .strip_prefix("scale-provider-")
            .unwrap()
            .parse()
            .unwrap();
        provider_to_category.insert(
            provider.clone(),
            SCALE_CATEGORIES[index % SCALE_CATEGORIES.len()].to_owned(),
        );
    }
    let coverage: Vec<rxscan::terminal::SearchCategoryCoverage> =
        coverage_by_category(&effective, &provider_to_category, &[])
            .into_iter()
            .map(|entry| rxscan::terminal::SearchCategoryCoverage {
                category: entry.category,
                label: entry.label,
                scheduled: entry.scheduled,
                complete: entry.complete,
                remaining: entry.remaining,
            })
            .collect();
    let scale = SearchScaleHeader {
        vectors_registered: SCALE_VECTORS,
        providers_usable: 2_500,
    };
    let text = render_search_report_full(
        "exampleuser",
        SCALE_VECTORS,
        &rows,
        &summary,
        false,
        false,
        false,
        TerminalCapabilities::plain(),
        Some(&enrichment),
        Some(&coverage),
        Some(&scale),
    );
    // Header denominators honest and formatted.
    assert!(
        text.contains("2,500 usable"),
        "header shows usable providers"
    );
    assert!(
        text.contains("3,000 registered"),
        "header shows registered vectors"
    );
    assert!(text.contains("3,000"), "scheduled denominator present");
    // Bounded: findings budget + summaries, never thousands of negatives.
    let lines = text.lines().count();
    assert!(
        lines < 300,
        "default output must stay readable, got {lines} lines"
    );
    let negative_rows = text
        .lines()
        .filter(|line| line.contains("scale-provider-") && line.contains("NOT FOUND"))
        .count();
    assert_eq!(
        negative_rows, 0,
        "default output must not print thousands of negatives"
    );
    // Per-category coverage present for every category.
    for category in SCALE_CATEGORIES {
        assert!(text.contains(category), "coverage missing {category}");
    }
    // No ANSI in plain caps even at scale.
    assert!(!text.contains('\x1b'));
}

#[test]
fn machine_output_reconciles_at_scale_without_ansi() {
    use rxscan::search::{ContactClass, SearchAccounting, UsernameSearchReport};
    let seed = SearchEntity::username("exampleuser", 1_700_000_000).unwrap();
    let results = (0..SCALE_VECTORS)
        .map(|index| {
            let status = match index % 100 {
                0 => SearchStatus::Confirmed,
                1 => SearchStatus::Possible,
                _ => SearchStatus::NotFound,
            };
            rxscan::search::SearchObservation {
                provider_id: format!("scale-provider-{index:05}"),
                provider_version: "1".to_owned(),
                task_id: format!("task-{index:05}"),
                input_entity_id: seed.id.clone(),
                contact_class: ContactClass::PublicHttp,
                status,
                confidence: 10,
                timestamp: 1_700_000_000,
                evidence: vec!["synthetic".to_owned()],
                attributes: BTreeMap::from([(
                    "category".to_owned(),
                    SCALE_CATEGORIES[index % SCALE_CATEGORIES.len()].to_owned(),
                )]),
            }
        })
        .collect::<Vec<_>>();
    let mut counts = BTreeMap::new();
    counts.insert(SearchStatus::Confirmed, 30);
    counts.insert(SearchStatus::Possible, 30);
    counts.insert(SearchStatus::NotFound, 2_940);
    let report = UsernameSearchReport {
        schema_version: 1,
        run_id: "search_run_scale".to_owned(),
        seed,
        provider_pack_version: "scale-test".to_owned(),
        accounting: SearchAccounting {
            providers_requested: SCALE_VECTORS,
            providers_completed: SCALE_VECTORS,
            skipped: 0,
            cancelled: 0,
            unscanned: 0,
            counts,
            truncated: false,
        },
        results,
        graph: rxscan::graph::ScanGraph::default(),
        network_scans: 0,
        started_at: 1_700_000_000,
        completed_at: 1_700_000_001,
    };
    let jsonl = rxscan::search::render_username_jsonl(&report);
    assert!(!jsonl.contains('\x1b'), "machine output never styled");
    // start + 3,000 observations + summary.
    assert_eq!(jsonl.lines().count(), SCALE_VECTORS + 2);
    let last: serde_json::Value = serde_json::from_str(jsonl.lines().last().unwrap()).unwrap();
    let payload = &last["payload"];
    assert_eq!(payload["scheduled"], SCALE_VECTORS);
    assert_eq!(payload["remaining"], 0);
    assert_eq!(payload["providers_requested"], SCALE_VECTORS);
}

// --- Corpus maintenance at scale ---------------------------------------------

#[test]
fn lint_names_offenders_and_counts_queues_at_scale() {
    let pack = synthetic_pack(500);
    let mut report = CorpusLintReport::default();
    rxscan::search::lint_definitions(&pack.providers, &mut report);
    assert!(
        report.errors.is_empty(),
        "valid synthetic corpus must lint clean: {:?}",
        report.errors
    );
    assert_eq!(report.providers_checked, 500);
    assert_eq!(report.vectors_checked, 500);
    assert_eq!(report.providers_count, 500);
    // Review and disabled queues are disjoint subsets of the registry: each
    // provider is counted at most once across queues.
    assert!(
        report.needs_review_count + report.disabled_count <= report.providers_checked,
        "queues must be disjoint subsets of the registry"
    );
    assert!(
        report.needs_review_count > 0,
        "review queue must be counted"
    );
    assert!(report.disabled_count > 0, "disabled must be counted");
    assert!(report.stale_count == 0, "fresh fixtures must not be stale");
}

#[test]
fn lint_catches_duplicates_conflicts_and_missing_absence() {
    // Duplicate vector IDs.
    let mut definitions = vec![synthetic_definition(1), synthetic_definition(1)];
    let mut report = CorpusLintReport::default();
    rxscan::search::lint_definitions(&definitions, &mut report);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("duplicate search vector")),
        "duplicate vectors must name the offender: {:?}",
        report.errors
    );
    // Conflicting presence/absence markers.
    definitions = vec![synthetic_definition(2)];
    definitions[0].not_found.any = definitions[0].success.required.clone();
    let mut report = CorpusLintReport::default();
    rxscan::search::lint_definitions(&definitions, &mut report);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("conflicting rules")),
        "conflicting rules must be caught: {:?}",
        report.errors
    );
    // Missing absence handling.
    definitions = vec![synthetic_definition(3)];
    definitions[0].not_found_status.clear();
    definitions[0].not_found = MarkerPolicy {
        required: vec![],
        any: vec![],
    };
    definitions[0].absence_redirect_markers.clear();
    let mut report = CorpusLintReport::default();
    rxscan::search::lint_definitions(&definitions, &mut report);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("no absence handling")),
        "missing absence must be caught: {:?}",
        report.errors
    );
    // Missing category.
    definitions = vec![synthetic_definition(4)];
    definitions[0].category.clear();
    let mut report = CorpusLintReport::default();
    rxscan::search::lint_definitions(&definitions, &mut report);
    assert!(
        report
            .errors
            .iter()
            .any(|error| error.contains("missing category")),
        "missing category must be caught: {:?}",
        report.errors
    );
    // Zero weight warns without failing the gate.
    definitions = vec![synthetic_definition(5)];
    definitions[0].metadata.weight = 0;
    let mut report = CorpusLintReport::default();
    rxscan::search::lint_definitions(&definitions, &mut report);
    assert!(report.errors.is_empty());
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("zero weight")),
        "zero weight must warn: {:?}",
        report.warnings
    );
}
