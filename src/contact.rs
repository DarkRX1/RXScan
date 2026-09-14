//! Bounded scan-lifetime HTTP contact registry.
//!
//! This is an optimization/correctness aid, not authorization. Scope checks
//! still happen before every request. Keys include purpose so intentional
//! probes, such as synthetic baseline paths, are distinct from accidental
//! duplicate content/crawl requests.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use crate::web::WebTarget;

pub const MAX_CONTACT_REGISTRY_ENTRIES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestPurpose {
    CrawlPage,
    BaselinePrimary,
    BaselineSynthetic,
    ContentCandidate,
    RedirectFollow,
    FuzzMutation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ContactRegistryEntry {
    pub method: String,
    pub url: String,
    pub purpose: RequestPurpose,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ContactKey {
    method: String,
    url: String,
    purpose: RequestPurpose,
}

#[derive(Debug, Default)]
struct RegistryState {
    exact: BTreeSet<ContactKey>,
    by_url: BTreeMap<String, RequestPurpose>,
    full: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ContactRegistry {
    state: Arc<Mutex<RegistryState>>,
}

impl ContactRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn claim(&self, target: &WebTarget, purpose: RequestPurpose) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.full {
            return true;
        }
        let url = target.canonical();
        let cross_module_dedup = matches!(
            purpose,
            RequestPurpose::ContentCandidate | RequestPurpose::CrawlPage
        );
        if cross_module_dedup
            && state.by_url.get(&url).is_some_and(|seen| {
                matches!(
                    seen,
                    RequestPurpose::ContentCandidate | RequestPurpose::CrawlPage
                )
            })
        {
            return false;
        }
        let key = ContactKey {
            method: "GET".to_owned(),
            url: url.clone(),
            purpose,
        };
        if !state.exact.insert(key) {
            return false;
        }
        if cross_module_dedup {
            state.by_url.insert(url, purpose);
        } else {
            state.by_url.entry(url).or_insert(purpose);
        }
        if state.exact.len() >= MAX_CONTACT_REGISTRY_ENTRIES {
            state.full = true;
        }
        true
    }

    pub fn len(&self) -> usize {
        self.state.lock().unwrap().exact.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn snapshot(&self) -> Vec<ContactRegistryEntry> {
        self.state
            .lock()
            .unwrap()
            .exact
            .iter()
            .take(MAX_CONTACT_REGISTRY_ENTRIES)
            .map(|key| ContactRegistryEntry {
                method: key.method.clone(),
                url: key.url.clone(),
                purpose: key.purpose,
            })
            .collect()
    }

    pub fn restore(entries: &[ContactRegistryEntry]) -> Result<Self, String> {
        if entries.len() > MAX_CONTACT_REGISTRY_ENTRIES {
            return Err("too many contact registry entries".to_owned());
        }
        let registry = Self::new();
        {
            let mut state = registry.state.lock().unwrap();
            for entry in entries {
                if entry.method != "GET" || entry.url.len() > 4096 {
                    return Err("invalid contact registry entry".to_owned());
                }
                let key = ContactKey {
                    method: entry.method.clone(),
                    url: entry.url.clone(),
                    purpose: entry.purpose,
                };
                state.exact.insert(key);
                state
                    .by_url
                    .entry(entry.url.clone())
                    .or_insert(entry.purpose);
            }
            state.full = state.exact.len() >= MAX_CONTACT_REGISTRY_ENTRIES;
        }
        Ok(registry)
    }
}
