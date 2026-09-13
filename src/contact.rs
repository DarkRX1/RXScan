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
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ContactKey {
    method: &'static str,
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
        if matches!(
            purpose,
            RequestPurpose::ContentCandidate | RequestPurpose::CrawlPage
        ) && state.by_url.contains_key(&url)
        {
            return false;
        }
        let key = ContactKey {
            method: "GET",
            url: url.clone(),
            purpose,
        };
        if !state.exact.insert(key) {
            return false;
        }
        state.by_url.entry(url).or_insert(purpose);
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
}
