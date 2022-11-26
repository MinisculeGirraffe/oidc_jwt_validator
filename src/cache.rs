#![allow(clippy::module_name_repetitions, clippy::missing_panics_doc)]
use jsonwebtoken::jwk::JwkSet;
use log::{debug, info};
use reqwest::header::HeaderValue;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};


use crate::{
    util::{current_time, decode_jwk},
    DecodingInfo, JwkSetFetch,
};

/// Determines settings about updating the JWKS in the background
/// By default will wait the entire refresh period before triggering an update
/// unless `immediate_refresh` is set to `true`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheConfig {
    /// Time in Seconds to refresh the JWKS from the OIDC Provider
    /// Default: 43200(12 hours)
    pub max_age: Duration,
    pub stale_while_revalidate: Option<Duration>,
    pub stale_if_error: Option<Duration>,
}

impl CacheConfig {
    pub fn from_header_val(value: Option<&HeaderValue>) -> Self {
        // Initalize the default config of polling every second
        let mut config = Self::default();

        if let Some(value) = value {
            if let Ok(value) = value.to_str() {
                config.parse_str(value);
            }
        }
        config
    }

    fn parse_str(&mut self, value: &str) {
        // Iterate over every token in the header value
        for token in value.split(',') {
            // split them into whitespace trimmed pairs
            let (key, val) = {
                let mut split = token.split('=').map(str::trim);
                (split.next(), split.next())
            };
            //Modify the default config based on the values that matter
            //Any values here would be more permisssive than the default behavior
            match (key, val) {
                (Some("max-age"), Some(val)) => {
                    if let Ok(secs) = val.parse::<u64>() {
                        self.max_age = Duration::from_secs(secs);
                    }
                }
                (Some("stale-while-revalidate"), Some(val)) => {
                    if let Ok(secs) = val.parse::<u64>() {
                        self.stale_while_revalidate = Some(Duration::from_secs(secs));
                    }
                }
                (Some("stale-if-error"), Some(val)) => {
                    if let Ok(secs) = val.parse::<u64>() {
                        self.stale_if_error = Some(Duration::from_secs(secs));
                    }
                }
                _ => continue,
            };
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(1),
            stale_while_revalidate: None,
            stale_if_error: None,
        }
    }
}

// Todo Fetch the jwks based on the cache control header.
// the poll time should be the cache control header
// if no-cache then we should poll for a minimum amount of time
// instead of literally just requesting it for every authentication
// because like holy fuck that just seems inefficent
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheStrat {
    Automatic,
    Manual(CacheConfig),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheUpdateAction {
    // We checked the JWKS uri and it was the same as the last time we refreshed it so no action was taken
    NoUpdate,
    // We checked the JWKS uri and it was different so we updated our local cache
    JwksUpdate,
    // The JWKS Uri responded with a different cache-control header
    CacheUpdate(CacheConfig),
    JwksAndCacheUpdate(CacheConfig),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheError {
    MissingKid,
    DecodeError,
}

pub struct CacheState {
    last_update: AtomicU64,
    is_revalidating: AtomicBool,
    is_error: AtomicBool,
}

impl CacheState {
    pub fn new() -> Self {
        Self {
            last_update: AtomicU64::new(current_time()),
            is_revalidating: AtomicBool::new(false),
            is_error: AtomicBool::new(false),
        }
    }
    pub fn is_error(&self) -> bool {
        self.is_error.load(Ordering::Acquire)
    }
    pub fn set_is_error(&self, value: bool) {
        self.is_error.store(value, Ordering::Release);
    }

    pub fn last_update(&self) -> u64 {
        self.last_update.load(Ordering::Acquire)
    }
    pub fn set_last_update(&self, timestamp: u64) {
        self.last_update.store(timestamp, Ordering::Release);
    }

    pub fn is_revalidating(&self) -> bool {
        self.is_revalidating.load(Ordering::Acquire)
    }

    pub fn set_is_revalidating(&self, value: bool) {
        self.is_revalidating.store(value, Ordering::Release);
    }
}

impl Default for CacheState {
    fn default() -> Self {
        Self::new()
    }
}

//Decoding info is stored in an Arc so it can be owned by multiple threads.
pub struct JwkSetCache {
    jwks: JwkSet,
    decoding_map: HashMap<String, Arc<DecodingInfo>>,
    pub cache_policy: CacheConfig,
}

impl JwkSetCache {
    pub fn new(jwks: JwkSet, config: CacheConfig) -> Self {
        Self {
            jwks,
            decoding_map: HashMap::new(),
            cache_policy: config,
        }
    }

    fn update_jwks(&mut self, new_jwks: JwkSet) {
        self.jwks = new_jwks;
        let keys = self.jwks.keys.iter().filter_map(|i| decode_jwk(i).ok());
        // Clear our cache of decoding keys
        self.decoding_map.clear();
        // Load the keys back into our hashmap cache.
        for key in keys {
            self.decoding_map.insert(key.0, Arc::new(key.1));
        }
    }

    pub fn get_key(&self, kid: &str) -> Option<Arc<DecodingInfo>> {
        self.decoding_map.get(kid).cloned()
    }

    pub(crate) fn update_fetch(&mut self, fetch: JwkSetFetch) -> CacheUpdateAction {
        let new_jwks = fetch.jwks;
        // If we didn't parse out a cache policy from the last request
        // Assume that it's the same as the last
        let cache_policy = fetch.cache_policy.unwrap_or(self.cache_policy);
        match (self.jwks == new_jwks, self.cache_policy == cache_policy) {
            // Everything is the same
            (true, true) => {
                debug!("JWKS Content has not changed since last update");
                CacheUpdateAction::NoUpdate
            }
            // The JWKS changed but the cache policy hasn't
            (false, true) => {
                info!("JWKS Content has changed since last update");
                self.update_jwks(new_jwks);
                CacheUpdateAction::JwksUpdate
            }
            // The cache policy changed, but the JWKS hasn't
            (true, false) => {
                self.cache_policy = cache_policy;
                CacheUpdateAction::CacheUpdate(cache_policy)
            }
            // Both the cache and the JWKS have changed
            (false, false) => {
                info!("cache-control header and JWKS content has changed since last update");
                self.update_jwks(new_jwks);
                self.cache_policy = cache_policy;
                CacheUpdateAction::JwksAndCacheUpdate(cache_policy)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn validate_headers() {
        let _input = vec![
            "max-age=604800",
            "no-cache",
            "max-age=604800, must-revalidate",
            "no-store",
            "public, max-age=604800, immutable",
            "max-age=604800, stale-while-revalidate=86400",
            "max-age=604800, stale-if-error=86400",
        ];
    }
}
