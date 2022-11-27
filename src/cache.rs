use jsonwebtoken::jwk::JwkSet;
use log::{debug, info};
use reqwest::header::HeaderValue;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use crate::{
    util::{current_time, decode_jwk},
    DecodingInfo, JwkSetFetch, ValidationSettings,
};

/// Determines settings about updating the cached JWKS data.
/// The JWKS will be lazily revalidated every time [validate](crate::Validator) validates a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// Time in Seconds to refresh the JWKS from the OIDC Provider
    /// Default/Minimum value: 1 Second
    pub max_age: Duration,
    /// The amount of time a s
    pub stale_while_revalidate: Option<Duration>,
    /// The amount of time the stale JWKS data should be valid for if we are unable to re-validate it from the URL.
    /// Minimum Value: 60 Seconds
    pub stale_if_error: Option<Duration>,
}

impl Settings {
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

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(1),
            stale_while_revalidate: Some(Duration::from_secs(1)),
            stale_if_error: Some(Duration::from_secs(60)),
        }
    }
}

/// Determines the JWKS Caching behavior of the validator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// The Reccomended Option.
    /// Determines [Settings] from the cache-control header on a per request basis.
    /// Allows for dynamic updating of the cache duration during run time.
    Automatic,
    /// Use a static [Settings] for the lifetime of the program. Ignores cache-control directives
    /// Not reccomended unless you are *really* sure that you know this will be the correct option
    /// This option could potentially introduce a security vulnerability if the JWKS has changed, and the value was set too high.
    Manual(Settings),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateAction {
    /// We checked the JWKS uri and it was the same as the last time we refreshed it so no action was taken
    NoUpdate,
    /// We checked the JWKS uri and it was different so we updated our local cache
    JwksUpdate,
    /// The JWKS Uri responded with a different cache-control header
    CacheUpdate(Settings),
    JwksAndCacheUpdate(Settings),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    MissingKid,
    DecodeError,
}
/// Helper struct for determining when our cache needs to be re-validated
/// Utilizes atomics to prevent write-locking as much as possible
#[derive(Debug)]
pub(crate) struct State {
    last_update: AtomicU64,
    is_revalidating: AtomicBool,
    is_error: AtomicBool,
}

impl State {
    pub fn new() -> Self {
        Self {
            last_update: AtomicU64::new(current_time()),
            is_revalidating: AtomicBool::new(false),
            is_error: AtomicBool::new(false),
        }
    }
    pub fn is_error(&self) -> bool {
        self.is_error.load(Ordering::SeqCst)
    }
    pub fn set_is_error(&self, value: bool) {
        self.is_error.store(value, Ordering::SeqCst);
    }

    pub fn last_update(&self) -> u64 {
        self.last_update.load(Ordering::SeqCst)
    }
    pub fn set_last_update(&self, timestamp: u64) {
        self.last_update.store(timestamp, Ordering::SeqCst);
    }

    pub fn is_revalidating(&self) -> bool {
        self.is_revalidating.load(Ordering::SeqCst)
    }

    pub fn set_is_revalidating(&self, value: bool) {
        self.is_revalidating.store(value, Ordering::SeqCst);
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper Struct for storing
pub struct JwkSetStore {
    pub jwks: JwkSet,
    decoding_map: HashMap<String, Arc<DecodingInfo>>,
    pub cache_policy: Settings,
    validation: ValidationSettings,
}

impl JwkSetStore {
    pub fn new(jwks: JwkSet, cache_config: Settings, validation: ValidationSettings) -> Self {
        Self {
            jwks,
            decoding_map: HashMap::new(),
            cache_policy: cache_config,
            validation,
        }
    }

    fn update_jwks(&mut self, new_jwks: JwkSet) {
        self.jwks = new_jwks;
        let keys = self
            .jwks
            .keys
            .iter()
            .filter_map(|i| decode_jwk(i, &self.validation).ok());
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

    pub(crate) fn update_fetch(&mut self, fetch: JwkSetFetch) -> UpdateAction {
        debug!("Decoding JWKS");
        let time = Instant::now();
        let new_jwks = fetch.jwks;
        // If we didn't parse out a cache policy from the last request
        // Assume that it's the same as the last
        let cache_policy = fetch.cache_policy.unwrap_or(self.cache_policy);
        let result = match (self.jwks == new_jwks, self.cache_policy == cache_policy) {
            // Everything is the same
            (true, true) => {
                debug!("JWKS Content has not changed since last update");
                UpdateAction::NoUpdate
            }
            // The JWKS changed but the cache policy hasn't
            (false, true) => {
                info!("JWKS Content has changed since last update");
                self.update_jwks(new_jwks);
                UpdateAction::JwksUpdate
            }
            // The cache policy changed, but the JWKS hasn't
            (true, false) => {
                self.cache_policy = cache_policy;
                UpdateAction::CacheUpdate(cache_policy)
            }
            // Both the cache and the JWKS have changed
            (false, false) => {
                info!("cache-control header and JWKS content has changed since last update");
                self.update_jwks(new_jwks);
                self.cache_policy = cache_policy;
                UpdateAction::JwksAndCacheUpdate(cache_policy)
            }
        };
        let elapsed = time.elapsed();
        debug!("Decoded and parsed JWKS in {:#?}", elapsed);
        result
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
