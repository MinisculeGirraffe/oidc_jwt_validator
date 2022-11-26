#![warn(clippy::pedantic)]
#![allow(unused, clippy::missing_errors_doc, clippy::must_use_candidate)]
use actix_web::cookie::time::util::is_leap_year;
use cache::{CacheConfig, CacheStrat, CacheUpdateAction};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation};
use reqwest::header::ToStrError;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{Mutex, RwLock};
use tokio::task::{self, JoinHandle};
use tokio::time::{Instant, MissedTickBehavior};
use tracing::instrument;
use util::decode_jwk;

use log::{debug, info, warn};

use reqwest::header::CACHE_CONTROL;

pub mod cache;
pub mod middleware;
pub mod util;

const CONFIG_URL_SUFFIX: &str = ".well-known/openid-configuration";

#[derive(Debug, serde::Deserialize)]
struct OidcConfig {
    jwks_uri: String,
}

async fn discover_jwks(
    url: String,
    client: &reqwest::Client,
) -> Result<OidcConfig, JWKSFetchError> {
    let client = client
        .get(url)
        .send()
        .await
        .map_err(JWKSFetchError::RequestFailed)?;

    client.json().await.map_err(JWKSFetchError::RequestFailed)
}

#[derive(Debug)]
pub enum JWKSFetchError {
    RequestFailed(reqwest::Error),
    DiscoverError,
    JSONDecodeError,
    IssuerParseError,
}

#[derive(Debug)]
pub enum JWKSValidationError {
    InvalidHeader,
    MiddingKid,
    InvakidJKW,
    InvalidAlgo,
    NonMatchingJWK,
    DecodeError,
    MissingToken,
    TokenParseFailed,
}
#[derive(Clone)]
pub struct Validator {
    issuer: String,
    jwks_uri: String,
    http_client: reqwest::Client,
    cache: Arc<RwLock<JwkSetCache>>,
    cache_strat: CacheStrat,
    is_revalidating: Arc<AtomicBool>,
}

impl Validator {
    pub async fn new(
        oidc_issuer: impl AsRef<str>,
        http_client: reqwest::Client,
        cache_strat: CacheStrat,
    ) -> Result<Validator, JWKSFetchError> {
        let issuer = oidc_issuer.as_ref().trim_end_matches('/').to_string();
        let discovery_url = format!("{issuer}/{CONFIG_URL_SUFFIX}");

        let jwks_uri = discover_jwks(discovery_url, &http_client).await?.jwks_uri;

        //Create an empty JWKS to initalize our Cache
        let jwks = JwkSet { keys: Vec::new() };

        let cache_config = match cache_strat {
            CacheStrat::Automatic => CacheConfig::default(),
            CacheStrat::Manual(config) => config,
        };

        let cache = Arc::new(RwLock::new(JwkSetCache::new(jwks, cache_config)));

        //Create the Validator
        let client = Self {
            issuer,
            jwks_uri,
            http_client,
            cache,
            cache_strat,
            is_revalidating: Arc::new(AtomicBool::new(false)),
        };

        // Replace the empty cache with data from the jwks endpoint before return
        // This ensures it's ready to validate immediatly after use.
        client.update_cache(UpdatePreference::Update).await?;

        Ok(client)
    }

    async fn get_jwks(&self) -> Result<JwkSetFetch, JWKSFetchError> {
        let uri = &self.jwks_uri;
        // Get the jwks endpoint
        debug!("Requesting JWKS From Uri: {uri}");
        let fetched_at = tokio::time::Instant::now();
        let result = self
            .http_client
            .get(uri)
            .send()
            .await
            .map_err(JWKSFetchError::RequestFailed)?;

        let cache_policy = {
            // If we haven't manually set a caching strategy
            if self.cache_strat == CacheStrat::Automatic {
                // Determine it from the cache_control header
                let cache_control = result.headers().get(CACHE_CONTROL);
                let cache_policy = CacheConfig::from_header_val(cache_control);
                Some(cache_policy)
            } else {
                None
            }
        };

        let jwks: JwkSet = result
            .json()
            .await
            .map_err(|e| JWKSFetchError::JSONDecodeError)?;

        Ok(JwkSetFetch {
            jwks,
            cache_policy,
            fetched_at,
        })
    }

    /// Triggers an immediate update from the JWKS URL
    async fn update_cache(
        &self,
        preference: UpdatePreference,
    ) -> Result<CacheUpdateAction, JWKSFetchError> {
        info!("Triggering update to JWKS Cache");
        let (fetch, mut cache) = match preference {
            // Lock as early as possible
            UpdatePreference::Update => tokio::join!(self.get_jwks(), self.cache.write()),
            // Lock as late as possible
            UpdatePreference::Revalidate => {
                let fetch = self.get_jwks().await;
                let mut cache = self.cache.write().await;
                (fetch, cache)
            }
        };
        match fetch {
            Ok(fetch) => {
                cache.last_update_failed = false;
                Ok(cache.update_fetch(fetch))
            }
            Err(e) => {
                cache.last_update_failed = true;
                Err(e)
            }
        }
    }

    // Triggers an eventual update from the JWKS URL
    fn revalidate_cache(&self) {
        // only attempts to spawn a task if there isn't currently one running
        if !self.is_revalidating.load(Ordering::SeqCst) {
            let self_ref = self.clone();
            tokio::task::spawn(async move {
                self_ref.is_revalidating.store(true, Ordering::SeqCst);
                self_ref.update_cache(UpdatePreference::Revalidate).await;
                self_ref.is_revalidating.store(false, Ordering::SeqCst);
            });
        }
    }
    /// Validates a JWT, Returning the claims serialized into type of T
    pub async fn validate<T>(
        &self,
        token: impl AsRef<str>,
    ) -> Result<TokenData<T>, JWKSValidationError>
    where
        T: for<'de> serde::de::Deserialize<'de>,
    {
        let token = token.as_ref();
        // Early return error conditions before acquiring a read lock
        let header =
            jsonwebtoken::decode_header(token).map_err(|_| JWKSValidationError::InvalidHeader)?;
        let kid = header.kid.ok_or(JWKSValidationError::MiddingKid)?;

        self.get_kid_retry(kid).await?.decode(token)
    }

    async fn get_kid_retry(
        &self,
        kid: impl AsRef<str>,
    ) -> Result<Arc<DecodingInfo>, JWKSValidationError> {
        let kid = kid.as_ref();
        // Check to see if we have the kid
        if let Some(key) = self.get_kid(kid).await {
            // if we have it, then return it
            Ok(key)
        } else {
            // Try and invalidate our cache. Maybe the JWKS has changed or our cached values expired
            self.update_cache(UpdatePreference::Update).await;
            self.get_kid(kid)
                .await
                .ok_or(JWKSValidationError::NonMatchingJWK)
        }
    }

    async fn get_kid(&self, kid: &str) -> Option<Arc<DecodingInfo>> {
        debug!("Waiting on read-lock for cache");
        let read_cache = &self.cache.read().await;

        let elapsed = read_cache.last_update.elapsed();
        let max_age = read_cache.cache_policy.max_age;

        if elapsed <= max_age {
            return read_cache.get_key(kid);
        }

        // If the stale while revalidate setting is present
        if let Some(swr) = read_cache.cache_policy.stale_while_revalidate {
            // if we're within the SWR allowed window
            if elapsed <= swr + max_age {
                self.revalidate_cache();
                return read_cache.get_key(kid);
            }
        }
        if let Some(swr_err) = read_cache.cache_policy.stale_if_error {
            // if the last update failed and the stale-if-error is present
            if elapsed <= swr_err + max_age && read_cache.last_update_failed {
                self.revalidate_cache();
                return read_cache.get_key(kid);
            }
        }

        None
    }
}

//Decoding info is stored in an Arc so it can be owned by multiple threads.
struct JwkSetCache {
    jwks: JwkSet,
    decoding_map: HashMap<String, Arc<DecodingInfo>>,
    cache_policy: CacheConfig,
    last_update: Instant,
    last_update_failed: bool,
}

impl JwkSetCache {
    pub fn new(jwks: JwkSet, config: CacheConfig) -> Self {
        Self {
            jwks,
            decoding_map: HashMap::new(),
            cache_policy: config,
            last_update: Instant::now(),
            last_update_failed: false,
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

    fn get_key(&self, kid: &str) -> Option<Arc<DecodingInfo>> {
        self.decoding_map.get(kid).cloned()
    }

    fn update_fetch(&mut self, fetch: JwkSetFetch) -> CacheUpdateAction {
        let new_jwks = fetch.jwks;
        // If we didn't parse out a cache policy from the last request
        // Assume that it's the same as the last
        let cache_policy = fetch.cache_policy.unwrap_or(self.cache_policy);
        // update the timestamp we last fetched the jwks from
        self.last_update = fetch.fetched_at;

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

/// Struct used to store all information needed to decode a JWT
/// Intended to be cached inside of `JwkSetCache` to prevent decoding information about the same JWK multiple times
struct DecodingInfo {
    jwk: Jwk,
    key: DecodingKey,
    validation: Validation,
    alg: Algorithm,
}
impl DecodingInfo {
    fn new(jwk: Jwk, key: DecodingKey, alg: Algorithm,) -> Self {
        let validation = Validation::new(alg);
        Self {
            jwk,
            key,
            validation,
            alg,
        }
    }

    fn decode<T>(&self, token: &str) -> Result<TokenData<T>, JWKSValidationError>
    where
        T: for<'de> serde::de::Deserialize<'de>,
    {
        debug!("Validating Token: {token}");

        jsonwebtoken::decode::<T>(token, &self.key, &self.validation).map_err(|e| {
            debug!("Token Validation failed with Error: {e}");
            JWKSValidationError::DecodeError
        })
    }
}
#[derive(Debug)]
pub struct JwkSetFetch {
    jwks: JwkSet,
    cache_policy: Option<CacheConfig>,
    fetched_at: Instant,
}
#[derive(Debug)]
enum UpdatePreference {
    Update,
    Revalidate,
}

