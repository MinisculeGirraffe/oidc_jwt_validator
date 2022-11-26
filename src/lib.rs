#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]
use crate::util::current_time;
use cache::{CacheConfig, CacheState, CacheStrat, CacheUpdateAction, JwkSetCache};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation};
use log::{debug, info, warn};

use serde::Deserialize;

use std::sync::Arc;
use tokio::sync::RwLock;

use reqwest::header::CACHE_CONTROL;

pub mod cache;
pub mod middleware;
pub mod util;


#[derive(Clone)]
pub struct Validator {
    issuer: String,
    http_client: reqwest::Client,
    cache: Arc<RwLock<JwkSetCache>>,
    cache_strat: CacheStrat,
    cache_state: Arc<CacheState>,
}

impl Validator {
    pub async fn new(
        oidc_issuer: impl AsRef<str>,
        http_client: reqwest::Client,
        cache_strat: CacheStrat,
    ) -> Result<Validator, anyhow::Error> {
        let issuer = oidc_issuer.as_ref().trim_end_matches('/').to_string();

        //Create an empty JWKS to initalize our Cache
        let jwks = JwkSet { keys: Vec::new() };

        let cache_config = match cache_strat {
            CacheStrat::Automatic => CacheConfig::default(),
            CacheStrat::Manual(config) => config,
        };

        let cache = Arc::new(RwLock::new(JwkSetCache::new(jwks, cache_config)));
        let cache_state = Arc::new(CacheState::new());
        //Create the Validator
        let client = Self {
            issuer,
            http_client,
            cache,
            cache_strat,
            cache_state,
        };

        // Replace the empty cache with data from the jwks endpoint before return
        // This ensures it's ready to validate immediatly after use.
        client.update_cache().await?;

        Ok(client)
    }

    fn openid_config_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", &self.issuer)
    }

    async fn get_openid_config(&self) -> Result<OidcConfig, anyhow::Error> {
        let request = self
            .http_client
            .get(&self.openid_config_url())
            .send()
            .await?;
        let config = request.json().await?;
        Ok(config)
    }

    async fn jwks_uri(&self) -> Result<String, anyhow::Error> {
        Ok(self.get_openid_config().await?.jwks_uri)
    }

    async fn get_jwks(&self) -> Result<JwkSetFetch, anyhow::Error> {
        let uri = &self.jwks_uri().await?;
        // Get the jwks endpoint
        debug!("Requesting JWKS From Uri: {uri}");

        let result = self.http_client.get(uri).send().await?;

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

        let jwks: JwkSet = result.json().await?;
        let fetched_at = current_time();
        Ok(JwkSetFetch {
            jwks,
            cache_policy,
            fetched_at,
        })
    }

    /// Triggers an immediate update from the JWKS URL
    async fn update_cache(&self) -> Result<CacheUpdateAction, anyhow::Error> {
        info!("Triggering update to JWKS Cache");
        let fetch = self.get_jwks().await;

        match fetch {
            Ok(fetch) => {
                self.cache_state.set_last_update(fetch.fetched_at);
                self.cache_state.set_is_error(false);
                let mut cache = self.cache.write().await;
                Ok(cache.update_fetch(fetch))
            }
            Err(e) => {
                self.cache_state.set_is_error(true);
                Err(e)
            }
        }
    }

    // Triggers an eventual update from the JWKS URL
    fn revalidate_cache(&self) {
        // only attempts to spawn a task if there isn't currently one running
        if !self.cache_state.is_revalidating() {
            let self_ref = self.clone();

            tokio::task::spawn(async move {
                self_ref.cache_state.set_is_revalidating(true);
                #[allow(unused_must_use)]
                {
                    self_ref.update_cache().await;
                };
                self_ref.cache_state.set_is_revalidating(false);
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
            // Even if it failed it. It may allow us to retrieve a key from stale-if-error
            #[allow(unused_must_use)]
            {
                self.update_cache().await;
            }
            self.get_kid(kid)
                .await
                .ok_or(JWKSValidationError::NonMatchingJWK)
        }
    }

    async fn get_kid(&self, kid: &str) -> Option<Arc<DecodingInfo>> {
        debug!("Waiting on read-lock for cache");
        let read_cache = &self.cache.read().await;

        let now = current_time();

        let fetched = self.cache_state.last_update();
        let max_age = fetched + read_cache.cache_policy.max_age.as_secs();

        if now <= max_age {
            return read_cache.get_key(kid);
        }

        // If the stale while revalidate setting is present
        if let Some(swr) = read_cache.cache_policy.stale_while_revalidate {
            // if we're within the SWR allowed window
            if now <= swr.as_secs() + max_age {
                self.revalidate_cache();
                return read_cache.get_key(kid);
            }
        }
        if let Some(swr_err) = read_cache.cache_policy.stale_if_error {
            // if the last update failed and the stale-if-error is present
            if now <= swr_err.as_secs() + max_age && self.cache_state.is_error() {
                self.revalidate_cache();
                return read_cache.get_key(kid);
            }
        }

        None
    }
}

/// Struct used to store all information needed to decode a JWT
/// Intended to be cached inside of `JwkSetCache` to prevent decoding information about the same JWK multiple times
#[allow(unused)]
pub struct DecodingInfo {
    jwk: Jwk,
    key: DecodingKey,
    validation: Validation,
    alg: Algorithm,
}
impl DecodingInfo {
    fn new(jwk: Jwk, key: DecodingKey, alg: Algorithm) -> Self {
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
    fetched_at: u64,
}


#[derive(Debug, Deserialize)]
struct OidcConfig {
    jwks_uri: String,
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