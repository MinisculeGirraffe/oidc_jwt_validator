#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

use serde::Deserialize;
use thiserror::Error;
use util::normalize_url;

use crate::{
    cache::{JwkSetStore, Settings, State, Strategy, UpdateAction},
    util::current_time,
};
use log::{debug, info, warn};
use tokio::sync::{Notify, RwLock};

use jsonwebtoken::{
    jwk::{Jwk, JwkSet},
    Algorithm, DecodingKey, TokenData, Validation,
};
use reqwest::header::CACHE_CONTROL;
use std::{collections::HashSet, sync::Arc};

pub mod cache;
pub mod util;

/// Primary interface used for validating JWTs.
#[derive(Clone)]
pub struct Validator {
    issuer: String,
    http_client: reqwest::Client,
    cache: Arc<RwLock<JwkSetStore>>,
    cache_strat: Strategy,
    cache_state: Arc<State>,
    notifier: Arc<Notify>,
}

impl Validator {
    pub async fn new(
        oidc_issuer: impl AsRef<str>,
        http_client: reqwest::Client,
        cache_strat: Strategy,
        validation: ValidationSettings,
    ) -> Result<Validator, FetchError> {
        let issuer = normalize_url(oidc_issuer.as_ref());

        //Create an empty JWKS to initalize our Cache
        let jwks = JwkSet { keys: Vec::new() };

        let cache_config = match cache_strat {
            Strategy::Automatic => Settings::default(),
            Strategy::Manual(config) => config,
        };

        let cache = Arc::new(RwLock::new(JwkSetStore::new(
            jwks,
            cache_config,
            validation,
        )));

        let cache_state = Arc::new(State::new());

        //Create the Validator
        let client = Self {
            issuer,
            http_client,
            cache,
            cache_strat,
            cache_state,
            notifier: Arc::new(Notify::new()),
        };

        // Replace the empty cache with data from the jwks endpoint before return
        // This ensures it's ready to validate immediatly once returned
        client.update_cache().await?;

        Ok(client)
    }

    fn openid_config_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", &self.issuer)
    }

    async fn get_openid_config(&self) -> Result<OidcConfig, FetchError> {
        let request = self
            .http_client
            .get(&self.openid_config_url())
            .send()
            .await?;
        let config = request.json().await?;
        Ok(config)
    }

    async fn jwks_uri(&self) -> Result<String, FetchError> {
        Ok(self.get_openid_config().await?.jwks_uri)
    }

    /// Triggers an HTTP Request to get a fresh `JwkSet`
    async fn get_jwks(&self) -> Result<JwkSetFetch, FetchError> {
        let uri = &self.jwks_uri().await?;
        // Get the jwks endpoint
        debug!("Requesting JWKS From Uri: {uri}");
        let result = self.http_client.get(uri).send().await?;

        let cache_policy = {
            // If we haven't manually set a caching strategy
            if self.cache_strat == Strategy::Automatic {
                // Determine it from the cache_control header
                let cache_control = result.headers().get(CACHE_CONTROL);
                let cache_policy = Settings::from_header_val(cache_control);
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
    /// Will only write lock the [`JwkSetStore`] if there is an actual change to the contents.
    async fn update_cache(&self) -> Result<UpdateAction, FetchError> {
        let fetch = self.get_jwks().await;
        match fetch {
            Ok(fetch) => {
                self.cache_state.set_last_update(fetch.fetched_at);
                info!("Set Last update to {:#?}", fetch.fetched_at);
                self.cache_state.set_is_error(false);
                let read = self.cache.read().await;

                if read.jwks == fetch.jwks
                    && fetch.cache_policy.unwrap_or(read.cache_policy) == read.cache_policy
                {
                    return Ok(UpdateAction::NoUpdate);
                }
                drop(read);
                let mut write = self.cache.write().await;

                Ok(write.update_fetch(fetch))
            }
            Err(e) => {
                self.cache_state.set_is_error(true);
                Err(e)
            }
        }
    }

    /// Triggers an eventual update from the JWKS URL
    /// Will only ever spawn one task at a single time.
    /// If called while an update task is currently running, will do nothing.
    fn revalidate_cache(&self) {
        if !self.cache_state.is_revalidating() {
            self.cache_state.set_is_revalidating(true);
            info!("Spawning Task to re-validate JWKS");
            let a = self.clone();
            #[allow(unused_must_use)]
            tokio::task::spawn(async move {
                a.update_cache().await;
                a.cache_state.set_is_revalidating(false);
                a.notifier.notify_waiters();
            });
        }
    }

    /// If we are currently updating the JWKS in the background this function will resolve when the update it complete
    /// If we are not currently updating the JWKS in the backgroun, this function will resolve immediatly.
    async fn wait_update(&self) {
        if self.cache_state.is_revalidating() {
            self.notifier.notified().await;
        }
    }

    /// Validates a JWT, Returning the claims serialized into type of T
    pub async fn validate<T>(&self, token: impl AsRef<str>) -> Result<TokenData<T>, ValidationError>
    where
        T: for<'de> serde::de::Deserialize<'de>,
    {
        let token = token.as_ref();
        // Early return error conditions before acquiring a read lock
        let header = jsonwebtoken::decode_header(token)?;
        let kid = header.kid.ok_or(ValidationError::MissingKIDToken)?;
        let decoding_key = self.get_kid_retry(kid).await?.ok_or(ValidationError::MissingKIDJWKS)?;
        let decoded = decoding_key.decode(token)?;

        Ok(decoded)
    }
    /// Primary method for getting the [`DecodingInfo`] for a JWK needed to validate a JWT.
    /// If the kid was not present in [`JwkSetStore`]
    async fn get_kid_retry(
        &self,
        kid: impl AsRef<str>,
    ) -> Result<Option<Arc<DecodingInfo>>, ValidationError> {
        let kid = kid.as_ref();
        // Check to see if we have the kid
        if let Ok(Some(key)) = self.get_kid(kid).await {
            // if we have it, then return it
            Ok(Some(key))
        } else {
            // Try and invalidate our cache. Maybe the JWKS has changed or our cached values expired
            // Even if it failed it. It may allow us to retrieve a key from stale-if-error
            self.revalidate_cache();
            self.wait_update().await;
            self.get_kid(kid).await
        }
    }

    /// Gets the decoding components of a JWK by kid from the JWKS in our cache
    /// Returns an Error, if the cache is stale and beyond the Stale While Revalidate and Stale If Error allowances configured in [`crate::cache::Settings`]
    /// Returns Ok if the cache is not stale.
    /// Returns Ok after triggering a background update of the JWKS If the cache is stale but within the Stale While Revalidate and Stale If Error allowances.
    async fn get_kid(&self, kid: &str) -> Result<Option<Arc<DecodingInfo>>, ValidationError> {
        let read_cache = self.cache.read().await;
        let fetched = self.cache_state.last_update();
        let max_age_secs = read_cache.cache_policy.max_age.as_secs();

        let max_age = fetched + max_age_secs;
        let now = current_time();
        let val = read_cache.get_key(kid);

        if now <= max_age {
            return Ok(val);
        }

        // If the stale while revalidate setting is present
        if let Some(swr) = read_cache.cache_policy.stale_while_revalidate {
            // if we're within the SWR allowed window
            if now <= swr.as_secs() + max_age {
                self.revalidate_cache();
                return Ok(val);
            }
        }
        if let Some(swr_err) = read_cache.cache_policy.stale_if_error {
            // if the last update failed and the stale-if-error is present
            if now <= swr_err.as_secs() + max_age && self.cache_state.is_error() {
                self.revalidate_cache();
                return Ok(val);
            }
        }
        drop(read_cache);
        info!("Returning None: {now} - {max_age}");
        Err(ValidationError::CacheError)
    }
}

/// Struct used to store the computed information needed to decode a JWT
/// Intended to be cached inside of [`JwkSetStore`] to prevent decoding information about the same JWK more than once
#[allow(unused)]
pub struct DecodingInfo {
    jwk: Jwk,
    key: DecodingKey,
    validation: Validation,
    alg: Algorithm,
}
impl DecodingInfo {
    fn new(
        jwk: Jwk,
        key: DecodingKey,
        alg: Algorithm,
        validation_settings: &ValidationSettings,
    ) -> Self {
        let mut validation = Validation::new(alg);

        validation.aud = validation_settings.aud.clone();
        validation.iss = validation_settings.iss.clone();
        validation.leeway = validation_settings.leeway;
        validation.required_spec_claims = validation_settings.required_spec_claims.clone();

        validation.sub = validation_settings.sub.clone();
        validation.validate_exp = validation_settings.validate_exp;
        validation.validate_nbf = validation_settings.validate_nbf;

        Self {
            jwk,
            key,
            validation,
            alg,
        }
    }

    fn decode<T>(&self, token: &str) -> Result<TokenData<T>, ValidationError>
    where
        T: for<'de> serde::de::Deserialize<'de>,
    {
        Ok(jsonwebtoken::decode::<T>(
            token,
            &self.key,
            &self.validation,
        )?)
    }
}

/// Helper Stuct that contains the response of a request to the jwks uri
/// `cache_policy` will be Some when [`cache::Strategy`] is set to [`cache::Strategy::Automatic`].
#[derive(Debug)]
pub(crate) struct JwkSetFetch {
    jwks: JwkSet,
    cache_policy: Option<Settings>,
    fetched_at: u64,
}

#[derive(Debug, Deserialize)]
struct OidcConfig {
    jwks_uri: String,
}

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("HTTP Request Failed")]
    RequestFailed(#[from] reqwest::Error),
    #[error("Failed to discover OIDC Configuration")]
    DiscoverError,
    #[error("Decoding of JWKS Failed")]
    DecodeError(#[from] base64::DecodeError),
    #[error("JWT was missing kid, alg, or decoding components")]
    InvalidJWK,
    #[error("Issuer URL Invalid")]
    IssuerParseError,
    #[error("Invalid algorithm {0}")]
    InvalidAlgorithm(String),
}

#[derive(Debug, Error)]
pub enum ValidationError {
    /// Failure of validating the token. See [jsonwebtoken::errors::ErrorKind] for possible reasons this value could be returned
    /// Would typically result in a 401 HTTP Status code
    #[error("JWT Is Invalid")]
    ValidationFailed(#[from] jsonwebtoken::errors::Error),
    /// Failure to re-validate the JWKS.
    /// Would typically result in a 401 or 500 status code depending on preference
    #[error("Token was unable to be validated due to cache expiration.")]
    CacheError,
    /// Token did not contain a kid in its header and would be impossible to validate
    /// Would typically result in a 401 HTTP Status code
    #[error("Token did not contain a KID field")]
    MissingKIDToken,
    #[error("The KID in the token was not present in the JWKS")]
    MissingKIDJWKS
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationSettings {
    pub required_spec_claims: HashSet<String>,
    pub leeway: u64,
    pub validate_exp: bool,
    pub validate_nbf: bool,
    pub aud: Option<HashSet<String>>,
    pub iss: Option<HashSet<String>>,
    pub sub: Option<String>,
}

impl ValidationSettings {
    pub fn new() -> Self {
        let mut required_spec_claims = HashSet::with_capacity(1);
        required_spec_claims.insert("exp".to_owned());

        Self {
            required_spec_claims,
            leeway: 60,
            validate_exp: true,
            validate_nbf: false,
            aud: None,
            iss: None,
            sub: None,
        }
    }

    /// `aud` is a collection of one or more acceptable audience members
    /// The simple usage is `set_audience(&["some aud name"])`
    pub fn set_audience<T: ToString>(&mut self, items: &[T]) {
        self.aud = Some(items.iter().map(std::string::ToString::to_string).collect());
    }

    /// `iss` is a collection of one or more acceptable issuers members
    /// The simple usage is `set_issuer(&["some iss name"])`
    pub fn set_issuer<T: ToString>(&mut self, items: &[T]) {
        self.iss = Some(items.iter().map(std::string::ToString::to_string).collect());
    }

    /// Which claims are required to be present for this JWT to be considered valid.
    /// The only values that will be considered are "exp", "nbf", "aud", "iss", "sub".
    /// The simple usage is `set_required_spec_claims(&["exp", "nbf"])`.
    /// If you want to have an empty set, do not use this function - set an empty set on the struct
    /// param directly.
    pub fn set_required_spec_claims<T: ToString>(&mut self, items: &[T]) {
        self.required_spec_claims = items.iter().map(std::string::ToString::to_string).collect();
    }
}

impl Default for ValidationSettings {
    fn default() -> Self {
        Self::new()
    }
}
