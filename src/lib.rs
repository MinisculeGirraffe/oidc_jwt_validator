#![allow(unused)]
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation};
use openidconnect::core::CoreProviderMetadata;
use openidconnect::reqwest::async_http_client;
use openidconnect::IssuerUrl;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;

// get our oidc config
async fn get_provider(url: impl ToString) -> Result<CoreProviderMetadata, JWKSFetchError> {
    let issuer_url =
        IssuerUrl::new(url.to_string()).map_err(|_| JWKSFetchError::IssuerParseError)?;

    CoreProviderMetadata::discover_async(issuer_url, async_http_client)
        .await
        .map_err(|_| JWKSFetchError::DiscoverError)
}

#[derive(Debug)]
enum JWKSFetchError {
    RequestFailed,
    DiscoverError,
    JSONDecodeError,
    IssuerParseError,
}

#[derive(Debug)]
enum JWKSValidationError {
    InvalidHeader,
    MiddingKid,
    InvakidJKW,
    InvalidAlgo,
    NonMatchingJWK,
    DecodeError,
}

struct Validator {
    oidc_config: CoreProviderMetadata,
    http_client: reqwest::Client,
    cache: RwLock<JWKSCache>,
}

impl Validator {
    pub async fn new(
        oidc_url: impl AsRef<str>,
        http_client: reqwest::Client,
    ) -> Result<Validator, JWKSFetchError> {
        //Create an empty JWKS to initalize our Cache
        let jwks = JwkSet { keys: Vec::new() };
        let cache = RwLock::new(JWKSCache::new(jwks));

        //TODO CHANGE ME
        let oidc_config = get_provider(oidc_url.as_ref())
            .await
            .map_err(|_| JWKSFetchError::RequestFailed)?;

        //Create the Validator
        let client = Self {
            oidc_config,
            http_client,
            cache,
        };

        // Replace the empty cache with data from the jwks endpoint before return
        // This ensures it's ready to validate immediatly after use.
        client.update_cache().await?;

        Ok(client)
    }

    async fn get_jwks(&self) -> Result<JwkSet, JWKSFetchError> {
        // Get the jwks endpoint
        let jwks_uri = self.oidc_config.jwks_uri().as_str();

        // Send out GET HTTP Request
        let response = self
            .http_client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|_| JWKSFetchError::RequestFailed)?;

        //Parse the response into JSON
        response
            .json()
            .await
            .map_err(|_| JWKSFetchError::JSONDecodeError)
    }

    async fn update_cache(&self) -> Result<(), JWKSFetchError> {
        // Get the JWKS via HTTP Request, and a read lock on the cache simultanously
        // Most of the time the JWKS won't change
        // we first get a read lock to determine if is has changed or not, which will typically be the case
        // Since a read lock won't require exclusive access and disrupt validation temporarily
        let (new_jwks, read) = tokio::join!(self.get_jwks(), self.cache.read());
        let new_jwks = new_jwks?;

        // if the new jwks is the same as the old
        if read.jwks == new_jwks {
            // Early return without doing anything
            return Ok(());
        }
        // only runs If the new jwks has changed
        // Drop the read lock and acquire a write lock otherwise we deadlock
        drop(read);

        //acquire a write lock
        let mut write = self.cache.write().await;
        // Clear our cache of decoding keys
        write.decoding_map.clear();
        // Over-write the value inside of the RwLock
        write.jwks = new_jwks;

        Ok(())
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

        // Obtain a read only copy of our jwks cache
        let read_cache = self.cache.read().await;
        match read_cache.get_decoding_key(&kid) {
            Some((key, alg)) => self.decode::<T>(token, key, alg),
            // if we haven't decoded the JWK yet then do it and add it to our cache
            None => {
                // Drop our read lock
                drop(read_cache);
                // get a write lock and modify the cache
                {
                    let mut write_cache = self.cache.write().await;
                    write_cache
                        .add_decoding_key(kid.clone())
                        .map_err(|_| JWKSValidationError::MiddingKid)?;
                }

                //re-acquire the read lock
                let read_cache = self.cache.read().await;
                let (key, alg) = read_cache.get_decoding_key(&kid).unwrap();
                self.decode::<T>(token, key, alg)
            }
        }
    }

    fn decode<T>(
        &self,

        token: &str,
        key: &DecodingKey,
        alg: &Option<Algorithm>,
    ) -> Result<TokenData<T>, JWKSValidationError>
    where
        T: for<'de> serde::de::Deserialize<'de>,
    {
        let alg = alg.ok_or(JWKSValidationError::InvalidAlgo)?;
        let validation = Validation::new(alg);
        jsonwebtoken::decode::<T>(token, key, &validation)
            .map_err(|_| JWKSValidationError::DecodeError)
    }
}

struct JWKSCache {
    jwks: JwkSet,
    decoding_map: HashMap<String, (DecodingKey, Option<Algorithm>)>,
}
impl JWKSCache {
    pub fn new(jwks: JwkSet) -> Self {
        Self {
            jwks,
            decoding_map: HashMap::new(),
        }
    }

    pub fn get_decoding_key(&self, kid: &str) -> Option<&(DecodingKey, Option<Algorithm>)> {
        self.decoding_map.get(kid)
    }

    pub fn add_decoding_key(&mut self, kid: String) -> Result<(), CacheError> {
        // Otherwise check the jwks for the key id
        let jwk = self.jwks.find(&kid).ok_or(CacheError::MissingKid)?;

        let key = decode_jwk(jwk).map_err(|_| CacheError::DecodeError)?;

        self.decoding_map.insert(kid, (key, jwk.common.algorithm));
        Ok(())
    }
}

enum CacheError {
    MissingKid,
    DecodeError,
}

fn decode_jwk(jwk: &Jwk) -> Result<DecodingKey, jsonwebtoken::errors::Error> {
    match jwk.algorithm {
        jsonwebtoken::jwk::AlgorithmParameters::EllipticCurve(ref params) => {
            let x_cmp = b64_decode(&params.x)?;
            let y_cmp = b64_decode(&params.y)?;
            let mut public_key = Vec::with_capacity(1 + params.x.len() + params.y.len());
            public_key.push(0x04);
            public_key.extend_from_slice(&x_cmp);
            public_key.extend_from_slice(&y_cmp);
            Ok(DecodingKey::from_ec_der(&public_key))
        }
        jsonwebtoken::jwk::AlgorithmParameters::RSA(ref params) => {
            DecodingKey::from_rsa_components(&params.n, &params.e)
        }
        jsonwebtoken::jwk::AlgorithmParameters::OctetKey(ref params) => {
            DecodingKey::from_base64_secret(&params.value)
        }
        jsonwebtoken::jwk::AlgorithmParameters::OctetKeyPair(ref params) => {
            let der = b64_decode(&params.x)?;

            Ok(DecodingKey::from_ed_der(&der))
        }
    }
}

fn b64_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, jsonwebtoken::errors::Error> {
    base64::decode_config(input, base64::URL_SAFE_NO_PAD)
        .map_err(|e| jsonwebtoken::errors::ErrorKind::Base64(e).into())
}

struct ValidatorParent {
    validator: Arc<Validator>,
    update_task: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl ValidatorParent {
    async fn new(
        url: impl AsRef<str>,
        client: reqwest::Client,
        update_config: JwksUpdateConfig,
    ) -> Result<ValidatorParent, JWKSFetchError> {
        let validator = Arc::new(Validator::new(url.as_ref(), client).await?);
        // Unwrap is safe here because it's the first time we've spawned the task
        let update_task = Arc::new(Mutex::new(None));
        let updater = Self {
            validator,
            update_task,
        };

        updater.start_jwks_update(update_config).await;

        Ok(updater)
    }
    /// Spawns a tokio task that loops forever to periodically updating the JWKS cache
    /// Does nothing if a task has already been spawned
    pub async fn start_jwks_update(&self, config: JwksUpdateConfig) {
        let mut lock = self.update_task.lock().await;
        if lock.is_none() {
            // Create a copy of ourselves to move into the task
            let validator = self.validator.clone();
            let task = tokio::task::spawn(async move {
                let ok_period = Duration::from_secs(config.refresh);
                let err_period = Duration::from_secs(config.err_refresh);

                if !config.immediate_refresh {
                    // Immediatly wait for our sleep period once
                    // Since the validator comes pre-filled with the jwks keys
                    // We typically don't need to re-fetch them right away
                    tokio::time::sleep(ok_period).await;
                }
                //Infinite Loop
                loop {
                    match validator.update_cache().await {
                        Ok(_) => tokio::time::sleep(ok_period).await,
                        Err(_) => tokio::time::sleep(err_period).await,
                    };
                }
            });
            *lock = Some(task);
        }
    }

    /// Stops Updating the JWKS
    /// Does nothing if no task is currently running
    async fn stop_jwks_update(&self) {
        let mut lock = self.update_task.lock().await;

        if let Some(handle) = &*lock {
            handle.abort();
            *lock = None;
        };
    }
}

impl Deref for ValidatorParent {
    type Target = Arc<Validator>;

    fn deref(&self) -> &Self::Target {
        &self.validator
    }
}

impl Drop for ValidatorParent {
    fn drop(&mut self) {
        // clone the join handle that
        let update_task = self.update_task.clone();

        tokio::task::spawn(async move {
            // Wait for the lock
            let lock = update_task.lock().await;
            // If there's a running update task, abort it
            if let Some(handle) = &*lock {
                handle.abort()
            }
        });
    }
}
/// Determines settings about updating the JWKS in the background
/// By default will wait the entire refresh period before triggering an update
/// unless immediate_refresh is set to `true`.
#[derive(Debug, Clone, Copy)]
struct JwksUpdateConfig {
    /// Time in Seconds to refresh the JWKS from the OIDC Provider
    /// Default: 43200(12 hours)
    refresh: u64,
    /// Time in Seconds to attempt another refresh JWKS from the OIDC Provider after an error
    /// Default: 600(10 Minutes)
    err_refresh: u64,
    /// Immediatly trigger a refresh on first update
    /// Default: false
    immediate_refresh: bool,
}

impl Default for JwksUpdateConfig {
    fn default() -> Self {
        Self {
            refresh: 43200,
            err_refresh: 600,
            immediate_refresh: false,
        }
    }
}

struct ValidationConfig {
    validate_exp: bool,
}
