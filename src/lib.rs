#![warn(clippy::pedantic)]
#![allow(unused, clippy::missing_errors_doc, clippy::must_use_candidate)]
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation};
use openidconnect::core::CoreProviderMetadata;
use openidconnect::reqwest::async_http_client;
use openidconnect::IssuerUrl;
use reqwest::header::ToStrError;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::task::{JoinHandle, self};
use tracing::instrument;

use tracing::{debug, info, warn};
pub mod middleware;

// get our oidc config
async fn get_provider(url: impl ToString) -> Result<CoreProviderMetadata, JWKSFetchError> {
    let issuer_url =
        IssuerUrl::new(url.to_string()).map_err(|_| JWKSFetchError::IssuerParseError)?;

    CoreProviderMetadata::discover_async(issuer_url, async_http_client)
        .await
        .map_err(|_| JWKSFetchError::DiscoverError)
}

#[derive(Debug)]
pub enum JWKSFetchError {
    RequestFailed,
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
    oidc_config: CoreProviderMetadata,
    http_client: reqwest::Client,
    cache: Arc<RwLock<JWKSCache>>,
}

impl Validator {
    pub async fn new(
        oidc_url: impl AsRef<str>,
        http_client: reqwest::Client,
    ) -> Result<(Validator,JoinHandle<()>), JWKSFetchError> {
        //Create an empty JWKS to initalize our Cache
        let jwks = JwkSet { keys: Vec::new() };
        let cache = Arc::new(RwLock::new(JWKSCache::new(jwks)));

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

        let task = {
            let validator = client.clone();
            tokio::task::spawn(async move {
                println!("Hello from bg-task");
                let duration = Duration::from_secs(10);
                //Infinite Loop
                loop {
                  
                    println!("Background Task: Attempting to update");
                    match validator.update_cache().await {
                        Ok(a) => {
                            tokio::time::sleep(duration).await;
                            println!("Background Task: Update Sucessful");
                        }
                        Err(e) => {
                           tokio::time::sleep(duration).await;
                            println!("Background Task: Update Failed: {:?}", e);
                        }
                    };
                }
            })
        };
        Ok((client,task))
    }

    async fn update_cache(&self) -> Result<CacheUpdateAction, JWKSFetchError> {
        println!("Triggering update to JWKS Cache");
        // Get the JWKS via HTTP Request, and a read lock on the cache simultanously
        // Most of the time the JWKS won't change
        // we first get a read lock to determine if is has changed or not, which will typically be the case
        // Since a read lock won't require exclusive access and disrupt validation temporarily
        let uri = self.oidc_config.jwks_uri().as_str().to_string();
        let new_jwks = tokio::task::spawn_blocking(move || get_jwks(&uri))
            .await
            .unwrap()?;
        println!("Update: Waiting on read lock");
        let read = self.cache.read().await;

        // if the new jwks is the same as the old
        if read.jwks == new_jwks {
            println!("JWKS Content has not changed since last update");
            return Ok(CacheUpdateAction::NoUpdate);
        }
        // Below only runs If the new jwks has changed
        // Drop the read lock and acquire a write lock otherwise we deadlock
        drop(read);
        println!("JWKS Content has changed since last update. Updating cache.");
        // Parse the JWKs into their decoding keys in a task
        // so we don't block the executor.
        let keys = {
            let new_jwks = new_jwks.clone();
            tokio::task::spawn_blocking(|| {
                new_jwks.keys.into_iter().filter_map(|i| decode_jwk(i).ok())
            })
            .await
            .map_err(|_| JWKSFetchError::IssuerParseError)?
        };
        //acquire a write lock only to make the updates to the cache
        let mut write = self.cache.write().await;
        // Over-write the value inside of the RwLock
        write.jwks = new_jwks;
        // Clear our cache of decoding keys
        write.decoding_map.clear();
        // Load the keys back into our cache hashmap.
        for key in keys {
            write.decoding_map.insert(key.0, Arc::new(key.1));
        }
        println!("Cache Update Complete");
        Ok(CacheUpdateAction::UpdateSucessful)
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
        println!("Checking KID: {kid}");
        match self.get_kid(&kid).await {
            // if we have it, then return it
            Some(key) => {
                println!("KID Present in cache");
                Ok(key)
            }
            // if we don't have it
            None => {
                // Try and invalidate our cache. Maybe the JWKS has changed
                if let Ok(action) = self.update_cache().await {
                    match action {
                        // If the cache hasn't changed then we know the kid just doesn't exist
                        CacheUpdateAction::NoUpdate => Err(JWKSValidationError::NonMatchingJWK),
                        // if the cache has changed, check if the kid is present
                        CacheUpdateAction::UpdateSucessful => self
                            .get_kid(kid)
                            .await
                            .ok_or(JWKSValidationError::NonMatchingJWK),
                    }
                } else {
                    Err(JWKSValidationError::NonMatchingJWK)
                }
            }
        }
        // If the kid isn't in the JWKS do a refresh on the JWKS URL to see if it's changed

        // if it's still not in the jwks after a refresh, return an error
    }

    async fn get_kid(&self, kid: impl AsRef<str>) -> Option<Arc<DecodingInfo>> {
        println!("get_kid: waiting on read_lock");
        let read_cache = &self.cache.read().await;
        println!("get_kid: got read_lock");
        // Check and see if the decoding key for the kid is in already in our cache
        read_cache.decoding_map.get(kid.as_ref()).cloned()
    }
}

struct JWKSCache {
    jwks: JwkSet,
    decoding_map: HashMap<String, Arc<DecodingInfo>>,
}
impl JWKSCache {
    pub fn new(jwks: JwkSet) -> Self {
        Self {
            jwks,
            decoding_map: HashMap::new(),
        }
    }
}

enum CacheError {
    MissingKid,
    DecodeError,
}

fn decode_jwk(jwk: Jwk) -> Result<(String, DecodingInfo), JWKSValidationError> {
    let kid = jwk.common.key_id.clone();
    let alg = jwk.common.algorithm;

    let dec_key = match jwk.algorithm {
        jsonwebtoken::jwk::AlgorithmParameters::EllipticCurve(ref params) => {
            let x_cmp = b64_decode(&params.x)?;
            let y_cmp = b64_decode(&params.y)?;
            let mut public_key = Vec::with_capacity(1 + params.x.len() + params.y.len());
            public_key.push(0x04);
            public_key.extend_from_slice(&x_cmp);
            public_key.extend_from_slice(&y_cmp);
            Some(DecodingKey::from_ec_der(&public_key))
        }
        jsonwebtoken::jwk::AlgorithmParameters::RSA(ref params) => {
            DecodingKey::from_rsa_components(&params.n, &params.e).ok()
        }
        jsonwebtoken::jwk::AlgorithmParameters::OctetKey(ref params) => {
            DecodingKey::from_base64_secret(&params.value).ok()
        }
        jsonwebtoken::jwk::AlgorithmParameters::OctetKeyPair(ref params) => {
            let der = b64_decode(&params.x).map_err(|_| JWKSValidationError::InvakidJKW)?;

            Some(DecodingKey::from_ed_der(&der))
        }
    };
    match (kid, alg, dec_key) {
        (Some(kid), Some(alg), Some(dec_key)) => {
            let info = DecodingInfo::new(jwk, dec_key, alg);
            Ok((kid, info))
        }
        _ => Err(JWKSValidationError::InvakidJKW),
    }
}

fn b64_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, JWKSValidationError> {
    base64::decode_config(input, base64::URL_SAFE_NO_PAD)
        .map_err(|e| JWKSValidationError::DecodeError)
}

/* 
///Wrapper Type for a Validator, and the associated task to update the JWKS
#[derive(Clone)]
pub struct ValidatorParent {
    validator: Validator,
    update_task: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl ValidatorParent {
    pub async fn new(
        url: impl AsRef<str>,
        client: reqwest::Client,
        update_config: JwksUpdateConfig,
    ) -> Result<(ValidatorParent,JoinHandle<()>), JWKSFetchError> {
        let validator = Validator::new(url.as_ref(), client).await?;
        let task = {
            let validator = validator.clone();
            tokio::spawn(async move {
                println!("Hello from bg-task");
                //Infinite Loop
                loop {
                  
                    println!("Background Task: Attempting to update");
                    match validator.update_cache().await {
                        Ok(a) => {
                            task::yield_now().await;
                            println!("Background Task: Update Sucessful");
                        }
                        Err(e) => {
                            task::yield_now().await;
                            println!("Background Task: Update Failed: {:?}", e);
                        }
                    };
                }
            })
        };
    
        let updater = Self {
            validator,
  
        };

   

        Ok(updater)
    }
    /// Spawns a tokio task that loops forever to periodically updating the JWKS cache
    /// Does nothing if a task has already been spawned
    pub async fn start_jwks_update(&self, config: JwksUpdateConfig) {
        println!("Getting Task Lock");

        let mut lock = self.update_task.lock().await;
        if lock.is_none() {
            println!("Task slot is none");
            // Create a copy of ourselves to move into the task
            let validator = self.validator.clone();
            let task = tokio::spawn(async move {
                println!("Hello from bg-task");
                //Infinite Loop
                loop {
                    println!("Background Task: Attempting to update");
                    match validator.update_cache().await {
                        Ok(a) => {
                            println!("Background Task: Update Sucessful");
                        }
                        Err(e) => {
                            println!("Background Task: Update Failed: {:?}", e);
                        }
                    };
                }
            });

            println!("Updated task slot to Some");
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
    type Target = Validator;

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
            let mut lock = update_task.lock().await;
            // If there's a running update task, abort it
            if let Some(handle) = &*lock {
                handle.abort();
                *lock = None;
            }
        });
    }
}
*/

/// Determines settings about updating the JWKS in the background
/// By default will wait the entire refresh period before triggering an update
/// unless `immediate_refresh` is set to `true`.
#[derive(Debug, Clone, Copy)]
pub struct JwksUpdateConfig {
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
            refresh: 1,
            err_refresh: 1,
            immediate_refresh: false,
        }
    }
}

// Todo Fetch the jwks based on the cache control header.
// the poll time should be the cache control header
// if no-cache then we should poll for a minimum amount of time
// instead of literally just requesting it for every authentication
// because like holy fuck that just seems inefficent

enum CacheStrat {
    Automatic,
    ManualRefresh(JwksUpdateConfig),
}

enum CacheUpdateAction {
    // We checked the JWKS uri and it was the same as the last time we refreshed it so no action was taken
    NoUpdate,
    // We checked the JWKS uri and it was different so we updated our local cache
    UpdateSucessful,
}

/// Struct used to store all information needed to decode a JWT
/// Intended to be cached to prevent decoding information about the same JWK multiple times
struct DecodingInfo {
    jwk: Jwk,
    key: DecodingKey,
    alg: Algorithm,
}
impl DecodingInfo {
    fn new(jwk: Jwk, key: DecodingKey, alg: Algorithm) -> Self {
        Self { jwk, key, alg }
    }

    fn decode<T>(&self, token: &str) -> Result<TokenData<T>, JWKSValidationError>
    where
        T: for<'de> serde::de::Deserialize<'de>,
    {
        println!("Validating Token");
        let validation = Validation::new(self.alg);
        jsonwebtoken::decode::<T>(token, &self.key, &validation).map_err(|e| {
            println!("{e}");
            JWKSValidationError::DecodeError
        })
    }
}

fn get_jwks(uri: &str) -> Result<JwkSet, JWKSFetchError> {
    // Get the jwks endpoint
    println!("Requesting JWKS From Uri: {uri}");
    // Send out GET HTTP Request
    let client = reqwest::ClientBuilder::new().build().unwrap();

    let result = reqwest::blocking::get(uri).map_err(|e| {
        println!("{e}");
        JWKSFetchError::RequestFailed
    })?;

    println!("Waiting for json");
    //Parse the response into JSON
    let json = result.json().map_err(|e| {
        println!("{e}");
        JWKSFetchError::JSONDecodeError
    });

    println!("got  json");

    json
}
