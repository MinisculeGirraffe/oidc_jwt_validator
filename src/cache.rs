#![allow(clippy::module_name_repetitions, clippy::missing_panics_doc)]
use reqwest::header::HeaderValue;
use std::time::Duration;


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
    pub immutable: bool,
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
                (Some("immutable"), None) => {
                    self.immutable = true;
                }
                _ => continue,
            };
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(2),
            stale_while_revalidate: None,
            stale_if_error: None,
            immutable: false,
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
impl CacheUpdateAction {
    // Determines if the content of the jwks has changed
    pub(crate) fn content_changed(&self) -> bool {
        match self {
            CacheUpdateAction::NoUpdate | CacheUpdateAction::CacheUpdate(_) => false,
            CacheUpdateAction::JwksUpdate | CacheUpdateAction::JwksAndCacheUpdate(_) => true,
        }
    }

    pub(crate) fn cache_changed(&self) -> Option<CacheConfig> {
        match self {
            CacheUpdateAction::NoUpdate | CacheUpdateAction::JwksUpdate => None,

            CacheUpdateAction::CacheUpdate(val) | CacheUpdateAction::JwksAndCacheUpdate(val) => {
                Some(*val)
            }
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheError {
    MissingKid,
    DecodeError,
}

#[cfg(test)]
mod tests {
    #[test]
    fn validate_headers() {
        let input = vec![
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
