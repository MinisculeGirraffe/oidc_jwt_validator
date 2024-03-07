use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{
    jwk::{Jwk, KeyAlgorithm},
    Algorithm, DecodingKey,
};

use crate::{DecodingInfo, FetchError, ValidationSettings};

pub(crate) fn decode_jwk(
    jwk: &Jwk,
    validation: &ValidationSettings,
) -> Result<(String, DecodingInfo), FetchError> {
    let kid = jwk.common.key_id.clone();

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
            let der = b64_decode(&params.x)?;

            Some(DecodingKey::from_ed_der(&der))
        }
    };

    let alg = jwk.common.key_algorithm.map(to_algorithm);

    match (kid, alg, dec_key) {
        (Some(kid), Some(alg), Some(dec_key)) => {
            let info = DecodingInfo::new(jwk.clone(), dec_key, alg?, validation);
            Ok((kid, info))
        }
        _ => Err(FetchError::InvalidJWK),
    }
}

// KeyAlgorithm::to_algorithm is private, so we implement an equivalent function here
fn to_algorithm(key_alg: KeyAlgorithm) -> Result<Algorithm, FetchError> {
    match key_alg {
        KeyAlgorithm::HS256 => Ok(Algorithm::HS256),
        KeyAlgorithm::HS384 => Ok(Algorithm::HS384),
        KeyAlgorithm::HS512 => Ok(Algorithm::HS512),
        KeyAlgorithm::RS256 => Ok(Algorithm::RS256),
        KeyAlgorithm::RS384 => Ok(Algorithm::RS384),
        KeyAlgorithm::RS512 => Ok(Algorithm::RS512),
        KeyAlgorithm::PS256 => Ok(Algorithm::PS256),
        KeyAlgorithm::PS384 => Ok(Algorithm::PS384),
        KeyAlgorithm::PS512 => Ok(Algorithm::PS512),
        KeyAlgorithm::ES256 => Ok(Algorithm::ES256),
        KeyAlgorithm::ES384 => Ok(Algorithm::ES384),
        KeyAlgorithm::EdDSA => Ok(Algorithm::EdDSA),
        _ => Err(FetchError::InvalidAlgorithm(key_alg.to_string())),
    }
}

fn b64_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(input)
}

pub(crate) fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time Went Backwards")
        .as_secs()
}

pub(crate) fn normalize_url(url: &str) -> String {
    let trimmed_url = url.trim_end_matches('/');
    let stripped_url = trimmed_url
        .strip_suffix(".well-known/openid-configuration")
        .map(|i| i.trim_end_matches('/'))
        .unwrap_or(trimmed_url);

    stripped_url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url() {
        assert_eq!(
            normalize_url("http://example.com//.well-known/openid-configuration"),
            "http://example.com"
        );
        assert_eq!(
            normalize_url("http://example.com/.well-known/openid-configuration"),
            "http://example.com"
        );
        assert_eq!(normalize_url("http://example.com//"), "http://example.com");
        assert_eq!(normalize_url("http://example.com/"), "http://example.com");
        assert_eq!(normalize_url("http://example.com"), "http://example.com");
    }
}
