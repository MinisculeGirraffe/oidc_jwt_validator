use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{jwk::Jwk, DecodingKey};

use crate::{DecodingInfo, JWKSValidationError};

pub(crate) fn decode_jwk(jwk: &Jwk) -> Result<(String, DecodingInfo), JWKSValidationError> {
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
            let info = DecodingInfo::new(jwk.clone(), dec_key, alg);
            Ok((kid, info))
        }
        _ => Err(JWKSValidationError::InvakidJKW),
    }
}

fn b64_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, JWKSValidationError> {
    base64::decode_config(input, base64::URL_SAFE_NO_PAD)
        .map_err(|_| JWKSValidationError::DecodeError)
}

pub(crate) fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time Went Backwards")
        .as_secs()
}
