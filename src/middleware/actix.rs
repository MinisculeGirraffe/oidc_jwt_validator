use std::{
    future::{ready, Future, Ready},
    marker::PhantomData,
    ops::Deref,
    pin::Pin,
    rc::Rc,
};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::HttpError,
    http::header::HeaderValue,
    Error, FromRequest, HttpMessage, ResponseError,
};

use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;

use crate::{JWKSValidationError, Validator};

pub struct ValidatorMiddlewareFactory<Token, TokenErr>
where
    Token: DeserializeOwned,
    TokenErr: ResponseError + From<JWKSValidationError>,
{
    validator: Validator,
    token_type: PhantomData<Token>,
    token_error: PhantomData<TokenErr>,
}

impl<Token, Error> ValidatorMiddlewareFactory<Token, Error>
where
    Token: DeserializeOwned,
    Error: ResponseError + From<JWKSValidationError>,
{
    pub fn new(validator: Validator) -> Self {
        Self {
            validator,
            token_type: PhantomData,
            token_error: PhantomData,
        }
    }
}

impl<S, B, Token, TokenError> Transform<S, ServiceRequest>
    for ValidatorMiddlewareFactory<Token, TokenError>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    Token: DeserializeOwned + 'static,
    TokenError: ResponseError + From<JWKSValidationError> + 'static,
{
    type Response = ServiceResponse<B>;

    type Error = Error;

    type Transform = OidcMiddleWare<S, Token, TokenError>;

    type InitError = ();

    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(OidcMiddleWare {
            service: Rc::new(service),
            valitator: self.validator.clone(),
            token_type: PhantomData,
            token_error: PhantomData,
        }))
    }
}

pub struct OidcMiddleWare<S, Token, TokenError> {
    service: Rc<S>,
    valitator: Validator,
    token_error: PhantomData<TokenError>,
    token_type: PhantomData<Token>,
}

impl<S, B, Token, TokenErr> Service<ServiceRequest> for OidcMiddleWare<S, Token, TokenErr>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    Token: DeserializeOwned + 'static,
    TokenErr: ResponseError + From<JWKSValidationError> + 'static,
{
    type Response = ServiceResponse<B>;

    type Error = Error;

    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let srv = self.service.clone();
        let validator = self.valitator.clone();
        Box::pin(async move {
            let auth_header = req
                .headers()
                .get("Authorization")
                .ok_or_else(|| {
                    std::convert::Into::<TokenErr>::into(JWKSValidationError::MissingToken)
                })?
                .to_str()
                .map_err(|_| {
                    std::convert::Into::<TokenErr>::into(JWKSValidationError::TokenParseFailed)
                })?;
                
            let token = auth_header.replace("Bearer ", "");
            let result = validator
                .validate::<Token>(token)
                .await
                .map_err(|e| std::convert::Into::<TokenErr>::into(e))?;

            req.extensions_mut().insert(TokenInfo::new(result));
            let next = srv.call(req).await?;
            Ok(next)
        })
    }
}

#[derive(Debug, Clone)]
pub struct TokenInfo<Claims>(Rc<TokenData<Claims>>);

impl<T> Deref for TokenInfo<T> {
    type Target = TokenData<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> TokenInfo<T> {
    fn new(token: TokenData<T>) -> Self {
        Self(Rc::new(token))
    }
}
