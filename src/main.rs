use std::fmt::Display;
use std::future::{ready, Ready};
use std::ops::Deref;
use std::time::Duration;

use actix_web::{http::StatusCode, web, App, HttpResponse, HttpServer, Responder, ResponseError};
use actix_web::{FromRequest, HttpMessage};
use jsonwebtoken::TokenData;
use oidc_jwt_validator::middleware::actix::{TokenInfo, ValidatorMiddlewareFactory};
use oidc_jwt_validator::Validator;
use serde::Deserialize;
async fn greet(user: Authenticated<UserClaims>) -> impl Responder {
    format!("Hello {}!", user.claims.email)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    // construct a metrics taskmonitor

    let oidc_url = "https://keycloak.udp.lgbt/realms/Main";

    let client = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    let (validator, task) = Validator::new(oidc_url, client).await.unwrap();

    let server = HttpServer::new(move || {
        App::new()
            .wrap(ValidatorMiddlewareFactory::<UserClaims, AuthError>::new(
                validator.clone(),
            ))
            .route("/", web::get().to(greet))
    })
    .bind(("0.0.0.0", 8081))
    .unwrap()
    .run();

    tokio::join!(server, task);

    Ok(())
}
#[derive(Debug, Deserialize, Clone)]
struct UserClaims {
    email: String,
}

struct Authenticated<T>(TokenInfo<T>);

impl<T> FromRequest for Authenticated<T>
where
    T: Clone + 'static,
{
    type Error = AuthError;

    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let auth = req.extensions().get::<TokenInfo<T>>().cloned();
        let result = match auth {
            Some(auth) => Ok(Authenticated(auth)),
            None => Err(AuthError::Failed),
        };

        ready(result)
    }
}

impl<T> Deref for Authenticated<T> {
    type Target = TokenData<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone)]
enum AuthError {
    Failed,
}
impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Auth Failed")
    }
}

impl From<oidc_jwt_validator::JWKSValidationError> for AuthError {
    fn from(_: oidc_jwt_validator::JWKSValidationError) -> Self {
        Self::Failed
    }
}

impl ResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        match self {
            AuthError::Failed => StatusCode::UNAUTHORIZED,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::new(self.status_code())
    }
}
