use std::fmt::Display;
use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::time::Duration;

use actix_web::FromRequest;
use actix_web::{http::StatusCode, web, App, HttpResponse, HttpServer, Responder, ResponseError};
use jsonwebtoken::TokenData;
use oidc_jwt_validator::cache::Strategy;
use oidc_jwt_validator::Validator;
use serde::Deserialize;

async fn greet(user: Authenticated<UserClaims>) -> impl Responder {
    format!("Hello {}!", user.claims.email)
}

#[tokio::main] //
async fn main() -> std::io::Result<()> {
    let oidc_url = "https://keycloak.udp.lgbt/realms/Main";

    let client = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    let validator = Validator::new(oidc_url, client, Strategy::Automatic)
        .await
        .unwrap();

    let _server = HttpServer::new(move || {
        App::new()
            .app_data(validator.clone())
            .route("/", web::get().to(greet))
    })
    .bind(("0.0.0.0", 8080))
    .unwrap()
    .run()
    .await;

    Ok(())
}
#[derive(Debug, Deserialize, Clone)]
struct UserClaims {
    email: String,
}

struct Authenticated<T>(TokenData<T>);

impl<T> FromRequest for Authenticated<T>
where
    T: for<'de> serde::de::Deserialize<'de> + Sized + Send + 'static,
{
    type Error = AuthError;

    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>> + 'static>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            let validator = req.app_data::<Validator>().ok_or(AuthError::Failed)?;
            let token2 = req
                .headers()
                .get("Authorization")
                .ok_or(AuthError::Failed)?
                .to_str()
                .map_err(|_| AuthError::Failed)?
                .replace("Bearer ", "");

            let valid_token = validator.validate::<T>(token2).await?;

            Ok(Authenticated(valid_token))
        })
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

impl From<oidc_jwt_validator::ValidationError> for AuthError {
    fn from(_: oidc_jwt_validator::ValidationError) -> Self {
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
