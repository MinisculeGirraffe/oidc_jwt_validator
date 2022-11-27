use std::{collections::HashMap, time::Duration};

use oidc_jwt_validator::{cache::Strategy, ValidationSettings, Validator};

const OIDC_URL: &str = "https://keycloak.udp.lgbt/realms/Main";
const TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUSS1Wei1jMU9uaGtJMmstUm1meFZmblh3VVlHTXR5Wk1ZQ1VlZjJxYUlNIn0.eyJleHAiOjE2Njk1ODg0NjIsImlhdCI6MTY2OTU4ODE2MiwiYXV0aF90aW1lIjoxNjY5NTg4MTU5LCJqdGkiOiI1MWFiNTY0Yi05Mjk1LTQ5OGUtYjliMS1hOTUxYjhmYWU3YzEiLCJpc3MiOiJodHRwczovL2tleWNsb2FrLnVkcC5sZ2J0L3JlYWxtcy9NYWluIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImVlM2E1NDU3LTdhODktNDczYS04ODhlLWQ0MzM2ZWZkMGJlNSIsInR5cCI6IkJlYXJlciIsImF6cCI6InBvc3RtYW4iLCJzZXNzaW9uX3N0YXRlIjoiYjM3Y2NlZDktNTgxZC00OTExLWJhZGEtMWM1ODE0MjNjYzQ5IiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIiwiZGVmYXVsdC1yb2xlcy1tYWluIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwic2lkIjoiYjM3Y2NlZDktNTgxZC00OTExLWJhZGEtMWM1ODE0MjNjYzQ5IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJTdXNzeSBCYWthIiwicHJlZmVycmVkX3VzZXJuYW1lIjoib3dvX3doYXRzX3RoaXMiLCJnaXZlbl9uYW1lIjoiU3Vzc3kiLCJmYW1pbHlfbmFtZSI6IkJha2EifQ.R6gZQI6u9YIU7ofqCUl0SjFhnxSfuQcj855S3I5p0sZluO-XmW5i3yqyDtQqDzOzQbMn_FHulhsK098iYg1LKPt6RxxLjs3qcKQ0otR-PhBmFkLi_RraV-Xm1tqVd77ORa_mfZHc1ilzvmMjch1K09i-NB36niuSYOH8k7HtH2sJE_FamB6SxEMN-uv6uuHHQPitSFWq2xM_oK0Mv_IsPIq5MV9WGZcG6AcJLwUQiBmQxB1RdZXEPIcgkqP3lVTTPduKiWRbFpfyGWybDNCsxS7y6zxKbOEizsElA6I8tuBxYTwVkO3qQ0qME-p92OwWk89v1O4iVg6CXFe350ICWA";

type TokenClaims = HashMap<String, serde_json::Value>;
#[tokio::main]
async fn main() {
    let client = reqwest::ClientBuilder::new()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    let mut settings = ValidationSettings::new();

    settings.set_issuer(&[OIDC_URL]);
    settings.set_audience(&["account"]);

    let validator = Validator::new(OIDC_URL, client, Strategy::Automatic, settings)
        .await
        .unwrap();

    let validation_result = validator.validate::<TokenClaims>(TOKEN).await;

    println!("{:?}", validation_result);
}
