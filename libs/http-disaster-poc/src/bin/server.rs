#[tokio::main]
async fn main() {
    let app_state = AppState::default();

    let app = Router::new()
        .route("/encrypted_secret", get(get_encrypted_secret))
        .route("/encrypted_secret", put(put_encrypted_secret))
        .with_state(app_state);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

#[derive(Clone)]
struct AppState {
    encrypted_secret: Arc<Mutex<String>>,
}

impl Default for AppState {
    fn default() -> Self {
        let secret = "Working software is the primary measure of progress.";
        let encrypted_secret = Arc::new(Mutex::new(
            dummy::SERVER_KEYPAIR
                .secret_key()
                .encrypt_to(dummy::CLIENT_KEYPAIR.public_key(), secret),
        ));
        Self { encrypted_secret }
    }
}

async fn get_encrypted_secret(_auth: BearerToken, State(state): State<AppState>) -> String {
    state.encrypted_secret.lock().unwrap().clone()
}

async fn put_encrypted_secret(
    _auth: BearerToken,
    State(state): State<AppState>,
    new_secret: String,
) -> StatusCode {
    let mut secret = state.encrypted_secret.lock().unwrap();

    let decrypted = dummy::SERVER_KEYPAIR
        .secret_key()
        .decrypt_from(dummy::CLIENT_KEYPAIR.public_key(), &new_secret);

    println!("Received secret: {decrypted}");

    *secret = new_secret;
    StatusCode::OK
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublicKeyResponse {
    key: PublicKey,
}

struct BearerToken;

impl<S> FromRequestParts<S> for BearerToken
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let headers = &parts.headers;

        if let Some(auth_header) = headers.get("authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    if token == dummy::BEARER_TOKEN {
                        return Ok(BearerToken);
                    }
                }
            }
        }

        Err(StatusCode::UNAUTHORIZED)
    }
}

use axum::{
    Router,
    extract::{FromRequestParts, State},
    http::{StatusCode, request::Parts},
    routing::{get, put},
};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

use http_disaster_poc::dummy;

use http_disaster_poc::encrypt::DecryptFrom as _;
use http_disaster_poc::encrypt::EncryptTo as _;
