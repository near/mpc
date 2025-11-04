use std::sync::Arc;

use anyhow::Context;
use ed25519_dalek::VerifyingKey;
use hyper::{body::to_bytes, client::conn::SendRequest, Body, Request};
use mpc_contract::primitives::key_state::Keyset;
use mpc_tls::tls::configure_tls;
use tokio::net::TcpStream;

use crate::{
    keyshare::Keyshare,
    migration_service::web::{
        authentication::authenticate_peer,
        serialization::{decrypt_and_deserialize_keyshares, serialize_and_encrypt_keyshares},
    },
};

#[allow(dead_code)]
/// Connects to the web server, performs the TLS handshake and returns the connection.
pub async fn connect_to_web_server(
    p2p_private_key: &ed25519_dalek::SigningKey,
    target_address: impl tokio::net::ToSocketAddrs + std::fmt::Debug,
    expected_server_key: &VerifyingKey,
) -> anyhow::Result<SendRequest<Body>> {
    tracing::info!(?target_address, "connecting on ");
    let (_server_config, client_config) = configure_tls(p2p_private_key)?;
    let conn = TcpStream::connect(target_address)
        .await
        .context("TCP connect")?;
    let tls_conn = tokio_rustls::TlsConnector::from(Arc::new(client_config))
        .connect("dummy".try_into().unwrap(), conn)
        .await
        .context("TLS connect")?;

    authenticate_peer(tls_conn.get_ref().1, expected_server_key)?;

    tracing::info!(
        "TLS handshake complete, mpc node authenticated and encrypted channel established."
    );

    let (request_sender, connection) = hyper::client::conn::handshake(tls_conn)
        .await
        .context("failed to perform HTTP handshake")?;

    // Run the connection driver in the background.
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            tracing::error!("Connection error: {err}");
        }
    });

    Ok(request_sender)
}

/// server matches on path only
const BOGUS_URL: &str = "http://example";
pub async fn make_hello_request(request_sender: &mut SendRequest<Body>) -> anyhow::Result<String> {
    let req = Request::builder()
        .method("GET")
        .uri(format!("{}/hello", BOGUS_URL))
        .body(hyper::Body::empty())?;

    let response = request_sender.send_request(req).await?;
    let body_bytes = to_bytes(response.into_body()).await?;
    let body_str = String::from_utf8_lossy(&body_bytes);

    tracing::info!("Response: {}", body_str);
    Ok(body_str.to_string())
}

pub async fn make_keyshare_get_request(
    request_sender: &mut SendRequest<Body>,
    keyset: &Keyset,
    backup_encryption_key: &[u8; 32],
) -> anyhow::Result<Vec<Keyshare>> {
    let params = serde_json::json!(keyset);
    let req = Request::builder()
        .method("GET")
        .uri(format!("{}/get_keyshares", BOGUS_URL))
        .body(hyper::Body::from(params.to_string()))
        .inspect_err(|err| tracing::error!(?err, "building request failed"))?;

    let response = request_sender
        .send_request(req)
        .await
        .inspect_err(|err| tracing::error!(?err, "sending request failed"))?;
    // Check HTTP status
    if !response.status().is_success() {
        let status = response.status();
        let body_bytes = to_bytes(response.into_body())
            .await
            .context("failed to read error body")?;
        let body_str = String::from_utf8_lossy(&body_bytes);
        anyhow::bail!("server returned {}: {}", status, body_str);
    }

    // Collect the response body
    let body_bytes = to_bytes(response.into_body())
        .await
        .inspect_err(|err| tracing::error!(?err, "failed to read body"))?;

    let keyshares: Vec<Keyshare> =
        decrypt_and_deserialize_keyshares(&body_bytes, backup_encryption_key)?;

    tracing::debug!("Received keyshares: {:?}", keyshares);

    Ok(keyshares)
}

pub async fn make_set_keyshares_request(
    request_sender: &mut SendRequest<Body>,
    keyshares: &[Keyshare],
    backup_encryption_key: &[u8; 32],
) -> anyhow::Result<()> {
    tracing::info!("making set keyshares request");
    let body = serialize_and_encrypt_keyshares(keyshares, backup_encryption_key)?;
    let req = Request::builder()
        .method("PUT")
        .uri(format!("{}/set_keyshares", BOGUS_URL))
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))?;
    let response = request_sender
        .send_request(req)
        .await
        .inspect_err(|err| tracing::error!(?err, "error"))?;

    // Check status code
    if !response.status().is_success() {
        let status = response.status();
        let body_bytes = to_bytes(response.into_body())
            .await
            .context("failed to read error body")?;
        let body_str = String::from_utf8_lossy(&body_bytes);
        anyhow::bail!("server returned {}: {}", status, body_str);
    }

    // Optionally read response body (the server sends "Keyshares received.")
    let body_bytes = to_bytes(response.into_body())
        .await
        .context("failed to read response body")?;
    let body_str = String::from_utf8_lossy(&body_bytes);

    tracing::info!("Server response: {}", body_str);

    Ok(())
}
