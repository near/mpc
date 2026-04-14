use axum::Router;
use axum::extract::{DefaultBodyLimit, Multipart, State};
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use clap::Parser;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const PCCS_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST_BODY_SIZE: usize = 1024 * 1024; // 1MB

/// Local PCCS proxy — Phala-compatible collateral endpoint backed by Intel PCCS.
#[derive(Parser)]
struct Args {
    /// Address and port to listen on.
    #[arg(long, default_value = "0.0.0.0:8082")]
    listen: SocketAddr,

    /// URL of the local Intel PCCS.
    #[arg(long, default_value = "https://localhost:8081")]
    pccs_url: reqwest::Url,
}

struct PccsClient {
    pccs_base_url: reqwest::Url,
    http: Client,
}

/// Wrapper to match Phala's response format: `{ "quote_collateral": { ... } }`.
/// The MPC node deserializes this via `UploadResponse { quote_collateral: Collateral }`.
#[derive(Serialize)]
struct CollateralWrapper {
    quote_collateral: CollateralResponse,
}

#[derive(Serialize)]
struct CollateralResponse {
    tcb_info_issuer_chain: String,
    tcb_info: String,
    tcb_info_signature: String,
    qe_identity_issuer_chain: String,
    qe_identity: String,
    qe_identity_signature: String,
    pck_crl_issuer_chain: String,
    root_ca_crl: String,
    pck_crl: String,
    pck_certificate_chain: String,
}

#[derive(Deserialize)]
struct TcbResponse {
    #[serde(alias = "tcbInfo")]
    tcb_info: serde_json::Value,
    signature: String,
}

#[derive(Deserialize)]
struct QeIdentityResponse {
    #[serde(alias = "enclaveIdentity")]
    enclave_identity: serde_json::Value,
    signature: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

async fn verify_attestation(
    State(state): State<Arc<PccsClient>>,
    mut multipart: Multipart,
) -> Result<Json<CollateralWrapper>, (StatusCode, Json<ErrorResponse>)> {
    let quote_hex = extract_quote_hex(&mut multipart).await.map_err(|e| {
        tracing::error!("Failed to extract hex field: {e}");
        error_response(StatusCode::BAD_REQUEST, e.to_string())
    })?;

    tracing::info!(quote_len = quote_hex.len(), "Received quote");

    let collateral = get_collateral(&state, &quote_hex).await.map_err(|e| {
        tracing::error!("Failed to get collateral: {e}");
        error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    tracing::info!("Collateral returned successfully");
    Ok(Json(CollateralWrapper {
        quote_collateral: collateral,
    }))
}

/// Extracts the hex-encoded TDX quote from the `hex` field in the multipart form.
async fn extract_quote_hex(multipart: &mut Multipart) -> anyhow::Result<String> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| anyhow::anyhow!("multipart error: {e}"))?
    {
        if field.name() == Some("hex") {
            let text = field
                .text()
                .await
                .map_err(|e| anyhow::anyhow!("failed to read hex field: {e}"))?;
            let trimmed = text.trim().to_string();
            if trimmed.is_empty() {
                anyhow::bail!("Empty quote");
            }
            return Ok(trimmed);
        }
    }
    anyhow::bail!("'hex' field not found in multipart form data")
}

async fn get_collateral(state: &PccsClient, quote_hex: &str) -> anyhow::Result<CollateralResponse> {
    let quote_bytes = hex::decode(quote_hex)?;
    let quote = dcap_qvl::quote::Quote::parse(&quote_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse TDX quote: {e}"))?;

    let fmspc = quote
        .fmspc()
        .map_err(|e| anyhow::anyhow!("Failed to extract FMSPC: {e}"))?;
    let fmspc_hex = hex::encode(fmspc);
    let ca_type = quote
        .ca()
        .map_err(|e| anyhow::anyhow!("Failed to extract CA type: {e}"))?;

    let pck_cert_chain = quote
        .raw_cert_chain()
        .map_err(|e| anyhow::anyhow!("Failed to extract PCK cert chain: {e}"))?;
    let pck_cert_chain_str = String::from_utf8(pck_cert_chain.to_vec())
        .map_err(|e| anyhow::anyhow!("PCK cert chain is not valid UTF-8: {e}"))?;

    tracing::info!(fmspc = %fmspc_hex, ca = %ca_type, "Parsed quote");

    // Fetch all collateral pieces from the local PCCS in parallel.
    let (tcb_result, qe_result, pck_crl_result, root_crl_result) = tokio::join!(
        fetch_tcb_info(state, &fmspc_hex),
        fetch_qe_identity(state),
        fetch_pck_crl(state, ca_type),
        fetch_root_ca_crl(state),
    );

    let (tcb_info, tcb_info_signature, tcb_info_issuer_chain) = tcb_result?;
    let (qe_identity, qe_identity_signature, qe_identity_issuer_chain) = qe_result?;
    let (pck_crl, pck_crl_issuer_chain) = pck_crl_result?;
    let root_ca_crl = root_crl_result?;

    Ok(CollateralResponse {
        tcb_info_issuer_chain,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain,
        qe_identity,
        qe_identity_signature,
        pck_crl_issuer_chain,
        root_ca_crl,
        pck_crl,
        pck_certificate_chain: pck_cert_chain_str,
    })
}

async fn fetch_tcb_info(
    state: &PccsClient,
    fmspc: &str,
) -> anyhow::Result<(String, String, String)> {
    let url = format!(
        "{}/tdx/certification/v4/tcb?fmspc={}",
        state.pccs_base_url.as_str().trim_end_matches('/'),
        fmspc
    );
    let resp = state.http.get(&url).send().await?;
    let issuer_chain = url_decode_header(&resp, "TCB-Info-Issuer-Chain")?;
    let body: TcbResponse = resp.json().await?;
    let tcb_info = serde_json::to_string(&body.tcb_info)?;
    Ok((tcb_info, body.signature, issuer_chain))
}

async fn fetch_qe_identity(state: &PccsClient) -> anyhow::Result<(String, String, String)> {
    let url = format!(
        "{}/tdx/certification/v4/qe/identity",
        state.pccs_base_url.as_str().trim_end_matches('/')
    );
    let resp = state.http.get(&url).send().await?;
    let issuer_chain = url_decode_header(&resp, "SGX-Enclave-Identity-Issuer-Chain")?;
    let body: QeIdentityResponse = resp.json().await?;
    let qe_identity = serde_json::to_string(&body.enclave_identity)?;
    Ok((qe_identity, body.signature, issuer_chain))
}

async fn fetch_pck_crl(state: &PccsClient, ca_type: &str) -> anyhow::Result<(String, String)> {
    let url = format!(
        "{}/sgx/certification/v4/pckcrl?ca={}",
        state.pccs_base_url.as_str().trim_end_matches('/'),
        ca_type
    );
    let resp = state.http.get(&url).send().await?;
    let issuer_chain = url_decode_header(&resp, "SGX-PCK-CRL-Issuer-Chain")?;
    // PCCS returns CRL as hex-encoded text
    let body = resp.text().await?;
    Ok((body, issuer_chain))
}

async fn fetch_root_ca_crl(state: &PccsClient) -> anyhow::Result<String> {
    let url = format!(
        "{}/sgx/certification/v4/rootcacrl",
        state.pccs_base_url.as_str().trim_end_matches('/')
    );
    let resp = state.http.get(&url).send().await?;
    // PCCS returns CRL as hex-encoded text
    Ok(resp.text().await?)
}

fn url_decode_header(resp: &reqwest::Response, header_name: &str) -> anyhow::Result<String> {
    let raw = resp
        .headers()
        .get(header_name)
        .ok_or_else(|| anyhow::anyhow!("Missing header: {header_name}"))?
        .to_str()
        .map_err(|e| anyhow::anyhow!("Invalid header value for {header_name}: {e}"))?;
    Ok(urlencoding::decode(raw)?.into_owned())
}

fn error_response(status: StatusCode, message: String) -> (StatusCode, Json<ErrorResponse>) {
    (status, Json(ErrorResponse { error: message }))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pccs_proxy=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();

    let http = Client::builder()
        .danger_accept_invalid_certs(true) // PCCS uses self-signed cert
        .timeout(PCCS_REQUEST_TIMEOUT)
        .build()
        .expect("Failed to build HTTP client");

    let state = Arc::new(PccsClient {
        pccs_base_url: args.pccs_url.clone(),
        http,
    });

    let app = Router::new()
        .route("/api/v1/attestations/verify", post(verify_attestation))
        .route("/health", get(health))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_SIZE))
        .with_state(state);

    tracing::info!(
        addr = %args.listen,
        pccs = %args.pccs_url,
        "Starting local PCCS proxy"
    );

    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .expect("Failed to bind");
    axum::serve(listener, app).await.expect("Server error");
}
