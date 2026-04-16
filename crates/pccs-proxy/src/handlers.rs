use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, Multipart, State};
use axum::http::StatusCode;
use axum::response::Json;
use serde::Serialize;

use crate::pccs::PccsClient;

/// Wrapper to match Phala's response format: `{ "quote_collateral": { ... } }`.
/// The MPC node deserializes this via `UploadResponse { quote_collateral: Collateral }`.
#[derive(Serialize)]
pub(crate) struct CollateralWrapper {
    quote_collateral: CollateralResponse,
}

#[derive(Serialize)]
pub(crate) struct CollateralResponse {
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

#[derive(Serialize)]
pub(crate) struct ErrorResponse {
    error: String,
}

pub async fn health(
    State(state): State<Arc<PccsClient>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let pccs_ok = state.check_pccs_reachable().await;
    if pccs_ok {
        Ok(Json(
            serde_json::json!({"status": "ok", "pccs": "reachable"}),
        ))
    } else {
        Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "PCCS is not reachable".to_string(),
        ))
    }
}

pub async fn verify_attestation(
    ConnectInfo(client_addr): ConnectInfo<std::net::SocketAddr>,
    State(state): State<Arc<PccsClient>>,
    mut multipart: Multipart,
) -> Result<Json<CollateralWrapper>, (StatusCode, Json<ErrorResponse>)> {
    let start = Instant::now();

    let quote_hex = extract_quote_hex(&mut multipart).await.map_err(|e| {
        tracing::error!(client = %client_addr, "Failed to extract hex field: {e}");
        error_response(StatusCode::BAD_REQUEST, e.to_string())
    })?;

    tracing::info!(
        client = %client_addr,
        quote_len = quote_hex.len(),
        "Received quote"
    );

    let collateral = state.get_collateral(&quote_hex).await.map_err(|e| {
        tracing::error!(
            client = %client_addr,
            elapsed_ms = start.elapsed().as_millis() as u64,
            "Failed to get collateral: {e}"
        );
        error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    tracing::info!(
        client = %client_addr,
        elapsed_ms = start.elapsed().as_millis() as u64,
        "Collateral returned successfully"
    );
    Ok(Json(CollateralWrapper {
        quote_collateral: CollateralResponse {
            tcb_info_issuer_chain: collateral.tcb_info_issuer_chain,
            tcb_info: collateral.tcb_info,
            tcb_info_signature: collateral.tcb_info_signature,
            qe_identity_issuer_chain: collateral.qe_identity_issuer_chain,
            qe_identity: collateral.qe_identity,
            qe_identity_signature: collateral.qe_identity_signature,
            pck_crl_issuer_chain: collateral.pck_crl_issuer_chain,
            root_ca_crl: collateral.root_ca_crl,
            pck_crl: collateral.pck_crl,
            pck_certificate_chain: collateral.pck_certificate_chain,
        },
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

fn error_response(status: StatusCode, message: String) -> (StatusCode, Json<ErrorResponse>) {
    (status, Json(ErrorResponse { error: message }))
}
