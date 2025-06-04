#![allow(dead_code)]

use anyhow::{bail, Context};
use backon::{BackoffBuilder, ExponentialBuilder};
use dstack_sdk::dstack_client::{DstackClient, TcbInfo};
use hex::ToHex;
use http::status::StatusCode;
use reqwest::multipart::Form;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::time::Duration;
use tracing::{error, info};

/// Endpoint to contact dstack service.
/// Set to [`None`] which defaults to `/var/run/dstack.sock`
const ENDPOINT: Option<&str> = None;
/// URL for usbmission of tdx quote. Returns collateral to be used for verification.
const PHALA_TDX_QUOTE_UPLOAD_URL: &str = "https://proof.t16z.com/api/upload";
/// Expected HTTP [`StatusCode`] for a successful submission.
const PHALA_SUCCESS_STATUS_CODE: StatusCode = StatusCode::OK;
/// The maximum duration to wait for retrying request to Phala's endpoint, [`PHALA_TDX_QUOTE_UPLOAD_URL`].
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);

#[derive(Serialize, Deserialize)]
pub struct TeeAttestation {
    tcb_info: TcbInfo,
    tdx_quote: String,
    collateral: String,
}

#[derive(Deserialize)]
struct UploadResponse {
    quote_collateral: String,
    #[serde(rename = "checksum")]
    _checksum: String,
}

pub async fn get_tdx_quote(
    node_public_key: near_crypto::ED25519PublicKey,
) -> anyhow::Result<TeeAttestation> {
    let client = DstackClient::new(ENDPOINT);

    let client_info_response = client.info().await?;
    let tcb_info = client_info_response.tcb_info;

    let mut hasher = Sha3_256::new();
    hasher.update(node_public_key.0);
    let public_key_hash = hasher.finalize();

    let tdx_quote: String = client
        .get_quote(public_key_hash.into_iter().collect())
        .await?
        .quote
        .encode_hex();

    let quote_upload_response = {
        let reqwest_client = reqwest::Client::new();
        let tdx_quote = tdx_quote.clone();

        let upload_tdx_quote = async move || {
            let form = Form::new().text("hex", tdx_quote.clone());

            let response = reqwest_client
                .post(PHALA_TDX_QUOTE_UPLOAD_URL)
                .multipart(form)
                .send()
                .await?;

            let status = response.status();

            if status != PHALA_SUCCESS_STATUS_CODE {
                bail!("Got unexpected HTTP status code: response from phala http_endpoint: {:?}, expected: {:?}", status, PHALA_SUCCESS_STATUS_CODE);
            }

            response
                .json::<UploadResponse>()
                .await
                .context("Failed to deserialize response from Phala.")
        };

        let mut backoff = ExponentialBuilder::default()
            .with_max_delay(MAX_BACKOFF_DURATION)
            .without_max_times()
            .with_jitter()
            .build();

        // Loop until we have a response.
        loop {
            match upload_tdx_quote().await {
                Err(err) => {
                    let duration = backoff.next().unwrap_or(MAX_BACKOFF_DURATION);
                    error!("Failed to upload tdx_quote to Phala due to: {:?}", err);
                    info!("Retrying tdx_quote upload to Phala in {:?}", duration);
                    continue;
                }
                Ok(response) => break response,
            }
        }
    };

    let collateral = quote_upload_response.quote_collateral;
    Ok(TeeAttestation {
        tdx_quote,
        tcb_info,
        collateral,
    })
}
