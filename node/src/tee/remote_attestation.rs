#![allow(dead_code)]

use anyhow::{bail, Context};
use backon::{BackoffBuilder, ExponentialBuilder};
use dstack_sdk::dstack_client::{DstackClient, TcbInfo};
use hex::ToHex;
use http::status::StatusCode;
use reqwest::multipart::Form;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_384};
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
/// Number of bytes for the report data.
/// report_data: [u8; 64] = [version(1 byte) || sha384(TLS pub key || account public key ) || zero padding]
const REPORT_DATA_SIZE: usize = 64;

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

pub struct BinaryVersion(u8);

/// Generates a [`TeeAttestation`] for this node, which can be used to send to the contract to prove that
/// the node is running in a `TEE` context.
///
/// Returns an [`anyhow::Error`] if a non-transient error occurs, that prevents the node
/// from generating the attestation.
pub async fn create_remote_attestation_info(
    binary_version: BinaryVersion,
    tls_public_key: near_crypto::ED25519PublicKey,
    account_public_key: near_crypto::ED25519PublicKey,
) -> anyhow::Result<TeeAttestation> {
    let client = DstackClient::new(ENDPOINT);

    let client_info_response = client.info().await?;
    let tcb_info = client_info_response.tcb_info;

    let report_data = {
        let mut hasher = Sha3_384::new();
        hasher.update(tls_public_key.0);
        hasher.update(account_public_key.0);

        let public_keys_hash = hasher.finalize();

        let mut report_data = [0_u8; REPORT_DATA_SIZE];

        report_data[0] = binary_version.0;
        report_data[1..33].copy_from_slice(&public_keys_hash);

        report_data
    };

    let tdx_quote: String = client
        .get_quote(report_data.into())
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
