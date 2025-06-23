#![allow(dead_code)]

use anyhow::{bail, Context};
use backon::{BackoffBuilder, ExponentialBuilder};
use dstack_sdk::dstack_client::{DstackClient, TcbInfo};
use hex::ToHex;
use http::status::StatusCode;
use mpc_contract::tee::tee_participant::TeeParticipantInfo;
use near_crypto::PublicKey;
use reqwest::multipart::Form;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_384};
use std::{future::Future, time::Duration};
use tokio::sync::mpsc;
use tracing::error;

use crate::indexer::types::{ChainSendTransactionRequest, ProposeJoinArgs};

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
/// report_data: [u8; 64] = [version(2 bytes (big endian)) || sha384(TLS pub key || account public key ) || zero padding]
const REPORT_DATA_SIZE: usize = 64;

const BINARY_VERSION_OFFSET: usize = 0;
const BINARY_VERSION_SIZE: usize = 2;

const PUBLIC_KEYS_OFFSET: usize = 3;
const PUBLIC_KEYS_SIZE: usize = 48;

pub const BINARY_VERSION: BinaryVersion = BinaryVersion(1);

// Compile-time assertions
const _: () = {
    assert!(
        BINARY_VERSION_SIZE + PUBLIC_KEYS_SIZE <= REPORT_DATA_SIZE,
        "Version and public key must not exceed report data size."
    );
    assert!(
        BINARY_VERSION_OFFSET + BINARY_VERSION_SIZE + 1 == PUBLIC_KEYS_OFFSET,
        "Public key offset must be after binary version."
    );
};

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

pub struct BinaryVersion(u16);

async fn get_with_backoff<Operation, OperationFuture, Value, Error>(
    operation: Operation,
    description: &str,
) -> Value
where
    Error: std::fmt::Debug,
    Operation: Fn() -> OperationFuture,
    OperationFuture: Future<Output = Result<Value, Error>>,
{
    let mut backoff = ExponentialBuilder::default()
        .with_max_delay(MAX_BACKOFF_DURATION)
        .without_max_times()
        .with_jitter()
        .build();

    // Loop until we have a response.
    loop {
        match operation().await {
            Err(err) => {
                let duration = backoff.next().unwrap_or(MAX_BACKOFF_DURATION);
                error!(?err, "{description} failed. retrying in: {:?}", duration);
                continue;
            }
            Ok(response) => break response,
        }
    }
}

/// Generates a [`TeeAttestation`] for this node, which can be used to send to the contract to prove that
/// the node is running in a `TEE` context.
///
/// Returns an [`anyhow::Error`] if a non-transient error occurs, that prevents the node
/// from generating the attestation.
pub async fn create_remote_attestation_info(
    tls_public_key: &PublicKey,
    account_public_key: &PublicKey,
) -> TeeAttestation {
    let client = DstackClient::new(ENDPOINT);

    let client_info_response = get_with_backoff(|| client.info(), "dstack client info").await;
    let tcb_info = client_info_response.tcb_info;

    let report_data: [u8; REPORT_DATA_SIZE] = {
        let mut report_data = [0u8; REPORT_DATA_SIZE];

        // Copy binary version
        let byte_representation = BINARY_VERSION.0.to_be_bytes();
        report_data[BINARY_VERSION_OFFSET..][..BINARY_VERSION_SIZE]
            .copy_from_slice(&byte_representation);

        // Copy hash
        let mut hasher = Sha3_384::new();
        hasher.update(tls_public_key.key_data());
        hasher.update(account_public_key.key_data());
        let public_keys_hash: [u8; PUBLIC_KEYS_SIZE] = hasher.finalize().into();
        report_data[PUBLIC_KEYS_OFFSET..][..PUBLIC_KEYS_SIZE].copy_from_slice(&public_keys_hash);

        report_data
    };

    let tdx_quote: String = get_with_backoff(
        || client.get_quote(report_data.into()),
        "dstack client tdx quote",
    )
    .await
    .quote
    .encode_hex();

    let quote_upload_response = {
        let reqwest_client = reqwest::Client::new();
        let tdx_quote = tdx_quote.clone();

        let upload_tdx_quote = async || {
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

        get_with_backoff(upload_tdx_quote, "upload tdx quote").await
    };

    let collateral = quote_upload_response.quote_collateral;
    TeeAttestation {
        tdx_quote,
        tcb_info,
        collateral,
    }
}

impl TryFrom<TeeAttestation> for TeeParticipantInfo {
    type Error = anyhow::Error;

    fn try_from(value: TeeAttestation) -> Result<Self, Self::Error> {
        let tee_quote = hex::decode(value.tdx_quote)
            .context("Failed to decode tee quote. Expected it to be in hex format.")?;
        let quote_collateral = value.collateral;
        let raw_tcb_info =
            serde_json::to_string(&value.tcb_info).context("Failed to serialize tcb info")?;

        Ok(Self {
            tee_quote,
            quote_collateral,
            raw_tcb_info,
        })
    }
}

pub async fn submit_remote_attestation(
    tx_sender: mpsc::Sender<ChainSendTransactionRequest>,
    report_data_contract: TeeParticipantInfo,
    account_public_key: PublicKey,
) -> Result<(), anyhow::Error> {
    //let report_data =
    //    create_remote_attestation_info(&BINARY_VERSION, &tls_public_key, &account_public_key).await;

    //let report_data_contract: TeeParticipantInfo = report_data.try_into()?;
    let propose_join_args = ProposeJoinArgs {
        proposed_tee_participant: report_data_contract,
        sign_pk: account_public_key,
    };

    tx_sender
        .send(ChainSendTransactionRequest::SubmitRemoteAttestation(
            propose_join_args,
        ))
        .await
        .context("Failed to send remote attestation transaction. Channel is closed.")
}
