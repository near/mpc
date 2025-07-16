use crate::{
    attestation::Attestation, collateral::Collateral, quote::Quote, report_data::ReportData,
    tcbinfo::TcbInfo,
};
use alloc::string::String;
use anyhow::{Context, bail};
use backon::{BackoffBuilder, ExponentialBuilder};
use core::{future::Future, time::Duration};
use dstack_sdk::dstack_client::DstackClient;
use http::status::StatusCode;
use reqwest::multipart::Form;
use serde::Deserialize;
use tracing::error;

/// The maximum duration to wait for retrying request to Phala's endpoint.
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);

/// Expected HTTP [`StatusCode`] for a successful submission.
const PHALA_SUCCESS_STATUS_CODE: StatusCode = StatusCode::OK;

pub struct LocalTeeAuthorityConfig;

pub struct DstackTeeAuthorityConfig {
    /// Endpoint to contact dstack service. [`None`]` defaults to `/var/run/dstack.sock`
    pub endpoint: Option<String>,
    /// URL for submission of TDX quote. Returns collateral to be used for verification.
    pub quote_upload_url: String,
}

impl Default for DstackTeeAuthorityConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            quote_upload_url: String::from("https://proof.t16z.com/api/upload"),
        }
    }
}

pub enum TeeAuthority {
    Local(LocalTeeAuthorityConfig),
    Dstack(DstackTeeAuthorityConfig),
}

impl TeeAuthority {
    pub async fn generate_attestation(
        &self,
        report_data: ReportData,
    ) -> anyhow::Result<Attestation> {
        match self {
            TeeAuthority::Local(_config) => {
                // Generate attestation using local TEE authority
                todo!("Implement local TEE attestation generation")
            }
            TeeAuthority::Dstack(config) => generate_dstack_attestation(config, report_data).await,
        }
    }
}

#[derive(Deserialize)]
struct UploadResponse {
    quote_collateral: serde_json::Value,
    #[serde(rename = "checksum")]
    _checksum: String,
}

/// Generates attestation using Dstack TEE authority.
async fn generate_dstack_attestation(
    config: &DstackTeeAuthorityConfig,
    report_data: ReportData,
) -> anyhow::Result<Attestation> {
    let client = DstackClient::new(config.endpoint.as_deref());
    let tcb_info = get_tcb_info(&client).await;
    let tdx_quote = get_tdx_quote(&client, report_data).await;
    let collateral = upload_quote_for_collateral(&config.quote_upload_url, &tdx_quote).await?;
    let quote = parse_quote_from_hex(&tdx_quote)?;

    Ok(Attestation::new(quote, collateral, tcb_info))
}

/// Retrieves TCB info from Dstack client.
async fn get_tcb_info(client: &DstackClient) -> TcbInfo {
    let client_info_response = get_with_backoff(|| client.info(), "dstack client info").await;
    TcbInfo::from(client_info_response.tcb_info)
}

/// Generates TDX quote from report data using Dstack client.
async fn get_tdx_quote(client: &DstackClient, report_data: ReportData) -> String {
    let report_data_bytes = report_data.to_bytes();
    let tdx_quote_response = get_with_backoff(
        || client.get_quote(report_data_bytes.into()),
        "dstack client tdx quote",
    )
    .await;
    tdx_quote_response.quote
}

/// Uploads TDX quote to Phala endpoint and retrieves collateral.
async fn upload_quote_for_collateral(
    quote_upload_url: &str,
    tdx_quote: &str,
) -> anyhow::Result<Collateral> {
    let reqwest_client = reqwest::Client::new();
    let tdx_quote = String::from(tdx_quote);

    let upload_tdx_quote = async || {
        let form = Form::new().text("hex", tdx_quote.clone());

        let response = reqwest_client
            .post(quote_upload_url)
            .multipart(form)
            .send()
            .await?;

        let status = response.status();
        if status != PHALA_SUCCESS_STATUS_CODE {
            bail!(
                "Got unexpected HTTP status code: response from phala endpoint: {:?}, expected: {:?}",
                status,
                PHALA_SUCCESS_STATUS_CODE
            );
        }

        response
            .json::<UploadResponse>()
            .await
            .context("Failed to deserialize response from Phala.")
    };

    let upload_response = get_with_backoff(upload_tdx_quote, "upload tdx quote").await;
    let collateral_json = serde_json::to_string(&upload_response.quote_collateral)?;

    Ok(Collateral::from(collateral_json))
}

/// Parses a hex-encoded TDX quote into a Quote object.
fn parse_quote_from_hex(tdx_quote_hex: &str) -> anyhow::Result<Quote> {
    let quote_bytes = hex::decode(tdx_quote_hex)?;
    let dcap_quote = dcap_qvl::quote::Quote::parse(quote_bytes.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to parse quote: {:?}", e))?;
    Ok(Quote::from(dcap_quote))
}

async fn get_with_backoff<Operation, OperationFuture, Value, Error>(
    operation: Operation,
    description: &str,
) -> Value
where
    Error: core::fmt::Debug,
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
