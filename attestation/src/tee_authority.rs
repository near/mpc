use crate::{
    attestation::{Attestation, DstackAttestation},
    collateral::Collateral,
    quote::Quote,
    report_data::ReportData,
    tcbinfo::TcbInfo,
};
use alloc::{boxed::Box, string::String};
use anyhow::{Context, bail};
use backon::{BackoffBuilder, ExponentialBuilder};
use core::{future::Future, time::Duration};
use dstack_sdk::dstack_client::DstackClient;
use http::status::StatusCode;
use near_sdk::serde_json;
use reqwest::{Url, multipart::Form};
use serde::Deserialize;
use tracing::error;

/// The maximum duration to wait for retrying request to Phala's endpoint.
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);

/// Default URL for submission of TDX quote. Returns collateral to be used for verification.
const DEFAULT_PHALA_TDX_QUOTE_UPLOAD_URL: &str = "https://proof.t16z.com/api/upload";

pub struct LocalTeeAuthorityConfig;

pub struct DstackTeeAuthorityConfig {
    /// Endpoint to contact dstack service. [`None`]` defaults to `/var/run/dstack.sock`
    pub dstack_endpoint: Option<String>,
    /// URL for submission of TDX quote. Returns collateral to be used for verification.
    pub quote_upload_url: Url,
}

impl Default for DstackTeeAuthorityConfig {
    fn default() -> Self {
        Self {
            dstack_endpoint: None,
            quote_upload_url: DEFAULT_PHALA_TDX_QUOTE_UPLOAD_URL
                .parse()
                .expect("Default URL should be valid"),
        }
    }
}

pub enum TeeAuthority {
    Dstack(DstackTeeAuthorityConfig),
    Local(LocalTeeAuthorityConfig),
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
            TeeAuthority::Dstack(config) => {
                self.generate_dstack_attestation(config, report_data).await
            }
        }
    }

    /// Generates attestation using Dstack TEE authority.
    async fn generate_dstack_attestation(
        &self,
        config: &DstackTeeAuthorityConfig,
        report_data: ReportData,
    ) -> anyhow::Result<Attestation> {
        let client = DstackClient::new(config.dstack_endpoint.as_deref());
        let tcb_info = self.get_tcb_info(&client).await;
        let tdx_quote = self.get_tdx_quote(&client, report_data).await;
        let collateral = self
            .upload_quote_for_collateral(&config.quote_upload_url, &tdx_quote)
            .await?;
        let quote: Quote = tdx_quote.parse()?;

        Ok(Attestation::Dstack(Box::new(DstackAttestation::new(
            quote, collateral, tcb_info,
        ))))
    }

    /// Retrieves TCB info from Dstack client.
    async fn get_tcb_info(&self, client: &DstackClient) -> TcbInfo {
        let client_info_response = get_with_backoff(|| client.info(), "dstack client info").await;
        TcbInfo::from(client_info_response.tcb_info)
    }

    /// Generates TDX quote from report data using Dstack client.
    async fn get_tdx_quote(&self, client: &DstackClient, report_data: ReportData) -> String {
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
        &self,
        quote_upload_url: &Url,
        tdx_quote: &str,
    ) -> anyhow::Result<Collateral> {
        let reqwest_client = reqwest::Client::new();
        let tdx_quote = String::from(tdx_quote);

        let upload_tdx_quote = async || {
            let form = Form::new().text("hex", tdx_quote.clone());

            let response = reqwest_client
                .post(quote_upload_url.clone())
                .multipart(form)
                .send()
                .await?;

            let status = response.status();
            if status != StatusCode::OK {
                bail!(
                    "Got unexpected HTTP status code: response from phala endpoint: {:?}, expected: {:?}",
                    status,
                    StatusCode::OK
                );
            }

            response
                .json::<UploadResponse>()
                .await
                .context("Failed to deserialize response from Phala.")
        };

        let upload_response = get_with_backoff(upload_tdx_quote, "upload tdx quote").await;

        Collateral::try_from_json(upload_response.quote_collateral)
            .map_err(|e| anyhow::anyhow!("Failed to parse collateral: {}", e))
    }
}

#[derive(Deserialize)]
struct UploadResponse {
    quote_collateral: serde_json::Value,
    #[serde(rename = "checksum")]
    _checksum: String,
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
