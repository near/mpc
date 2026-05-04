use anyhow::Context as _;
use backon::{BackoffBuilder, ExponentialBuilder};
use core::{future::Future, time::Duration};
use dcap_qvl::http::{HttpClient, HttpResponse};
use derive_more::{Constructor, From};
use dstack_sdk::dstack_client::DstackClient;
use launcher_interface::types::{PccsEndpointConfig, PccsTlsTrust};
use mpc_attestation::{
    attestation::{Attestation, DstackAttestation, MockAttestation},
    collateral::Collateral,
    report_data::ReportData,
};
use near_mpc_bounded_collections::NonEmptyVec;
use std::collections::BTreeMap;
use std::path::PathBuf;
use thiserror::Error;
use tracing::{error, info, warn};
use url::Url;

/// Errors that can occur during TEE attestation generation.
#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("dstack client info failed: {0:#}")]
    DstackClientInfo(#[source] anyhow::Error),

    #[error("TCB info conversion failed: {0:#}")]
    TcbInfoConversion(#[source] anyhow::Error),

    #[error("TDX quote generation failed: {0:#}")]
    QuoteGeneration(#[source] anyhow::Error),

    #[error("TDX quote decoding failed: {0:#}")]
    QuoteDecode(#[source] anyhow::Error),

    #[error("collateral fetch failed: {0}")]
    CollateralFetch(#[source] AllPccsEndpointsFailed),

    #[error("dstack_endpoint path is not valid UTF-8")]
    InvalidEndpoint,
}

/// One PCCS endpoint's failure. Carries the URL it was tried against and
/// the underlying cause. The cause stays as `anyhow::Error` because the
/// upstream `dcap_qvl::CollateralClient` itself returns `anyhow::Result`.
#[derive(Debug, Error)]
pub enum PccsEndpointError {
    #[error("invalid PCCS client construction for {url}: {source:#}")]
    ClientConstruction {
        url: Url,
        #[source]
        source: anyhow::Error,
    },

    #[error("timed out fetching collateral from {url} after {timeout:?}")]
    Timeout { url: Url, timeout: Duration },

    #[error("collateral fetch failed for {url}: {source:#}")]
    Fetch {
        url: Url,
        #[source]
        source: anyhow::Error,
    },
}

/// Returned when every configured PCCS endpoint failed. Owns the full list
/// of per-endpoint failures in the order they were tried. The collection is
/// non-empty by construction: this error only ever fires after a loop over a
/// `NonEmptyVec<Url>`, so the type-level invariant matches the value-level
/// one and rules out nonsense renderings like "all 0 PCCS endpoints failed".
#[derive(Debug, Error)]
#[error(
    "all {} PCCS endpoints failed:\n{}",
    failures.len(),
    format_pccs_failures(failures.as_slice())
)]
pub struct AllPccsEndpointsFailed {
    pub failures: NonEmptyVec<PccsEndpointError>,
}

fn format_pccs_failures(failures: &[PccsEndpointError]) -> String {
    failures
        .iter()
        .map(|e| format!("  - {e}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The maximum duration to wait for retrying requests.
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);

/// Per-request timeout for fetching collateral from PCCS. Applied at two
/// layers — `reqwest::Client::builder().timeout(...)` (per-HTTP-request)
/// and `tokio::time::timeout(...)` around `client.fetch(quote)` (whole
/// fetch operation). claude bot review on PR #3026 flagged the double
/// timeout; using the same constant at both layers is intentional —
/// each fetch is a single HTTP request, so there's no current benefit
/// to splitting them, and the redundancy is harmless.
const PCCS_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Default path for dstack Unix socket endpoint.
pub const DEFAULT_DSTACK_ENDPOINT: &str = "/var/run/dstack.sock";

#[derive(Constructor, Clone)]
pub struct LocalTeeAuthorityConfig {
    generate_valid_attestations: bool,
}

impl Default for LocalTeeAuthorityConfig {
    fn default() -> Self {
        Self {
            generate_valid_attestations: true,
        }
    }
}

#[derive(Constructor, Clone)]
pub struct DstackTeeAuthorityConfig {
    /// Endpoint to contact dstack service. Defaults to [`DEFAULT_DSTACK_ENDPOINT`]
    dstack_endpoint: PathBuf,
    /// PCCS servers used to fetch TDX attestation collateral. Each entry
    /// is a URL with an optional per-URL TLS trust override. Tried in
    /// order; the first one to succeed wins, the rest act as fallbacks.
    /// At least one entry is required (enforced by the type).
    pccs_endpoints: NonEmptyVec<PccsEndpointConfig>,
}

impl Default for DstackTeeAuthorityConfig {
    fn default() -> Self {
        let default_url: Url = launcher_interface::DEFAULT_PCCS_URL
            .parse()
            .expect("default PCCS URL is valid");
        Self {
            dstack_endpoint: PathBuf::from(DEFAULT_DSTACK_ENDPOINT),
            pccs_endpoints: NonEmptyVec::try_from(vec![PccsEndpointConfig {
                url: default_url,
                tls: None,
            }])
            .expect("single-element vec is non-empty"),
        }
    }
}

/// Validate the PCCS endpoint list at startup. Runs once during config
/// conversion to fail fast on a typo'd `ca_cert_pem` (so the operator
/// gets a clear message at startup rather than at first attestation).
///
/// Also emits one WARN per `Insecure` endpoint at startup so operators
/// see the security signal up front instead of buried in fetch logs.
pub fn validate_pccs_endpoints(
    pccs_endpoints: &NonEmptyVec<PccsEndpointConfig>,
) -> anyhow::Result<()> {
    for endpoint in pccs_endpoints.iter() {
        match &endpoint.tls {
            None => {}
            Some(PccsTlsTrust::CaCertPem { .. }) => {
                build_pccs_http_client(endpoint)
                    .context("failed to build TLS client at startup")?;
            }
            Some(PccsTlsTrust::Insecure) => {
                tracing::warn!(
                    url = %endpoint.url,
                    "tls.override = \"insecure\": PCCS TLS certificate verification is DISABLED \
                     for this endpoint. Recommended only for local/loopback PCCS endpoints."
                );
            }
        }
    }
    Ok(())
}

/// `dcap_qvl::http::HttpClient` adapter over a `reqwest::Client`.
/// `dcap-qvl` keeps `reqwest::Client` out of its public API
/// ([Phala-Network/dcap-qvl#156](https://github.com/Phala-Network/dcap-qvl/pull/156)),
/// so callers using a custom client must implement this trait themselves.
struct PccsHttpClient(reqwest::Client);

impl HttpClient for PccsHttpClient {
    async fn get(&self, url: &str) -> anyhow::Result<HttpResponse> {
        let resp = self.0.get(url).send().await?;
        Ok(HttpResponse {
            status: resp.status().as_u16(),
            headers: resp
                .headers()
                .iter()
                .map(|(n, v)| Ok((n.as_str().to_string(), v.to_str()?.to_string())))
                .collect::<anyhow::Result<BTreeMap<_, _>>>()?,
            body: resp.bytes().await?.to_vec(),
        })
    }
}

/// Build the per-endpoint HTTP client that's handed to
/// `dcap_qvl::collateral::CollateralClient::new`. Used for every
/// endpoint regardless of `tls` setting — the builder applies any
/// per-endpoint trust override on top of the default reqwest+rustls
/// trust roots.
///
/// Returns [`PccsEndpointError::ClientConstruction`] (carrying the
/// endpoint URL) on any failure so callers can propagate with `?` and
/// don't have to attach the URL themselves.
fn build_pccs_http_client(
    endpoint: &PccsEndpointConfig,
) -> Result<PccsHttpClient, PccsEndpointError> {
    let to_construction_err = |source: anyhow::Error| PccsEndpointError::ClientConstruction {
        url: endpoint.url.clone(),
        source,
    };

    let builder = reqwest::Client::builder().timeout(PCCS_REQUEST_TIMEOUT);
    let builder = match endpoint.tls.as_ref() {
        None => builder,
        Some(PccsTlsTrust::CaCertPem { ca_cert_pem }) => {
            let cert = reqwest::Certificate::from_pem(ca_cert_pem.as_bytes())
                .context("failed to parse `tls.ca_cert_pem` as a PEM-encoded certificate")
                .map_err(to_construction_err)?;
            builder.add_root_certificate(cert)
        }
        Some(PccsTlsTrust::Insecure) => builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true),
    };
    builder
        .build()
        .context("failed to build PCCS HTTP client")
        .map(PccsHttpClient)
        .map_err(to_construction_err)
}

/// TeeAuthority is an abstraction over different TEE attestation generator implementations. It
/// generates [`Attestation`] instances - either mocked or real ones.
#[derive(From, Clone)]
pub enum TeeAuthority {
    Dstack(DstackTeeAuthorityConfig),
    Local(LocalTeeAuthorityConfig),
}

impl TeeAuthority {
    pub async fn generate_attestation(
        &self,
        report_data: ReportData,
    ) -> Result<Attestation, AttestationError> {
        match self {
            TeeAuthority::Local(config) => {
                let create_valid_attestation = config.generate_valid_attestations;

                let attestation = if create_valid_attestation {
                    MockAttestation::Valid
                } else {
                    MockAttestation::Invalid
                };

                Ok(Attestation::Mock(attestation))
            }
            TeeAuthority::Dstack(config) => {
                self.generate_dstack_attestation(config, report_data).await
            }
        }
    }

    async fn generate_dstack_attestation(
        &self,
        config: &DstackTeeAuthorityConfig,
        report_data: ReportData,
    ) -> Result<Attestation, AttestationError> {
        let endpoint = config
            .dstack_endpoint
            .to_str()
            .ok_or(AttestationError::InvalidEndpoint)?;
        let client = DstackClient::new(Some(endpoint));

        let client_info_response = get_with_backoff(|| client.info(), "dstack client info", None)
            .await
            .map_err(AttestationError::DstackClientInfo)?;
        let tcb_info = client_info_response
            .tcb_info
            .try_into()
            .map_err(|e| AttestationError::TcbInfoConversion(anyhow::anyhow!("{e}")))?;

        let quote = get_with_backoff(
            || client.get_quote(report_data.to_bytes().into()),
            "dstack client tdx quote",
            None,
        )
        .await
        .map_err(AttestationError::QuoteGeneration)?
        .quote;

        let quote_bytes: Vec<u8> =
            hex::decode(&quote).map_err(|e| AttestationError::QuoteDecode(e.into()))?;

        let collateral = Self::fetch_collateral(&config.pccs_endpoints, &quote_bytes)
            .await
            .map_err(AttestationError::CollateralFetch)?;

        Ok(Attestation::Dstack(DstackAttestation::new(
            quote_bytes.into(),
            collateral,
            tcb_info,
        )))
    }

    /// Fetches attestation collateral from a list of PCCS endpoints, tried
    /// in order. The first endpoint to return success wins; later
    /// endpoints act as fallbacks and are only contacted when earlier
    /// ones fail (after their own per-URL backoff). When every endpoint
    /// fails, returns an [`AllPccsEndpointsFailed`] aggregating each
    /// per-endpoint failure.
    async fn fetch_collateral(
        pccs_endpoints: &NonEmptyVec<PccsEndpointConfig>,
        quote: &[u8],
    ) -> Result<Collateral, AllPccsEndpointsFailed> {
        try_each_pccs_endpoint(pccs_endpoints, async |endpoint: PccsEndpointConfig| {
            Self::fetch_collateral_from(&endpoint, quote).await
        })
        .await
    }

    /// Fetches attestation collateral from a single PCCS endpoint, with
    /// the usual per-request timeout and a single retry via exponential
    /// backoff. Honors the endpoint's per-URL TLS trust override: with
    /// `tls = None` the client uses default reqwest+rustls trust roots
    /// (bundled Mozilla webpki-roots); with a set `tls` the client
    /// reflects the override (`add_root_certificate` for `CaCertPem`,
    /// `danger_accept_invalid_certs` for `Insecure`).
    async fn fetch_collateral_from(
        endpoint: &PccsEndpointConfig,
        quote: &[u8],
    ) -> Result<Collateral, PccsEndpointError> {
        let http = build_pccs_http_client(endpoint)?;
        let client = dcap_qvl::collateral::CollateralClient::<
            dcap_qvl::configs::DefaultConfig,
            PccsHttpClient,
        >::new(http, endpoint.url.as_str());
        let fetch = async || {
            tokio::time::timeout(PCCS_REQUEST_TIMEOUT, client.fetch(quote))
                .await
                .map_err(|_| PccsEndpointError::Timeout {
                    url: endpoint.url.clone(),
                    timeout: PCCS_REQUEST_TIMEOUT,
                })?
                .map(Collateral::from)
                .map_err(|e| PccsEndpointError::Fetch {
                    url: endpoint.url.clone(),
                    source: anyhow::anyhow!(e),
                })
        };

        get_with_backoff(fetch, "fetch collateral from PCCS", Some(1)).await
    }
}

/// Try each PCCS endpoint in order, returning the first success. If every
/// endpoint fails, returns [`AllPccsEndpointsFailed`] listing each
/// per-endpoint failure in attempt order. Failed attempts log at `warn`;
/// a fallback success (attempt > 1) logs at `info` so an always-failing
/// primary masked by a healthy fallback isn't invisible.
async fn try_each_pccs_endpoint<Fetcher, Fut>(
    pccs_endpoints: &NonEmptyVec<PccsEndpointConfig>,
    fetcher: Fetcher,
) -> Result<Collateral, AllPccsEndpointsFailed>
where
    Fetcher: Fn(PccsEndpointConfig) -> Fut,
    Fut: Future<Output = Result<Collateral, PccsEndpointError>>,
{
    let mut failures: Vec<PccsEndpointError> = Vec::new();
    let total_endpoints = pccs_endpoints.len();
    for (index, endpoint) in pccs_endpoints.iter().enumerate() {
        let attempt = index + 1;
        let is_last_endpoint = attempt == total_endpoints;
        let url = endpoint.url.clone();
        match fetcher(endpoint.clone()).await {
            Ok(collateral) => {
                if attempt > 1 {
                    info!(
                        %url,
                        attempt,
                        total_endpoints,
                        "fetched collateral via PCCS fallback"
                    );
                }
                return Ok(collateral);
            }
            Err(err) => {
                warn!(
                    ?err,
                    %url,
                    attempt,
                    total_endpoints,
                    "failed to fetch collateral from PCCS; {}",
                    if is_last_endpoint { "no more endpoints remain" } else { "trying next endpoint" }
                );
                failures.push(err);
            }
        }
    }
    // Sound by construction: the loop iterates `pccs_endpoints`, which is
    // itself a `NonEmptyVec<PccsEndpointConfig>`, so any path that exits
    // the loop without an early `Ok(...)` return must have pushed at
    // least one failure.
    let failures = NonEmptyVec::try_from(failures)
        .expect("loop over NonEmptyVec<PccsEndpointConfig> guarantees at least one failure");
    Err(AllPccsEndpointsFailed { failures })
}

async fn get_with_backoff<Operation, OperationFuture, Value, Error>(
    operation: Operation,
    description: &str,
    max_retries: Option<usize>,
) -> Result<Value, Error>
where
    Error: core::fmt::Debug,
    Operation: Fn() -> OperationFuture,
    OperationFuture: Future<Output = Result<Value, Error>>,
{
    let mut backoff = {
        let builder = ExponentialBuilder::default()
            .with_max_delay(MAX_BACKOFF_DURATION)
            .with_jitter();

        if let Some(max_retries) = max_retries {
            builder.with_max_times(max_retries)
        } else {
            builder.without_max_times()
        }
        .build()
    };

    // Loop until we have a response or exceed max retries
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match operation().await {
            Ok(response) => return Ok(response),
            Err(err) => match backoff.next() {
                Some(duration) => {
                    error!(
                        ?err,
                        attempt, "{description} failed. retrying in: {:?}", duration
                    );
                    tokio::time::sleep(duration).await;
                }
                None => {
                    let retry_msg = match max_retries {
                        Some(retries) => format!("after {retries} retries"),
                        None => "and backoff returned None with unlimited retries".to_string(),
                    };
                    error!(?err, attempt, "{description} failed {retry_msg}");
                    return Err(err);
                }
            },
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use mpc_attestation::report_data::ReportDataV1;
    use rstest::rstest;
    use std::{
        cell::RefCell,
        rc::Rc,
        sync::{
            Arc,
            atomic::{AtomicI32, Ordering},
        },
    };

    #[cfg(feature = "external-services-tests")]
    use test_utils::attestation::quote;

    use test_utils::attestation::{account_key, p2p_tls_key};

    extern crate std;

    #[rstest]
    #[tokio::test]
    async fn test_generate_and_verify_attestation_local(
        #[values(true, false)] quote_verification_result: bool,
    ) {
        let tls_key = p2p_tls_key();
        let account_key = account_key();
        let report_data: ReportData = ReportDataV1::new(tls_key, account_key).into();

        let authority =
            TeeAuthority::Local(LocalTeeAuthorityConfig::new(quote_verification_result));
        let attestation = authority
            .generate_attestation(report_data.clone())
            .await
            .unwrap();
        let timestamp_s = 0u64;
        assert_eq!(
            attestation
                .verify(report_data.into(), timestamp_s, &[], &[], &[])
                .is_ok(),
            quote_verification_result
        );
    }

    #[tokio::test]
    async fn test_get_with_backoff_success_on_first_try() {
        const MAX_RETRIES: usize = 3;
        let call_count = Rc::new(RefCell::new(0));
        let call_count_clone = call_count.clone();

        let operation = move || {
            *call_count_clone.borrow_mut() += 1;
            async move { Ok::<i32, &str>(42) }
        };

        let result = get_with_backoff(operation, "test operation", Some(MAX_RETRIES)).await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(*call_count.borrow(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_with_backoff_success_after_retries() {
        const FAILURE_COUNT: i32 = 3;
        const MAX_RETRIES: usize = 5;
        let call_count = Arc::new(AtomicI32::new(0));
        let call_count_clone = call_count.clone();

        let operation = move || {
            let current_count = call_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                if current_count < FAILURE_COUNT {
                    Err("temporary failure")
                } else {
                    Ok::<i32, &str>(42)
                }
            }
        };

        let start_time = tokio::time::Instant::now();

        // Run get_with_backoff in a spawned task so we can control time advancement
        let backoff_task = tokio::spawn(async move {
            get_with_backoff(operation, "test operation", Some(MAX_RETRIES)).await
        });

        // Let the first call execute and fail
        tokio::time::advance(Duration::from_millis(1)).await;

        // The backon ExponentialBuilder::default() uses:
        // - Base delay: 1 second
        // - Multiplier: 2
        // - Max attempts: 3
        // - Jitter: up to 100% of calculated delay
        // So expected delays are: ~1s, ~2s (each with potential jitter up to 2x)

        // Advance time for both retries: 2s + 4s = 6s total (with jitter buffer)
        tokio::time::advance(Duration::from_secs(6)).await;

        let result = backoff_task.await.unwrap();
        let elapsed = start_time.elapsed();

        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count.load(Ordering::SeqCst), FAILURE_COUNT);

        // Verify time was properly simulated (1ms initial + 2s + 4s = ~6s minimum)
        assert!(elapsed >= Duration::from_secs(6));
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_with_backoff_failure_exhausts_retries() {
        const MAX_RETRIES: usize = 2;
        let call_count = Arc::new(AtomicI32::new(0));
        let call_count_clone = call_count.clone();

        let operation = move || {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            async move { Err::<i32, &str>("persistent failure") }
        };

        // Run get_with_backoff in a spawned task so we can control time advancement
        let backoff_task = tokio::spawn(async move {
            get_with_backoff(operation, "test operation", Some(MAX_RETRIES)).await
        });

        // The backon ExponentialBuilder::default() uses:
        // - Base delay: 1 second
        // - Multiplier: 2
        // - Max retries: 2 (as specified)
        // - Jitter: up to 100% of calculated delay
        // So expected delays are: ~1s, ~2s (each with potential jitter up to 2x)

        // Advance time for all retry delays: 2s + 4s = 6s total (with jitter buffer)
        tokio::time::advance(Duration::from_secs(6)).await;

        let result = backoff_task.await.unwrap();

        assert_eq!(result.unwrap_err(), "persistent failure");
        assert_eq!(call_count.load(Ordering::SeqCst), (MAX_RETRIES + 1) as i32); // Initial attempt + retries
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_with_backoff_unlimited_retries_eventually_succeeds() {
        const FAILURE_COUNT: i32 = 5;
        let call_count = Arc::new(AtomicI32::new(0));
        let call_count_clone = call_count.clone();

        let operation = move || {
            let current_count = call_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
            async move {
                if current_count < FAILURE_COUNT {
                    Err("still failing")
                } else {
                    Ok::<i32, &str>(42)
                }
            }
        };

        let start_time = tokio::time::Instant::now();

        // Run get_with_backoff in a spawned task so we can control time advancement
        let backoff_task =
            tokio::spawn(async move { get_with_backoff(operation, "test operation", None).await });

        // Let the first call execute and fail
        tokio::time::advance(Duration::from_millis(1)).await;

        // For unlimited retries, we need to advance through 4 retry delays
        // ExponentialBuilder::default(): 1s, 2s, 4s, 8s (each with potential jitter up to 2x)
        let retry_delays = [2, 4, 8, 16]; // With jitter buffer: 2s, 4s, 8s, 16s

        for delay_secs in retry_delays {
            tokio::time::advance(Duration::from_secs(delay_secs)).await;
        }

        let result = backoff_task.await.unwrap();
        let elapsed = start_time.elapsed();

        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count.load(Ordering::SeqCst), FAILURE_COUNT);

        // Verify time was properly simulated (1ms initial + sum of delays = ~30s minimum)
        let total_expected_secs: u64 = retry_delays.iter().sum::<u64>();
        assert!(elapsed >= Duration::from_secs(total_expected_secs));
    }

    /// Build a minimal `Collateral` for tests. None of the fields are
    /// inspected — it just needs to be a valid value that round-trips through
    /// the fetch path.
    fn dummy_collateral(tag: &str) -> Collateral {
        dcap_qvl::QuoteCollateralV3 {
            pck_crl_issuer_chain: tag.into(),
            root_ca_crl: Vec::new(),
            pck_crl: Vec::new(),
            tcb_info_issuer_chain: String::new(),
            tcb_info: String::new(),
            tcb_info_signature: Vec::new(),
            qe_identity_issuer_chain: String::new(),
            qe_identity: String::new(),
            qe_identity_signature: Vec::new(),
            pck_certificate_chain: None,
        }
        .into()
    }

    fn endpoints(list: &[&str]) -> NonEmptyVec<PccsEndpointConfig> {
        let vec: Vec<PccsEndpointConfig> = list
            .iter()
            .map(|s| PccsEndpointConfig {
                url: s.parse().unwrap(),
                tls: None,
            })
            .collect();
        NonEmptyVec::try_from(vec).expect("test inputs must be non-empty")
    }

    /// A single-endpoint list should call the fetcher exactly once and
    /// propagate the success.
    #[tokio::test]
    async fn try_each_pccs_endpoint__single_url_success() {
        let call_count = Arc::new(AtomicI32::new(0));
        let expected = dummy_collateral("single");

        let result = try_each_pccs_endpoint(
            &endpoints(&["https://a.example/"]),
            |endpoint: PccsEndpointConfig| {
                let call_count = call_count.clone();
                let expected = expected.clone();
                async move {
                    call_count.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(endpoint.url.as_str(), "https://a.example/");
                    Ok(expected)
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert_eq!(result.pck_crl_issuer_chain, "single");
    }

    /// When the first endpoint fails and the second succeeds, the fetcher
    /// is called exactly twice — once per endpoint, in the configured
    /// order — and the second endpoint's collateral is returned.
    #[tokio::test]
    async fn try_each_pccs_endpoint__fallback_to_second() {
        let seen_urls = Rc::new(RefCell::new(Vec::<Url>::new()));

        let result = try_each_pccs_endpoint(
            &endpoints(&["https://primary.example/", "https://fallback.example/"]),
            |endpoint: PccsEndpointConfig| {
                let seen_urls = seen_urls.clone();
                async move {
                    let is_primary = endpoint.url.as_str().contains("primary");
                    seen_urls.borrow_mut().push(endpoint.url.clone());
                    if is_primary {
                        Err(PccsEndpointError::Fetch {
                            url: endpoint.url,
                            source: anyhow::anyhow!("simulated primary outage"),
                        })
                    } else {
                        Ok(dummy_collateral("fallback"))
                    }
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(
            seen_urls.borrow().as_slice(),
            &[
                "https://primary.example/".parse::<Url>().unwrap(),
                "https://fallback.example/".parse::<Url>().unwrap(),
            ],
            "endpoints must be tried in the exact order the user listed them"
        );
        assert_eq!(result.pck_crl_issuer_chain, "fallback");
    }

    /// When every endpoint fails, the loop captures every per-endpoint
    /// failure in the order the endpoints were tried — so structured
    /// consumers (alerting, support tickets, tests) see the full picture,
    /// not just the last attempt.
    #[tokio::test]
    async fn try_each_pccs_endpoint__should_collect_every_endpoint_failure_in_order() {
        // PccsEndpointError can't derive PartialEq (anyhow::Error: !PartialEq),
        // so we project to a comparable shape that drops the source field but
        // keeps the variant + URL — the only properties this test asserts.
        #[derive(Debug, PartialEq)]
        enum FailureShape {
            Fetch(Url),
            Timeout(Url),
            ClientConstruction(Url),
        }

        impl From<&PccsEndpointError> for FailureShape {
            fn from(err: &PccsEndpointError) -> Self {
                match err {
                    PccsEndpointError::Fetch { url, .. } => Self::Fetch(url.clone()),
                    PccsEndpointError::Timeout { url, .. } => Self::Timeout(url.clone()),
                    PccsEndpointError::ClientConstruction { url, .. } => {
                        Self::ClientConstruction(url.clone())
                    }
                }
            }
        }

        // Given
        let pccs_endpoints = endpoints(&[
            "https://first.example/",
            "https://second.example/",
            "https://third.example/",
        ]);

        // When
        let err =
            try_each_pccs_endpoint(&pccs_endpoints, |endpoint: PccsEndpointConfig| async move {
                Err::<Collateral, _>(PccsEndpointError::Fetch {
                    url: endpoint.url.clone(),
                    source: anyhow::anyhow!("{} is down", endpoint.url),
                })
            })
            .await
            .unwrap_err();

        // Then
        let actual: Vec<FailureShape> = err.failures.iter().map(FailureShape::from).collect();
        let expected: Vec<FailureShape> = pccs_endpoints
            .iter()
            .map(|e| FailureShape::Fetch(e.url.clone()))
            .collect();
        assert_eq!(actual, expected);
    }

    /// `Display` renders one line per failure for log/ticket pastes.
    #[tokio::test]
    async fn all_pccs_endpoints_failed__should_render_each_failure_on_its_own_line() {
        // Given
        const FIRST_URL: &str = "https://first.example/";
        const SECOND_URL: &str = "https://second.example/";
        const TIMEOUT: Duration = Duration::from_secs(10);
        const FETCH_ERROR: &str = "503 Service Unavailable";

        let err = AllPccsEndpointsFailed {
            failures: NonEmptyVec::try_from(vec![
                PccsEndpointError::Timeout {
                    url: FIRST_URL.parse().unwrap(),
                    timeout: TIMEOUT,
                },
                PccsEndpointError::Fetch {
                    url: SECOND_URL.parse().unwrap(),
                    source: anyhow::anyhow!(FETCH_ERROR),
                },
            ])
            .expect("two-element vec is non-empty"),
        };

        // When
        let rendered = err.to_string();

        // Then
        assert_eq!(
            rendered,
            format!(
                "all 2 PCCS endpoints failed:\n\
                 \x20 - timed out fetching collateral from {FIRST_URL} after {TIMEOUT:?}\n\
                 \x20 - collateral fetch failed for {SECOND_URL}: {FETCH_ERROR}"
            )
        );
    }

    #[tokio::test]
    #[cfg(feature = "external-services-tests")]
    async fn test_fetch_collateral_from_pccs() {
        let quote_bytes: Vec<u8> = quote().into();

        let config = DstackTeeAuthorityConfig::default();

        let result = tokio::time::timeout(
            Duration::from_secs(30),
            TeeAuthority::fetch_collateral(&config.pccs_endpoints, &quote_bytes),
        )
        .await;

        match result {
            Ok(Ok(collateral)) => {
                let dcap_qvl::QuoteCollateralV3 {
                    tcb_info_issuer_chain,
                    tcb_info,
                    tcb_info_signature,
                    qe_identity_issuer_chain,
                    qe_identity,
                    qe_identity_signature,
                    pck_crl_issuer_chain,
                    root_ca_crl,
                    pck_crl,
                    pck_certificate_chain,
                }: dcap_qvl::QuoteCollateralV3 = collateral.into();

                assert!(!tcb_info_issuer_chain.is_empty());
                assert!(!tcb_info.is_empty());
                assert!(!tcb_info_signature.is_empty());
                assert!(!qe_identity_issuer_chain.is_empty());
                assert!(!qe_identity.is_empty());
                assert!(!qe_identity_signature.is_empty());
                assert!(!pck_crl_issuer_chain.is_empty());
                assert!(!root_ca_crl.is_empty());
                assert!(!pck_crl.is_empty());
                assert!(pck_certificate_chain.is_some());
            }
            Ok(Err(e)) => panic!("Test failed: {e:?}"),
            Err(e) => panic!("Test timed out: {e:?}"),
        }
    }
}
