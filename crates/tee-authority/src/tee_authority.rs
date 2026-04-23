use backon::{BackoffBuilder, ExponentialBuilder};
use core::{future::Future, time::Duration};
use derive_more::{Constructor, From};
use dstack_sdk::dstack_client::DstackClient;
use mpc_attestation::{
    attestation::{Attestation, DstackAttestation, MockAttestation},
    collateral::Collateral,
    report_data::ReportData,
};
use near_mpc_bounded_collections::NonEmptyVec;
use std::path::PathBuf;
use thiserror::Error;
use tracing::{error, warn};
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

    #[error("collateral fetch failed: {0:#}")]
    CollateralFetch(#[source] anyhow::Error),

    #[error("dstack_endpoint path is not valid UTF-8")]
    InvalidEndpoint,
}

/// The maximum duration to wait for retrying requests.
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);

/// Per-request timeout for fetching collateral from PCCS.
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
    /// Base URLs of PCCS servers used to fetch TDX attestation collateral.
    /// Tried in order; the first one to succeed wins, the rest act as
    /// fallbacks. At least one URL is required (enforced by the type).
    pccs_urls: NonEmptyVec<Url>,
}

impl Default for DstackTeeAuthorityConfig {
    fn default() -> Self {
        let default_url: Url = launcher_interface::DEFAULT_PCCS_URL
            .parse()
            .expect("default PCCS URL is valid");
        Self {
            dstack_endpoint: PathBuf::from(DEFAULT_DSTACK_ENDPOINT),
            pccs_urls: NonEmptyVec::try_from(vec![default_url])
                .expect("single-element vec is non-empty"),
        }
    }
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

        let collateral = Self::fetch_collateral(&config.pccs_urls, &quote_bytes)
            .await
            .map_err(AttestationError::CollateralFetch)?;

        Ok(Attestation::Dstack(DstackAttestation::new(
            quote_bytes.into(),
            collateral,
            tcb_info,
        )))
    }

    /// Fetches attestation collateral from a list of PCCS servers, tried in
    /// order. The first URL to return success wins; later URLs act as
    /// fallbacks and are only contacted when earlier ones fail (after their
    /// own per-URL backoff). Returns the last error if every URL fails.
    async fn fetch_collateral(
        pccs_urls: &NonEmptyVec<Url>,
        quote: &[u8],
    ) -> anyhow::Result<Collateral> {
        try_each_pccs_endpoint(pccs_urls, async |url: String| {
            Self::fetch_collateral_from(&url, quote).await
        })
        .await
    }

    /// Fetches attestation collateral from a single PCCS endpoint, with the
    /// usual per-request timeout and a single retry via exponential backoff.
    async fn fetch_collateral_from(pccs_url: &str, quote: &[u8]) -> anyhow::Result<Collateral> {
        let client = dcap_qvl::collateral::CollateralClient::with_default_http(pccs_url)
            .map_err(|e| anyhow::anyhow!(e))?;
        let fetch = async || {
            tokio::time::timeout(PCCS_REQUEST_TIMEOUT, client.fetch(quote))
                .await
                .map_err(|_| anyhow::anyhow!("timed out fetching collateral from PCCS"))?
                .map(Collateral::from)
                .map_err(|e| anyhow::anyhow!(e))
        };

        get_with_backoff(fetch, "fetch collateral from PCCS", Some(1)).await
    }
}

/// Try each PCCS endpoint in order, returning the first success. If every
/// endpoint fails, the last error is returned. `fetcher(url) -> Future` is
/// called once per URL in the order the caller listed them; intermediate
/// failures are logged at `warn` level and do not short-circuit.
///
/// Factored out of [`TeeAuthority::fetch_collateral`] so tests can drive the
/// same iteration / error-merge logic with an injected fake fetcher — the
/// production path is not mockable directly because
/// `dcap_qvl::collateral::CollateralClient` is a concrete type, not a trait.
async fn try_each_pccs_endpoint<Fetcher, Fut>(
    pccs_urls: &NonEmptyVec<Url>,
    mut fetcher: Fetcher,
) -> anyhow::Result<Collateral>
where
    Fetcher: FnMut(String) -> Fut,
    Fut: Future<Output = anyhow::Result<Collateral>>,
{
    let mut last_err: Option<anyhow::Error> = None;
    for url in pccs_urls.iter() {
        match fetcher(url.as_str().to_owned()).await {
            Ok(collateral) => return Ok(collateral),
            Err(err) => {
                warn!(
                    ?err,
                    %url,
                    "failed to fetch collateral from PCCS, trying next endpoint"
                );
                last_err = Some(err);
            }
        }
    }
    // NonEmptyVec guarantees at least one iteration above, which either
    // returns Ok(...) or populates last_err.
    Err(last_err.expect("NonEmptyVec guarantees at least one URL"))
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
#[expect(non_snake_case, reason = "test-name convention: <sut>__<case>")]
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

    fn urls(list: &[&str]) -> NonEmptyVec<Url> {
        let vec: Vec<Url> = list.iter().map(|s| s.parse().unwrap()).collect();
        NonEmptyVec::try_from(vec).expect("test inputs must be non-empty")
    }

    /// A single-URL list should call the fetcher exactly once and propagate
    /// the success.
    #[tokio::test]
    async fn try_each_pccs_endpoint__single_url_success() {
        let call_count = Arc::new(AtomicI32::new(0));
        let expected = dummy_collateral("single");

        let result = try_each_pccs_endpoint(&urls(&["https://a.example/"]), |url| {
            let call_count = call_count.clone();
            let expected = expected.clone();
            async move {
                call_count.fetch_add(1, Ordering::SeqCst);
                assert_eq!(url, "https://a.example/");
                Ok(expected)
            }
        })
        .await
        .unwrap();

        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert_eq!(result.pck_crl_issuer_chain, "single");
    }

    /// When the first URL fails and the second succeeds, the fetcher is
    /// called exactly twice — once per URL, in the configured order — and the
    /// second URL's collateral is returned.
    #[tokio::test]
    async fn try_each_pccs_endpoint__fallback_to_second() {
        let seen_urls = Rc::new(RefCell::new(Vec::<String>::new()));

        let result = try_each_pccs_endpoint(
            &urls(&["https://primary.example/", "https://fallback.example/"]),
            |url| {
                let seen_urls = seen_urls.clone();
                async move {
                    seen_urls.borrow_mut().push(url.clone());
                    if url.contains("primary") {
                        Err(anyhow::anyhow!("simulated primary outage"))
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
                "https://primary.example/".to_owned(),
                "https://fallback.example/".to_owned(),
            ],
            "endpoints must be tried in the exact order the user listed them"
        );
        assert_eq!(result.pck_crl_issuer_chain, "fallback");
    }

    /// If every URL fails, the error returned is the last one (ordering-wise)
    /// so operators can see the most recently attempted endpoint's message.
    #[tokio::test]
    async fn try_each_pccs_endpoint__all_fail_returns_last_error() {
        let err = try_each_pccs_endpoint(
            &urls(&[
                "https://first.example/",
                "https://second.example/",
                "https://third.example/",
            ]),
            |url| async move { Err::<Collateral, _>(anyhow::anyhow!("{url} is down")) },
        )
        .await
        .unwrap_err()
        .to_string();

        assert_eq!(err, "https://third.example/ is down");
    }

    #[tokio::test]
    #[cfg(feature = "external-services-tests")]
    async fn test_fetch_collateral_from_pccs() {
        let quote_bytes: Vec<u8> = quote().into();

        let config = DstackTeeAuthorityConfig::default();

        let result = tokio::time::timeout(
            Duration::from_secs(30),
            TeeAuthority::fetch_collateral(&config.pccs_urls, &quote_bytes),
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
