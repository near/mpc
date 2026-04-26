use backon::{BackoffBuilder, ExponentialBuilder};
use core::{future::Future, time::Duration};
use derive_more::{Constructor, From};
use dstack_sdk::dstack_client::DstackClient;
use mpc_attestation::{
    attestation::{Attestation, DstackAttestation, MockAttestation},
    collateral::Collateral,
    report_data::ReportData,
};
use std::path::PathBuf;
use thiserror::Error;
use tracing::error;
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
    /// Base URL of the PCCS server used to fetch TDX attestation collateral.
    pccs_url: Url,
    /// Optional PEM-encoded root certificate added to the TLS trust anchors
    /// when fetching collateral. Used to trust a self-signed local PCCS
    /// without changing the rest of the node's TLS posture.
    pccs_ca_cert_pem: Option<String>,
    /// Disable TLS certificate verification for the PCCS request. Loopback
    /// only — startup validation rejects this with non-loopback `pccs_url`
    /// hosts. See `mpc_node_config::StartConfig::pccs_tls_insecure` for the
    /// security rationale.
    pccs_tls_insecure: bool,
}

impl Default for DstackTeeAuthorityConfig {
    fn default() -> Self {
        Self {
            dstack_endpoint: PathBuf::from(DEFAULT_DSTACK_ENDPOINT),
            pccs_url: launcher_interface::DEFAULT_PCCS_URL
                .parse()
                .expect("default PCCS URL is valid"),
            pccs_ca_cert_pem: None,
            pccs_tls_insecure: false,
        }
    }
}

/// Hosts for which `pccs_tls_insecure = true` is honored. Other hosts are
/// rejected at startup, so a copy-pasted dev config cannot silently disable
/// TLS verification against a real network endpoint.
///
/// `[::1]` is the IPv6 loopback. We compare against `Url::host_str()` which
/// keeps the URL-syntax brackets for IPv6 hosts, so the entry includes them.
const LOOPBACK_PCCS_HOSTS: &[&str] = &["localhost", "127.0.0.1", "[::1]", "10.0.2.2"];

/// Validate the PCCS TLS-trust knobs at startup:
///
/// - `pccs_ca_cert_pem` and `pccs_tls_insecure` are mutually exclusive: the
///   first explicitly trusts a known cert, the second turns trust off
///   entirely. Asking for both is a config mistake.
/// - `pccs_tls_insecure` is only honored for loopback-ish PCCS URLs so a
///   copy-pasted dev config cannot silently disable TLS validation against a
///   real network endpoint.
pub fn validate_pccs_tls_config(
    pccs_url: &Url,
    pccs_ca_cert_pem: Option<&str>,
    pccs_tls_insecure: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !(pccs_tls_insecure && pccs_ca_cert_pem.is_some()),
        "pccs_tls_insecure=true and pccs_ca_cert_pem are mutually exclusive: \
         pin a specific cert or disable verification entirely, not both",
    );
    if !pccs_tls_insecure {
        return Ok(());
    }
    let host = pccs_url.host_str().unwrap_or("");
    anyhow::ensure!(
        LOOPBACK_PCCS_HOSTS.contains(&host),
        "pccs_tls_insecure=true is only allowed for loopback PCCS URLs (one of {:?}); got host {host:?}",
        LOOPBACK_PCCS_HOSTS,
    );
    Ok(())
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

        let collateral = Self::fetch_collateral(
            config.pccs_url.as_str(),
            config.pccs_ca_cert_pem.as_deref(),
            config.pccs_tls_insecure,
            &quote_bytes,
        )
        .await
        .map_err(AttestationError::CollateralFetch)?;

        Ok(Attestation::Dstack(DstackAttestation::new(
            quote_bytes.into(),
            collateral,
            tcb_info,
        )))
    }

    /// Fetches attestation collateral from a PCCS server for the given TDX quote.
    async fn fetch_collateral(
        pccs_url: &str,
        pccs_ca_cert_pem: Option<&str>,
        pccs_tls_insecure: bool,
        quote: &[u8],
    ) -> anyhow::Result<Collateral> {
        let http = build_pccs_http_client(pccs_ca_cert_pem, pccs_tls_insecure)?;
        // Use `DefaultConfig` to match the trust posture of `with_default_http`
        // (selected as `RingConfig` when the `ring` feature is on, which we do).
        let client =
            dcap_qvl::collateral::CollateralClient::<dcap_qvl::configs::DefaultConfig>::new(
                http, pccs_url,
            );
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

/// Build the `reqwest::Client` used to talk to the PCCS server, applying the
/// operator's TLS-trust knobs. With both knobs unset the result is the
/// standard `reqwest` client with system CAs only — same trust posture as
/// `with_default_http`.
///
/// The caller is expected to have run [`validate_pccs_tls_config`] first
/// (which rejects the both-knobs-set combo). This function nonetheless
/// matches all four input quadrants explicitly so the precedence rule is
/// local: a future caller that skips validation cannot accidentally land
/// in a silent precedence rule that disables TLS validation.
fn build_pccs_http_client(
    pccs_ca_cert_pem: Option<&str>,
    pccs_tls_insecure: bool,
) -> anyhow::Result<reqwest::Client> {
    use anyhow::Context;
    let builder = reqwest::Client::builder().timeout(PCCS_REQUEST_TIMEOUT);

    let builder = match (pccs_tls_insecure, pccs_ca_cert_pem) {
        (true, Some(_)) => anyhow::bail!(
            "pccs_tls_insecure and pccs_ca_cert_pem are mutually exclusive; \
             this combination should have been rejected by validate_pccs_tls_config"
        ),
        (true, None) => {
            tracing::warn!(
                "pccs_tls_insecure=true: PCCS TLS certificate verification is DISABLED. \
                 Only honored for loopback PCCS hosts; the host is the effective \
                 trust boundary."
            );
            builder.danger_accept_invalid_certs(true)
        }
        (false, Some(pem)) => {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .context("failed to parse pccs_ca_cert_pem as a PEM-encoded certificate")?;
            builder.add_root_certificate(cert)
        }
        (false, None) => builder,
    };

    builder.build().context("failed to build PCCS HTTP client")
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

    /// Generate a small valid X.509 v3 self-signed cert as PEM, for tests
    /// that need a real cert `reqwest::Certificate::from_pem` will accept.
    fn test_cert_pem() -> String {
        let cert =
            rcgen::generate_simple_self_signed(vec!["test.local".into()]).expect("rcgen generate");
        cert.cert.pem()
    }

    #[rstest]
    #[case::loopback_localhost("https://localhost:8081/")]
    #[case::loopback_127("https://127.0.0.1:8081/")]
    #[case::loopback_ipv6("https://[::1]:8081/")]
    #[case::loopback_slirp("https://10.0.2.2:8081/")]
    fn validate_pccs_tls_config__should_accept_insecure_for_loopback_hosts(#[case] url: &str) {
        // Given
        let url: Url = url.parse().expect("valid URL");

        // When
        let result = validate_pccs_tls_config(&url, None, true);

        // Then
        assert!(result.is_ok(), "expected ok, got {result:?}");
    }

    #[rstest]
    #[case::public_host("https://pccs.phala.network/")]
    #[case::intel_host("https://api.trustedservices.intel.com/")]
    #[case::other_loopback_alias("https://0.0.0.0:8081/")]
    fn validate_pccs_tls_config__should_reject_insecure_for_non_loopback_hosts(#[case] url: &str) {
        // Given
        let url: Url = url.parse().expect("valid URL");

        // When
        let result = validate_pccs_tls_config(&url, None, true);

        // Then
        assert!(result.is_err(), "expected err for {url}, got {result:?}");
    }

    #[rstest]
    #[case::public_host("https://pccs.phala.network/")]
    #[case::loopback_localhost("https://localhost:8081/")]
    fn validate_pccs_tls_config__should_accept_any_host_when_insecure_disabled(#[case] url: &str) {
        // Given
        let url: Url = url.parse().expect("valid URL");

        // When (no PEM, no insecure)
        let result = validate_pccs_tls_config(&url, None, false);

        // Then
        assert!(result.is_ok(), "expected ok, got {result:?}");
    }

    #[rstest]
    #[case::public_host("https://pccs.phala.network/")]
    #[case::intel_host("https://api.trustedservices.intel.com/")]
    #[case::loopback_localhost("https://localhost:8081/")]
    fn validate_pccs_tls_config__should_accept_pem_only_for_any_host(#[case] url: &str) {
        // Given a placeholder PEM (validate_pccs_tls_config doesn't parse it, just
        // checks that the two knobs aren't both set; PEM parsing is exercised by
        // build_pccs_http_client__should_reject_invalid_pem).
        let url: Url = url.parse().expect("valid URL");
        let pem = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";

        // When
        let result = validate_pccs_tls_config(&url, Some(pem), false);

        // Then
        assert!(result.is_ok(), "expected ok for {url}, got {result:?}");
    }

    #[test]
    fn validate_pccs_tls_config__should_reject_pem_and_insecure_combined() {
        // Given
        let url: Url = "https://localhost:8081/".parse().expect("valid URL");
        let pem = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";

        // When (both knobs set)
        let result = validate_pccs_tls_config(&url, Some(pem), true);

        // Then
        assert!(
            result.is_err(),
            "expected err when pccs_ca_cert_pem and pccs_tls_insecure both set, got {result:?}"
        );
    }

    #[test]
    fn build_pccs_http_client__should_reject_invalid_pem() {
        // Given
        let bogus_pem = "-----BEGIN CERTIFICATE-----\nnot really base64\n-----END CERTIFICATE-----";

        // When
        let result = build_pccs_http_client(Some(bogus_pem), false);

        // Then
        assert!(
            result.is_err(),
            "expected err for invalid PEM, got {result:?}"
        );
    }

    #[test]
    fn build_pccs_http_client__should_succeed_with_no_knobs_set() {
        // Given default inputs (the no-config path that every existing
        // operator hits on the public Phala / Intel endpoints).

        // When
        let result = build_pccs_http_client(None, false);

        // Then
        assert!(result.is_ok(), "expected ok, got {result:?}");
    }

    #[test]
    fn build_pccs_http_client__should_succeed_with_insecure_only() {
        // When
        let result = build_pccs_http_client(None, true);

        // Then
        assert!(result.is_ok(), "expected ok, got {result:?}");
    }

    #[test]
    fn build_pccs_http_client__should_succeed_with_valid_pem() {
        // Given a real, freshly-generated PEM cert.
        let pem = test_cert_pem();

        // When
        let result = build_pccs_http_client(Some(&pem), false);

        // Then
        assert!(result.is_ok(), "expected ok, got {result:?}");
    }

    #[test]
    fn build_pccs_http_client__should_fail_when_both_knobs_set() {
        // Given a real PEM (so the failure isn't from PEM parsing).
        let pem = test_cert_pem();

        // When (both knobs — should have been caught by validation, but
        // build_pccs_http_client also fails locally as defense in depth).
        let result = build_pccs_http_client(Some(&pem), true);

        // Then
        assert!(
            result.is_err(),
            "expected err when both knobs set, got {result:?}"
        );
    }

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

    #[tokio::test]
    #[cfg(feature = "external-services-tests")]
    async fn test_fetch_collateral_from_pccs() {
        let quote_bytes: Vec<u8> = quote().into();

        let config = DstackTeeAuthorityConfig::default();

        let result = tokio::time::timeout(
            Duration::from_secs(30),
            TeeAuthority::fetch_collateral(
                config.pccs_url.as_str(),
                config.pccs_ca_cert_pem.as_deref(),
                config.pccs_tls_insecure,
                &quote_bytes,
            ),
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
