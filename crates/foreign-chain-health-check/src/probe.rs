//! Asks every configured RPC provider which network it serves and compares the answer against the
//! operator's `expected_network_fingerprint`.

use std::collections::BTreeMap;
use std::time::Duration;

use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use foreign_chain_inspector::{
    FanOut, ForeignChainInspectionError, NetworkFingerprint, ProviderFailure,
};
use mpc_node_config::{ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig};
use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types::{ForeignChain, ProviderId};

use crate::prepare_jsonrpc;

/// One provider's verdict. Anything other than [`ProviderStatus::Healthy`] is unhealthy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderStatus {
    Healthy,
    WrongNetwork {
        expected: NetworkFingerprint,
        observed: NetworkFingerprint,
    },
    /// DNS, TLS, connection refused, 5xx, or rate limiting.
    Unreachable,
    /// The provider answered and refused: credentials invalid, or not enabled for this chain.
    RequestRejected,
    MalformedResponse,
    TimedOut,
    AuthTokenUnresolved,
    ClientSetupFailed,
    /// The chain is configured without an `expected_network_fingerprint`, so its providers cannot
    /// be checked.
    MissingExpectedFingerprint,
    ProbeNotImplemented,
}

impl ProviderStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderHealth {
    pub chain: ForeignChain,
    pub provider: ProviderId,
    pub status: ProviderStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProviderCounts {
    pub configured: usize,
    pub healthy: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    rows: Vec<ProviderHealth>,
}

impl ProbeReport {
    pub fn rows(&self) -> &[ProviderHealth] {
        &self.rows
    }

    /// Only configured chains appear, never reports on a chain the operator did not configure.
    pub fn counts_per_chain(&self) -> BTreeMap<ForeignChain, ProviderCounts> {
        let mut counts: BTreeMap<ForeignChain, ProviderCounts> = BTreeMap::new();
        for row in &self.rows {
            let entry = counts.entry(row.chain).or_default();
            entry.configured += 1;
            if row.status.is_healthy() {
                entry.healthy += 1;
            }
        }
        counts
    }
}

/// Probe every configured provider concurrently.
///
/// Each provider is tried up to `max_retries` times, `timeout_sec` per try, and only for as long as
/// the failures stay transient. This returns within the largest configured `timeout_sec *
/// max_retries`, plus the [`foreign_chain_inspector::RETRY_BACKOFF`] between tries.
pub async fn probe_all_providers(config: &ForeignChainsConfig) -> ProbeReport {
    let probe_attempts = config
        .iter_chains()
        .map(|(chain, chain_config)| async move {
            match chain {
                ForeignChain::Starknet => {
                    probe_chain(chain, chain_config, |provider| {
                        Ok(StarknetInspector::new(prepare_jsonrpc(provider)?))
                    })
                    .await
                }
                // TODO(#4003): probe the remaining chains.
                _ => rows_of(chain, chain_config, ProviderStatus::ProbeNotImplemented),
            }
        });

    let report_rows = futures::future::join_all(probe_attempts).await.concat();
    ProbeReport { rows: report_rows }
}

async fn probe_chain<I>(
    chain: ForeignChain,
    config: &ForeignChainConfig,
    new_inspector: impl Fn(&ForeignChainProviderConfig) -> anyhow::Result<I>,
) -> Vec<ProviderHealth>
where
    I: foreign_chain_inspector::NetworkFingerprintInspector + Clone + Send + Sync + 'static,
{
    let Some(expected) = &config.expected_network_fingerprint else {
        return rows_of(chain, config, ProviderStatus::MissingExpectedFingerprint);
    };
    let expected = I::canonical_fingerprint(expected);

    let mut inspectors = Vec::new();
    let mut rows = Vec::new();
    for (name, provider) in config.providers.iter() {
        let provider_id = ProviderId(name.as_str().to_owned());
        match new_inspector(provider) {
            Ok(inspector) => inspectors.push((provider_id, inspector)),
            Err(error) => rows.push(ProviderHealth {
                chain,
                provider: provider_id,
                status: setup_failure(&error),
            }),
        }
    }

    let Ok(inspectors) = NonEmptyVec::try_from(inspectors) else {
        return rows;
    };

    let timeout = Duration::from_secs(config.timeout_sec.get());
    let fingerprints = FanOut::new(inspectors)
        .network_fingerprints(timeout, config.max_retries)
        .await;
    for (provider, reported) in fingerprints {
        rows.push(ProviderHealth {
            chain,
            provider,
            status: classify(&expected, reported),
        });
    }
    rows
}

/// [`ProviderStatus`] carries no error text, so the one actionable cause gets its own variant. Only
/// a token read from the environment can fail to resolve; a [`std::env::VarError`] identifies it.
fn setup_failure(error: &anyhow::Error) -> ProviderStatus {
    if error.chain().any(|cause| cause.is::<std::env::VarError>()) {
        ProviderStatus::AuthTokenUnresolved
    } else {
        ProviderStatus::ClientSetupFailed
    }
}

fn rows_of(
    chain: ForeignChain,
    config: &ForeignChainConfig,
    status: ProviderStatus,
) -> Vec<ProviderHealth> {
    config
        .providers
        .keys()
        .map(|name| ProviderHealth {
            chain,
            provider: ProviderId(name.as_str().to_owned()),
            status: status.clone(),
        })
        .collect()
}

/// A provider answers what it likes and the report reaches logs and metric labels, so the length is
/// capped well clear of the longest real fingerprint: Bitcoin's genesis hash, at 66 characters.
fn bounded(observed: NetworkFingerprint) -> NetworkFingerprint {
    const MAX_CHARS: usize = 96;

    let observed = observed.to_string();
    match observed.char_indices().nth(MAX_CHARS) {
        None => NetworkFingerprint::from(observed),
        Some((cutoff, _)) => NetworkFingerprint::from(format!("{}…", &observed[..cutoff])),
    }
}

fn classify(
    expected: &NetworkFingerprint,
    reported: Result<NetworkFingerprint, ForeignChainInspectionError>,
) -> ProviderStatus {
    match reported {
        Ok(observed) if &observed == expected => ProviderStatus::Healthy,
        Ok(observed) => ProviderStatus::WrongNetwork {
            expected: expected.clone(),
            observed: bounded(observed),
        },
        Err(error) => match error.provider_failure() {
            Some(ProviderFailure::Unreachable) => ProviderStatus::Unreachable,
            Some(ProviderFailure::Rejected) => ProviderStatus::RequestRejected,
            Some(ProviderFailure::TimedOut) => ProviderStatus::TimedOut,
            Some(ProviderFailure::Malformed) => ProviderStatus::MalformedResponse,
            // Probing does not inspect transactions, so a transaction-level error means
            // an impl answered outside its contract.
            None => ProviderStatus::MalformedResponse,
        },
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use mpc_node_config::{AuthConfig, TokenConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use std::num::NonZeroU64;

    /// Starknet mainnet's chain id, `SN_MAIN` in ASCII.
    const MAINNET: &str = "0x534e5f4d41494e";
    const SEPOLIA: &str = "0x534e5f5345504f4c4941";
    const PADDED_UPPERCASE_MAINNET: &str = "0x00534E5F4D41494E";
    /// Reserved as "discard", so nothing listens there.
    const CLOSED_PORT_URL: &str = "http://127.0.0.1:9";

    fn provider(rpc_url: &str) -> ForeignChainProviderConfig {
        ForeignChainProviderConfig {
            rpc_url: rpc_url.to_string(),
            auth: AuthConfig::None,
        }
    }

    fn chain_config(
        expected: Option<&str>,
        providers: NonEmptyBTreeMap<
            mpc_node_config::foreign_chains::RpcProviderName,
            ForeignChainProviderConfig,
        >,
    ) -> ForeignChainConfig {
        ForeignChainConfig {
            timeout_sec: NonZeroU64::new(1).unwrap(),
            max_retries: NonZeroU64::new(1).unwrap(),
            expected_network_fingerprint: expected.map(str::to_string),
            providers,
        }
    }

    fn with_retries(config: ForeignChainConfig, max_retries: u64) -> ForeignChainConfig {
        ForeignChainConfig {
            max_retries: NonZeroU64::new(max_retries).unwrap(),
            ..config
        }
    }

    fn one_provider(
        name: &str,
        rpc_url: &str,
    ) -> NonEmptyBTreeMap<
        mpc_node_config::foreign_chains::RpcProviderName,
        ForeignChainProviderConfig,
    > {
        NonEmptyBTreeMap::new(name.to_string().into(), provider(rpc_url))
    }

    fn starknet_only(config: ForeignChainConfig) -> ForeignChainsConfig {
        ForeignChainsConfig {
            starknet: Some(config),
            ..Default::default()
        }
    }

    async fn mock_chain_id<'a>(
        server: &'a httpmock::MockServer,
        chain_id: &str,
    ) -> httpmock::Mock<'a> {
        let body = serde_json::json!({"jsonrpc": "2.0", "result": chain_id, "id": 0});
        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST);
                then.status(200).json_body(body);
            })
            .await
    }

    async fn mock_error_object<'a>(
        server: &'a httpmock::MockServer,
        status: u16,
        code: i32,
        message: &str,
    ) -> httpmock::Mock<'a> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "error": {"code": code, "message": message},
        });
        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST);
                then.status(status).json_body(body);
            })
            .await
    }

    async fn mock_bad_api_key(server: &httpmock::MockServer) -> httpmock::Mock<'_> {
        mock_error_object(server, 401, -32600, "Must be authenticated!").await
    }

    async fn mock_unsupported_method(server: &httpmock::MockServer) -> httpmock::Mock<'_> {
        mock_error_object(server, 200, -32601, "Method not found").await
    }

    /// Throttling over HTTP 200, so only the JSON-RPC code tells the caller to back off.
    async fn mock_throttled_over_http_200(server: &httpmock::MockServer) -> httpmock::Mock<'_> {
        mock_error_object(server, 200, -32005, "limit exceeded").await
    }

    async fn mock_non_jsonrpc_body(server: &httpmock::MockServer) -> httpmock::Mock<'_> {
        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST);
                then.status(200).body("<html>gateway</html>");
            })
            .await
    }

    async fn mock_never_answers_in_time(server: &httpmock::MockServer) -> httpmock::Mock<'_> {
        let body = serde_json::json!({"jsonrpc": "2.0", "result": MAINNET, "id": 0});
        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST);
                then.status(200)
                    .json_body(body)
                    .delay(Duration::from_secs(30));
            })
            .await
    }

    /// Keyed by chain too: provider names repeat across chains in real configs.
    fn must_status_of(report: &ProbeReport, chain: ForeignChain, provider: &str) -> ProviderStatus {
        report
            .rows()
            .iter()
            .find(|row| row.chain == chain && row.provider.0 == provider)
            .unwrap_or_else(|| panic!("missing row for `{chain:?}` provider `{provider}`"))
            .status
            .clone()
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_on_the_expected_network_as_healthy() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        let mock = mock_chain_id(&server, MAINNET).await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        mock.assert_async().await;
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::Healthy
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_on_another_network_as_wrong_network() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_chain_id(&server, SEPOLIA).await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::WrongNetwork {
                expected: NetworkFingerprint::from(MAINNET.to_string()),
                observed: NetworkFingerprint::from(SEPOLIA.to_string()),
            }
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_normalize_the_reported_fingerprint_before_comparing() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_chain_id(&server, PADDED_UPPERCASE_MAINNET).await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::Healthy
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_chain_without_an_expected_fingerprint_without_probing()
     {
        // Given
        let server = httpmock::MockServer::start_async().await;
        let mock = mock_chain_id(&server, MAINNET).await;
        let config = starknet_only(chain_config(
            None,
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::MissingExpectedFingerprint
        );
        mock.assert_calls_async(0).await;
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_an_unreachable_provider() {
        // Given
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", CLOSED_PORT_URL),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::Unreachable
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_refusing_the_request_without_retrying() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        let mock = mock_bad_api_key(&server).await;
        let config = starknet_only(with_retries(
            chain_config(Some(MAINNET), one_provider("keyed", &server.base_url())),
            3,
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "keyed"),
            ProviderStatus::RequestRejected
        );
        mock.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_answering_with_a_jsonrpc_error() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_unsupported_method(&server).await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::RequestRejected
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_answering_with_an_unusable_body() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_non_jsonrpc_body(&server).await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::MalformedResponse
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_that_does_not_answer_in_time() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_never_answers_in_time(&server).await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("slow", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "slow"),
            ProviderStatus::TimedOut
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_normalize_the_configured_fingerprint_before_comparing() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_chain_id(&server, MAINNET).await;
        let config = starknet_only(chain_config(
            Some(PADDED_UPPERCASE_MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::Healthy
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_whose_auth_token_does_not_resolve() {
        // Given
        let config = starknet_only(chain_config(
            Some(MAINNET),
            NonEmptyBTreeMap::new(
                "keyed".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: CLOSED_PORT_URL.to_string(),
                    auth: AuthConfig::Header {
                        name: http::HeaderName::from_static("authorization"),
                        scheme: Some("Bearer".to_string()),
                        token: TokenConfig::Env {
                            env: "PROBE_TEST_TOKEN_THAT_IS_NOT_SET".to_string(),
                        },
                    },
                },
            ),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "keyed"),
            ProviderStatus::AuthTokenUnresolved
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_whose_client_cannot_be_built() {
        // Given
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("wrong-scheme", "ws://127.0.0.1:9"),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "wrong-scheme"),
            ProviderStatus::ClientSetupFailed
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_each_provider_of_a_chain_separately() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_chain_id(&server, MAINNET).await;
        let mut providers = one_provider("healthy", &server.base_url());
        providers.insert("broken".to_string().into(), provider(CLOSED_PORT_URL));
        let config = starknet_only(chain_config(Some(MAINNET), providers));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "healthy"),
            ProviderStatus::Healthy
        );
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "broken"),
            ProviderStatus::Unreachable
        );
        assert_eq!(
            report.counts_per_chain()[&ForeignChain::Starknet],
            ProviderCounts {
                configured: 2,
                healthy: 1,
            }
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_chain_with_no_fingerprint_probe_as_not_implemented()
     {
        // Given
        let config = ForeignChainsConfig {
            base: Some(chain_config(
                Some("8453"),
                one_provider("publicnode", CLOSED_PORT_URL),
            )),
            ..Default::default()
        };

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Base, "publicnode"),
            ProviderStatus::ProbeNotImplemented
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_every_configured_chain_under_its_own_chain() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_chain_id(&server, MAINNET).await;
        let config = ForeignChainsConfig {
            starknet: Some(chain_config(
                Some(MAINNET),
                one_provider("publicnode", &server.base_url()),
            )),
            base: Some(chain_config(
                Some("8453"),
                one_provider("publicnode", CLOSED_PORT_URL),
            )),
            ..Default::default()
        };

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::Healthy
        );
        assert_eq!(
            must_status_of(&report, ForeignChain::Base, "publicnode"),
            ProviderStatus::ProbeNotImplemented
        );
        assert_eq!(report.counts_per_chain().len(), 2);
    }

    #[tokio::test]
    async fn probe_all_providers__should_retry_a_provider_that_refused_with_a_rate_limit_code() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        let mock = mock_throttled_over_http_200(&server).await;
        let config = starknet_only(with_retries(
            chain_config(Some(MAINNET), one_provider("keyed", &server.base_url())),
            2,
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "keyed"),
            ProviderStatus::Unreachable
        );
        mock.assert_calls_async(2).await;
    }

    #[tokio::test]
    async fn probe_all_providers__should_bound_the_fingerprint_a_provider_reports() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        let flood = "n".repeat(5_000);
        mock_chain_id(&server, &flood).await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        let ProviderStatus::WrongNetwork { observed, .. } =
            must_status_of(&report, ForeignChain::Starknet, "publicnode")
        else {
            panic!("expected the flood to read as the wrong network");
        };
        assert!(observed.to_string().chars().count() < 100);
    }

    #[test]
    fn classify__should_report_a_transaction_level_error_as_malformed() {
        // Given
        let expected = NetworkFingerprint::from(MAINNET.to_string());

        // When
        let status = classify(
            &expected,
            Err(ForeignChainInspectionError::TransactionNotFound),
        );

        // Then
        assert_eq!(status, ProviderStatus::MalformedResponse);
    }

    #[tokio::test]
    async fn probe_all_providers__should_return_an_empty_report_when_no_chains_are_configured() {
        // Given
        let config = ForeignChainsConfig::default();

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert!(report.rows().is_empty());
        assert!(report.counts_per_chain().is_empty());
    }

    #[tokio::test]
    async fn probe_all_providers__should_keep_auth_material_out_of_the_report() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_chain_id(&server, SEPOLIA).await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            NonEmptyBTreeMap::new(
                "keyed".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: format!("{}/v2/API_KEY", server.base_url()),
                    auth: AuthConfig::Path {
                        placeholder: "API_KEY".to_string(),
                        token: TokenConfig::Val {
                            val: "super-secret".to_string(),
                        },
                    },
                },
            ),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then
        assert_matches!(
            must_status_of(&report, ForeignChain::Starknet, "keyed"),
            ProviderStatus::WrongNetwork { .. }
        );
        let rendered = format!("{report:?}");
        assert!(!rendered.contains("super-secret"), "{rendered}");
        assert!(!rendered.contains("127.0.0.1"), "{rendered}");
    }
}
