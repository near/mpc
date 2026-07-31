//! Asks every configured RPC provider which network it serves and compares the answer against the
//! operator's `expected_chain_identity`.

use std::collections::BTreeMap;
use std::time::Duration;

use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use foreign_chain_inspector::{
    ChainIdentity, FanOut, ForeignChainInspectionError, ProviderFailure,
};
use mpc_node_config::{ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig};
use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types::{ForeignChain, ProviderId};

use crate::prepare_jsonrpc;

/// One provider's verdict. Anything other than [`ProviderStatus::Healthy`] is unhealthy.
///
/// Carries no rendered RPC error: `Path`/`Query` auth splices the operator's API key into the URL,
/// and upstream errors interpolate that URL into their text. Dropping the text here keeps the key
/// out of anything built from a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderStatus {
    Healthy,
    WrongNetwork {
        expected: ChainIdentity,
        observed: ChainIdentity,
    },
    /// DNS, TLS, connection refused, 5xx, or rate limiting.
    Unreachable,
    /// The provider answered and refused: credentials invalid, or not enabled for this chain.
    RequestRejected,
    MalformedResponse,
    TimedOut,
    /// The provider's auth token did not resolve, e.g. an environment variable that is not set.
    AuthTokenUnresolved,
    /// The RPC client could not be built from the provider's URL and auth.
    ClientSetupFailed,
    /// The chain is configured without an `expected_chain_identity`, so its providers cannot be
    /// checked. Reported rather than skipped: silence would read as healthy.
    MissingExpectedIdentity,
    /// The chain has no identity probe yet, either because none is written for it or because the
    /// node cannot inspect it at all.
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
    I: foreign_chain_inspector::ChainIdentityInspector + Clone + Send + Sync + 'static,
{
    let Some(expected) = &config.expected_chain_identity else {
        return rows_of(chain, config, ProviderStatus::MissingExpectedIdentity);
    };
    let expected = I::canonical_identity(expected);

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
    let identities = FanOut::new(inspectors)
        .chain_identities(timeout, config.max_retries)
        .await;
    for (provider, identity) in identities {
        rows.push(ProviderHealth {
            chain,
            provider,
            status: classify(&expected, identity),
        });
    }
    rows
}

/// The error itself is dropped for the reason [`ProviderStatus`] documents, so the one cause an
/// operator can act on gets a status of its own instead.
///
/// A token resolves from the environment or from the config file, and only the former can fail, so
/// a [`std::env::VarError`] in the chain is what names this case.
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

/// Every chain's identity fits comfortably: the longest is Bitcoin's 66-character genesis hash. What
/// a provider answers instead is its own choice, and a report ends up in logs and metric labels.
fn bounded(observed: ChainIdentity) -> ChainIdentity {
    const MAX_CHARS: usize = 96;

    let observed = observed.to_string();
    match observed.char_indices().nth(MAX_CHARS) {
        None => ChainIdentity::from(observed),
        Some((cutoff, _)) => ChainIdentity::from(format!("{}…", &observed[..cutoff])),
    }
}

fn classify(
    expected: &ChainIdentity,
    identity: Result<ChainIdentity, ForeignChainInspectionError>,
) -> ProviderStatus {
    match identity {
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
            // The probe inspects no transaction, so a transaction-level error means an impl
            // answered outside its contract.
            None => ProviderStatus::MalformedResponse,
        },
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use mpc_node_config::{AuthConfig, TokenConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use std::num::NonZeroU64;

    /// Starknet mainnet's chain id, `SN_MAIN` in ASCII.
    const MAINNET: &str = "0x534e5f4d41494e";
    const SEPOLIA: &str = "0x534e5f5345504f4c4941";
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
            expected_chain_identity: expected.map(str::to_string),
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
        // Given a provider serving Sepolia while the operator configured mainnet
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
                expected: ChainIdentity::from(MAINNET.to_string()),
                observed: ChainIdentity::from(SEPOLIA.to_string()),
            }
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_normalize_the_reported_identity_before_comparing() {
        // Given a provider padding and uppercasing the chain id, as the spec permits
        let server = httpmock::MockServer::start_async().await;
        mock_chain_id(&server, "0x00534E5F4D41494E").await;
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
    async fn probe_all_providers__should_report_a_chain_without_an_expected_identity_without_probing()
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

        // Then the provider is reported rather than skipped, and no request was sent
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::MissingExpectedIdentity
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
        // Given a provider answering the way an authenticated provider answers a bad API key
        let server = httpmock::MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST);
                then.status(401).json_body(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 0,
                    "error": {"code": -32600, "message": "Must be authenticated!"},
                }));
            })
            .await;
        let config = starknet_only(with_retries(
            chain_config(Some(MAINNET), one_provider("keyed", &server.base_url())),
            3,
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then the refusal is named as such, and retrying it is pointless
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "keyed"),
            ProviderStatus::RequestRejected
        );
        mock.assert_calls_async(1).await;
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_answering_with_a_jsonrpc_error() {
        // Given a provider that does not serve this chain's methods
        let server = httpmock::MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST);
                then.status(200).json_body(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 0,
                    "error": {"code": -32601, "message": "Method not found"},
                }));
            })
            .await;
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
        // Given a provider whose answer is not JSON-RPC at all
        let server = httpmock::MockServer::start_async().await;
        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST);
                then.status(200).body("<html>gateway</html>");
            })
            .await;
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
        // Given a provider slower than the configured timeout
        let server = httpmock::MockServer::start_async().await;
        let body = serde_json::json!({"jsonrpc": "2.0", "result": MAINNET, "id": 0});
        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST);
                then.status(200)
                    .json_body(body)
                    .delay(Duration::from_secs(30));
            })
            .await;
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
    async fn probe_all_providers__should_normalize_the_configured_identity_before_comparing() {
        // Given an operator writing the chain id padded and uppercased, as the spec permits
        let server = httpmock::MockServer::start_async().await;
        mock_chain_id(&server, MAINNET).await;
        let config = starknet_only(chain_config(
            Some("0x00534E5F4D41494E"),
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
        // Given a provider whose auth token comes from an environment variable that is not set
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

        // Then the operator learns which of the two setup failures it was
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "keyed"),
            ProviderStatus::AuthTokenUnresolved
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_whose_client_cannot_be_built() {
        // Given a provider whose URL is not one a client can be built for
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
        // Given one healthy provider and one that is unreachable
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
    async fn probe_all_providers__should_report_a_chain_with_no_identity_probe_as_not_implemented()
    {
        // Given a chain the node can inspect but has no identity probe for
        let config = ForeignChainsConfig {
            base: Some(chain_config(
                Some("8453"),
                one_provider("publicnode", CLOSED_PORT_URL),
            )),
            ..Default::default()
        };

        // When
        let report = probe_all_providers(&config).await;

        // Then it is visible in the report rather than silently absent
        assert_eq!(
            must_status_of(&report, ForeignChain::Base, "publicnode"),
            ProviderStatus::ProbeNotImplemented
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_every_configured_chain_under_its_own_chain() {
        // Given the same provider name configured for two chains
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

        // Then each chain gets its own row rather than one shadowing the other
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
        // Given a provider signalling throttling as a JSON-RPC error object over HTTP 200
        let server = httpmock::MockServer::start_async().await;
        let mock = server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST);
                then.status(200).json_body(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 0,
                    "error": {"code": -32005, "message": "limit exceeded"},
                }));
            })
            .await;
        let config = starknet_only(with_retries(
            chain_config(Some(MAINNET), one_provider("keyed", &server.base_url())),
            2,
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then throttling is the one refusal worth retrying
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "keyed"),
            ProviderStatus::Unreachable
        );
        mock.assert_calls_async(2).await;
    }

    #[tokio::test]
    async fn probe_all_providers__should_bound_the_identity_a_provider_reports() {
        // Given a provider answering with far more than an identity
        let server = httpmock::MockServer::start_async().await;
        let flood = "n".repeat(5_000);
        mock_chain_id(&server, &flood).await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config).await;

        // Then what reaches a log line or a metric label is bounded
        let ProviderStatus::WrongNetwork { observed, .. } =
            must_status_of(&report, ForeignChain::Starknet, "publicnode")
        else {
            panic!("expected the flood to read as the wrong network");
        };
        assert!(observed.to_string().chars().count() < 100);
    }

    #[test]
    fn classify__should_report_a_transaction_level_error_as_malformed() {
        // Given an error about a transaction, which the probe never asks about
        let expected = ChainIdentity::from(MAINNET.to_string());

        // When
        let status = classify(
            &expected,
            Err(ForeignChainInspectionError::TransactionNotFound),
        );

        // Then the inspector answered outside the contract its probe has
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
        // Given a provider whose API key is spliced into the URL path
        let config = starknet_only(chain_config(
            Some(MAINNET),
            NonEmptyBTreeMap::new(
                "keyed".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: format!("{CLOSED_PORT_URL}/v2/API_KEY"),
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

        // Then neither the token nor the URL it was spliced into reaches the report
        let rendered = format!("{report:?}");
        assert!(!rendered.contains("super-secret"), "{rendered}");
        assert!(!rendered.contains("127.0.0.1"), "{rendered}");
    }
}
