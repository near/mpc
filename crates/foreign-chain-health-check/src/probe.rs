//! Asks every configured RPC provider which network it serves and compares the answer against the
//! operator's `expected_network_fingerprint`.

use std::collections::BTreeMap;

use foreign_chain_inspector::{
    BuildInspectors, FanOut, ForeignChainInspectionError, NetworkFingerprint, ProviderFailure,
};
use mpc_node_config::{ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig};
use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types::{ForeignChain, ProviderId};

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

impl From<Vec<ProviderHealth>> for ProbeReport {
    fn from(rows: Vec<ProviderHealth>) -> Self {
        Self { rows }
    }
}

impl ProbeReport {
    pub fn rows(&self) -> &[ProviderHealth] {
        &self.rows
    }

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
pub async fn probe_all_providers<InspectorFactory>(
    config: &ForeignChainsConfig,
    inspectors: &InspectorFactory,
) -> ProbeReport
where
    InspectorFactory: BuildInspectors,
{
    let probe_attempts = config.iter_chains().map(|(chain, chain_config)| {
        let timeout = chain_config.timeout_duration();
        async move {
            probe_chain(chain, chain_config, |provider| {
                inspectors.build(chain, provider, timeout)
            })
            .await
        }
    });

    futures::future::join_all(probe_attempts)
        .await
        .concat()
        .into()
}

async fn probe_chain<I>(
    chain: ForeignChain,
    config: &ForeignChainConfig,
    build_new_inspector: impl Fn(&ForeignChainProviderConfig) -> anyhow::Result<Option<I>>,
) -> Vec<ProviderHealth>
where
    I: foreign_chain_inspector::ChainInspector,
{
    let mut inspectors = Vec::new();
    let mut rows = Vec::new();
    for (name, provider) in config.providers.iter() {
        let provider_id = ProviderId(name.as_str().to_owned());
        match build_new_inspector(provider) {
            // Inspector not implemented for the chain
            Ok(None) => return rows_of(chain, config, ProviderStatus::ProbeNotImplemented),
            Ok(Some(inspector)) => inspectors.push((provider_id, inspector)),
            Err(error) => rows.push(ProviderHealth {
                chain,
                provider: provider_id,
                status: setup_failure(&error),
            }),
        }
    }

    let Some(expected) = &config.expected_network_fingerprint else {
        return rows_of(chain, config, ProviderStatus::MissingExpectedFingerprint);
    };

    let Ok(inspectors) = NonEmptyVec::try_from(inspectors) else {
        return rows;
    };
    // Any of the chain's inspectors normalizes the same way; the first one that built is enough.
    let (_, inspector) = inspectors.first();
    let expected = inspector.canonical_fingerprint(expected);

    let fingerprints = FanOut::new(inspectors)
        .network_fingerprints(config.timeout_duration(), config.max_retries)
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

fn classify(
    expected: &NetworkFingerprint,
    reported: Result<NetworkFingerprint, ForeignChainInspectionError>,
) -> ProviderStatus {
    match reported {
        Ok(observed) if &observed == expected => ProviderStatus::Healthy,
        Ok(observed) => ProviderStatus::WrongNetwork {
            expected: expected.clone(),
            observed,
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
    use foreign_chain_inspector::mock::{MockInspector, MockReply};

    /// Hands the probe a mock inspector per provider URL.
    struct MockInspectors(std::collections::BTreeMap<String, MockInspector>);

    impl MockInspectors {
        fn new<'a>(inspectors: impl IntoIterator<Item = (&'a str, MockInspector)>) -> Self {
            Self(
                inspectors
                    .into_iter()
                    .map(|(url, inspector)| (url.to_string(), inspector))
                    .collect(),
            )
        }
    }

    impl BuildInspectors for MockInspectors {
        type Inspector = MockInspector;

        fn build(
            &self,
            _chain: ForeignChain,
            provider: &ForeignChainProviderConfig,
            _timeout: std::time::Duration,
        ) -> anyhow::Result<Option<MockInspector>> {
            let inspector = self
                .0
                .get(&provider.rpc_url)
                .unwrap_or_else(|| panic!("no mock inspector for `{}`", provider.rpc_url));
            Ok(Some(inspector.clone()))
        }
    }
    use super::*;
    use assert_matches::assert_matches;
    use foreign_chain_inspector::{
        abstract_chain, adi, aptos, arbitrum, avalanche, base, bitcoin, bnb, ethereum, hyperevm,
        polygon, starknet, sui,
    };
    use foreign_chain_rpc_factory::inspectors::InspectorFactory;
    use foreign_chain_rpc_interfaces::sui::Status;
    use foreign_chain_rpc_interfaces::sui::proto::ledger_service_server::{
        LedgerService, LedgerServiceServer,
    };
    use foreign_chain_rpc_interfaces::sui::proto::{GetServiceInfoRequest, GetServiceInfoResponse};
    use mpc_node_config::{AuthConfig, TokenConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use rstest::rstest;
    use std::num::NonZeroU64;

    const MAINNET: &str = starknet::MAINNET_CHAIN_ID;
    const SEPOLIA: &str = starknet::SEPOLIA_CHAIN_ID;
    const PADDED_UPPERCASE_MAINNET: &str = "0x00534E5F4D41494E";
    /// Reserved as "discard", so nothing listens there.
    const CLOSED_PORT_URL: &str = "http://127.0.0.1:9";
    /// For a chain with no probe: the value is never read, only whether it is set at all.
    const ANY_FINGERPRINT: &str = "any-fingerprint";
    const SUI_MAINNET: &str = sui::MAINNET_GENESIS_CHECKPOINT_DIGEST;
    const SUI_TESTNET: &str = sui::TESTNET_GENESIS_CHECKPOINT_DIGEST;
    /// Aptos providers reports its chain id as a bare JSON number (`uint8`). The configured fingerprint is
    /// the same number as text.
    const APTOS_MAINNET: u64 = aptos::MAINNET_CHAIN_ID;
    const APTOS_TESTNET: u64 = aptos::TESTNET_CHAIN_ID;
    const PROVIDER_NAME: &str = "publicnode";
    const BITCOIN_MAINNET: &str = bitcoin::MAINNET_GENESIS_BLOCK_HASH;
    const BITCOIN_TESTNET3: &str = bitcoin::TESTNET3_GENESIS_BLOCK_HASH;

    struct EvmMainnet {
        chain: ForeignChain,
        chain_id: u64,
    }

    impl EvmMainnet {
        /// The form an operator configures.
        fn expected(&self) -> String {
            self.chain_id.to_string()
        }

        /// The `0xXXX` hex quantity an RPC provider answers to an `eth_chainId` request.
        fn answered(&self) -> String {
            format!("{:#x}", self.chain_id)
        }
    }

    /// Every EVM chain the probe covers, with its mainnet chain id.
    const EVM_MAINNETS: [EvmMainnet; 9] = [
        EvmMainnet {
            chain: ForeignChain::Abstract,
            chain_id: abstract_chain::MAINNET_CHAIN_ID,
        },
        EvmMainnet {
            chain: ForeignChain::Adi,
            chain_id: adi::MAINNET_CHAIN_ID,
        },
        EvmMainnet {
            chain: ForeignChain::Arbitrum,
            chain_id: arbitrum::MAINNET_CHAIN_ID,
        },
        EvmMainnet {
            chain: ForeignChain::Avalanche,
            chain_id: avalanche::MAINNET_CHAIN_ID,
        },
        EvmMainnet {
            chain: ForeignChain::Base,
            chain_id: base::MAINNET_CHAIN_ID,
        },
        EvmMainnet {
            chain: ForeignChain::Bnb,
            chain_id: bnb::MAINNET_CHAIN_ID,
        },
        EvmMainnet {
            chain: ForeignChain::Ethereum,
            chain_id: ethereum::MAINNET_CHAIN_ID,
        },
        EvmMainnet {
            chain: ForeignChain::HyperEvm,
            chain_id: hyperevm::MAINNET_CHAIN_ID,
        },
        EvmMainnet {
            chain: ForeignChain::Polygon,
            chain_id: polygon::MAINNET_CHAIN_ID,
        },
    ];

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

    fn solana_only(config: ForeignChainConfig) -> ForeignChainsConfig {
        ForeignChainsConfig {
            solana: Some(config),
            ..Default::default()
        }
    }

    fn bitcoin_only(config: ForeignChainConfig) -> ForeignChainsConfig {
        ForeignChainsConfig {
            bitcoin: Some(config),
            ..Default::default()
        }
    }

    fn put_chain(
        chains: &mut ForeignChainsConfig,
        chain: ForeignChain,
        config: ForeignChainConfig,
    ) {
        let slot = match chain {
            ForeignChain::Abstract => &mut chains.abstract_chain,
            ForeignChain::Adi => &mut chains.adi,
            ForeignChain::Arbitrum => &mut chains.arbitrum,
            ForeignChain::Avalanche => &mut chains.avalanche,
            ForeignChain::Base => &mut chains.base,
            ForeignChain::Bnb => &mut chains.bnb,
            ForeignChain::Ethereum => &mut chains.ethereum,
            ForeignChain::HyperEvm => &mut chains.hyper_evm,
            ForeignChain::Polygon => &mut chains.polygon,
            other => panic!("no config slot wired for `{other:?}`"),
        };
        *slot = Some(config);
    }

    async fn mock_fingerprint<'a>(
        server: &'a httpmock::MockServer,
        fingerprint: &str,
    ) -> httpmock::Mock<'a> {
        let body = serde_json::json!({"jsonrpc": "2.0", "result": fingerprint, "id": 0});
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

    async fn mock_unsupported_method(server: &httpmock::MockServer) -> httpmock::Mock<'_> {
        mock_error_object(server, 200, -32601, "Method not found").await
    }

    async fn mock_non_jsonrpc_body(server: &httpmock::MockServer) -> httpmock::Mock<'_> {
        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::POST);
                then.status(200).body("<html>gateway</html>");
            })
            .await
    }

    fn answering(fingerprint: &str) -> MockReply {
        MockReply::Answer {
            delay: std::time::Duration::ZERO,
            fingerprint: fingerprint.to_string(),
        }
    }

    /// Keyed by chain too: provider names repeat across chains in real configs.
    fn status_of(report: &ProbeReport, chain: ForeignChain, provider: &str) -> ProviderStatus {
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
        let url = "http://mock.invalid/only";
        let config = starknet_only(chain_config(Some(MAINNET), one_provider("publicnode", url)));
        let inspector = MockInspector::new([answering(MAINNET)]);
        let inspectors = MockInspectors::new([(url, inspector.clone())]);

        // When
        let report = probe_all_providers(&config, &inspectors).await;

        // Then
        assert_eq!(inspector.calls(), 1);
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::Healthy
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_on_another_network_as_wrong_network() {
        // Given
        let url = "http://mock.invalid/only";
        let config = starknet_only(chain_config(Some(MAINNET), one_provider("publicnode", url)));
        let inspectors = MockInspectors::new([(url, MockInspector::new([answering(SEPOLIA)]))]);

        // When
        let report = probe_all_providers(&config, &inspectors).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::WrongNetwork {
                expected: NetworkFingerprint::new(MAINNET),
                observed: NetworkFingerprint::new(SEPOLIA),
            }
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_normalize_the_reported_fingerprint_before_comparing() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_fingerprint(&server, PADDED_UPPERCASE_MAINNET).await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::Healthy
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_chain_without_an_expected_fingerprint_without_probing()
     {
        // Given
        let server = httpmock::MockServer::start_async().await;
        let mock = mock_fingerprint(&server, MAINNET).await;
        let config = starknet_only(chain_config(
            None,
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "publicnode"),
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
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::Unreachable
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_refusing_the_request_without_retrying() {
        // Given
        let url = "http://mock.invalid/only";
        let inspector = MockInspector::new([MockReply::refusal(std::time::Duration::ZERO)]);
        let config = starknet_only(with_retries(
            chain_config(Some(MAINNET), one_provider("keyed", url)),
            3,
        ));
        let inspectors = MockInspectors::new([(url, inspector.clone())]);

        // When
        let report = probe_all_providers(&config, &inspectors).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "keyed"),
            ProviderStatus::RequestRejected
        );
        assert_eq!(inspector.calls(), 1, "a refusal must not be retried");
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
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "publicnode"),
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
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::MalformedResponse
        );
    }

    #[tokio::test(start_paused = true)]
    async fn probe_all_providers__should_report_a_provider_that_does_not_answer_in_time() {
        // Given
        let url = "http://mock.invalid/slow";
        let config = starknet_only(chain_config(Some(MAINNET), one_provider("slow", url)));
        let inspectors = MockInspectors::new([(url, MockInspector::new([MockReply::Hang]))]);

        // When
        let report = probe_all_providers(&config, &inspectors).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "slow"),
            ProviderStatus::TimedOut
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_normalize_the_configured_fingerprint_before_comparing() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_fingerprint(&server, MAINNET).await;
        let config = starknet_only(chain_config(
            Some(PADDED_UPPERCASE_MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "publicnode"),
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
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "keyed"),
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
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "wrong-scheme"),
            ProviderStatus::ClientSetupFailed
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_each_provider_of_a_chain_separately() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_fingerprint(&server, MAINNET).await;
        let mut providers = one_provider("healthy", &server.base_url());
        providers.insert("broken".to_string().into(), provider(CLOSED_PORT_URL));
        let config = starknet_only(chain_config(Some(MAINNET), providers));

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "healthy"),
            ProviderStatus::Healthy
        );
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "broken"),
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
        let config = solana_only(chain_config(
            Some(ANY_FINGERPRINT),
            one_provider("publicnode", CLOSED_PORT_URL),
        ));

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Solana, "publicnode"),
            ProviderStatus::ProbeNotImplemented
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_every_configured_chain_under_its_own_chain() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_fingerprint(&server, MAINNET).await;
        let config = ForeignChainsConfig {
            starknet: Some(chain_config(
                Some(MAINNET),
                one_provider("publicnode", &server.base_url()),
            )),
            solana: Some(chain_config(
                Some(ANY_FINGERPRINT),
                one_provider("publicnode", CLOSED_PORT_URL),
            )),
            ..Default::default()
        };

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::Healthy
        );
        assert_eq!(
            status_of(&report, ForeignChain::Solana, "publicnode"),
            ProviderStatus::ProbeNotImplemented
        );
        assert_eq!(report.counts_per_chain().len(), 2);
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_every_evm_chain_on_its_expected_network_as_healthy()
    {
        // Given
        let mut servers = Vec::new();
        let mut config = ForeignChainsConfig::default();
        for mainnet in EVM_MAINNETS {
            let server = httpmock::MockServer::start_async().await;
            mock_fingerprint(&server, &mainnet.answered()).await;
            put_chain(
                &mut config,
                mainnet.chain,
                chain_config(
                    Some(&mainnet.expected()),
                    one_provider("publicnode", &server.base_url()),
                ),
            );
            servers.push(server);
        }

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        for EvmMainnet { chain, .. } in EVM_MAINNETS {
            assert_eq!(
                status_of(&report, chain, "publicnode"),
                ProviderStatus::Healthy,
                "{chain:?}"
            );
        }
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_an_evm_provider_on_another_network_as_wrong_network()
     {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_fingerprint(&server, "0x14a34").await;
        let mut config = ForeignChainsConfig::default();
        put_chain(
            &mut config,
            ForeignChain::Base,
            chain_config(Some("8453"), one_provider("publicnode", &server.base_url())),
        );

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Base, "publicnode"),
            ProviderStatus::WrongNetwork {
                expected: NetworkFingerprint::new("8453"),
                observed: NetworkFingerprint::new("84532"),
            }
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_bitcoin_on_its_genesis_block_as_healthy() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_fingerprint(&server, BITCOIN_MAINNET).await;
        let config = bitcoin_only(chain_config(
            Some(BITCOIN_MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Bitcoin, "publicnode"),
            ProviderStatus::Healthy
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_bitcoin_on_another_network_as_wrong_network() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_fingerprint(&server, BITCOIN_TESTNET3).await;
        let config = bitcoin_only(chain_config(
            Some(BITCOIN_MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Bitcoin, "publicnode"),
            ProviderStatus::WrongNetwork {
                expected: NetworkFingerprint::new(BITCOIN_MAINNET),
                observed: NetworkFingerprint::new(BITCOIN_TESTNET3),
            }
        );
    }

    async fn mock_ledger_info<'a>(
        server: &'a httpmock::MockServer,
        chain_id: u64,
    ) -> httpmock::Mock<'a> {
        let body = serde_json::json!({"chain_id": chain_id, "ledger_version": "1"});
        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::GET);
                then.status(200).json_body(body);
            })
            .await
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_aptos_on_its_expected_chain_id_as_healthy() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_ledger_info(&server, APTOS_MAINNET).await;
        let config = ForeignChainsConfig {
            aptos: Some(chain_config(
                Some(&APTOS_MAINNET.to_string()),
                one_provider(PROVIDER_NAME, &server.base_url()),
            )),
            ..Default::default()
        };

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Aptos, PROVIDER_NAME),
            ProviderStatus::Healthy
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_aptos_on_another_network_as_wrong_network() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_ledger_info(&server, APTOS_TESTNET).await;
        let config = ForeignChainsConfig {
            aptos: Some(chain_config(
                Some(&APTOS_MAINNET.to_string()),
                one_provider(PROVIDER_NAME, &server.base_url()),
            )),
            ..Default::default()
        };

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Aptos, PROVIDER_NAME),
            ProviderStatus::WrongNetwork {
                expected: NetworkFingerprint::new(APTOS_MAINNET.to_string()),
                observed: NetworkFingerprint::new(APTOS_TESTNET.to_string()),
            }
        );
    }

    fn sui_only(config: ForeignChainConfig) -> ForeignChainsConfig {
        ForeignChainsConfig {
            sui: Some(config),
            ..Default::default()
        }
    }

    /// A gRPC ledger service answering whatever a test arms.
    struct FakeSuiLedger(Result<GetServiceInfoResponse, Status>);

    #[tonic::async_trait]
    impl LedgerService for FakeSuiLedger {
        async fn get_service_info(
            &self,
            _request: tonic::Request<GetServiceInfoRequest>,
        ) -> Result<tonic::Response<GetServiceInfoResponse>, Status> {
            self.0.clone().map(tonic::Response::new)
        }
    }

    /// Serves a [`FakeSuiLedger`] on a loopback port until dropped.
    struct FakeSuiServer {
        url: String,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for FakeSuiServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn sui_answering(answer: Result<GetServiceInfoResponse, Status>) -> FakeSuiServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(LedgerServiceServer::new(FakeSuiLedger(answer)))
                .serve_with_incoming(tonic::transport::server::TcpIncoming::from(listener))
                .await
                .expect("the fake Sui ledger should keep serving until the test drops it");
        });
        FakeSuiServer { url, task }
    }

    #[rstest]
    #[case::on_its_genesis_digest(
        Ok(GetServiceInfoResponse::default().with_chain_id(SUI_MAINNET)),
        ProviderStatus::Healthy
    )]
    #[case::on_another_network(
        Ok(GetServiceInfoResponse::default().with_chain_id(SUI_TESTNET)),
        ProviderStatus::WrongNetwork {
            expected: NetworkFingerprint::new(SUI_MAINNET),
            observed: NetworkFingerprint::new(SUI_TESTNET),
        }
    )]
    #[case::missing_chain_id(
        Ok(GetServiceInfoResponse::default()),
        ProviderStatus::MalformedResponse
    )]
    #[case::not_serving_the_api(
        Err(Status::not_found("no such service")),
        ProviderStatus::RequestRejected
    )]
    #[case::slow_answer(Err(Status::deadline_exceeded("too slow")), ProviderStatus::TimedOut)]
    #[tokio::test]
    async fn probe_all_providers__should_classify_the_sui_answer(
        #[case] answer: Result<GetServiceInfoResponse, Status>,
        #[case] expected: ProviderStatus,
    ) {
        // Given
        let server = sui_answering(answer).await;
        let config = sui_only(chain_config(
            Some(SUI_MAINNET),
            one_provider(PROVIDER_NAME, &server.url),
        ));

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Sui, PROVIDER_NAME),
            expected
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_an_unreachable_sui_provider() {
        // Given
        let config = sui_only(chain_config(
            Some(SUI_MAINNET),
            one_provider(PROVIDER_NAME, CLOSED_PORT_URL),
        ));

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Sui, PROVIDER_NAME),
            ProviderStatus::Unreachable
        );
    }

    #[tokio::test(start_paused = true)]
    async fn probe_all_providers__should_retry_a_provider_that_refused_with_a_rate_limit_code() {
        // Given
        let url = "http://mock.invalid/keyed";
        let inspector = MockInspector::new([
            MockReply::transient(std::time::Duration::from_millis(10)),
            MockReply::transient(std::time::Duration::from_millis(10)),
        ]);
        let config = starknet_only(with_retries(
            chain_config(Some(MAINNET), one_provider("keyed", url)),
            2,
        ));
        let inspectors = MockInspectors::new([(url, inspector.clone())]);

        // When
        let report = probe_all_providers(&config, &inspectors).await;

        // Then
        assert_eq!(
            status_of(&report, ForeignChain::Starknet, "keyed"),
            ProviderStatus::Unreachable
        );
        assert_eq!(
            inspector.calls(),
            2,
            "the transient failure should be retried"
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_bound_the_fingerprint_a_provider_reports() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        let flood = "n".repeat(5_000);
        mock_fingerprint(&server, &flood).await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        let ProviderStatus::WrongNetwork { observed, .. } =
            status_of(&report, ForeignChain::Starknet, "publicnode")
        else {
            panic!("expected the flood to read as the wrong network");
        };
        let observed = observed.to_string();
        assert!(observed.ends_with("_TRUNCATED"), "{observed}");
        assert_eq!(
            observed.chars().count(),
            NetworkFingerprint::MAX_CHARS,
            "{observed}"
        );
    }

    #[test]
    fn classify__should_report_a_transaction_level_error_as_malformed() {
        // Given
        let expected = NetworkFingerprint::new(MAINNET);

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
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert!(report.rows().is_empty());
        assert!(report.counts_per_chain().is_empty());
    }

    #[tokio::test]
    async fn probe_all_providers__should_keep_auth_material_out_of_the_report() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        mock_fingerprint(&server, SEPOLIA).await;
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
        let report = probe_all_providers(&config, &InspectorFactory).await;

        // Then
        assert_matches!(
            status_of(&report, ForeignChain::Starknet, "keyed"),
            ProviderStatus::WrongNetwork { .. }
        );
        let rendered = format!("{report:?}");
        assert!(!rendered.contains("super-secret"), "{rendered}");
        assert!(!rendered.contains("127.0.0.1"), "{rendered}");
    }
}
