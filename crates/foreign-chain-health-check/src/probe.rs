//! Asks every configured RPC provider which network it serves and compares the answer against the
//! operator's `expected_network_fingerprint`.

use std::collections::BTreeMap;

use foreign_chain_inspector::abstract_chain::inspector::Abstract;
use foreign_chain_inspector::adi::inspector::Adi;
use foreign_chain_inspector::aptos::inspector::AptosInspector;
use foreign_chain_inspector::arbitrum::inspector::Arbitrum;
use foreign_chain_inspector::avalanche::inspector::Avalanche;
use foreign_chain_inspector::base::inspector::Base;
use foreign_chain_inspector::bitcoin::inspector::BitcoinInspector;
use foreign_chain_inspector::bnb::inspector::Bnb;
use foreign_chain_inspector::evm::inspector::{EvmChain, EvmInspector};
use foreign_chain_inspector::http_client::HttpClient;
use foreign_chain_inspector::hyperevm::inspector::HyperEvm;
use foreign_chain_inspector::polygon::inspector::Polygon;
use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use foreign_chain_inspector::sui::inspector::SuiInspector;
use foreign_chain_inspector::{
    FanOut, ForeignChainInspectionError, NetworkFingerprint, NetworkFingerprintInspector,
    ProviderFailure,
};
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use foreign_chain_rpc_interfaces::sui::GrpcSuiClient;
use mpc_node_config::{ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig};
use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types::{ForeignChain, ProviderId};

use crate::timeout_of;
use foreign_chain_rpc_auth::{aptos_client, http_client, sui_client};

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

/// Probe every configured provider concurrently, building each provider's inspector with
/// `new_inspector`. The node injects [`rpc_inspector`].
///
/// Each provider is tried up to `max_retries` times, `timeout_sec` per try, and only for as long as
/// the failures stay transient. This returns within the largest configured `timeout_sec *
/// max_retries`, plus the [`foreign_chain_inspector::RETRY_BACKOFF`] between tries.
pub async fn probe_all_providers<I>(
    config: &ForeignChainsConfig,
    new_inspector: impl Fn(
        ForeignChain,
        &ForeignChainConfig,
        &ForeignChainProviderConfig,
    ) -> anyhow::Result<I>
    + Sync,
) -> ProbeReport
where
    I: NetworkFingerprintInspector + Clone + Send + Sync + 'static,
{
    // A shared reference is Copy, so every per chain future can capture the closure.
    let new_inspector = &new_inspector;
    let probe_attempts = config
        .iter_chains()
        .map(|(chain, chain_config)| async move {
            if new_rpc_inspector(chain).is_none() {
                return rows_of(chain, chain_config, ProviderStatus::ProbeNotImplemented);
            }
            probe_chain(chain, chain_config, |provider| {
                new_inspector(chain, chain_config, provider)
            })
            .await
        });

    futures::future::join_all(probe_attempts)
        .await
        .concat()
        .into()
}

/// Builds one provider's inspector for a chain whose probe exists.
type NewRpcInspector =
    fn(&ForeignChainConfig, &ForeignChainProviderConfig) -> anyhow::Result<RpcInspector>;

/// How to build a chain's inspector, or `None` when no probe exists for the chain. The single
/// source of truth for which chains the probe covers.
fn new_rpc_inspector(chain: ForeignChain) -> Option<NewRpcInspector> {
    Some(match chain {
        ForeignChain::Starknet => |_, provider| {
            Ok(RpcInspector::Starknet(StarknetInspector::new(http_client(
                provider,
            )?)))
        },
        ForeignChain::Abstract => |_, provider| Ok(RpcInspector::Abstract(new_evm(provider)?)),
        ForeignChain::Adi => |_, provider| Ok(RpcInspector::Adi(new_evm(provider)?)),
        ForeignChain::Arbitrum => |_, provider| Ok(RpcInspector::Arbitrum(new_evm(provider)?)),
        ForeignChain::Avalanche => |_, provider| Ok(RpcInspector::Avalanche(new_evm(provider)?)),
        ForeignChain::Base => |_, provider| Ok(RpcInspector::Base(new_evm(provider)?)),
        ForeignChain::Bnb => |_, provider| Ok(RpcInspector::Bnb(new_evm(provider)?)),
        ForeignChain::HyperEvm => |_, provider| Ok(RpcInspector::HyperEvm(new_evm(provider)?)),
        ForeignChain::Polygon => |_, provider| Ok(RpcInspector::Polygon(new_evm(provider)?)),
        ForeignChain::Bitcoin => |_, provider| {
            Ok(RpcInspector::Bitcoin(BitcoinInspector::new(http_client(
                provider,
            )?)))
        },
        ForeignChain::Aptos => |chain_config, provider| {
            Ok(RpcInspector::Aptos(AptosInspector::new(aptos_client(
                provider,
                timeout_of(chain_config),
            )?)))
        },
        ForeignChain::Sui => |chain_config, provider| {
            Ok(RpcInspector::Sui(SuiInspector::new(sui_client(
                provider,
                timeout_of(chain_config),
            )?)))
        },
        // Ethereum, Solana and Ton have no inspector to probe them with.
        _ => return None,
    })
}

/// The EVM chains differ only in their marker type, which the caller's variant fixes.
fn new_evm<Chain: EvmChain>(
    provider: &ForeignChainProviderConfig,
) -> anyhow::Result<EvmInspector<HttpClient, Chain>> {
    Ok(EvmInspector::new(http_client(provider)?))
}

/// The inspector for one provider, backed by a real RPC client, as [`rpc_inspector`] builds it.
/// One variant per probeable chain, so [`probe_all_providers`] can hold providers of different
/// chains behind a single type.
#[derive(Clone)]
pub enum RpcInspector {
    Starknet(StarknetInspector<HttpClient>),
    Abstract(EvmInspector<HttpClient, Abstract>),
    Adi(EvmInspector<HttpClient, Adi>),
    Arbitrum(EvmInspector<HttpClient, Arbitrum>),
    Avalanche(EvmInspector<HttpClient, Avalanche>),
    Base(EvmInspector<HttpClient, Base>),
    Bnb(EvmInspector<HttpClient, Bnb>),
    HyperEvm(EvmInspector<HttpClient, HyperEvm>),
    Polygon(EvmInspector<HttpClient, Polygon>),
    Bitcoin(BitcoinInspector<HttpClient>),
    Aptos(AptosInspector<ReqwestAptosClient>),
    Sui(SuiInspector<GrpcSuiClient>),
}

impl NetworkFingerprintInspector for RpcInspector {
    async fn network_fingerprint(&self) -> Result<NetworkFingerprint, ForeignChainInspectionError> {
        match self {
            Self::Starknet(inspector) => inspector.network_fingerprint().await,
            Self::Abstract(inspector) => inspector.network_fingerprint().await,
            Self::Adi(inspector) => inspector.network_fingerprint().await,
            Self::Arbitrum(inspector) => inspector.network_fingerprint().await,
            Self::Avalanche(inspector) => inspector.network_fingerprint().await,
            Self::Base(inspector) => inspector.network_fingerprint().await,
            Self::Bnb(inspector) => inspector.network_fingerprint().await,
            Self::HyperEvm(inspector) => inspector.network_fingerprint().await,
            Self::Polygon(inspector) => inspector.network_fingerprint().await,
            Self::Bitcoin(inspector) => inspector.network_fingerprint().await,
            Self::Aptos(inspector) => inspector.network_fingerprint().await,
            Self::Sui(inspector) => inspector.network_fingerprint().await,
        }
    }

    fn canonical_fingerprint(&self, fingerprint: &str) -> NetworkFingerprint {
        match self {
            Self::Starknet(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Abstract(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Adi(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Arbitrum(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Avalanche(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Base(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Bnb(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::HyperEvm(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Polygon(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Bitcoin(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Aptos(inspector) => inspector.canonical_fingerprint(fingerprint),
            Self::Sui(inspector) => inspector.canonical_fingerprint(fingerprint),
        }
    }
}

/// Build the inspector that asks a provider's real RPC endpoint for its network fingerprint.
///
/// This is the production argument to [`probe_all_providers`].
pub fn rpc_inspector(
    chain: ForeignChain,
    chain_config: &ForeignChainConfig,
    provider: &ForeignChainProviderConfig,
) -> anyhow::Result<RpcInspector> {
    let Some(new_inspector) = new_rpc_inspector(chain) else {
        anyhow::bail!("no probe exists for {chain:?}");
    };
    new_inspector(chain_config, provider)
}

async fn probe_chain<I>(
    chain: ForeignChain,
    config: &ForeignChainConfig,
    new_inspector: impl Fn(&ForeignChainProviderConfig) -> anyhow::Result<I>,
) -> Vec<ProviderHealth>
where
    I: NetworkFingerprintInspector + Clone + Send + Sync + 'static,
{
    let Some(expected) = &config.expected_network_fingerprint else {
        return rows_of(chain, config, ProviderStatus::MissingExpectedFingerprint);
    };

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
    // Every provider of a chain normalizes alike, so any one of them speaks for the chain.
    let expected = inspectors.first().1.canonical_fingerprint(expected);

    let fingerprints = FanOut::new(inspectors)
        .network_fingerprints(timeout_of(config), config.max_retries)
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
    use super::*;
    use assert_matches::assert_matches;
    use foreign_chain_inspector::mock::{ScriptedInspector, ScriptedReply};
    use foreign_chain_inspector::{
        abstract_chain, adi, aptos, arbitrum, avalanche, base, bitcoin, bnb, hyperevm, polygon,
        starknet, sui,
    };
    use foreign_chain_rpc_interfaces::sui::Status;
    use foreign_chain_rpc_interfaces::sui::proto::ledger_service_server::{
        LedgerService, LedgerServiceServer,
    };
    use foreign_chain_rpc_interfaces::sui::proto::{GetServiceInfoRequest, GetServiceInfoResponse};
    use mpc_node_config::{AuthConfig, TokenConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use rstest::rstest;
    use std::num::NonZeroU64;
    use std::time::Duration;

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
    const EVM_MAINNETS: [EvmMainnet; 8] = [
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

    fn must_put_chain(
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

    async fn mock_bad_api_key(server: &httpmock::MockServer) -> httpmock::Mock<'_> {
        mock_error_object(server, 401, -32600, "Must be authenticated!").await
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

    // The scripted tests below run under a paused tokio clock; see `foreign_chain_inspector::mock`
    // for why that must never be combined with the httpmock or tonic tests in this module.

    type NewScripted = Box<
        dyn Fn(
                ForeignChain,
                &ForeignChainConfig,
                &ForeignChainProviderConfig,
            ) -> anyhow::Result<ScriptedInspector>
            + Sync,
    >;

    /// A `new_inspector` for scripted tests: each provider gets the inspector scripted for its
    /// URL, and a provider without one fails its setup.
    fn scripted_by_url(inspectors: BTreeMap<String, ScriptedInspector>) -> NewScripted {
        Box::new(move |_, _, provider| {
            inspectors
                .get(&provider.rpc_url)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no inspector scripted for `{}`", provider.rpc_url))
        })
    }

    fn scripted_one(url: &str, inspector: &ScriptedInspector) -> NewScripted {
        scripted_by_url(BTreeMap::from([(url.to_string(), inspector.clone())]))
    }

    fn never_built(
        _: ForeignChain,
        _: &ForeignChainConfig,
        _: &ForeignChainProviderConfig,
    ) -> anyhow::Result<ScriptedInspector> {
        unreachable!("no inspector may be built for a chain that cannot be probed")
    }

    #[tokio::test(start_paused = true)]
    async fn probe_all_providers__should_report_a_provider_that_never_answers_as_timed_out_without_waiting()
     {
        // Given
        let hung = ScriptedInspector::new([ScriptedReply::Hang]);
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("hung", "scripted://hung"),
        ));
        let started = tokio::time::Instant::now();

        // When
        let report = probe_all_providers(&config, scripted_one("scripted://hung", &hung)).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "hung"),
            ProviderStatus::TimedOut
        );
        // The hang can end only by the configured 1s per try timeout.
        assert_eq!(started.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn probe_all_providers__should_report_a_provider_as_unreachable_after_its_last_retry() {
        // Given
        let failing = ScriptedInspector::new([
            ScriptedReply::TransientFailure {
                delay: Duration::ZERO,
            },
            ScriptedReply::TransientFailure {
                delay: Duration::ZERO,
            },
        ]);
        let config = starknet_only(with_retries(
            chain_config(Some(MAINNET), one_provider("failing", "scripted://failing")),
            2,
        ));

        // When
        let report =
            probe_all_providers(&config, scripted_one("scripted://failing", &failing)).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "failing"),
            ProviderStatus::Unreachable
        );
        assert_eq!(failing.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn probe_all_providers__should_retry_a_transient_failure_and_report_the_later_answer() {
        // Given
        let flaky = ScriptedInspector::new([
            ScriptedReply::TransientFailure {
                delay: Duration::ZERO,
            },
            ScriptedReply::Answer {
                delay: Duration::ZERO,
                fingerprint: MAINNET.to_string(),
            },
        ]);
        let config = starknet_only(with_retries(
            chain_config(Some(MAINNET), one_provider("flaky", "scripted://flaky")),
            2,
        ));

        // When
        let report = probe_all_providers(&config, scripted_one("scripted://flaky", &flaky)).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "flaky"),
            ProviderStatus::Healthy
        );
        assert_eq!(flaky.calls(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn probe_all_providers__should_report_setup_failures_next_to_probed_providers() {
        // Given
        // No inspector is scripted for `unbuildable`, so its setup fails.
        let probed = ScriptedInspector::new([ScriptedReply::Answer {
            delay: Duration::ZERO,
            fingerprint: MAINNET.to_string(),
        }]);
        let mut providers = one_provider("probed", "scripted://probed");
        providers.insert(
            "unbuildable".to_string().into(),
            provider("scripted://unbuildable"),
        );
        let config = starknet_only(chain_config(Some(MAINNET), providers));

        // When
        let report = probe_all_providers(&config, scripted_one("scripted://probed", &probed)).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "probed"),
            ProviderStatus::Healthy
        );
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "unbuildable"),
            ProviderStatus::ClientSetupFailed
        );
    }

    #[tokio::test(start_paused = true)]
    async fn probe_all_providers__should_build_no_inspector_without_an_expected_fingerprint() {
        // Given
        let config = starknet_only(chain_config(
            None,
            one_provider("unchecked", "scripted://unchecked"),
        ));

        // When
        let report = probe_all_providers(&config, never_built).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "unchecked"),
            ProviderStatus::MissingExpectedFingerprint
        );
    }

    /// The probe of an unprobeable chain is reported as not implemented even when the chain also
    /// has no expected fingerprint; the fingerprint check applies only to probeable chains.
    #[tokio::test(start_paused = true)]
    async fn probe_all_providers__should_report_an_unprobeable_chain_without_a_fingerprint_as_not_implemented()
     {
        // Given
        let config = solana_only(chain_config(
            None,
            one_provider("unchecked", "scripted://unchecked"),
        ));

        // When
        let report = probe_all_providers(&config, never_built).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Solana, "unchecked"),
            ProviderStatus::ProbeNotImplemented
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_a_provider_on_the_expected_network_as_healthy() {
        // Given
        let server = httpmock::MockServer::start_async().await;
        let mock = mock_fingerprint(&server, MAINNET).await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config, rpc_inspector).await;

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
        mock_fingerprint(&server, SEPOLIA).await;
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", &server.base_url()),
        ));

        // When
        let report = probe_all_providers(&config, rpc_inspector).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "publicnode"),
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
        let report = probe_all_providers(&config, rpc_inspector).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::Healthy
        );
    }

    #[tokio::test]
    async fn probe_all_providers__should_report_an_unreachable_provider() {
        // Given
        let config = starknet_only(chain_config(
            Some(MAINNET),
            one_provider("publicnode", CLOSED_PORT_URL),
        ));

        // When
        let report = probe_all_providers(&config, rpc_inspector).await;

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
        let report = probe_all_providers(&config, rpc_inspector).await;

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
        let report = probe_all_providers(&config, rpc_inspector).await;

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
        let report = probe_all_providers(&config, rpc_inspector).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::MalformedResponse
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
        let report = probe_all_providers(&config, rpc_inspector).await;

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
        let report = probe_all_providers(&config, rpc_inspector).await;

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
        let report = probe_all_providers(&config, rpc_inspector).await;

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
        mock_fingerprint(&server, MAINNET).await;
        let mut providers = one_provider("healthy", &server.base_url());
        providers.insert("broken".to_string().into(), provider(CLOSED_PORT_URL));
        let config = starknet_only(chain_config(Some(MAINNET), providers));

        // When
        let report = probe_all_providers(&config, rpc_inspector).await;

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
        let config = solana_only(chain_config(
            Some(ANY_FINGERPRINT),
            one_provider("publicnode", CLOSED_PORT_URL),
        ));

        // When
        let report = probe_all_providers(&config, rpc_inspector).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Solana, "publicnode"),
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
        let report = probe_all_providers(&config, rpc_inspector).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Starknet, "publicnode"),
            ProviderStatus::Healthy
        );
        assert_eq!(
            must_status_of(&report, ForeignChain::Solana, "publicnode"),
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
            must_put_chain(
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
        let report = probe_all_providers(&config, rpc_inspector).await;

        // Then
        for EvmMainnet { chain, .. } in EVM_MAINNETS {
            assert_eq!(
                must_status_of(&report, chain, "publicnode"),
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
        must_put_chain(
            &mut config,
            ForeignChain::Base,
            chain_config(Some("8453"), one_provider("publicnode", &server.base_url())),
        );

        // When
        let report = probe_all_providers(&config, rpc_inspector).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Base, "publicnode"),
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
        let report = probe_all_providers(&config, rpc_inspector).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Bitcoin, "publicnode"),
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
        let report = probe_all_providers(&config, rpc_inspector).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Bitcoin, "publicnode"),
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
        let report = probe_all_providers(&config, rpc_inspector).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Aptos, PROVIDER_NAME),
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
        let report = probe_all_providers(&config, rpc_inspector).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Aptos, PROVIDER_NAME),
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
        let report = probe_all_providers(&config, rpc_inspector).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Sui, PROVIDER_NAME),
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
        let report = probe_all_providers(&config, rpc_inspector).await;

        // Then
        assert_eq!(
            must_status_of(&report, ForeignChain::Sui, PROVIDER_NAME),
            ProviderStatus::Unreachable
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
        let report = probe_all_providers(&config, rpc_inspector).await;

        // Then
        let ProviderStatus::WrongNetwork { observed, .. } =
            must_status_of(&report, ForeignChain::Starknet, "publicnode")
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
        let report = probe_all_providers(&config, rpc_inspector).await;

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
        let report = probe_all_providers(&config, rpc_inspector).await;

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
