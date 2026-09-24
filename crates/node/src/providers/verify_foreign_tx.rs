mod provider_call_metrics;
mod sign;

pub(crate) use sign::FOREIGN_CHAIN_INSPECTION_TIMEOUT;

use crate::foreign_chain_policy::{ForeignChainLeadersRefiner, SupportersByForeignChain};
use crate::network::NetworkTaskChannel;
use crate::network::wire_format::{MpcTaskId, VerifyForeignTxTaskId};
use crate::providers::EcdsaSignatureProvider;
use crate::storage::VerifyForeignTransactionRequestStorage;
use foreign_chain_inspector::FanOut;
use foreign_chain_inspector::abstract_chain::inspector::AbstractInspector;
use foreign_chain_inspector::adi::inspector::AdiInspector;
use foreign_chain_inspector::aptos::inspector::AptosInspector;
use foreign_chain_inspector::arbitrum::inspector::ArbitrumInspector;
use foreign_chain_inspector::avalanche::inspector::AvalancheInspector;
use foreign_chain_inspector::base::inspector::BaseInspector;
use foreign_chain_inspector::bitcoin::inspector::BitcoinInspector;
use foreign_chain_inspector::bnb::inspector::BnbInspector;
use foreign_chain_inspector::ethereum::inspector::EthereumInspector;
use foreign_chain_inspector::http_client::HttpClient;
use foreign_chain_inspector::hyperevm::inspector::HyperEvmInspector;
use foreign_chain_inspector::polygon::inspector::PolygonInspector;
use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use foreign_chain_inspector::sui::inspector::SuiInspector;
use foreign_chain_inspector::svm::inspector::{FogoInspector, SolanaInspector};
use foreign_chain_rpc_factory::{build_http_client, resolve_provider_auth};
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use foreign_chain_rpc_interfaces::sui::GrpcSuiClient;
use mpc_node_config::{
    ConfigFile, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
};
use near_mpc_contract_interface::types::{ForeignChain, ProviderId};
use provider_call_metrics::ProviderCallMetrics;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// Pre-built HTTP clients for each foreign chain, one per configured provider and named by its
/// [`ProviderId`].
///
/// Built once at startup so that request handling fans out over ready clients instead of re-parsing
/// config and constructing them on every call.
pub(crate) struct ForeignChainInspectors<Client> {
    pub bitcoin: Option<MeasuredFanOut<BitcoinInspector<Client>>>,
    pub ethereum: Option<MeasuredFanOut<EthereumInspector<Client>>>,
    pub abstract_chain: Option<MeasuredFanOut<AbstractInspector<Client>>>,
    pub bnb: Option<MeasuredFanOut<BnbInspector<Client>>>,
    pub starknet: Option<MeasuredFanOut<StarknetInspector<Client>>>,
    pub base: Option<MeasuredFanOut<BaseInspector<Client>>>,
    pub arbitrum: Option<MeasuredFanOut<ArbitrumInspector<Client>>>,
    pub hyper_evm: Option<MeasuredFanOut<HyperEvmInspector<Client>>>,
    pub polygon: Option<MeasuredFanOut<PolygonInspector<Client>>>,
    pub avalanche: Option<MeasuredFanOut<AvalancheInspector<Client>>>,
    pub adi: Option<MeasuredFanOut<AdiInspector<Client>>>,
    pub aptos: Option<MeasuredFanOut<AptosInspector<ReqwestAptosClient>>>,
    pub sui: Option<MeasuredFanOut<SuiInspector<GrpcSuiClient>>>,
    pub solana: Option<MeasuredFanOut<SolanaInspector<Client>>>,
    pub fogo: Option<MeasuredFanOut<FogoInspector<Client>>>,
}

/// A [`FanOut`] whose provider calls are reported to the node's Prometheus metrics.
pub(crate) type MeasuredFanOut<Inspector> = FanOut<Inspector, ProviderCallMetrics>;

impl ForeignChainInspectors<HttpClient> {
    fn build(config: &ForeignChainsConfig) -> anyhow::Result<Self> {
        fn build_fanout<I>(
            chain: ForeignChain,
            chain_config: Option<&ForeignChainConfig>,
            new_inspector: impl Fn(&ForeignChainProviderConfig, Duration) -> anyhow::Result<I>,
        ) -> anyhow::Result<Option<MeasuredFanOut<I>>> {
            let Some(c) = chain_config else {
                return Ok(None);
            };
            let timeout = Duration::from_secs(c.timeout_sec.get());
            let inspectors = c.providers.try_map_to_vec(|name, p| {
                let inspector = new_inspector(p, timeout)?;
                anyhow::Ok((ProviderId(name.as_str().to_owned()), inspector))
            })?;
            let providers = inspectors.iter().map(|(provider, _)| provider);
            let recorder = ProviderCallMetrics::new(chain, providers);
            Ok(Some(FanOut::new(inspectors).measuring(recorder)))
        }

        /// Adapts an inspector constructor over a jsonrpsee [`HttpClient`] to `build_fanout`'s
        /// closure shape. The timeout is unused: the jsonrpsee chains rely on the inspection
        /// deadline in the signing flow, as they did before this adapter existed.
        fn with_http_client<I>(
            new_inspector: impl Fn(HttpClient) -> I,
        ) -> impl Fn(&ForeignChainProviderConfig, Duration) -> anyhow::Result<I> {
            move |provider, _timeout| {
                let client = build_http_client(provider)?;
                Ok(new_inspector(client))
            }
        }

        fn new_sui_inspector(
            provider: &ForeignChainProviderConfig,
            timeout: Duration,
        ) -> anyhow::Result<SuiInspector<GrpcSuiClient>> {
            let (url, auth_header) = resolve_provider_auth(provider)?;
            let client = GrpcSuiClient::new(url, auth_header, timeout)
                .map_err(|e| anyhow::anyhow!("failed to build the Sui gRPC client: {e}"))?;
            Ok(SuiInspector::new(client))
        }

        fn new_aptos_inspector(
            provider: &ForeignChainProviderConfig,
            timeout: Duration,
        ) -> anyhow::Result<AptosInspector<ReqwestAptosClient>> {
            let (url, auth_header) = resolve_provider_auth(provider)?;
            Ok(AptosInspector::new(ReqwestAptosClient::new(
                url,
                auth_header,
                timeout,
            )))
        }

        Ok(Self {
            bitcoin: build_fanout(
                ForeignChain::Bitcoin,
                config.bitcoin.as_ref(),
                with_http_client(BitcoinInspector::new),
            )?,
            ethereum: build_fanout(
                ForeignChain::Ethereum,
                config.ethereum.as_ref(),
                with_http_client(EthereumInspector::new),
            )?,
            abstract_chain: build_fanout(
                ForeignChain::Abstract,
                config.abstract_chain.as_ref(),
                with_http_client(AbstractInspector::new),
            )?,
            base: build_fanout(
                ForeignChain::Base,
                config.base.as_ref(),
                with_http_client(BaseInspector::new),
            )?,
            bnb: build_fanout(
                ForeignChain::Bnb,
                config.bnb.as_ref(),
                with_http_client(BnbInspector::new),
            )?,
            starknet: build_fanout(
                ForeignChain::Starknet,
                config.starknet.as_ref(),
                with_http_client(StarknetInspector::new),
            )?,
            arbitrum: build_fanout(
                ForeignChain::Arbitrum,
                config.arbitrum.as_ref(),
                with_http_client(ArbitrumInspector::new),
            )?,
            hyper_evm: build_fanout(
                ForeignChain::HyperEvm,
                config.hyper_evm.as_ref(),
                with_http_client(HyperEvmInspector::new),
            )?,
            polygon: build_fanout(
                ForeignChain::Polygon,
                config.polygon.as_ref(),
                with_http_client(PolygonInspector::new),
            )?,
            avalanche: build_fanout(
                ForeignChain::Avalanche,
                config.avalanche.as_ref(),
                with_http_client(AvalancheInspector::new),
            )?,
            adi: build_fanout(
                ForeignChain::Adi,
                config.adi.as_ref(),
                with_http_client(AdiInspector::new),
            )?,
            aptos: build_fanout(
                ForeignChain::Aptos,
                config.aptos.as_ref(),
                new_aptos_inspector,
            )?,
            sui: build_fanout(ForeignChain::Sui, config.sui.as_ref(), new_sui_inspector)?,
            solana: build_fanout(
                ForeignChain::Solana,
                config.solana.as_ref(),
                with_http_client(SolanaInspector::new),
            )?,
            fogo: build_fanout(
                ForeignChain::Fogo,
                config.fogo.as_ref(),
                with_http_client(FogoInspector::new),
            )?,
        })
    }
}

pub struct VerifyForeignTxProvider {
    config: Arc<ConfigFile>,
    inspectors: ForeignChainInspectors<HttpClient>,
    supporters_by_foreign_chain: watch::Receiver<SupportersByForeignChain>,
    /// [`foreign_tx_required_active_signers`](crate::foreign_chain_policy::foreign_tx_required_active_signers)
    /// of the running domains; `None` when there is no ForeignTx domain.
    foreign_tx_required_active_signers: Option<u64>,
    verify_foreign_tx_request_store: Arc<VerifyForeignTransactionRequestStorage>,
    ecdsa_signature_provider: Arc<EcdsaSignatureProvider>,
}

impl VerifyForeignTxProvider {
    pub fn new(
        config: Arc<ConfigFile>,
        supporters_by_foreign_chain: watch::Receiver<SupportersByForeignChain>,
        foreign_tx_required_active_signers: Option<u64>,
        verify_foreign_tx_request_store: Arc<VerifyForeignTransactionRequestStorage>,
        ecdsa_signature_provider: Arc<EcdsaSignatureProvider>,
    ) -> anyhow::Result<Self> {
        let inspectors = ForeignChainInspectors::build(&config.foreign_chains)?;
        Ok(Self {
            config,
            inspectors,
            supporters_by_foreign_chain,
            foreign_tx_required_active_signers,
            verify_foreign_tx_request_store,
            ecdsa_signature_provider,
        })
    }

    pub(crate) fn new_eligible_leaders_refiner(&self) -> ForeignChainLeadersRefiner {
        ForeignChainLeadersRefiner::new(
            self.supporters_by_foreign_chain.clone(),
            self.foreign_tx_required_active_signers,
        )
    }

    pub async fn process_channel(&self, channel: NetworkTaskChannel) -> anyhow::Result<()> {
        match channel.task_id() {
            MpcTaskId::VerifyForeignTxTaskId(task) => match task {
                VerifyForeignTxTaskId::VerifyForeignTx {
                    id,
                    presignature_id,
                } => {
                    self.make_verify_foreign_tx_follower(channel, id, presignature_id)
                        .await?;
                }
            },
            _ => anyhow::bail!(
                "verify_foreign_tx task handler: received unexpected task id: {:?}",
                channel.task_id()
            ),
        }

        Ok(())
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use ForeignChain::*;
    use mpc_node_config::AuthConfig;
    use mpc_node_config::foreign_chains::RpcProviderName;
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use prometheus::core::Collector as _;
    use std::collections::BTreeSet;
    use std::num::NonZeroU64;

    fn provider_names(chain: ForeignChain) -> [String; 2] {
        let label = chain.label();
        [format!("{label}-wiring-a"), format!("{label}-wiring-b")]
    }

    fn provider(name: &str) -> (RpcProviderName, ForeignChainProviderConfig) {
        (
            RpcProviderName::from(name.to_string()),
            ForeignChainProviderConfig {
                rpc_url: "http://127.0.0.1:1/".to_string(),
                auth: AuthConfig::None,
            },
        )
    }

    fn chain_config(chain: ForeignChain) -> Option<ForeignChainConfig> {
        let [a, b] = provider_names(chain);
        let (a_name, a_config) = provider(&a);
        let (b_name, b_config) = provider(&b);
        let mut providers = NonEmptyBTreeMap::new(a_name, a_config);
        providers.insert(b_name, b_config);
        Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(1).unwrap(),
            max_retries: NonZeroU64::new(1).unwrap(),
            expected_network_fingerprint: None,
            providers,
        })
    }

    fn published_inspection_series() -> BTreeSet<(String, String)> {
        crate::metrics::MPC_FOREIGN_CHAIN_PROVIDER_INSPECTION_SECONDS
            .collect()
            .iter()
            .flat_map(|family| family.get_metric())
            .map(|metric| {
                let label = |name: &str| {
                    metric
                        .get_label()
                        .iter()
                        .find(|pair| pair.name() == name)
                        .map(|pair| pair.value().to_string())
                        .unwrap_or_default()
                };
                (label("chain"), label("provider"))
            })
            .collect()
    }

    #[tokio::test]
    async fn foreign_chain_inspectors_build__should_wire_provider_metrics_for_every_configured_chain()
     {
        // Given
        let config = ForeignChainsConfig {
            bitcoin: chain_config(Bitcoin),
            ethereum: chain_config(Ethereum),
            abstract_chain: chain_config(Abstract),
            starknet: chain_config(Starknet),
            bnb: chain_config(Bnb),
            base: chain_config(Base),
            arbitrum: chain_config(Arbitrum),
            hyper_evm: chain_config(HyperEvm),
            polygon: chain_config(Polygon),
            aptos: chain_config(Aptos),
            sui: chain_config(Sui),
            avalanche: chain_config(Avalanche),
            adi: chain_config(Adi),
            solana: chain_config(Solana),
            fogo: chain_config(Fogo),
        };

        // When
        ForeignChainInspectors::build(&config).unwrap();

        // Then
        let published = published_inspection_series();
        for (chain, _) in config.iter_chains() {
            for index in 0..2 {
                let series = (chain.label().to_string(), format!("p{index}"));
                assert!(published.contains(&series), "{series:?} was not published");
            }
        }
    }

    // The chain markers cannot check which *config* feeds `build` — a
    // `config.solana`/`config.fogo` swap still type-checks — so these pin it.
    #[test]
    fn build__should_wire_the_solana_config_to_the_solana_slot_only() {
        // Given
        let config = ForeignChainsConfig {
            solana: chain_config(Solana),
            ..Default::default()
        };

        // When
        let inspectors = ForeignChainInspectors::build(&config).unwrap();

        // Then
        assert!(inspectors.solana.is_some());
        assert!(inspectors.fogo.is_none());
    }

    #[test]
    fn build__should_wire_the_fogo_config_to_the_fogo_slot_only() {
        // Given
        let config = ForeignChainsConfig {
            fogo: chain_config(Fogo),
            ..Default::default()
        };

        // When
        let inspectors = ForeignChainInspectors::build(&config).unwrap();

        // Then
        assert!(inspectors.fogo.is_some());
        assert!(inspectors.solana.is_none());
    }
}
