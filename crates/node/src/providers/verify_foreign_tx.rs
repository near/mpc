mod provider_call_metrics;
mod sign;

pub(crate) use sign::FOREIGN_CHAIN_INSPECTION_TIMEOUT;

use crate::foreign_chain_policy::{ForeignChainLeadersRefiner, SupportersByForeignChain};
use crate::network::NetworkTaskChannel;
use crate::primitives::{MpcTaskId, UniqueId};
use crate::providers::EcdsaSignatureProvider;
use crate::storage::VerifyForeignTransactionRequestStorage;
use crate::types::VerifyForeignTxId;
use borsh::{BorshDeserialize, BorshSerialize};
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
use foreign_chain_rpc_factory::{build_http_client, resolve_provider_auth};
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use foreign_chain_rpc_interfaces::sui::GrpcSuiClient;
use mpc_node_config::{
    ConfigFile, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
};
use mpc_primitives::ReconstructionThreshold;
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
    pub bitcoin: Option<FanOut<BitcoinInspector<Client>>>,
    pub ethereum: Option<FanOut<EthereumInspector<Client>>>,
    pub abstract_chain: Option<FanOut<AbstractInspector<Client>>>,
    pub bnb: Option<FanOut<BnbInspector<Client>>>,
    pub starknet: Option<FanOut<StarknetInspector<Client>>>,
    pub base: Option<FanOut<BaseInspector<Client>>>,
    pub arbitrum: Option<FanOut<ArbitrumInspector<Client>>>,
    pub hyper_evm: Option<FanOut<HyperEvmInspector<Client>>>,
    pub polygon: Option<FanOut<PolygonInspector<Client>>>,
    pub avalanche: Option<FanOut<AvalancheInspector<Client>>>,
    pub adi: Option<FanOut<AdiInspector<Client>>>,
    pub aptos: Option<FanOut<AptosInspector<ReqwestAptosClient>>>,
    pub sui: Option<FanOut<SuiInspector<GrpcSuiClient>>>,
}

impl ForeignChainInspectors<HttpClient> {
    fn build(config: &ForeignChainsConfig) -> anyhow::Result<Self> {
        fn build_fanout<I>(
            chain: ForeignChain,
            chain_config: Option<&ForeignChainConfig>,
            new_inspector: impl Fn(&ForeignChainProviderConfig, Duration) -> anyhow::Result<I>,
        ) -> anyhow::Result<Option<FanOut<I>>> {
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
            Ok(Some(FanOut::new(inspectors).measuring(Arc::new(recorder))))
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
        })
    }
}

pub struct VerifyForeignTxProvider {
    config: Arc<ConfigFile>,
    inspectors: ForeignChainInspectors<HttpClient>,
    supporters_by_foreign_chain: watch::Receiver<SupportersByForeignChain>,
    /// [`foreign_tx_reconstruction_threshold`](crate::foreign_chain_policy::foreign_tx_reconstruction_threshold)
    /// of the running domains; `None` when there is no ForeignTx domain.
    foreign_tx_reconstruction_threshold: Option<ReconstructionThreshold>,
    verify_foreign_tx_request_store: Arc<VerifyForeignTransactionRequestStorage>,
    ecdsa_signature_provider: Arc<EcdsaSignatureProvider>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub enum VerifyForeignTxTaskId {
    VerifyForeignTx {
        id: VerifyForeignTxId,
        presignature_id: UniqueId,
    },
}

impl From<VerifyForeignTxTaskId> for MpcTaskId {
    fn from(val: VerifyForeignTxTaskId) -> Self {
        MpcTaskId::VerifyForeignTxTaskId(val)
    }
}

impl VerifyForeignTxProvider {
    pub fn new(
        config: Arc<ConfigFile>,
        supporters_by_foreign_chain: watch::Receiver<SupportersByForeignChain>,
        foreign_tx_reconstruction_threshold: Option<ReconstructionThreshold>,
        verify_foreign_tx_request_store: Arc<VerifyForeignTransactionRequestStorage>,
        ecdsa_signature_provider: Arc<EcdsaSignatureProvider>,
    ) -> anyhow::Result<Self> {
        let inspectors = ForeignChainInspectors::build(&config.foreign_chains)?;
        Ok(Self {
            config,
            inspectors,
            supporters_by_foreign_chain,
            foreign_tx_reconstruction_threshold,
            verify_foreign_tx_request_store,
            ecdsa_signature_provider,
        })
    }

    pub(crate) fn new_eligible_leaders_refiner(&self) -> ForeignChainLeadersRefiner {
        ForeignChainLeadersRefiner::new(
            self.supporters_by_foreign_chain.clone(),
            self.foreign_tx_reconstruction_threshold,
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

    fn provider_of(chain: ForeignChain) -> String {
        format!("{}-wiring", chain.label())
    }

    fn chain_config(chain: ForeignChain) -> Option<ForeignChainConfig> {
        Some(ForeignChainConfig {
            timeout_sec: NonZeroU64::new(1).unwrap(),
            max_retries: NonZeroU64::new(1).unwrap(),
            expected_network_fingerprint: None,
            providers: NonEmptyBTreeMap::new(
                RpcProviderName::from(provider_of(chain)),
                ForeignChainProviderConfig {
                    rpc_url: "http://127.0.0.1:1/".to_string(),
                    auth: AuthConfig::None,
                },
            ),
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
    async fn foreign_chain_inspectors_build__should_label_each_chain_by_its_own_config_key() {
        // Given
        let config = ForeignChainsConfig {
            solana: None,
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
        };

        // When
        ForeignChainInspectors::build(&config).unwrap();

        // Then
        let published = published_inspection_series();
        for chain in [
            Bitcoin, Ethereum, Abstract, Starknet, Bnb, Base, Arbitrum, HyperEvm, Polygon, Aptos,
            Sui, Avalanche, Adi,
        ] {
            let series = (chain.label().to_string(), provider_of(chain));
            assert!(published.contains(&series), "{series:?} was not published");
        }
    }
}
