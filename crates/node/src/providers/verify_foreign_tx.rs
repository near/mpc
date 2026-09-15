mod sign;

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
use foreign_chain_inspector::svm::inspector::{FogoInspector, SolanaInspector};
use foreign_chain_rpc_factory::{build_http_client, resolve_provider_auth};
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use foreign_chain_rpc_interfaces::sui::GrpcSuiClient;
use mpc_node_config::{
    ConfigFile, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
};
use mpc_primitives::ReconstructionThreshold;
use near_mpc_contract_interface::types::ProviderId;
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
    pub solana: Option<FanOut<SolanaInspector<Client>>>,
    pub fogo: Option<FanOut<FogoInspector<Client>>>,
}

impl ForeignChainInspectors<HttpClient> {
    fn build(config: &ForeignChainsConfig) -> anyhow::Result<Self> {
        fn build_fanout<I>(
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
            Ok(Some(FanOut::new(inspectors)))
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
                config.bitcoin.as_ref(),
                with_http_client(BitcoinInspector::new),
            )?,
            ethereum: build_fanout(
                config.ethereum.as_ref(),
                with_http_client(EthereumInspector::new),
            )?,
            abstract_chain: build_fanout(
                config.abstract_chain.as_ref(),
                with_http_client(AbstractInspector::new),
            )?,
            base: build_fanout(config.base.as_ref(), with_http_client(BaseInspector::new))?,
            bnb: build_fanout(config.bnb.as_ref(), with_http_client(BnbInspector::new))?,
            starknet: build_fanout(
                config.starknet.as_ref(),
                with_http_client(StarknetInspector::new),
            )?,
            arbitrum: build_fanout(
                config.arbitrum.as_ref(),
                with_http_client(ArbitrumInspector::new),
            )?,
            hyper_evm: build_fanout(
                config.hyper_evm.as_ref(),
                with_http_client(HyperEvmInspector::new),
            )?,
            polygon: build_fanout(
                config.polygon.as_ref(),
                with_http_client(PolygonInspector::new),
            )?,
            avalanche: build_fanout(
                config.avalanche.as_ref(),
                with_http_client(AvalancheInspector::new),
            )?,
            adi: build_fanout(config.adi.as_ref(), with_http_client(AdiInspector::new))?,
            aptos: build_fanout(config.aptos.as_ref(), new_aptos_inspector)?,
            sui: build_fanout(config.sui.as_ref(), new_sui_inspector)?,
            solana: build_fanout(
                config.solana.as_ref(),
                with_http_client(SolanaInspector::new),
            )?,
            fogo: build_fanout(config.fogo.as_ref(), with_http_client(FogoInspector::new))?,
        })
    }
}

/// The chain markers cannot check which *config* feeds `build` — a
/// `config.solana`/`config.fogo` swap still type-checks — so these tests pin it.
#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use mpc_node_config::{AuthConfig, ForeignChainProviderConfig};
    use near_mpc_bounded_collections::NonEmptyBTreeMap;
    use std::num::NonZeroU64;

    fn chain_config() -> ForeignChainConfig {
        ForeignChainConfig {
            timeout_sec: NonZeroU64::new(30).unwrap(),
            max_retries: NonZeroU64::new(3).unwrap(),
            expected_network_fingerprint: None,
            providers: NonEmptyBTreeMap::new(
                "public".to_string().into(),
                ForeignChainProviderConfig {
                    rpc_url: "https://rpc.example.com".to_string(),
                    auth: AuthConfig::None,
                },
            ),
        }
    }

    #[test]
    fn build__should_wire_the_solana_config_to_the_solana_slot_only() {
        // Given
        let config = ForeignChainsConfig {
            solana: Some(chain_config()),
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
            fogo: Some(chain_config()),
            ..Default::default()
        };

        // When
        let inspectors = ForeignChainInspectors::build(&config).unwrap();

        // Then
        assert!(inspectors.fogo.is_some());
        assert!(inspectors.solana.is_none());
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
