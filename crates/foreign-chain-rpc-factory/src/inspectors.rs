//! Building a chain's inspector for one of its providers.
//!
//! Injecting [`BuildInspectors`] settles which inspectors a caller gets. [`InspectorFactory`] is
//! the one that builds real inspectors, and is itself injected with the clients to build them
//! over; a caller that needs to answer for the inspectors themselves, a test most of all,
//! implements [`BuildInspectors`] on its own type and builds no client at all.

use std::time::Duration;

use foreign_chain_inspector::ChainInspector;
use foreign_chain_inspector::aptos::inspector::AptosInspector;
use foreign_chain_inspector::bitcoin::inspector::BitcoinInspector;
use foreign_chain_inspector::evm::inspector::EvmInspector;
use foreign_chain_inspector::rpc_inspector::RpcInspector;
use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use foreign_chain_inspector::sui::inspector::SuiInspector;
use mpc_node_config::ForeignChainProviderConfig;
use near_mpc_contract_interface::types::ForeignChain;

use crate::clients::BuildRpcClients;

/// `Sync` because a caller that probes several chains at once shares one factory across them.
pub trait BuildInspectors: Sync {
    /// One type covering every chain, so a caller that spans them can hold their inspectors
    /// together.
    type Inspector: ChainInspector;

    /// The inspector for whichever chain `chain` is, or `None` when none exists to probe it.
    ///
    /// `timeout` is the provider's configured deadline. The chains reached over JSON-RPC take it in
    /// the inspection deadline instead, so an implementation may ignore it for those.
    fn build(
        &self,
        chain: ForeignChain,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<Option<Self::Inspector>>;
}

/// Builds each chain's inspector over the client that reaches it, whichever clients it was given.
pub struct InspectorFactory<Clients> {
    clients: Clients,
}

impl<Clients> InspectorFactory<Clients> {
    pub fn new(clients: Clients) -> Self {
        Self { clients }
    }
}

impl<Clients: BuildRpcClients + Sync> BuildInspectors for InspectorFactory<Clients> {
    type Inspector = RpcInspector<Clients::JsonRpc, Clients::Aptos, Clients::Sui>;

    fn build(
        &self,
        chain: ForeignChain,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<Option<Self::Inspector>> {
        Ok(Some(match chain {
            ForeignChain::Abstract => {
                RpcInspector::Abstract(EvmInspector::new(self.clients.json_rpc(provider, timeout)?))
            }
            ForeignChain::Adi => {
                RpcInspector::Adi(EvmInspector::new(self.clients.json_rpc(provider, timeout)?))
            }
            ForeignChain::Aptos => {
                RpcInspector::Aptos(AptosInspector::new(self.clients.aptos(provider, timeout)?))
            }
            ForeignChain::Arbitrum => {
                RpcInspector::Arbitrum(EvmInspector::new(self.clients.json_rpc(provider, timeout)?))
            }
            ForeignChain::Avalanche => RpcInspector::Avalanche(EvmInspector::new(
                self.clients.json_rpc(provider, timeout)?,
            )),
            ForeignChain::Base => {
                RpcInspector::Base(EvmInspector::new(self.clients.json_rpc(provider, timeout)?))
            }
            ForeignChain::Bitcoin => RpcInspector::Bitcoin(BitcoinInspector::new(
                self.clients.json_rpc(provider, timeout)?,
            )),
            ForeignChain::Bnb => {
                RpcInspector::Bnb(EvmInspector::new(self.clients.json_rpc(provider, timeout)?))
            }
            ForeignChain::Ethereum => {
                RpcInspector::Ethereum(EvmInspector::new(self.clients.json_rpc(provider, timeout)?))
            }
            ForeignChain::HyperEvm => {
                RpcInspector::HyperEvm(EvmInspector::new(self.clients.json_rpc(provider, timeout)?))
            }
            ForeignChain::Polygon => {
                RpcInspector::Polygon(EvmInspector::new(self.clients.json_rpc(provider, timeout)?))
            }
            ForeignChain::Starknet => RpcInspector::Starknet(StarknetInspector::new(
                self.clients.json_rpc(provider, timeout)?,
            )),
            ForeignChain::Sui => {
                RpcInspector::Sui(SuiInspector::new(self.clients.sui(provider, timeout)?))
            }
            // No inspector exists for other chains.
            _ => return Ok(None),
        }))
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::num::NonZeroU64;

    use mpc_node_config::{
        AuthConfig, ForeignChainConfig, ForeignChainProviderConfig, ForeignChainsConfig,
    };
    use near_mpc_bounded_collections::NonEmptyBTreeMap;

    use super::*;
    use crate::clients::RpcClientFactory;

    /// Every chain a config can hold is set, so a chain added later has to be listed here too, and
    /// whoever adds it has to say whether an inspector covers it.
    fn every_configurable_chain() -> ForeignChainsConfig {
        let section = || {
            Some(ForeignChainConfig {
                timeout_sec: NonZeroU64::new(1).unwrap(),
                max_retries: NonZeroU64::new(1).unwrap(),
                expected_network_fingerprint: None,
                providers: NonEmptyBTreeMap::new(
                    "only".to_string().into(),
                    ForeignChainProviderConfig {
                        rpc_url: "http://127.0.0.1:9".to_string(),
                        auth: AuthConfig::None,
                    },
                ),
            })
        };
        ForeignChainsConfig {
            solana: section(),
            bitcoin: section(),
            ethereum: section(),
            abstract_chain: section(),
            starknet: section(),
            bnb: section(),
            base: section(),
            arbitrum: section(),
            hyper_evm: section(),
            polygon: section(),
            aptos: section(),
            sui: section(),
            avalanche: section(),
            adi: section(),
        }
    }

    // The Sui client is built on a gRPC channel, which needs a reactor to exist.
    #[tokio::test]
    async fn build__should_cover_every_configurable_chain_that_has_an_inspector() {
        // Given
        let config = every_configurable_chain();
        let factory = InspectorFactory::new(RpcClientFactory);

        // When
        let uncovered: Vec<_> = config
            .iter_chains()
            .filter(|(chain, chain_config)| {
                let provider = chain_config.providers.iter().next().expect("a provider").1;
                factory
                    .build(*chain, provider, Duration::from_secs(1))
                    .expect("the provider is well formed")
                    .is_none()
            })
            .map(|(chain, _)| chain)
            .collect();

        // Then
        assert_eq!(uncovered, vec![ForeignChain::Solana]);
    }
}
