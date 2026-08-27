//! Building a chain's inspector for one of its providers.
//!
//! Injecting [`BuildInspectors`] settles which inspectors a caller gets. Anything that builds
//! clients gets the real ones for free, through the blanket implementation over
//! [`BuildRpcClients`]; a caller that needs to answer for the inspectors themselves, a test most of
//! all, implements this instead and never builds a client at all.

use std::time::Duration;

use foreign_chain_inspector::NetworkFingerprintInspector;
use foreign_chain_inspector::aptos::inspector::AptosInspector;
use foreign_chain_inspector::bitcoin::inspector::BitcoinInspector;
use foreign_chain_inspector::evm::inspector::{EvmChain, EvmInspector};
use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use foreign_chain_inspector::sui::inspector::SuiInspector;
use mpc_node_config::ForeignChainProviderConfig;

use crate::clients::BuildRpcClients;

/// One method per inspector shape rather than per chain: the EVM chains differ only in the marker
/// type the caller fixes.
///
/// `timeout` is the provider's configured deadline. The chains reached over JSON-RPC take it in the
/// inspection deadline instead, so their implementations may ignore it.
pub trait BuildInspectors {
    type Evm<Chain: EvmChain + Clone + Send + Sync + 'static>: NetworkFingerprintInspector
        + Clone
        + Send
        + Sync
        + 'static;
    type Starknet: NetworkFingerprintInspector + Clone + Send + Sync + 'static;
    type Bitcoin: NetworkFingerprintInspector + Clone + Send + Sync + 'static;
    type Aptos: NetworkFingerprintInspector + Clone + Send + Sync + 'static;
    type Sui: NetworkFingerprintInspector + Clone + Send + Sync + 'static;

    fn evm<Chain: EvmChain + Clone + Send + Sync + 'static>(
        &self,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<Self::Evm<Chain>>;

    fn starknet(
        &self,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<Self::Starknet>;

    fn bitcoin(
        &self,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<Self::Bitcoin>;

    fn aptos(
        &self,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<Self::Aptos>;

    fn sui(
        &self,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<Self::Sui>;
}

/// Choosing the clients is enough to settle the inspectors: each is its chain's inspector over the
/// client that reaches it.
impl<Clients: BuildRpcClients> BuildInspectors for Clients {
    type Aptos = AptosInspector<Clients::Aptos>;
    type Bitcoin = BitcoinInspector<Clients::JsonRpc>;
    type Evm<Chain: EvmChain + Clone + Send + Sync + 'static> =
        EvmInspector<Clients::JsonRpc, Chain>;
    type Starknet = StarknetInspector<Clients::JsonRpc>;
    type Sui = SuiInspector<Clients::Sui>;

    fn evm<Chain: EvmChain + Clone + Send + Sync + 'static>(
        &self,
        provider: &ForeignChainProviderConfig,
        _timeout: Duration,
    ) -> anyhow::Result<Self::Evm<Chain>> {
        Ok(EvmInspector::new(self.json_rpc(provider)?))
    }

    fn starknet(
        &self,
        provider: &ForeignChainProviderConfig,
        _timeout: Duration,
    ) -> anyhow::Result<Self::Starknet> {
        Ok(StarknetInspector::new(self.json_rpc(provider)?))
    }

    fn bitcoin(
        &self,
        provider: &ForeignChainProviderConfig,
        _timeout: Duration,
    ) -> anyhow::Result<Self::Bitcoin> {
        Ok(BitcoinInspector::new(self.json_rpc(provider)?))
    }

    fn aptos(
        &self,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<Self::Aptos> {
        Ok(AptosInspector::new(BuildRpcClients::aptos(
            self, provider, timeout,
        )?))
    }

    fn sui(
        &self,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<Self::Sui> {
        Ok(SuiInspector::new(BuildRpcClients::sui(
            self, provider, timeout,
        )?))
    }
}
