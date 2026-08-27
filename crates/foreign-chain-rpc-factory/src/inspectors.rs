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
use foreign_chain_inspector::rpc_inspector::RpcInspector;
use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use foreign_chain_inspector::sui::inspector::SuiInspector;
use mpc_node_config::ForeignChainProviderConfig;
use near_mpc_contract_interface::types::ForeignChain;

use crate::clients::BuildRpcClients;

/// What every inspector this builds must satisfy: probe a provider, and survive being held and
/// shared for as long as the caller keeps it.
pub trait ChainInspector: NetworkFingerprintInspector + Clone + Send + Sync + 'static {}

impl<T: NetworkFingerprintInspector + Clone + Send + Sync + 'static> ChainInspector for T {}

/// One method per inspector shape rather than per chain: the EVM chains differ only in the marker
/// type the caller fixes.
///
/// `timeout` is the provider's configured deadline. The chains reached over JSON-RPC take it in the
/// inspection deadline instead, so their implementations may ignore it.
pub trait BuildInspectors {
    type Evm<Chain: EvmChain + Clone + Send + Sync + 'static>: ChainInspector;
    type Starknet: ChainInspector;
    type Bitcoin: ChainInspector;
    type Aptos: ChainInspector;
    type Sui: ChainInspector;
    /// One type covering every chain, for a caller that holds inspectors of several at once.
    type Any: ChainInspector;

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

    /// The inspector for whichever chain `chain` is, or `None` when none exists to probe it.
    fn any(
        &self,
        chain: ForeignChain,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<Option<Self::Any>>;
}

/// Choosing the clients is enough to settle the inspectors: each is its chain's inspector over the
/// client that reaches it.
impl<Clients: BuildRpcClients> BuildInspectors for Clients {
    type Aptos = AptosInspector<Clients::Aptos>;
    type Bitcoin = BitcoinInspector<Clients::JsonRpc>;
    type Evm<Chain: EvmChain + Clone + Send + Sync + 'static> =
        EvmInspector<Clients::JsonRpc, Chain>;
    type Starknet = StarknetInspector<Clients::JsonRpc>;
    type Any = RpcInspector<Clients::JsonRpc, Clients::Aptos, Clients::Sui>;
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

    fn any(
        &self,
        chain: ForeignChain,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<Option<Self::Any>> {
        Ok(Some(match chain {
            ForeignChain::Abstract => RpcInspector::Abstract(self.evm(provider, timeout)?),
            ForeignChain::Adi => RpcInspector::Adi(self.evm(provider, timeout)?),
            ForeignChain::Aptos => {
                RpcInspector::Aptos(BuildInspectors::aptos(self, provider, timeout)?)
            }
            ForeignChain::Arbitrum => RpcInspector::Arbitrum(self.evm(provider, timeout)?),
            ForeignChain::Avalanche => RpcInspector::Avalanche(self.evm(provider, timeout)?),
            ForeignChain::Base => RpcInspector::Base(self.evm(provider, timeout)?),
            ForeignChain::Bitcoin => RpcInspector::Bitcoin(self.bitcoin(provider, timeout)?),
            ForeignChain::Bnb => RpcInspector::Bnb(self.evm(provider, timeout)?),
            ForeignChain::Ethereum => RpcInspector::Ethereum(self.evm(provider, timeout)?),
            ForeignChain::HyperEvm => RpcInspector::HyperEvm(self.evm(provider, timeout)?),
            ForeignChain::Polygon => RpcInspector::Polygon(self.evm(provider, timeout)?),
            ForeignChain::Starknet => RpcInspector::Starknet(self.starknet(provider, timeout)?),
            ForeignChain::Sui => RpcInspector::Sui(BuildInspectors::sui(self, provider, timeout)?),
            // Solana, Ton and Fogo have no inspector to probe them with.
            _ => return Ok(None),
        }))
    }
}
