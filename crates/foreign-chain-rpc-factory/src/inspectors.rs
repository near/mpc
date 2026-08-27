//! Building a chain's inspector for one of its providers, over whichever clients the caller
//! injects.

use std::time::Duration;

use foreign_chain_inspector::aptos::inspector::AptosInspector;
use foreign_chain_inspector::bitcoin::inspector::BitcoinInspector;
use foreign_chain_inspector::evm::inspector::{EvmChain, EvmInspector};
use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use foreign_chain_inspector::sui::inspector::SuiInspector;
use mpc_node_config::ForeignChainProviderConfig;

use crate::clients::BuildRpcClients;

/// The EVM chains differ only in their marker type, which the caller fixes.
pub fn evm_inspector<Clients: BuildRpcClients, Chain: EvmChain>(
    clients: &Clients,
    provider: &ForeignChainProviderConfig,
) -> anyhow::Result<EvmInspector<Clients::JsonRpc, Chain>> {
    Ok(EvmInspector::new(clients.json_rpc(provider)?))
}

pub fn starknet_inspector<Clients: BuildRpcClients>(
    clients: &Clients,
    provider: &ForeignChainProviderConfig,
) -> anyhow::Result<StarknetInspector<Clients::JsonRpc>> {
    Ok(StarknetInspector::new(clients.json_rpc(provider)?))
}

pub fn bitcoin_inspector<Clients: BuildRpcClients>(
    clients: &Clients,
    provider: &ForeignChainProviderConfig,
) -> anyhow::Result<BitcoinInspector<Clients::JsonRpc>> {
    Ok(BitcoinInspector::new(clients.json_rpc(provider)?))
}

pub fn aptos_inspector<Clients: BuildRpcClients>(
    clients: &Clients,
    provider: &ForeignChainProviderConfig,
    timeout: Duration,
) -> anyhow::Result<AptosInspector<Clients::Aptos>> {
    Ok(AptosInspector::new(clients.aptos(provider, timeout)?))
}

pub fn sui_inspector<Clients: BuildRpcClients>(
    clients: &Clients,
    provider: &ForeignChainProviderConfig,
    timeout: Duration,
) -> anyhow::Result<SuiInspector<Clients::Sui>> {
    Ok(SuiInspector::new(clients.sui(provider, timeout)?))
}
