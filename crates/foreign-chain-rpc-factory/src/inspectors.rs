use std::time::Duration;

use foreign_chain_inspector::BuildInspectors;
use foreign_chain_inspector::aptos::inspector::AptosInspector;
use foreign_chain_inspector::bitcoin::inspector::BitcoinInspector;
use foreign_chain_inspector::evm::inspector::EvmInspector;
use foreign_chain_inspector::rpc_inspector::RpcInspector;
use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use foreign_chain_inspector::sui::inspector::SuiInspector;
use foreign_chain_inspector::svm::inspector::{Fogo, Solana, SvmInspector};
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use foreign_chain_rpc_interfaces::sui::GrpcSuiClient;
use mpc_node_config::ForeignChainProviderConfig;
use near_mpc_contract_interface::types::ForeignChain;

use crate::{build_http_client, resolve_provider_auth};

#[derive(Clone, Copy)]
pub struct InspectorFactory;

impl BuildInspectors for InspectorFactory {
    type Inspector = RpcInspector;

    fn build(
        &self,
        chain: ForeignChain,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<Option<Self::Inspector>> {
        Ok(Some(match chain {
            ForeignChain::Abstract => {
                RpcInspector::Abstract(EvmInspector::new(build_http_client(provider)?))
            }
            ForeignChain::Adi => RpcInspector::Adi(EvmInspector::new(build_http_client(provider)?)),
            ForeignChain::Aptos => {
                let (url, auth_header) = resolve_provider_auth(provider)?;
                RpcInspector::Aptos(AptosInspector::new(ReqwestAptosClient::new(
                    url,
                    auth_header,
                    timeout,
                )))
            }
            ForeignChain::Arbitrum => {
                RpcInspector::Arbitrum(EvmInspector::new(build_http_client(provider)?))
            }
            ForeignChain::Avalanche => {
                RpcInspector::Avalanche(EvmInspector::new(build_http_client(provider)?))
            }
            ForeignChain::Base => {
                RpcInspector::Base(EvmInspector::new(build_http_client(provider)?))
            }
            ForeignChain::Bitcoin => {
                RpcInspector::Bitcoin(BitcoinInspector::new(build_http_client(provider)?))
            }
            ForeignChain::Bnb => RpcInspector::Bnb(EvmInspector::new(build_http_client(provider)?)),
            ForeignChain::Ethereum => {
                RpcInspector::Ethereum(EvmInspector::new(build_http_client(provider)?))
            }
            ForeignChain::Fogo => {
                RpcInspector::Fogo(SvmInspector::new(build_http_client(provider)?))
            }
            ForeignChain::HyperEvm => {
                RpcInspector::HyperEvm(EvmInspector::new(build_http_client(provider)?))
            }
            ForeignChain::Polygon => {
                RpcInspector::Polygon(EvmInspector::new(build_http_client(provider)?))
            }
            ForeignChain::Solana => {
                RpcInspector::Solana(SvmInspector::new(build_http_client(provider)?))
            }
            ForeignChain::Starknet => {
                RpcInspector::Starknet(StarknetInspector::new(build_http_client(provider)?))
            }
            ForeignChain::Sui => {
                let (url, auth_header) = resolve_provider_auth(provider)?;
                RpcInspector::Sui(SuiInspector::new(
                    GrpcSuiClient::new(url, auth_header, timeout)
                        .map_err(|e| anyhow::anyhow!("failed to build the Sui gRPC client: {e}"))?,
                ))
            }
            // `ForeignChain` is `non_exhaustive`, so the chains left without an inspector cannot
            // be listed here.
            _ => return Ok(None),
        }))
    }
}
