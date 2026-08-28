use std::time::Duration;

use foreign_chain_inspector::aptos::inspector::AptosInspector;
use foreign_chain_inspector::bitcoin::inspector::BitcoinInspector;
use foreign_chain_inspector::evm::inspector::EvmInspector;
use foreign_chain_inspector::rpc_inspector::RpcInspector;
use foreign_chain_inspector::starknet::inspector::StarknetInspector;
use foreign_chain_inspector::sui::inspector::SuiInspector;
use foreign_chain_inspector::{BuildInspectors, RpcAuthentication, build_http_client};
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use foreign_chain_rpc_interfaces::sui::GrpcSuiClient;
use mpc_node_config::ForeignChainProviderConfig;
use near_mpc_contract_interface::types::ForeignChain;

use crate::auth_config_to_rpc_auth;

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
        let (url, auth) = Self::authenticate(provider)?;
        let auth_header = Self::auth_header(auth.clone());
        Ok(Some(match chain {
            ForeignChain::Abstract => {
                RpcInspector::Abstract(EvmInspector::new(build_http_client(url, auth)?))
            }
            ForeignChain::Adi => {
                RpcInspector::Adi(EvmInspector::new(build_http_client(url, auth)?))
            }
            ForeignChain::Aptos => RpcInspector::Aptos(AptosInspector::new(
                ReqwestAptosClient::new(url, auth_header, timeout),
            )),
            ForeignChain::Arbitrum => {
                RpcInspector::Arbitrum(EvmInspector::new(build_http_client(url, auth)?))
            }
            ForeignChain::Avalanche => {
                RpcInspector::Avalanche(EvmInspector::new(build_http_client(url, auth)?))
            }
            ForeignChain::Base => {
                RpcInspector::Base(EvmInspector::new(build_http_client(url, auth)?))
            }
            ForeignChain::Bitcoin => {
                RpcInspector::Bitcoin(BitcoinInspector::new(build_http_client(url, auth)?))
            }
            ForeignChain::Bnb => {
                RpcInspector::Bnb(EvmInspector::new(build_http_client(url, auth)?))
            }
            ForeignChain::Ethereum => {
                RpcInspector::Ethereum(EvmInspector::new(build_http_client(url, auth)?))
            }
            ForeignChain::HyperEvm => {
                RpcInspector::HyperEvm(EvmInspector::new(build_http_client(url, auth)?))
            }
            ForeignChain::Polygon => {
                RpcInspector::Polygon(EvmInspector::new(build_http_client(url, auth)?))
            }
            ForeignChain::Starknet => {
                RpcInspector::Starknet(StarknetInspector::new(build_http_client(url, auth)?))
            }
            ForeignChain::Sui => RpcInspector::Sui(SuiInspector::new(
                GrpcSuiClient::new(url, auth_header, timeout)
                    .map_err(|e| anyhow::anyhow!("failed to build the Sui gRPC client: {e}"))?,
            )),
            // `ForeignChain` is `non_exhaustive`, so the chains left without an inspector cannot
            // be listed here.
            _ => return Ok(None),
        }))
    }
}

impl InspectorFactory {
    fn authenticate(
        provider: &ForeignChainProviderConfig,
    ) -> anyhow::Result<(String, RpcAuthentication)> {
        let mut url = provider.rpc_url.clone();
        let auth = auth_config_to_rpc_auth(provider.auth.clone(), &mut url)?;
        Ok((url, auth))
    }

    fn auth_header(auth: RpcAuthentication) -> Option<(http::HeaderName, http::HeaderValue)> {
        match auth {
            RpcAuthentication::KeyInUrl => None,
            RpcAuthentication::CustomHeader {
                header_name,
                header_value,
            } => Some((header_name, header_value)),
        }
    }
}
