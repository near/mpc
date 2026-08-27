//! Building the client that talks to one provider, with the provider's credentials applied.

use std::time::Duration;

use foreign_chain_inspector::{RpcAuthentication, build_http_client};
use foreign_chain_rpc_interfaces::aptos::{AptosRpcClient, ReqwestAptosClient};
use foreign_chain_rpc_interfaces::sui::{GrpcSuiClient, SuiRpcClient};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClient;
use mpc_node_config::ForeignChainProviderConfig;

use crate::auth_config_to_rpc_auth;

/// The transports a chain is reached over. [`RpcClients`] reaches the real providers; a caller that
/// needs something else, a test most of all, implements this instead.
///
/// Injecting it also settles which inspectors get built, since
/// [`crate::inspectors`] puts them on whatever this returns.
pub trait BuildRpcClients {
    type JsonRpc: ClientT + Clone + Send + Sync + 'static;
    type Aptos: AptosRpcClient + Clone + Send + Sync + 'static;
    type Sui: SuiRpcClient + Clone + Send + Sync + 'static;

    fn json_rpc(&self, provider: &ForeignChainProviderConfig) -> anyhow::Result<Self::JsonRpc>;

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

/// Resolves the provider's credentials and reaches it over the network.
#[derive(Clone, Copy)]
pub struct RpcClients;

impl RpcClients {
    /// Applies the provider's credentials, leaving them in the URL or in a header as its auth
    /// config asks.
    fn authenticate(
        provider: &ForeignChainProviderConfig,
    ) -> anyhow::Result<(String, RpcAuthentication)> {
        let mut url = provider.rpc_url.clone();
        let auth = auth_config_to_rpc_auth(provider.auth.clone(), &mut url)?;
        Ok((url, auth))
    }

    /// The gRPC and REST clients carry credentials in request metadata rather than the URL.
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

impl BuildRpcClients for RpcClients {
    type Aptos = ReqwestAptosClient;
    type JsonRpc = HttpClient;
    type Sui = GrpcSuiClient;

    fn json_rpc(&self, provider: &ForeignChainProviderConfig) -> anyhow::Result<HttpClient> {
        let (url, auth) = Self::authenticate(provider)?;
        Ok(build_http_client(url, auth)?)
    }

    fn aptos(
        &self,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<ReqwestAptosClient> {
        let (url, auth) = Self::authenticate(provider)?;
        Ok(ReqwestAptosClient::new(
            url,
            Self::auth_header(auth),
            timeout,
        ))
    }

    fn sui(
        &self,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<GrpcSuiClient> {
        let (url, auth) = Self::authenticate(provider)?;
        GrpcSuiClient::new(url, Self::auth_header(auth), timeout)
            .map_err(|e| anyhow::anyhow!("failed to build the Sui gRPC client: {e}"))
    }
}
