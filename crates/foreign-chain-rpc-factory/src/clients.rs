//! Building the client that talks to one provider, with the provider's credentials applied.

use std::time::Duration;

use foreign_chain_inspector::{RpcAuthentication, build_http_client};
use foreign_chain_rpc_interfaces::aptos::{AptosRpcClient, ReqwestAptosClient};
use foreign_chain_rpc_interfaces::sui::{GrpcSuiClient, SuiRpcClient};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClient;
use mpc_node_config::ForeignChainProviderConfig;

use crate::auth_config_to_rpc_auth;

/// The transports a chain is reached over. [`RpcClientFactory`] reaches the real providers; a
/// caller that needs something else, a test most of all, implements this instead.
///
/// An [`crate::inspectors::InspectorFactory`] is built over one of these, so the choice also
/// settles what the inspectors it hands out are talking to.
pub trait BuildRpcClients {
    type JsonRpc: ClientT + Clone + Send + Sync + 'static;
    type Aptos: AptosRpcClient + Clone + Send + Sync + 'static;
    type Sui: SuiRpcClient + Clone + Send + Sync + 'static;

    fn json_rpc(
        &self,
        provider: &ForeignChainProviderConfig,
        timeout: Duration,
    ) -> anyhow::Result<Self::JsonRpc>;

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

/// Reaches the real providers over the network, with each one's credentials applied.
#[derive(Clone, Copy)]
pub struct RpcClientFactory;

impl RpcClientFactory {
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

impl BuildRpcClients for RpcClientFactory {
    type Aptos = ReqwestAptosClient;
    type JsonRpc = HttpClient;
    type Sui = GrpcSuiClient;

    /// The deadline is not handed to jsonrpsee: these chains are bounded by the caller's own
    /// deadline, as they were before this factory existed. It stays in the signature so a caller
    /// building its own clients can honour it.
    fn json_rpc(
        &self,
        provider: &ForeignChainProviderConfig,
        _timeout: Duration,
    ) -> anyhow::Result<HttpClient> {
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
