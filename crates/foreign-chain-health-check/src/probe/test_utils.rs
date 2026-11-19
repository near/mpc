//! Fixtures shared by the probe's test modules.

use super::*;
use foreign_chain_inspector::mock::{MockInspector, MockReply};
use foreign_chain_inspector::{
    abstract_chain, adi, aptos, arbitrum, avalanche, base, bitcoin, bnb, ethereum, hyperevm,
    polygon, starknet, sui, svm,
};
use foreign_chain_rpc_interfaces::sui::Status;
use foreign_chain_rpc_interfaces::sui::proto::ledger_service_server::{
    LedgerService, LedgerServiceServer,
};
use foreign_chain_rpc_interfaces::sui::proto::{GetServiceInfoRequest, GetServiceInfoResponse};
use mpc_node_config::AuthConfig;
use near_mpc_bounded_collections::NonEmptyBTreeMap;
use std::num::NonZeroU64;

/// Hands the probe a mock inspector per provider URL.
pub(crate) struct MockInspectors(std::collections::BTreeMap<String, MockInspector>);

impl MockInspectors {
    pub(crate) fn new<'a>(inspectors: impl IntoIterator<Item = (&'a str, MockInspector)>) -> Self {
        Self(
            inspectors
                .into_iter()
                .map(|(url, inspector)| (url.to_string(), inspector))
                .collect(),
        )
    }
}

/// Stands in for a chain the probe cannot build an inspector for. Every chain an operator
/// can configure now has one, so this path is unreachable from a real config.
pub(crate) struct NoInspectors;

impl BuildInspectors for NoInspectors {
    type Inspector = MockInspector;

    fn build(
        &self,
        _chain: ForeignChain,
        _provider: &ForeignChainProviderConfig,
        _timeout: std::time::Duration,
    ) -> anyhow::Result<Option<MockInspector>> {
        Ok(None)
    }
}

impl BuildInspectors for MockInspectors {
    type Inspector = MockInspector;

    fn build(
        &self,
        _chain: ForeignChain,
        provider: &ForeignChainProviderConfig,
        _timeout: std::time::Duration,
    ) -> anyhow::Result<Option<MockInspector>> {
        let inspector = self
            .0
            .get(&provider.rpc_url)
            .unwrap_or_else(|| panic!("no mock inspector for `{}`", provider.rpc_url));
        Ok(Some(inspector.clone()))
    }
}

pub(crate) const MAINNET: &str = starknet::MAINNET_CHAIN_ID;
pub(crate) const SEPOLIA: &str = starknet::SEPOLIA_CHAIN_ID;
pub(crate) const PADDED_UPPERCASE_MAINNET: &str = "0x00534E5F4D41494E";
/// Reserved as "discard", so nothing listens there.
pub(crate) const CLOSED_PORT_URL: &str = "http://127.0.0.1:9";
/// For a chain with no probe: the value is never read, only whether it is set at all.
pub(crate) const ANY_FINGERPRINT: &str = "any-fingerprint";
pub(crate) const SUI_MAINNET: &str = sui::MAINNET_GENESIS_CHECKPOINT_DIGEST;
pub(crate) const SUI_TESTNET: &str = sui::TESTNET_GENESIS_CHECKPOINT_DIGEST;
/// Aptos providers reports its chain id as a bare JSON number (`uint8`). The configured fingerprint is
/// the same number as text.
pub(crate) const APTOS_MAINNET: u64 = aptos::MAINNET_CHAIN_ID;
pub(crate) const APTOS_TESTNET: u64 = aptos::TESTNET_CHAIN_ID;
pub(crate) const PROVIDER_NAME: &str = "publicnode";
pub(crate) const BITCOIN_MAINNET: &str = bitcoin::MAINNET_GENESIS_BLOCK_HASH;
pub(crate) const BITCOIN_TESTNET3: &str = bitcoin::TESTNET3_GENESIS_BLOCK_HASH;
pub(crate) const SOLANA_MAINNET: &str = svm::SOLANA_MAINNET_GENESIS_HASH;
pub(crate) const SOLANA_DEVNET: &str = svm::SOLANA_DEVNET_GENESIS_HASH;
pub(crate) const FOGO_MAINNET: &str = svm::FOGO_MAINNET_GENESIS_HASH;

pub(crate) struct EvmMainnet {
    pub(crate) chain: ForeignChain,
    pub(crate) chain_id: u64,
}

impl EvmMainnet {
    /// The form an operator configures.
    pub(crate) fn expected(&self) -> String {
        self.chain_id.to_string()
    }

    /// The `0xXXX` hex quantity an RPC provider answers to an `eth_chainId` request.
    pub(crate) fn answered(&self) -> String {
        format!("{:#x}", self.chain_id)
    }
}

/// Every EVM chain the probe covers, with its mainnet chain id.
pub(crate) const EVM_MAINNETS: [EvmMainnet; 9] = [
    EvmMainnet {
        chain: ForeignChain::Abstract,
        chain_id: abstract_chain::MAINNET_CHAIN_ID,
    },
    EvmMainnet {
        chain: ForeignChain::Adi,
        chain_id: adi::MAINNET_CHAIN_ID,
    },
    EvmMainnet {
        chain: ForeignChain::Arbitrum,
        chain_id: arbitrum::MAINNET_CHAIN_ID,
    },
    EvmMainnet {
        chain: ForeignChain::Avalanche,
        chain_id: avalanche::MAINNET_CHAIN_ID,
    },
    EvmMainnet {
        chain: ForeignChain::Base,
        chain_id: base::MAINNET_CHAIN_ID,
    },
    EvmMainnet {
        chain: ForeignChain::Bnb,
        chain_id: bnb::MAINNET_CHAIN_ID,
    },
    EvmMainnet {
        chain: ForeignChain::Ethereum,
        chain_id: ethereum::MAINNET_CHAIN_ID,
    },
    EvmMainnet {
        chain: ForeignChain::HyperEvm,
        chain_id: hyperevm::MAINNET_CHAIN_ID,
    },
    EvmMainnet {
        chain: ForeignChain::Polygon,
        chain_id: polygon::MAINNET_CHAIN_ID,
    },
];

pub(crate) fn provider(rpc_url: &str) -> ForeignChainProviderConfig {
    ForeignChainProviderConfig {
        rpc_url: rpc_url.to_string(),
        auth: AuthConfig::None,
    }
}

pub(crate) fn chain_config(
    expected: Option<&str>,
    providers: NonEmptyBTreeMap<
        mpc_node_config::foreign_chains::RpcProviderName,
        ForeignChainProviderConfig,
    >,
) -> ForeignChainConfig {
    ForeignChainConfig {
        timeout_sec: NonZeroU64::new(1).unwrap(),
        max_retries: NonZeroU64::new(1).unwrap(),
        expected_network_fingerprint: expected.map(str::to_string),
        providers,
    }
}

pub(crate) fn with_retries(config: ForeignChainConfig, max_retries: u64) -> ForeignChainConfig {
    ForeignChainConfig {
        max_retries: NonZeroU64::new(max_retries).unwrap(),
        ..config
    }
}

pub(crate) fn one_provider(
    name: &str,
    rpc_url: &str,
) -> NonEmptyBTreeMap<mpc_node_config::foreign_chains::RpcProviderName, ForeignChainProviderConfig>
{
    NonEmptyBTreeMap::new(name.to_string().into(), provider(rpc_url))
}

pub(crate) fn single_chain(chain: ForeignChain, config: ForeignChainConfig) -> ForeignChainsConfig {
    let mut chains = ForeignChainsConfig::default();
    put_chain(&mut chains, chain, config);
    chains
}

pub(crate) fn put_chain(
    chains: &mut ForeignChainsConfig,
    chain: ForeignChain,
    config: ForeignChainConfig,
) {
    let slot = match chain {
        ForeignChain::Abstract => &mut chains.abstract_chain,
        ForeignChain::Adi => &mut chains.adi,
        ForeignChain::Arbitrum => &mut chains.arbitrum,
        ForeignChain::Avalanche => &mut chains.avalanche,
        ForeignChain::Base => &mut chains.base,
        ForeignChain::Bnb => &mut chains.bnb,
        ForeignChain::Ethereum => &mut chains.ethereum,
        ForeignChain::HyperEvm => &mut chains.hyper_evm,
        ForeignChain::Polygon => &mut chains.polygon,
        ForeignChain::Solana => &mut chains.solana,
        ForeignChain::Fogo => &mut chains.fogo,
        ForeignChain::Starknet => &mut chains.starknet,
        ForeignChain::Bitcoin => &mut chains.bitcoin,
        ForeignChain::Aptos => &mut chains.aptos,
        ForeignChain::Sui => &mut chains.sui,
        other => panic!("no config slot wired for `{other:?}`"),
    };
    *slot = Some(config);
}

pub(crate) async fn mock_fingerprint<'a>(
    server: &'a httpmock::MockServer,
    fingerprint: &str,
) -> httpmock::Mock<'a> {
    let body = serde_json::json!({"jsonrpc": "2.0", "result": fingerprint, "id": 0});
    server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST);
            then.status(200).json_body(body);
        })
        .await
}

pub(crate) async fn mock_error_object<'a>(
    server: &'a httpmock::MockServer,
    status: u16,
    code: i32,
    message: &str,
) -> httpmock::Mock<'a> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 0,
        "error": {"code": code, "message": message},
    });
    server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST);
            then.status(status).json_body(body);
        })
        .await
}

pub(crate) async fn mock_unsupported_method(server: &httpmock::MockServer) -> httpmock::Mock<'_> {
    mock_error_object(server, 200, -32601, "Method not found").await
}

pub(crate) async fn mock_non_jsonrpc_body(server: &httpmock::MockServer) -> httpmock::Mock<'_> {
    server
        .mock_async(|when, then| {
            when.method(httpmock::Method::POST);
            then.status(200).body("<html>gateway</html>");
        })
        .await
}

pub(crate) fn answering(fingerprint: &str) -> MockReply {
    MockReply::Answer {
        delay: std::time::Duration::ZERO,
        fingerprint: fingerprint.to_string(),
    }
}

/// Keyed by chain too: provider names repeat across chains in real configs.
pub(crate) fn status_of(
    report: &ProbeReport,
    chain: ForeignChain,
    provider: &str,
) -> ProviderStatus {
    report
        .rows()
        .iter()
        .find(|row| row.chain == chain && row.provider.0 == provider)
        .unwrap_or_else(|| panic!("missing row for `{chain:?}` provider `{provider}`"))
        .status
        .clone()
}

pub(crate) async fn mock_ledger_info<'a>(
    server: &'a httpmock::MockServer,
    chain_id: u64,
) -> httpmock::Mock<'a> {
    let body = serde_json::json!({"chain_id": chain_id, "ledger_version": "1"});
    server
        .mock_async(|when, then| {
            when.method(httpmock::Method::GET);
            then.status(200).json_body(body);
        })
        .await
}

/// A gRPC ledger service answering whatever a test arms.
struct FakeSuiLedger(Result<GetServiceInfoResponse, Status>);

#[tonic::async_trait]
impl LedgerService for FakeSuiLedger {
    async fn get_service_info(
        &self,
        _request: tonic::Request<GetServiceInfoRequest>,
    ) -> Result<tonic::Response<GetServiceInfoResponse>, Status> {
        self.0.clone().map(tonic::Response::new)
    }
}

/// Serves a [`FakeSuiLedger`] on a loopback port until dropped.
pub(crate) struct FakeSuiServer {
    pub(crate) url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeSuiServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) async fn sui_answering(answer: Result<GetServiceInfoResponse, Status>) -> FakeSuiServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(LedgerServiceServer::new(FakeSuiLedger(answer)))
            .serve_with_incoming(tonic::transport::server::TcpIncoming::from(listener))
            .await
            .expect("the fake Sui ledger should keep serving until the test drops it");
    });
    FakeSuiServer { url, task }
}
