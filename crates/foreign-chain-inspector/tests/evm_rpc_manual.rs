use foreign_chain_inspector::{
    EthereumFinality, ForeignChainInspector, NetworkFingerprintInspector, Verdict,
    abstract_chain::{self, inspector::Abstract},
    adi::{self, inspector::Adi},
    arbitrum::{self, inspector::Arbitrum},
    avalanche::{self, inspector::Avalanche},
    base::{self, inspector::Base},
    bnb::{self, inspector::Bnb},
    ethereum::{self, inspector::Ethereum},
    evm::inspector::{EvmChain, EvmExtractedValue, EvmExtractor, EvmInspector},
    hyperevm::{self, inspector::HyperEvm},
    polygon::{self, inspector::Polygon},
};
use foreign_chain_rpc_factory::build_http_client;
use jsonrpsee::http_client::HttpClient;
use mpc_node_config::{AuthConfig, ForeignChainProviderConfig};
use std::{assert_matches, fmt::Debug, str::FromStr};

fn build_inspector<Chain: EvmChain>(rpc_url: &str) -> EvmInspector<HttpClient, Chain> {
    let http_client = build_http_client(&ForeignChainProviderConfig {
        rpc_url: rpc_url.to_string(),
        auth: AuthConfig::None,
    })
    .unwrap();
    EvmInspector::new(http_client)
}

async fn assert_extracts_block_hash<Chain>(
    rpc_url: &str,
    transaction_id: &str,
    expected_block_hash: &str,
    log_indices: &[u64],
) where
    Chain: EvmChain + Debug + PartialEq + Send + Sync,
    Chain::TransactionHash: FromStr<Err: Debug>,
    Chain::BlockHash: FromStr<Err: Debug>,
{
    // Given
    let threshold = EthereumFinality::Finalized;
    let transaction_id: Chain::TransactionHash = transaction_id.parse().unwrap();
    let expected_block_hash: Chain::BlockHash = expected_block_hash.parse().unwrap();
    let inspector = build_inspector::<Chain>(rpc_url);
    let extractors = [EvmExtractor::BlockHash]
        .into_iter()
        .chain(
            log_indices
                .iter()
                .map(|&log_index| EvmExtractor::Log { log_index }),
        )
        .collect();

    // When
    let extracted_values = inspector
        .extract(transaction_id, threshold, extractors)
        .await
        .expect("extract should succeed");
    let Verdict::Extracted(extracted_values) = extracted_values else {
        panic!("expected extracted values, got: {extracted_values}");
    };

    // Then
    assert_eq!(extracted_values.len(), 1 + log_indices.len());
    assert_eq!(
        extracted_values[0],
        EvmExtractedValue::<Chain>::BlockHash(expected_block_hash)
    );
    for value in &extracted_values[1..] {
        assert_matches!(value, EvmExtractedValue::Log(_));
    }
}

async fn assert_network_fingerprint_matches<Chain>(rpc_url: &str, expected_chain_id: u64)
where
    Chain: EvmChain + Send + Sync,
{
    // Given
    let inspector = build_inspector::<Chain>(rpc_url);

    // When
    let fingerprint = inspector
        .network_fingerprint()
        .await
        .expect("network_fingerprint should succeed");

    // Then
    assert_eq!(fingerprint.to_string(), expected_chain_id.to_string());
}

const ABSTRACT_RPC_URL: &str = "https://api.testnet.abs.xyz";

#[tokio::test]
#[ignore = "manual test to sanity check against live Abstract RPC provider"]
async fn abstract_inspector_extracts_block_hash_against_live_rpc_provider() {
    // Example transaction from Abstract testnet
    // https://explorer.testnet.abs.xyz/tx/0x497fc5f5b5d81d6bc15cccc6d4d8be8ef6ad19376233b944a60dc435593f7234
    assert_extracts_block_hash::<Abstract>(
        ABSTRACT_RPC_URL,
        "497fc5f5b5d81d6bc15cccc6d4d8be8ef6ad19376233b944a60dc435593f7234",
        "4c93dd4a8f347e6480b0a44f8c2b7eecdfb31d711e8d542fd60112ea5d98fb02",
        &[1],
    )
    .await;
}

#[tokio::test]
#[ignore = "manual test to sanity check against live Abstract RPC provider"]
async fn abstract_network_fingerprint_matches_the_shipped_config_value_against_live_rpc_provider() {
    assert_network_fingerprint_matches::<Abstract>(
        ABSTRACT_RPC_URL,
        abstract_chain::TESTNET_CHAIN_ID,
    )
    .await;
}

const ADI_RPC_URL: &str = "https://rpc.adifoundation.ai";

#[tokio::test]
#[ignore = "manual test to sanity check against live ADI Chain RPC provider"]
async fn adi_inspector_extracts_block_hash_against_live_rpc_provider() {
    // Example transaction on ADI Chain (block 0x186a0) with 17 logs;
    // https://explorer.adifoundation.ai/tx/0xdf89849ce8e1b4cf390560395198a10f1bd0498822c6880346a8ce28869ec8e5
    assert_extracts_block_hash::<Adi>(
        ADI_RPC_URL,
        "df89849ce8e1b4cf390560395198a10f1bd0498822c6880346a8ce28869ec8e5",
        "e49e64cb14a417a1356929043dc87559c57afb540492bc62c8c0d8270902f5c2",
        &[0, 1, 2],
    )
    .await;
}

#[tokio::test]
#[ignore = "manual test to sanity check against live ADI Chain RPC provider"]
async fn adi_network_fingerprint_matches_the_shipped_config_value_against_live_rpc_provider() {
    assert_network_fingerprint_matches::<Adi>(ADI_RPC_URL, adi::MAINNET_CHAIN_ID).await;
}

const ARBITRUM_RPC_URL: &str = "https://arb1.arbitrum.io/rpc";

#[tokio::test]
#[ignore = "manual test to sanity check against live Arbitrum RPC provider"]
async fn arbitrum_inspector_extracts_block_hash_against_live_rpc_provider() {
    // Example transaction on Arbitrum One with 3 logs;
    // https://arbiscan.io/tx/0x8f1f497285dcf54624cba2c3dd46d13e25fc83466033c139e77e4dce12a1e484
    assert_extracts_block_hash::<Arbitrum>(
        ARBITRUM_RPC_URL,
        "8f1f497285dcf54624cba2c3dd46d13e25fc83466033c139e77e4dce12a1e484",
        "da0e369bfb9688ca4591604104e4f2953329542bfb3bc0d0c94686b5ad798c1c",
        &[0, 1, 2],
    )
    .await;
}

#[tokio::test]
#[ignore = "manual test to sanity check against live Arbitrum RPC provider"]
async fn arbitrum_network_fingerprint_matches_the_shipped_config_value_against_live_rpc_provider() {
    assert_network_fingerprint_matches::<Arbitrum>(ARBITRUM_RPC_URL, arbitrum::MAINNET_CHAIN_ID)
        .await;
}

const AVALANCHE_RPC_URL: &str = "https://api.avax.network/ext/bc/C/rpc";

#[tokio::test]
#[ignore = "manual test to sanity check against live Avalanche C-Chain RPC provider"]
async fn avalanche_inspector_extracts_block_hash_against_live_rpc_provider() {
    // Example transaction on Avalanche C-Chain (block 0x989680) with 1 log;
    // https://snowtrace.io/tx/0x51f5b652c9917189b64a5abb5e1814d3bd0a58dbe433f3f7a58e9b0d20f40bb5
    assert_extracts_block_hash::<Avalanche>(
        AVALANCHE_RPC_URL,
        "51f5b652c9917189b64a5abb5e1814d3bd0a58dbe433f3f7a58e9b0d20f40bb5",
        "ce5c4ceb1b1c14ba8a0d58f23545106934278390446466810991245a9cff2a43",
        &[0],
    )
    .await;
}

#[tokio::test]
#[ignore = "manual test to sanity check against live Avalanche C-Chain RPC provider"]
async fn avalanche_network_fingerprint_matches_the_shipped_config_value_against_live_rpc_provider()
{
    assert_network_fingerprint_matches::<Avalanche>(AVALANCHE_RPC_URL, avalanche::MAINNET_CHAIN_ID)
        .await;
}

const BASE_RPC_URL: &str = "https://mainnet.base.org";

#[tokio::test]
#[ignore = "manual test to sanity check against live Base RPC provider"]
async fn base_inspector_extracts_block_hash_against_live_rpc_provider() {
    // Example transaction on Base mainnet (block 33554432) with 16 logs;
    // https://basescan.org/tx/0xa11eaa1236e80f26ddc7aca164f2ba4c6c2726405cb12b1aa8f52c520bad99e1
    assert_extracts_block_hash::<Base>(
        BASE_RPC_URL,
        "a11eaa1236e80f26ddc7aca164f2ba4c6c2726405cb12b1aa8f52c520bad99e1",
        "b8488c9272c547c45e63ea76cc2d1c927c8f888e2721f790b14db996b6cc6aca",
        &[0, 1, 2],
    )
    .await;
}

#[tokio::test]
#[ignore = "manual test to sanity check against live Base RPC provider"]
async fn base_network_fingerprint_matches_the_shipped_config_value_against_live_rpc_provider() {
    assert_network_fingerprint_matches::<Base>(BASE_RPC_URL, base::MAINNET_CHAIN_ID).await;
}

const BNB_RPC_URL: &str = "https://bsc-rpc.publicnode.com";

#[tokio::test]
#[ignore = "manual test to sanity check against live BNB RPC provider"]
async fn bnb_inspector_extracts_block_hash_against_live_rpc_provider() {
    // Example DEX swap transaction on BNB with 3 logs
    // https://bscscan.com/tx/0x90514fff1563dc9876bc9a02a7b1d4dd2ce44b8d11ea0490aa8d427166eba349
    assert_extracts_block_hash::<Bnb>(
        BNB_RPC_URL,
        "90514fff1563dc9876bc9a02a7b1d4dd2ce44b8d11ea0490aa8d427166eba349",
        "4f125b8e2716df5cbc72719212d5189dae0e49b6b7a44523165cb01888914999",
        &[0, 1, 2],
    )
    .await;
}

#[tokio::test]
#[ignore = "manual test to sanity check against live BNB RPC provider"]
async fn bnb_network_fingerprint_matches_the_shipped_config_value_against_live_rpc_provider() {
    assert_network_fingerprint_matches::<Bnb>(BNB_RPC_URL, bnb::MAINNET_CHAIN_ID).await;
}

const ETHEREUM_RPC_URL: &str = "https://ethereum-rpc.publicnode.com";

#[tokio::test]
#[ignore = "manual test to sanity check against live Ethereum RPC provider"]
async fn ethereum_inspector_extracts_block_hash_against_live_rpc_provider() {
    // Example transaction on Ethereum (block 0x444f76) with 1 log at block-wide index 0x10;
    // https://etherscan.io/tx/0x7f1c6a58dc880438236d0b0a4ae166e9e9a038dbea8ec074149bd8b176332cac
    assert_extracts_block_hash::<Ethereum>(
        ETHEREUM_RPC_URL,
        "7f1c6a58dc880438236d0b0a4ae166e9e9a038dbea8ec074149bd8b176332cac",
        "34e5a6cfbdbb84f7625df1de69d218ade4da72f4a2558064a156674e72e976c9",
        &[0x10],
    )
    .await;
}

#[tokio::test]
#[ignore = "manual test to sanity check against live Ethereum RPC provider"]
async fn ethereum_network_fingerprint_matches_the_shipped_config_value_against_live_rpc_provider() {
    assert_network_fingerprint_matches::<Ethereum>(ETHEREUM_RPC_URL, ethereum::MAINNET_CHAIN_ID)
        .await;
}

const HYPEREVM_RPC_URL: &str = "https://rpc.hyperliquid.xyz/evm";

#[tokio::test]
#[ignore = "manual test to sanity check against live HyperEVM RPC provider"]
async fn hyperevm_inspector_extracts_block_hash_against_live_rpc_provider() {
    // Example transaction on HyperEVM (block 0x20c6dc5) with 3 logs;
    // https://hyperevmscan.io/tx/0x4d94e2c9c33c533f125bd28a788e80ee24c108356e8fa8a7878f642cf94dcf4a
    assert_extracts_block_hash::<HyperEvm>(
        HYPEREVM_RPC_URL,
        "4d94e2c9c33c533f125bd28a788e80ee24c108356e8fa8a7878f642cf94dcf4a",
        "657b2ee81add87e3f654840425baca06a06d5876f6d2d873197e70f00f6762e6",
        &[0, 1, 2],
    )
    .await;
}

#[tokio::test]
#[ignore = "manual test to sanity check against live HyperEVM RPC provider"]
async fn hyperevm_network_fingerprint_matches_the_shipped_config_value_against_live_rpc_provider() {
    assert_network_fingerprint_matches::<HyperEvm>(HYPEREVM_RPC_URL, hyperevm::MAINNET_CHAIN_ID)
        .await;
}

const POLYGON_RPC_URL: &str = "https://polygon.drpc.org";

#[tokio::test]
#[ignore = "manual test to sanity check against live Polygon RPC provider"]
async fn polygon_inspector_extracts_block_hash_against_live_rpc_provider() {
    // Example transaction on Polygon (block 0x5276e5d) with 8 logs;
    // https://polygonscan.com/tx/0x7b231f0f5bf36782a48db9b1d89e4613bd00618f03c3c0fba922aa59288e4d38
    assert_extracts_block_hash::<Polygon>(
        POLYGON_RPC_URL,
        "7b231f0f5bf36782a48db9b1d89e4613bd00618f03c3c0fba922aa59288e4d38",
        "56d98f80b91c9cf9dcda71c63c01ea441d46ba31149c902adfbee97e55ff82a6",
        &[0, 1, 2],
    )
    .await;
}

#[tokio::test]
#[ignore = "manual test to sanity check against live Polygon RPC provider"]
async fn polygon_network_fingerprint_matches_the_shipped_config_value_against_live_rpc_provider() {
    assert_network_fingerprint_matches::<Polygon>(POLYGON_RPC_URL, polygon::MAINNET_CHAIN_ID).await;
}
