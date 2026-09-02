use assert_matches::assert_matches;
use foreign_chain_inspector::{
    EthereumFinality, ForeignChainInspector, NetworkFingerprintInspector,
    ethereum::{
        EthereumBlockHash, EthereumTransactionHash, MAINNET_CHAIN_ID,
        inspector::{EthereumExtractedValue, EthereumExtractor, EthereumInspector},
    },
};
use foreign_chain_rpc_factory::build_http_client;

const ETHEREUM_RPC_URL: &str = "https://ethereum-rpc.publicnode.com";

#[tokio::test]
#[ignore = "manual test to sanity check against live Ethereum RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
    let threshold = EthereumFinality::Finalized;

    // Example transaction on Ethereum (block 0x444f76) with 1 log at block-wide index 0x10;
    // https://etherscan.io/tx/0x7f1c6a58dc880438236d0b0a4ae166e9e9a038dbea8ec074149bd8b176332cac
    let transaction_id: EthereumTransactionHash =
        "7f1c6a58dc880438236d0b0a4ae166e9e9a038dbea8ec074149bd8b176332cac"
            .parse()
            .unwrap();
    let expected_block_hash: EthereumBlockHash =
        "34e5a6cfbdbb84f7625df1de69d218ade4da72f4a2558064a156674e72e976c9"
            .parse()
            .unwrap();

    let http_client = build_http_client(&mpc_node_config::ForeignChainProviderConfig {
        rpc_url: ETHEREUM_RPC_URL.to_string(),
        auth: mpc_node_config::AuthConfig::None,
    })
    .unwrap();
    let inspector = EthereumInspector::new(http_client);

    // when
    let extracted_values = inspector
        .extract(
            transaction_id,
            threshold,
            vec![
                EthereumExtractor::BlockHash,
                EthereumExtractor::Log { log_index: 0x10 },
            ],
        )
        .await
        .expect("extract should succeed");

    // then
    assert_eq!(extracted_values.len(), 2);
    assert_eq!(
        extracted_values[0],
        EthereumExtractedValue::BlockHash(expected_block_hash)
    );
    assert_matches!(extracted_values[1], EthereumExtractedValue::Log(_));
}

/// As shipped in `expected_network_fingerprint`.
const EXPECTED_NETWORK_FINGERPRINT: u64 = MAINNET_CHAIN_ID;

#[tokio::test]
#[ignore = "manual test to sanity check against live Ethereum RPC provider"]
async fn network_fingerprint_matches_the_shipped_config_value_against_live_rpc_provider() {
    // given
    let http_client = build_http_client(&mpc_node_config::ForeignChainProviderConfig {
        rpc_url: ETHEREUM_RPC_URL.to_string(),
        auth: mpc_node_config::AuthConfig::None,
    })
    .unwrap();
    let inspector = EthereumInspector::new(http_client);

    // when
    let fingerprint = inspector
        .network_fingerprint()
        .await
        .expect("network_fingerprint should succeed");

    // then
    assert_eq!(
        fingerprint.to_string(),
        EXPECTED_NETWORK_FINGERPRINT.to_string()
    );
}
