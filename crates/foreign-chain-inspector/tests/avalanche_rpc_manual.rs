use assert_matches::assert_matches;
use foreign_chain_inspector::{
    EthereumFinality, ForeignChainInspector, NetworkFingerprintInspector, RpcAuthentication,
    avalanche::{
        AvalancheBlockHash, AvalancheTransactionHash, MAINNET_CHAIN_ID,
        inspector::{AvalancheExtractedValue, AvalancheExtractor, AvalancheInspector},
    },
};

const AVALANCHE_RPC_URL: &str = "https://api.avax.network/ext/bc/C/rpc";

#[tokio::test]
#[ignore = "manual test to sanity check against live Avalanche C-Chain RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
    let threshold = EthereumFinality::Finalized;

    // Example transaction on Avalanche C-Chain (block 0x989680) with 1 log;
    // https://snowtrace.io/tx/0x51f5b652c9917189b64a5abb5e1814d3bd0a58dbe433f3f7a58e9b0d20f40bb5
    let transaction_id: AvalancheTransactionHash =
        "51f5b652c9917189b64a5abb5e1814d3bd0a58dbe433f3f7a58e9b0d20f40bb5"
            .parse()
            .unwrap();
    let expected_block_hash: AvalancheBlockHash =
        "ce5c4ceb1b1c14ba8a0d58f23545106934278390446466810991245a9cff2a43"
            .parse()
            .unwrap();

    let http_client = foreign_chain_inspector::build_http_client(
        AVALANCHE_RPC_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let inspector = AvalancheInspector::new(http_client);

    // when
    let extracted_values = inspector
        .extract(
            transaction_id,
            threshold,
            vec![
                AvalancheExtractor::BlockHash,
                AvalancheExtractor::Log { log_index: 0 },
            ],
        )
        .await
        .expect("extract should succeed");

    // then
    assert_eq!(extracted_values.len(), 2);
    assert_eq!(
        extracted_values[0],
        AvalancheExtractedValue::BlockHash(expected_block_hash)
    );
    assert_matches!(extracted_values[1], AvalancheExtractedValue::Log(_));
}

/// As shipped in `expected_network_fingerprint`.
const EXPECTED_NETWORK_FINGERPRINT: u64 = MAINNET_CHAIN_ID;

#[tokio::test]
#[ignore = "manual test to sanity check against live Avalanche C-Chain RPC provider"]
async fn network_fingerprint_matches_the_shipped_config_value_against_live_rpc_provider() {
    // given
    let http_client = foreign_chain_inspector::build_http_client(
        AVALANCHE_RPC_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let inspector = AvalancheInspector::new(http_client);

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
