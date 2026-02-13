use foreign_chain_inspector::{
    ForeignChainInspector, RpcAuthentication,
    starknet::{
        StarknetBlockHash, StarknetExtractedValue, StarknetTransactionHash,
        inspector::{StarknetExtractor, StarknetFinality, StarknetInspector},
    },
};
use jsonrpsee::core::client::ClientT;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct LatestBlockWithTxHashesResponse {
    block_hash: String,
    transactions: Vec<String>,
}

#[tokio::test]
#[ignore = "manual test to sanity check against live RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
    // Public Starknet mainnet endpoint
    const PUBLIC_NODE_URL: &str = "https://starknet-rpc.publicnode.com";

    let http_client = foreign_chain_inspector::build_http_client(
        PUBLIC_NODE_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let latest_block: LatestBlockWithTxHashesResponse = http_client
        .request("starknet_getBlockWithTxHashes", ("latest",))
        .await
        .expect("latest block should be fetched");
    let first_transaction_hash = latest_block
        .transactions
        .first()
        .expect("latest block should contain at least one transaction");

    let transaction_id: StarknetTransactionHash = first_transaction_hash
        .trim_start_matches("0x")
        .parse()
        .expect("transaction hash should be valid hex");
    let block_hash: StarknetBlockHash = latest_block
        .block_hash
        .trim_start_matches("0x")
        .parse()
        .expect("block hash should be valid hex");
    let inspector = StarknetInspector::new(http_client);

    // when
    let extracted_values = inspector
        .extract(
            transaction_id,
            StarknetFinality::AcceptedOnL2,
            vec![StarknetExtractor::BlockHash],
        )
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions: Vec<StarknetExtractedValue> =
        vec![StarknetExtractedValue::BlockHash(block_hash)];

    assert_eq!(expected_extractions, extracted_values);
}
