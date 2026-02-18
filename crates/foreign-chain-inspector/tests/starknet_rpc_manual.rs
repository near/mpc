use foreign_chain_inspector::{
    ForeignChainInspector, RpcAuthentication,
    starknet::{
        StarknetBlockHash, StarknetExtractedValue, StarknetTransactionHash,
        inspector::{StarknetExtractor, StarknetFinality, StarknetInspector},
    },
};
use jsonrpsee::core::client::ClientT;
use serde::Deserialize;

#[tokio::test]
#[ignore = "manual test to sanity check against live RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
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

    let transaction_id: StarknetTransactionHash = parse_starknet_felt_hash(first_transaction_hash)
        .expect("transaction hash should be valid starknet felt hex");
    let block_hash: StarknetBlockHash = parse_starknet_felt_hash(&latest_block.block_hash)
        .expect("block hash should be valid starknet felt hex");
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

#[derive(Debug, Deserialize)]
struct LatestBlockWithTxHashesResponse {
    block_hash: String,
    transactions: Vec<String>,
}

fn parse_starknet_felt_hash<T>(value: &str) -> Result<mpc_primitives::hash::Hash32<T>, String> {
    let stripped = value.trim_start_matches("0x");
    if stripped.len() > 64 {
        return Err(format!("felt hash too long: {value}"));
    }
    let padded = format!("{stripped:0>64}");
    padded
        .parse()
        .map_err(|e| format!("invalid felt hash {value}: {e}"))
}
