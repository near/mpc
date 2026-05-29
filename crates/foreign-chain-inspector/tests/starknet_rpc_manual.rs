use foreign_chain_inspector::{
    ForeignChainInspector, RpcAuthentication,
    starknet::{
        StarknetBlockHash, StarknetExtractedValue, StarknetTransactionHash,
        inspector::{StarknetExtractor, StarknetFinality, StarknetInspector},
    },
};
use jsonrpsee::core::client::ClientT;
use serde::Deserialize;

const PUBLIC_NODE_URL: &str = "https://starknet-rpc.publicnode.com";

#[tokio::test]
#[ignore = "manual test: extract block hash from the latest block against live RPC provider"]
async fn inspector_extracts_latest_block_hash_against_live_rpc_provider() {
    // given
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

/// Happy-path smoke test driving `extract()` end-to-end against a real RPC
/// for an L1-finalized tx: receipt fetch, finality check, canonical-chain
/// re-fetch, and block-hash extraction. A correctly-behaving Starknet node
/// never returns a side-block receipt, so a live RPC can't exercise the
/// canonical-chain failure path — that path is covered by the mocked unit
/// tests.
#[tokio::test]
#[ignore = "manual test: extract block hash for a hardcoded L1-finalized tx against live RPC provider"]
async fn inspector_extracts_block_hash_for_finalized_tx_against_live_rpc_provider() {
    // given: a known L1-finalized Starknet mainnet tx in block 6_868_546.
    // https://starkscan.co/tx/0x52a6c2b9d1d1b77dbc322b298fd91f39e3cca9bf1db4a7aa79f14a90efa633e
    const FINALIZED_TX_HASH: &str =
        "0x52a6c2b9d1d1b77dbc322b298fd91f39e3cca9bf1db4a7aa79f14a90efa633e";
    const FINALIZED_BLOCK_HASH: &str =
        "0x1b716b05027567f9f4a2fe37f8769dc3b04a2e5a3893f6e0ed45f24c7c0ffa5";

    let transaction_id: StarknetTransactionHash = parse_starknet_felt_hash(FINALIZED_TX_HASH)
        .expect("transaction hash should be valid starknet felt hex");
    let expected_block_hash: StarknetBlockHash = parse_starknet_felt_hash(FINALIZED_BLOCK_HASH)
        .expect("block hash should be valid starknet felt hex");

    let http_client = foreign_chain_inspector::build_http_client(
        PUBLIC_NODE_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let inspector = StarknetInspector::new(http_client);

    // when: requesting L1 finality drives `extract()` through the finality
    // and canonical-chain code paths end-to-end against a real RPC.
    let extracted_values = inspector
        .extract(
            transaction_id,
            StarknetFinality::AcceptedOnL1,
            vec![StarknetExtractor::BlockHash],
        )
        .await
        .expect("extract should succeed");

    // then
    assert_eq!(
        vec![StarknetExtractedValue::BlockHash(expected_block_hash)],
        extracted_values,
    );
}

#[derive(Debug, Deserialize)]
struct LatestBlockWithTxHashesResponse {
    block_hash: String,
    transactions: Vec<String>,
}

fn parse_starknet_felt_hash<T: core::str::FromStr<Err = mpc_primitives::hash::HashParseError>>(
    value: &str,
) -> Result<T, String> {
    let stripped = value.trim_start_matches("0x");
    if stripped.len() > 64 {
        return Err(format!("felt hash too long: {value}"));
    }
    let padded = format!("{stripped:0>64}");
    padded
        .parse()
        .map_err(|e| format!("invalid felt hash {value}: {e}"))
}
