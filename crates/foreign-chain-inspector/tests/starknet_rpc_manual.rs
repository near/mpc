use foreign_chain_inspector::{
    ForeignChainInspector, RpcAuthentication,
    starknet::{
        StarknetBlockHash, StarknetExtractedValue, StarknetTransactionHash,
        inspector::{StarknetExtractor, StarknetFinality, StarknetInspector},
    },
};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClient;
use rstest::rstest;
use serde::Deserialize;

const PUBLIC_NODE_URL: &str = "https://starknet-rpc.publicnode.com";

/// A known L1-finalized Starknet mainnet tx in block 6_868_546.
/// https://starkscan.co/tx/0x52a6c2b9d1d1b77dbc322b298fd91f39e3cca9bf1db4a7aa79f14a90efa633e
const FINALIZED_TX_HASH: &str = "0x52a6c2b9d1d1b77dbc322b298fd91f39e3cca9bf1db4a7aa79f14a90efa633e";
const FINALIZED_BLOCK_HASH: &str =
    "0x1b716b05027567f9f4a2fe37f8769dc3b04a2e5a3893f6e0ed45f24c7c0ffa5";

/// `None` for both `tx_hash`/`expected_block_hash` means "resolve at runtime from
/// the live `starknet_getBlockWithTxHashes("latest")` lookup"; both `Some` means
/// "use these hardcoded constants for a known L1-finalized mainnet tx."
#[rstest]
#[case::latest(None, None, StarknetFinality::AcceptedOnL2)]
#[case::finalized(
    Some(FINALIZED_TX_HASH),
    Some(FINALIZED_BLOCK_HASH),
    StarknetFinality::AcceptedOnL1
)]
#[ignore = "manual test: extract block hash against live RPC provider"]
#[tokio::test]
async fn inspector_extracts_block_hash_against_live_rpc_provider(
    #[case] tx_hash: Option<&'static str>,
    #[case] expected_block_hash: Option<&'static str>,
    #[case] finality: StarknetFinality,
) {
    // given
    let http_client = foreign_chain_inspector::build_http_client(
        PUBLIC_NODE_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let (transaction_id, expected_block_hash) =
        resolve_input(&http_client, tx_hash, expected_block_hash).await;
    let inspector = StarknetInspector::new(http_client);

    // when
    let extracted_values = inspector
        .extract(transaction_id, finality, vec![StarknetExtractor::BlockHash])
        .await
        .expect("extract should succeed");

    // then
    assert_eq!(
        vec![StarknetExtractedValue::BlockHash(expected_block_hash)],
        extracted_values,
    );
}

async fn resolve_input(
    http_client: &HttpClient,
    tx_hash: Option<&str>,
    expected_block_hash: Option<&str>,
) -> (StarknetTransactionHash, StarknetBlockHash) {
    match (tx_hash, expected_block_hash) {
        (Some(tx_hash), Some(block_hash)) => (
            parse_starknet_felt_hash(tx_hash)
                .expect("transaction hash should be valid starknet felt hex"),
            parse_starknet_felt_hash(block_hash)
                .expect("block hash should be valid starknet felt hex"),
        ),
        (None, None) => {
            let latest_block: LatestBlockWithTxHashesResponse = http_client
                .request("starknet_getBlockWithTxHashes", ("latest",))
                .await
                .expect("latest block should be fetched");
            let first_transaction_hash = latest_block
                .transactions
                .first()
                .expect("latest block should contain at least one transaction");
            (
                parse_starknet_felt_hash(first_transaction_hash)
                    .expect("transaction hash should be valid starknet felt hex"),
                parse_starknet_felt_hash(&latest_block.block_hash)
                    .expect("block hash should be valid starknet felt hex"),
            )
        }
        _ => panic!("tx_hash and expected_block_hash must both be Some or both None"),
    }
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
