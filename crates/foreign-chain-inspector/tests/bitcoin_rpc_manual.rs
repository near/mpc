use foreign_chain_inspector::{
    BlockConfirmations, ForeignChainInspector, RpcAuthentication,
    bitcoin::{
        BitcoinBlockHash, BitcoinExtractedValue, BitcoinTransactionHash,
        inspector::{BitcoinExtractor, BitcoinInspector},
    },
};
use jsonrpsee::{core::client::ClientT, http_client::HttpClient};
use rstest::rstest;
use serde::Deserialize;

const PUBLIC_NODE_URL: &str = "https://bitcoin-rpc.publicnode.com";

/// A known mainnet tx and the block that contains it, taken from mempool.space:
/// <https://mempool.space/tx/58ee376171bcc4e2cc040c13848d420b5eaf2f634872055b0a08c1fc2ec6453c>
const CONFIRMED_TX_HASH: &str = "58ee376171bcc4e2cc040c13848d420b5eaf2f634872055b0a08c1fc2ec6453c";
const CONFIRMED_BLOCK_HASH: &str =
    "00000000000000000001fadaf3f8591e071c202762193cf78e389ea691f2ecab";

/// How far below the chain tip to pick the "latest" block, so it has enough confirmations
/// to pass the threshold and is firmly on the canonical chain (not a tip that might reorg).
const LATEST_BLOCK_DEPTH: u64 = 6;

/// `None` for both `tx_hash`/`expected_block_hash` means "resolve at runtime from a recent
/// canonical block"; both `Some` means "use these hardcoded constants for a known confirmed
/// mainnet tx". The call exercises the canonical-chain check end-to-end against a live node.
#[rstest]
#[case::latest(None, None)]
#[case::confirmed(Some(CONFIRMED_TX_HASH), Some(CONFIRMED_BLOCK_HASH))]
#[ignore = "manual test: exercises block-hash extraction and the canonical-chain check against a live Bitcoin RPC provider"]
#[tokio::test]
async fn inspector_extracts_block_hash_against_live_rpc_provider(
    #[case] tx_hash: Option<&'static str>,
    #[case] expected_block_hash: Option<&'static str>,
) {
    // given
    let http_client = foreign_chain_inspector::build_http_client(
        PUBLIC_NODE_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let (transaction_id, expected_block_hash) =
        resolve_input(&http_client, tx_hash, expected_block_hash).await;
    let threshold = BlockConfirmations::from(1);
    let inspector = BitcoinInspector::new(http_client);

    // when
    let extracted_values = inspector
        .extract(transaction_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await
        .expect("extract should succeed");

    // then
    assert_eq!(
        vec![BitcoinExtractedValue::BlockHash(expected_block_hash)],
        extracted_values,
    );
}

/// Resolves the (transaction, block hash) input for a case, either from the hardcoded
/// constants or — for the `latest` case — from a recent canonical block looked up live:
/// `getblockchaininfo` → step back `LATEST_BLOCK_DEPTH` → `getblockhash(height)` →
/// `getblock(hash)` to pull a transaction id out of that block.
async fn resolve_input(
    http_client: &HttpClient,
    tx_hash: Option<&str>,
    expected_block_hash: Option<&str>,
) -> (BitcoinTransactionHash, BitcoinBlockHash) {
    match (tx_hash, expected_block_hash) {
        (Some(tx_hash), Some(block_hash)) => (
            tx_hash.parse().expect("tx hash should be valid hex"),
            block_hash.parse().expect("block hash should be valid hex"),
        ),
        (None, None) => {
            let chain_info: GetBlockchainInfoResponse = http_client
                .request(
                    "getblockchaininfo",
                    jsonrpsee::core::params::ArrayParams::new(),
                )
                .await
                .expect("getblockchaininfo should succeed");
            let target_height = chain_info
                .blocks
                .checked_sub(LATEST_BLOCK_DEPTH)
                .expect("chain tip should be deeper than LATEST_BLOCK_DEPTH");

            let block_hash: String = http_client
                .request("getblockhash", (target_height,))
                .await
                .expect("getblockhash should succeed");

            // Verbosity 1 returns the block with its transaction-id list.
            let block: GetBlockVerbosityOneResponse = http_client
                .request("getblock", (&block_hash, 1))
                .await
                .expect("getblock should succeed");
            let tx_hash = block
                .tx
                .first()
                .expect("block should contain at least one transaction");

            (
                tx_hash.parse().expect("tx hash should be valid hex"),
                block_hash.parse().expect("block hash should be valid hex"),
            )
        }
        _ => panic!("tx_hash and expected_block_hash must both be Some or both None"),
    }
}

#[derive(Debug, Deserialize)]
struct GetBlockchainInfoResponse {
    /// Height of the most-work fully-validated chain (the canonical tip).
    blocks: u64,
}

#[derive(Debug, Deserialize)]
struct GetBlockVerbosityOneResponse {
    tx: Vec<String>,
}
