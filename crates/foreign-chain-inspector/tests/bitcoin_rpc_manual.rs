use foreign_chain_inspector::{
    BlockConfirmations, ForeignChainInspector, RpcAuthentication,
    bitcoin::{
        BitcoinBlockHash, BitcoinExtractedValue, BitcoinTransactionHash,
        inspector::{BitcoinExtractor, BitcoinInspector},
    },
};

#[tokio::test]
#[ignore = "manual test to sanity check against live RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
    const PUBLIC_NODE_URL: &str = "https://bitcoin-rpc.publicnode.com";

    let threshold = BlockConfirmations::from(1);

    // Transaction taken from mempool space
    // https://mempool.space/tx/58ee376171bcc4e2cc040c13848d420b5eaf2f634872055b0a08c1fc2ec6453c
    let transaction_id: BitcoinTransactionHash =
        "58ee376171bcc4e2cc040c13848d420b5eaf2f634872055b0a08c1fc2ec6453c"
            .parse()
            .unwrap();
    let block_hash: BitcoinBlockHash =
        "00000000000000000001fadaf3f8591e071c202762193cf78e389ea691f2ecab"
            .parse()
            .unwrap();

    let http_client = foreign_chain_inspector::build_http_client(
        PUBLIC_NODE_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let inspector = BitcoinInspector::new(http_client);

    // when
    let extracted_values = inspector
        .extract(transaction_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions: Vec<BitcoinExtractedValue> =
        vec![BitcoinExtractedValue::BlockHash(block_hash)];

    assert_eq!(expected_extractions, extracted_values);
}
