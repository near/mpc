use assert_matches::assert_matches;
use foreign_chain_inspector::{
    EthereumFinality, ForeignChainInspector, RpcAuthentication,
    bnb::{
        BnbBlockHash, BnbTransactionHash,
        inspector::{BnbExtractedValue, BnbExtractor, BnbInspector},
    },
};

#[tokio::test]
#[ignore = "manual test to sanity check against live BNB RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
    const BNB_RPC_URL: &str = "https://bsc-rpc.publicnode.com";

    let threshold = EthereumFinality::Finalized;

    // Example DEX swap transaction on BNB with 3 logs
    // https://bscscan.com/tx/0x90514fff1563dc9876bc9a02a7b1d4dd2ce44b8d11ea0490aa8d427166eba349
    let transaction_id: BnbTransactionHash =
        "90514fff1563dc9876bc9a02a7b1d4dd2ce44b8d11ea0490aa8d427166eba349"
            .parse()
            .unwrap();
    let expected_block_hash: BnbBlockHash =
        "4f125b8e2716df5cbc72719212d5189dae0e49b6b7a44523165cb01888914999"
            .parse()
            .unwrap();

    let http_client = foreign_chain_inspector::build_http_client(
        BNB_RPC_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let inspector = BnbInspector::new(http_client);

    // when
    let extracted_values = inspector
        .extract(
            transaction_id,
            threshold,
            vec![
                BnbExtractor::BlockHash,
                BnbExtractor::Log { log_index: 0 },
                BnbExtractor::Log { log_index: 1 },
                BnbExtractor::Log { log_index: 2 },
            ],
        )
        .await
        .expect("extract should succeed");

    // then
    assert_eq!(extracted_values.len(), 4);
    assert_eq!(
        extracted_values[0],
        BnbExtractedValue::BlockHash(expected_block_hash)
    );
    assert_matches!(extracted_values[1], BnbExtractedValue::Log(_));
    assert_matches!(extracted_values[2], BnbExtractedValue::Log(_));
    assert_matches!(extracted_values[3], BnbExtractedValue::Log(_));
}
