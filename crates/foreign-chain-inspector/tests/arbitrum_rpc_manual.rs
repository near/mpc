use assert_matches::assert_matches;
use foreign_chain_inspector::{
    EthereumFinality, ForeignChainInspector, RpcAuthentication,
    arbitrum::{
        ArbitrumBlockHash, ArbitrumTransactionHash,
        inspector::{ArbitrumExtractedValue, ArbitrumExtractor, ArbitrumInspector},
    },
};

#[tokio::test]
#[ignore = "manual test to sanity check against live Arbitrum RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
    const ARBITRUM_RPC_URL: &str = "https://arb1.arbitrum.io/rpc";

    let threshold = EthereumFinality::Finalized;

    // Example transaction on Arbitrum One with 3 logs;
    // https://arbiscan.io/tx/0x8f1f497285dcf54624cba2c3dd46d13e25fc83466033c139e77e4dce12a1e484
    let transaction_id: ArbitrumTransactionHash =
        "8f1f497285dcf54624cba2c3dd46d13e25fc83466033c139e77e4dce12a1e484"
            .parse()
            .unwrap();
    let expected_block_hash: ArbitrumBlockHash =
        "da0e369bfb9688ca4591604104e4f2953329542bfb3bc0d0c94686b5ad798c1c"
            .parse()
            .unwrap();

    let http_client = foreign_chain_inspector::build_http_client(
        ARBITRUM_RPC_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let inspector = ArbitrumInspector::new(
        near_mpc_bounded_collections::NonEmptyVec::from_vec(vec![http_client]).unwrap(),
    );

    // when
    let extracted_values = inspector
        .extract(
            transaction_id,
            threshold,
            vec![
                ArbitrumExtractor::BlockHash,
                ArbitrumExtractor::Log { log_index: 0 },
                ArbitrumExtractor::Log { log_index: 1 },
                ArbitrumExtractor::Log { log_index: 2 },
            ],
        )
        .await
        .expect("extract should succeed");

    // then
    assert_eq!(extracted_values.len(), 4);
    assert_eq!(
        extracted_values[0],
        ArbitrumExtractedValue::BlockHash(expected_block_hash)
    );
    assert_matches!(extracted_values[1], ArbitrumExtractedValue::Log(_));
    assert_matches!(extracted_values[2], ArbitrumExtractedValue::Log(_));
    assert_matches!(extracted_values[3], ArbitrumExtractedValue::Log(_));
}
