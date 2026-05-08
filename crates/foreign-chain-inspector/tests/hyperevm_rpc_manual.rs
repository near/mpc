use assert_matches::assert_matches;
use foreign_chain_inspector::{
    EthereumFinality, ForeignChainInspector, RpcAuthentication,
    hyperevm::{
        HyperEvmBlockHash, HyperEvmTransactionHash,
        inspector::{HyperEvmExtractedValue, HyperEvmExtractor, HyperEvmInspector},
    },
};

#[tokio::test]
#[ignore = "manual test to sanity check against live HyperEVM RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
    const HYPEREVM_RPC_URL: &str = "https://rpc.hyperliquid.xyz/evm";

    let threshold = EthereumFinality::Finalized;

    // Example transaction on HyperEVM (block 0x20c6dc5) with 3 logs;
    // https://hyperevmscan.io/tx/0x4d94e2c9c33c533f125bd28a788e80ee24c108356e8fa8a7878f642cf94dcf4a
    let transaction_id: HyperEvmTransactionHash =
        "4d94e2c9c33c533f125bd28a788e80ee24c108356e8fa8a7878f642cf94dcf4a"
            .parse()
            .unwrap();
    let expected_block_hash: HyperEvmBlockHash =
        "657b2ee81add87e3f654840425baca06a06d5876f6d2d873197e70f00f6762e6"
            .parse()
            .unwrap();

    let http_client = foreign_chain_inspector::build_http_client(
        HYPEREVM_RPC_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let inspector = HyperEvmInspector::new(
        near_mpc_bounded_collections::NonEmptyVec::from_vec(vec![http_client]).unwrap(),
    );

    // when
    let extracted_values = inspector
        .extract(
            transaction_id,
            threshold,
            vec![
                HyperEvmExtractor::BlockHash,
                HyperEvmExtractor::Log { log_index: 0 },
                HyperEvmExtractor::Log { log_index: 1 },
                HyperEvmExtractor::Log { log_index: 2 },
            ],
        )
        .await
        .expect("extract should succeed");

    // then
    assert_eq!(extracted_values.len(), 4);
    assert_eq!(
        extracted_values[0],
        HyperEvmExtractedValue::BlockHash(expected_block_hash)
    );
    assert_matches!(extracted_values[1], HyperEvmExtractedValue::Log(_));
    assert_matches!(extracted_values[2], HyperEvmExtractedValue::Log(_));
    assert_matches!(extracted_values[3], HyperEvmExtractedValue::Log(_));
}
