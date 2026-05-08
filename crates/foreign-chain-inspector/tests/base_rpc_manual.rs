use assert_matches::assert_matches;
use foreign_chain_inspector::{
    EthereumFinality, ForeignChainInspector, RpcAuthentication,
    base::{
        BaseBlockHash, BaseTransactionHash,
        inspector::{BaseExtractedValue, BaseExtractor, BaseInspector},
    },
};

#[tokio::test]
#[ignore = "manual test to sanity check against live Base RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
    const BASE_RPC_URL: &str = "https://mainnet.base.org";

    let threshold = EthereumFinality::Finalized;

    // Example transaction on Base mainnet (block 33554432) with 16 logs;
    // https://basescan.org/tx/0xa11eaa1236e80f26ddc7aca164f2ba4c6c2726405cb12b1aa8f52c520bad99e1
    let transaction_id: BaseTransactionHash =
        "a11eaa1236e80f26ddc7aca164f2ba4c6c2726405cb12b1aa8f52c520bad99e1"
            .parse()
            .unwrap();
    let expected_block_hash: BaseBlockHash =
        "b8488c9272c547c45e63ea76cc2d1c927c8f888e2721f790b14db996b6cc6aca"
            .parse()
            .unwrap();

    let http_client = foreign_chain_inspector::build_http_client(
        BASE_RPC_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let inspector = BaseInspector::new(
        near_mpc_bounded_collections::NonEmptyVec::from_vec(vec![http_client]).unwrap(),
    );

    // when
    let extracted_values = inspector
        .extract(
            transaction_id,
            threshold,
            vec![
                BaseExtractor::BlockHash,
                BaseExtractor::Log { log_index: 0 },
                BaseExtractor::Log { log_index: 1 },
                BaseExtractor::Log { log_index: 2 },
            ],
        )
        .await
        .expect("extract should succeed");

    // then
    assert_eq!(extracted_values.len(), 4);
    assert_eq!(
        extracted_values[0],
        BaseExtractedValue::BlockHash(expected_block_hash)
    );
    assert_matches!(extracted_values[1], BaseExtractedValue::Log(_));
    assert_matches!(extracted_values[2], BaseExtractedValue::Log(_));
    assert_matches!(extracted_values[3], BaseExtractedValue::Log(_));
}
