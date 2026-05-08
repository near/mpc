use assert_matches::assert_matches;
use foreign_chain_inspector::{
    EthereumFinality, ForeignChainInspector, RpcAuthentication,
    polygon::{
        PolygonBlockHash, PolygonTransactionHash,
        inspector::{PolygonExtractedValue, PolygonExtractor, PolygonInspector},
    },
};

#[tokio::test]
#[ignore = "manual test to sanity check against live Polygon RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
    const POLYGON_RPC_URL: &str = "https://polygon.drpc.org";

    let threshold = EthereumFinality::Finalized;

    // Example transaction on Polygon (block 0x5276e5d) with 8 logs;
    // https://polygonscan.com/tx/0x7b231f0f5bf36782a48db9b1d89e4613bd00618f03c3c0fba922aa59288e4d38
    let transaction_id: PolygonTransactionHash =
        "7b231f0f5bf36782a48db9b1d89e4613bd00618f03c3c0fba922aa59288e4d38"
            .parse()
            .unwrap();
    let expected_block_hash: PolygonBlockHash =
        "56d98f80b91c9cf9dcda71c63c01ea441d46ba31149c902adfbee97e55ff82a6"
            .parse()
            .unwrap();

    let http_client = foreign_chain_inspector::build_http_client(
        POLYGON_RPC_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let inspector = PolygonInspector::new(
        near_mpc_bounded_collections::NonEmptyVec::from_vec(vec![http_client]).unwrap(),
    );

    // when
    let extracted_values = inspector
        .extract(
            transaction_id,
            threshold,
            vec![
                PolygonExtractor::BlockHash,
                PolygonExtractor::Log { log_index: 0 },
                PolygonExtractor::Log { log_index: 1 },
                PolygonExtractor::Log { log_index: 2 },
            ],
        )
        .await
        .expect("extract should succeed");

    // then
    assert_eq!(extracted_values.len(), 4);
    assert_eq!(
        extracted_values[0],
        PolygonExtractedValue::BlockHash(expected_block_hash)
    );
    assert_matches!(extracted_values[1], PolygonExtractedValue::Log(_));
    assert_matches!(extracted_values[2], PolygonExtractedValue::Log(_));
    assert_matches!(extracted_values[3], PolygonExtractedValue::Log(_));
}
