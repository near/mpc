use assert_matches::assert_matches;
use foreign_chain_inspector::Verdict;
use foreign_chain_inspector::{
    EthereumFinality, ForeignChainInspector, NetworkFingerprintInspector, RpcAuthentication,
    adi::{
        AdiBlockHash, AdiTransactionHash, MAINNET_CHAIN_ID,
        inspector::{AdiExtractedValue, AdiExtractor, AdiInspector},
    },
};

const ADI_RPC_URL: &str = "https://rpc.adifoundation.ai";

#[tokio::test]
#[ignore = "manual test to sanity check against live ADI Chain RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
    let threshold = EthereumFinality::Finalized;

    // Example transaction on ADI Chain (block 0x186a0) with 17 logs;
    // https://explorer.adifoundation.ai/tx/0xdf89849ce8e1b4cf390560395198a10f1bd0498822c6880346a8ce28869ec8e5
    let transaction_id: AdiTransactionHash =
        "df89849ce8e1b4cf390560395198a10f1bd0498822c6880346a8ce28869ec8e5"
            .parse()
            .unwrap();
    let expected_block_hash: AdiBlockHash =
        "e49e64cb14a417a1356929043dc87559c57afb540492bc62c8c0d8270902f5c2"
            .parse()
            .unwrap();

    let http_client = foreign_chain_inspector::build_http_client(
        ADI_RPC_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let inspector = AdiInspector::new(http_client);

    // when
    let extracted_values = inspector
        .extract(
            transaction_id,
            threshold,
            vec![
                AdiExtractor::BlockHash,
                AdiExtractor::Log { log_index: 0 },
                AdiExtractor::Log { log_index: 1 },
                AdiExtractor::Log { log_index: 2 },
            ],
        )
        .await
        .expect("extract should succeed");
    let Verdict::Extracted(extracted_values) = extracted_values else {
        panic!("expected extracted values, got: {extracted_values}");
    };

    // then
    assert_eq!(extracted_values.len(), 4);
    assert_eq!(
        extracted_values[0],
        AdiExtractedValue::BlockHash(expected_block_hash)
    );
    assert_matches!(extracted_values[1], AdiExtractedValue::Log(_));
    assert_matches!(extracted_values[2], AdiExtractedValue::Log(_));
    assert_matches!(extracted_values[3], AdiExtractedValue::Log(_));
}

/// As shipped in `expected_network_fingerprint`.
const EXPECTED_NETWORK_FINGERPRINT: u64 = MAINNET_CHAIN_ID;

#[tokio::test]
#[ignore = "manual test to sanity check against live ADI Chain RPC provider"]
async fn network_fingerprint_matches_the_shipped_config_value_against_live_rpc_provider() {
    // given
    let http_client = foreign_chain_inspector::build_http_client(
        ADI_RPC_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let inspector = AdiInspector::new(http_client);

    // when
    let fingerprint = inspector
        .network_fingerprint()
        .await
        .expect("network_fingerprint should succeed");

    // then
    assert_eq!(
        fingerprint.to_string(),
        EXPECTED_NETWORK_FINGERPRINT.to_string()
    );
}
