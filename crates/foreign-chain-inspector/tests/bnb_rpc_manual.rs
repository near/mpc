use assert_matches::assert_matches;
use foreign_chain_inspector::Verdict;
use foreign_chain_inspector::{
    EthereumFinality, ForeignChainInspector, NetworkFingerprintInspector, RpcAuthentication,
    bnb::{
        BnbBlockHash, BnbTransactionHash, MAINNET_CHAIN_ID,
        inspector::{BnbExtractedValue, BnbExtractor, BnbInspector},
    },
};

const BNB_RPC_URL: &str = "https://bsc-rpc.publicnode.com";

#[tokio::test]
#[ignore = "manual test to sanity check against live BNB RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
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
    let Verdict::Extracted(extracted_values) = extracted_values else {
        panic!("expected extracted values, got: {extracted_values}");
    };

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

/// As shipped in `expected_network_fingerprint`.
const EXPECTED_NETWORK_FINGERPRINT: u64 = MAINNET_CHAIN_ID;

#[tokio::test]
#[ignore = "manual test to sanity check against live BNB RPC provider"]
async fn network_fingerprint_matches_the_shipped_config_value_against_live_rpc_provider() {
    // given
    let http_client = foreign_chain_inspector::build_http_client(
        BNB_RPC_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let inspector = BnbInspector::new(http_client);

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
