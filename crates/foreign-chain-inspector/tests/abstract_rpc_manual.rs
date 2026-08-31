use assert_matches::assert_matches;
use foreign_chain_inspector::{
    EthereumFinality, ForeignChainInspector, NetworkFingerprintInspector,
    abstract_chain::{
        AbstractBlockHash, AbstractTransactionHash, TESTNET_CHAIN_ID,
        inspector::{AbstractExtractedValue, AbstractExtractor, AbstractInspector},
    },
};
use foreign_chain_rpc_factory::build_http_client;

const ABSTRACT_RPC_URL: &str = "https://api.testnet.abs.xyz";

#[tokio::test]
#[ignore = "manual test to sanity check against live Abstract RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
    let threshold = EthereumFinality::Finalized;

    // Example transaction from Abstract testnet
    // https://explorer.testnet.abs.xyz/tx/0x497fc5f5b5d81d6bc15cccc6d4d8be8ef6ad19376233b944a60dc435593f7234
    let transaction_id: AbstractTransactionHash =
        "497fc5f5b5d81d6bc15cccc6d4d8be8ef6ad19376233b944a60dc435593f7234"
            .parse()
            .unwrap();
    let expected_block_hash: AbstractBlockHash =
        "4c93dd4a8f347e6480b0a44f8c2b7eecdfb31d711e8d542fd60112ea5d98fb02"
            .parse()
            .unwrap();

    let http_client = build_http_client(&mpc_node_config::ForeignChainProviderConfig {
        rpc_url: ABSTRACT_RPC_URL.to_string(),
        auth: mpc_node_config::AuthConfig::None,
    })
    .unwrap();
    let inspector = AbstractInspector::new(http_client);

    // when
    let extracted_values = inspector
        .extract(
            transaction_id,
            threshold,
            vec![
                AbstractExtractor::BlockHash,
                AbstractExtractor::Log { log_index: 1 },
            ],
        )
        .await
        .expect("extract should succeed");

    // then
    assert_eq!(extracted_values.len(), 2);
    assert_eq!(
        extracted_values[0],
        AbstractExtractedValue::BlockHash(expected_block_hash)
    );
    assert_matches!(extracted_values[1], AbstractExtractedValue::Log(_));
}

/// As shipped in `expected_network_fingerprint`.
const EXPECTED_NETWORK_FINGERPRINT: u64 = TESTNET_CHAIN_ID;

#[tokio::test]
#[ignore = "manual test to sanity check against live Abstract RPC provider"]
async fn network_fingerprint_matches_the_shipped_config_value_against_live_rpc_provider() {
    // given
    let http_client = build_http_client(&mpc_node_config::ForeignChainProviderConfig {
        rpc_url: ABSTRACT_RPC_URL.to_string(),
        auth: mpc_node_config::AuthConfig::None,
    })
    .unwrap();
    let inspector = AbstractInspector::new(http_client);

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
