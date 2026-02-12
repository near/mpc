use foreign_chain_inspector::{
    EthereumFinality, ForeignChainInspector, RpcAuthentication,
    abstract_chain::{
        AbstractBlockHash, AbstractTransactionHash,
        inspector::{AbstractExtractedValue, AbstractExtractor, AbstractInspector},
    },
};

#[tokio::test]
#[ignore = "manual test to sanity check against live Abstract RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
    // Note: Replace with your actual Abstract RPC endpoint URL
    // Example: QuickNode Abstract endpoint
    const ABSTRACT_RPC_URL: &str = "https://api.testnet.abs.xyz";

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

    let http_client = foreign_chain_inspector::build_http_client(
        ABSTRACT_RPC_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let inspector = AbstractInspector::new(http_client);

    // when
    let extracted_values = inspector
        .extract(
            transaction_id,
            threshold,
            vec![
                AbstractExtractor::BlockHash,
                AbstractExtractor::LogHash { log_index: 1 },
            ],
        )
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions: Vec<AbstractExtractedValue> = vec![
        AbstractExtractedValue::BlockHash(expected_block_hash),
        AbstractExtractedValue::LogHash(
            [
                100, 141, 8, 144, 67, 37, 123, 148, 227, 174, 63, 57, 209, 17, 193, 83, 203, 212,
                185, 179, 204, 105, 77, 40, 210, 74, 91, 102, 127, 197, 227, 222,
            ]
            .into(),
        ),
    ];

    assert_eq!(expected_extractions, extracted_values);
}
