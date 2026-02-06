use foreign_chain_inspector::{
    BlockConfirmations, ForeignChainInspector, RpcAuthentication,
    abstract_chain::{
        AbstractBlockHash, AbstractTransactionHash,
        inspector::{AbstractExtractedValue, AbstractExtractor, AbstractInspector},
        rpc_client::AbstractRpcClient,
    },
};

#[tokio::test]
#[ignore = "manual test to sanity check against live Abstract RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
    // Note: Replace with your actual Abstract RPC endpoint URL
    // Example: QuickNode Abstract endpoint
    const ABSTRACT_RPC_URL: &str = "https://api.testnet.abs.xyz";

    let threshold = BlockConfirmations::from(1);

    // Example transaction from Abstract testnet
    // https://explorer.mainnet.abs.xyz/tx/0x28a3cae05b6a489e104407e38b9e273f3989e21eaf68363c2f552d20204b8c99
    let transaction_id: AbstractTransactionHash =
        "497fc5f5b5d81d6bc15cccc6d4d8be8ef6ad19376233b944a60dc435593f7234"
            .parse()
            .unwrap();
    let expected_block_hash: AbstractBlockHash =
        "d327a3242a687dea34f119cca57045c29f31b7ac82059c021c6c86af75caa865"
            .parse()
            .unwrap();

    let http_client = foreign_chain_inspector::build_http_client(
        ABSTRACT_RPC_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let client = AbstractRpcClient::new(http_client);
    let inspector = AbstractInspector::new(client);

    // when
    let extracted_values = inspector
        .extract(
            transaction_id,
            threshold,
            vec![AbstractExtractor::BlockHash],
        )
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions: Vec<AbstractExtractedValue> =
        vec![AbstractExtractedValue::BlockHash(expected_block_hash)];

    assert_eq!(expected_extractions, extracted_values);
}
