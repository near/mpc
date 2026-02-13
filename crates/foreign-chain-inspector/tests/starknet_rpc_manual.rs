use foreign_chain_inspector::{
    ForeignChainInspector, RpcAuthentication,
    starknet::{
        StarknetBlockHash, StarknetExtractedValue, StarknetTransactionHash,
        inspector::{StarknetExtractor, StarknetFinality, StarknetInspector},
    },
};

#[tokio::test]
#[ignore = "manual test to sanity check against live RPC provider"]
async fn inspector_extracts_block_hash_against_live_rpc_provider() {
    // given
    // Free Nethermind Starknet mainnet endpoint
    const PUBLIC_NODE_URL: &str = "https://free-rpc.nethermind.io/mainnet-juno/";

    // Transaction from Starknet mainnet
    // https://starkscan.co/tx/0x06a0667e38abecc19e1443c5b82b46de8a80e69ee39025b9fb49aee6b97f52d2
    let transaction_id: StarknetTransactionHash =
        "06a0667e38abecc19e1443c5b82b46de8a80e69ee39025b9fb49aee6b97f52d2"
            .parse()
            .unwrap();
    let block_hash: StarknetBlockHash =
        "035120c1ce63c27f0e3e7f612e1b54b08c0c4b04c463a3a98a8e95fa9ee6b78e"
            .parse()
            .unwrap();

    let http_client = foreign_chain_inspector::build_http_client(
        PUBLIC_NODE_URL.to_string(),
        RpcAuthentication::KeyInUrl,
    )
    .unwrap();
    let inspector = StarknetInspector::new(http_client);

    // when
    let extracted_values = inspector
        .extract(
            transaction_id,
            StarknetFinality::AcceptedOnL1,
            vec![StarknetExtractor::BlockHash],
        )
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions: Vec<StarknetExtractedValue> =
        vec![StarknetExtractedValue::BlockHash(block_hash)];

    assert_eq!(expected_extractions, extracted_values);
}
