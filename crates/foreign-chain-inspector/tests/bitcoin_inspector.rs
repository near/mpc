use foreign_chain_inspector::{
    BlockConfirmations, ForeignChainInspectionError, ForeignChainInspector, ForeignChainRpcClient,
    RpcAuthentication, RpcError,
    bitcoin::{
        BitcoinBlockHash, BitcoinRpcResponse, BitcoinTransactionHash,
        inspector::{BitcoinExtractedValue, BitcoinExtractor, BitcoinInspector},
        rpc_client::BitcoinCoreRpcClient,
    },
};

use assert_matches::assert_matches;
use httpmock::prelude::*;
use mockall::{mock, predicate::eq};
use rstest::rstest;
use serde_json::json;

mock! {
    pub BitcoinRpcClient {}

    impl ForeignChainRpcClient for BitcoinRpcClient {
        type TransactionId = BitcoinTransactionHash;
        type Finality = BlockConfirmations;
        type RpcResponse = BitcoinRpcResponse;

        fn get(
            &self,
            transaction: <Self as ForeignChainRpcClient>::TransactionId,
            finality: <Self as ForeignChainRpcClient>::Finality,
        ) -> impl Future<Output = Result<<Self as foreign_chain_inspector::ForeignChainRpcClient>::RpcResponse, foreign_chain_inspector::RpcError>>;
    }
}

#[rstest]
#[tokio::test]
#[case::confirmations_equals_threshold(BlockConfirmations::from(1), BlockConfirmations::from(1))]
#[case::confirmations_greater_tan_threshold(
    BlockConfirmations::from(1),
    BlockConfirmations::from(2)
)]
async fn extract_returns_block_hash_when_confirmations_sufficient(
    #[case] confirmations: BlockConfirmations,
    #[case] threshold: BlockConfirmations,
) {
    // given
    let tx_id = BitcoinTransactionHash::from([3; 32]);
    let expected_block_hash = BitcoinBlockHash::from([4; 32]);

    let response = BitcoinRpcResponse {
        block_hash: expected_block_hash.clone(),
        confirmations,
    };

    let mut client = MockBitcoinRpcClient::new();
    client
        .expect_get()
        .with(eq(tx_id.clone()), eq(threshold))
        .times(1)
        .returning(move |_, _| {
            let response = response.clone();
            Box::pin(async move { Ok(response) })
        });

    let inspector = BitcoinInspector::new(client);

    // when
    let extracted_values = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions = vec![BitcoinExtractedValue::BlockHash(
        expected_block_hash.clone(),
    )];

    assert_eq!(expected_extractions, extracted_values);
}

#[tokio::test]
async fn extract_returns_error_when_confirmations_insufficient() {
    // given
    let tx_id = BitcoinTransactionHash::from([1; 32]);
    let expected_block_hash = BitcoinBlockHash::from([2; 32]);

    let confirmations = BlockConfirmations::from(2u64);
    let threshold = BlockConfirmations::from(6u64);

    let response = BitcoinRpcResponse {
        block_hash: expected_block_hash,
        confirmations,
    };

    let mut client = MockBitcoinRpcClient::new();
    client
        .expect_get()
        .with(eq(tx_id.clone()), eq(threshold))
        .times(1)
        .returning(move |_, _| {
            let response = response.clone();
            Box::pin(async move { Ok(response) })
        });

    let inspector = BitcoinInspector::new(client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await;

    // then
    let expected_response = Err(ForeignChainInspectionError::NotEnoughBlockConfirmations {
        expected: threshold,
        got: confirmations,
    });

    assert_eq!(response, expected_response);
}

#[tokio::test]
async fn extract_returns_empty_when_no_extractors_provided() {
    // given
    let tx_id = BitcoinTransactionHash::from([11; 32]);
    let expected_block_hash = BitcoinBlockHash::from([12; 32]);

    let confirmations = BlockConfirmations::from(9u64);
    let threshold = BlockConfirmations::from(6u64);

    let response = BitcoinRpcResponse {
        block_hash: expected_block_hash,
        confirmations,
    };

    let mut client = MockBitcoinRpcClient::new();
    client
        .expect_get()
        .with(eq(tx_id.clone()), eq(threshold))
        .times(1)
        .returning(move |_, _| {
            let response = response.clone();
            Box::pin(async move { Ok(response) })
        });

    let inspector = BitcoinInspector::new(client);

    // when
    let extracted_values = inspector
        .extract(tx_id, threshold, Vec::new())
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions: Vec<BitcoinExtractedValue> = vec![];
    assert_eq!(expected_extractions, extracted_values);
}

#[tokio::test]
async fn extract_propagates_rpc_client_errors() {
    // given
    let tx_id = BitcoinTransactionHash::from([9; 32]);
    let threshold = BlockConfirmations::from(1u64);

    let mut client = MockBitcoinRpcClient::new();
    client
        .expect_get()
        .with(eq(tx_id.clone()), eq(threshold))
        .times(1)
        .returning(|_, _| Box::pin(async { Err(RpcError::ClientError) }));

    let inspector = BitcoinInspector::new(client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await;

    // then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::RpcClientError(
            RpcError::ClientError
        ))
    );
}

#[tokio::test]
async fn inspector_extracts_block_hash_via_http_rpc_client() {
    // given
    let server = MockServer::start();

    let tx_id = BitcoinTransactionHash::from([9; 32]);
    let expected_block_hash = BitcoinBlockHash::from([5; 32]);
    let confirmations = 10u64;
    let threshold = BlockConfirmations::from(6u64);

    server.mock(|when, then| {
        when.method(POST).path("/");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "jsonrpc": "2.0",
                "result": {
                    "blockhash": expected_block_hash.as_hex(),
                    "confirmations": confirmations
                },
                "id": 0
            }));
    });

    let client = BitcoinCoreRpcClient::new(server.url("/"), RpcAuthentication::KeyInUrl)
        .expect("Failed to create client");
    let inspector = BitcoinInspector::new(client);

    // when
    let extracted_values = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions = vec![BitcoinExtractedValue::BlockHash(expected_block_hash)];
    assert_eq!(expected_extractions, extracted_values);
}
