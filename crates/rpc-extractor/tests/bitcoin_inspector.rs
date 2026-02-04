use assert_matches::assert_matches;
use mockall::predicate::eq;
use rpc_extractor::bitcoin::inspector::{
    BitcoinExtractedValue, BitcoinExtractor, BitcoinInspector,
};
use rpc_extractor::{
    BlockConfirmations, ForeignChainInspectionError, ForeignChainInspector,
    MockForeignChainRpcClient, RpcError,
    bitcoin::{BitcoinBlockHash, BitcoinRpcResponse, BitcoinTransactionHash},
};

type MockBitcoinRpcClient =
    MockForeignChainRpcClient<BitcoinTransactionHash, BlockConfirmations, BitcoinRpcResponse>;

#[tokio::test]
async fn extract_returns_block_hash_when_confirmations_sufficient() {
    // given
    let tx_id = BitcoinTransactionHash::from([7; 32]);
    let expected_block_hash = BitcoinBlockHash::from([42; 32]);

    let confirmations = BlockConfirmations::from(12u64);
    let threshold = BlockConfirmations::from(6u64);

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
    let error = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await
        .expect_err("extract should fail with insufficient confirmations");

    // then
    assert_matches!(
        error,
        ForeignChainInspectionError::NotEnoughBlockConfirmations {
            expected,
            got
        } if expected == threshold && got == confirmations
    );
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
    let error = inspector
        .extract(tx_id, threshold, vec![BitcoinExtractor::BlockHash])
        .await
        .expect_err("extract should propagate rpc client errors");

    // then
    assert_matches!(
        error,
        ForeignChainInspectionError::RpcClientError(RpcError::ClientError)
    );
}
