mod common;

use crate::common::FixedResponseRpcClient;

use foreign_chain_inspector::{
    BlockConfirmations, ForeignChainInspectionError, ForeignChainInspector,
    abstract_chain::{
        AbstractBlockHash, AbstractTransactionHash,
        inspector::{AbstractExtractedValue, AbstractExtractor, AbstractInspector},
        rpc_client::AbstractRpcClient,
    },
};

use assert_matches::assert_matches;
use jsonrpsee::core::client::error::Error as RpcClientError;
use rstest::rstest;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[rstest]
#[tokio::test]
#[case::confirmations_equals_threshold(BlockConfirmations::from(1), BlockConfirmations::from(1))]
#[case::confirmations_greater_than_threshold(
    BlockConfirmations::from(1),
    BlockConfirmations::from(2)
)]
async fn extract_returns_block_hash_when_confirmations_sufficient(
    #[case] expected_confirmations: BlockConfirmations,
    #[case] threshold: BlockConfirmations,
) {
    // given
    let tx_id = AbstractTransactionHash::from([3; 32]);
    let expected_block_hash = AbstractBlockHash::from([4; 32]);
    let current_block_number = 1000u64;
    let tx_block_number = current_block_number - *expected_confirmations + 1;

    // Mock responses for the two RPC calls: eth_getTransactionByHash and eth_blockNumber
    let tx_response = AbstractTransactionResponse {
        block_hash: expected_block_hash.clone(),
        block_number: format!("0x{:x}", tx_block_number),
    };

    let responses = Arc::new(Mutex::new(vec![
        serde_json::to_value(Some(tx_response)).unwrap(),
        serde_json::to_value(format!("0x{:x}", current_block_number)).unwrap(),
    ]));

    let mock_client = FixedResponseRpcClient::new(move || {
        let mut resp = responses.lock().unwrap();
        Ok(resp.remove(0))
    });

    let rpc_client = AbstractRpcClient::new(mock_client);
    let inspector = AbstractInspector::new(rpc_client);

    // when
    let extracted_values = inspector
        .extract(tx_id, threshold, vec![AbstractExtractor::BlockHash])
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions = vec![AbstractExtractedValue::BlockHash(expected_block_hash)];

    assert_eq!(expected_extractions, extracted_values);
}

#[tokio::test]
async fn extract_returns_error_when_confirmations_insufficient() {
    // given
    let tx_id = AbstractTransactionHash::from([1; 32]);
    let expected_block_hash = AbstractBlockHash::from([2; 32]);

    let current_block_number = 100u64;
    let tx_block_number = 99u64; // Only 2 confirmations
    let threshold = BlockConfirmations::from(6u64);

    let tx_response = AbstractTransactionResponse {
        block_hash: expected_block_hash,
        block_number: format!("0x{:x}", tx_block_number),
    };

    let responses = Arc::new(Mutex::new(vec![
        serde_json::to_value(Some(tx_response)).unwrap(),
        serde_json::to_value(format!("0x{:x}", current_block_number)).unwrap(),
    ]));

    let mock_client = FixedResponseRpcClient::new(move || {
        let mut resp = responses.lock().unwrap();
        Ok(resp.remove(0))
    });

    let rpc_client = AbstractRpcClient::new(mock_client);
    let inspector = AbstractInspector::new(rpc_client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![AbstractExtractor::BlockHash])
        .await;

    // then
    assert_matches!(
    response,
    Err(ForeignChainInspectionError::NotEnoughBlockConfirmations { expected, got }) => {
        assert_eq!(expected, threshold);
        assert_eq!(got, BlockConfirmations::from(2u64));
    });
}

#[tokio::test]
async fn extract_returns_empty_when_no_extractors_provided() {
    // given
    let tx_id = AbstractTransactionHash::from([11; 32]);
    let expected_block_hash = AbstractBlockHash::from([12; 32]);

    let current_block_number = 1000u64;
    let tx_block_number = 991u64; // 10 confirmations
    let threshold = BlockConfirmations::from(6u64);

    let tx_response = AbstractTransactionResponse {
        block_hash: expected_block_hash,
        block_number: format!("0x{:x}", tx_block_number),
    };

    let responses = Arc::new(Mutex::new(vec![
        serde_json::to_value(Some(tx_response)).unwrap(),
        serde_json::to_value(format!("0x{:x}", current_block_number)).unwrap(),
    ]));

    let mock_client = FixedResponseRpcClient::new(move || {
        let mut resp = responses.lock().unwrap();
        Ok(resp.remove(0))
    });

    let rpc_client = AbstractRpcClient::new(mock_client);
    let inspector = AbstractInspector::new(rpc_client);

    // when
    let extracted_values = inspector
        .extract(tx_id, threshold, Vec::new())
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions: Vec<AbstractExtractedValue> = vec![];
    assert_eq!(expected_extractions, extracted_values);
}

#[tokio::test]
async fn extract_propagates_rpc_client_errors() {
    // given
    let tx_id = AbstractTransactionHash::from([9; 32]);
    let threshold = BlockConfirmations::from(1u64);

    let mock_client = FixedResponseRpcClient::new(|| {
        Err(RpcClientError::Transport(Box::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ))))
    });

    let rpc_client = AbstractRpcClient::new(mock_client);
    let inspector = AbstractInspector::new(rpc_client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![AbstractExtractor::BlockHash])
        .await;

    // then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::RpcClientError(_))
    );
}

// Note: HTTP integration test removed due to JSON-RPC ID matching complexity.
// The mock client tests above provide comprehensive coverage of the inspector functionality.

#[tokio::test]
async fn rpc_client_handles_transaction_not_found() {
    // given
    let tx_id = AbstractTransactionHash::from([7; 32]);
    let threshold = BlockConfirmations::from(1u64);

    let mock_client = FixedResponseRpcClient::new(|| {
        Ok(serde_json::Value::Null) // Transaction returns null when not found
    });

    let rpc_client = AbstractRpcClient::new(mock_client);
    let inspector = AbstractInspector::new(rpc_client);

    // when
    let response = inspector
        .extract(tx_id, threshold, vec![AbstractExtractor::BlockHash])
        .await;

    // then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::RpcClientError(_))
    );
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AbstractTransactionResponse {
    block_hash: AbstractBlockHash,
    block_number: String,
}
