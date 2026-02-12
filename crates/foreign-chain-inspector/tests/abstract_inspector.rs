pub mod common;

use crate::common::FixedResponseRpcClient;

use foreign_chain_inspector::{
    EthereumFinality, ForeignChainInspectionError, ForeignChainInspector, RpcAuthentication,
    abstract_chain::{
        AbstractBlockHash, AbstractTransactionHash,
        inspector::{AbstractExtractedValue, AbstractExtractor, AbstractInspector},
    },
    build_http_client,
};

use assert_matches::assert_matches;
use foreign_chain_rpc_interfaces::evm::{
    GetBlockByNumberResponse, GetTransactionReceiptResponse, H160, H256, Log, U64,
};
use httpmock::prelude::*;
use httpmock::{HttpMockRequest, HttpMockResponse};
use jsonrpsee::core::client::error::Error as RpcClientError;
use rstest::rstest;
use std::sync::atomic::{AtomicUsize, Ordering};

#[rstest]
#[tokio::test]
#[case::finalized(EthereumFinality::Finalized)]
#[case::safe(EthereumFinality::Safe)]
async fn extract_returns_block_hash_when_finalized(#[case] finality: EthereumFinality) {
    // given
    let tx_id = AbstractTransactionHash::from([3; 32]);
    let expected_block_hash = AbstractBlockHash::from([4; 32]);

    let block_response = GetBlockByNumberResponse {
        number: U64::from(100),
    };
    let tx_response = GetTransactionReceiptResponse {
        block_hash: H256::from([4; 32]),
        block_number: U64::from(90),
        status: U64::one(),
        logs: vec![test_log()],
    };

    let mock_client = mock_abstract_client(block_response, tx_response);
    let inspector = AbstractInspector::new(mock_client);

    // when
    let extracted_values = inspector
        .extract(tx_id, finality, vec![AbstractExtractor::BlockHash])
        .await
        .unwrap();

    // then
    let expected_extractions = vec![AbstractExtractedValue::BlockHash(expected_block_hash)];
    assert_eq!(expected_extractions, extracted_values);
}

#[tokio::test]
async fn extract_returns_block_hash_when_finality_block_equals_tx_block() {
    // given
    let tx_id = AbstractTransactionHash::from([3; 32]);
    let expected_block_hash = AbstractBlockHash::from([4; 32]);

    let block_number = U64::from(50);
    let block_response = GetBlockByNumberResponse {
        number: block_number,
    };
    let tx_response = GetTransactionReceiptResponse {
        block_hash: H256::from([4; 32]),
        block_number,
        status: U64::one(),
        logs: vec![test_log()],
    };

    let mock_client = mock_abstract_client(block_response, tx_response);
    let inspector = AbstractInspector::new(mock_client);

    // when
    let extracted_values = inspector
        .extract(
            tx_id,
            EthereumFinality::Finalized,
            vec![AbstractExtractor::BlockHash],
        )
        .await
        .unwrap();

    // then
    let expected_extractions = vec![AbstractExtractedValue::BlockHash(expected_block_hash)];
    assert_eq!(expected_extractions, extracted_values);
}

#[tokio::test]
async fn extract_returns_error_when_not_finalized() {
    // given
    let tx_id = AbstractTransactionHash::from([1; 32]);

    let block_response = GetBlockByNumberResponse {
        number: U64::from(50),
    };
    let tx_response = GetTransactionReceiptResponse {
        block_hash: H256::from([2; 32]),
        block_number: U64::from(60), // tx block > finalized block
        status: U64::one(),
        logs: vec![test_log()],
    };

    let mock_client = mock_abstract_client(block_response, tx_response);
    let inspector = AbstractInspector::new(mock_client);

    // when
    let response = inspector
        .extract(
            tx_id,
            EthereumFinality::Finalized,
            vec![AbstractExtractor::BlockHash],
        )
        .await;

    // then
    assert_matches!(response, Err(ForeignChainInspectionError::NotFinalized));
}

#[tokio::test]
async fn extract_returns_error_when_transaction_failed() {
    // given
    let tx_id = AbstractTransactionHash::from([1; 32]);

    let block_response = GetBlockByNumberResponse {
        number: U64::from(100),
    };
    let tx_response = GetTransactionReceiptResponse {
        block_hash: H256::from([2; 32]),
        block_number: U64::from(90),
        status: U64::zero(), // failed transaction
        logs: vec![test_log()],
    };

    let mock_client = mock_abstract_client(block_response, tx_response);
    let inspector = AbstractInspector::new(mock_client);

    // when
    let response = inspector
        .extract(
            tx_id,
            EthereumFinality::Finalized,
            vec![AbstractExtractor::BlockHash],
        )
        .await;

    // then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::TransactionFailed)
    );
}

#[tokio::test]
async fn extract_returns_empty_when_no_extractors_provided() {
    // given
    let tx_id = AbstractTransactionHash::from([11; 32]);

    let block_response = GetBlockByNumberResponse {
        number: U64::from(100),
    };
    let tx_response = GetTransactionReceiptResponse {
        block_hash: H256::from([12; 32]),
        block_number: U64::from(90),
        status: U64::one(),
        logs: vec![test_log()],
    };

    let mock_client = mock_abstract_client(block_response, tx_response);
    let inspector = AbstractInspector::new(mock_client);

    // when
    let extracted_values = inspector
        .extract(tx_id, EthereumFinality::Finalized, Vec::new())
        .await
        .unwrap();

    // then
    let expected_extractions: Vec<AbstractExtractedValue> = vec![];
    assert_eq!(expected_extractions, extracted_values);
}

#[tokio::test]
async fn extract_propagates_rpc_client_errors() {
    // given
    let tx_id = AbstractTransactionHash::from([9; 32]);

    let mock_client = FixedResponseRpcClient::new(|| {
        Err(RpcClientError::Transport(Box::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ))))
    });
    let inspector = AbstractInspector::new(mock_client);

    // when
    let response = inspector
        .extract(
            tx_id,
            EthereumFinality::Finalized,
            vec![AbstractExtractor::BlockHash],
        )
        .await;

    // then
    assert_matches!(response, Err(ForeignChainInspectionError::ClientError(_)));
}

#[tokio::test]
async fn inspector_extracts_block_hash_via_http_rpc_client() {
    // given
    let server = MockServer::start();

    let tx_id = AbstractTransactionHash::from([9; 32]);
    let expected_block_hash = AbstractBlockHash::from([5; 32]);

    let block_response = GetBlockByNumberResponse {
        number: U64::from(100),
    };

    let tx_response = GetTransactionReceiptResponse {
        block_hash: H256::from([5; 32]),
        block_number: U64::from(90),
        status: U64::one(),
        logs: vec![test_log()],
    };

    // Single mock that dispatches on the JSON-RPC method and echoes back the request ID.
    server.mock(|when, then| {
        when.method(POST).path("/");
        then.respond_with(move |req: &HttpMockRequest| {
            let body: serde_json::Value =
                serde_json::from_slice(req.body().as_ref()).expect("valid json-rpc request");
            let id = body["id"].clone();
            let method = body["method"].as_str().expect("method field");

            let result = match method {
                "eth_getBlockByNumber" => serde_json::to_value(&block_response).unwrap(),
                "eth_getTransactionReceipt" => serde_json::to_value(&tx_response).unwrap(),
                other => panic!("unexpected RPC method: {other}"),
            };

            let response_body = serde_json::json!({
                "jsonrpc": "2.0",
                "result": result,
                "id": id,
            });

            HttpMockResponse::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(serde_json::to_string(&response_body).unwrap())
                .build()
        });
    });

    let client = build_http_client(server.url("/"), RpcAuthentication::KeyInUrl).unwrap();
    let inspector = AbstractInspector::new(client);

    // when
    let extracted_values = inspector
        .extract(
            tx_id,
            EthereumFinality::Finalized,
            vec![AbstractExtractor::BlockHash],
        )
        .await
        .unwrap();

    // then
    let expected_extractions = vec![AbstractExtractedValue::BlockHash(expected_block_hash)];
    assert_eq!(expected_extractions, extracted_values);
}

// TODO(#2024): change FixedResponseRpcClient to support multiple expectations to avoid this hacky wrapper.
fn mock_abstract_client(
    block_response: GetBlockByNumberResponse,
    tx_response: GetTransactionReceiptResponse,
) -> FixedResponseRpcClient<impl Fn() -> Result<serde_json::Value, RpcClientError>> {
    let call_count = AtomicUsize::new(0);
    FixedResponseRpcClient::new(move || {
        let count = call_count.fetch_add(1, Ordering::SeqCst);
        match count {
            0 => Ok(serde_json::to_value(&block_response).unwrap()),
            1 => Ok(serde_json::to_value(&tx_response).unwrap()),
            _ => panic!("unexpected third RPC call"),
        }
    })
}

fn test_log() -> Log {
    Log {
        removed: false,
        log_index: U64([1]),
        transaction_index: U64([2]),
        transaction_hash: H256([3; 32]),
        block_hash: H256([4; 32]),
        block_number: U64([5]),
        address: H160([6; 20]),
        data: "test_log".to_string(),
        topics: vec![H256([7; 32]), H256([8; 32])],
    }
}
