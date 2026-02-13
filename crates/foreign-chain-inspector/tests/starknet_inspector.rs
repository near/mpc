pub mod common;

use crate::common::{FixedResponseRpcClient, mock_client_from_fixed_response};

use foreign_chain_inspector::{
    ForeignChainInspectionError, ForeignChainInspector, RpcAuthentication, build_http_client,
    starknet::{
        StarknetBlockHash, StarknetExtractedValue, StarknetTransactionHash,
        inspector::{StarknetExtractor, StarknetFinality, StarknetInspector},
    },
};

use assert_matches::assert_matches;
use foreign_chain_rpc_interfaces::starknet::GetTransactionReceiptResponse;
use httpmock::prelude::*;
use httpmock::{HttpMockRequest, HttpMockResponse};
use jsonrpsee::core::client::error::Error as RpcClientError;
use rstest::rstest;

fn mock_receipt(finality_status: &str, execution_status: &str) -> GetTransactionReceiptResponse {
    GetTransactionReceiptResponse {
        block_hash: "0x04a5e07b39584018ec".to_string(),
        finality_status: finality_status.to_string(),
        execution_status: execution_status.to_string(),
    }
}

#[rstest]
#[tokio::test]
#[case::requested_l2_actual_l2(StarknetFinality::AcceptedOnL2, "ACCEPTED_ON_L2")]
#[case::requested_l2_actual_l1(StarknetFinality::AcceptedOnL2, "ACCEPTED_ON_L1")]
#[case::requested_l1_actual_l1(StarknetFinality::AcceptedOnL1, "ACCEPTED_ON_L1")]
async fn extract_returns_block_hash_when_finality_sufficient(
    #[case] requested_finality: StarknetFinality,
    #[case] actual_finality_status: &str,
) {
    // given
    let tx_id = StarknetTransactionHash::from([3; 32]);

    let receipt = mock_receipt(actual_finality_status, "SUCCEEDED");
    let mock_client = mock_client_from_fixed_response(receipt);
    let inspector = StarknetInspector::new(mock_client);

    // when
    let extracted_values = inspector
        .extract(
            tx_id,
            requested_finality,
            vec![StarknetExtractor::BlockHash],
        )
        .await
        .expect("extract should succeed");

    // then
    assert_eq!(extracted_values.len(), 1);
    assert_matches!(&extracted_values[0], StarknetExtractedValue::BlockHash(_));
}

#[tokio::test]
async fn extract_returns_error_when_finality_insufficient() {
    // given
    let tx_id = StarknetTransactionHash::from([1; 32]);

    // Requested L1 but actual is only L2
    let receipt = mock_receipt("ACCEPTED_ON_L2", "SUCCEEDED");
    let mock_client = mock_client_from_fixed_response(receipt);
    let inspector = StarknetInspector::new(mock_client);

    // when
    let response = inspector
        .extract(
            tx_id,
            StarknetFinality::AcceptedOnL1,
            vec![StarknetExtractor::BlockHash],
        )
        .await;

    // then
    assert_matches!(response, Err(ForeignChainInspectionError::NotFinalized));
}

#[tokio::test]
async fn extract_returns_error_when_execution_reverted() {
    // given
    let tx_id = StarknetTransactionHash::from([2; 32]);

    let receipt = mock_receipt("ACCEPTED_ON_L2", "REVERTED");
    let mock_client = mock_client_from_fixed_response(receipt);
    let inspector = StarknetInspector::new(mock_client);

    // when
    let response = inspector
        .extract(
            tx_id,
            StarknetFinality::AcceptedOnL2,
            vec![StarknetExtractor::BlockHash],
        )
        .await;

    // then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::TransactionFailed)
    );
}

#[tokio::test]
async fn extract_returns_empty_when_no_extractors() {
    // given
    let tx_id = StarknetTransactionHash::from([11; 32]);

    let receipt = mock_receipt("ACCEPTED_ON_L1", "SUCCEEDED");
    let mock_client = mock_client_from_fixed_response(receipt);
    let inspector = StarknetInspector::new(mock_client);

    // when
    let extracted_values = inspector
        .extract(tx_id, StarknetFinality::AcceptedOnL2, Vec::new())
        .await
        .expect("extract should succeed");

    // then
    let expected: Vec<StarknetExtractedValue> = vec![];
    assert_eq!(expected, extracted_values);
}

#[tokio::test]
async fn extract_propagates_rpc_client_errors() {
    // given
    let tx_id = StarknetTransactionHash::from([9; 32]);

    let mock_client = FixedResponseRpcClient::new(|| {
        Err(RpcClientError::Transport(Box::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ))))
    });
    let inspector = StarknetInspector::new(mock_client);

    // when
    let response = inspector
        .extract(
            tx_id,
            StarknetFinality::AcceptedOnL2,
            vec![StarknetExtractor::BlockHash],
        )
        .await;

    // then
    assert_matches!(response, Err(ForeignChainInspectionError::ClientError(_)));
}

#[tokio::test]
async fn inspector_extracts_block_hash_via_http_rpc_client() {
    // given
    let server = MockServer::start();

    let tx_id = StarknetTransactionHash::from([9; 32]);

    let expected_bytes: [u8; 32] = {
        let mut b = [0u8; 32];
        b[31] = 5;
        b
    };

    let receipt = GetTransactionReceiptResponse {
        block_hash: "0x05".to_string(),
        finality_status: "ACCEPTED_ON_L1".to_string(),
        execution_status: "SUCCEEDED".to_string(),
    };

    let expected_block_hash = StarknetBlockHash::from(expected_bytes);

    server.mock(|when, then| {
        when.method(POST).path("/");
        then.respond_with(move |req: &HttpMockRequest| {
            let body: serde_json::Value =
                serde_json::from_slice(req.body().as_ref()).expect("valid json-rpc request");
            let id = body["id"].clone();
            let method = body["method"].as_str().expect("method field");

            assert_eq!(method, "starknet_getTransactionReceipt");

            let result = serde_json::to_value(&receipt).unwrap();

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
    let inspector = StarknetInspector::new(client);

    // when
    let extracted_values = inspector
        .extract(
            tx_id,
            StarknetFinality::AcceptedOnL1,
            vec![StarknetExtractor::BlockHash],
        )
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions = vec![StarknetExtractedValue::BlockHash(expected_block_hash)];
    assert_eq!(expected_extractions, extracted_values);
}
