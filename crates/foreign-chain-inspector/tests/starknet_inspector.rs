#![allow(non_snake_case)]

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
use contract_interface::types::{StarknetFelt, StarknetLog};
use foreign_chain_rpc_interfaces::starknet::{
    GetTransactionReceiptResponse, H256, StarknetEvent, StarknetExecutionStatus,
    StarknetFinalityStatus,
};
use httpmock::prelude::*;
use httpmock::{HttpMockRequest, HttpMockResponse};
use jsonrpsee::core::client::error::Error as RpcClientError;
use rstest::rstest;

fn mock_receipt(
    finality_status: StarknetFinalityStatus,
    execution_status: StarknetExecutionStatus,
) -> GetTransactionReceiptResponse {
    GetTransactionReceiptResponse {
        block_hash: H256::from([4; 32]),
        block_number: 842_750,
        events: vec![StarknetEvent {
            data: vec![H256::from([0xab; 32])],
            from_address: H256::from([0x11; 32]),
            keys: vec![H256::from([0xcc; 32]), H256::from([0xdd; 32])],
        }],
        finality_status,
        execution_status,
    }
}

#[rstest]
#[tokio::test]
#[case::requested_l2_actual_l2(
    StarknetFinality::AcceptedOnL2,
    StarknetFinalityStatus::AcceptedOnL2
)]
#[case::requested_l2_actual_l1(
    StarknetFinality::AcceptedOnL2,
    StarknetFinalityStatus::AcceptedOnL1
)]
#[case::requested_l1_actual_l1(
    StarknetFinality::AcceptedOnL1,
    StarknetFinalityStatus::AcceptedOnL1
)]
async fn extract__should_return_block_hash_when_finality_is_sufficient(
    #[case] requested_finality: StarknetFinality,
    #[case] actual_finality_status: StarknetFinalityStatus,
) {
    // given
    let tx_id = StarknetTransactionHash::from([3; 32]);

    let receipt = mock_receipt(actual_finality_status, StarknetExecutionStatus::Succeeded);
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
async fn extract__should_return_not_finalized_when_finality_is_insufficient() {
    // given
    let tx_id = StarknetTransactionHash::from([1; 32]);

    // Requested L1 but actual is only L2
    let receipt = mock_receipt(
        StarknetFinalityStatus::AcceptedOnL2,
        StarknetExecutionStatus::Succeeded,
    );
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
async fn extract__should_return_client_error_for_received_finality() {
    // given
    let tx_id = StarknetTransactionHash::from([7; 32]);

    let receipt = mock_receipt(
        StarknetFinalityStatus::Received,
        StarknetExecutionStatus::Succeeded,
    );
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
    assert_matches!(response, Err(ForeignChainInspectionError::ClientError(_)));
}

#[tokio::test]
async fn extract__should_return_transaction_failed_when_execution_is_reverted() {
    // given
    let tx_id = StarknetTransactionHash::from([2; 32]);

    let receipt = mock_receipt(
        StarknetFinalityStatus::AcceptedOnL2,
        StarknetExecutionStatus::Reverted,
    );
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
async fn extract__should_return_empty_when_no_extractors_are_requested() {
    // given
    let tx_id = StarknetTransactionHash::from([11; 32]);

    let receipt = mock_receipt(
        StarknetFinalityStatus::AcceptedOnL1,
        StarknetExecutionStatus::Succeeded,
    );
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
async fn extract__should_propagate_rpc_client_errors() {
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
async fn extract__should_return_block_hash_via_http_rpc_client() {
    // given
    let server = MockServer::start();

    let tx_id = StarknetTransactionHash::from([9; 32]);

    let expected_bytes: [u8; 32] = {
        let mut b = [0u8; 32];
        b[31] = 5;
        b
    };

    let receipt = GetTransactionReceiptResponse {
        block_hash: H256::from(expected_bytes),
        block_number: 1_023_456,
        events: vec![StarknetEvent {
            data: vec![H256::from([0x01; 32]), H256::from([0x02; 32])],
            from_address: H256::from([0xff; 32]),
            keys: vec![H256::from([0xaa; 32])],
        }],
        finality_status: StarknetFinalityStatus::AcceptedOnL1,
        execution_status: StarknetExecutionStatus::Succeeded,
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
            vec![
                StarknetExtractor::BlockHash,
                StarknetExtractor::Log { log_index: 0 },
            ],
        )
        .await
        .expect("extract should succeed");

    // then
    let expected_extractions = vec![
        StarknetExtractedValue::BlockHash(expected_block_hash),
        StarknetExtractedValue::Log(StarknetLog {
            block_hash: StarknetFelt(expected_bytes),
            block_number: 1_023_456,
            data: vec![StarknetFelt([0x01; 32]), StarknetFelt([0x02; 32])],
            from_address: StarknetFelt([0xff; 32]),
            keys: vec![StarknetFelt([0xaa; 32])],
        }),
    ];
    assert_eq!(expected_extractions, extracted_values);
}
