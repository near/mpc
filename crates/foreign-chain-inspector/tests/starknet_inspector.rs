#![allow(non_snake_case)]

pub mod common;

use crate::common::{
    FixedResponseRpcClient, SequentialResponseMockClientBuilder, mock_client_from_fixed_response,
};

use foreign_chain_inspector::{
    FanOut, ForeignChainInspectionError, ForeignChainInspector, NetworkFingerprintInspector,
    RpcAuthentication, build_http_client,
    starknet::{
        StarknetBlockHash, StarknetExtractedValue, StarknetTransactionHash,
        inspector::{StarknetExtractor, StarknetFinality, StarknetInspector},
    },
};

use assert_matches::assert_matches;
use foreign_chain_rpc_interfaces::starknet::{
    GetBlockWithTxHashesResponse, GetTransactionReceiptResponse, H256, StarknetEvent,
    StarknetExecutionStatus, StarknetFinalityStatus,
};
use httpmock::prelude::*;
use httpmock::{HttpMockRequest, HttpMockResponse};
use jsonrpsee::core::client::error::Error as RpcClientError;
use near_mpc_bounded_collections::NonEmptyVec;
use near_mpc_contract_interface::types::ProviderId;
use near_mpc_contract_interface::types::{StarknetFelt, StarknetLog};
use rstest::rstest;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

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

fn canonical_block_for(receipt: &GetTransactionReceiptResponse) -> GetBlockWithTxHashesResponse {
    GetBlockWithTxHashesResponse {
        block_hash: receipt.block_hash,
        block_number: receipt.block_number,
    }
}

#[rstest]
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
#[tokio::test]
async fn extract__should_return_block_hash_when_finality_is_sufficient(
    #[case] requested_finality: StarknetFinality,
    #[case] actual_finality_status: StarknetFinalityStatus,
) {
    // given
    let tx_id = StarknetTransactionHash::from([3; 32]);

    let receipt = mock_receipt(actual_finality_status, StarknetExecutionStatus::Succeeded);
    let canonical_block = canonical_block_for(&receipt);
    let mock_client = SequentialResponseMockClientBuilder::new()
        .with_response(&receipt)
        .with_response(&canonical_block)
        .build();
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
    let canonical_block = canonical_block_for(&receipt);
    let mock_client = SequentialResponseMockClientBuilder::new()
        .with_response(&receipt)
        .with_response(&canonical_block)
        .build();
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
    let canonical_block = canonical_block_for(&receipt);
    let mock_client = SequentialResponseMockClientBuilder::new()
        .with_response(&receipt)
        .with_response(&canonical_block)
        .build();
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
async fn extract__should_return_error_when_log_index_out_of_bounds() {
    // given
    let tx_id = StarknetTransactionHash::from([1; 32]);

    let receipt = mock_receipt(
        StarknetFinalityStatus::AcceptedOnL1,
        StarknetExecutionStatus::Succeeded,
    );
    let canonical_block = canonical_block_for(&receipt);
    let mock_client = SequentialResponseMockClientBuilder::new()
        .with_response(&receipt)
        .with_response(&canonical_block)
        .build();
    let inspector = StarknetInspector::new(mock_client);

    // when
    let response = inspector
        .extract(
            tx_id,
            StarknetFinality::AcceptedOnL1,
            vec![StarknetExtractor::Log { log_index: 5 }],
        )
        .await;

    // then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::LogIndexOutOfBounds)
    );
}

#[tokio::test]
async fn extract__should_return_correct_log_for_specific_index() {
    // given
    let tx_id = StarknetTransactionHash::from([3; 32]);

    let event_0 = StarknetEvent {
        data: vec![H256::from([0xab; 32])],
        from_address: H256::from([0x11; 32]),
        keys: vec![H256::from([0xcc; 32])],
    };
    let event_1 = StarknetEvent {
        data: vec![H256::from([0x01; 32]), H256::from([0x02; 32])],
        from_address: H256::from([0xff; 32]),
        keys: vec![H256::from([0xaa; 32]), H256::from([0xbb; 32])],
    };

    let receipt = GetTransactionReceiptResponse {
        block_hash: H256::from([4; 32]),
        block_number: 842_750,
        events: vec![event_0, event_1],
        finality_status: StarknetFinalityStatus::AcceptedOnL1,
        execution_status: StarknetExecutionStatus::Succeeded,
    };
    let canonical_block = canonical_block_for(&receipt);
    let mock_client = SequentialResponseMockClientBuilder::new()
        .with_response(&receipt)
        .with_response(&canonical_block)
        .build();
    let inspector = StarknetInspector::new(mock_client);

    // when
    let extracted_values = inspector
        .extract(
            tx_id,
            StarknetFinality::AcceptedOnL1,
            vec![StarknetExtractor::Log { log_index: 1 }],
        )
        .await
        .expect("extract should succeed");

    // then
    assert_eq!(
        vec![StarknetExtractedValue::Log(StarknetLog {
            block_hash: StarknetFelt([4; 32]),
            block_number: 842_750,
            data: vec![StarknetFelt([0x01; 32]), StarknetFelt([0x02; 32])],
            from_address: StarknetFelt([0xff; 32]),
            keys: vec![StarknetFelt([0xaa; 32]), StarknetFelt([0xbb; 32])],
        })],
        extracted_values,
    );
}

fn test_receipt() -> GetTransactionReceiptResponse {
    let mut block_hash_bytes = [0u8; 32];
    block_hash_bytes[31] = 5;
    GetTransactionReceiptResponse {
        block_hash: H256::from(block_hash_bytes),
        block_number: 1_023_456,
        events: vec![StarknetEvent {
            data: vec![H256::from([0x01; 32]), H256::from([0x02; 32])],
            from_address: H256::from([0xff; 32]),
            keys: vec![H256::from([0xaa; 32])],
        }],
        finality_status: StarknetFinalityStatus::AcceptedOnL1,
        execution_status: StarknetExecutionStatus::Succeeded,
    }
}

fn setup_starknet_rpc_mock(server: &MockServer) {
    let receipt = test_receipt();
    let canonical_block = canonical_block_for(&receipt);
    server.mock(|when, then| {
        when.method(POST).path("/");
        then.respond_with(move |req: &HttpMockRequest| {
            let body: serde_json::Value =
                serde_json::from_slice(req.body().as_ref()).expect("valid json-rpc request");
            let id = body["id"].clone();
            let method = body["method"].as_str().expect("method field");

            let result = match method {
                "starknet_getTransactionReceipt" => serde_json::to_value(&receipt).unwrap(),
                "starknet_getBlockWithTxHashes" => serde_json::to_value(&canonical_block).unwrap(),
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
}

#[tokio::test]
async fn extract__should_return_block_hash_via_http_rpc_client() {
    // given
    let server = MockServer::start();
    setup_starknet_rpc_mock(&server);

    let tx_id = StarknetTransactionHash::from([9; 32]);
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
    let mut expected_bytes = [0u8; 32];
    expected_bytes[31] = 5;
    assert_eq!(
        vec![StarknetExtractedValue::BlockHash(StarknetBlockHash::from(
            expected_bytes
        ))],
        extracted_values,
    );
}

#[tokio::test]
async fn extract__should_return_non_canonical_block_when_receipt_block_hash_differs_from_canonical()
{
    // given: the receipt is fully finalized but the canonical block at its height has a
    // different hash, simulating an RPC that served a side-block receipt for a finalized block.
    let tx_id = StarknetTransactionHash::from([1; 32]);
    let block_number: u64 = 842_750;
    let receipt_hash_bytes = [0xbb; 32];
    let canonical_hash_bytes = [0xcc; 32];

    let receipt = GetTransactionReceiptResponse {
        block_hash: H256::from(receipt_hash_bytes),
        block_number,
        events: vec![],
        finality_status: StarknetFinalityStatus::AcceptedOnL1,
        execution_status: StarknetExecutionStatus::Succeeded,
    };
    let canonical_block = GetBlockWithTxHashesResponse {
        block_hash: H256::from(canonical_hash_bytes),
        block_number,
    };

    let mock_client = SequentialResponseMockClientBuilder::new()
        .with_response(&receipt)
        .with_response(&canonical_block)
        .build();
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
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::NonCanonicalBlock {
            block_number: observed_block_number,
            receipt_hash,
            canonical_hash,
        }) if observed_block_number == block_number
            && receipt_hash == foreign_chain_inspector::HexBytes(receipt_hash_bytes.to_vec())
            && canonical_hash == foreign_chain_inspector::HexBytes(canonical_hash_bytes.to_vec())
    );
}

#[tokio::test]
async fn extract__should_propagate_get_block_with_tx_hashes_rpc_error() {
    // given: starknet_getTransactionReceipt succeeds; starknet_getBlockWithTxHashes returns
    // a payload that fails to deserialize as GetBlockWithTxHashesResponse.
    let tx_id = StarknetTransactionHash::from([1; 32]);

    let receipt = mock_receipt(
        StarknetFinalityStatus::AcceptedOnL1,
        StarknetExecutionStatus::Succeeded,
    );

    let mock_client = SequentialResponseMockClientBuilder::new()
        .with_response(receipt)
        .with_response(serde_json::json!({ "unexpected": "shape" }))
        .build();
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
    assert_matches!(response, Err(ForeignChainInspectionError::ClientError(_)));
}

#[tokio::test]
async fn extract__should_return_event_log_for_specific_index_via_http_rpc_client() {
    // given
    let server = MockServer::start();
    setup_starknet_rpc_mock(&server);

    let tx_id = StarknetTransactionHash::from([9; 32]);
    let client = build_http_client(server.url("/"), RpcAuthentication::KeyInUrl).unwrap();
    let inspector = StarknetInspector::new(client);

    // when
    let extracted_values = inspector
        .extract(
            tx_id,
            StarknetFinality::AcceptedOnL1,
            vec![StarknetExtractor::Log { log_index: 0 }],
        )
        .await
        .expect("extract should succeed");

    // then
    let mut expected_block_hash = [0u8; 32];
    expected_block_hash[31] = 5;
    assert_eq!(
        vec![StarknetExtractedValue::Log(StarknetLog {
            block_hash: StarknetFelt(expected_block_hash),
            block_number: 1_023_456,
            data: vec![StarknetFelt([0x01; 32]), StarknetFelt([0x02; 32])],
            from_address: StarknetFelt([0xff; 32]),
            keys: vec![StarknetFelt([0xaa; 32])],
        })],
        extracted_values,
    );
}

/// Starknet mainnet's chain id, `SN_MAIN` in ASCII.
const MAINNET_CHAIN_ID: &str = "0x534e5f4d41494e";

#[tokio::test]
async fn network_fingerprint__should_return_the_canonical_chain_id() {
    // Given: the chain id padded and uppercased, as a provider is free to send it.
    let inspector = StarknetInspector::new(mock_client_from_fixed_response("0x00534E5F4D41494E"));

    // When
    let fingerprint = inspector
        .network_fingerprint()
        .await
        .expect("network_fingerprint should succeed");

    // Then
    assert_eq!(fingerprint.to_string(), MAINNET_CHAIN_ID);
}

/// Builds a fan-out of one Starknet provider whose client runs `respond` on each call, and reports
/// the number of calls it received.
#[expect(
    clippy::type_complexity,
    reason = "the client holds an unnameable closure type, so the tuple has to spell it out"
)]
fn single_provider_fan_out(
    respond: impl Fn(usize) -> Result<serde_json::Value, RpcClientError> + Send + Sync + 'static,
) -> (
    FanOut<
        StarknetInspector<
            FixedResponseRpcClient<
                impl Fn() -> Result<serde_json::Value, RpcClientError> + Clone + Sync,
            >,
        >,
    >,
    Arc<AtomicUsize>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&calls);
    let respond: Arc<dyn Fn(usize) -> Result<serde_json::Value, RpcClientError> + Send + Sync> =
        Arc::new(respond);
    let client = FixedResponseRpcClient::new(move || respond(seen.fetch_add(1, Ordering::SeqCst)));
    let inspectors: NonEmptyVec<_> = vec![(
        ProviderId("only".to_string()),
        StarknetInspector::new(client),
    )]
    .try_into()
    .expect("one inspector");
    (FanOut::new(inspectors), calls)
}

fn transport_error() -> RpcClientError {
    RpcClientError::Transport(Box::new(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "connection refused",
    )))
}

#[tokio::test]
async fn network_fingerprints__should_retry_a_transient_failure_and_report_the_later_success() {
    // Given a provider that refuses the first call and answers the second
    let (fan_out, calls) = single_provider_fan_out(|call| match call {
        0 => Err(transport_error()),
        _ => Ok(serde_json::json!(MAINNET_CHAIN_ID)),
    });

    // When
    let results = fan_out
        .network_fingerprints(Duration::from_secs(1), NonZeroU64::new(2).unwrap())
        .await;

    // Then
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let fingerprint = results[0]
        .1
        .as_ref()
        .expect("second attempt should succeed");
    assert_eq!(fingerprint.to_string(), MAINNET_CHAIN_ID);
}

#[tokio::test]
async fn network_fingerprints__should_stop_after_the_configured_number_of_attempts() {
    // Given a provider that never answers
    let (fan_out, calls) = single_provider_fan_out(|_| Err(transport_error()));

    // When
    let results = fan_out
        .network_fingerprints(Duration::from_secs(1), NonZeroU64::new(3).unwrap())
        .await;

    // Then
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_matches!(
        results[0].1,
        Err(ForeignChainInspectionError::RpcRequestFailed(_))
    );
}

#[tokio::test]
async fn network_fingerprints__should_not_retry_a_provider_that_refused_the_request() {
    // Given a provider refusing with a JSON-RPC error object, as one does for a bad API key
    let (fan_out, calls) = single_provider_fan_out(|_| {
        Err(RpcClientError::Call(jsonrpsee::types::ErrorObject::owned(
            -32600,
            "Must be authenticated!",
            None::<()>,
        )))
    });

    // When
    let results = fan_out
        .network_fingerprints(Duration::from_secs(1), NonZeroU64::new(3).unwrap())
        .await;

    // Then the refusal is reported as one, and the remaining attempts are not spent on it
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_matches!(
        results[0].1,
        Err(ForeignChainInspectionError::RpcRequestRejected(_))
    );
}

#[tokio::test]
async fn network_fingerprint__should_propagate_rpc_client_errors() {
    // Given
    let client = FixedResponseRpcClient::new(|| {
        Err(RpcClientError::Transport(Box::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ))))
    });
    let inspector = StarknetInspector::new(client);

    // When
    let response = inspector.network_fingerprint().await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::RpcRequestFailed(_))
    );
}
