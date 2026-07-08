#![allow(non_snake_case)]

pub mod common;

use crate::common::{FixedResponseRpcClient, mock_client_from_fixed_response};

use assert_matches::assert_matches;
use base64::Engine as _;
use foreign_chain_inspector::{
    ForeignChainInspectionError, ForeignChainInspector, RpcAuthentication, build_http_client,
    sui::{
        SuiExtractedValue, SuiTransactionDigest,
        inspector::{SuiExtractor, SuiFinality, SuiInspector},
    },
};
use foreign_chain_rpc_interfaces::sui::{
    ExecutionStatus, SuiEventId, SuiEventResponse, TransactionBlockEffects,
    TransactionBlockResponse,
};
use httpmock::prelude::*;
use httpmock::{HttpMockRequest, HttpMockResponse};
use jsonrpsee::core::client::error::Error as RpcClientError;
use jsonrpsee::types::ErrorObject;
use near_mpc_contract_interface::types::{SuiAddress, SuiEvent};

const EVENT_BCS_BYTES: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

fn tx_id() -> SuiTransactionDigest {
    SuiTransactionDigest::from([0xab; 32])
}

fn tx_digest_base58() -> String {
    bs58::encode([0xab; 32]).into_string()
}

fn framework_event(event_seq: &str) -> SuiEventResponse {
    SuiEventResponse {
        id: SuiEventId {
            tx_digest: tx_digest_base58(),
            event_seq: event_seq.to_string(),
        },
        package_id: "0x0000000000000000000000000000000000000000000000000000000000000003"
            .to_string(),
        transaction_module: "sui_system".to_string(),
        sender: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        // Short-form framework address: the inspector must normalize it to the long form.
        event_type: "0x3::validator_set::ValidatorEpochInfoEventV2".to_string(),
        bcs: base64::engine::general_purpose::STANDARD.encode(EVENT_BCS_BYTES),
        bcs_encoding: Some("base64".to_string()),
    }
}

fn checkpointed_tx(events: Vec<SuiEventResponse>) -> TransactionBlockResponse {
    TransactionBlockResponse {
        digest: tx_digest_base58(),
        effects: Some(TransactionBlockEffects {
            status: ExecutionStatus {
                status: "success".to_string(),
            },
        }),
        events,
        checkpoint: Some("296112296".to_string()),
    }
}

fn expected_event() -> SuiEvent {
    let mut package_id = [0u8; 32];
    package_id[31] = 0x03;
    SuiEvent {
        package_id: SuiAddress(package_id),
        transaction_module: "sui_system".to_string(),
        sender: SuiAddress([0u8; 32]),
        type_tag: format!(
            "0x{}3::validator_set::ValidatorEpochInfoEventV2",
            "0".repeat(63)
        ),
        bcs: EVENT_BCS_BYTES.to_vec(),
    }
}

#[tokio::test]
async fn extract__should_return_normalized_event_for_checkpointed_transaction() {
    // Given
    let mock_client = mock_client_from_fixed_response(checkpointed_tx(vec![framework_event("0")]));
    let inspector = SuiInspector::new(mock_client);

    // When
    let extracted_values = inspector
        .extract(
            tx_id(),
            SuiFinality::Checkpointed,
            vec![SuiExtractor::Event { event_index: 0 }],
        )
        .await
        .expect("extract should succeed");

    // Then — type_tag address padded to long form, bcs decoded to raw bytes.
    assert_eq!(
        extracted_values,
        vec![SuiExtractedValue::Event(expected_event())],
    );
}

#[tokio::test]
async fn extract__should_return_correct_event_for_specific_index() {
    // Given a transaction with two events.
    let mut second = framework_event("1");
    second.event_type = "0x3::validator::StakingRequestEvent".to_string();
    let tx = checkpointed_tx(vec![framework_event("0"), second]);
    let inspector = SuiInspector::new(mock_client_from_fixed_response(tx));

    // When
    let extracted_values = inspector
        .extract(
            tx_id(),
            SuiFinality::Checkpointed,
            vec![SuiExtractor::Event { event_index: 1 }],
        )
        .await
        .expect("extract should succeed");

    // Then
    assert_eq!(extracted_values.len(), 1);
    let SuiExtractedValue::Event(event) = &extracted_values[0];
    assert_eq!(
        event.type_tag,
        format!("0x{}3::validator::StakingRequestEvent", "0".repeat(63))
    );
}

#[tokio::test]
async fn extract__should_return_not_finalized_when_checkpoint_is_missing() {
    // Given — executed but not yet included in a certified checkpoint.
    let mut tx = checkpointed_tx(vec![]);
    tx.checkpoint = None;
    let inspector = SuiInspector::new(mock_client_from_fixed_response(tx));

    // When
    let response = inspector
        .extract(tx_id(), SuiFinality::Checkpointed, vec![])
        .await;

    // Then — transient, so the fan-out keeps retrying until it is checkpointed.
    assert_matches!(response, Err(ForeignChainInspectionError::NotFinalized));
    assert!(response.unwrap_err().is_transient());
}

#[tokio::test]
async fn extract__should_return_transaction_failed_when_execution_failed() {
    // Given
    let mut tx = checkpointed_tx(vec![]);
    tx.effects = Some(TransactionBlockEffects {
        status: ExecutionStatus {
            status: "failure".to_string(),
        },
    });
    let inspector = SuiInspector::new(mock_client_from_fixed_response(tx));

    // When
    let response = inspector
        .extract(tx_id(), SuiFinality::Checkpointed, vec![])
        .await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::TransactionFailed)
    );
}

#[tokio::test]
async fn extract__should_reject_response_missing_effects_as_malformed() {
    // Given — effects were requested via `showEffects`, so their absence violates the API.
    let mut tx = checkpointed_tx(vec![]);
    tx.effects = None;
    let inspector = SuiInspector::new(mock_client_from_fixed_response(tx));

    // When
    let response = inspector
        .extract(tx_id(), SuiFinality::Checkpointed, vec![])
        .await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::MalformedRpcResponse(_))
    );
}

#[tokio::test]
async fn extract__should_return_transaction_not_found_for_unknown_digest() {
    // Given — the JSON-RPC error a node returns for an unknown or pruned digest.
    let mock_client = FixedResponseRpcClient::new(|| {
        Err(RpcClientError::Call(ErrorObject::owned(
            -32602,
            "Could not find the referenced transaction [TransactionDigest(88XKXHJRmGzkfwJa8PhoeDkqt4kxz8AEsB1UTzAbtd29)].",
            None::<()>,
        )))
    });
    let inspector = SuiInspector::new(mock_client);

    // When
    let response = inspector
        .extract(tx_id(), SuiFinality::Checkpointed, vec![])
        .await;

    // Then — a substantive (non-transient) verdict.
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::TransactionNotFound)
    );
    assert!(!response.unwrap_err().is_transient());
}

#[tokio::test]
async fn extract__should_propagate_transport_errors_as_transient() {
    // Given
    let mock_client = FixedResponseRpcClient::new(|| {
        Err(RpcClientError::Transport(Box::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "connection refused",
        ))))
    });
    let inspector = SuiInspector::new(mock_client);

    // When
    let response = inspector
        .extract(tx_id(), SuiFinality::Checkpointed, vec![])
        .await;

    // Then
    assert_matches!(response, Err(ForeignChainInspectionError::ClientError(_)));
    assert!(response.unwrap_err().is_transient());
}

#[tokio::test]
async fn extract__should_return_error_when_event_index_out_of_bounds() {
    // Given
    let inspector = SuiInspector::new(mock_client_from_fixed_response(checkpointed_tx(vec![
        framework_event("0"),
    ])));

    // When
    let response = inspector
        .extract(
            tx_id(),
            SuiFinality::Checkpointed,
            vec![SuiExtractor::Event { event_index: 5 }],
        )
        .await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::LogIndexOutOfBounds)
    );
}

#[tokio::test]
async fn extract__should_reject_response_with_mismatched_digest() {
    // Given — the backend echoes a different transaction than queried.
    let mut tx = checkpointed_tx(vec![]);
    tx.digest = bs58::encode([0xcd; 32]).into_string();
    let inspector = SuiInspector::new(mock_client_from_fixed_response(tx));

    // When
    let response = inspector
        .extract(tx_id(), SuiFinality::Checkpointed, vec![])
        .await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::InconsistentRpcResponse { .. })
    );
}

#[tokio::test]
async fn extract__should_reject_event_with_reordered_sequence() {
    // Given — the event at position 0 claims eventSeq 1: a reordered or filtered list.
    let inspector = SuiInspector::new(mock_client_from_fixed_response(checkpointed_tx(vec![
        framework_event("1"),
    ])));

    // When
    let response = inspector
        .extract(
            tx_id(),
            SuiFinality::Checkpointed,
            vec![SuiExtractor::Event { event_index: 0 }],
        )
        .await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::MalformedRpcResponse(_))
    );
}

#[tokio::test]
async fn extract__should_return_empty_when_no_extractors_are_requested() {
    // Given
    let inspector = SuiInspector::new(mock_client_from_fixed_response(checkpointed_tx(vec![])));

    // When
    let extracted_values = inspector
        .extract(tx_id(), SuiFinality::Checkpointed, Vec::new())
        .await
        .expect("extract should succeed");

    // Then
    let expected: Vec<SuiExtractedValue> = vec![];
    assert_eq!(expected, extracted_values);
}

fn setup_sui_rpc_mock(server: &MockServer, result: serde_json::Value) {
    server.mock(|when, then| {
        when.method(POST).path("/");
        then.respond_with(move |req: &HttpMockRequest| {
            let body: serde_json::Value =
                serde_json::from_slice(req.body().as_ref()).expect("valid json-rpc request");
            assert_eq!(
                body["method"].as_str().expect("method field"),
                "sui_getTransactionBlock"
            );
            assert_eq!(
                body["params"],
                serde_json::json!([
                    tx_digest_base58(),
                    { "showEffects": true, "showEvents": true }
                ])
            );

            let response_body = serde_json::json!({
                "jsonrpc": "2.0",
                "result": result,
                "id": body["id"],
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
async fn extract__should_return_event_via_http_rpc_client() {
    // Given
    let server = MockServer::start();
    setup_sui_rpc_mock(
        &server,
        serde_json::to_value(checkpointed_tx(vec![framework_event("0")])).unwrap(),
    );
    let client = build_http_client(server.url("/"), RpcAuthentication::KeyInUrl).unwrap();
    let inspector = SuiInspector::new(client);

    // When
    let extracted_values = inspector
        .extract(
            tx_id(),
            SuiFinality::Checkpointed,
            vec![SuiExtractor::Event { event_index: 0 }],
        )
        .await
        .expect("extract should succeed");

    // Then
    assert_eq!(
        extracted_values,
        vec![SuiExtractedValue::Event(expected_event())],
    );
}

#[tokio::test]
async fn extract__should_return_transaction_not_found_via_http_rpc_client() {
    // Given — the exact not-found error envelope a mainnet node returns; jsonrpsee must
    // surface it as a call error that classifies as `TransactionNotFound`.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/");
        then.respond_with(move |req: &HttpMockRequest| {
            let body: serde_json::Value =
                serde_json::from_slice(req.body().as_ref()).expect("valid json-rpc request");
            let response_body = serde_json::json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32602,
                    "message": "Could not find the referenced transaction [TransactionDigest(88XKXHJRmGzkfwJa8PhoeDkqt4kxz8AEsB1UTzAbtd29)]."
                },
                "id": body["id"],
            });
            HttpMockResponse::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(serde_json::to_string(&response_body).unwrap())
                .build()
        });
    });
    let client = build_http_client(server.url("/"), RpcAuthentication::KeyInUrl).unwrap();
    let inspector = SuiInspector::new(client);

    // When
    let response = inspector
        .extract(tx_id(), SuiFinality::Checkpointed, vec![])
        .await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::TransactionNotFound)
    );
}
