#![allow(non_snake_case)]

use std::time::Duration;

use assert_matches::assert_matches;
use foreign_chain_inspector::{
    ForeignChainInspectionError, ForeignChainInspector,
    aptos::{
        AptosExtractedValue, AptosTransactionHash,
        inspector::{AptosExtractor, AptosFinality, AptosInspector},
    },
};
use foreign_chain_rpc_interfaces::aptos::ReqwestAptosClient;
use httpmock::prelude::*;
use near_mpc_contract_interface::types::{AptosAddress, AptosEvent};
use rstest::rstest;

const TIMEOUT: Duration = Duration::from_secs(5);

fn tx_id() -> AptosTransactionHash {
    AptosTransactionHash::from([0xab; 32])
}

fn tx_hash_hex() -> String {
    format!("0x{}", "ab".repeat(32))
}

/// The REST resource path the client is expected to hit. Every mock matches on it, which also
/// verifies the `/v1` segment from the base URL is not doubled.
fn tx_path() -> String {
    format!("/v1/transactions/by_hash/{}", tx_hash_hex())
}

fn inspector_for(server: &MockServer) -> AptosInspector<ReqwestAptosClient> {
    let client = ReqwestAptosClient::new(server.url("/v1"), None, TIMEOUT);
    AptosInspector::new(client)
}

fn committed_user_tx_body() -> serde_json::Value {
    serde_json::json!({
        "type": "user_transaction",
        "hash": tx_hash_hex(),
        "sender": "0x1",
        "sequence_number": "7",
        "gas_used": "57",
        "success": true,
        "vm_status": "Executed successfully",
        "version": "5670430862",
        "events": [
            {
                "guid": { "creation_number": "2", "account_address": "0x1" },
                "sequence_number": "5",
                // Long-form address: the inspector must normalize it to `0xdeadbeef::…`.
                "type": format!("0x{}deadbeef::bridge::InitTransfer", "0".repeat(56)),
                // Intentionally unsorted keys: the inspector must emit them sorted.
                "data": { "z_amount": "100", "a_recipient": "alice.near" }
            }
        ]
    })
}

#[tokio::test]
async fn extract__should_return_normalized_event_via_rest_client() {
    // Given
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET).path(tx_path());
        then.status(200)
            .header("content-type", "application/json")
            .json_body(committed_user_tx_body());
    });
    let inspector = inspector_for(&server);

    // When
    let extracted_values = inspector
        .extract(
            tx_id(),
            AptosFinality::Committed,
            vec![AptosExtractor::Event { event_index: 0 }],
        )
        .await
        .expect("extract should succeed");

    // Then — type_tag address trimmed to short form, data keys sorted.
    let mut framework_address = [0u8; 32];
    framework_address[31] = 1;
    assert_eq!(
        extracted_values,
        vec![AptosExtractedValue::Event(AptosEvent {
            account_address: AptosAddress(framework_address),
            sequence_number: 5,
            type_tag: "0xdeadbeef::bridge::InitTransfer".to_string(),
            data: r#"{"a_recipient":"alice.near","z_amount":"100"}"#.to_string(),
        })],
    );
    mock.assert();
}

#[tokio::test]
async fn extract__should_send_auth_header_when_configured() {
    // Given — the mock only matches when the auth header is present.
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(GET)
            .path(tx_path())
            .header("api-key", "secret-token");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(committed_user_tx_body());
    });
    let auth_header = Some((
        http::HeaderName::from_static("api-key"),
        http::HeaderValue::from_static("secret-token"),
    ));
    let client = ReqwestAptosClient::new(server.url("/v1"), auth_header, TIMEOUT);
    let inspector = AptosInspector::new(client);

    // When
    let result = inspector
        .extract(tx_id(), AptosFinality::Committed, vec![])
        .await;

    // Then
    result.expect("extract should succeed when the auth header is sent");
    mock.assert();
}

#[tokio::test]
async fn extract__should_return_not_finalized_for_pending_transaction() {
    // Given — a pending body: no execution result, no events.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path(tx_path());
        then.status(200)
            .header("content-type", "application/json")
            .json_body(serde_json::json!({
                "type": "pending_transaction",
                "hash": tx_hash_hex(),
                "sender": "0x1",
                "sequence_number": "7",
                "payload": { "type": "entry_function_payload" }
            }));
    });
    let inspector = inspector_for(&server);

    // When
    let response = inspector
        .extract(tx_id(), AptosFinality::Committed, vec![])
        .await;

    // Then
    assert_matches!(response, Err(ForeignChainInspectionError::NotFinalized));
}

#[tokio::test]
async fn extract__should_return_transaction_not_found_on_404() {
    // Given
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path(tx_path());
        then.status(404)
            .header("content-type", "application/json")
            .json_body(serde_json::json!({
                "message": "transaction not found",
                "error_code": "transaction_not_found"
            }));
    });
    let inspector = inspector_for(&server);

    // When
    let response = inspector
        .extract(tx_id(), AptosFinality::Committed, vec![])
        .await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::TransactionNotFound)
    );
}

#[rstest]
#[case::forbidden(403, false)]
#[case::internal_error(500, true)]
#[tokio::test]
async fn extract__should_classify_http_errors_by_status(
    #[case] status: u16,
    #[case] expected_transient: bool,
) {
    // Given
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path(tx_path());
        then.status(status);
    });
    let inspector = inspector_for(&server);

    // When
    let response = inspector
        .extract(tx_id(), AptosFinality::Committed, vec![])
        .await;

    // Then
    let error = response.expect_err("extract should fail");
    match expected_transient {
        true => assert_matches!(error, ForeignChainInspectionError::RpcRequestFailed(_)),
        false => assert_matches!(error, ForeignChainInspectionError::RpcRequestRejected(_)),
    }
    assert_eq!(error.is_transient(), expected_transient);
}

#[tokio::test]
async fn extract__should_reject_response_with_mismatched_hash() {
    // Given — the backend echoes a different transaction than queried.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path(tx_path());
        then.status(200)
            .header("content-type", "application/json")
            .json_body(serde_json::json!({
                "type": "user_transaction",
                "hash": format!("0x{}", "cd".repeat(32)),
                "success": true,
                "events": []
            }));
    });
    let inspector = inspector_for(&server);

    // When
    let response = inspector
        .extract(tx_id(), AptosFinality::Committed, vec![])
        .await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::InconsistentRpcResponse { .. })
    );
}
