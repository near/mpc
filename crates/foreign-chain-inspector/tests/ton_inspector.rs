#![allow(non_snake_case)]

//! End-to-end tests for the TON inspector against a mock HTTP server.
//!
//! Unlike the `src/ton/inspector.rs` unit tests (which feed the inspector an
//! in-memory `StubClient`), these drive the real `ReqwestTonClient`: they
//! exercise request-URL construction and deserialization of realistic TON HTTP
//! API v3 `/transactions` JSON, on top of the extraction logic.

pub mod common;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::hash32;
use foreign_chain_inspector::ton::TonInspectionError;
use foreign_chain_inspector::ton::inspector::TonInspector;
use foreign_chain_inspector::ton::rpc_client::{ReqwestTonClient, TonRpcError};
use foreign_chain_inspector::ton::types::{
    TonAddress, TonExtractedValue, TonExtractor, TonFinality, TonLog, TonTransactionId,
    TonWorkchain,
};
use foreign_chain_inspector::{
    ForeignChainInspectionError, ForeignChainInspector, RpcAuthentication,
};
use httpmock::prelude::*;
use near_mpc_contract_interface::types::{Hash256, TonCellBody};
use serde_json::{Value, json};

const ACCOUNT_HASH: [u8; 32] = [0x11; 32];
const TX_HASH: [u8; 32] = [0xde; 32];

// Golden message-body BoCs (base64) captured from tonlib, with their decoded
// contents, so this test needs no BoC library of its own. (They mirror the
// `src/ton/test_support.rs` goldens, which a `tests/` binary cannot import.)
//
// A 4-byte (32-bit) body cell `0x99000001` with no references.
const BYTE_ALIGNED_BODY: &str = "te6ccgEBAQEABgAACJkAAAE=";
// A 2-byte (16-bit) body cell `0xdead` referencing one child cell `0xaa` (8 bits).
const ONE_REF_BODY: &str = "te6ccgEBAgEACAABBN6tAQACqg==";
// The representation hash of that child cell.
const ONE_REF_CHILD_HASH: &str = "08da99aa8eb36c5c627a221005ca60f004f392de79b18e90be10c0cb420ab332";

fn account_str() -> String {
    format!("0:{}", hex::encode(ACCOUNT_HASH))
}

/// The hash as the inspector encodes it in the request query string (hex).
fn hash_hex() -> String {
    hex::encode(TX_HASH)
}

/// The hash as the v3 API echoes it back in the transaction `hash` field (base64).
fn hash_b64() -> String {
    STANDARD.encode(TX_HASH)
}

fn tx_id() -> TonTransactionId {
    TonTransactionId {
        workchain: TonWorkchain::Basechain,
        account: ACCOUNT_HASH.into(),
        tx_hash: TX_HASH.into(),
    }
}

fn log_extractor() -> Vec<TonExtractor> {
    vec![TonExtractor::Log { message_index: 0 }]
}

/// A realistic TON HTTP API v3 `/transactions` response carrying a single
/// transaction with one ext-out (`destination: null`) message. Includes the
/// surrounding fields a real provider returns so the test proves the DTOs
/// tolerate (ignore) everything the inspector doesn't consume.
fn v3_response(body_b64: &str, mc_block_seqno: Value) -> Value {
    json!({
        "transactions": [{
            "account": account_str(),
            "hash": hash_b64(),
            "lt": "29161856000001",
            "now": 1_716_000_000,
            "mc_block_seqno": mc_block_seqno,
            "trace_id": "00112233",
            "orig_status": "active",
            "end_status": "active",
            "total_fees": "1000",
            "description": {
                "type": "ord",
                "aborted": false,
                "destroyed": false,
                "credit_first": true,
                "compute_ph": {
                    "type": "vm",
                    "skipped": false,
                    "success": true,
                    "gas_used": "3308",
                    "exit_code": 0,
                    "vm_steps": 39
                },
                "action": { "success": true, "result_code": 0 }
            },
            "block_ref": { "workchain": 0, "shard": "8000000000000000", "seqno": 100 },
            "out_msgs": [{
                "hash": "msghashbase64==",
                "source": account_str(),
                "destination": Value::Null,
                "value": Value::Null,
                "created_lt": "29161856000002",
                "created_at": "1716000000",
                "opcode": "0x99000001",
                "message_content": {
                    "hash": "bodyhashbase64==",
                    "body": body_b64,
                    "decoded": Value::Null
                }
            }]
        }],
        "address_book": {
            account_str(): { "user_friendly": "EQexample", "domain": Value::Null }
        }
    })
}

fn inspector_for(server: &MockServer) -> TonInspector<ReqwestTonClient> {
    let client =
        ReqwestTonClient::new(server.url("/api/v3/"), RpcAuthentication::KeyInUrl).unwrap();
    TonInspector::new(client)
}

/// Mock the `GET /api/v3/transactions` endpoint, asserting on the full set of
/// query parameters the inspector is expected to send.
fn mock_transactions(server: &MockServer, status: u16, body: Value) -> httpmock::Mock<'_> {
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v3/transactions")
            .query_param("account", account_str())
            .query_param("hash", hash_hex())
            .query_param("include_msgs", "true")
            .query_param("limit", "1");
        then.status(status)
            .header("content-type", "application/json")
            .json_body(body);
    })
}

#[tokio::test]
async fn extract__should_return_log_via_http_rpc_client() {
    // Given a finalized, successful tx whose ext-out carries a 4-byte body cell.
    let server = MockServer::start();
    let mock = mock_transactions(&server, 200, v3_response(BYTE_ALIGNED_BODY, json!(12345)));
    let inspector = inspector_for(&server);

    // When
    let extracted = inspector
        .extract(tx_id(), TonFinality::MasterchainIncluded, log_extractor())
        .await
        .expect("extract should succeed");

    // Then the request hit the expected URL, and the body decoded as the cell.
    mock.assert();
    assert_eq!(
        extracted,
        vec![TonExtractedValue::Log(TonLog {
            from_address: TonAddress {
                workchain: TonWorkchain::Basechain,
                hash: Hash256(ACCOUNT_HASH),
            },
            body: TonCellBody::new(vec![0x99, 0x00, 0x00, 0x01].try_into().unwrap(), 32).unwrap(),
            body_refs: vec![].try_into().unwrap(),
        })],
    );
}

#[tokio::test]
async fn extract__should_extract_reference_cell_hashes_via_http_rpc_client() {
    // Given an ext-out body cell that references a child cell.
    let server = MockServer::start();
    let mock = mock_transactions(&server, 200, v3_response(ONE_REF_BODY, json!(12345)));
    let inspector = inspector_for(&server);

    // When
    let extracted = inspector
        .extract(tx_id(), TonFinality::MasterchainIncluded, log_extractor())
        .await
        .expect("extract should succeed");

    // Then the reference is reported by its representation hash.
    mock.assert();
    assert_eq!(
        extracted,
        vec![TonExtractedValue::Log(TonLog {
            from_address: TonAddress {
                workchain: TonWorkchain::Basechain,
                hash: Hash256(ACCOUNT_HASH),
            },
            body: TonCellBody::new(vec![0xde, 0xad].try_into().unwrap(), 16).unwrap(),
            body_refs: vec![Hash256(hash32(ONE_REF_CHILD_HASH))]
                .try_into()
                .unwrap(),
        })],
    );
}

// The verdict logic itself (finality, failed phases, missing transaction, ...)
// is covered by the `StubClient` unit tests in `src/ton/inspector.rs`; this one
// case stays as the representative for deserializing a JSON `null` field.
#[tokio::test]
async fn extract__should_reject_when_not_included_in_masterchain() {
    // Given a tx that is not yet referenced by a masterchain block.
    let server = MockServer::start();
    mock_transactions(&server, 200, v3_response(BYTE_ALIGNED_BODY, Value::Null));
    let inspector = inspector_for(&server);

    // When
    let result = inspector
        .extract(tx_id(), TonFinality::MasterchainIncluded, log_extractor())
        .await;

    // Then
    assert_matches::assert_matches!(result, Err(ForeignChainInspectionError::NotFinalized));
}

#[tokio::test]
async fn extract__should_reject_response_body_exceeding_size_cap() {
    // Given a provider streaming a response body past the 10 MiB cap.
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/api/v3/transactions");
        then.status(200)
            .header("content-type", "application/json")
            .body("x".repeat(10 * 1024 * 1024 + 1));
    });
    let inspector = inspector_for(&server);

    // When
    let result = inspector
        .extract(tx_id(), TonFinality::MasterchainIncluded, log_extractor())
        .await;

    // Then the body is not buffered or parsed; the request fails as too large.
    assert_matches::assert_matches!(
        result,
        Err(ForeignChainInspectionError::Ton(
            TonInspectionError::RpcError(TonRpcError::ResponseTooLarge { .. })
        ))
    );
}

#[tokio::test]
async fn extract__should_propagate_rpc_error_on_non_success_status() {
    // Given the provider returns an HTTP 500.
    let server = MockServer::start();
    mock_transactions(&server, 500, json!({ "error": "internal" }));
    let inspector = inspector_for(&server);

    // When
    let result = inspector
        .extract(tx_id(), TonFinality::MasterchainIncluded, log_extractor())
        .await;

    // Then it surfaces as a (transient) RPC error.
    assert_matches::assert_matches!(
        result,
        Err(ForeignChainInspectionError::Ton(
            TonInspectionError::RpcError(_)
        ))
    );
}
