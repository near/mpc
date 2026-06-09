#![allow(non_snake_case)]

//! End-to-end tests for the TON inspector against a mock HTTP server.
//!
//! Unlike the `src/ton/inspector.rs` unit tests (which feed the inspector an
//! in-memory `StubClient`), these drive the real `ReqwestTonClient`: they
//! exercise request-URL construction and deserialization of realistic TON HTTP
//! API v3 `/transactions` JSON, on top of the extraction logic.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use foreign_chain_inspector::ton::TonInspectionError;
use foreign_chain_inspector::ton::inspector::TonInspector;
use foreign_chain_inspector::ton::rpc_client::{ReqwestTonClient, build_ton_http_client};
use foreign_chain_inspector::ton::types::{
    TonAddress, TonExtractedValue, TonExtractor, TonFinality, TonLog, TonTransactionId,
};
use foreign_chain_inspector::{
    ForeignChainInspectionError, ForeignChainInspector, RpcAuthentication,
};
use httpmock::prelude::*;
use near_mpc_contract_interface::types::{Hash256, TonCellBody};
use serde_json::{Value, json};
use tonlib_core::cell::{ArcCell, BagOfCells, Cell};

const ACCOUNT_HASH: [u8; 32] = [0x11; 32];
const TX_HASH: [u8; 32] = [0xde; 32];

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
        workchain: 0,
        account: ACCOUNT_HASH,
        tx_hash: TX_HASH,
    }
}

fn log_extractor() -> Vec<TonExtractor> {
    vec![TonExtractor::Log { message_index: 0 }]
}

/// Serialize a cell as a base64 single-root BoC, matching the `body` field the
/// v3 API emits for a message's `message_content`.
fn encode_cell(data: Vec<u8>, bit_len: usize, refs: Vec<ArcCell>) -> String {
    let cell = Arc::new(Cell::new(data, bit_len, refs, false).unwrap());
    STANDARD.encode(BagOfCells::new(&[cell]).serialize(false).unwrap())
}

/// A realistic TON HTTP API v3 `/transactions` response carrying a single
/// transaction with one ext-out (`destination: null`) message. Includes the
/// surrounding fields a real provider returns so the test proves the DTOs
/// tolerate (ignore) everything the inspector doesn't consume.
fn v3_response(
    body_b64: &str,
    mc_block_seqno: Value,
    compute_success: bool,
    aborted: bool,
) -> Value {
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
                "aborted": aborted,
                "destroyed": false,
                "credit_first": true,
                "compute_ph": {
                    "type": "vm",
                    "skipped": false,
                    "success": compute_success,
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
        build_ton_http_client(server.url("/api/v3/"), RpcAuthentication::KeyInUrl).unwrap();
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
    let body_b64 = encode_cell(vec![0x99, 0x00, 0x00, 0x01], 32, vec![]);
    let mock = mock_transactions(
        &server,
        200,
        v3_response(&body_b64, json!(12345), true, false),
    );
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
                workchain: 0,
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
    let child = Arc::new(Cell::new(vec![0xaa], 8, vec![], false).unwrap());
    let body_b64 = encode_cell(vec![0xde, 0xad], 16, vec![child.clone()]);
    let mock = mock_transactions(
        &server,
        200,
        v3_response(&body_b64, json!(12345), true, false),
    );
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
                workchain: 0,
                hash: Hash256(ACCOUNT_HASH),
            },
            body: TonCellBody::new(vec![0xde, 0xad].try_into().unwrap(), 16).unwrap(),
            body_refs: vec![Hash256(child.cell_hash().into())].try_into().unwrap(),
        })],
    );
}

#[tokio::test]
async fn extract__should_reject_when_not_included_in_masterchain() {
    // Given a tx that is not yet referenced by a masterchain block.
    let server = MockServer::start();
    let body_b64 = encode_cell(vec![0x99, 0x00, 0x00, 0x01], 32, vec![]);
    mock_transactions(
        &server,
        200,
        v3_response(&body_b64, Value::Null, true, false),
    );
    let inspector = inspector_for(&server);

    // When
    let result = inspector
        .extract(tx_id(), TonFinality::MasterchainIncluded, log_extractor())
        .await;

    // Then
    assert_matches::assert_matches!(result, Err(ForeignChainInspectionError::NotFinalized));
}

#[tokio::test]
async fn extract__should_reject_when_compute_phase_failed() {
    // Given a tx whose compute phase reports failure.
    let server = MockServer::start();
    let body_b64 = encode_cell(vec![0x99, 0x00, 0x00, 0x01], 32, vec![]);
    mock_transactions(
        &server,
        200,
        v3_response(&body_b64, json!(12345), false, false),
    );
    let inspector = inspector_for(&server);

    // When
    let result = inspector
        .extract(tx_id(), TonFinality::MasterchainIncluded, log_extractor())
        .await;

    // Then
    assert_matches::assert_matches!(result, Err(ForeignChainInspectionError::TransactionFailed));
}

#[tokio::test]
async fn extract__should_reject_when_no_transaction_found() {
    // Given an empty result set (provider knows of no such tx).
    let server = MockServer::start();
    mock_transactions(&server, 200, json!({ "transactions": [] }));
    let inspector = inspector_for(&server);

    // When
    let result = inspector
        .extract(tx_id(), TonFinality::MasterchainIncluded, log_extractor())
        .await;

    // Then
    assert_matches::assert_matches!(
        result,
        Err(ForeignChainInspectionError::Ton(
            TonInspectionError::TransactionNotFound { .. }
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
