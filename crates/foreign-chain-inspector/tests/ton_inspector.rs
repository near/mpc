#![allow(non_snake_case)]

use foreign_chain_inspector::{
    ForeignChainInspectionError, ForeignChainInspector, RpcAuthentication,
    ton::{
        TonExtractedValue,
        inspector::{TonExtractor, TonFinality, TonInspector, TonTransactionId},
        rpc_client::{ReqwestTonClient, build_ton_http_client},
    },
};
use httpmock::prelude::*;
use near_mpc_contract_interface::types::{Hash256, TonLog};
use serde_json::Value;
use std::path::PathBuf;
use tonlib_core::cell::BagOfCells;

fn fixture_path(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/ton");
    p.push(name);
    p
}

fn load_fixture(name: &str) -> String {
    std::fs::read_to_string(fixture_path(name))
        .unwrap_or_else(|e| panic!("failed to load fixture {name}: {e}"))
}

fn mount_toncenter_mock(server: &MockServer, body: &str) {
    server.mock(|when, then| {
        when.method(GET).path("/transactions");
        then.status(200)
            .header("content-type", "application/json")
            .body(body);
    });
}

fn inspector_for(server: &MockServer) -> TonInspector<ReqwestTonClient> {
    // toncenter client wants a trailing slash on the base URL.
    let client = build_ton_http_client(server.url("/"), RpcAuthentication::KeyInUrl)
        .expect("client build should succeed");
    TonInspector::new(client)
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let bytes = hex_decode(s);
    assert_eq!(bytes.len(), 32, "expected 32-byte hex, got {}", bytes.len());
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd hex length: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn take_log(extracted: Vec<TonExtractedValue>) -> TonLog {
    assert_eq!(extracted.len(), 1, "expected exactly one extracted value");
    match extracted.into_iter().next().unwrap() {
        TonExtractedValue::Log(log) => log,
    }
}

/// Parse a `body_refs[i]` entry back through `BagOfCells::parse`, asserting it
/// is a single-root BoC, and return `(bit_len, data_bytes, ref_count)`.
///
/// Refs are compared structurally rather than byte-for-byte because
/// `tonlib-core` and alternative BoC libraries may differ in envelope flags
/// (e.g. `has_idx`, `has_cache_bits`) while still encoding the same cell tree.
fn structural_ref(bytes: &[u8]) -> (usize, Vec<u8>, usize) {
    let boc = BagOfCells::parse(bytes).expect("ref bytes should parse as BoC");
    let root = boc.single_root().expect("ref should be single-root");
    (
        root.bit_len(),
        root.data().to_vec(),
        root.references().len(),
    )
}

const FX_A_ACCOUNT_HEX: &str = "a11802e9d7001af100c1af89ab361d43209ccccaf1b60aab01f120fd0c345de9";
const FX_A_TX_HASH_HEX: &str = "96742cb3a9d0d74f3def6087de14385a031ea2a3ee876c4e106d4284abacd954";
const FX_A_BODY_BITS_HEX: &str =
    "0000000af93a652b04be48be8cc6bf2b655e021f9e5d4ea353dc03e53d2e97d810ac0000000000032bdf";

#[tokio::test]
async fn extract__should_return_log_for_simple_no_refs_fixture() {
    // given
    let server = MockServer::start();
    let fixture = load_fixture("simple_no_refs.json");
    mount_toncenter_mock(&server, &fixture);

    let inspector = inspector_for(&server);

    let tx_id = TonTransactionId {
        workchain: 0,
        account: hex_to_32(FX_A_ACCOUNT_HEX),
        tx_hash: hex_to_32(FX_A_TX_HASH_HEX),
    };

    // when
    let extracted = inspector
        .extract(
            tx_id,
            TonFinality::MasterchainIncluded,
            vec![TonExtractor::Log { message_index: 0 }],
        )
        .await
        .expect("extract should succeed");

    // then
    let log = take_log(extracted);
    assert_eq!(log.from_address, Hash256(hex_to_32(FX_A_ACCOUNT_HEX)));
    assert_eq!(log.body_bits, hex_decode(FX_A_BODY_BITS_HEX));
    assert!(log.body_refs.is_empty());
}

const FX_B_ACCOUNT_HEX: &str = "cefef6cb206d1bff2afb930081d16617ccbcdc9cc0fbaf0dc94ea32fd35357e6";
const FX_B_TX_HASH_HEX: &str = "7ad54ad0e2b41799575b1a24be5b9d498283a113602bd23e98ce64b6396ae701";
const FX_B_BODY_BITS_HEX: &str = "9c610de3100ee1a0a9953bfc012088ec047be69ba3321e7eea1a8ab4d62cec9dedcfdff06870659175a11c659533b705fa8f";
const FX_B_REF0_BIT_LEN: usize = 381;

#[tokio::test]
async fn extract__should_return_log_with_ref_for_event_fixture() {
    // given
    let server = MockServer::start();
    let fixture = load_fixture("event_with_ref.json");
    mount_toncenter_mock(&server, &fixture);

    let inspector = inspector_for(&server);

    let tx_id = TonTransactionId {
        workchain: 0,
        account: hex_to_32(FX_B_ACCOUNT_HEX),
        tx_hash: hex_to_32(FX_B_TX_HASH_HEX),
    };

    // when
    let extracted = inspector
        .extract(
            tx_id,
            TonFinality::MasterchainIncluded,
            vec![TonExtractor::Log { message_index: 0 }],
        )
        .await
        .expect("extract should succeed");

    // then
    let log = take_log(extracted);
    assert_eq!(log.from_address, Hash256(hex_to_32(FX_B_ACCOUNT_HEX)));
    assert_eq!(log.body_bits, hex_decode(FX_B_BODY_BITS_HEX));
    assert_eq!(log.body_refs.len(), 1, "expected exactly one ref");
    let (bit_len, _data, refs) = structural_ref(&log.body_refs[0]);
    assert_eq!(bit_len, FX_B_REF0_BIT_LEN, "ref bit_len should round-trip");
    assert_eq!(refs, 0, "ref should itself be leaf");
}

const FX_C_ACCOUNT_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FX_C_TX_HASH_HEX: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const FX_C_BODY_BITS_HEX: &str = "9900000100000000cafebabe00000000000000000de0b6b3a7640000";
const FX_C_REF0_DATA: &[u8] = b"NEAR:alice.near";
const FX_C_REF1_DATA: &[u8] = b"bridge-transfer-1";

#[tokio::test]
async fn extract__should_return_log_with_multiple_refs_for_init_transfer_fixture() {
    // given
    let server = MockServer::start();
    let fixture = load_fixture("synthetic_init_transfer.json");
    mount_toncenter_mock(&server, &fixture);

    let inspector = inspector_for(&server);

    let tx_id = TonTransactionId {
        workchain: 0,
        account: hex_to_32(FX_C_ACCOUNT_HEX),
        tx_hash: hex_to_32(FX_C_TX_HASH_HEX),
    };

    // when
    let extracted = inspector
        .extract(
            tx_id,
            TonFinality::MasterchainIncluded,
            vec![TonExtractor::Log { message_index: 0 }],
        )
        .await
        .expect("extract should succeed");

    // then
    let log = take_log(extracted);
    assert_eq!(log.from_address, Hash256(hex_to_32(FX_C_ACCOUNT_HEX)));
    assert_eq!(log.body_bits, hex_decode(FX_C_BODY_BITS_HEX));
    assert_eq!(log.body_refs.len(), 2);

    let (bit_len_0, data_0, refs_0) = structural_ref(&log.body_refs[0]);
    assert_eq!(bit_len_0, FX_C_REF0_DATA.len() * 8);
    assert_eq!(&data_0[..FX_C_REF0_DATA.len()], FX_C_REF0_DATA);
    assert_eq!(refs_0, 0);

    let (bit_len_1, data_1, refs_1) = structural_ref(&log.body_refs[1]);
    assert_eq!(bit_len_1, FX_C_REF1_DATA.len() * 8);
    assert_eq!(&data_1[..FX_C_REF1_DATA.len()], FX_C_REF1_DATA);
    assert_eq!(refs_1, 0);
}

#[tokio::test]
async fn extract__should_reject_when_mc_block_seqno_is_null() {
    // given — same fixture but mc_block_seqno patched to null
    let server = MockServer::start();
    let fixture = load_fixture("simple_no_refs.json");
    let mut v: Value = serde_json::from_str(&fixture).unwrap();
    v["transactions"][0]["mc_block_seqno"] = Value::Null;
    mount_toncenter_mock(&server, &serde_json::to_string(&v).unwrap());

    let inspector = inspector_for(&server);
    let tx_id = TonTransactionId {
        workchain: 0,
        account: hex_to_32(FX_A_ACCOUNT_HEX),
        tx_hash: hex_to_32(FX_A_TX_HASH_HEX),
    };

    // when
    let result = inspector
        .extract(
            tx_id,
            TonFinality::MasterchainIncluded,
            vec![TonExtractor::Log { message_index: 0 }],
        )
        .await;

    // then
    assert!(
        matches!(result, Err(ForeignChainInspectionError::NotFinalized)),
        "expected NotFinalized, got {result:?}"
    );
}

#[tokio::test]
async fn extract__should_reject_when_description_aborted() {
    // given — same fixture but description.aborted flipped to true
    let server = MockServer::start();
    let fixture = load_fixture("event_with_ref.json");
    let mut v: Value = serde_json::from_str(&fixture).unwrap();
    v["transactions"][0]["description"]["aborted"] = Value::Bool(true);
    mount_toncenter_mock(&server, &serde_json::to_string(&v).unwrap());

    let inspector = inspector_for(&server);
    let tx_id = TonTransactionId {
        workchain: 0,
        account: hex_to_32(FX_B_ACCOUNT_HEX),
        tx_hash: hex_to_32(FX_B_TX_HASH_HEX),
    };

    // when
    let result = inspector
        .extract(
            tx_id,
            TonFinality::MasterchainIncluded,
            vec![TonExtractor::Log { message_index: 0 }],
        )
        .await;

    // then
    assert!(
        matches!(result, Err(ForeignChainInspectionError::TransactionFailed)),
        "expected TransactionFailed, got {result:?}"
    );
}

#[tokio::test]
async fn extract__should_reject_when_account_in_response_does_not_match_request() {
    // given — request for account A, but fixture response is for account B
    let server = MockServer::start();
    let fixture = load_fixture("event_with_ref.json");
    mount_toncenter_mock(&server, &fixture);

    let inspector = inspector_for(&server);
    let tx_id = TonTransactionId {
        workchain: 0,
        account: hex_to_32(FX_A_ACCOUNT_HEX),
        tx_hash: hex_to_32(FX_B_TX_HASH_HEX),
    };

    // when
    let result = inspector
        .extract(
            tx_id,
            TonFinality::MasterchainIncluded,
            vec![TonExtractor::Log { message_index: 0 }],
        )
        .await;

    // then
    assert!(
        matches!(
            result,
            Err(ForeignChainInspectionError::AccountMismatch { .. })
        ),
        "expected AccountMismatch, got {result:?}"
    );
}
