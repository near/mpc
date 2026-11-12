use super::*;
use crate::providers::verify_foreign_tx::testing::{TestProvider, open_with};
use httpmock::prelude::*;
use httpmock::{HttpMockRequest, HttpMockResponse};
use near_time::Clock;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

const MOCK_BLOCK_HASH: [u8; 32] = [0xaa; 32];

/// Serves an Ethereum transaction in block 10. The first finality check reports block 5 as
/// final, a transient error, and every later one block 100.
fn start_ethereum_rpc_mock_final_on_second_check() -> MockServer {
    start_ethereum_rpc_mock(|| {})
}

/// Like [`start_ethereum_rpc_mock_final_on_second_check`], and runs `on_rpc_call` before it
/// answers each call.
fn start_ethereum_rpc_mock(on_rpc_call: impl Fn() + Send + Sync + 'static) -> MockServer {
    let server = MockServer::start();
    let finality_checks = Arc::new(AtomicUsize::new(0));
    server.mock(|when, then| {
        when.method(POST);
        then.respond_with(move |req: &HttpMockRequest| {
            on_rpc_call();
            let body: serde_json::Value = serde_json::from_slice(req.body().as_ref()).unwrap();
            let hash = format!("0x{}", hex::encode(MOCK_BLOCK_HASH));
            let result = match body["method"].as_str().unwrap() {
                "eth_getTransactionReceipt" => serde_json::json!({
                    "transactionHash": body["params"][0],
                    "blockHash": hash,
                    "blockNumber": "0xa",
                    "status": "0x1",
                    "logs": [],
                }),
                "eth_getBlockByNumber" if body["params"][0] == "finalized" => {
                    let number = match finality_checks.fetch_add(1, Ordering::SeqCst) {
                        0 => "0x5",
                        _ => "0x64",
                    };
                    serde_json::json!({ "number": number, "hash": hash })
                }
                "eth_getBlockByNumber" => serde_json::json!({ "number": "0xa", "hash": hash }),
                other => panic!("unexpected ethereum rpc method: {other}"),
            };
            HttpMockResponse::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(
                    serde_json::json!({ "jsonrpc": "2.0", "result": result, "id": body["id"] })
                        .to_string(),
                )
                .build()
        });
    });
    server
}

fn ethereum_request() -> dtos::ForeignChainRpcRequest {
    dtos::ForeignChainRpcRequest::Ethereum(dtos::EvmRpcRequest {
        tx_id: dtos::EvmTxId([0xbb; 32]),
        extractors: [dtos::EvmExtractor::BlockHash].into(),
        finality: dtos::EvmFinality::Finalized,
    })
}

/// A request on Ethereum that expects the block hash the RPC mock serves.
fn ethereum_v2_request() -> VerifyForeignTxRequestV2 {
    VerifyForeignTxRequestV2 {
        request: ethereum_request(),
        expected_values_hash: dtos::VerifyForeignTransactionRequestV2 {
            request: ethereum_request(),
            domain_id: DomainId(0),
            expected_values: vec![dtos::ExtractedValue::EvmExtractedValue(
                dtos::EvmExtractedValue::BlockHash(dtos::Hash256(MOCK_BLOCK_HASH)),
            )],
        }
        .expected_values_hash()
        .unwrap(),
        ..request()
    }
}

fn node_outcomes_sent(
    transport: &TestMeshTransportSender,
) -> Vec<(ParticipantId, SignedNodeOutcome)> {
    transport
        .take_packets_sent()
        .into_iter()
        .filter_map(|(recipient, packet)| match packet {
            Packet::NodeOutcome(outcome) => Some((recipient, outcome)),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn reach_node_outcome__should_retry_a_transient_error_within_the_inspection_cap() {
    // Given
    let rpc_mock = start_ethereum_rpc_mock_final_on_second_check();
    let (client, _transport) =
        new_test_client_with_versions(vec![ME], ME, current_protocol_versions(&[ME]));
    let (open_requests, _chain) = open_with(ethereum_v2_request(), Clock::real());
    let node = TestProvider::with_ethereum_rpc(
        client,
        open_requests,
        HashSet::from([ME]),
        &rpc_mock.base_url(),
    );

    // When
    let outcome = node
        .provider
        .reach_node_outcome(
            &ethereum_request(),
            &ethereum_v2_request().expected_values_hash,
        )
        .await;

    // Then
    assert_eq!(
        outcome.unwrap(),
        NodeOutcome::Verdict(NodeVerdict::Verified)
    );
}

#[tokio::test]
async fn inspect_and_send_node_outcome__should_send_its_signed_outcome_to_every_peer() {
    // Given
    let rpc_mock = start_ethereum_rpc_mock_final_on_second_check();
    let participants = vec![ME, PEER];
    let (client, transport) = new_test_client_with_versions(
        participants.clone(),
        ME,
        current_protocol_versions(&participants),
    );
    client
        .node_outcomes()
        .set_outcome_keys(outcome_public_keys(&[ME]));
    client.node_outcomes().index([request().yield_id]);
    let (open_requests, mut chain) = open_with(ethereum_v2_request(), Clock::real());
    let node = TestProvider::with_ethereum_rpc(
        client.clone(),
        open_requests.clone(),
        HashSet::from([ME, PEER]),
        &rpc_mock.base_url(),
    );
    let settle_once_kept = async {
        loop {
            let changed = client.node_outcomes().changed();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !client
                .node_outcomes()
                .outcomes_of(request().yield_id)
                .is_empty()
            {
                break;
            }
            changed.await;
        }
        open_requests.notify_new_block(&chain.extend(vec![], vec![request().id]));
        open_requests.notify_new_block(&chain.extend(vec![], vec![]));
        open_requests.notify_new_block(&chain.extend(vec![], vec![]));
    };

    // When
    let (inspected, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(
            node.provider
                .inspect_and_send_node_outcome(ethereum_v2_request()),
            settle_once_kept
        )
    })
    .await
    .unwrap();

    // Then
    inspected.unwrap();
    let sent = node_outcomes_sent(&transport);
    let [(recipient, outcome)] = &sent[..] else {
        panic!("expected one node outcome, got {sent:?}");
    };
    assert_eq!(*recipient, PEER);
    let statement = outcome
        .clone()
        .verify(&outcome_public_keys(&[ME]))
        .unwrap()
        .statement()
        .clone();
    assert_eq!(
        statement,
        NodeOutcomeStatement {
            yield_id: request().yield_id,
            signer: ME,
            outcome: NodeOutcome::Verdict(NodeVerdict::Verified),
        }
    );
}

#[tokio::test]
async fn inspect_and_send_node_outcome__should_stay_silent_on_a_chain_it_does_not_support() {
    // Given
    let rpc_calls = Arc::new(AtomicUsize::new(0));
    let rpc_mock = start_ethereum_rpc_mock({
        let rpc_calls = rpc_calls.clone();
        move || {
            rpc_calls.fetch_add(1, Ordering::SeqCst);
        }
    });
    let participants = vec![ME, PEER];
    let (client, transport) = new_test_client_with_versions(
        participants.clone(),
        ME,
        current_protocol_versions(&participants),
    );
    client.node_outcomes().index([request().yield_id]);
    let (open_requests, _chain) = open_with(ethereum_v2_request(), Clock::real());
    let node = TestProvider::with_ethereum_rpc(
        client.clone(),
        open_requests,
        HashSet::from([PEER]),
        &rpc_mock.base_url(),
    );

    // When
    let inspected = tokio::time::timeout(
        Duration::from_secs(5),
        node.provider
            .inspect_and_send_node_outcome(ethereum_v2_request()),
    )
    .await
    .unwrap();

    // Then
    inspected.unwrap();
    assert_eq!(node_outcomes_sent(&transport), vec![]);
    assert!(
        client
            .node_outcomes()
            .outcomes_of(request().yield_id)
            .is_empty()
    );
    assert_eq!(rpc_calls.load(Ordering::SeqCst), 0);
}
