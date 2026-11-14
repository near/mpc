#![allow(non_snake_case)]

pub mod common;

use crate::common::{FixedResponseRpcClient, mock_client_from_fixed_response};

use base64::Engine as _;
use foreign_chain_inspector::{
    ForeignChainInspectionError, ForeignChainInspector, NetworkFingerprintInspector,
    ProviderFailure, Verdict,
    svm::{
        SvmExtractedValue, SvmTransactionSignature,
        inspector::{SolanaInspector, SvmExtractor, SvmFinality},
    },
};
use jsonrpsee::core::client::{BatchResponse, ClientT, error::Error as RpcClientError};
use jsonrpsee::core::params::BatchRequestBuilder;
use near_mpc_contract_interface::types::{SvmAccount, SvmAddress, SvmInnerInstruction};
use rstest::rstest;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::{
    assert_matches,
    sync::atomic::{AtomicUsize, Ordering},
};

const TX_SLOT: u64 = 296_112_296;

/// Like `SequentialResponseMockClientBuilder`, but records each request's method and
/// params — the `common` mocks discard both, so they cannot pin what the inspector sends.
#[derive(Clone)]
struct RecordingClient(Arc<RecordingClientInner>);

struct RecordingClientInner {
    responses: Vec<serde_json::Value>,
    call_count: AtomicUsize,
    requests: Mutex<Vec<(String, serde_json::Value)>>,
}

impl RecordingClient {
    fn new(responses: Vec<serde_json::Value>) -> Self {
        Self(Arc::new(RecordingClientInner {
            responses,
            call_count: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
        }))
    }

    fn requests(&self) -> Vec<(String, serde_json::Value)> {
        self.0.requests.lock().unwrap().clone()
    }
}

impl ClientT for RecordingClient {
    async fn request<R, Params>(&self, method: &str, params: Params) -> Result<R, RpcClientError>
    where
        R: serde::de::DeserializeOwned,
        Params: jsonrpsee::core::traits::ToRpcParams + Send,
    {
        let params = params
            .to_rpc_params()
            .map_err(RpcClientError::ParseError)?
            .map(|raw| serde_json::from_str(raw.get()).unwrap())
            .unwrap_or(serde_json::Value::Null);
        self.0
            .requests
            .lock()
            .unwrap()
            .push((method.to_string(), params));
        let call = self.0.call_count.fetch_add(1, Ordering::SeqCst);
        let response = self.0.responses.get(call).cloned().unwrap_or_else(|| {
            panic!(
                "mock client received call #{} but only {} responses were configured",
                call + 1,
                self.0.responses.len(),
            )
        });
        serde_json::from_value(response).map_err(RpcClientError::ParseError)
    }

    async fn notification<Params>(&self, _: &str, _: Params) -> Result<(), RpcClientError> {
        unimplemented!("notification() not used in tests")
    }

    async fn batch_request<'a, R>(
        &self,
        _: BatchRequestBuilder<'a>,
    ) -> Result<BatchResponse<'a, R>, RpcClientError>
    where
        R: serde::de::DeserializeOwned + std::fmt::Debug + 'a,
    {
        unimplemented!("batch_request() not used in tests")
    }
}

fn tx_id() -> SvmTransactionSignature {
    SvmTransactionSignature::from([7; 64])
}

fn key(byte: u8) -> String {
    bs58::encode([byte; 32]).into_string()
}

/// A confirmed, successful v0 transaction whose top-level instruction 1 produced two
/// inner instructions; account list = three static keys ++ one writable ++ one readonly.
fn confirmed_tx() -> serde_json::Value {
    json!({
        "slot": TX_SLOT,
        "transaction": {
            "signatures": [bs58::encode([7; 64]).into_string()],
            "message": {
                "accountKeys": [key(1), key(2), key(3)],
                "recentBlockhash": key(9),
                "instructions": [],
            },
        },
        "meta": {
            "err": null,
            "innerInstructions": [
                {
                    "index": 1,
                    "instructions": [
                        // References a static key (program) and a loaded one (account).
                        { "programIdIndex": 2, "accounts": [0, 3], "data": bs58::encode([0xde, 0xad, 0xbe, 0xef]).into_string(), "stackHeight": 2 },
                        { "programIdIndex": 4, "accounts": [], "data": "", "stackHeight": 3 },
                    ],
                },
            ],
            "loadedAddresses": { "writable": [key(4)], "readonly": [key(5)] },
        },
    })
}

fn account_info(owner_byte: u8, data: &[u8]) -> serde_json::Value {
    account_info_at_slot(owner_byte, data, TX_SLOT + 10)
}

fn account_info_at_slot(owner_byte: u8, data: &[u8], slot: u64) -> serde_json::Value {
    json!({
        "context": { "apiVersion": "2.0.15", "slot": slot },
        "value": {
            // Served by the RPC but deliberately not extracted: see `SvmAccount`.
            "lamports": 1_000_000u64,
            "owner": key(owner_byte),
            "data": [base64::engine::general_purpose::STANDARD.encode(data), "base64"],
            "executable": false,
            "rentEpoch": u64::MAX,
            "space": data.len(),
        },
    })
}

fn inner_instruction_extractor() -> SvmExtractor {
    SvmExtractor::InnerInstruction {
        instruction_index: 1,
        inner_instruction_index: 0,
    }
}

fn account_state_extractor() -> SvmExtractor {
    SvmExtractor::AccountState {
        pubkey: SvmAddress([6; 32]),
    }
}

fn confirmed_tx_with(pointer: &str, value: serde_json::Value) -> serde_json::Value {
    let mut tx = confirmed_tx();
    *tx.pointer_mut(pointer).unwrap() = value;
    tx
}

fn resolved_inner_instruction() -> SvmExtractedValue {
    SvmExtractedValue::InnerInstruction(SvmInnerInstruction {
        program_id: SvmAddress([3; 32]),
        accounts: vec![SvmAddress([1; 32]), SvmAddress([4; 32])],
        data: vec![0xde, 0xad, 0xbe, 0xef],
    })
}

async fn extract_from(
    responses: Vec<serde_json::Value>,
    finality: SvmFinality,
    extractors: Vec<SvmExtractor>,
) -> Result<Verdict<SvmExtractedValue>, ForeignChainInspectionError> {
    SolanaInspector::new(RecordingClient::new(responses))
        .extract(tx_id(), finality, extractors)
        .await
}

#[tokio::test]
async fn extract__should_read_a_repeated_account_once() {
    // Given — one response per distinct account, so a second read would exhaust the mock.
    let mock_client = RecordingClient::new(vec![confirmed_tx(), account_info(8, b"once")]);
    let inspector = SolanaInspector::new(mock_client.clone());

    // When
    let values = inspector
        .extract(
            tx_id(),
            SvmFinality::Confirmed,
            vec![
                SvmExtractor::AccountState {
                    pubkey: SvmAddress([6; 32]),
                },
                SvmExtractor::AccountState {
                    pubkey: SvmAddress([6; 32]),
                },
            ],
        )
        .await
        .unwrap()
        .into_extracted()
        .unwrap();

    // Then — both extractors resolve, from a single round trip, to the same state.
    let expected = SvmExtractedValue::AccountState(SvmAccount {
        owner: SvmAddress([8; 32]),
        data: b"once".to_vec(),
    });
    assert_eq!(values, vec![expected.clone(), expected]);
    let account_reads = mock_client
        .requests()
        .into_iter()
        .filter(|(method, _)| method == "getAccountInfo")
        .count();
    assert_eq!(account_reads, 1);
}

#[tokio::test]
async fn extract__should_read_distinct_accounts_separately() {
    // Given
    let mock_client = RecordingClient::new(vec![
        confirmed_tx(),
        account_info(8, b"first"),
        account_info(9, b"second"),
    ]);
    let inspector = SolanaInspector::new(mock_client.clone());

    // When
    let values = inspector
        .extract(
            tx_id(),
            SvmFinality::Confirmed,
            vec![
                SvmExtractor::AccountState {
                    pubkey: SvmAddress([6; 32]),
                },
                SvmExtractor::AccountState {
                    pubkey: SvmAddress([7; 32]),
                },
            ],
        )
        .await
        .unwrap()
        .into_extracted()
        .unwrap();

    // Then — deduplication keys on the pubkey, so distinct accounts are both read, in order.
    assert_eq!(
        values,
        vec![
            SvmExtractedValue::AccountState(SvmAccount {
                owner: SvmAddress([8; 32]),
                data: b"first".to_vec(),
            }),
            SvmExtractedValue::AccountState(SvmAccount {
                owner: SvmAddress([9; 32]),
                data: b"second".to_vec(),
            }),
        ]
    );
    let requests = mock_client.requests();
    assert_eq!(requests[1].1[0], bs58::encode([6; 32]).into_string());
    assert_eq!(requests[2].1[0], bs58::encode([7; 32]).into_string());
}

#[tokio::test]
async fn extract__should_read_account_state_at_finalized_when_finality_is_finalized() {
    // Given — the only combination in which `Commitment::Finalized` reaches `getAccountInfo`.
    let mock_client = RecordingClient::new(vec![confirmed_tx(), account_info(8, b"rooted")]);
    let inspector = SolanaInspector::new(mock_client.clone());

    // When
    let values = inspector
        .extract(
            tx_id(),
            SvmFinality::Finalized,
            vec![SvmExtractor::AccountState {
                pubkey: SvmAddress([6; 32]),
            }],
        )
        .await
        .unwrap()
        .into_extracted()
        .unwrap();

    // Then
    assert_eq!(
        values,
        vec![SvmExtractedValue::AccountState(SvmAccount {
            owner: SvmAddress([8; 32]),
            data: b"rooted".to_vec(),
        })]
    );
    // Asserted on the recorded params: decoded responses alone cannot show the commitment.
    let requests = mock_client.requests();
    assert_eq!(requests.len(), 2, "the rooted answer needs no second read");
    assert_eq!(requests[1].0, "getAccountInfo");
    assert_eq!(requests[1].1[1]["commitment"], "finalized");
    assert_eq!(requests[1].1[1]["encoding"], "base64");
}

#[rstest]
#[case::confirmed(SvmFinality::Confirmed, "confirmed")]
#[case::finalized(SvmFinality::Finalized, "finalized")]
#[tokio::test]
async fn extract__should_query_the_transaction_at_the_requested_commitment_with_version_zero(
    #[case] finality: SvmFinality,
    #[case] expected_commitment: &str,
) {
    // Given
    let mock_client = RecordingClient::new(vec![confirmed_tx()]);
    let inspector = SolanaInspector::new(mock_client.clone());

    // When
    inspector
        .extract(tx_id(), finality, vec![inner_instruction_extractor()])
        .await
        .unwrap();

    // Then — the commitment carries the finality check; without version 0 every v0
    // transaction errors.
    let requests = mock_client.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, "getTransaction");
    let config = &requests[0].1[1];
    assert_eq!(config["commitment"], expected_commitment);
    assert_eq!(config["encoding"], "json");
    assert_eq!(config["maxSupportedTransactionVersion"], 0);
}

#[tokio::test]
async fn extract__should_accept_finalized_transaction_when_finality_is_finalized() {
    // Given — the provider serves the transaction at `finalized`, i.e. from a slot it rooted.

    // When
    let values = extract_from(
        vec![confirmed_tx()],
        SvmFinality::Finalized,
        vec![inner_instruction_extractor()],
    )
    .await
    .unwrap()
    .into_extracted()
    .unwrap();

    // Then
    assert_eq!(values.len(), 1);
}

#[tokio::test]
async fn extract__should_return_not_finalized_when_the_transaction_is_only_confirmed() {
    // Given — null at `finalized`, then the same transaction at `confirmed`: it exists but
    // the provider has not rooted its slot.
    let mock_client = RecordingClient::new(vec![serde_json::Value::Null, confirmed_tx()]);
    let inspector = SolanaInspector::new(mock_client.clone());

    // When
    let response = inspector
        .extract(
            tx_id(),
            SvmFinality::Finalized,
            vec![inner_instruction_extractor()],
        )
        .await;

    // Then — "not final yet" is a transient verdict, not an error.
    assert_matches!(response, Err(ForeignChainInspectionError::NotFinalized));
    assert!(response.unwrap_err().is_transient());
    let requests = mock_client.requests();
    assert_eq!(requests[0].1[1]["commitment"], "finalized");
    assert_eq!(requests[1].1[1]["commitment"], "confirmed");
}

#[rstest]
#[case::resolved_inner_instruction(
    vec![confirmed_tx()],
    SvmFinality::Confirmed,
    vec![inner_instruction_extractor()],
    Verdict::Extracted(vec![resolved_inner_instruction()]),
)]
#[case::program_id_from_loaded_addresses(
    vec![confirmed_tx()],
    SvmFinality::Confirmed,
    vec![SvmExtractor::InnerInstruction {
        instruction_index: 1,
        inner_instruction_index: 1,
    }],
    Verdict::Extracted(vec![SvmExtractedValue::InnerInstruction(SvmInnerInstruction {
        program_id: SvmAddress([5; 32]),
        accounts: vec![],
        data: vec![],
    })]),
)]
#[case::account_state(
    vec![confirmed_tx(), account_info(8, b"bridge message")],
    SvmFinality::Confirmed,
    vec![account_state_extractor()],
    Verdict::Extracted(vec![SvmExtractedValue::AccountState(SvmAccount {
        owner: SvmAddress([8; 32]),
        data: b"bridge message".to_vec(),
    })]),
)]
#[case::account_read_answered_at_the_transaction_slot(
    vec![confirmed_tx(), account_info_at_slot(8, b"fresh", TX_SLOT)],
    SvmFinality::Confirmed,
    vec![account_state_extractor()],
    Verdict::Extracted(vec![SvmExtractedValue::AccountState(SvmAccount {
        owner: SvmAddress([8; 32]),
        data: b"fresh".to_vec(),
    })]),
)]
#[case::values_in_extractor_order(
    vec![confirmed_tx(), account_info(8, &[0xca, 0xfe])],
    SvmFinality::Confirmed,
    vec![inner_instruction_extractor(), account_state_extractor()],
    Verdict::Extracted(vec![
        resolved_inner_instruction(),
        SvmExtractedValue::AccountState(SvmAccount {
            owner: SvmAddress([8; 32]),
            data: vec![0xca, 0xfe],
        }),
    ]),
)]
#[case::transaction_not_found_only_when_neither_commitment_has_it(
    vec![serde_json::Value::Null, serde_json::Value::Null],
    SvmFinality::Finalized,
    vec![inner_instruction_extractor()],
    Verdict::TransactionNotFound,
)]
#[case::null_response_is_a_settled_transaction_not_found_verdict(
    vec![serde_json::Value::Null],
    SvmFinality::Confirmed,
    vec![inner_instruction_extractor()],
    Verdict::TransactionNotFound,
)]
#[case::failed_transaction(
    vec![confirmed_tx_with("/meta/err", json!({ "InstructionError": [0, { "Custom": 6000 }] }))],
    SvmFinality::Confirmed,
    vec![inner_instruction_extractor()],
    Verdict::TransactionFailed,
)]
#[case::no_inner_instruction_entry_for_top_level_instruction(
    vec![confirmed_tx()],
    SvmFinality::Confirmed,
    vec![SvmExtractor::InnerInstruction {
        instruction_index: 0,
        inner_instruction_index: 0,
    }],
    Verdict::LogIndexOutOfBounds,
)]
#[case::inner_index_beyond_entry(
    vec![confirmed_tx()],
    SvmFinality::Confirmed,
    vec![SvmExtractor::InnerInstruction {
        instruction_index: 1,
        inner_instruction_index: 99,
    }],
    Verdict::LogIndexOutOfBounds,
)]
#[case::empty_inner_instruction_list_is_the_chains_own_answer(
    vec![confirmed_tx_with("/meta/innerInstructions", json!([]))],
    SvmFinality::Confirmed,
    vec![inner_instruction_extractor()],
    Verdict::LogIndexOutOfBounds,
)]
#[case::account_not_found_for_null_account_value(
    vec![confirmed_tx(), json!({ "context": { "slot": TX_SLOT }, "value": null })],
    SvmFinality::Confirmed,
    vec![account_state_extractor()],
    Verdict::AccountNotFound,
)]
#[tokio::test]
async fn extract__should_return_the_expected_verdict(
    #[case] responses: Vec<serde_json::Value>,
    #[case] finality: SvmFinality,
    #[case] extractors: Vec<SvmExtractor>,
    #[case] expected: Verdict<SvmExtractedValue>,
) {
    // When
    let response = extract_from(responses, finality, extractors).await;

    // Then
    assert_eq!(response.unwrap(), expected);
}

#[rstest]
#[case::null_inner_instructions_means_not_recorded_unlike_the_empty_list(
    vec![confirmed_tx_with("/meta/innerInstructions", serde_json::Value::Null)],
    vec![inner_instruction_extractor()],
)]
#[case::account_read_answered_before_the_transaction_slot_from_a_lagging_backend(
    vec![confirmed_tx(), account_info_at_slot(8, b"stale", TX_SLOT - 1)],
    vec![account_state_extractor()],
)]
#[tokio::test]
async fn extract__should_report_a_transient_provider_failure(
    #[case] responses: Vec<serde_json::Value>,
    #[case] extractors: Vec<SvmExtractor>,
) {
    // When
    let error = extract_from(responses, SvmFinality::Confirmed, extractors)
        .await
        .unwrap_err();

    // Then
    assert_matches!(error, ForeignChainInspectionError::RpcRequestFailed(_));
    assert!(error.is_transient());
}

#[tokio::test]
async fn extract__should_not_read_a_failed_finality_recheck_as_transaction_not_found() {
    // Given — null at `finalized`, and the `confirmed` re-read fails outright.
    let call_count = AtomicUsize::new(0);
    let mock_client = FixedResponseRpcClient::new(move || {
        if call_count.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(serde_json::Value::Null)
        } else {
            Err(RpcClientError::RequestTimeout)
        }
    });
    let inspector = SolanaInspector::new(mock_client);

    // When
    let error = inspector
        .extract(
            tx_id(),
            SvmFinality::Finalized,
            vec![inner_instruction_extractor()],
        )
        .await
        .unwrap_err();

    // Then — the provider's own failure must not stand in for the chain's verdict.
    assert_matches!(error, ForeignChainInspectionError::Timeout);
    assert!(error.is_transient());
}

#[tokio::test]
async fn extract__should_reject_response_with_mismatched_signature() {
    // Given — the provider returns a different transaction than queried.
    let tx = confirmed_tx_with(
        "/transaction/signatures",
        json!([bs58::encode([8; 64]).into_string()]),
    );

    // When
    let response = extract_from(
        vec![tx],
        SvmFinality::Confirmed,
        vec![inner_instruction_extractor()],
    )
    .await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::InconsistentRpcResponse { .. })
    );
}

#[tokio::test]
async fn extract__should_report_missing_meta_as_a_provider_failure() {
    // Given — a node that holds the transaction but not its status metadata.
    let tx = confirmed_tx_with("/meta", serde_json::Value::Null);

    // When
    let response = extract_from(
        vec![tx],
        SvmFinality::Confirmed,
        vec![inner_instruction_extractor()],
    )
    .await;

    // Then — the same class as an unrecorded inner-instruction list, and reported the same
    // way: a gap in what this provider serves, not data the chain settled or a broken payload.
    let error = response.unwrap_err();
    assert_matches!(error, ForeignChainInspectionError::RpcRequestFailed(_));
    assert_eq!(error.provider_failure(), Some(ProviderFailure::Unreachable));
}

#[tokio::test]
async fn extract__should_report_absent_transaction_history_as_a_provider_failure() {
    // Given — a node started without `--enable-rpc-transaction-history` (the default) answers
    // `getTransaction` with code -32011.
    let mock_client = FixedResponseRpcClient::new(|| {
        Err(RpcClientError::Call(jsonrpsee::types::ErrorObject::owned(
            -32011,
            "Transaction history is not available from this node",
            None::<()>,
        )))
    });
    let inspector = SolanaInspector::new(mock_client);

    // When
    let response = inspector
        .extract(
            tx_id(),
            SvmFinality::Confirmed,
            vec![inner_instruction_extractor()],
        )
        .await;

    // Then — a capability gap, not the deterministic refusal the shared classifier would read
    // any unrecognized JSON-RPC code as.
    let error = response.unwrap_err();
    assert_matches!(error, ForeignChainInspectionError::RpcRequestFailed(_));
    assert!(error.is_transient());
}

#[tokio::test]
async fn extract__should_reject_out_of_bounds_account_index_as_malformed() {
    // Given — an instruction referencing an account index past the full key list.
    let tx = confirmed_tx_with(
        "/meta/innerInstructions/0/instructions/0/accounts",
        json!([99]),
    );

    // When
    let response = extract_from(
        vec![tx],
        SvmFinality::Confirmed,
        vec![inner_instruction_extractor()],
    )
    .await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::MalformedRpcResponse(_))
    );
}

#[tokio::test]
async fn extract__should_reject_oversized_account_list_before_resolving_it() {
    // Given — index 99 is out of bounds, so resolve-then-cap would answer "index out of
    // bounds"; the count in the message proves the cap fired before resolving.
    let tx = confirmed_tx_with(
        "/meta/innerInstructions/0/instructions/0/accounts",
        json!(vec![99u8; 300]),
    );

    // When
    let response = extract_from(
        vec![tx],
        SvmFinality::Confirmed,
        vec![inner_instruction_extractor()],
    )
    .await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::MalformedRpcResponse(message)) if message.contains("lists 300 accounts")
    );
}

#[tokio::test]
async fn extract__should_reject_an_account_response_omitting_value_as_malformed() {
    // Given — a provider that omits `value` rather than answering `null`.
    let responses = vec![confirmed_tx(), json!({ "context": { "slot": TX_SLOT } })];

    // When
    let response = extract_from(
        responses,
        SvmFinality::Confirmed,
        vec![account_state_extractor()],
    )
    .await;

    // Then — the provider is at fault, not the chain: an omitted field must not read as an
    // absent account, which would blame nobody for a broken response.
    let error = response.unwrap_err();
    assert_matches!(
        error,
        ForeignChainInspectionError::MalformedRpcResponse(_),
        "an omitted `value` must not be indistinguishable from an absent account"
    );
    assert_eq!(error.provider_failure(), Some(ProviderFailure::Malformed));
}

#[tokio::test]
async fn extract__should_reject_account_data_in_wrong_encoding_as_malformed() {
    // Given — a provider that ignored the requested base64 encoding.
    let mut account = account_info(8, &[1, 2, 3]);
    account["value"]["data"] = json!(["3Bxs4NN8M2Yn4TLb", "base58"]);

    // When
    let response = extract_from(
        vec![confirmed_tx(), account],
        SvmFinality::Confirmed,
        vec![account_state_extractor()],
    )
    .await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::MalformedRpcResponse(_))
    );
}

#[tokio::test]
async fn network_fingerprint__should_report_the_genesis_hash() {
    // Given — Solana mainnet's genesis hash.
    let genesis_hash = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
    let mock_client = mock_client_from_fixed_response(genesis_hash.to_string());
    let inspector = SolanaInspector::new(mock_client);

    // When
    let fingerprint = inspector.network_fingerprint().await.unwrap();

    // Then
    assert_eq!(fingerprint.to_string(), genesis_hash);
}
