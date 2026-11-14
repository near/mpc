#![allow(non_snake_case)]

use foreign_chain_inspector::Verdict;
use foreign_chain_inspector::{
    ForeignChainInspectionError, ForeignChainInspector, NetworkFingerprintInspector,
    sui::{
        MAINNET_GENESIS_CHECKPOINT_DIGEST, SuiExtractedValue, SuiTransactionDigest,
        inspector::{SuiExtractor, SuiFinality, SuiInspector},
    },
};
use foreign_chain_rpc_interfaces::sui::proto::{
    Bcs, Event, ExecutedTransaction, ExecutionStatus, GetCheckpointResponse,
    GetServiceInfoResponse, GetTransactionResponse, TransactionEffects, TransactionEvents,
};
use foreign_chain_rpc_interfaces::sui::{Status, SuiRpcClient};
use near_mpc_contract_interface::types::{SuiAddress, SuiEvent};
use rstest::rstest;
use std::assert_matches;

const EVENT_BCS_BYTES: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

struct MockSuiClient {
    response: Option<Result<GetTransactionResponse, Status>>,
    service_info: Option<Result<GetServiceInfoResponse, Status>>,
}

impl MockSuiClient {
    fn answering(response: GetTransactionResponse) -> Self {
        Self {
            response: Some(Ok(response)),
            service_info: None,
        }
    }

    fn transaction(tx: ExecutedTransaction) -> Self {
        Self::answering(GetTransactionResponse::default().with_transaction(tx))
    }

    fn status(status: Status) -> Self {
        Self {
            response: Some(Err(status.clone())),
            service_info: Some(Err(status)),
        }
    }

    fn serving(service_info: GetServiceInfoResponse) -> Self {
        Self {
            response: None,
            service_info: Some(Ok(service_info)),
        }
    }
}

impl SuiRpcClient for MockSuiClient {
    async fn get_transaction(&self, _digest: &str) -> Result<GetTransactionResponse, Status> {
        self.response
            .clone()
            .expect("test did not arm get_transaction")
    }

    async fn get_service_info(&self) -> Result<GetServiceInfoResponse, Status> {
        self.service_info
            .clone()
            .expect("test did not arm get_service_info")
    }

    async fn get_checkpoint(&self, _sequence_number: u64) -> Result<GetCheckpointResponse, Status> {
        unimplemented!("get_checkpoint() not used by the inspector")
    }
}

fn tx_id() -> SuiTransactionDigest {
    SuiTransactionDigest::from([0xab; 32])
}

fn tx_digest_base58() -> String {
    bs58::encode([0xab; 32]).into_string()
}

fn framework_event() -> Event {
    Event::default()
        .with_package_id("0x0000000000000000000000000000000000000000000000000000000000000003")
        .with_module("sui_system")
        .with_sender("0x0000000000000000000000000000000000000000000000000000000000000000")
        // Short-form framework address: the inspector must normalize it to the long form.
        .with_event_type("0x3::validator_set::ValidatorEpochInfoEventV2")
        .with_contents(
            Bcs::default()
                .with_name("0x3::validator_set::ValidatorEpochInfoEventV2")
                .with_value(EVENT_BCS_BYTES.to_vec()),
        )
}

fn checkpointed_tx(events: Vec<Event>) -> ExecutedTransaction {
    ExecutedTransaction::default()
        .with_digest(tx_digest_base58())
        .with_effects(
            TransactionEffects::default()
                .with_status(ExecutionStatus::default().with_success(true)),
        )
        .with_events(TransactionEvents::default().with_events(events))
        .with_checkpoint(296_112_296u64)
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

fn checkpointed_tx_with(modify: impl FnOnce(&mut ExecutedTransaction)) -> ExecutedTransaction {
    let mut tx = checkpointed_tx(vec![]);
    modify(&mut tx);
    tx
}

fn framework_event_without_contents() -> Event {
    let mut event = framework_event();
    event.contents = None;
    event
}

async fn extract_from(
    client: MockSuiClient,
    extractors: Vec<SuiExtractor>,
) -> Result<Verdict<SuiExtractedValue>, ForeignChainInspectionError> {
    SuiInspector::new(client)
        .extract(tx_id(), SuiFinality::Checkpointed, extractors)
        .await
}

#[tokio::test]
async fn extract__should_return_correct_event_for_specific_index() {
    // Given a transaction with two events.
    let second = framework_event()
        .with_event_type("0x3::validator::StakingRequestEvent")
        .with_contents(
            Bcs::default()
                .with_name("0x3::validator::StakingRequestEvent")
                .with_value(EVENT_BCS_BYTES.to_vec()),
        );
    let tx = checkpointed_tx(vec![framework_event(), second]);
    let inspector = SuiInspector::new(MockSuiClient::transaction(tx));

    // When
    let extracted_values = inspector
        .extract(
            tx_id(),
            SuiFinality::Checkpointed,
            vec![SuiExtractor::Event { event_index: 1 }],
        )
        .await
        .expect("extract should succeed");
    let Verdict::Extracted(extracted_values) = extracted_values else {
        panic!("expected extracted values, got: {extracted_values}");
    };

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
    let tx = checkpointed_tx_with(|tx| tx.checkpoint = None);

    // When
    let response = extract_from(MockSuiClient::transaction(tx), vec![]).await;

    // Then: transient, worth retrying once the transaction is checkpointed.
    assert_matches!(response, Err(ForeignChainInspectionError::NotFinalized));
    assert!(response.unwrap_err().is_transient());
}

#[rstest]
#[case::normalized_event_with_padded_type_tag_address_and_raw_bcs_bytes(
    MockSuiClient::transaction(checkpointed_tx(vec![framework_event()])),
    vec![SuiExtractor::Event { event_index: 0 }],
    Verdict::Extracted(vec![SuiExtractedValue::Event(expected_event())]),
)]
#[case::event_without_optional_contents_type_name(
    MockSuiClient::transaction(checkpointed_tx(vec![framework_event().with_contents(
        Bcs::default().with_value(EVENT_BCS_BYTES.to_vec()),
    )])),
    vec![SuiExtractor::Event { event_index: 0 }],
    Verdict::Extracted(vec![SuiExtractedValue::Event(expected_event())]),
)]
#[case::contents_type_long_form_address_reconciled_with_short_form_event_type(
    MockSuiClient::transaction(checkpointed_tx(vec![framework_event().with_contents(
        Bcs::default()
            .with_name(format!(
                "0x{}3::validator_set::ValidatorEpochInfoEventV2",
                "0".repeat(63)
            ))
            .with_value(EVENT_BCS_BYTES.to_vec()),
    )])),
    vec![SuiExtractor::Event { event_index: 0 }],
    Verdict::Extracted(vec![SuiExtractedValue::Event(expected_event())]),
)]
#[case::transaction_failed_when_execution_failed(
    MockSuiClient::transaction(checkpointed_tx_with(|tx| {
        tx.effects = Some(
            TransactionEffects::default()
                .with_status(ExecutionStatus::default().with_success(false)),
        );
    })),
    vec![],
    Verdict::TransactionFailed,
)]
#[case::transaction_not_found_for_unknown_or_pruned_digest(
    MockSuiClient::status(Status::not_found(
        "Transaction 88XKXHJRmGzkfwJa8PhoeDkqt4kxz8AEsB1UTzAbtd29 not found",
    )),
    vec![],
    Verdict::TransactionNotFound,
)]
#[case::no_extractors_requested(
    MockSuiClient::transaction(checkpointed_tx(vec![])),
    vec![],
    Verdict::Extracted(vec![]),
)]
#[case::out_of_bounds_for_an_absent_event_index(
    MockSuiClient::transaction(checkpointed_tx(vec![framework_event()])),
    vec![SuiExtractor::Event { event_index: 5 }],
    Verdict::LogIndexOutOfBounds,
)]
#[tokio::test]
async fn extract__should_return_the_expected_verdict(
    #[case] client: MockSuiClient,
    #[case] extractors: Vec<SuiExtractor>,
    #[case] expected: Verdict<SuiExtractedValue>,
) {
    // When
    let response = extract_from(client, extractors).await;

    // Then
    assert_eq!(response.unwrap(), expected);
}

#[rstest]
#[case::missing_execution_status_requested_via_the_read_mask(
    MockSuiClient::transaction(checkpointed_tx_with(|tx| tx.effects = None)),
    vec![],
)]
#[case::status_without_success_flag_which_real_servers_always_populate(
    MockSuiClient::transaction(checkpointed_tx_with(|tx| {
        tx.effects = Some(TransactionEffects::default().with_status(ExecutionStatus::default()));
    })),
    vec![],
)]
#[case::missing_transaction_section(
    MockSuiClient::answering(GetTransactionResponse::default()),
    vec![],
)]
#[case::event_missing_bcs_contents(
    MockSuiClient::transaction(checkpointed_tx(vec![framework_event_without_contents()])),
    vec![SuiExtractor::Event { event_index: 0 }],
)]
#[case::event_whose_contents_type_disagrees_with_the_event_type(
    MockSuiClient::transaction(checkpointed_tx(vec![framework_event().with_contents(
        Bcs::default()
            .with_name("0x3::validator::StakingRequestEvent")
            .with_value(EVENT_BCS_BYTES.to_vec()),
    )])),
    vec![SuiExtractor::Event { event_index: 0 }],
)]
#[tokio::test]
async fn extract__should_reject_the_response_as_malformed(
    #[case] client: MockSuiClient,
    #[case] extractors: Vec<SuiExtractor>,
) {
    // When
    let error = extract_from(client, extractors).await.unwrap_err();

    // Then
    assert_matches!(error, ForeignChainInspectionError::MalformedRpcResponse(_));
    assert!(!error.is_transient());
}

#[tokio::test]
async fn extract__should_propagate_unavailable_provider_as_transient() {
    // Given — the status a lazy tonic channel yields when the endpoint is unreachable.
    let client = MockSuiClient::status(Status::unavailable(
        "error trying to connect: connection refused",
    ));

    // When
    let response = extract_from(client, vec![]).await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::RpcRequestFailed(_))
    );
    assert!(response.unwrap_err().is_transient());
}

#[tokio::test]
async fn extract__should_reject_response_with_mismatched_digest() {
    // Given — the backend echoes a different transaction than queried.
    let tx = checkpointed_tx_with(|tx| tx.digest = Some(bs58::encode([0xcd; 32]).into_string()));

    // When
    let response = extract_from(MockSuiClient::transaction(tx), vec![]).await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::InconsistentRpcResponse { .. })
    );
}

#[tokio::test]
async fn network_fingerprint__should_return_the_chain_id_the_service_reports() {
    // Given
    let client = MockSuiClient::serving(
        GetServiceInfoResponse::default().with_chain_id(MAINNET_GENESIS_CHECKPOINT_DIGEST),
    );
    let inspector = SuiInspector::new(client);

    // When
    let fingerprint = inspector
        .network_fingerprint()
        .await
        .expect("network_fingerprint should succeed");

    // Then
    assert_eq!(fingerprint.to_string(), MAINNET_GENESIS_CHECKPOINT_DIGEST);
}

#[tokio::test]
async fn network_fingerprint__should_report_service_info_without_a_chain_id_as_malformed() {
    // Given
    let client = MockSuiClient::serving(GetServiceInfoResponse::default());
    let inspector = SuiInspector::new(client);

    // When
    let fingerprint = inspector.network_fingerprint().await;

    // Then
    assert_matches!(
        fingerprint,
        Err(ForeignChainInspectionError::MalformedRpcResponse(_))
    );
}

/// A missing method is a refusal, not a missing transaction.
#[tokio::test]
async fn network_fingerprint__should_report_a_not_found_service_as_rejected() {
    // Given
    let inspector = SuiInspector::new(MockSuiClient::status(Status::not_found("no such service")));

    // When
    let fingerprint = inspector.network_fingerprint().await;

    // Then
    assert_matches!(
        fingerprint,
        Err(ForeignChainInspectionError::RpcRequestRejected(_))
    );
}
