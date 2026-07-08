#![allow(non_snake_case)]

use assert_matches::assert_matches;
use foreign_chain_inspector::{
    ForeignChainInspectionError, ForeignChainInspector,
    sui::{
        SuiExtractedValue, SuiTransactionDigest,
        inspector::{SuiExtractor, SuiFinality, SuiInspector},
    },
};
use foreign_chain_rpc_interfaces::sui::proto::{
    Bcs, Event, ExecutedTransaction, ExecutionStatus, GetCheckpointResponse,
    GetServiceInfoResponse, GetTransactionResponse, TransactionEffects, TransactionEvents,
};
use foreign_chain_rpc_interfaces::sui::{Status, SuiRpcClient};
use near_mpc_contract_interface::types::{SuiAddress, SuiEvent};

const EVENT_BCS_BYTES: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

/// A client that always returns a hard-coded `GetTransaction` response.
struct MockSuiClient {
    response: Result<GetTransactionResponse, Status>,
}

impl MockSuiClient {
    fn transaction(tx: ExecutedTransaction) -> Self {
        Self {
            response: Ok(GetTransactionResponse::default().with_transaction(tx)),
        }
    }

    fn status(status: Status) -> Self {
        Self {
            response: Err(status),
        }
    }
}

impl SuiRpcClient for MockSuiClient {
    async fn get_transaction(&self, _digest: &str) -> Result<GetTransactionResponse, Status> {
        self.response.clone()
    }

    async fn get_service_info(&self) -> Result<GetServiceInfoResponse, Status> {
        unimplemented!("get_service_info() not used by the inspector")
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

#[tokio::test]
async fn extract__should_return_normalized_event_for_checkpointed_transaction() {
    // Given
    let inspector = SuiInspector::new(MockSuiClient::transaction(checkpointed_tx(vec![
        framework_event(),
    ])));

    // When
    let extracted_values = inspector
        .extract(
            tx_id(),
            SuiFinality::Checkpointed,
            vec![SuiExtractor::Event { event_index: 0 }],
        )
        .await
        .expect("extract should succeed");

    // Then — type_tag address padded to long form, bcs carried as raw bytes.
    assert_eq!(
        extracted_values,
        vec![SuiExtractedValue::Event(expected_event())],
    );
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
    let inspector = SuiInspector::new(MockSuiClient::transaction(tx));

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
    tx.effects = Some(
        TransactionEffects::default().with_status(ExecutionStatus::default().with_success(false)),
    );
    let inspector = SuiInspector::new(MockSuiClient::transaction(tx));

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
async fn extract__should_reject_response_missing_execution_status_as_malformed() {
    // Given — the execution status was requested via the read mask, so its absence
    // violates the API contract.
    let mut tx = checkpointed_tx(vec![]);
    tx.effects = None;
    let inspector = SuiInspector::new(MockSuiClient::transaction(tx));

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
async fn extract__should_reject_response_missing_transaction_as_malformed() {
    // Given — a `GetTransactionResponse` whose transaction section is absent entirely.
    let inspector = SuiInspector::new(MockSuiClient {
        response: Ok(GetTransactionResponse::default()),
    });

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
    // Given — the status a node returns for an unknown or pruned digest.
    let inspector = SuiInspector::new(MockSuiClient::status(Status::not_found(
        "Transaction 88XKXHJRmGzkfwJa8PhoeDkqt4kxz8AEsB1UTzAbtd29 not found",
    )));

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
async fn extract__should_propagate_unavailable_provider_as_transient() {
    // Given — the status a lazy tonic channel yields when the endpoint is unreachable.
    let inspector = SuiInspector::new(MockSuiClient::status(Status::unavailable(
        "error trying to connect: connection refused",
    )));

    // When
    let response = inspector
        .extract(tx_id(), SuiFinality::Checkpointed, vec![])
        .await;

    // Then
    assert_matches!(
        response,
        Err(ForeignChainInspectionError::RpcRequestFailed(_))
    );
    assert!(response.unwrap_err().is_transient());
}

#[tokio::test]
async fn extract__should_return_error_when_event_index_out_of_bounds() {
    // Given
    let inspector = SuiInspector::new(MockSuiClient::transaction(checkpointed_tx(vec![
        framework_event(),
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
    tx.digest = Some(bs58::encode([0xcd; 32]).into_string());
    let inspector = SuiInspector::new(MockSuiClient::transaction(tx));

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
async fn extract__should_reject_event_missing_bcs_contents_as_malformed() {
    // Given — an event whose BCS payload is absent.
    let mut event = framework_event();
    event.contents = None;
    let inspector = SuiInspector::new(MockSuiClient::transaction(checkpointed_tx(vec![event])));

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
async fn extract__should_reject_event_whose_contents_type_differs() {
    // Given — the type name shipped with the BCS bytes disagrees with the event type.
    let event = framework_event().with_contents(
        Bcs::default()
            .with_name("0x3::validator::StakingRequestEvent")
            .with_value(EVENT_BCS_BYTES.to_vec()),
    );
    let inspector = SuiInspector::new(MockSuiClient::transaction(checkpointed_tx(vec![event])));

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
async fn extract__should_accept_event_without_contents_type_name() {
    // Given — the type name inside the BCS message is optional metadata.
    let event =
        framework_event().with_contents(Bcs::default().with_value(EVENT_BCS_BYTES.to_vec()));
    let inspector = SuiInspector::new(MockSuiClient::transaction(checkpointed_tx(vec![event])));

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
async fn extract__should_accept_contents_type_in_different_address_form() {
    // Given — the same type, rendered long-form in the contents name and short-form in the
    // event type; normalization must reconcile the two.
    let event = framework_event().with_contents(
        Bcs::default()
            .with_name(format!(
                "0x{}3::validator_set::ValidatorEpochInfoEventV2",
                "0".repeat(63)
            ))
            .with_value(EVENT_BCS_BYTES.to_vec()),
    );
    let inspector = SuiInspector::new(MockSuiClient::transaction(checkpointed_tx(vec![event])));

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
async fn extract__should_return_empty_when_no_extractors_are_requested() {
    // Given
    let inspector = SuiInspector::new(MockSuiClient::transaction(checkpointed_tx(vec![])));

    // When
    let extracted_values = inspector
        .extract(tx_id(), SuiFinality::Checkpointed, Vec::new())
        .await
        .expect("extract should succeed");

    // Then
    let expected: Vec<SuiExtractedValue> = vec![];
    assert_eq!(expected, extracted_values);
}
