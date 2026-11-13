use super::*;
use near_indexer_primitives::near_primitives::errors::{
    ActionError, ActionErrorKind, FunctionCallError, TxExecutionError,
};
use near_indexer_primitives::types::{AccountId as NearAccountId, Balance, Gas};
use near_indexer_primitives::views::{ExecutionMetadataView, ExecutionOutcomeView};
use near_mpc_contract_interface::call_args::{
    ReadRpcArgs, RequestAppPrivateKeyArgs, SignArgs as SignCallArgs, VerifyForeignTransactionArgs,
};
use near_mpc_contract_interface::events::{
    EVENT_JSON_PREFIX, MPC_CONTRACT_EVENT_STANDARD, VerifyForeignTxV2YieldCreated,
};
use near_mpc_contract_interface::types::{
    BitcoinExtractedValue, BitcoinExtractor, BitcoinRpcRequest, CKDAppPublicKey, ExtractedValue,
    ForeignChainRpcRequest, ForeignTxPayloadVersion, VerifyForeignTransactionRequestV2, YieldId,
};
use near_mpc_crypto_types::Bls12381G1PublicKey;
use serde_json::json;

const RECEIPT_ID: CryptoHash = CryptoHash([1; 32]);
const NEXT_RECEIPT_ID: CryptoHash = CryptoHash([2; 32]);
const BLOCK_HEIGHT: BlockHeight = BlockHeight::new(1234);
const CALLER: &str = "caller.near";
const MPC_CONTRACT: &str = "signer.near";

fn mpc_contract_id() -> AccountId {
    MPC_CONTRACT.parse().unwrap()
}

fn function_call_receipt(method_name: &str, args: impl Serialize) -> ReceiptView {
    let caller: NearAccountId = CALLER.parse().unwrap();
    ReceiptView {
        predecessor_id: caller.clone(),
        receiver_id: MPC_CONTRACT.parse().unwrap(),
        receipt_id: RECEIPT_ID,
        receipt: ReceiptEnumView::Action {
            signer_id: caller,
            signer_public_key: "ed25519:11111111111111111111111111111111".parse().unwrap(),
            gas_price: Balance::from_yoctonear(0),
            output_data_receivers: vec![],
            input_data_ids: vec![],
            actions: vec![ActionView::FunctionCall {
                method_name: method_name.to_string(),
                args: serde_json::to_vec(&args).unwrap().into(),
                gas: Gas::from_teragas(15),
                deposit: Balance::from_yoctonear(1),
            }],
            is_promise_yield: false,
            refund_to: None,
        },
        _priority: 0,
    }
}

fn execution_outcome(status: ExecutionStatusView, logs: Vec<String>) -> ExecutionOutcomeWithIdView {
    ExecutionOutcomeWithIdView {
        proof: vec![],
        block_hash: CryptoHash::default(),
        id: RECEIPT_ID,
        outcome: ExecutionOutcomeView {
            logs,
            receipt_ids: vec![NEXT_RECEIPT_ID],
            gas_burnt: Gas::from_teragas(5),
            tokens_burnt: Balance::from_yoctonear(0),
            executor_id: MPC_CONTRACT.parse().unwrap(),
            status,
            metadata: ExecutionMetadataView::default(),
        },
    }
}

fn succeeded(logs: Vec<String>) -> ExecutionOutcomeWithIdView {
    execution_outcome(ExecutionStatusView::SuccessReceiptId(NEXT_RECEIPT_ID), logs)
}

fn panicked(logs: Vec<String>) -> ExecutionOutcomeWithIdView {
    execution_outcome(
        ExecutionStatusView::Failure(TxExecutionError::ActionError(ActionError {
            index: Some(0),
            kind: ActionErrorKind::FunctionCallError(FunctionCallError::ExecutionError(
                "Smart contract panicked".to_string(),
            )),
        })),
        logs,
    )
}

fn bitcoin_request() -> ForeignChainRpcRequest {
    ForeignChainRpcRequest::Bitcoin(BitcoinRpcRequest {
        tx_id: [7; 32].into(),
        confirmations: 2.into(),
        extractors: [BitcoinExtractor::BlockHash].into(),
    })
}

fn read_rpc_request() -> VerifyForeignTransactionRequestV2 {
    VerifyForeignTransactionRequestV2 {
        request: bitcoin_request(),
        domain_id: DomainId::default(),
        expected_values: vec![ExtractedValue::BitcoinExtractedValue(
            BitcoinExtractedValue::BlockHash([42; 32].into()),
        )],
    }
}

fn yield_created_log(yield_id: YieldId) -> String {
    let event = json!({
        "standard": MPC_CONTRACT_EVENT_STANDARD,
        "version": VerifyForeignTxV2YieldCreated::VERSION,
        "event": VerifyForeignTxV2YieldCreated::EVENT,
        "data": VerifyForeignTxV2YieldCreated { yield_id },
    });
    format!("{EVENT_JSON_PREFIX}{event}")
}

#[test]
fn try_index_request__should_index_a_read_rpc_call_with_its_yield_id_and_block_height() {
    // Given
    let yield_id = YieldId([9; 32]);
    let receipt = function_call_receipt(READ_RPC, ReadRpcArgs::new(read_rpc_request()));
    let outcome = succeeded(vec![
        "read_rpc: predecessor=caller.near".to_string(),
        yield_created_log(yield_id),
    ]);

    // When
    let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

    // Then
    let Some(IndexedRequest::VerifyForeignTxV2(request)) = indexed else {
        panic!("expected a V2 foreign tx request");
    };
    assert_eq!(
        request,
        VerifyForeignTxRequestV2FromChain {
            verify_foreign_tx_id: NEXT_RECEIPT_ID,
            receipt_id: RECEIPT_ID,
            yield_id,
            request_block_height: BLOCK_HEIGHT,
            request: bitcoin_request(),
            domain_id: DomainId::default(),
            expected_values_hash: read_rpc_request().expected_values_hash().unwrap(),
        }
    );
}

#[test]
fn try_index_request__should_count_a_skipped_read_rpc_call() {
    // Given
    let receipt = function_call_receipt(READ_RPC, ReadRpcArgs::new(read_rpc_request()));
    let outcome = succeeded(vec![
        yield_created_log(YieldId([1; 32])),
        yield_created_log(YieldId([2; 32])),
    ]);
    let skipped_before = metrics::MPC_NUM_VERIFY_FOREIGN_TX_V2_REQUESTS_SKIPPED.get();

    // When
    try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

    // Then
    assert_eq!(
        metrics::MPC_NUM_VERIFY_FOREIGN_TX_V2_REQUESTS_SKIPPED.get(),
        skipped_before + 1
    );
}

#[test]
fn try_index_request__should_skip_a_read_rpc_call_without_a_yield_created_event() {
    // Given
    let receipt = function_call_receipt(READ_RPC, ReadRpcArgs::new(read_rpc_request()));
    let outcome = succeeded(vec!["read_rpc: predecessor=caller.near".to_string()]);

    // When
    let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

    // Then
    assert!(indexed.is_none());
}

#[test]
fn try_index_request__should_skip_a_read_rpc_call_with_several_yield_created_events() {
    // Given
    let receipt = function_call_receipt(READ_RPC, ReadRpcArgs::new(read_rpc_request()));
    let outcome = succeeded(vec![
        yield_created_log(YieldId([1; 32])),
        yield_created_log(YieldId([2; 32])),
    ]);

    // When
    let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

    // Then
    assert!(indexed.is_none());
}

#[test]
fn try_index_request__should_skip_a_failed_read_rpc_call_despite_its_event() {
    // Given
    let receipt = function_call_receipt(READ_RPC, ReadRpcArgs::new(read_rpc_request()));
    let outcome = panicked(vec![yield_created_log(YieldId([9; 32]))]);

    // When
    let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

    // Then
    assert!(indexed.is_none());
}

#[test]
fn try_index_request__should_skip_a_read_rpc_call_another_contract_executed() {
    // Given
    let receipt = function_call_receipt(READ_RPC, ReadRpcArgs::new(read_rpc_request()));
    let mut outcome = succeeded(vec![yield_created_log(YieldId([9; 32]))]);
    outcome.outcome.executor_id = "impostor.near".parse().unwrap();

    // When
    let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

    // Then
    assert!(indexed.is_none());
}

#[test]
fn try_index_request__should_skip_a_read_rpc_call_with_unparsable_arguments() {
    // Given
    let receipt = function_call_receipt(READ_RPC, json!({ "request": "not a request" }));
    let outcome = succeeded(vec![yield_created_log(YieldId([9; 32]))]);

    // When
    let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

    // Then
    assert!(indexed.is_none());
}

#[test]
fn try_index_request__should_index_a_verify_foreign_transaction_call() {
    // Given
    let request_args = VerifyForeignTransactionRequestArgs {
        request: bitcoin_request(),
        domain_id: DomainId::default(),
        payload_version: ForeignTxPayloadVersion::V1,
        expected_payload_hash: None,
    };
    let receipt = function_call_receipt(
        VERIFY_FOREIGN_TRANSACTION,
        VerifyForeignTransactionArgs::new(request_args.clone()),
    );
    let outcome = succeeded(vec![]);

    // When
    let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

    // Then
    let Some(IndexedRequest::VerifyForeignTx(request)) = indexed else {
        panic!("expected a foreign tx request");
    };
    assert_eq!(request.verify_foreign_tx_id, NEXT_RECEIPT_ID);
    assert_eq!(request.receipt_id, RECEIPT_ID);
    assert_eq!(request.request, request_args);
}

#[test]
fn try_index_request__should_index_a_sign_call() {
    // Given
    let payload = Payload::from_legacy_ecdsa([3; 32]);
    let receipt = function_call_receipt(
        SIGN,
        SignCallArgs::new(SignRequestArgs::new(
            "path".to_string(),
            payload.clone(),
            DomainId::default(),
        )),
    );
    let outcome = succeeded(vec![]);

    // When
    let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

    // Then
    let Some(IndexedRequest::Signature(request)) = indexed else {
        panic!("expected a signature request");
    };
    assert_eq!(request.signature_id, NEXT_RECEIPT_ID);
    assert_eq!(request.receipt_id, RECEIPT_ID);
    assert_eq!(request.predecessor_id.as_str(), CALLER);
    assert_eq!(
        request.request,
        SignArgs {
            payload,
            path: "path".to_string(),
            domain_id: DomainId::default(),
        }
    );
}

#[test]
fn try_index_request__should_index_a_request_app_private_key_call() {
    // Given
    let app_public_key = CKDAppPublicKey::AppPublicKey(Bls12381G1PublicKey([5; 48]));
    let receipt = function_call_receipt(
        REQUEST_APP_PRIVATE_KEY,
        RequestAppPrivateKeyArgs::new(CKDRequestArgs {
            derivation_path: "path".to_string(),
            app_public_key: app_public_key.clone(),
            domain_id: DomainId::default(),
        }),
    );
    let outcome = succeeded(vec![]);

    // When
    let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

    // Then
    let Some(IndexedRequest::Ckd(request)) = indexed else {
        panic!("expected a CKD request");
    };
    assert_eq!(request.ckd_id, NEXT_RECEIPT_ID);
    assert_eq!(request.receipt_id, RECEIPT_ID);
    assert_eq!(request.request.app_public_key, app_public_key);
    assert_eq!(request.request.domain_id, DomainId::default());
}

#[test]
fn try_index_request__should_skip_a_failed_sign_call() {
    // Given
    let receipt = function_call_receipt(
        SIGN,
        SignCallArgs::new(SignRequestArgs::new(
            "path".to_string(),
            Payload::from_legacy_ecdsa([3; 32]),
            DomainId::default(),
        )),
    );
    let outcome = panicked(vec![]);

    // When
    let indexed = try_index_request(&receipt, &outcome, &mpc_contract_id(), BLOCK_HEIGHT);

    // Then
    assert!(indexed.is_none());
}
