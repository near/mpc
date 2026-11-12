#![allow(non_snake_case)]

use crate::sandbox::common::{
    SandboxTestSetup, bitcoin_extracted_values, bitcoin_request, make_foreign_chain_available,
    sign_foreign_tx_payload,
};
use crate::sandbox::utils::transactions::CallMpcContract;
use mpc_contract::errors::{InvalidParameters, RequestError};
use near_jsonrpc_client::{JsonRpcClient, methods};
use near_mpc_contract_interface::events::VerifyForeignTxV2YieldCreated;
use near_mpc_contract_interface::types::{
    self as dtos, ForeignTxSignPayload, ForeignTxSignPayloadV2,
    ForeignTxVerificationNegativeVerdict, ForeignTxVerificationOutcome,
    VerifyForeignTransactionRequestV2, VerifyForeignTransactionResponseV2,
};
use near_primitives::views::TxExecutionStatus;
use near_workspaces::operations::TransactionStatus;
use std::time::Duration;
use test_utils::sandbox::SandboxWorker;

const SIGNATURE_TIMEOUT_BLOCKS: u64 = 200;

/// The yield a V2 request waits on, as a node's indexer learns it.
struct AnnouncedYield {
    yield_id: dtos::YieldId,
    block_height: dtos::BlockHeight,
}

fn yield_created_events(logs: &[&str]) -> Vec<VerifyForeignTxV2YieldCreated> {
    logs.iter()
        .filter_map(|line| VerifyForeignTxV2YieldCreated::from_log_line(line))
        .collect()
}

/// Waits until the receipt of `status` that ran `read_rpc` announced its
/// yield, and returns the yield id and the height of that receipt's block.
async fn await_announced_yield(
    worker: &SandboxWorker,
    status: &TransactionStatus,
) -> AnnouncedYield {
    const TIMEOUT: Duration = Duration::from_secs(30);
    let rpc = JsonRpcClient::connect(worker.rpc_addr());
    let request = methods::tx::RpcTransactionStatusRequest {
        transaction_info: methods::tx::TransactionInfo::TransactionId {
            tx_hash: near_primitives::hash::CryptoHash(status.hash().0),
            sender_account_id: status.sender_id().clone(),
        },
        wait_until: TxExecutionStatus::Included,
    };
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        let receipts = rpc
            .call(&request)
            .await
            .ok()
            .and_then(|response| response.final_execution_outcome)
            .map(|outcome| outcome.into_outcome().receipts_outcome)
            .unwrap_or_default();
        let announced = receipts.iter().find_map(|receipt| {
            let logs: Vec<&str> = receipt.outcome.logs.iter().map(String::as_str).collect();
            let events = yield_created_events(&logs);
            let [event] = events.as_slice() else {
                return None;
            };
            Some((event.yield_id, receipt.block_hash))
        });
        if let Some((yield_id, block_hash)) = announced {
            let block = worker
                .view_block()
                .block_hash(near_workspaces::types::CryptoHash(block_hash.0))
                .await
                .unwrap();
            return AnnouncedYield {
                yield_id,
                block_height: dtos::BlockHeight::new(block.height()),
            };
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for the yield created event"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn read_rpc__should_return_the_signed_outcome_of_respond_verify_foreign_tx_v2() {
    // Given
    let rpc_request = bitcoin_request();
    let setup = SandboxTestSetup::builder()
        .with_foreign_tx_domain()
        .build()
        .await;
    let foreign_tx_key = setup.foreign_tx_key();
    make_foreign_chain_available(
        rpc_request.chain(),
        &setup.contract,
        &setup.mpc_signer_accounts,
    )
    .await;
    let user = setup.worker.dev_create_account().await.unwrap();
    let request = VerifyForeignTransactionRequestV2 {
        request: rpc_request,
        domain_id: dtos::DomainId(foreign_tx_key.domain_id().0),
        expected_values: bitcoin_extracted_values(),
    };
    let status = user
        .call_mpc_async(setup.contract.id())
        .read_rpc(request.clone())
        .await
        .unwrap();
    let AnnouncedYield {
        yield_id,
        block_height,
    } = await_announced_yield(&setup.worker, &status).await;
    let outcome = ForeignTxVerificationOutcome::Negative {
        verdict: ForeignTxVerificationNegativeVerdict::TransactionNotFound,
    };
    let payload = ForeignTxSignPayload::V2(ForeignTxSignPayloadV2 {
        request: request.request.clone(),
        expected_values_hash: request.expected_values_hash().unwrap(),
        request_block_height: block_height,
        yield_id,
        outcome: outcome.clone(),
    });
    let signature = sign_foreign_tx_payload(&payload, foreign_tx_key.as_secp256k1());
    let node = setup.mpc_signer_accounts[0].call_mpc(setup.contract.id());

    // When
    let first_response = node
        .respond_verify_foreign_tx_v2(yield_id, outcome.clone(), signature.clone())
        .await
        .unwrap()
        .into_result();
    let replayed_response = node
        .respond_verify_foreign_tx_v2(yield_id, outcome.clone(), signature.clone())
        .await
        .unwrap()
        .into_result();
    let execution = status.await.unwrap().into_result().unwrap();

    // Then
    assert!(
        first_response.is_ok(),
        "the first response should succeed: {first_response:?}"
    );
    let replay_failure = replayed_response.unwrap_err().to_string();
    assert!(
        replay_failure.contains(&InvalidParameters::RequestNotFound.to_string()),
        "a replayed response should find no request, got: {replay_failure}"
    );
    let returned: VerifyForeignTransactionResponseV2 = execution.json().unwrap();
    assert_eq!(
        returned,
        VerifyForeignTransactionResponseV2 {
            payload_hash: payload.compute_msg_hash().unwrap(),
            signature,
            request_block_height: block_height,
            yield_id,
            outcome,
        }
    );
}

#[tokio::test]
async fn read_rpc__should_announce_one_yield_id_and_time_out_without_a_response() {
    // Given
    let rpc_request = bitcoin_request();
    let setup = SandboxTestSetup::builder()
        .with_foreign_tx_domain()
        .build()
        .await;
    make_foreign_chain_available(
        rpc_request.chain(),
        &setup.contract,
        &setup.mpc_signer_accounts,
    )
    .await;
    let user = setup.worker.dev_create_account().await.unwrap();
    let request = VerifyForeignTransactionRequestV2 {
        request: rpc_request,
        domain_id: dtos::DomainId(setup.foreign_tx_key().domain_id().0),
        expected_values: bitcoin_extracted_values(),
    };

    // When
    let status = user
        .call_mpc_async(setup.contract.id())
        .read_rpc(request)
        .await
        .unwrap();
    setup
        .worker
        .fast_forward(SIGNATURE_TIMEOUT_BLOCKS)
        .await
        .unwrap();
    let execution = status.await.unwrap();

    // Then
    assert_eq!(yield_created_events(&execution.logs()).len(), 1);
    let failure = execution.into_result().unwrap_err().to_string();
    assert!(
        failure.contains(&RequestError::Timeout.to_string()),
        "the request should time out, got: {failure}"
    );
}
