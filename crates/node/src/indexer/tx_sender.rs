use super::ChainSendTransactionRequest::{self, *};
use super::IndexerState;
use super::chain::SubmissionAck;
use super::tx_signer::TransactionSigner;
use crate::metrics;
use crate::types::{
    LogTransaction, SignerContext, SubmittedTransaction, SubmittedTransactionStatus,
    SubmittedTxMetadata,
};
use ed25519_dalek::SigningKey;
use near_account_id::AccountId;
use near_contract_transport::ViewContract;
use near_indexer_primitives::types::Gas;
use near_mpc_contract_interface::client::MpcContractHandle;
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_time::Clock;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;

const TRANSACTION_PROCESSOR_CHANNEL_SIZE: usize = 10000;
const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(10);

pub trait TransactionSender: Clone + Send + Sync {
    fn send(
        &self,
        transaction: ChainSendTransactionRequest,
    ) -> impl Future<Output = Result<(), TransactionProcessorError>> + Send;
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum TransactionProcessorError {
    #[error("The transaction processor is closed.")]
    ProcessorIsClosed,
}

#[derive(Clone, Debug)]
pub struct TransactionProcessorHandle {
    transaction_sender: mpsc::Sender<ChainSendTransactionRequest>,
}

impl TransactionProcessorHandle {
    pub(crate) fn start_transaction_processor(
        owner_account_id: AccountId,
        owner_secret_key: SigningKey,
        indexer_state: Arc<IndexerState>,
        tx_logger: impl LogTransaction,
    ) -> impl TransactionSender {
        // All transactions must share one signer: its nonce counter is the only
        // thing keeping nonces of the node's access key unique and increasing.
        let signer = Arc::new(TransactionSigner::from_key(
            owner_account_id,
            owner_secret_key,
        ));

        let (transaction_sender, mut transaction_receiver) =
            mpsc::channel::<ChainSendTransactionRequest>(TRANSACTION_PROCESSOR_CHANNEL_SIZE);

        tokio::spawn(async move {
            while let Some(tx_request) = transaction_receiver.recv().await {
                let tx_signer = signer.clone();
                let indexer_state = indexer_state.clone();
                let tx_logger = tx_logger.clone();
                tokio::spawn(async move {
                    let Ok(txn_json) = serde_json::to_string(&tx_request) else {
                        tracing::error!(target: "mpc", "Failed to serialize response args");
                        return;
                    };
                    tracing::debug!(target = "mpc", "tx args {:?}", txn_json);
                    let recent_transaction = ensure_send_transaction(
                        tx_signer.clone(),
                        indexer_state,
                        tx_request,
                        txn_json,
                    )
                    .await;

                    tx_logger.log_transaction(recent_transaction);
                });
            }
        });

        TransactionProcessorHandle { transaction_sender }
    }
}

impl TransactionSender for TransactionProcessorHandle {
    async fn send(
        &self,
        transaction: ChainSendTransactionRequest,
    ) -> Result<(), TransactionProcessorError> {
        self.transaction_sender
            .send(transaction)
            .await
            .map_err(|_| TransactionProcessorError::ProcessorIsClosed)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TransactionStatus {
    Executed,
    NotExecuted,
    Unknown,
}

/// Creates, signs, and submits a function call with the given method and serialized arguments.
/// On success, returns the metadata of the submitted transaction for debugging.
async fn submit_tx(
    tx_signer: Arc<TransactionSigner>,
    indexer_state: Arc<IndexerState>,
    method: String,
    params_ser: String,
    gas: Gas,
) -> anyhow::Result<(SubmittedTxMetadata, SubmissionAck)> {
    let block = indexer_state.chain.latest_final_block().await?;

    let transaction = tx_signer.create_and_sign_function_call_tx(
        indexer_state.mpc_contract_id.clone(),
        method,
        params_ser.into(),
        gas,
        block.value,
        block.observed_at.into(),
    );

    let tx_hash = transaction.get_hash();
    let nonce = transaction.transaction.nonce().nonce();
    let signature = transaction.signature.clone();
    tracing::info!(
        target = "mpc",
        "sending tx {:?} with ak={:?} nonce={:?}",
        tx_hash,
        tx_signer.public_key(),
        nonce,
    );

    let ack = indexer_state.chain.submit_tx(transaction).await?;

    Ok((
        SubmittedTxMetadata {
            tx_hash,
            nonce,
            signature,
            block_height: block.observed_at.into(),
        },
        ack,
    ))
}

/// Confirms whether the intended effect of the transaction request has been observed on chain.
async fn observe_tx_result<C: ViewContract + Clone + Send + 'static>(
    contract: &MpcContractHandle<C>,
    request: &ChainSendTransactionRequest,
) -> anyhow::Result<TransactionStatus> {
    match request {
        Respond(respond_args) => {
            // Confirm whether the respond call succeeded by checking whether the
            // pending signature request still exists in the contract state.
            // A successful respond removes the request from contract state.
            let pending_request_response = contract
                .get_pending_request(respond_args.request.clone())
                .await?
                .value;

            let transaction_status = match pending_request_response {
                Some(_) => TransactionStatus::NotExecuted,
                None => TransactionStatus::Executed,
            };

            Ok(transaction_status)
        }
        CKDRespond(respond_args) => {
            // Confirm whether the respond call succeeded by checking whether the
            // pending ckd request still exists in the contract state.
            // A successful respond removes the request from contract state.
            let pending_request_response = contract
                .get_pending_ckd_request(respond_args.request.clone())
                .await?
                .value;

            let transaction_status = match pending_request_response {
                Some(_) => TransactionStatus::NotExecuted,
                None => TransactionStatus::Executed,
            };

            Ok(transaction_status)
        }
        VerifyForeignTransactionRespond(respond_args) => {
            // Confirm whether the respond call succeeded by checking whether the
            // pending verify foreign tx request still exists in the contract state.
            // A successful respond removes the request from contract state.
            let pending_request_response = contract
                .get_pending_verify_foreign_tx_request(respond_args.request.clone())
                .await?
                .value;

            let transaction_status = match pending_request_response {
                Some(_) => TransactionStatus::NotExecuted,
                None => TransactionStatus::Executed,
            };

            Ok(transaction_status)
        }
        // We don't care. The contract state change will handle this.
        StartKeygen(_)
        | StartReshare(_)
        | VotePk(_)
        | VoteReshared(_)
        | VoteAbortKeyEventInstance(_)
        | VerifyTee()
        | SubmitParticipantInfo(_)
        | ConcludeNodeMigration(_)
        | RegisterForeignChainsConfig(_) => Ok(TransactionStatus::Unknown),
    }
}

/// Attempts to ensure that a function call with the given method and args is
/// included on-chain. Submits the transaction, waits `TRANSACTION_TIMEOUT` for
/// it to be included, then observes once whether it had its intended on-chain
/// effect.
async fn ensure_send_transaction(
    tx_signer: Arc<TransactionSigner>,
    indexer_state: Arc<IndexerState>,
    request: ChainSendTransactionRequest,
    params_ser: String,
) -> SubmittedTransaction {
    let method = request.method();
    let signer = SignerContext {
        account_id: tx_signer.account_id().clone(),
        public_key: Ed25519PublicKey::from(&tx_signer.public_key()),
        method,
    };
    let submitted_metadata = submit_tx(
        tx_signer.clone(),
        indexer_state.clone(),
        method.to_string(),
        params_ser.clone(),
        request.gas_required(),
    )
    .await;

    // Stamp the submission time now, before the observation wait below, so the
    // debug page reflects when the transaction was actually routed.
    let submitted_at = Clock::real().now_utc();

    let (metadata, ack) = match submitted_metadata {
        Ok(submission) => submission,
        Err(err) => {
            metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                .with_label_values(&[method, "local_error"])
                .inc();
            tracing::error!(%err, "Failed to forward transaction {:?}", request);
            return SubmittedTransaction::submit_failed(signer, submitted_at);
        }
    };

    // Allow time for the transaction to be included
    time::sleep(TRANSACTION_TIMEOUT).await;

    // Then try to check whether it had the intended effect
    let transaction_status = observe_tx_result(&indexer_state.contract, &request)
        .await
        .map(|observed| after_submission(ack, observed));

    let (outcome_label, recorded_status) = match &transaction_status {
        Ok(TransactionStatus::Executed) => ("succeeded", SubmittedTransactionStatus::Executed),
        Ok(TransactionStatus::NotExecuted) => {
            ("timed_out", SubmittedTransactionStatus::NotExecuted)
        }
        Ok(TransactionStatus::Unknown) => ("unknown", SubmittedTransactionStatus::Unknown),
        Err(err) => {
            tracing::warn!(target:"mpc", %err, "encountered error trying to confirm result of transaction {:?}", request);
            ("unknown_err", SubmittedTransactionStatus::ObserveError)
        }
    };
    metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
        .with_label_values(&[method, outcome_label])
        .inc();

    SubmittedTransaction::submitted(signer, metadata, recorded_status, submitted_at)
}

/// An effect unobserved after an accepted submission timed out, under either
/// backend. Without an acknowledgement the transaction may never have reached a
/// node, so the outcome stays unknown.
fn after_submission(ack: SubmissionAck, observed: TransactionStatus) -> TransactionStatus {
    match observed {
        TransactionStatus::NotExecuted if !ack.was_accepted() => TransactionStatus::Unknown,
        observed => observed,
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{SubmissionAck, TransactionStatus, after_submission};

    #[test]
    fn after_submission__should_report_an_unobserved_accepted_transaction_as_not_executed() {
        // When
        let queued = after_submission(SubmissionAck::Queued, TransactionStatus::NotExecuted);
        let routed = after_submission(SubmissionAck::Routed, TransactionStatus::NotExecuted);
        let unknown = after_submission(SubmissionAck::Unknown, TransactionStatus::NotExecuted);
        let executed = after_submission(SubmissionAck::Unknown, TransactionStatus::Executed);

        // Then
        assert_eq!(queued, TransactionStatus::NotExecuted);
        assert_eq!(routed, TransactionStatus::NotExecuted);
        assert_eq!(unknown, TransactionStatus::Unknown);
        assert_eq!(executed, TransactionStatus::Executed);
    }
}
