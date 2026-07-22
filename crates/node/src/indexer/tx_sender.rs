use super::IndexerState;
use super::tx_signer::{TransactionSigner, TransactionSigners};
use super::types::ChainSendTransactionRequest;
use crate::config::RespondConfig;
use crate::metrics;
use crate::types::{
    LogTransaction, SignerContext, SubmittedTransaction, SubmittedTransactionStatus,
    SubmittedTxMetadata,
};
use anyhow::Context;
use ed25519_dalek::SigningKey;
use near_account_id::AccountId;
use near_contract_transport::{CallContract, FunctionCallArgs};
use near_mpc_contract_interface::call_args as contract_args;
use near_mpc_contract_interface::method_names::{
    RESPOND, RESPOND_CKD, RESPOND_VERIFY_FOREIGN_TX, SUBMIT_PARTICIPANT_INFO,
};
use near_mpc_contract_interface::types::{Attestation, Ed25519PublicKey, VerifiedAttestation};
use near_time::Clock;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
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
    transaction_sender: mpsc::Sender<TransactionSenderSubmission>,
    mpc_contract_id: AccountId,
}

impl TransactionProcessorHandle {
    pub(crate) fn start_transaction_processor(
        owner_account_id: AccountId,
        owner_secret_key: SigningKey,
        config: RespondConfig,
        indexer_state: Arc<IndexerState>,
        tx_logger: impl LogTransaction,
    ) -> anyhow::Result<TransactionProcessorHandle> {
        let mut signers = TransactionSigners::new(config, owner_account_id, owner_secret_key)
            .context("Failed to initialize transaction signers")?;
        let mpc_contract_id = indexer_state.mpc_contract_id.clone();

        let (transaction_sender, mut transaction_receiver) =
            mpsc::channel::<TransactionSenderSubmission>(TRANSACTION_PROCESSOR_CHANNEL_SIZE);

        tokio::spawn(async move {
            while let Some(transaction_submission) = transaction_receiver.recv().await {
                let TransactionSenderSubmission {
                    contract_id,
                    call,
                    response_sender,
                } = transaction_submission;

                let tx_signer = signers.signer_for(&call.method_name);
                let indexer_state = indexer_state.clone();
                let tx_logger = tx_logger.clone();
                tokio::spawn(async move {
                    tracing::debug!(
                        target = "mpc",
                        "tx args {:?}",
                        String::from_utf8_lossy(&call.args)
                    );
                    let (transaction_status, recent_transaction) = ensure_send_transaction(
                        tx_signer.clone(),
                        indexer_state,
                        contract_id,
                        call,
                    )
                    .await;

                    tx_logger.log_transaction(recent_transaction);

                    if let Some(response_sender) = response_sender {
                        let _ = response_sender.send(transaction_status);
                    }
                });
            }
        });

        Ok(TransactionProcessorHandle {
            transaction_sender,
            mpc_contract_id,
        })
    }

    async fn submit(
        &self,
        contract_id: AccountId,
        call: FunctionCallArgs,
        response_sender: Option<oneshot::Sender<TransactionStatus>>,
    ) -> Result<(), TransactionProcessorError> {
        self.transaction_sender
            .send(TransactionSenderSubmission {
                contract_id,
                call,
                response_sender,
            })
            .await
            .map_err(|_| TransactionProcessorError::ProcessorIsClosed)
    }
}

impl TransactionSender for TransactionProcessorHandle {
    async fn send(
        &self,
        transaction: ChainSendTransactionRequest,
    ) -> Result<(), TransactionProcessorError> {
        let call = match transaction.into_function_call() {
            Ok(call) => call,
            // Parity with the pre-queue-currency behavior: a request that fails
            // to serialize is logged and dropped, and the fire-and-forget send
            // still reports acceptance.
            Err(error) => {
                tracing::error!(target: "mpc", %error, "Failed to serialize response args");
                return Ok(());
            }
        };
        self.submit(self.mpc_contract_id.clone(), call, None).await
    }
}

impl CallContract for TransactionProcessorHandle {
    type Output = TransactionStatus;
    type Error = TransactionProcessorError;

    /// Enqueues the call and waits until the processor has submitted it and
    /// observed (or failed to observe) its on-chain effect.
    async fn call_contract(
        &self,
        contract_id: &AccountId,
        call_args: FunctionCallArgs,
    ) -> Result<TransactionStatus, TransactionProcessorError> {
        let (response_sender, response_receiver) = oneshot::channel();

        self.submit(contract_id.clone(), call_args, Some(response_sender))
            .await?;

        response_receiver
            .await
            .map_err(|_| TransactionProcessorError::ProcessorIsClosed)
    }
}

struct TransactionSenderSubmission {
    contract_id: AccountId,
    call: FunctionCallArgs,
    response_sender: Option<oneshot::Sender<TransactionStatus>>,
}

#[derive(Debug)]
pub enum TransactionStatus {
    Executed,
    NotExecuted,
    Unknown,
}

/// Creates, signs, and submits a function call with the given method and serialized arguments.
/// On success, returns the metadata of the submitted transaction for debugging.
async fn submit_tx(
    tx_signer: Arc<TransactionSigner>,
    indexer_state: Arc<IndexerState>,
    contract_id: AccountId,
    call: FunctionCallArgs,
) -> anyhow::Result<SubmittedTxMetadata> {
    let block = indexer_state.view_client.latest_final_block().await?;

    let transaction = tx_signer.create_and_sign_function_call_tx(
        contract_id,
        call,
        block.header.hash,
        block.header.height,
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

    indexer_state.rpc_handler.submit_tx(transaction).await?;

    Ok(SubmittedTxMetadata {
        tx_hash,
        nonce,
        signature,
        block_height: block.header.height,
    })
}

fn attestation_expiry_changed(pre_submit_expiry: Option<u64>, stored_expiry: u64) -> bool {
    match pre_submit_expiry {
        Some(expiry_before_submit) => stored_expiry != expiry_before_submit,
        None => true,
    }
}

/// Whether the attestation we submitted is now the one stored on chain.
///
/// Mock is matched by identity. A Dstack entry keeps no stored per-submission identity, so it is
/// confirmed via [`attestation_expiry_changed`]: an accepted submit re-stamps the entry's expiry
/// (to the submit block time plus
/// [`DEFAULT_EXPIRATION_DURATION_SECONDS`](mpc_attestation::attestation::DEFAULT_EXPIRATION_DURATION_SECONDS)),
/// and only the owning account may rewrite it, so a changed expiry means our submit landed.
// TODO(#1639): match a certificate-derived identity instead of this expiry heuristic.
fn submitted_attestation_landed(
    pre_submit_expiry: Option<u64>,
    stored: &VerifiedAttestation,
    submitted: &Attestation,
) -> bool {
    match (stored, submitted) {
        (VerifiedAttestation::Dstack(stored), Attestation::Dstack(_)) => {
            attestation_expiry_changed(pre_submit_expiry, stored.expiry_timestamp_seconds)
        }
        (VerifiedAttestation::Mock(stored), Attestation::Mock(submitted)) => stored == submitted,
        _ => false,
    }
}

/// Baseline for the `submit_participant_info` landing check (see
/// [`submitted_attestation_landed`]): the Dstack expiry stored on chain before
/// we submit. `None` for every other method, for a non-Dstack stored entry,
/// and on a failed read — a broken read must not block the submission (the
/// confirmation just can't use a baseline).
async fn pre_submit_attestation_expiry(
    indexer_state: &Arc<IndexerState>,
    call: &FunctionCallArgs,
) -> Option<u64> {
    if call.method_name != SUBMIT_PARTICIPANT_INFO {
        return None;
    }
    let args: contract_args::SubmitParticipantInfoArgs = match serde_json::from_slice(&call.args) {
        Ok(args) => args,
        Err(error) => {
            tracing::warn!(%error, "could not read pre-submit attestation baseline; submitting without it");
            return None;
        }
    };
    match indexer_state
        .view_client
        .get_participant_attestation(&indexer_state.mpc_contract_id, &args.tls_public_key)
        .await
    {
        Ok(Some(VerifiedAttestation::Dstack(stored))) => Some(stored.expiry_timestamp_seconds),
        Ok(_) => None,
        Err(error) => {
            tracing::warn!(%error, "could not read pre-submit attestation baseline; submitting without it");
            None
        }
    }
}

/// Confirms whether the intended effect of the transaction request has been observed on chain.
async fn observe_tx_result(
    indexer_state: Arc<IndexerState>,
    call: &FunctionCallArgs,
    pre_submit_expiry: Option<u64>,
) -> anyhow::Result<TransactionStatus> {
    match call.method_name.as_str() {
        RESPOND => {
            // Confirm whether the respond call succeeded by checking whether the
            // pending signature request still exists in the contract state.
            // A successful respond removes the request from contract state.
            let respond_args: contract_args::SignatureRespondArgs =
                serde_json::from_slice(&call.args)?;
            let pending_request_response = indexer_state
                .view_client
                .get_pending_request(&indexer_state.mpc_contract_id, &respond_args.request)
                .await?;

            let transaction_status = match pending_request_response {
                Some(_) => TransactionStatus::NotExecuted,
                None => TransactionStatus::Executed,
            };

            Ok(transaction_status)
        }
        RESPOND_CKD => {
            // Confirm whether the respond call succeeded by checking whether the
            // pending ckd request still exists in the contract state.
            // A successful respond removes the request from contract state.
            let respond_args: contract_args::CKDRespondArgs = serde_json::from_slice(&call.args)?;
            let pending_request_response = indexer_state
                .view_client
                .get_pending_ckd_request(&indexer_state.mpc_contract_id, &respond_args.request)
                .await?;

            let transaction_status = match pending_request_response {
                Some(_) => TransactionStatus::NotExecuted,
                None => TransactionStatus::Executed,
            };

            Ok(transaction_status)
        }
        RESPOND_VERIFY_FOREIGN_TX => {
            // Confirm whether the respond call succeeded by checking whether the
            // pending verify foreign tx request still exists in the contract state.
            // A successful respond removes the request from contract state.
            let respond_args: contract_args::VerifyForeignTransactionRespondArgs =
                serde_json::from_slice(&call.args)?;
            let pending_request_response = indexer_state
                .view_client
                .get_pending_verify_foreign_tx_request(
                    &indexer_state.mpc_contract_id,
                    &respond_args.request,
                )
                .await?;

            let transaction_status = match pending_request_response {
                Some(_) => TransactionStatus::NotExecuted,
                None => TransactionStatus::Executed,
            };

            Ok(transaction_status)
        }
        SUBMIT_PARTICIPANT_INFO => {
            let args: contract_args::SubmitParticipantInfoArgs =
                serde_json::from_slice(&call.args)?;
            let stored_attestation = indexer_state
                .view_client
                .get_participant_attestation(&indexer_state.mpc_contract_id, &args.tls_public_key)
                .await?;

            let Some(stored_attestation) = stored_attestation else {
                tracing::debug!(
                    "no attestation stored on chain for our key; submission not yet landed"
                );
                return Ok(TransactionStatus::NotExecuted);
            };

            let stored_expiry = match &stored_attestation {
                VerifiedAttestation::Dstack(stored) => Some(stored.expiry_timestamp_seconds),
                VerifiedAttestation::Mock(_) => None,
            };
            let attestation_landed = submitted_attestation_landed(
                pre_submit_expiry,
                &stored_attestation,
                &args.proposed_participant_attestation,
            );

            tracing::info!(
                pre_submit_expiry = ?pre_submit_expiry,
                ?stored_expiry,
                attestation_landed,
                "checked attestation submission on chain"
            );

            Ok(if attestation_landed {
                TransactionStatus::Executed
            } else {
                TransactionStatus::NotExecuted
            })
        }
        // We don't care. The contract state change will handle this.
        _ => Ok(TransactionStatus::Unknown),
    }
}

/// Attempts to ensure that a function call with the given method and args is
/// included on-chain. Submits the transaction, waits `TRANSACTION_TIMEOUT` for
/// it to be included, then observes once whether it had its intended on-chain
/// effect.
async fn ensure_send_transaction(
    tx_signer: Arc<TransactionSigner>,
    indexer_state: Arc<IndexerState>,
    contract_id: AccountId,
    call: FunctionCallArgs,
) -> (TransactionStatus, SubmittedTransaction) {
    let method = call.method_name.clone();
    let signer = SignerContext {
        account_id: tx_signer.account_id().clone(),
        public_key: Ed25519PublicKey::from(&tx_signer.public_key()),
        method: method.clone(),
    };
    // The landing-check baseline must be captured before the transaction is
    // submitted.
    let pre_submit_expiry = pre_submit_attestation_expiry(&indexer_state, &call).await;
    let submitted_metadata = submit_tx(
        tx_signer.clone(),
        indexer_state.clone(),
        contract_id,
        call.clone(),
    )
    .await;

    // Stamp the submission time now, before the observation wait below, so the
    // debug page reflects when the transaction was actually routed.
    let submitted_at = Clock::real().now_utc();

    let metadata = match submitted_metadata {
        Ok(metadata) => metadata,
        Err(err) => {
            metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
                .with_label_values(&[method.as_str(), "local_error"])
                .inc();
            tracing::error!(%err, method, "Failed to forward transaction");
            return (
                TransactionStatus::NotExecuted,
                SubmittedTransaction::submit_failed(signer, submitted_at),
            );
        }
    };

    // Allow time for the transaction to be included
    time::sleep(TRANSACTION_TIMEOUT).await;

    // Then try to check whether it had the intended effect
    let transaction_status =
        observe_tx_result(indexer_state.clone(), &call, pre_submit_expiry).await;

    let (outcome_label, recorded_status) = match &transaction_status {
        Ok(TransactionStatus::Executed) => ("succeeded", SubmittedTransactionStatus::Executed),
        Ok(TransactionStatus::NotExecuted) => {
            ("timed_out", SubmittedTransactionStatus::NotExecuted)
        }
        Ok(TransactionStatus::Unknown) => ("unknown", SubmittedTransactionStatus::Unknown),
        Err(err) => {
            tracing::warn!(target:"mpc", %err, method, "encountered error trying to confirm result of transaction");
            ("unknown_err", SubmittedTransactionStatus::ObserveError)
        }
    };
    metrics::MPC_OUTGOING_TRANSACTION_OUTCOMES
        .with_label_values(&[method.as_str(), outcome_label])
        .inc();

    (
        transaction_status.unwrap_or(TransactionStatus::Unknown),
        SubmittedTransaction::submitted(signer, metadata, recorded_status, submitted_at),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        Attestation, VerifiedAttestation, attestation_expiry_changed, submitted_attestation_landed,
    };
    use near_mpc_contract_interface::types::MockAttestation;

    #[test]
    #[expect(non_snake_case)]
    fn attestation_expiry_changed__should_confirm_when_expiry_increases() {
        // Given: an attestation was stored before submitting
        let pre_submit_expiry = Some(100);

        // When: the stored expiry is now higher than before (a fresh submit landed)
        let landed = attestation_expiry_changed(pre_submit_expiry, 200);

        // Then: our submission is confirmed to have landed
        assert!(landed);
    }

    #[test]
    #[expect(non_snake_case)]
    fn attestation_expiry_changed__should_reject_when_expiry_unchanged() {
        // Given: an attestation was stored before submitting
        let pre_submit_expiry = Some(200);

        // When: the stored expiry is unchanged (our submit did not land)
        let landed = attestation_expiry_changed(pre_submit_expiry, 200);

        // Then: the submission is treated as not executed
        assert!(!landed);
    }

    #[test]
    #[expect(non_snake_case)]
    fn attestation_expiry_changed__should_confirm_when_expiry_decreases() {
        // Given: an attestation was stored before submitting, and a contract upgrade has lowered
        // the expiration constant, so a landed submit now stamps an *earlier* expiry
        let pre_submit_expiry = Some(300);

        // When: the stored expiry is now lower than before
        let landed = attestation_expiry_changed(pre_submit_expiry, 200);

        // Then: the change still confirms our submission landed (this is why we compare for
        // inequality rather than a strict increase)
        assert!(landed);
    }

    #[test]
    #[expect(non_snake_case)]
    fn attestation_expiry_changed__should_confirm_when_no_prior_attestation() {
        // Given: no attestation was stored before submitting
        let pre_submit_expiry = None;

        // When: an attestation is now stored
        let landed = attestation_expiry_changed(pre_submit_expiry, 200);

        // Then: its presence confirms our submission landed
        assert!(landed);
    }

    #[test]
    #[expect(non_snake_case)]
    fn submitted_attestation_landed__should_confirm_matching_mock() {
        // Given: the stored mock attestation equals the one we submitted
        let stored = VerifiedAttestation::Mock(MockAttestation::Valid);
        let submitted = Attestation::Mock(MockAttestation::Valid);

        // When
        let landed = submitted_attestation_landed(None, &stored, &submitted);

        // Then
        assert!(landed);
    }

    #[test]
    #[expect(non_snake_case)]
    fn submitted_attestation_landed__should_reject_mismatching_mock() {
        // Given: the stored mock attestation differs from the one we submitted
        let stored = VerifiedAttestation::Mock(MockAttestation::Valid);
        let submitted = Attestation::Mock(MockAttestation::Invalid);

        // When
        let landed = submitted_attestation_landed(None, &stored, &submitted);

        // Then
        assert!(!landed);
    }
}
