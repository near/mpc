use std::time::Duration;

use anyhow::Context;
use attestation::attestation::Attestation;
use backon::{BackoffBuilder, ExponentialBuilder, Retryable};
use ed25519_dalek::VerifyingKey;
use tokio_util::time::FutureExt;

use crate::{
    indexer::{
        tx_sender::{TransactionSender, TransactionStatus},
        types::{ChainSendTransactionRequest, SubmitParticipantInfoArgs},
    },
    trait_extensions::convert_to_contract_dto::IntoDtoType,
};

const MIN_BACKOFF_DURATION: Duration = Duration::from_millis(100);
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);
const MAX_RETRY_DURATION: Duration = Duration::from_secs(60 * 60 * 12); // 12 hours.
const BACKOFF_FACTOR: f32 = 1.5;

/// Submits a remote attestation transaction to the MPC contract, retrying with backoff until success.
///
/// This function continuously attempts to submit a [`SubmitParticipantInfo`] transaction containing
/// the given participant's attestation and TLS public key. It uses the provided
/// [`TransactionSender`] to send the transaction and waits until [`TransactionStatus::Executed`]
/// is observed.  
pub async fn submit_remote_attestation(
    tx_sender: impl TransactionSender,
    attestation: Attestation,
    tls_public_key: VerifyingKey,
) -> anyhow::Result<()> {
    let propose_join_args = SubmitParticipantInfoArgs {
        proposed_participant_attestation: attestation.into_dto_type(),
        tls_public_key: tls_public_key.into_dto_type(),
    };

    let set_attestation = move || {
        let tx_sender = tx_sender.clone();
        let propose_join_args_clone = propose_join_args.clone();
        let chain_args =
            ChainSendTransactionRequest::SubmitParticipantInfo(Box::new(propose_join_args_clone));

        async move {
            let attestation_submission_response = tx_sender
                .send_and_wait(chain_args)
                .await
                .context("failed to submit transaction")?;

            match attestation_submission_response {
                TransactionStatus::Executed => Ok(()),
                TransactionStatus::NotExecuted => {
                    anyhow::bail!("Attestation submission was not executed.")
                }
                TransactionStatus::Unknown => {
                    anyhow::bail!("Attestation submission has unknown response.")
                }
            }
        }
    };

    let exponential_backoff = ExponentialBuilder::default()
        .with_min_delay(MIN_BACKOFF_DURATION)
        .with_max_delay(MAX_BACKOFF_DURATION)
        .with_factor(BACKOFF_FACTOR)
        .without_max_times()
        .build();

    set_attestation
        .retry(exponential_backoff)
        .sleep(tokio::time::sleep)
        .notify(|error, duration| {
            tracing::error!(
                cause = ?error,
                backoff_duration = ?duration,
                "failed to submit attestation."
            );
        })
        .timeout(MAX_RETRY_DURATION)
        .await
        .context("Failed to submit attestation. Stop trying.")?
}
