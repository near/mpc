use std::time::Duration;

use anyhow::Context;
use attestation::attestation::Attestation;
use ed25519_dalek::VerifyingKey;

use crate::{
    indexer::{
        tx_sender::{TransactionSender, TransactionStatus},
        types::{ChainSendTransactionRequest, SubmitParticipantInfoArgs},
    },
    trait_extensions::convert_to_contract_dto::IntoDtoType,
};

const ATTESTATION_SUBMISSION_BACKOFF_DURATION: Duration = Duration::from_secs(10);

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
) {
    let propose_join_args = SubmitParticipantInfoArgs {
        proposed_participant_attestation: attestation.into_dto_type(),
        tls_public_key: tls_public_key.into_dto_type(),
    };

    loop {
        let attestation_submission_result = tx_sender
            .send_and_wait(ChainSendTransactionRequest::SubmitParticipantInfo(
                Box::new(propose_join_args.clone()),
            ))
            .await
            .context("Failed to send remote attestation transaction. Channel is closed.");

        match attestation_submission_result {
            Ok(TransactionStatus::Executed) => {
                tracing::info!("Attestation is successfully submitted.");
                return;
            }
            error => {
                tracing::error!(
                    cause = ?error,
                    backoff_duration = ?ATTESTATION_SUBMISSION_BACKOFF_DURATION,
                    "Failed to submit attestation."
                );

                tokio::time::sleep(ATTESTATION_SUBMISSION_BACKOFF_DURATION).await;
            }
        }
    }
}
