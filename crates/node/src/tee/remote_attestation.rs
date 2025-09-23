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

#[cfg(test)]
mod tests {
    use crate::indexer::tx_sender::TransactionProcessorError;

    use super::*;
    use attestation::attestation::MockAttestation;
    use mockall::mock;
    use tokio::time::{self, Duration};

    mock! {
        pub TransactionSender {}

        impl Clone for TransactionSender {
            fn clone(&self) -> Self;
        }

        impl TransactionSender for TransactionSender {
            async fn send(
                &self,
                _transaction: ChainSendTransactionRequest,
            ) -> Result<(), TransactionProcessorError>;

            async fn send_and_wait(
                &self,
                _transaction: ChainSendTransactionRequest,
            ) -> Result<TransactionStatus, TransactionProcessorError>;
        }
    }

    fn dummy_args() -> (Attestation, VerifyingKey) {
        (
            Attestation::Mock(MockAttestation::Valid),
            VerifyingKey::from_bytes(&[0; 32]).unwrap(),
        )
    }

    #[tokio::test]
    async fn test_submit_remote_attestation_success_first_try() {
        let (attestation, key) = dummy_args();

        let mut mock_sender = MockTransactionSender::new();
        mock_sender
            .expect_send_and_wait()
            .returning(|_| Ok(TransactionStatus::Executed));

        // No errors, should return immediately
        let result = time::timeout(
            Duration::from_secs(1),
            submit_remote_attestation(mock_sender, attestation, key),
        )
        .await;
        assert!(result.is_ok(), "Function should finish without looping");
    }

    #[tokio::test]
    async fn test_submit_remote_attestation_retries_then_succeeds() {
        let (attestation, key) = dummy_args();

        let mut mock_sender = MockTransactionSender::new();
        let mut call_count = 0;

        mock_sender.expect_send_and_wait().returning(move |_| {
            call_count += 1;
            if call_count < 3 {
                // Fail first two times
                Ok(TransactionStatus::NotExecuted)
            } else {
                // Succeed on third attempt
                Ok(TransactionStatus::Executed)
            }
        });

        // Use Tokio’s timeout to ensure test doesn’t hang
        let result = time::timeout(
            Duration::from_secs(5),
            submit_remote_attestation(mock_sender, attestation, key),
        )
        .await;

        assert!(
            result.is_ok(),
            "Function should eventually succeed after retries"
        );
    }
}
