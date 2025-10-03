use std::time::Duration;

use crate::{
    config::ParticipantsConfig,
    indexer::{
        participants::ContractState,
        tx_sender::{TransactionSender, TransactionStatus},
        types::{ChainSendTransactionRequest, SubmitParticipantInfoArgs},
    },
    providers::PublicKeyConversion,
    trait_extensions::convert_to_contract_dto::IntoDtoType,
};
use anyhow::Context;
use attestation::{attestation::Attestation, report_data::ReportData};
use backon::{BackoffBuilder, ExponentialBuilder, Retryable};
use ed25519_dalek::VerifyingKey;
use tee_authority::tee_authority::TeeAuthority;
use tokio_util::time::FutureExt;

use near_sdk::AccountId;
use tokio::sync::watch;

const ATTESTATION_RESUBMISSION_INTERVAL: Duration = Duration::from_secs(10 * 60);
const MIN_BACKOFF_DURATION: Duration = Duration::from_millis(100);
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);
const MAX_RETRY_DURATION: Duration = Duration::from_secs(60 * 60 * 12); // 12 hours.
const BACKOFF_FACTOR: f32 = 1.5;

/// Submits a remote attestation transaction to the MPC contract, retrying with backoff until success.
///
/// This function continuously attempts to submit a [`SubmitParticipantInfoArgs`] transaction containing
/// the given participant's attestation and TLS public key. It uses the provided
/// [`TransactionSender`] to send the transaction and waits until [`TransactionStatus::Executed`]
/// is observed.  
pub async fn submit_remote_attestation(
    tx_sender: impl TransactionSender,
    attestation: Attestation,
    tls_public_key: VerifyingKey,
) -> anyhow::Result<()> {
    let submit_participant_info_args = SubmitParticipantInfoArgs {
        proposed_participant_attestation: attestation.into_dto_type(),
        tls_public_key: tls_public_key.into_dto_type(),
    };

    let set_attestation = move || {
        let tx_sender = tx_sender.clone();
        let propose_join_args_clone = submit_participant_info_args.clone();
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
                    anyhow::bail!("attestation submission was not executed")
                }
                TransactionStatus::Unknown => {
                    anyhow::bail!("attestation submission has unknown response")
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
                "failed to submit attestation"
            );
        })
        .timeout(MAX_RETRY_DURATION)
        .await
        .context("failed to submit attestation after multiple retry attempts")?
}

/// Periodically generates and submits fresh attestations at regular intervals.
///
/// This future runs indefinitely, generating a fresh attestation every 10 minutes
/// and submitting it to the blockchain.
pub async fn periodic_attestation_submission<T: TransactionSender + Clone>(
    tee_authority: TeeAuthority,
    tx_sender: T,
    tls_public_key: VerifyingKey,
) -> anyhow::Result<()> {
    periodic_attestation_submission_with_interval(
        tee_authority,
        tx_sender,
        tls_public_key,
        tokio::time::interval(ATTESTATION_RESUBMISSION_INTERVAL),
    )
    .await
}

async fn periodic_attestation_submission_with_interval<T: TransactionSender + Clone, I: Tick>(
    tee_authority: TeeAuthority,
    tx_sender: T,
    tls_public_key: VerifyingKey,
    mut interval_ticker: I,
) -> anyhow::Result<()> {
    loop {
        interval_ticker.tick().await;

        let tls_sdk_public_key = tls_public_key.to_near_sdk_public_key()?;
        let report_data = ReportData::new(tls_sdk_public_key.clone());
        let fresh_attestation = match tee_authority.generate_attestation(report_data).await {
            Ok(attestation) => attestation,
            Err(error) => {
                tracing::error!(
                    ?error,
                    "failed to generate fresh attestation, skipping this cycle"
                );
                continue;
            }
        };

        match submit_remote_attestation(tx_sender.clone(), fresh_attestation, tls_public_key).await
        {
            Ok(()) => tracing::info!("successfully submitted fresh remote attestation"),
            Err(error) => {
                tracing::error!(?error, "failed to submit fresh remote attestation");
            }
        }
    }
}

async fn resubmit_attestation<T: TransactionSender + Clone>(
    node_account_id: &AccountId,
    tee_authority: &TeeAuthority,
    tx_sender: &T,
    tls_public_key: VerifyingKey,
) -> anyhow::Result<()> {
    let tls_sdk_public_key = tls_public_key.to_near_sdk_public_key()?;
    let report_data = ReportData::new(tls_sdk_public_key.clone());
    let fresh_attestation = tee_authority.generate_attestation(report_data).await?;
    submit_remote_attestation(tx_sender.clone(), fresh_attestation, tls_public_key).await?;
    tracing::info!(%node_account_id, "successfully resubmitted attestation after state change detection");
    Ok(())
}

fn is_participant_in_config(
    participants: &ParticipantsConfig,
    node_account_id: &AccountId,
) -> bool {
    participants
        .participants
        .iter()
        .any(|p| p.near_account_id == *node_account_id)
}

fn extract_participant_info(state: &ContractState, node_account_id: &AccountId) -> bool {
    match state {
        ContractState::Running(s) => is_participant_in_config(&s.participants, node_account_id),
        ContractState::Initializing(s) => {
            is_participant_in_config(&s.participants, node_account_id)
        }
        ContractState::Invalid => false,
    }
}

/// Monitors contract state changes and triggers attestation resubmission when appropriate.
///
/// This function watches contract state transitions and resubmits attestations when
/// the node transitions from being a participant to not being a participant.
pub async fn monitor_attestation_removal<T: TransactionSender + Clone>(
    node_account_id: AccountId,
    tee_authority: TeeAuthority,
    tx_sender: T,
    tls_public_key: VerifyingKey,
    mut contract_state_receiver: watch::Receiver<ContractState>,
) -> anyhow::Result<()> {
    tracing::info!(
        %node_account_id,
        "starting attestation removal monitoring"
    );

    let initial_state = contract_state_receiver.borrow().clone();
    let initially_participant = extract_participant_info(&initial_state, &node_account_id);

    tracing::info!(
        %node_account_id,
        initially_participant = initially_participant,
        "established initial attestation monitoring baseline"
    );

    let mut was_participant = initially_participant;

    loop {
        if contract_state_receiver.changed().await.is_err() {
            tracing::warn!("contract state receiver closed, stopping attestation monitoring");
            break;
        }

        let current_state = contract_state_receiver.borrow().clone();
        let currently_participant = extract_participant_info(&current_state, &node_account_id);
        let participant_removed = was_participant && !currently_participant;

        if participant_removed {
            tracing::warn!(%node_account_id, "detected transition from participant to non-participant, triggering attestation resubmission");

            if let Err(error) =
                resubmit_attestation(&node_account_id, &tee_authority, &tx_sender, tls_public_key)
                    .await
            {
                tracing::debug!(
                    ?error,
                    "attestation resubmission failed, will retry on next state change"
                );
            }
        }

        was_participant = currently_participant;
    }

    Ok(())
}

/// Allows repeatedly awaiting for something, like a `tokio::time::Interval`.
pub trait Tick {
    async fn tick(&mut self);
}

impl Tick for tokio::time::Interval {
    async fn tick(&mut self) {
        self.tick().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexer::tx_sender::{TransactionProcessorError, TransactionStatus};
    use ed25519_dalek::SigningKey;
    use rand::SeedableRng;
    use std::sync::{Arc, Mutex};
    use tee_authority::tee_authority::{LocalTeeAuthorityConfig, TeeAuthority};

    const TEST_SUBMISSION_COUNT: usize = 2;

    struct MockTicker {
        count: usize,
    }

    impl MockTicker {
        fn new(count: usize) -> Self {
            Self { count }
        }
    }

    impl Tick for MockTicker {
        async fn tick(&mut self) {
            if self.count > 0 {
                self.count -= 1;
            } else {
                std::future::pending::<()>().await;
            }
        }
    }

    #[derive(Clone)]
    struct MockSender {
        submissions: Arc<Mutex<usize>>,
    }

    impl MockSender {
        fn new() -> Self {
            Self {
                submissions: Arc::new(Mutex::new(0)),
            }
        }

        fn count(&self) -> usize {
            *self.submissions.lock().unwrap()
        }
    }

    impl TransactionSender for MockSender {
        async fn send(
            &self,
            _: ChainSendTransactionRequest,
        ) -> Result<(), TransactionProcessorError> {
            *self.submissions.lock().unwrap() += 1;
            Ok(())
        }

        async fn send_and_wait(
            &self,
            request: ChainSendTransactionRequest,
        ) -> Result<TransactionStatus, TransactionProcessorError> {
            self.send(request).await?;
            Ok(TransactionStatus::Executed)
        }
    }

    #[tokio::test]
    async fn test_periodic_attestation_submission() {
        let tee_authority = TeeAuthority::from(LocalTeeAuthorityConfig::default());
        let sender = MockSender::new();
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let key = SigningKey::generate(&mut rng).verifying_key();

        let handle = tokio::spawn(periodic_attestation_submission_with_interval(
            tee_authority,
            sender.clone(),
            key,
            MockTicker::new(TEST_SUBMISSION_COUNT),
        ));

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert_eq!(sender.count(), TEST_SUBMISSION_COUNT);
        handle.abort();
    }

    #[tokio::test]
    async fn test_attestation_removal_detection() {
        use crate::{
            config::ParticipantInfo,
            indexer::participants::{ContractRunningState, ContractState},
            primitives::ParticipantId,
        };
        use mpc_contract::primitives::key_state::{EpochId, Keyset};
        use near_sdk::AccountId;
        use tokio::sync::watch;

        let tee_authority = TeeAuthority::from(LocalTeeAuthorityConfig::default());
        let sender = MockSender::new();
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let key = SigningKey::generate(&mut rng).verifying_key();
        let account_id: AccountId = "test.near".parse().unwrap();

        // Create initial contract state with our node as a participant
        let our_participant = ParticipantInfo {
            id: ParticipantId::from_raw(0),
            address: "127.0.0.1".to_string(),
            port: 8080,
            p2p_public_key: key,
            near_account_id: account_id.clone(),
        };

        let initial_participants = ParticipantsConfig {
            participants: vec![our_participant.clone()],
            threshold: 1,
        };

        let initial_state = ContractState::Running(ContractRunningState {
            keyset: Keyset {
                epoch_id: EpochId::new(1),
                domains: vec![],
            },
            participants: initial_participants.clone(),
            resharing_state: None,
        });

        let (state_sender, state_receiver) = watch::channel(initial_state);

        // Start the monitoring task
        let monitor_handle = tokio::spawn(monitor_attestation_removal(
            account_id.clone(),
            tee_authority,
            sender.clone(),
            key,
            state_receiver,
        ));

        // Give the monitor time to process the initial state
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Check initial submission count (should be 0 since no resubmissions yet)
        let initial_count = sender.count();
        assert_eq!(initial_count, 0, "Expected no initial resubmissions");

        // Trigger initial state processing by sending the same state again
        let initial_state_copy = initial_participants.clone();
        let initial_state_trigger = ContractState::Running(ContractRunningState {
            keyset: Keyset {
                epoch_id: EpochId::new(1),
                domains: vec![],
            },
            participants: initial_state_copy,
            resharing_state: None,
        });
        state_sender.send_replace(initial_state_trigger);
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

        // Test 1: Participant removal (resharing scenario)
        let other_participant = ParticipantInfo {
            id: ParticipantId::from_raw(1),
            address: "127.0.0.1".to_string(),
            port: 8081,
            p2p_public_key: SigningKey::generate(&mut rng).verifying_key(),
            near_account_id: "other.near".parse().unwrap(),
        };

        let removed_participants = ParticipantsConfig {
            participants: vec![other_participant],
            threshold: 1,
        };

        // Send state where our node is no longer a participant (same epoch)
        let removed_state = ContractState::Running(ContractRunningState {
            keyset: Keyset {
                epoch_id: EpochId::new(1), // Same epoch - participant removal
                domains: vec![],
            },
            participants: removed_participants.clone(),
            resharing_state: None,
        });

        state_sender.send(removed_state).unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

        // Should have detected participant removal and triggered resubmission
        assert!(
            sender.count() >= 1,
            "Expected attestation resubmission after participant removal"
        );

        // Test 2: Epoch change without participant removal should NOT trigger resubmission
        let epoch_change_state = ContractState::Running(ContractRunningState {
            keyset: Keyset {
                epoch_id: EpochId::new(2), // New epoch - should NOT trigger resubmission
                domains: vec![],
            },
            participants: removed_participants, // Same participants as before
            resharing_state: None,
        });

        let count_before_epoch_change = sender.count();
        state_sender.send(epoch_change_state).unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

        // Should NOT have triggered resubmission for epoch change alone
        assert_eq!(
            sender.count(),
            count_before_epoch_change,
            "Epoch change alone should not trigger attestation resubmission"
        );

        monitor_handle.abort();
    }
}
