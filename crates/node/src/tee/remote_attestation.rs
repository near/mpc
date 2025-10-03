use std::time::Duration;

use crate::{
    indexer::{
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

use mpc_contract::tee::tee_state::NodeId;
use near_sdk::AccountId;
use tokio::sync::watch;

const ATTESTATION_RESUBMISSION_INTERVAL: Duration = Duration::from_secs(10 * 60);
const MIN_BACKOFF_DURATION: Duration = Duration::from_millis(100);
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);
const MAX_RETRY_DURATION: Duration = Duration::from_secs(60 * 60 * 12); // 12 hours.
const BACKOFF_FACTOR: f32 = 1.5;
const RESUBMISSION_RETRY_DELAY: Duration = Duration::from_secs(2);

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
    const MAX_RETRIES: usize = 3;
    let mut retry_interval = tokio::time::interval(RESUBMISSION_RETRY_DELAY);

    for attempt in 1..=MAX_RETRIES {
        let tls_sdk_public_key = tls_public_key.to_near_sdk_public_key()?;
        let report_data = ReportData::new(tls_sdk_public_key.clone());
        let fresh_attestation = tee_authority.generate_attestation(report_data).await?;

        match submit_remote_attestation(tx_sender.clone(), fresh_attestation, tls_public_key).await
        {
            Ok(_) => {
                tracing::info!(%node_account_id, attempt, "successfully resubmitted attestation");
                return Ok(());
            }
            Err(error) if attempt == MAX_RETRIES => {
                tracing::error!(%node_account_id, %error, "attestation resubmission failed after {MAX_RETRIES} attempts");
                return Err(error);
            }
            Err(error) => {
                tracing::warn!(%node_account_id, attempt, %error, "attestation resubmission failed, retrying");
                if attempt < MAX_RETRIES {
                    retry_interval.tick().await;
                }
            }
        }
    }

    unreachable!()
}

/// Checks if TEE attestation is available for the given node in the TEE accounts list.
fn is_tee_attestation_available(tee_accounts: &[NodeId], node_id: &NodeId) -> bool {
    tee_accounts.iter().any(|tee_node_id| {
        tee_node_id.account_id == node_id.account_id
            && tee_node_id.tls_public_key == node_id.tls_public_key
    })
}

/// Monitors the contract for TEE attestation removal and triggers resubmission when needed.
///
/// This function watches TEE account changes in the contract and resubmits attestations when
/// the node's TEE attestation is no longer available. This covers all removal scenarios:
/// - Attestation timeout/expiration
/// - Node removal during resharing
/// - TEE validation failures
pub async fn monitor_attestation_removal<T: TransactionSender + Clone>(
    node_account_id: AccountId,
    tee_authority: TeeAuthority,
    tx_sender: T,
    tls_public_key: VerifyingKey,
    mut tee_accounts_receiver: watch::Receiver<Vec<NodeId>>,
) -> anyhow::Result<()> {
    let node_id = NodeId {
        account_id: node_account_id.clone(),
        tls_public_key: near_sdk::PublicKey::from_parts(
            near_sdk::CurveType::ED25519,
            tls_public_key.to_bytes().to_vec(),
        )
        .expect("Failed to create PublicKey from TLS public key"),
    };

    tracing::info!(
        %node_account_id,
        "starting TEE attestation removal monitoring"
    );

    let initial_tee_accounts = tee_accounts_receiver.borrow().clone();
    let initially_available = is_tee_attestation_available(&initial_tee_accounts, &node_id);

    tracing::info!(
        %node_account_id,
        initially_available,
        "initial TEE attestation status"
    );

    let mut was_available = initially_available;

    while tee_accounts_receiver.changed().await.is_ok() {
        let tee_accounts = tee_accounts_receiver.borrow().clone();
        let is_available = is_tee_attestation_available(&tee_accounts, &node_id);

        tracing::debug!(
            %node_account_id,
            is_available,
            was_available,
            "TEE attestation status check"
        );

        if was_available && !is_available {
            tracing::warn!(
                %node_account_id,
                "TEE attestation removed from contract, resubmitting"
            );

            resubmit_attestation(&node_account_id, &tee_authority, &tx_sender, tls_public_key)
                .await?;
        }

        was_available = is_available;
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
    async fn test_tee_attestation_removal_detection() {
        let node_account_id: AccountId = "test_node.near".parse().unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let tls_public_key = SigningKey::generate(&mut rng).verifying_key();
        let tee_authority = TeeAuthority::from(LocalTeeAuthorityConfig::default());
        let mock_sender = MockSender::new();

        let node_id = NodeId {
            account_id: node_account_id.clone(),
            tls_public_key: near_sdk::PublicKey::from_parts(
                near_sdk::CurveType::ED25519,
                tls_public_key.to_bytes().to_vec(),
            )
            .expect("Failed to create PublicKey from TLS public key"),
        };

        // Create initial TEE accounts list including our node
        let initial_tee_accounts = vec![node_id.clone()];
        let (sender, receiver) = watch::channel(initial_tee_accounts);

        // Start monitoring task
        let monitoring_task = tokio::spawn(monitor_attestation_removal(
            node_account_id.clone(),
            tee_authority,
            mock_sender.clone(),
            tls_public_key,
            receiver,
        ));

        // Wait for initial setup
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Verify no submission occurred initially (node is in TEE accounts)
        assert_eq!(mock_sender.count(), 0);

        // Remove the node from TEE accounts (simulate attestation removal)
        let removed_tee_accounts = vec![]; // Node is no longer in TEE accounts
        sender.send(removed_tee_accounts).unwrap();

        // Wait for monitoring to detect the change
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify attestation resubmission occurred
        assert_eq!(mock_sender.count(), 1);

        // Add the node back to TEE accounts
        let restored_tee_accounts = vec![node_id];
        sender.send(restored_tee_accounts).unwrap();

        // Wait for state update
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Verify no additional submission (node is back in TEE accounts)
        assert_eq!(mock_sender.count(), 1);

        // Clean up
        monitoring_task.abort();
        let _ = monitoring_task.await;
    }
}
