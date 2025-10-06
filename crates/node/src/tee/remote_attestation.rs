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

const ATTESTATION_RESUBMISSION_RETRY_DELAY: Duration = Duration::from_secs(2);
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
        let report_data = ReportData::new(tls_sdk_public_key);
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
    let mut retry_interval = tokio::time::interval(ATTESTATION_RESUBMISSION_RETRY_DELAY);
    let tls_sdk_public_key = tls_public_key.to_near_sdk_public_key()?;
    let report_data = ReportData::new(tls_sdk_public_key.clone());
    let fresh_attestation = tee_authority.generate_attestation(report_data).await?;

    for attempt in 1..=MAX_RETRIES {
        let is_final_attempt = attempt == MAX_RETRIES;

        match submit_remote_attestation(
            tx_sender.clone(),
            fresh_attestation.clone(),
            tls_public_key,
        )
        .await
        {
            Ok(_) => {
                tracing::info!(%node_account_id, attempt, "successfully resubmitted attestation");
                return Ok(());
            }
            Err(error) => {
                if is_final_attempt {
                    tracing::error!(%node_account_id, %error, "attestation resubmission failed after {MAX_RETRIES} attempts");
                    return Err(error);
                } else {
                    tracing::warn!(%node_account_id, attempt, %error, "attestation resubmission failed, retrying");
                    retry_interval.tick().await;
                }
            }
        }
    }

    Ok(()) // This line is unreachable but satisfies the compiler
}

/// Checks if TEE attestation is available for the given node in the TEE accounts list.
fn is_node_in_contract_tee_accounts(
    tee_accounts_receiver: &mut watch::Receiver<Vec<NodeId>>,
    node_id: &NodeId,
) -> bool {
    let tee_accounts = tee_accounts_receiver.borrow_and_update();
    tee_accounts.contains(node_id)
}

/// Monitors the contract for TEE attestation removal and triggers resubmission when needed.
///
/// This function watches TEE account changes in the contract and resubmits attestations when
/// the node's TEE attestation is no longer available.
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
        .map_err(|e| anyhow::anyhow!("Failed to create PublicKey from TLS public key: {}", e))?,
    };

    let initially_available =
        is_node_in_contract_tee_accounts(&mut tee_accounts_receiver, &node_id);

    tracing::info!(
        %node_account_id,
        initially_available,
        "starting TEE attestation removal monitoring; initial TEE attestation status"
    );

    let mut was_available = initially_available;

    while tee_accounts_receiver.changed().await.is_ok() {
        let is_available = is_node_in_contract_tee_accounts(&mut tee_accounts_receiver, &node_id);

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

    /// Simulates contract behavior by automatically adding the node back to TEE accounts
    /// when an attestation submission occurs, mimicking real contract response to successful submissions.
    struct ContractSimulator {
        sender: watch::Sender<Vec<NodeId>>,
        node_id: NodeId,
    }

    /// Mock that tracks attestation submissions and simulates contract responses.
    #[derive(Clone)]
    struct MockSender {
        submissions: Arc<Mutex<usize>>,
        contract_simulator: Arc<ContractSimulator>,
    }

    impl MockSender {
        fn new(sender: watch::Sender<Vec<NodeId>>, node_id: NodeId) -> Self {
            Self {
                submissions: Arc::new(Mutex::new(0)),
                contract_simulator: Arc::new(ContractSimulator { sender, node_id }),
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

            // Simulate contract adding the node back to TEE accounts after successful submission
            let updated_tee_accounts = vec![self.contract_simulator.node_id.clone()];
            let _ = self.contract_simulator.sender.send(updated_tee_accounts);

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

        let (dummy_sender, _) = watch::channel(vec![]);
        let dummy_node_id = NodeId {
            account_id: "dummy.near".parse().unwrap(),
            tls_public_key: near_sdk::PublicKey::from_parts(
                near_sdk::CurveType::ED25519,
                vec![0u8; 32],
            )
            .unwrap(),
        };
        let sender = MockSender::new(dummy_sender, dummy_node_id);
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

        let node_id = NodeId {
            account_id: node_account_id.clone(),
            tls_public_key: near_sdk::PublicKey::from_parts(
                near_sdk::CurveType::ED25519,
                tls_public_key.to_bytes().to_vec(),
            )
            .unwrap(),
        };

        // Create initial TEE accounts list including our node
        let initial_tee_accounts = vec![node_id.clone()];
        let (tee_accounts_sender, receiver) = watch::channel(initial_tee_accounts);

        // Create mock sender with contract simulator built-in
        let mock_sender = MockSender::new(tee_accounts_sender.clone(), node_id.clone());

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
        tee_accounts_sender.send(removed_tee_accounts).unwrap();

        // Wait for monitoring to detect removal and resubmit
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify attestation resubmission occurred (monitoring detected removal)
        assert_eq!(
            mock_sender.count(),
            1,
            "Expected exactly one resubmission when node was removed"
        );

        // Wait a bit more to ensure the monitoring service has processed the automatic re-addition
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Verify no additional submissions occurred (node should be back in TEE accounts automatically)
        assert_eq!(
            mock_sender.count(),
            1,
            "Expected no additional submissions after node was automatically re-added"
        );

        // Stop monitoring service and verify no further submissions occur
        monitoring_task.abort();
        let _ = monitoring_task.await;

        // Wait a bit to ensure the monitoring task has fully stopped
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Verify the submission count remains unchanged after stopping monitoring
        // (This confirms that only the monitoring service triggers resubmissions)
        assert_eq!(
            mock_sender.count(),
            1,
            "Expected submission count to remain stable after stopping monitoring service"
        );

        // Remove the node from TEE accounts again to verify monitoring service is truly stopped
        let removed_tee_accounts = vec![]; // Node is no longer in TEE accounts
        let _ = tee_accounts_sender.send(removed_tee_accounts);

        // Wait to ensure no resubmission occurs when monitoring is stopped
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify no resubmission occurred (monitoring service is stopped)
        assert_eq!(
            mock_sender.count(),
            1,
            "Expected no resubmission when monitoring service is stopped"
        );
    }
}
