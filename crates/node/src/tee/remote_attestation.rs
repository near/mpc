use std::time::Duration;

use crate::{
    indexer::{
        tx_sender::{TransactionSender, TransactionStatus},
        types::{ChainSendTransactionRequest, SubmitParticipantInfoArgs},
    },
    trait_extensions::convert_to_contract_dto::IntoContractInterfaceType,
};
use anyhow::Context;
use attestation::{
    attestation::{Attestation, VerificationError},
    report_data::ReportData,
};
use backon::{BackoffBuilder, ExponentialBuilder, Retryable};
use contract_interface::types::Ed25519PublicKey;
use tee_authority::tee_authority::TeeAuthority;
use tokio_util::time::FutureExt;

use mpc_contract::tee::{
    proposal::{LauncherDockerComposeHash, MpcDockerImageHash},
    tee_state::NodeId,
};
use near_sdk::AccountId;
use tokio::sync::watch;

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
    tls_public_key: Ed25519PublicKey,
) -> anyhow::Result<()> {
    let submit_participant_info_args = SubmitParticipantInfoArgs {
        proposed_participant_attestation: attestation.into_contract_interface_type(),
        tls_public_key,
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

fn validate_remote_attestation(
    attestation: &Attestation,
    tls_public_key: Ed25519PublicKey,
    account_public_key: Ed25519PublicKey,
    allowed_docker_image_hashes: &[MpcDockerImageHash],
    allowed_launcher_compose_hashes: &[LauncherDockerComposeHash],
) -> Result<(), VerificationError> {
    let expected_report_data =
        ReportData::new(*tls_public_key.as_bytes(), *account_public_key.as_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    attestation.verify(
        expected_report_data,
        now,
        allowed_docker_image_hashes,
        allowed_launcher_compose_hashes,
    )
}

pub async fn validate_and_submit_remote_attestation(
    tx_sender: impl TransactionSender,
    attestation: Attestation,
    tls_public_key: Ed25519PublicKey,
    account_public_key: Ed25519PublicKey,
    allowed_docker_image_hashes: &[MpcDockerImageHash],
    allowed_launcher_compose_hashes: &[LauncherDockerComposeHash],
) -> anyhow::Result<()> {
    let _ = validate_remote_attestation(
        &attestation,
        tls_public_key.clone(),
        account_public_key,
        allowed_docker_image_hashes,
        allowed_launcher_compose_hashes,
    )
    .inspect_err(|err| {
        // We could also return here, but for the moment I am just logging the
        // attestation failure error and letting the submission continue
        tracing::warn!("Attestation is not valid: {err}");
    });
    submit_remote_attestation(tx_sender, attestation, tls_public_key).await
}

pub async fn periodic_attestation_submission<T: TransactionSender + Clone, I: Tick>(
    tee_authority: TeeAuthority,
    tx_sender: T,
    tls_public_key: Ed25519PublicKey,
    account_public_key: Ed25519PublicKey,
    allowed_image_hashes_in_contract: watch::Receiver<Vec<MpcDockerImageHash>>,
    allowed_launcher_compose_hashes_in_contract: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    mut interval_ticker: I,
) -> anyhow::Result<()> {
    let report_data = ReportData::new(*tls_public_key.as_bytes(), *account_public_key.as_bytes());

    loop {
        interval_ticker.tick().await;

        let fresh_attestation = tee_authority
            .generate_attestation(report_data.clone())
            .await?;
        let allowed_image_hashes_in_contract = allowed_image_hashes_in_contract.borrow().clone();
        let allowed_launcher_compose_hashes_in_contract =
            allowed_launcher_compose_hashes_in_contract.borrow().clone();
        validate_and_submit_remote_attestation(
            tx_sender.clone(),
            fresh_attestation.clone(),
            tls_public_key.clone(),
            account_public_key.clone(),
            &allowed_image_hashes_in_contract,
            &allowed_launcher_compose_hashes_in_contract,
        )
        .await?;
    }
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
#[allow(clippy::too_many_arguments)]
pub async fn monitor_attestation_removal<T: TransactionSender + Clone>(
    node_account_id: AccountId,
    tee_authority: TeeAuthority,
    tx_sender: T,
    tls_public_key: Ed25519PublicKey,
    account_public_key: Ed25519PublicKey,
    allowed_image_hashes_in_contract: watch::Receiver<Vec<MpcDockerImageHash>>,
    allowed_launcher_compose_hashes_in_contract: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    mut tee_accounts_receiver: watch::Receiver<Vec<NodeId>>,
) -> anyhow::Result<()> {
    // TODO: we should unify these conversions, will not be needed after https://github.com/near/mpc/issues/1246
    let node_id = NodeId {
        account_id: node_account_id.clone(),
        tls_public_key: near_sdk::PublicKey::from_parts(
            near_sdk::CurveType::ED25519,
            tls_public_key.as_bytes().to_vec(),
        )
        .map_err(|e| anyhow::anyhow!("Failed to create PublicKey from TLS public key: {}", e))?,
        account_public_key: Some(
            near_sdk::PublicKey::from_parts(
                near_sdk::CurveType::ED25519,
                account_public_key.as_bytes().to_vec(),
            )
            .map_err(|e| {
                anyhow::anyhow!("Failed to create PublicKey from account public key: {}", e)
            })?,
        ),
    };

    let initially_available =
        is_node_in_contract_tee_accounts(&mut tee_accounts_receiver, &node_id);

    tracing::info!(
        %node_account_id,
        initially_available,
        "starting TEE attestation removal monitoring; initial TEE attestation status"
    );

    let mut was_available = initially_available;
    let report_data = ReportData::new(*tls_public_key.as_bytes(), *account_public_key.as_bytes());

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

            let fresh_attestation = tee_authority
                .generate_attestation(report_data.clone())
                .await?;
            let allowed_image_hashes_in_contract =
                allowed_image_hashes_in_contract.borrow().clone();
            let allowed_launcher_compose_hashes_in_contract =
                allowed_launcher_compose_hashes_in_contract.borrow().clone();
            validate_and_submit_remote_attestation(
                tx_sender.clone(),
                fresh_attestation.clone(),
                tls_public_key.clone(),
                account_public_key.clone(),
                &allowed_image_hashes_in_contract,
                &allowed_launcher_compose_hashes_in_contract,
            )
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
    const TEST_EXPECTED_ATTESTATION_RESUBMISSION_TIMEOUT: Duration = Duration::from_millis(100);
    const TEST_VERIFY_NO_ATTESTATION_RESUBMISSION_TIMEOUT: Duration = Duration::from_millis(100);

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
        notify: Arc<tokio::sync::Notify>,
    }

    impl MockSender {
        fn new(sender: watch::Sender<Vec<NodeId>>, node_id: NodeId) -> Self {
            Self {
                submissions: Arc::new(Mutex::new(0)),
                contract_simulator: Arc::new(ContractSimulator { sender, node_id }),
                notify: Arc::new(tokio::sync::Notify::new()),
            }
        }

        fn count(&self) -> usize {
            *self.submissions.lock().unwrap()
        }

        async fn wait_for_submission(&self) {
            self.notify.notified().await;
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

            // Notify that a submission occurred
            self.notify.notify_one();

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
            account_public_key: Some(
                near_sdk::PublicKey::from_parts(near_sdk::CurveType::ED25519, vec![0u8; 32])
                    .unwrap(),
            ),
        };
        let sender = MockSender::new(dummy_sender, dummy_node_id);
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let tls_key = SigningKey::generate(&mut rng)
            .verifying_key()
            .into_contract_interface_type();
        let account_key = SigningKey::generate(&mut rng)
            .verifying_key()
            .into_contract_interface_type();
        let (_, allowed_image_hashes_receiver) = watch::channel(vec![]);
        let (_, allowed_launcher_compose_hashes_receiver) = watch::channel(vec![]);
        let handle = tokio::spawn(periodic_attestation_submission(
            tee_authority,
            sender.clone(),
            tls_key,
            account_key,
            allowed_image_hashes_receiver,
            allowed_launcher_compose_hashes_receiver,
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
        let tls_public_key = SigningKey::generate(&mut rng)
            .verifying_key()
            .into_contract_interface_type();
        let account_public_key = SigningKey::generate(&mut rng)
            .verifying_key()
            .into_contract_interface_type();
        let tee_authority = TeeAuthority::from(LocalTeeAuthorityConfig::default());

        let node_id = NodeId {
            account_id: node_account_id.clone(),
            tls_public_key: near_sdk::PublicKey::from_parts(
                near_sdk::CurveType::ED25519,
                tls_public_key.as_bytes().to_vec(),
            )
            .unwrap(),
            account_public_key: Some(
                near_sdk::PublicKey::from_parts(
                    near_sdk::CurveType::ED25519,
                    account_public_key.as_bytes().to_vec(),
                )
                .unwrap(),
            ),
        };

        // Create initial TEE accounts list including our node
        let initial_tee_accounts = vec![node_id.clone()];
        let (tee_accounts_sender, receiver) = watch::channel(initial_tee_accounts);
        let (_, allowed_image_hashes_receiver) = watch::channel(vec![]);
        let (_, allowed_launcher_compose_hashes_receiver) = watch::channel(vec![]);

        // Create mock sender with contract simulator built-in
        let mock_sender = MockSender::new(tee_accounts_sender.clone(), node_id.clone());

        let monitoring_task = tokio::spawn(monitor_attestation_removal(
            node_account_id.clone(),
            tee_authority,
            mock_sender.clone(),
            tls_public_key,
            account_public_key,
            allowed_image_hashes_receiver,
            allowed_launcher_compose_hashes_receiver,
            receiver,
        ));

        // Yield control to allow the monitoring task to start and process initial state.
        // This is preferred over sleep() as it doesn't introduce arbitrary timing delays
        tokio::task::yield_now().await;

        // Verify no submission occurred initially (node is in TEE accounts)
        assert_eq!(mock_sender.count(), 0);

        // Remove the node from TEE accounts (simulate attestation removal)
        let removed_tee_accounts = vec![]; // Node is no longer in TEE accounts
        tee_accounts_sender.send(removed_tee_accounts).unwrap();

        // Wait for the resubmission to occur (with timeout to avoid hanging)
        tokio::time::timeout(
            TEST_EXPECTED_ATTESTATION_RESUBMISSION_TIMEOUT,
            mock_sender.wait_for_submission(),
        )
        .await
        .expect("Expected resubmission to occur within timeout");

        // Verify attestation resubmission occurred and no additional submissions occurred
        // (node should be back in TEE accounts automatically after resubmission)
        assert_eq!(
            mock_sender.count(),
            1,
            "Expected exactly one resubmission when node was removed"
        );

        // Stop monitoring service and verify no further submissions occur
        monitoring_task.abort();
        let _ = monitoring_task.await;

        // Verify the submission count remains unchanged after stopping monitoring
        assert_eq!(
            mock_sender.count(),
            1,
            "Expected submission count to remain stable after stopping monitoring service"
        );

        // Remove the node from TEE accounts again to verify monitoring service is truly stopped
        let removed_tee_accounts = vec![]; // Node is no longer in TEE accounts
        let _ = tee_accounts_sender.send(removed_tee_accounts);

        // Give a brief moment to ensure no resubmission occurs when monitoring is stopped
        // Since the monitoring task is stopped, we use a timeout to verify no submission happens
        let timeout_result = tokio::time::timeout(
            TEST_VERIFY_NO_ATTESTATION_RESUBMISSION_TIMEOUT,
            mock_sender.wait_for_submission(),
        )
        .await;

        // Verify the timeout occurred (no submission)
        assert!(
            timeout_result.is_err(),
            "Expected no resubmission when monitoring service is stopped"
        );

        // Verify no resubmission occurred (monitoring service is stopped)
        assert_eq!(
            mock_sender.count(),
            1,
            "Expected no resubmission when monitoring service is stopped"
        );
    }

    #[tokio::test]
    async fn test_validate_remote_attestation_valid() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let tls_public_key = SigningKey::generate(&mut rng)
            .verifying_key()
            .into_contract_interface_type();
        let account_public_key = SigningKey::generate(&mut rng)
            .verifying_key()
            .into_contract_interface_type();
        let tee_authority = TeeAuthority::from(LocalTeeAuthorityConfig::default());
        let report_data =
            ReportData::new(*tls_public_key.as_bytes(), *account_public_key.as_bytes());
        let attestation = tee_authority
            .generate_attestation(report_data)
            .await
            .unwrap();
        let allowed_docker_image_hashes = [MpcDockerImageHash::from([42u8; 32])];
        let allowed_launcher_compose_hashes = [LauncherDockerComposeHash::from([42u8; 32])];
        assert!(validate_remote_attestation(
            &attestation,
            tls_public_key,
            account_public_key,
            &allowed_docker_image_hashes,
            &allowed_launcher_compose_hashes
        )
        .is_ok());
    }

    #[tokio::test]
    async fn test_validate_remote_attestation_invalid() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let tls_public_key = SigningKey::generate(&mut rng)
            .verifying_key()
            .into_contract_interface_type();
        let account_public_key = SigningKey::generate(&mut rng)
            .verifying_key()
            .into_contract_interface_type();
        let tee_authority = TeeAuthority::from(LocalTeeAuthorityConfig::new(false));
        let report_data =
            ReportData::new(*tls_public_key.as_bytes(), *account_public_key.as_bytes());
        let attestation = tee_authority
            .generate_attestation(report_data)
            .await
            .unwrap();
        let allowed_docker_image_hashes = [MpcDockerImageHash::from([42u8; 32])];
        let allowed_launcher_compose_hashes = [LauncherDockerComposeHash::from([42u8; 32])];
        assert!(validate_remote_attestation(
            &attestation,
            tls_public_key,
            account_public_key,
            &allowed_docker_image_hashes,
            &allowed_launcher_compose_hashes
        )
        .is_err());
    }
}
