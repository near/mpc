use std::time::Duration;

use crate::{
    indexer::tx_sender::TransactionStatus,
    trait_extensions::convert_to_contract_dto::IntoContractInterfaceType,
};
use anyhow::Context;
use backon::{BackoffBuilder, ExponentialBuilder, Retryable};
use mpc_attestation::{
    attestation::{Attestation, VerificationError},
    report_data::{ReportData, ReportDataV1},
};
use near_contract_transport::CallContract;
use near_mpc_contract_interface::client::MpcContractHandle;
use near_mpc_contract_interface::types::{AllowedMpcDockerImageHash, Ed25519PublicKey};
use tee_authority::tee_authority::TeeAuthority;
use tokio_util::time::FutureExt;

use mpc_primitives::hash::{LauncherDockerComposeHash, NodeImageHash};
use near_account_id::AccountId;
use near_mpc_contract_interface::types::NodeId;
use tokio::sync::watch;

const MIN_BACKOFF_DURATION: Duration = Duration::from_millis(100);
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);
const MAX_RETRY_DURATION: Duration = Duration::from_secs(60 * 60 * 12); // 12 hours.
const BACKOFF_FACTOR: f32 = 1.5;

/// Shared inputs for the attestation-submission background tasks
/// ([`periodic_attestation_submission`] and [`monitor_attestation_removal`]).
#[derive(Clone)]
pub struct AttestationSubmitter<C> {
    pub tee_authority: TeeAuthority,
    pub contract_handle: MpcContractHandle<C>,
    pub tls_public_key: Ed25519PublicKey,
    pub account_public_key: Ed25519PublicKey,
    pub allowed_image_hashes: watch::Receiver<Vec<AllowedMpcDockerImageHash>>,
    pub allowed_launcher_compose_hashes: watch::Receiver<Vec<LauncherDockerComposeHash>>,
}

/// Submits a remote attestation transaction to the MPC contract, retrying with backoff until success.
///
/// This function continuously attempts to submit the given participant's attestation and TLS
/// public key through [`MpcContractHandle::submit_participant_info`] and waits until
/// [`TransactionStatus::Executed`] is observed.
pub async fn submit_remote_attestation<C>(
    contract_handle: &MpcContractHandle<C>,
    attestation: Attestation,
    tls_public_key: Ed25519PublicKey,
) -> anyhow::Result<()>
where
    C: CallContract<Output = TransactionStatus>,
    C::Error: std::error::Error + Send + Sync + 'static,
{
    let attestation = attestation.into_contract_interface_type();

    // TODO(#3746): retries the same attestation and errors on timeout, so a late success can store
    // a stale one; #3746 splits this into a submit loop and an outer regenerate loop.
    let set_attestation = || {
        let attestation = attestation.clone();
        let tls_public_key = tls_public_key.clone();

        async move {
            let attestation_submission_response = contract_handle
                .submit_participant_info(attestation, tls_public_key)
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
    allowed_docker_image_hashes: &[NodeImageHash],
    allowed_launcher_compose_hashes: &[LauncherDockerComposeHash],
) -> Result<(), VerificationError> {
    let expected_report_data: ReportData =
        ReportDataV1::new(*tls_public_key.as_bytes(), *account_public_key.as_bytes()).into();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    attestation
        .verify_locally(
            expected_report_data.into(),
            now,
            allowed_docker_image_hashes,
            allowed_launcher_compose_hashes,
            mpc_attestation::attestation::default_measurements(),
        )
        .map(|_| ())
}

pub async fn validate_and_submit_remote_attestation<C>(
    contract_handle: &MpcContractHandle<C>,
    attestation: Attestation,
    tls_public_key: Ed25519PublicKey,
    account_public_key: Ed25519PublicKey,
    allowed_docker_image_hashes: &[NodeImageHash],
    allowed_launcher_compose_hashes: &[LauncherDockerComposeHash],
) -> anyhow::Result<()>
where
    C: CallContract<Output = TransactionStatus>,
    C::Error: std::error::Error + Send + Sync + 'static,
{
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
    submit_remote_attestation(contract_handle, attestation, tls_public_key).await
}

#[tracing::instrument(skip_all)]
pub async fn periodic_attestation_submission<C, I: Tick>(
    submitter: AttestationSubmitter<C>,
    mut interval_ticker: I,
) -> anyhow::Result<()>
where
    C: CallContract<Output = TransactionStatus>,
    C::Error: std::error::Error + Send + Sync + 'static,
{
    let AttestationSubmitter {
        tee_authority,
        contract_handle,
        tls_public_key,
        account_public_key,
        allowed_image_hashes: allowed_image_hashes_in_contract,
        allowed_launcher_compose_hashes: allowed_launcher_compose_hashes_in_contract,
    } = submitter;
    let report_data: ReportData =
        ReportDataV1::new(*tls_public_key.as_bytes(), *account_public_key.as_bytes()).into();

    loop {
        interval_ticker.tick().await;

        let fresh_attestation = match tee_authority
            .generate_attestation(report_data.clone())
            .await
        {
            Ok(att) => {
                crate::metrics::MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL
                    .with_label_values(&[crate::metrics::MPC_TEE_ATTESTATION_OUTCOME_SUCCESS])
                    .inc();
                att
            }
            Err(tee_authority::tee_authority::AttestationError::CollateralFetch(e)) => {
                crate::metrics::MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL
                    .with_label_values(&[crate::metrics::MPC_TEE_ATTESTATION_OUTCOME_FAILURE])
                    .inc();
                tracing::warn!(error = %e, "TEE attestation failed, will retry next interval");
                continue;
            }
            Err(e) => {
                crate::metrics::MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL
                    .with_label_values(&[crate::metrics::MPC_TEE_ATTESTATION_OUTCOME_FAILURE])
                    .inc();
                return Err(anyhow::anyhow!(e).context("TEE attestation failed, cannot continue"));
            }
        };
        let allowed_image_hashes_in_contract: Vec<_> = allowed_image_hashes_in_contract
            .borrow()
            .iter()
            .map(|entry| entry.image_hash)
            .collect();
        let allowed_launcher_compose_hashes_in_contract =
            allowed_launcher_compose_hashes_in_contract.borrow().clone();
        validate_and_submit_remote_attestation(
            &contract_handle,
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
#[tracing::instrument(skip_all)]
pub async fn monitor_attestation_removal<C>(
    submitter: AttestationSubmitter<C>,
    node_account_id: AccountId,
    mut tee_accounts_receiver: watch::Receiver<Vec<NodeId>>,
) -> anyhow::Result<()>
where
    C: CallContract<Output = TransactionStatus>,
    C::Error: std::error::Error + Send + Sync + 'static,
{
    let AttestationSubmitter {
        tee_authority,
        contract_handle,
        tls_public_key,
        account_public_key,
        allowed_image_hashes: allowed_image_hashes_in_contract,
        allowed_launcher_compose_hashes: allowed_launcher_compose_hashes_in_contract,
    } = submitter;
    let node_id = NodeId {
        account_id: node_account_id.clone(),
        tls_public_key: tls_public_key.clone(),
        account_public_key: account_public_key.clone(),
    };

    let initially_available =
        is_node_in_contract_tee_accounts(&mut tee_accounts_receiver, &node_id);

    tracing::info!(
        %node_account_id,
        initially_available,
        "starting TEE attestation removal monitoring; initial TEE attestation status"
    );

    let mut was_available = initially_available;
    let report_data: ReportData =
        ReportDataV1::new(*tls_public_key.as_bytes(), *account_public_key.as_bytes()).into();

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

            let fresh_attestation = match tee_authority
                .generate_attestation(report_data.clone())
                .await
            {
                Ok(att) => {
                    crate::metrics::MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL
                        .with_label_values(&[crate::metrics::MPC_TEE_ATTESTATION_OUTCOME_SUCCESS])
                        .inc();
                    att
                }
                Err(tee_authority::tee_authority::AttestationError::CollateralFetch(e)) => {
                    crate::metrics::MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL
                        .with_label_values(&[crate::metrics::MPC_TEE_ATTESTATION_OUTCOME_FAILURE])
                        .inc();
                    tracing::warn!(
                        error = %e,
                        "TEE attestation failed, periodic attestation task will retry",
                    );
                    was_available = is_available;
                    continue;
                }
                Err(e) => {
                    crate::metrics::MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL
                        .with_label_values(&[crate::metrics::MPC_TEE_ATTESTATION_OUTCOME_FAILURE])
                        .inc();
                    return Err(
                        anyhow::anyhow!(e).context("TEE attestation failed, cannot continue")
                    );
                }
            };
            let allowed_image_hashes_in_contract: Vec<_> = allowed_image_hashes_in_contract
                .borrow()
                .iter()
                .map(|entry| entry.image_hash)
                .collect();
            let allowed_launcher_compose_hashes_in_contract =
                allowed_launcher_compose_hashes_in_contract.borrow().clone();
            validate_and_submit_remote_attestation(
                &contract_handle,
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
    use super::{
        AttestationSubmitter, Duration, Ed25519PublicKey, MpcContractHandle, NodeId, Tick,
        monitor_attestation_removal, periodic_attestation_submission, validate_remote_attestation,
        watch,
    };
    use crate::indexer::tx_sender::{TransactionProcessorError, TransactionStatus};
    use ed25519_dalek::SigningKey;
    use mpc_attestation::report_data::{ReportData, ReportDataV1};
    use mpc_primitives::hash::{LauncherDockerComposeHash, NodeImageHash};
    use near_account_id::AccountId;
    use near_contract_transport::{CallContract, FunctionCallArgs};
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

        fn contract_handle(&self) -> MpcContractHandle<MockSender> {
            MpcContractHandle::new(self.clone(), "contract.test.near".parse().unwrap())
        }
    }

    impl CallContract for MockSender {
        type Output = TransactionStatus;
        type Error = TransactionProcessorError;

        async fn call_contract(
            &self,
            _contract_id: &AccountId,
            _call_args: FunctionCallArgs,
        ) -> Result<TransactionStatus, TransactionProcessorError> {
            *self.submissions.lock().unwrap() += 1;

            // Simulate contract adding the node back to TEE accounts after successful submission
            let updated_tee_accounts = vec![self.contract_simulator.node_id.clone()];
            let _ = self.contract_simulator.sender.send(updated_tee_accounts);

            // Notify that a submission occurred
            self.notify.notify_one();

            Ok(TransactionStatus::Executed)
        }
    }

    #[tokio::test]
    async fn test_periodic_attestation_submission() {
        let tee_authority = TeeAuthority::from(LocalTeeAuthorityConfig::default());

        let (dummy_sender, _) = watch::channel(vec![]);
        let dummy_node_id = NodeId {
            account_id: "dummy.near".parse().unwrap(),
            tls_public_key: Ed25519PublicKey::from([0u8; 32]),
            account_public_key: Ed25519PublicKey::from([0u8; 32]),
        };
        let sender = MockSender::new(dummy_sender, dummy_node_id);
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let tls_key = (&SigningKey::generate(&mut rng).verifying_key()).into();
        let account_key = (&SigningKey::generate(&mut rng).verifying_key()).into();
        let (_, allowed_image_hashes_receiver) = watch::channel(vec![]);
        let (_, allowed_launcher_compose_hashes_receiver) = watch::channel(vec![]);
        let submitter = AttestationSubmitter {
            tee_authority,
            contract_handle: sender.contract_handle(),
            tls_public_key: tls_key,
            account_public_key: account_key,
            allowed_image_hashes: allowed_image_hashes_receiver,
            allowed_launcher_compose_hashes: allowed_launcher_compose_hashes_receiver,
        };
        let handle = tokio::spawn(periodic_attestation_submission(
            submitter,
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
        let tls_public_key: Ed25519PublicKey =
            (&SigningKey::generate(&mut rng).verifying_key()).into();
        let account_public_key: Ed25519PublicKey =
            (&SigningKey::generate(&mut rng).verifying_key()).into();
        let tee_authority = TeeAuthority::from(LocalTeeAuthorityConfig::default());

        let node_id = NodeId {
            account_id: node_account_id.clone(),
            tls_public_key: tls_public_key.clone(),
            account_public_key: account_public_key.clone(),
        };

        // Create initial TEE accounts list including our node
        let initial_tee_accounts = vec![node_id.clone()];
        let (tee_accounts_sender, receiver) = watch::channel(initial_tee_accounts);
        let (_, allowed_image_hashes_receiver) = watch::channel(vec![]);
        let (_, allowed_launcher_compose_hashes_receiver) = watch::channel(vec![]);

        // Create mock sender with contract simulator built-in
        let mock_sender = MockSender::new(tee_accounts_sender.clone(), node_id.clone());

        let submitter = AttestationSubmitter {
            tee_authority,
            contract_handle: mock_sender.contract_handle(),
            tls_public_key,
            account_public_key,
            allowed_image_hashes: allowed_image_hashes_receiver,
            allowed_launcher_compose_hashes: allowed_launcher_compose_hashes_receiver,
        };
        let monitoring_task = tokio::spawn(monitor_attestation_removal(
            submitter,
            node_account_id.clone(),
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
        let tls_public_key: Ed25519PublicKey =
            (&SigningKey::generate(&mut rng).verifying_key()).into();
        let account_public_key: Ed25519PublicKey =
            (&SigningKey::generate(&mut rng).verifying_key()).into();
        let tee_authority = TeeAuthority::from(LocalTeeAuthorityConfig::default());
        let report_data: ReportData =
            ReportDataV1::new(*tls_public_key.as_bytes(), *account_public_key.as_bytes()).into();
        let attestation = tee_authority
            .generate_attestation(report_data)
            .await
            .unwrap();
        let allowed_docker_image_hashes = [NodeImageHash::from([42u8; 32])];
        let allowed_launcher_compose_hashes = [LauncherDockerComposeHash::from([42u8; 32])];
        validate_remote_attestation(
            &attestation,
            tls_public_key,
            account_public_key,
            &allowed_docker_image_hashes,
            &allowed_launcher_compose_hashes,
        )
        .expect("Valid attestation should pass validation");
    }

    #[tokio::test]
    async fn test_validate_remote_attestation_invalid() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let tls_public_key: Ed25519PublicKey =
            (&SigningKey::generate(&mut rng).verifying_key()).into();
        let account_public_key: Ed25519PublicKey =
            (&SigningKey::generate(&mut rng).verifying_key()).into();
        let tee_authority = TeeAuthority::from(LocalTeeAuthorityConfig::new(false));
        let report_data: ReportData =
            ReportDataV1::new(*tls_public_key.as_bytes(), *account_public_key.as_bytes()).into();
        let attestation = tee_authority
            .generate_attestation(report_data)
            .await
            .unwrap();
        let allowed_docker_image_hashes = [NodeImageHash::from([42u8; 32])];
        let allowed_launcher_compose_hashes = [LauncherDockerComposeHash::from([42u8; 32])];
        assert!(
            validate_remote_attestation(
                &attestation,
                tls_public_key,
                account_public_key,
                &allowed_docker_image_hashes,
                &allowed_launcher_compose_hashes
            )
            .is_err()
        );
    }
}
