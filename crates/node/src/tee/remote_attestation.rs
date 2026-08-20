use std::time::Duration;

use crate::{
    indexer::{
        tx_sender::{TransactionSender, TransactionStatus},
        types::ChainSendTransactionRequest,
    },
    trait_extensions::convert_to_contract_dto::IntoContractInterfaceType,
};
use anyhow::Context;
use backon::{BackoffBuilder, ExponentialBuilder, Retryable};
use mpc_attestation::{
    attestation::{Attestation, VerificationError},
    report_data::{ReportData, ReportDataV1},
};
use near_mpc_contract_interface::types::{AllowedMpcDockerImageHash, Ed25519PublicKey};
use tee_authority::tee_authority::TeeAuthority;
use tokio_util::time::FutureExt;

use mpc_primitives::hash::{LauncherDockerComposeHash, NodeImageHash};
use near_account_id::AccountId;
use near_mpc_contract_interface::call_args as contract_args;
use near_mpc_contract_interface::types::NodeId;
use tokio::sync::watch;

const MIN_BACKOFF_DURATION: Duration = Duration::from_millis(100);
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);
const MAX_RETRY_DURATION: Duration = Duration::from_secs(60 * 60 * 12); // 12 hours.
const BACKOFF_FACTOR: f32 = 1.5;

/// Shared inputs for the attestation-submission background tasks
/// ([`periodic_attestation_submission`] and [`monitor_attestation_removal`]).
#[derive(Clone)]
pub struct AttestationSubmitter<T> {
    pub tee_authority: TeeAuthority,
    pub tx_sender: T,
    pub tls_public_key: Ed25519PublicKey,
    pub account_public_key: Ed25519PublicKey,
    pub allowed_image_hashes: watch::Receiver<Vec<AllowedMpcDockerImageHash>>,
    pub allowed_launcher_compose_hashes: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    pub attestation_reader: std::sync::Arc<dyn crate::indexer::ReadAttestationExpiry>,
}

/// Submits a remote attestation transaction to the MPC contract, retrying with backoff until
/// success or until a fixed retry window elapses, whichever comes first.
///
/// This function repeatedly attempts to submit a [`contract_args::SubmitParticipantInfoArgs`] transaction containing
/// the given participant's attestation and TLS public key. It uses the provided
/// [`TransactionSender`] to send the transaction and waits until [`TransactionStatus::Executed`]
/// is observed. Returns an error if no attempt succeeds within the retry window.
pub async fn submit_remote_attestation(
    tx_sender: impl TransactionSender,
    attestation: Attestation,
    tls_public_key: Ed25519PublicKey,
    pre_submit_expiry: Option<u64>,
) -> anyhow::Result<()> {
    let submit_participant_info_args = contract_args::SubmitParticipantInfoArgs::new(
        attestation.into_contract_interface_type(),
        tls_public_key,
    );

    // TODO(#3746): retries the same attestation and errors on timeout, so a late success can store
    // a stale one; #3746 splits this into a submit loop and an outer regenerate loop.
    let set_attestation = move || {
        let tx_sender = tx_sender.clone();
        let propose_join_args_clone = submit_participant_info_args.clone();
        let chain_args = ChainSendTransactionRequest::SubmitParticipantInfo {
            args: Box::new(propose_join_args_clone),
            pre_submit_expiry,
        };

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

pub async fn validate_and_submit_remote_attestation(
    tx_sender: impl TransactionSender,
    attestation: Attestation,
    tls_public_key: Ed25519PublicKey,
    account_public_key: Ed25519PublicKey,
    allowed_docker_image_hashes: &[NodeImageHash],
    allowed_launcher_compose_hashes: &[LauncherDockerComposeHash],
    pre_submit_expiry: Option<u64>,
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
    submit_remote_attestation(tx_sender, attestation, tls_public_key, pre_submit_expiry).await
}

/// Periodically regenerates and submits this node's attestation. Generation and submission
/// failures are logged and retried on the next tick; this task never returns.
#[tracing::instrument(skip_all)]
pub async fn periodic_attestation_submission<T: TransactionSender + Clone, I: Tick>(
    submitter: AttestationSubmitter<T>,
    mut interval_ticker: I,
) {
    let AttestationSubmitter {
        tee_authority,
        tx_sender,
        tls_public_key,
        account_public_key,
        allowed_image_hashes: allowed_image_hashes_in_contract,
        allowed_launcher_compose_hashes: allowed_launcher_compose_hashes_in_contract,
        attestation_reader,
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
            Err(e) => {
                crate::metrics::MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL
                    .with_label_values(&[crate::metrics::MPC_TEE_ATTESTATION_OUTCOME_FAILURE])
                    .inc();
                tracing::warn!(error = %e, "TEE attestation failed, will retry next interval");
                continue;
            }
        };
        let allowed_image_hashes_in_contract: Vec<_> = allowed_image_hashes_in_contract
            .borrow()
            .iter()
            .map(|entry| entry.image_hash)
            .collect();
        let allowed_launcher_compose_hashes_in_contract =
            allowed_launcher_compose_hashes_in_contract.borrow().clone();
        let pre_submit_expiry = match attestation_reader
            .read_stored_attestation_expiry(&tls_public_key)
            .await
        {
            Ok(baseline) => baseline, // None just means nothing stored yet (e.g. first submit)
            // Submit anyway on a read error: refreshing the attestation is the priority, and a
            // broken read must not block submission (the confirmation just can't use a baseline).
            Err(error) => {
                tracing::warn!(%error, "could not read pre-submit attestation baseline; submitting without it");
                None
            }
        };
        if let Err(error) = validate_and_submit_remote_attestation(
            tx_sender.clone(),
            fresh_attestation.clone(),
            tls_public_key.clone(),
            account_public_key.clone(),
            &allowed_image_hashes_in_contract,
            &allowed_launcher_compose_hashes_in_contract,
            pre_submit_expiry,
        )
        .await
        {
            tracing::error!(
                error = %error,
                "attestation submission failed; will retry with a fresh attestation next interval"
            );
        }
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
/// the node's TEE attestation is no longer available. Failures are logged and never fatal;
/// this task returns only when the TEE-accounts watch channel closes.
#[tracing::instrument(skip_all)]
pub async fn monitor_attestation_removal<T: TransactionSender + Clone>(
    submitter: AttestationSubmitter<T>,
    node_account_id: AccountId,
    mut tee_accounts_receiver: watch::Receiver<Vec<NodeId>>,
) {
    let AttestationSubmitter {
        tee_authority,
        tx_sender,
        tls_public_key,
        account_public_key,
        allowed_image_hashes: allowed_image_hashes_in_contract,
        allowed_launcher_compose_hashes: allowed_launcher_compose_hashes_in_contract,
        attestation_reader,
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
                Err(e) => {
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
            };
            let allowed_image_hashes_in_contract: Vec<_> = allowed_image_hashes_in_contract
                .borrow()
                .iter()
                .map(|entry| entry.image_hash)
                .collect();
            let allowed_launcher_compose_hashes_in_contract =
                allowed_launcher_compose_hashes_in_contract.borrow().clone();
            let pre_submit_expiry = match attestation_reader
                .read_stored_attestation_expiry(&tls_public_key)
                .await
            {
                Ok(baseline) => baseline, // None just means nothing stored yet (e.g. first submit)
                // Submit anyway on a read error: re-submitting a removed attestation is the
                // priority, and a broken read must not block it (confirmation just lacks a baseline).
                Err(error) => {
                    tracing::warn!(%error, "could not read pre-submit attestation baseline; submitting without it");
                    None
                }
            };
            if let Err(error) = validate_and_submit_remote_attestation(
                tx_sender.clone(),
                fresh_attestation.clone(),
                tls_public_key.clone(),
                account_public_key.clone(),
                &allowed_image_hashes_in_contract,
                &allowed_launcher_compose_hashes_in_contract,
                pre_submit_expiry,
            )
            .await
            {
                tracing::error!(
                    error = %error,
                    "attestation resubmission failed; the periodic attestation task will retry"
                );
            }
        }

        was_available = is_available;
    }
}

/// Allows repeatedly awaiting for something, like a [`tokio::time::Interval`].
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
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
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

    struct StubAttestationExpiryReader;

    impl crate::indexer::ReadAttestationExpiry for StubAttestationExpiryReader {
        fn read_stored_attestation_expiry<'a>(
            &'a self,
            _tls_public_key: &'a Ed25519PublicKey,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = anyhow::Result<Option<u64>>> + Send + 'a>,
        > {
            Box::pin(async { Ok(None) })
        }
    }

    struct FailingAttestationExpiryReader;

    impl crate::indexer::ReadAttestationExpiry for FailingAttestationExpiryReader {
        fn read_stored_attestation_expiry<'a>(
            &'a self,
            _tls_public_key: &'a Ed25519PublicKey,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = anyhow::Result<Option<u64>>> + Send + 'a>,
        > {
            Box::pin(async { Err(anyhow::anyhow!("simulated baseline read failure")) })
        }
    }

    /// Simulates contract behavior by automatically adding the node back to TEE accounts
    /// when an attestation submission occurs, mimicking real contract response to successful submissions.
    struct ContractSimulator {
        sender: watch::Sender<Vec<NodeId>>,
        node_id: NodeId,
    }

    /// Mock that tracks successful attestation submissions and simulates contract responses.
    #[derive(Clone)]
    struct MockSender {
        submissions: Arc<Mutex<usize>>,
        contract_simulator: Arc<ContractSimulator>,
        notify: Arc<tokio::sync::Notify>,
        failing: Arc<AtomicBool>,
    }

    impl MockSender {
        fn new(sender: watch::Sender<Vec<NodeId>>, node_id: NodeId) -> Self {
            Self {
                submissions: Arc::new(Mutex::new(0)),
                contract_simulator: Arc::new(ContractSimulator { sender, node_id }),
                notify: Arc::new(tokio::sync::Notify::new()),
                failing: Arc::new(AtomicBool::new(false)),
            }
        }

        fn set_failing(&self, failing: bool) {
            self.failing.store(failing, Ordering::Relaxed);
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
            if self.failing.load(Ordering::Relaxed) {
                return Err(TransactionProcessorError::ProcessorIsClosed);
            }

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

    struct TestSetup {
        node_account_id: AccountId,
        node_id: NodeId,
        tee_accounts_sender: watch::Sender<Vec<NodeId>>,
        tee_accounts_receiver: watch::Receiver<Vec<NodeId>>,
        sender: MockSender,
        submitter: AttestationSubmitter<MockSender>,
    }

    /// Builds an [`AttestationSubmitter`] around a [`MockSender`], with the node initially
    /// present in the TEE accounts watch channel.
    fn test_setup() -> TestSetup {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let tls_public_key: Ed25519PublicKey =
            (&SigningKey::generate(&mut rng).verifying_key()).into();
        let account_public_key: Ed25519PublicKey =
            (&SigningKey::generate(&mut rng).verifying_key()).into();
        let node_account_id: AccountId = "test_node.near".parse().unwrap();
        let node_id = NodeId {
            account_id: node_account_id.clone(),
            tls_public_key: tls_public_key.clone(),
            account_public_key: account_public_key.clone(),
        };
        let (tee_accounts_sender, tee_accounts_receiver) = watch::channel(vec![node_id.clone()]);
        let (_, allowed_image_hashes) = watch::channel(vec![]);
        let (_, allowed_launcher_compose_hashes) = watch::channel(vec![]);
        let sender = MockSender::new(tee_accounts_sender.clone(), node_id.clone());
        let submitter = AttestationSubmitter {
            tee_authority: TeeAuthority::from(LocalTeeAuthorityConfig::default()),
            tx_sender: sender.clone(),
            tls_public_key,
            account_public_key,
            allowed_image_hashes,
            allowed_launcher_compose_hashes,
            attestation_reader: Arc::new(StubAttestationExpiryReader),
        };
        TestSetup {
            node_account_id,
            node_id,
            tee_accounts_sender,
            tee_accounts_receiver,
            sender,
            submitter,
        }
    }

    #[tokio::test]
    async fn test_periodic_attestation_submission() {
        let setup = test_setup();
        let handle = tokio::spawn(periodic_attestation_submission(
            setup.submitter,
            MockTicker::new(TEST_SUBMISSION_COUNT),
        ));

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(setup.sender.count(), TEST_SUBMISSION_COUNT);
        handle.abort();
    }

    #[tokio::test]
    #[expect(non_snake_case)]
    async fn periodic_attestation_submission__should_submit_when_baseline_read_fails() {
        // A failing pre-submit baseline read must not block submission (the node would otherwise
        // let its attestation lapse); submissions still happen, just without a baseline.
        let mut setup = test_setup();
        setup.submitter.attestation_reader = Arc::new(FailingAttestationExpiryReader);
        let handle = tokio::spawn(periodic_attestation_submission(
            setup.submitter,
            MockTicker::new(TEST_SUBMISSION_COUNT),
        ));

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(setup.sender.count(), TEST_SUBMISSION_COUNT);
        handle.abort();
    }

    #[tokio::test]
    async fn test_tee_attestation_removal_detection() {
        let setup = test_setup();
        let tee_accounts_sender = setup.tee_accounts_sender;
        let mock_sender = setup.sender;
        let monitoring_task = tokio::spawn(monitor_attestation_removal(
            setup.submitter,
            setup.node_account_id,
            setup.tee_accounts_receiver,
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

    #[tokio::test(start_paused = true)]
    #[expect(non_snake_case)]
    async fn periodic_attestation_submission__should_survive_submission_retry_timeout() {
        // Given
        let setup = test_setup();
        setup.sender.set_failing(true);
        let handle = tokio::spawn(periodic_attestation_submission(
            setup.submitter,
            MockTicker::new(2),
        ));

        // When
        tokio::time::sleep(MAX_RETRY_DURATION + Duration::from_secs(1)).await;
        setup.sender.set_failing(false);

        // Then
        tokio::time::timeout(MAX_RETRY_DURATION, setup.sender.wait_for_submission())
            .await
            .expect("expected a successful submission after the first retry window timed out");
        assert_eq!(setup.sender.count(), 1);
        assert!(!handle.is_finished());
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    #[expect(non_snake_case)]
    async fn monitor_attestation_removal__should_survive_submission_retry_timeout() {
        // Given
        let setup = test_setup();
        setup.sender.set_failing(true);
        let handle = tokio::spawn(monitor_attestation_removal(
            setup.submitter,
            setup.node_account_id.clone(),
            setup.tee_accounts_receiver,
        ));
        // Under the paused clock each sleep is a barrier: it completes only once the monitor
        // has processed the previous watch update and is idle again.
        tokio::time::sleep(Duration::from_millis(1)).await;

        // When
        setup.tee_accounts_sender.send(vec![]).unwrap();
        tokio::time::sleep(MAX_RETRY_DURATION + Duration::from_secs(1)).await;
        setup.sender.set_failing(false);
        setup
            .tee_accounts_sender
            .send(vec![setup.node_id.clone()])
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1)).await;
        setup.tee_accounts_sender.send(vec![]).unwrap();

        // Then
        tokio::time::timeout(MAX_RETRY_DURATION, setup.sender.wait_for_submission())
            .await
            .expect("expected a successful resubmission after the first retry window timed out");
        assert_eq!(setup.sender.count(), 1);
        assert!(!handle.is_finished());
        handle.abort();
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
