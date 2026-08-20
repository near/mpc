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

impl<T: TransactionSender + Clone> AttestationSubmitter<T> {
    /// Generates a fresh attestation and submits it to the contract. Failures are logged,
    /// never fatal; the caller decides when to try again.
    async fn generate_and_submit(&self) {
        let report_data: ReportData = ReportDataV1::new(
            *self.tls_public_key.as_bytes(),
            *self.account_public_key.as_bytes(),
        )
        .into();
        let attestation = match self.tee_authority.generate_attestation(report_data).await {
            Ok(attestation) => {
                crate::metrics::MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL
                    .with_label_values(&[crate::metrics::MPC_TEE_ATTESTATION_OUTCOME_SUCCESS])
                    .inc();
                attestation
            }
            Err(error) => {
                crate::metrics::MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL
                    .with_label_values(&[crate::metrics::MPC_TEE_ATTESTATION_OUTCOME_FAILURE])
                    .inc();
                tracing::error!(%error, "TEE attestation generation failed");
                return;
            }
        };
        let allowed_image_hashes: Vec<_> = self
            .allowed_image_hashes
            .borrow()
            .iter()
            .map(|entry| entry.image_hash)
            .collect();
        let allowed_launcher_compose_hashes = self.allowed_launcher_compose_hashes.borrow().clone();
        let pre_submit_expiry = match self
            .attestation_reader
            .read_stored_attestation_expiry(&self.tls_public_key)
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
        if let Err(error) = validate_remote_attestation(
            &attestation,
            self.tls_public_key.clone(),
            self.account_public_key.clone(),
            &allowed_image_hashes,
            &allowed_launcher_compose_hashes,
        ) {
            // Non-blocking pre-flight check; its exact output is documented in the external
            // node-operator guide, so keep the message format stable.
            tracing::warn!("Attestation is not valid: {error}");
        }
        if let Err(error) = submit_remote_attestation(
            self.tx_sender.clone(),
            attestation,
            self.tls_public_key.clone(),
            pre_submit_expiry,
        )
        .await
        {
            tracing::error!(
                %error,
                "attestation submission failed; will retry with a fresh attestation on the next trigger"
            );
        }
    }
}

/// Periodically regenerates and submits this node's attestation. Generation and submission
/// failures are logged and retried on the next tick; this task never returns.
#[tracing::instrument(skip_all)]
pub async fn periodic_attestation_submission<T: TransactionSender + Clone, I: Tick>(
    submitter: AttestationSubmitter<T>,
    mut interval_ticker: I,
) {
    loop {
        interval_ticker.tick().await;
        submitter.generate_and_submit().await;
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
    let node_id = NodeId {
        account_id: node_account_id.clone(),
        tls_public_key: submitter.tls_public_key.clone(),
        account_public_key: submitter.account_public_key.clone(),
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
            submitter.generate_and_submit().await;
        }

        was_available = is_available;
    }

    tracing::warn!("TEE accounts watch channel closed; stopping attestation removal monitoring");
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
    const TEST_RESUBMISSION_WAIT: Duration = Duration::from_millis(100);

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

    struct FakeAttestationExpiryReader {
        fail: bool,
    }

    impl crate::indexer::ReadAttestationExpiry for FakeAttestationExpiryReader {
        fn read_stored_attestation_expiry<'a>(
            &'a self,
            _tls_public_key: &'a Ed25519PublicKey,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = anyhow::Result<Option<u64>>> + Send + 'a>,
        > {
            Box::pin(async {
                if self.fail {
                    Err(anyhow::anyhow!("simulated baseline read failure"))
                } else {
                    Ok(None)
                }
            })
        }
    }

    /// Mock that tracks successful attestation submissions and mimics the contract by adding
    /// the node back to TEE accounts on each one.
    #[derive(Clone)]
    struct MockSender {
        submissions: Arc<Mutex<usize>>,
        tee_accounts_sender: Arc<watch::Sender<Vec<NodeId>>>,
        node_id: NodeId,
        notify: Arc<tokio::sync::Notify>,
        failing: Arc<AtomicBool>,
    }

    impl MockSender {
        fn new(tee_accounts_sender: watch::Sender<Vec<NodeId>>, node_id: NodeId) -> Self {
            Self {
                submissions: Arc::new(Mutex::new(0)),
                tee_accounts_sender: Arc::new(tee_accounts_sender),
                node_id,
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
            let _ = self.tee_accounts_sender.send(vec![self.node_id.clone()]);

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

    fn test_keys() -> (Ed25519PublicKey, Ed25519PublicKey) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        (
            (&SigningKey::generate(&mut rng).verifying_key()).into(),
            (&SigningKey::generate(&mut rng).verifying_key()).into(),
        )
    }

    struct TestSetup {
        node_id: NodeId,
        tee_accounts_sender: watch::Sender<Vec<NodeId>>,
        tee_accounts_receiver: watch::Receiver<Vec<NodeId>>,
        sender: MockSender,
        submitter: AttestationSubmitter<MockSender>,
    }

    /// Builds an [`AttestationSubmitter`] around a [`MockSender`], with the node initially
    /// present in the TEE accounts watch channel.
    fn test_setup() -> TestSetup {
        let (tls_public_key, account_public_key) = test_keys();
        let node_id = NodeId {
            account_id: "test_node.near".parse().unwrap(),
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
            attestation_reader: Arc::new(FakeAttestationExpiryReader { fail: false }),
        };
        TestSetup {
            node_id,
            tee_accounts_sender,
            tee_accounts_receiver,
            sender,
            submitter,
        }
    }

    impl TestSetup {
        fn spawn_periodic(&self, ticks: usize) -> tokio::task::JoinHandle<()> {
            tokio::spawn(periodic_attestation_submission(
                self.submitter.clone(),
                MockTicker::new(ticks),
            ))
        }

        fn spawn_monitor(&self) -> tokio::task::JoinHandle<()> {
            tokio::spawn(monitor_attestation_removal(
                self.submitter.clone(),
                self.node_id.account_id.clone(),
                self.tee_accounts_receiver.clone(),
            ))
        }

        fn remove_node_from_tee_accounts(&self) {
            self.tee_accounts_sender.send(vec![]).unwrap();
        }

        fn restore_node_to_tee_accounts(&self) {
            self.tee_accounts_sender
                .send(vec![self.node_id.clone()])
                .unwrap();
        }
    }

    #[tokio::test]
    #[expect(non_snake_case)]
    async fn periodic_attestation_submission__should_submit_on_each_tick() {
        // Given
        let setup = test_setup();
        let handle = setup.spawn_periodic(TEST_SUBMISSION_COUNT);

        // When
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Then
        assert_eq!(setup.sender.count(), TEST_SUBMISSION_COUNT);
        handle.abort();
    }

    #[tokio::test]
    #[expect(non_snake_case)]
    async fn periodic_attestation_submission__should_submit_when_baseline_read_fails() {
        // Given: a failing pre-submit baseline read must not block submission (the node would
        // otherwise let its attestation lapse); submissions still happen, just without a baseline.
        let mut setup = test_setup();
        setup.submitter.attestation_reader = Arc::new(FakeAttestationExpiryReader { fail: true });
        let handle = setup.spawn_periodic(TEST_SUBMISSION_COUNT);

        // When
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Then
        assert_eq!(setup.sender.count(), TEST_SUBMISSION_COUNT);
        handle.abort();
    }

    #[tokio::test]
    #[expect(non_snake_case)]
    async fn monitor_attestation_removal__should_resubmit_when_attestation_removed() {
        // Given
        let setup = test_setup();
        let monitoring_task = setup.spawn_monitor();

        // Yield control to allow the monitoring task to start and process initial state.
        // This is preferred over sleep() as it doesn't introduce arbitrary timing delays
        tokio::task::yield_now().await;
        assert_eq!(setup.sender.count(), 0);

        // When
        setup.remove_node_from_tee_accounts();

        // Then
        tokio::time::timeout(TEST_RESUBMISSION_WAIT, setup.sender.wait_for_submission())
            .await
            .expect("Expected resubmission to occur within timeout");
        assert_eq!(
            setup.sender.count(),
            1,
            "Expected exactly one resubmission when node was removed"
        );

        // A removal after the monitor stops must no longer trigger a resubmission
        monitoring_task.abort();
        let _ = monitoring_task.await;
        assert_eq!(
            setup.sender.count(),
            1,
            "Expected submission count to remain stable after stopping monitoring service"
        );
        setup.remove_node_from_tee_accounts();
        let timeout_result =
            tokio::time::timeout(TEST_RESUBMISSION_WAIT, setup.sender.wait_for_submission()).await;
        assert!(
            timeout_result.is_err(),
            "Expected no resubmission when monitoring service is stopped"
        );
        assert_eq!(
            setup.sender.count(),
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
        let handle = setup.spawn_periodic(2);

        // When
        tokio::time::sleep(MAX_RETRY_DURATION + Duration::from_secs(1)).await;
        assert_eq!(setup.sender.count(), 0);
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
        let handle = setup.spawn_monitor();
        tokio::task::yield_now().await;

        // When
        setup.remove_node_from_tee_accounts();
        tokio::time::sleep(MAX_RETRY_DURATION + Duration::from_secs(1)).await;
        assert_eq!(setup.sender.count(), 0);
        setup.sender.set_failing(false);
        setup.restore_node_to_tee_accounts();
        // Yield so the monitor observes the restore before the watch channel coalesces it
        // with the next removal.
        tokio::task::yield_now().await;
        setup.remove_node_from_tee_accounts();

        // Then
        tokio::time::timeout(MAX_RETRY_DURATION, setup.sender.wait_for_submission())
            .await
            .expect("expected a successful resubmission after the first retry window timed out");
        assert_eq!(setup.sender.count(), 1);
        assert!(!handle.is_finished());
        handle.abort();
    }

    async fn validate_locally_generated_attestation(
        config: LocalTeeAuthorityConfig,
    ) -> Result<(), VerificationError> {
        let (tls_public_key, account_public_key) = test_keys();
        let report_data: ReportData =
            ReportDataV1::new(*tls_public_key.as_bytes(), *account_public_key.as_bytes()).into();
        let attestation = TeeAuthority::from(config)
            .generate_attestation(report_data)
            .await
            .unwrap();
        validate_remote_attestation(
            &attestation,
            tls_public_key,
            account_public_key,
            &[NodeImageHash::from([42u8; 32])],
            &[LauncherDockerComposeHash::from([42u8; 32])],
        )
    }

    #[tokio::test]
    async fn test_validate_remote_attestation_valid() {
        // Given / When
        let result =
            validate_locally_generated_attestation(LocalTeeAuthorityConfig::default()).await;

        // Then
        result.expect("Valid attestation should pass validation");
    }

    #[tokio::test]
    async fn test_validate_remote_attestation_invalid() {
        // Given / When
        let result =
            validate_locally_generated_attestation(LocalTeeAuthorityConfig::new(false)).await;

        // Then
        assert!(result.is_err());
    }
}
