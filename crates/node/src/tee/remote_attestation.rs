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
use tee_authority::tee_authority::{AttestationError, TeeAuthority};
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
const RESUBMISSION_RETRY_DELAY: Duration = Duration::from_secs(60 * 10); // 10 minutes.

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
    /// Generates a fresh attestation and submits it to the contract, reporting whether it
    /// reached the contract so the caller can decide when to try again. Failures are logged,
    /// never propagated.
    async fn generate_and_submit(&self) -> bool {
        let report_data: ReportData = ReportDataV1::new(
            *self.tls_public_key.as_bytes(),
            *self.account_public_key.as_bytes(),
        )
        .into();
        let result = self.tee_authority.generate_attestation(report_data).await;
        crate::metrics::MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL
            .with_label_values(&[outcome_label(result.is_ok())])
            .inc();
        let attestation = match result {
            Ok(attestation) => attestation,
            Err(error @ AttestationError::CollateralFetch(_)) => {
                tracing::warn!(%error, "TEE attestation generation failed");
                return false;
            }
            Err(error) => {
                tracing::error!(%error, "TEE attestation generation failed");
                return false;
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
                tracing::warn!(
                    ?error,
                    "could not read pre-submit attestation baseline; submitting without it"
                );
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
            // Submit anyway: the contract runs the authoritative check, and this local one can
            // fail on a stale view of the allowed hashes. Operators are told to grep for this
            // exact message, so keep it stable
            tracing::warn!("Attestation is not valid: {error}");
        }
        let submission = submit_remote_attestation(
            self.tx_sender.clone(),
            attestation,
            self.tls_public_key.clone(),
            pre_submit_expiry,
        )
        .await;
        crate::metrics::MPC_TEE_ATTESTATION_SUBMISSIONS_TOTAL
            .with_label_values(&[outcome_label(submission.is_ok())])
            .inc();
        if let Err(error) = submission {
            tracing::error!(?error, "attestation submission failed");
            return false;
        }
        true
    }
}

fn outcome_label(succeeded: bool) -> &'static str {
    if succeeded {
        crate::metrics::MPC_TEE_ATTESTATION_OUTCOME_SUCCESS
    } else {
        crate::metrics::MPC_TEE_ATTESTATION_OUTCOME_FAILURE
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
/// the node's TEE attestation is no longer available. A failed resubmission is retried after
/// a fixed delay, or sooner on the next TEE-accounts update; this task returns only when the
/// watch channel closes.
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

    let mut was_available = is_node_in_contract_tee_accounts(&mut tee_accounts_receiver, &node_id);

    tracing::info!(
        %node_account_id,
        initially_available = was_available,
        "starting TEE attestation removal monitoring; initial TEE attestation status"
    );

    'watch: while tee_accounts_receiver.changed().await.is_ok() {
        let mut is_available =
            is_node_in_contract_tee_accounts(&mut tee_accounts_receiver, &node_id);

        tracing::debug!(
            %node_account_id,
            is_available,
            was_available,
            "TEE attestation status check"
        );

        while was_available && !is_available {
            tracing::warn!(
                %node_account_id,
                "TEE attestation removed from contract, resubmitting"
            );
            if submitter.generate_and_submit().await {
                break;
            }
            // Treat the removal as unhandled and retry after a delay: the watch fires only on
            // actual changes to the attested-nodes list, which a quiet network may never
            // produce again
            match tee_accounts_receiver
                .changed()
                .timeout(RESUBMISSION_RETRY_DELAY)
                .await
            {
                Ok(Err(_)) => break 'watch,
                // An update arrived, or the retry delay elapsed
                Ok(Ok(())) | Err(_) => {
                    is_available =
                        is_node_in_contract_tee_accounts(&mut tee_accounts_receiver, &node_id)
                }
            }
        }

        was_available = is_available;
    }

    tracing::info!("TEE accounts watch channel closed; stopping attestation removal monitoring");
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

    struct StubAttestationExpiryReader {
        fail: bool,
    }

    impl crate::indexer::ReadAttestationExpiry for StubAttestationExpiryReader {
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

    #[derive(Clone, Default)]
    struct MockSender {
        submissions: Arc<Mutex<usize>>,
        notify: Arc<tokio::sync::Notify>,
        failing: Arc<AtomicBool>,
    }

    impl MockSender {
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
        let (tee_accounts_sender, _) = watch::channel(vec![node_id.clone()]);
        let (_, allowed_image_hashes) = watch::channel(vec![]);
        let (_, allowed_launcher_compose_hashes) = watch::channel(vec![]);
        let submitter = AttestationSubmitter {
            tee_authority: TeeAuthority::from(LocalTeeAuthorityConfig::default()),
            tx_sender: MockSender::default(),
            tls_public_key,
            account_public_key,
            allowed_image_hashes,
            allowed_launcher_compose_hashes,
            attestation_reader: Arc::new(StubAttestationExpiryReader { fail: false }),
        };
        TestSetup {
            node_id,
            tee_accounts_sender,
            submitter,
        }
    }

    impl TestSetup {
        fn sender(&self) -> &MockSender {
            &self.submitter.tx_sender
        }

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
                self.tee_accounts_sender.subscribe(),
            ))
        }

        fn remove_node_from_tee_accounts(&self) {
            self.tee_accounts_sender.send_replace(vec![]);
        }

        fn add_node_to_tee_accounts(&self) {
            self.tee_accounts_sender
                .send_replace(vec![self.node_id.clone()]);
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
        assert_eq!(setup.sender().count(), TEST_SUBMISSION_COUNT);
        handle.abort();
    }

    #[tokio::test]
    #[expect(non_snake_case)]
    async fn periodic_attestation_submission__should_submit_when_baseline_read_fails() {
        // Given: reading the stored attestation's expiry (used only to confirm the submission
        // landed) fails; the submission must still go out, otherwise a broken read path would
        // stop the node from refreshing its attestation until the contract evicts it
        let mut setup = test_setup();
        setup.submitter.attestation_reader = Arc::new(StubAttestationExpiryReader { fail: true });
        let handle = setup.spawn_periodic(TEST_SUBMISSION_COUNT);

        // When
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Then
        assert_eq!(setup.sender().count(), TEST_SUBMISSION_COUNT);
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    #[expect(non_snake_case)]
    async fn monitor_attestation_removal__should_resubmit_when_attestation_removed() {
        // Given
        let setup = test_setup();
        let handle = setup.spawn_monitor();
        tokio::task::yield_now().await;
        assert_eq!(setup.sender().count(), 0);

        // When
        setup.remove_node_from_tee_accounts();

        // Then
        tokio::time::timeout(TEST_RESUBMISSION_WAIT, setup.sender().wait_for_submission())
            .await
            .expect("expected a resubmission after the removal");
        assert_eq!(setup.sender().count(), 1);
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    #[expect(non_snake_case)]
    async fn periodic_attestation_submission__should_survive_submission_retry_timeout() {
        // Given: the first tick burns the whole retry window, the second one lands
        let setup = test_setup();
        setup.sender().set_failing(true);
        let handle = setup.spawn_periodic(2);

        // When
        tokio::time::sleep(MAX_RETRY_DURATION + Duration::from_secs(1)).await;
        setup.sender().set_failing(false);

        // Then
        tokio::time::timeout(MAX_RETRY_DURATION, setup.sender().wait_for_submission())
            .await
            .expect("expected a successful submission after the first retry window timed out");
        assert_eq!(setup.sender().count(), 1);
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    #[expect(non_snake_case)]
    async fn monitor_attestation_removal__should_retry_failed_resubmission_without_further_updates()
    {
        // Given: the node is removed and the resubmission burns its whole retry window
        let setup = test_setup();
        setup.sender().set_failing(true);
        let handle = setup.spawn_monitor();
        tokio::task::yield_now().await;
        setup.remove_node_from_tee_accounts();
        tokio::time::sleep(MAX_RETRY_DURATION + Duration::from_secs(1)).await;

        // When: the submission starts succeeding, with no further TEE-accounts updates
        setup.sender().set_failing(false);

        // Then: the monitor retries on its own delay
        tokio::time::timeout(
            RESUBMISSION_RETRY_DELAY + Duration::from_secs(1),
            setup.sender().wait_for_submission(),
        )
        .await
        .expect("expected a resubmission after the retry delay with no further updates");
        assert_eq!(setup.sender().count(), 1);
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    #[expect(non_snake_case)]
    async fn monitor_attestation_removal__should_retry_failed_resubmission_on_next_update() {
        // Given: the node is removed and the resubmission burns its whole retry window
        let setup = test_setup();
        setup.sender().set_failing(true);
        let handle = setup.spawn_monitor();
        tokio::task::yield_now().await;
        setup.remove_node_from_tee_accounts();
        tokio::time::sleep(MAX_RETRY_DURATION + Duration::from_secs(1)).await;

        // When: a TEE-accounts update arrives while the node is still absent
        setup.sender().set_failing(false);
        setup.remove_node_from_tee_accounts();

        // Then: the update triggers the retry well before the fixed retry delay
        tokio::time::timeout(TEST_RESUBMISSION_WAIT, setup.sender().wait_for_submission())
            .await
            .expect("expected a resubmission on the update after a failed one");
        assert_eq!(setup.sender().count(), 1);
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    #[expect(non_snake_case)]
    async fn monitor_attestation_removal__should_resubmit_on_each_removal() {
        // Given
        let setup = test_setup();
        let handle = setup.spawn_monitor();
        tokio::task::yield_now().await;

        // When: the node is removed, re-added, and removed again
        setup.remove_node_from_tee_accounts();
        tokio::time::timeout(TEST_RESUBMISSION_WAIT, setup.sender().wait_for_submission())
            .await
            .expect("expected a resubmission after the first removal");
        setup.add_node_to_tee_accounts();
        tokio::task::yield_now().await;
        setup.remove_node_from_tee_accounts();

        // Then
        tokio::time::timeout(TEST_RESUBMISSION_WAIT, setup.sender().wait_for_submission())
            .await
            .expect("expected a resubmission after the second removal");
        assert_eq!(setup.sender().count(), 2);
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    #[expect(non_snake_case)]
    async fn monitor_attestation_removal__should_stop_when_watch_channel_closes() {
        // Given
        let setup = test_setup();
        let handle = setup.spawn_monitor();
        tokio::task::yield_now().await;

        // When
        drop(setup.tee_accounts_sender);

        // Then
        tokio::time::timeout(TEST_RESUBMISSION_WAIT, handle)
            .await
            .expect("expected the monitor to stop when the watch channel closed")
            .unwrap();
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
    #[expect(non_snake_case)]
    async fn validate_remote_attestation__should_accept_valid_attestation() {
        // Given
        let config = LocalTeeAuthorityConfig::default();

        // When
        let result = validate_locally_generated_attestation(config).await;

        // Then
        result.expect("Valid attestation should pass validation");
    }

    #[tokio::test]
    #[expect(non_snake_case)]
    async fn validate_remote_attestation__should_reject_invalid_attestation() {
        // Given
        let config = LocalTeeAuthorityConfig::new(false);

        // When
        let result = validate_locally_generated_attestation(config).await;

        // Then
        assert!(result.is_err());
    }
}
