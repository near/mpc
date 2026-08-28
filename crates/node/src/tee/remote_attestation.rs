use std::{sync::Arc, time::Duration};

use crate::{
    indexer::{
        ReadAttestationExpiry,
        tx_sender::{TransactionSender, TransactionStatus},
        types::ChainSendTransactionRequest,
    },
    metrics::{
        MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL, MPC_TEE_ATTESTATION_OUTCOME_FAILURE,
        MPC_TEE_ATTESTATION_OUTCOME_SUCCESS, MPC_TEE_ATTESTATION_SUBMISSIONS_TOTAL,
    },
    tick::Tick,
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
use near_mpc_contract_interface::call_args as contract_args;
use tokio::sync::watch;

const MIN_BACKOFF_DURATION: Duration = Duration::from_millis(100);
const MAX_BACKOFF_DURATION: Duration = Duration::from_secs(60);
const MAX_RETRY_DURATION: Duration = Duration::from_secs(60 * 60 * 12); // 12 hours.
const BACKOFF_FACTOR: f32 = 1.5;
const ATTESTATION_RESUBMISSION_INTERVAL: Duration = Duration::from_secs(60 * 60); // 1 hour.

/// Inputs for the attestation-submission background task
/// [`run_periodic_attestation_submission`].
#[derive(Clone)]
pub struct AttestationSubmitter<T> {
    pub tee_authority: TeeAuthority,
    pub tx_sender: T,
    pub tls_public_key: Ed25519PublicKey,
    pub account_public_key: Ed25519PublicKey,
    pub allowed_image_hashes: watch::Receiver<Vec<AllowedMpcDockerImageHash>>,
    pub allowed_launcher_compose_hashes: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    pub attestation_reader: Arc<dyn ReadAttestationExpiry>,
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
        MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL
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
            // fail on a stale view of the allowed hashes
            tracing::warn!("Attestation is not valid: {error}");
        }
        let submission = submit_remote_attestation(
            self.tx_sender.clone(),
            attestation,
            self.tls_public_key.clone(),
            pre_submit_expiry,
        )
        .await;
        MPC_TEE_ATTESTATION_SUBMISSIONS_TOTAL
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
        MPC_TEE_ATTESTATION_OUTCOME_SUCCESS
    } else {
        MPC_TEE_ATTESTATION_OUTCOME_FAILURE
    }
}

pub async fn run_periodic_attestation_submission<T: TransactionSender + Clone>(
    submitter: AttestationSubmitter<T>,
) {
    let mut interval = tokio::time::interval(ATTESTATION_RESUBMISSION_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    periodic_attestation_submission(submitter, interval).await
}

/// Periodically regenerates and submits this node's attestation. Generation and submission
/// failures are logged and retried on the next tick; this task never returns.
#[tracing::instrument(skip_all)]
async fn periodic_attestation_submission<T: TransactionSender + Clone, I: Tick>(
    submitter: AttestationSubmitter<T>,
    mut interval_ticker: I,
) {
    loop {
        interval_ticker.tick().await;
        submitter.generate_and_submit().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexer::tx_sender::{TransactionProcessorError, TransactionStatus};
    use crate::tick::MockTicker;
    use ed25519_dalek::SigningKey;
    use rand::SeedableRng;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    };
    use tee_authority::tee_authority::{LocalTeeAuthorityConfig, TeeAuthority};

    const TEST_SUBMISSION_COUNT: usize = 2;

    struct StubAttestationExpiryReader {
        fail: bool,
    }

    impl ReadAttestationExpiry for StubAttestationExpiryReader {
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
        submitter: AttestationSubmitter<MockSender>,
    }

    /// Builds an [`AttestationSubmitter`] around a [`MockSender`].
    fn test_setup() -> TestSetup {
        let (tls_public_key, account_public_key) = test_keys();
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
        TestSetup { submitter }
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
