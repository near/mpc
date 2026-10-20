use std::{future::Future, time::Duration};

use crate::{
    indexer::{tx_sender::TransactionSender, types::ChainSendTransactionRequest},
    metrics::{
        MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL, MPC_TEE_ATTESTATION_OUTCOME_FAILURE,
        MPC_TEE_ATTESTATION_OUTCOME_SENT, MPC_TEE_ATTESTATION_OUTCOME_SUCCESS,
        MPC_TEE_ATTESTATION_ROUND_TIMEOUTS_TOTAL, MPC_TEE_ATTESTATION_STAGE_GENERATE_ATTESTATION,
        MPC_TEE_ATTESTATION_STAGE_SUBMIT_ATTESTATION, MPC_TEE_ATTESTATION_SUBMISSIONS_TOTAL,
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
use near_mpc_contract_interface::types::{
    AllowedMpcDockerImageHash, Ed25519PublicKey, GetAttestationResponse, VerifiedAttestation,
};
use near_time::Clock;
use tee_authority::tee_authority::{AttestationError, TeeAuthority};
use tokio_util::time::FutureExt;

use mpc_primitives::hash::{LauncherDockerComposeHash, NodeImageHash};
use near_mpc_contract_interface::call_args as contract_args;
use tokio::{sync::watch, time::Instant};

const MIN_BACKOFF_DURATION: Duration = Duration::from_millis(100);
const MAX_BACKOFF_DURATION: Duration = Duration::from_mins(1);
const BACKOFF_FACTOR: f32 = 1.5;
const ATTESTATION_RESUBMISSION_INTERVAL: Duration = Duration::from_hours(1);
const ATTESTATION_LANDING_TIMEOUT: Duration = Duration::from_secs(10);
const STALE_LANDING_AGE_SECONDS: i64 = 90 * 60;

pub(crate) trait GenerateAttestation: Send + Sync {
    fn generate_attestation(
        &self,
        report_data: ReportData,
    ) -> impl Future<Output = Result<Attestation, AttestationError>> + Send;
}

impl GenerateAttestation for TeeAuthority {
    async fn generate_attestation(
        &self,
        report_data: ReportData,
    ) -> Result<Attestation, AttestationError> {
        TeeAuthority::generate_attestation(self, report_data).await
    }
}

/// Inputs for the attestation-submission background task
/// [`run_periodic_attestation_submission`].
#[derive(Clone)]
pub struct AttestationSubmitter<T, A> {
    pub tee_authority: A,
    pub tx_sender: T,
    pub tls_public_key: Ed25519PublicKey,
    pub account_public_key: Ed25519PublicKey,
    pub allowed_image_hashes: watch::Receiver<Vec<AllowedMpcDockerImageHash>>,
    pub allowed_launcher_compose_hashes: watch::Receiver<Vec<LauncherDockerComposeHash>>,
    pub stored_attestation: watch::Receiver<Option<GetAttestationResponse>>,
}

/// Submits a [`contract_args::SubmitParticipantInfoArgs`] transaction containing the given
/// participant's attestation and TLS public key, using the provided [`TransactionSender`] and
/// retrying with backoff while the send fails or no stored attestation that can be ours shows up
/// within [`ATTESTATION_LANDING_TIMEOUT`].
/// Retries are unbounded; the caller stops them by dropping this future, as
/// [`periodic_attestation_submission`] does when a round times out.
async fn submit_remote_attestation(
    tx_sender: impl TransactionSender,
    stored_attestation: watch::Receiver<Option<GetAttestationResponse>>,
    attestation: Attestation,
    tls_public_key: Ed25519PublicKey,
) -> anyhow::Result<()> {
    let dstack_submitted = matches!(attestation, Attestation::Dstack(_));
    let submit_participant_info_args = contract_args::SubmitParticipantInfoArgs::new(
        attestation.into_contract_interface_type(),
        tls_public_key,
    );

    let set_attestation = move || {
        let tx_sender = tx_sender.clone();
        let mut stored_attestation = stored_attestation.clone();
        let chain_args = ChainSendTransactionRequest::SubmitParticipantInfo(Box::new(
            submit_participant_info_args.clone(),
        ));

        async move {
            tx_sender
                .send(chain_args)
                .await
                .context("failed to submit transaction")?;

            let landed = stored_attestation
                .wait_for(|stored| {
                    can_be_own_attestation(
                        stored.as_ref().map(GetAttestationResponse::attestation),
                        dstack_submitted,
                    )
                })
                .timeout(ATTESTATION_LANDING_TIMEOUT)
                .await
                .is_ok_and(|waited| waited.is_ok());
            anyhow::ensure!(landed, "attestation submission was not executed");
            Ok(())
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
        .await
}

fn can_be_own_attestation(stored: Option<&VerifiedAttestation>, dstack_submitted: bool) -> bool {
    match stored {
        None => false,
        Some(VerifiedAttestation::Mock(_)) => !dstack_submitted,
        Some(VerifiedAttestation::Dstack(_)) => true,
    }
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

impl<T: TransactionSender + Clone, A: GenerateAttestation> AttestationSubmitter<T, A> {
    async fn generate_attestation(&self) -> Option<Attestation> {
        let report_data: ReportData = ReportDataV1::new(
            *self.tls_public_key.as_bytes(),
            *self.account_public_key.as_bytes(),
        )
        .into();
        let result = self.tee_authority.generate_attestation(report_data).await;
        MPC_TEE_ATTESTATION_ATTEMPTS_TOTAL
            .with_label_values(&[outcome_label(result.is_ok())])
            .inc();
        match result {
            Ok(attestation) => Some(attestation),
            Err(error @ AttestationError::CollateralFetch(_)) => {
                tracing::warn!(%error, "TEE attestation collateral fetch failed");
                None
            }
            Err(error) => {
                tracing::error!(%error, "TEE attestation generation failed");
                None
            }
        }
    }

    async fn submit_attestation(&self, attestation: Attestation) {
        let allowed_image_hashes: Vec<_> = self
            .allowed_image_hashes
            .borrow()
            .iter()
            .map(|entry| entry.image_hash)
            .collect();
        let allowed_launcher_compose_hashes = self.allowed_launcher_compose_hashes.borrow().clone();
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
            self.stored_attestation.clone(),
            attestation,
            self.tls_public_key.clone(),
        )
        .await;
        match submission {
            Ok(()) => MPC_TEE_ATTESTATION_SUBMISSIONS_TOTAL
                .with_label_values(&[MPC_TEE_ATTESTATION_OUTCOME_SENT])
                .inc(),
            Err(error) => tracing::error!(?error, "attestation submission failed"),
        }
    }
}

fn outcome_label(succeeded: bool) -> &'static str {
    if succeeded {
        MPC_TEE_ATTESTATION_OUTCOME_SUCCESS
    } else {
        MPC_TEE_ATTESTATION_OUTCOME_FAILURE
    }
}

pub async fn run_periodic_attestation_submission<T, A>(submitter: AttestationSubmitter<T, A>)
where
    T: TransactionSender + Clone,
    A: GenerateAttestation,
{
    let mut interval = tokio::time::interval(ATTESTATION_RESUBMISSION_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    periodic_attestation_submission(submitter, interval).await
}

/// Periodically regenerates and submits this node's attestation. A stage still running at the
/// round deadline is abandoned, recorded in [`MPC_TEE_ATTESTATION_ROUND_TIMEOUTS_TOTAL`], and
/// the next tick starts over with a fresh attestation. Failures are logged, never propagated;
/// this task never returns.
#[tracing::instrument(skip_all)]
async fn periodic_attestation_submission<T: TransactionSender + Clone, A: GenerateAttestation>(
    submitter: AttestationSubmitter<T, A>,
    mut interval_ticker: impl Tick,
) {
    loop {
        interval_ticker.tick().await;
        warn_if_no_recent_acceptance(submitter.stored_attestation.borrow().as_ref());
        let deadline = Instant::now() + ATTESTATION_RESUBMISSION_INTERVAL;
        let Ok(generated) = submitter.generate_attestation().timeout_at(deadline).await else {
            record_round_timeout(MPC_TEE_ATTESTATION_STAGE_GENERATE_ATTESTATION);
            continue;
        };
        let Some(attestation) = generated else {
            continue;
        };
        let submission = submitter.submit_attestation(attestation);
        if submission.timeout_at(deadline).await.is_err() {
            record_round_timeout(MPC_TEE_ATTESTATION_STAGE_SUBMIT_ATTESTATION);
        }
    }
}

fn warn_if_no_recent_acceptance(stored: Option<&GetAttestationResponse>) {
    if let Some(landed_at) = stored.and_then(GetAttestationResponse::accepted_at_seconds) {
        let landed_at = i64::try_from(landed_at).unwrap_or(i64::MAX);
        let landing_age = Clock::real()
            .now_utc()
            .unix_timestamp()
            .saturating_sub(landed_at);
        if landing_age > STALE_LANDING_AGE_SECONDS {
            tracing::warn!(
                accepted_at_seconds = landed_at,
                "no attestation from this node accepted in over 90 minutes; its recent \
                 submit_participant_info transactions were likely rejected"
            );
        }
    }
}

fn record_round_timeout(stage: &'static str) {
    MPC_TEE_ATTESTATION_ROUND_TIMEOUTS_TOTAL
        .with_label_values(&[stage])
        .inc();
    tracing::warn!(
        stage,
        "attestation round timed out; retrying from scratch on the next tick"
    );
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::async_testing::{MaybeReady, run_future_once};
    use crate::indexer::tx_sender::TransactionProcessorError;
    use crate::tick::MockTicker;
    use ed25519_dalek::SigningKey;
    use near_mpc_contract_interface::types::{
        MockAttestation, VerifiedDstackAttestation, VerifiedMeasurements,
    };
    use rand::SeedableRng;
    use rstest::rstest;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use tee_authority::tee_authority::{LocalTeeAuthorityConfig, TeeAuthority};

    const TEST_SUBMISSION_COUNT: usize = 2;
    const STORED_MOCK: VerifiedAttestation = VerifiedAttestation::Mock(MockAttestation::Valid);

    #[derive(Clone, Default)]
    struct FailingAttestationGenerator {
        attempts: Arc<AtomicUsize>,
    }

    impl FailingAttestationGenerator {
        fn attempts(&self) -> usize {
            self.attempts.load(Ordering::Relaxed)
        }
    }

    impl GenerateAttestation for FailingAttestationGenerator {
        async fn generate_attestation(
            &self,
            _report_data: ReportData,
        ) -> Result<Attestation, AttestationError> {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            Err(AttestationError::InvalidEndpoint)
        }
    }

    #[derive(Clone)]
    struct HangingAttestationGenerator;

    impl GenerateAttestation for HangingAttestationGenerator {
        async fn generate_attestation(
            &self,
            _report_data: ReportData,
        ) -> Result<Attestation, AttestationError> {
            std::future::pending().await
        }
    }

    #[derive(Clone, Default)]
    struct MockSender {
        attempts: Arc<AtomicUsize>,
        submissions: Arc<Mutex<usize>>,
        notify: Arc<tokio::sync::Notify>,
        failing: Arc<AtomicBool>,
    }

    impl MockSender {
        fn set_failing(&self, failing: bool) {
            self.failing.store(failing, Ordering::Relaxed);
        }

        fn attempts(&self) -> usize {
            self.attempts.load(Ordering::Relaxed)
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
            self.attempts.fetch_add(1, Ordering::Relaxed);
            if self.failing.load(Ordering::Relaxed) {
                return Err(TransactionProcessorError::ProcessorIsClosed);
            }

            *self.submissions.lock().unwrap() += 1;
            self.notify.notify_one();
            Ok(())
        }
    }

    fn test_keys() -> (Ed25519PublicKey, Ed25519PublicKey) {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        (
            (&SigningKey::generate(&mut rng).verifying_key()).into(),
            (&SigningKey::generate(&mut rng).verifying_key()).into(),
        )
    }

    struct TestSetup<A> {
        submitter: AttestationSubmitter<MockSender, A>,
        stored_attestation: watch::Sender<Option<GetAttestationResponse>>,
    }

    /// Builds an [`AttestationSubmitter`] around a [`MockSender`].
    fn test_setup() -> TestSetup<TeeAuthority> {
        test_setup_with(TeeAuthority::from(LocalTeeAuthorityConfig::default()))
    }

    fn test_setup_with<A: GenerateAttestation>(tee_authority: A) -> TestSetup<A> {
        let (tls_public_key, account_public_key) = test_keys();
        let (_, allowed_image_hashes) = watch::channel(vec![]);
        let (_, allowed_launcher_compose_hashes) = watch::channel(vec![]);
        let (stored_attestation, stored_attestation_receiver) =
            watch::channel(Some(GetAttestationResponse::Legacy(STORED_MOCK)));
        let submitter = AttestationSubmitter {
            tee_authority,
            tx_sender: MockSender::default(),
            tls_public_key,
            account_public_key,
            allowed_image_hashes,
            allowed_launcher_compose_hashes,
            stored_attestation: stored_attestation_receiver,
        };
        TestSetup {
            submitter,
            stored_attestation,
        }
    }

    impl<A: GenerateAttestation + Clone + 'static> TestSetup<A> {
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

    fn stored_dstack() -> VerifiedAttestation {
        VerifiedAttestation::Dstack(VerifiedDstackAttestation {
            mpc_image_hash: [0; 32].into(),
            launcher_compose_hash: [0; 32].into(),
            expiry_timestamp_seconds: 0,
            measurements: VerifiedMeasurements {
                mrtd: [0; 48].into(),
                rtmr0: [0; 48].into(),
                rtmr1: [0; 48].into(),
                rtmr2: [0; 48].into(),
                key_provider_event_digest: [0; 48].into(),
            },
        })
    }

    #[rstest]
    #[case::nothing_stored(None, true, false)]
    #[case::mock_stored_for_a_dstack_submission(Some(STORED_MOCK), true, false)]
    #[case::mock_stored_for_a_mock_submission(Some(STORED_MOCK), false, true)]
    #[case::dstack_stored_for_a_dstack_submission(Some(stored_dstack()), true, true)]
    fn can_be_own_attestation__should_be_false_while_no_stored_entry_can_be_ours(
        #[case] stored: Option<VerifiedAttestation>,
        #[case] dstack_submitted: bool,
        #[case] expected: bool,
    ) {
        // When
        let can_be_own = can_be_own_attestation(stored.as_ref(), dstack_submitted);

        // Then
        assert_eq!(can_be_own, expected);
    }

    #[tokio::test]
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

    #[tokio::test(start_paused = true)]
    async fn periodic_attestation_submission__should_not_resend_while_an_attestation_is_stored() {
        // Given
        let setup = test_setup();
        let handle = setup.spawn_periodic(1);

        // When
        tokio::time::sleep(ATTESTATION_RESUBMISSION_INTERVAL).await;

        // Then
        assert_eq!(setup.sender().attempts(), 1);
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_attestation_submission__should_resend_while_nothing_is_stored() {
        // Given
        let setup = test_setup();
        setup.stored_attestation.send_replace(None);
        let handle = setup.spawn_periodic(1);

        // When
        tokio::time::sleep(ATTESTATION_RESUBMISSION_INTERVAL).await;

        // Then
        assert!(setup.sender().attempts() > 1);
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_attestation_submission__should_survive_submission_retry_timeout() {
        // Given: the first round times out, the second one lands
        let setup = test_setup();
        setup.sender().set_failing(true);
        let handle = setup.spawn_periodic(2);

        // When
        tokio::time::sleep(ATTESTATION_RESUBMISSION_INTERVAL + Duration::from_secs(1)).await;
        setup.sender().set_failing(false);

        // Then
        tokio::time::timeout(
            ATTESTATION_RESUBMISSION_INTERVAL,
            setup.sender().wait_for_submission(),
        )
        .await
        .expect("expected a successful submission on the round after the cut-off one");
        assert_eq!(setup.sender().count(), 1);
        handle.abort();
    }

    #[tokio::test]
    async fn periodic_attestation_submission__should_wait_for_the_next_tick_when_generation_fails()
    {
        // Given
        let generator = FailingAttestationGenerator::default();
        let setup = test_setup_with(generator.clone());
        let ticker = MockTicker::new(1);

        // When
        let MaybeReady::Future(parked_loop) = run_future_once(periodic_attestation_submission(
            setup.submitter.clone(),
            ticker.clone(),
        )) else {
            panic!("the loop should park once its ticker runs out");
        };
        let attempts_before_the_next_tick = generator.attempts();
        ticker.schedule(1);
        run_future_once(parked_loop);

        // Then
        assert_eq!(attempts_before_the_next_tick, 1);
        assert_eq!(generator.attempts(), 2);
        assert_eq!(setup.sender().count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_attestation_submission__should_stop_submission_retries_at_the_round_timeout()
    {
        // Given
        let setup = test_setup();
        setup.sender().set_failing(true);
        let handle = setup.spawn_periodic(1);

        // When
        tokio::time::sleep(ATTESTATION_RESUBMISSION_INTERVAL + Duration::from_secs(1)).await;
        let attempts_at_the_timeout = setup.sender().attempts();
        tokio::time::sleep(ATTESTATION_RESUBMISSION_INTERVAL).await;

        // Then
        assert!(attempts_at_the_timeout > 1);
        assert_eq!(setup.sender().attempts(), attempts_at_the_timeout);
        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_attestation_submission__should_cut_hung_generation_at_the_round_timeout() {
        // Given
        let setup = test_setup_with(HangingAttestationGenerator);
        let cut_rounds_before = MPC_TEE_ATTESTATION_ROUND_TIMEOUTS_TOTAL
            .with_label_values(&[MPC_TEE_ATTESTATION_STAGE_GENERATE_ATTESTATION])
            .get();
        let handle = setup.spawn_periodic(1);

        // When
        tokio::time::sleep(ATTESTATION_RESUBMISSION_INTERVAL + Duration::from_secs(1)).await;

        // Then
        assert_eq!(setup.sender().count(), 0);
        assert_eq!(
            MPC_TEE_ATTESTATION_ROUND_TIMEOUTS_TOTAL
                .with_label_values(&[MPC_TEE_ATTESTATION_STAGE_GENERATE_ATTESTATION])
                .get(),
            cut_rounds_before + 1
        );
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
    async fn validate_remote_attestation__should_accept_valid_attestation() {
        // Given
        let config = LocalTeeAuthorityConfig::default();

        // When
        let result = validate_locally_generated_attestation(config).await;

        // Then
        result.expect("Valid attestation should pass validation");
    }

    #[tokio::test]
    async fn validate_remote_attestation__should_reject_invalid_attestation() {
        // Given
        let config = LocalTeeAuthorityConfig::new(false);

        // When
        let result = validate_locally_generated_attestation(config).await;

        // Then
        assert!(result.is_err());
    }
}
