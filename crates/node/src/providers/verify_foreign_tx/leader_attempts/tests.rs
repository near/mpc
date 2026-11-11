use super::*;
use crate::primitives::{ChannelId, UniqueId};
use crate::providers::verify_foreign_tx::attempt_outcomes::ParticipantVerdict;
use crate::providers::verify_foreign_tx::node_outcome::NodeVerdict;
use anyhow::Context as _;
use near_mpc_contract_interface::types::ForeignTxVerificationNegativeVerdict;
use rstest::rstest;
use std::assert_matches;
use std::collections::VecDeque;
use std::sync::Mutex;
use tokio::sync::watch;
use tokio::time::{Duration, Instant};

const LEADER: ParticipantId = ParticipantId::from_raw(1);
const FOLLOWER: ParticipantId = ParticipantId::from_raw(2);
const OTHER_FOLLOWER: ParticipantId = ParticipantId::from_raw(3);
const SIGNED: &str = "signed";
const SIGNED_INCONCLUSIVE: &str = "signed inconclusive";
const EVIDENCE: &str = "evidence";

type AttemptResult = Result<&'static str, AttemptFailure>;
type RoundResult = anyhow::Result<&'static str>;

/// A leader whose attempts and inconclusive rounds end as scripted, in order. It records the
/// nodes each asset take avoids.
struct ScriptedLeader {
    attempts: Mutex<VecDeque<AttemptResult>>,
    rounds: Mutex<VecDeque<RoundResult>>,
    /// The wait for each asset, or `None` when no asset comes.
    asset_wait: Option<Duration>,
    /// The time each attempt runs before it ends as scripted.
    attempt_duration: Duration,
    /// The number of the attempt that leaves the evidence of an inconclusive behind.
    evidence_after_attempt: Option<usize>,
    /// The time from the start until the evidence proves an inconclusive.
    evidence_at: Option<Duration>,
    evidence: watch::Sender<Option<&'static str>>,
    avoided: Mutex<Vec<BTreeSet<ParticipantId>>>,
    round_avoided: Mutex<Vec<BTreeSet<ParticipantId>>>,
    attempts_run: Mutex<usize>,
    rounds_run: Mutex<usize>,
}

impl ScriptedLeader {
    fn new(attempts: impl IntoIterator<Item = AttemptResult>) -> Self {
        Self {
            attempts: Mutex::new(attempts.into_iter().collect()),
            rounds: Mutex::new(VecDeque::new()),
            asset_wait: Some(Duration::ZERO),
            attempt_duration: Duration::ZERO,
            evidence_after_attempt: None,
            evidence_at: None,
            evidence: watch::Sender::new(None),
            avoided: Mutex::new(Vec::new()),
            round_avoided: Mutex::new(Vec::new()),
            attempts_run: Mutex::new(0),
            rounds_run: Mutex::new(0),
        }
    }

    fn with_rounds(self, rounds: impl IntoIterator<Item = RoundResult>) -> Self {
        Self {
            rounds: Mutex::new(rounds.into_iter().collect()),
            ..self
        }
    }

    fn with_evidence_after_attempt(self, attempt: usize) -> Self {
        Self {
            evidence_after_attempt: Some(attempt),
            ..self
        }
    }

    fn avoided(&self) -> Vec<BTreeSet<ParticipantId>> {
        self.avoided.lock().unwrap().clone()
    }

    fn round_avoided(&self) -> Vec<BTreeSet<ParticipantId>> {
        self.round_avoided.lock().unwrap().clone()
    }

    fn attempts_run(&self) -> usize {
        *self.attempts_run.lock().unwrap()
    }

    fn rounds_run(&self) -> usize {
        *self.rounds_run.lock().unwrap()
    }

    async fn wait_for_asset(&self) -> anyhow::Result<()> {
        tokio::task::yield_now().await;
        let wait = self.asset_wait.context("the request closed")?;
        tokio::time::sleep(wait).await;
        Ok(())
    }
}

impl LeadV2Request for ScriptedLeader {
    type Asset = ();
    type Signed = &'static str;
    type Evidence = &'static str;

    async fn take_attempt_asset(&self, avoid: &BTreeSet<ParticipantId>) -> anyhow::Result<()> {
        self.avoided.lock().unwrap().push(avoid.clone());
        self.wait_for_asset().await
    }

    async fn run_attempt(&self, (): ()) -> AttemptResult {
        tokio::time::sleep(self.attempt_duration).await;
        let attempt = {
            let mut attempts_run = self.attempts_run.lock().unwrap();
            *attempts_run += 1;
            *attempts_run
        };
        if self.evidence_after_attempt == Some(attempt) {
            self.evidence.send_replace(Some(EVIDENCE));
        }
        self.attempts
            .lock()
            .unwrap()
            .pop_front()
            .expect("the leader runs no attempt beyond the script")
    }

    async fn wait_for_inconclusive_evidence(&self) -> &'static str {
        let mut evidence = self.evidence.subscribe();
        let scripted = async {
            *evidence
                .wait_for(Option::is_some)
                .await
                .unwrap()
                .as_ref()
                .unwrap()
        };
        match self.evidence_at {
            Some(at) => {
                tokio::select! {
                    found = scripted => found,
                    () = tokio::time::sleep(at) => EVIDENCE,
                }
            }
            None => scripted.await,
        }
    }

    async fn take_round_asset(&self, avoid: &BTreeSet<ParticipantId>) -> anyhow::Result<()> {
        self.round_avoided.lock().unwrap().push(avoid.clone());
        self.wait_for_asset().await
    }

    async fn run_inconclusive_round(&self, (): (), evidence: &&'static str) -> RoundResult {
        assert_eq!(*evidence, EVIDENCE);
        *self.rounds_run.lock().unwrap() += 1;
        self.rounds
            .lock()
            .unwrap()
            .pop_front()
            .expect("the leader runs no round beyond the script")
    }
}

fn cluster_problem() -> AttemptFailure {
    AttemptFailure::Cluster(anyhow::anyhow!("a share does not combine"))
}

fn aborted_by(participant: ParticipantId) -> AbortedByParticipant {
    AbortedByParticipant {
        participant,
        reason: "the V2 request is not open".to_string(),
    }
}

fn verdicts_differ() -> AttemptEnd {
    AttemptEnd::VerdictsDiffer {
        first: ParticipantVerdict {
            participant: LEADER,
            verdict: NodeVerdict::Verified,
        },
        second: ParticipantVerdict {
            participant: FOLLOWER,
            verdict: NodeVerdict::Negative(
                ForeignTxVerificationNegativeVerdict::TransactionNotFound,
            ),
        },
    }
}

fn no_verdict(reason: NoVerdictReason) -> AttemptEnd {
    AttemptEnd::NoVerdict {
        participant: FOLLOWER,
        reason,
    }
}

#[tokio::test]
async fn lead_attempts__should_return_the_signature_of_the_first_attempt_that_signs() {
    // Given
    let leader = ScriptedLeader::new([Err(cluster_problem()), Ok(SIGNED)]);

    // When
    let signed = lead_attempts(&leader).await;

    // Then
    assert_eq!(signed.unwrap(), SIGNED);
    assert_eq!(leader.attempts_run(), 2);
}

#[tokio::test]
async fn lead_attempts__should_stop_after_three_failed_attempts() {
    // Given
    let leader = ScriptedLeader::new([
        Err(cluster_problem()),
        Err(AttemptFailure::Transient {
            participant: FOLLOWER,
        }),
        Err(AttemptFailure::Aborted(aborted_by(OTHER_FOLLOWER))),
    ]);

    // When
    let stop = lead_attempts(&leader).await;

    // Then
    assert_matches!(
        stop,
        Err(LeaderStop::AttemptsExhausted(AttemptFailure::Aborted(_)))
    );
    assert_eq!(leader.attempts_run(), 3);
}

#[rstest]
#[case::verdicts_differ(verdicts_differ())]
#[case::inspectors_disagree(no_verdict(NoVerdictReason::InspectorsDisagree))]
#[tokio::test]
async fn lead_attempts__should_not_retry_a_disagreement(#[case] end: AttemptEnd) {
    // Given
    let leader = ScriptedLeader::new([Err(AttemptFailure::Disagreement(end))]);

    // When
    let stop = lead_attempts(&leader).await;

    // Then
    assert_matches!(stop, Err(LeaderStop::Disagreement(stopped_on)) if stopped_on == end);
    assert_eq!(leader.attempts_run(), 1);
}

#[rstest]
#[case::transient(AttemptFailure::Transient { participant: FOLLOWER }, [FOLLOWER].into())]
#[case::aborted(AttemptFailure::Aborted(aborted_by(OTHER_FOLLOWER)), [OTHER_FOLLOWER].into())]
#[case::silent(
    AttemptFailure::DeadlineExceeded { silent: [FOLLOWER, OTHER_FOLLOWER].into() },
    [FOLLOWER, OTHER_FOLLOWER].into(),
)]
#[case::cluster_problem(cluster_problem(), BTreeSet::new())]
#[tokio::test]
async fn lead_attempts__should_retry_with_an_asset_that_avoids_the_nodes_that_failed(
    #[case] failure: AttemptFailure,
    #[case] avoided: BTreeSet<ParticipantId>,
) {
    // Given
    let leader = ScriptedLeader::new([Err(failure), Ok(SIGNED)]);

    // When
    let signed = lead_attempts(&leader).await;

    // Then
    assert_eq!(signed.unwrap(), SIGNED);
    assert_eq!(leader.avoided(), vec![BTreeSet::new(), avoided]);
}

#[tokio::test(start_paused = true)]
async fn lead_attempts__should_not_count_the_wait_for_an_asset_as_an_attempt() {
    // Given
    let asset_wait = Duration::from_mins(1);
    let leader = ScriptedLeader {
        asset_wait: Some(asset_wait),
        ..ScriptedLeader::new([Err(cluster_problem()), Err(cluster_problem()), Ok(SIGNED)])
    };
    let started = Instant::now();

    // When
    let signed = lead_attempts(&leader).await;

    // Then
    assert_eq!(signed.unwrap(), SIGNED);
    assert_eq!(leader.attempts_run(), 3);
    assert_eq!(started.elapsed(), 3 * asset_wait);
}

#[tokio::test]
async fn lead_attempts__should_stop_without_an_attempt_when_no_asset_comes() {
    // Given
    let leader = ScriptedLeader {
        asset_wait: None,
        ..ScriptedLeader::new([])
    };

    // When
    let stop = lead_attempts(&leader).await;

    // Then
    assert_matches!(stop, Err(LeaderStop::NoAsset(_)));
    assert_eq!(leader.attempts_run(), 0);
}

fn attempt_id() -> AttemptId {
    AttemptId(ChannelId(UniqueId::new(LEADER, 1_700_000_000, 0)))
}

#[rstest]
#[case::transient(
    anyhow::Error::new(no_verdict(NoVerdictReason::Transient)),
    AttemptFailure::Transient { participant: FOLLOWER },
)]
#[case::inspectors_disagree(
    anyhow::Error::new(no_verdict(NoVerdictReason::InspectorsDisagree)),
    AttemptFailure::Disagreement(no_verdict(NoVerdictReason::InspectorsDisagree))
)]
#[case::verdicts_differ(
    anyhow::Error::new(verdicts_differ()),
    AttemptFailure::Disagreement(verdicts_differ())
)]
#[case::aborted(
    anyhow::Error::new(aborted_by(OTHER_FOLLOWER)).context("the attempt failed"),
    AttemptFailure::Aborted(aborted_by(OTHER_FOLLOWER)),
)]
#[case::timeout(
    anyhow::Error::new(ComputationTimeout),
    AttemptFailure::DeadlineExceeded { silent: BTreeSet::new() },
)]
#[case::other(anyhow::anyhow!("a share does not combine"), cluster_problem())]
fn attempt_failure_new__should_sort_the_error_that_ended_the_attempt(
    #[case] error: anyhow::Error,
    #[case] expected: AttemptFailure,
) {
    // Given
    let evidence = AttemptEvidence::new();

    // When
    let failure = AttemptFailure::new(error, attempt_id(), &evidence);

    // Then
    assert_eq!(failure.to_string(), expected.to_string());
    assert_eq!(
        std::mem::discriminant(&failure),
        std::mem::discriminant(&expected)
    );
}

#[rstest]
#[case::verdicts_differ(verdicts_differ())]
#[case::inspectors_disagree(no_verdict(NoVerdictReason::InspectorsDisagree))]
#[tokio::test]
async fn lead_request__should_sign_an_inconclusive_after_a_disagreement(#[case] end: AttemptEnd) {
    // Given
    let leader = ScriptedLeader::new([Err(AttemptFailure::Disagreement(end))])
        .with_evidence_after_attempt(1)
        .with_rounds([Ok(SIGNED_INCONCLUSIVE)]);

    // When
    let signed = lead_request(&leader).await;

    // Then
    assert_eq!(signed.unwrap(), SIGNED_INCONCLUSIVE);
    assert_eq!(leader.attempts_run(), 1);
    assert_eq!(leader.rounds_run(), 1);
}

#[tokio::test(start_paused = true)]
async fn lead_request__should_stop_after_a_disagreement_without_evidence() {
    // Given
    let leader = ScriptedLeader::new([Err(AttemptFailure::Disagreement(verdicts_differ()))]);

    // When
    let stop = lead_request(&leader).await;

    // Then
    assert_matches!(stop, Err(LeaderStop::Disagreement(_)));
    assert_eq!(leader.rounds_run(), 0);
}

#[tokio::test]
async fn lead_request__should_sign_an_inconclusive_once_the_evidence_holds_enough_transient_errors()
{
    // Given
    let transient = || AttemptFailure::Transient {
        participant: FOLLOWER,
    };
    let leader = ScriptedLeader::new([Err(transient()), Err(transient()), Ok(SIGNED)])
        .with_evidence_after_attempt(2)
        .with_rounds([Ok(SIGNED_INCONCLUSIVE)]);

    // When
    let signed = lead_request(&leader).await;

    // Then
    assert_eq!(signed.unwrap(), SIGNED_INCONCLUSIVE);
    assert_eq!(leader.attempts_run(), 2);
}

#[tokio::test(start_paused = true)]
async fn lead_request__should_stop_when_no_evidence_comes_within_the_inspection_cap() {
    // Given
    let leader = ScriptedLeader::new([
        Err(AttemptFailure::Transient {
            participant: FOLLOWER,
        }),
        Err(cluster_problem()),
        Err(AttemptFailure::Aborted(aborted_by(OTHER_FOLLOWER))),
    ]);
    let started = Instant::now();

    // When
    let stop = lead_request(&leader).await;

    // Then
    assert_matches!(stop, Err(LeaderStop::AttemptsExhausted(_)));
    assert_eq!(leader.rounds_run(), 0);
    assert_eq!(started.elapsed(), FOREIGN_CHAIN_INSPECTION_TIMEOUT);
}

#[tokio::test(start_paused = true)]
async fn lead_request__should_count_evidence_that_completes_after_the_last_attempt() {
    // Given
    let late_report = Duration::from_secs(1);
    let transient = || AttemptFailure::Transient {
        participant: FOLLOWER,
    };
    let leader = ScriptedLeader {
        evidence_at: Some(late_report),
        ..ScriptedLeader::new([Err(transient()), Err(transient()), Err(transient())])
            .with_rounds([Ok(SIGNED_INCONCLUSIVE)])
    };
    let started = Instant::now();

    // When
    let signed = lead_request(&leader).await;

    // Then
    assert_eq!(signed.unwrap(), SIGNED_INCONCLUSIVE);
    assert_eq!(leader.attempts_run(), 3);
    assert_eq!(started.elapsed(), late_report);
}

#[test]
fn led_attempt_count__should_count_an_attempt_dropped_before_its_result_as_abandoned() {
    // Given
    let counted = |label| {
        metrics::MPC_NUM_VERIFY_FOREIGN_TX_COMPUTATIONS_LED
            .with_label_values(&[label])
            .get()
    };
    let total_before = counted(metrics::TOTAL_RESULT_LABEL);
    let abandoned_before = counted(metrics::ABANDONED_OUTCOME_LABEL);

    // When
    drop(LedAttemptCount::new());

    // Then
    assert_eq!(counted(metrics::TOTAL_RESULT_LABEL), total_before + 1);
    assert_eq!(
        counted(metrics::ABANDONED_OUTCOME_LABEL),
        abandoned_before + 1
    );
}

#[tokio::test(start_paused = true)]
async fn lead_request__should_start_the_inconclusive_as_soon_as_the_evidence_proves_it() {
    // Given
    let evidence_at = Duration::from_secs(2);
    let leader = ScriptedLeader {
        attempt_duration: Duration::from_secs(13),
        evidence_at: Some(evidence_at),
        ..ScriptedLeader::new([Ok(SIGNED)]).with_rounds([Ok(SIGNED_INCONCLUSIVE)])
    };
    let started = Instant::now();

    // When
    let signed = lead_request(&leader).await;

    // Then
    assert_eq!(signed.unwrap(), SIGNED_INCONCLUSIVE);
    assert_eq!(started.elapsed(), evidence_at);
}

#[tokio::test]
async fn lead_request__should_stop_after_three_failed_inconclusive_rounds() {
    // Given
    let leader = ScriptedLeader::new([Err(AttemptFailure::Disagreement(verdicts_differ()))])
        .with_evidence_after_attempt(1)
        .with_rounds([
            Err(anyhow::anyhow!("a share does not combine")),
            Err(anyhow::anyhow!("a share does not combine")),
            Err(anyhow::anyhow!("a share does not combine")),
            Ok(SIGNED_INCONCLUSIVE),
        ]);

    // When
    let stop = lead_request(&leader).await;

    // Then
    assert_matches!(stop, Err(LeaderStop::RoundsExhausted(_)));
    assert_eq!(leader.rounds_run(), 3);
}

#[tokio::test]
async fn lead_request__should_retry_a_round_with_an_asset_that_avoids_the_node_that_refused() {
    // Given
    let leader = ScriptedLeader::new([Err(AttemptFailure::Disagreement(verdicts_differ()))])
        .with_evidence_after_attempt(1)
        .with_rounds([
            Err(anyhow::Error::new(aborted_by(OTHER_FOLLOWER)).context("the round failed")),
            Ok(SIGNED_INCONCLUSIVE),
        ]);

    // When
    let signed = lead_request(&leader).await;

    // Then
    assert_eq!(signed.unwrap(), SIGNED_INCONCLUSIVE);
    assert_eq!(
        leader.round_avoided(),
        vec![BTreeSet::new(), BTreeSet::from([OTHER_FOLLOWER])]
    );
}
