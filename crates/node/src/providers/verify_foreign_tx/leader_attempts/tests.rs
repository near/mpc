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
use tokio::time::{Duration, Instant};

const LEADER: ParticipantId = ParticipantId::from_raw(1);
const FOLLOWER: ParticipantId = ParticipantId::from_raw(2);
const OTHER_FOLLOWER: ParticipantId = ParticipantId::from_raw(3);
const SIGNED: &str = "signed";

type AttemptResult = Result<&'static str, AttemptFailure>;

/// A leader whose attempts end as scripted, in order. It records the nodes each asset take
/// avoids.
struct ScriptedLeader {
    results: Mutex<VecDeque<AttemptResult>>,
    /// The wait for each asset, or `None` when no asset comes.
    asset_wait: Option<Duration>,
    avoided: Mutex<Vec<BTreeSet<ParticipantId>>>,
    attempts_run: Mutex<usize>,
}

impl ScriptedLeader {
    fn new(results: impl IntoIterator<Item = AttemptResult>) -> Self {
        Self {
            results: Mutex::new(results.into_iter().collect()),
            asset_wait: Some(Duration::ZERO),
            avoided: Mutex::new(Vec::new()),
            attempts_run: Mutex::new(0),
        }
    }

    fn avoided(&self) -> Vec<BTreeSet<ParticipantId>> {
        self.avoided.lock().unwrap().clone()
    }

    fn attempts_run(&self) -> usize {
        *self.attempts_run.lock().unwrap()
    }
}

impl LeadV2Attempt for ScriptedLeader {
    type Asset = ();
    type Signed = &'static str;

    async fn take_asset(&self, avoid: &BTreeSet<ParticipantId>) -> anyhow::Result<()> {
        self.avoided.lock().unwrap().push(avoid.clone());
        let wait = self.asset_wait.context("the request closed")?;
        tokio::time::sleep(wait).await;
        Ok(())
    }

    async fn run_attempt(&self, (): ()) -> AttemptResult {
        *self.attempts_run.lock().unwrap() += 1;
        self.results
            .lock()
            .unwrap()
            .pop_front()
            .expect("the leader runs no attempt beyond the script")
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
