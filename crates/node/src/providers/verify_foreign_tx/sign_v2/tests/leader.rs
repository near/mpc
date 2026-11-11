use super::*;
use crate::network::testing::run_test_clients;
use crate::providers::verify_foreign_tx::attempt_outcomes::AttemptEnd;
use crate::providers::verify_foreign_tx::leader_attempts::AttemptFailure;
use crate::providers::verify_foreign_tx::node_outcome::NoVerdictReason;
use crate::tests::into_participant_ids;
use crate::tracking::testing::start_root_task_with_periodic_dump;
use k256::Scalar;
use k256::elliptic_curve::PrimeField;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::assert_matches;
use std::collections::HashMap;
use threshold_signatures::frost_secp256k1::Secp256K1Sha256;
use threshold_signatures::participants::Participant;
use threshold_signatures::test_utils::{deal_triple, generate_participants, run_keygen};
use tokio::sync::Notify;

/// Below [`ATTEMPT_DEADLINE`], so finishing within it means the attempt failed fast.
const FAIL_FAST_BOUND: Duration = Duration::from_secs(10);

/// A key and a triple pair dealt to every participant, so the clients only run the attempt.
struct DealtShares {
    by_participant: HashMap<ParticipantId, (KeygenOutput, PairedTriple)>,
}

impl DealtShares {
    fn new(participants: &[Participant]) -> Self {
        let mut rng = StdRng::seed_from_u64(42);
        let keys: HashMap<Participant, KeygenOutput> =
            run_keygen::<Secp256K1Sha256, _>(participants, THRESHOLD, &mut rng)
                .into_iter()
                .collect();
        let (pub0, shares0) = deal_triple(&mut rng, participants, THRESHOLD.into()).unwrap();
        let (pub1, shares1) = deal_triple(&mut rng, participants, THRESHOLD.into()).unwrap();
        let by_participant = participants
            .iter()
            .zip(shares0)
            .zip(shares1)
            .map(|((p, share0), share1)| {
                let pair = ((share0, pub0.clone()), (share1, pub1.clone()));
                ((*p).into(), (keys[p].clone(), pair))
            })
            .collect();
        Self { by_participant }
    }
}

/// What a simulated follower does once it receives the Start of an attempt.
#[derive(Clone)]
enum Follower {
    /// Reports `outcome`, then signs for a verdict.
    Reports(NodeOutcome),
    Refuses,
    /// Reports `outcome` only after the leader's attempt ended.
    ReportsLate(NodeOutcome, Arc<Notify>),
    /// Sends nothing until the leader's attempt ended.
    Silent(Arc<Notify>),
}

async fn run_follower(
    channel: NetworkTaskChannel,
    behaviour: Follower,
    shares: (KeygenOutput, PairedTriple),
) -> anyhow::Result<()> {
    let me = channel.my_participant_id();
    let sender = channel.sender();
    match behaviour {
        Follower::Refuses => {
            sender.abort(&anyhow::anyhow!("the request is not open"));
            Ok(())
        }
        Follower::Silent(leader_done) => {
            let _channel = channel;
            leader_done.notified().await;
            Ok(())
        }
        Follower::ReportsLate(outcome, leader_done) => {
            let statement = statement(&channel, me, outcome);
            drop(channel);
            leader_done.notified().await;
            sender.send_node_outcome(signing_key(me).sign(statement)?)
        }
        Follower::Reports(outcome) => {
            sender.send_node_outcome(signing_key(me).sign(statement(&channel, me, outcome))?)?;
            let NodeOutcome::Verdict(verdict) = outcome else {
                return Ok(());
            };
            let payload_hash = request().sign_payload(verdict.into())?.compute_msg_hash()?;
            let (keygen_out, triples) = shares;
            OnlinePresignSignComputation {
                keygen_out,
                reconstruction_threshold: ReconstructionThreshold::from(THRESHOLD),
                triples,
                msg_hash: payload_hash.into(),
                tweak: Tweak::new([0; 32]),
            }
            .perform_leader_centric_computation(channel, Duration::from_mins(1))
            .await
            .map(|_| ())
        }
    }
}

struct AttemptRun {
    participants: Vec<ParticipantId>,
    leader_result: Result<SignedVerdict, AttemptFailure>,
    elapsed: Duration,
    evidence: Vec<NodeOutcomeStatement>,
}

/// Runs one attempt among three participants: the leader finds `leader_outcome`, and each
/// follower acts as given. Returns once the leader keeps `kept_outcomes` node outcomes.
async fn run_attempt(
    leader_outcome: NodeOutcome,
    followers: [Follower; 2],
    kept_outcomes: usize,
) -> AttemptRun {
    let ts_participants = generate_participants(THRESHOLD);
    let participants = into_participant_ids(&ts_participants);
    let leader = participants[0];
    let shares = Arc::new(DealtShares::new(&ts_participants));
    let behaviours: Arc<HashMap<ParticipantId, Follower>> =
        Arc::new(participants[1..].iter().copied().zip(followers).collect());
    let leader_done: Vec<Arc<Notify>> = behaviours
        .values()
        .filter_map(|behaviour| match behaviour {
            Follower::ReportsLate(_, done) | Follower::Silent(done) => Some(done.clone()),
            _ => None,
        })
        .collect();

    let results = run_test_clients(participants.clone(), move |client, mut receiver| {
        let shares = shares.clone();
        let participants = participants.clone();
        let behaviours = behaviours.clone();
        let leader_done = leader_done.clone();
        async move {
            let me = client.my_participant_id();
            let my_shares = shares.by_participant[&me].clone();
            if me != leader {
                let channel = receiver.recv().await.context("no channel received")?;
                if let Err(err) = run_follower(channel, behaviours[&me].clone(), my_shares).await {
                    tracing::info!(%me, %err, "follower ended");
                }
                return Ok(None);
            }
            let started = tokio::time::Instant::now();
            let leader_result = run_leader(&client, &participants, leader_outcome, my_shares).await;
            let elapsed = started.elapsed();
            leader_done.iter().for_each(|done| done.notify_one());
            let evidence = wait_for_evidence(&client, kept_outcomes).await;
            Ok(Some(AttemptRun {
                participants,
                leader_result,
                elapsed,
                evidence,
            }))
        }
    })
    .await
    .unwrap();
    results.into_iter().flatten().next().unwrap()
}

async fn run_leader(
    client: &Arc<MeshNetworkClient>,
    participants: &[ParticipantId],
    leader_outcome: NodeOutcome,
    (keygen_out, triples): (KeygenOutput, PairedTriple),
) -> Result<SignedVerdict, AttemptFailure> {
    let me = client.my_participant_id();
    let (channel, attempt) = open_led_attempt(
        client,
        VerifyForeignTxTaskId::VerifyForeignTxV2 {
            id: request().id,
            paired_triple_id: UniqueId::new(me, 1, 0),
        },
        participants.to_vec(),
        request().yield_id,
        keys(participants),
    )
    .unwrap();
    let signed = signing_key(me)
        .sign(statement(&channel, me, leader_outcome))
        .unwrap();
    let (own_outcome_sender, own_outcome) = oneshot::channel();
    own_outcome_sender
        .send(record_own_outcome(
            signed,
            &attempt,
            client.attempt_evidence(),
        ))
        .unwrap();
    V2LeaderComputation {
        attempt,
        own_outcome,
        request: request(),
        keygen_out,
        reconstruction_threshold: ReconstructionThreshold::from(THRESHOLD),
        triples,
    }
    .run(channel, client.attempt_evidence())
    .await
}

/// The statements the leader keeps, once it keeps `count` of them.
async fn wait_for_evidence(
    client: &Arc<MeshNetworkClient>,
    count: usize,
) -> Vec<NodeOutcomeStatement> {
    let evidence = client.attempt_evidence();
    timeout(
        Duration::from_secs(30),
        evidence.wait_for_outcomes(request().yield_id, count),
    )
    .await
    .expect("the leader keeps every node outcome that reaches it");
    let mut statements: Vec<_> = evidence
        .outcomes_for(request().yield_id)
        .iter()
        .map(|outcome| outcome.statement().clone())
        .collect();
    statements.sort_by_key(|statement| statement.signer);
    statements
}

fn signers(evidence: &[NodeOutcomeStatement]) -> Vec<ParticipantId> {
    evidence.iter().map(|statement| statement.signer).collect()
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn v2_leader_computation__should_sign_the_payload_when_every_participant_agrees() {
    start_root_task_with_periodic_dump(async {
        // Given
        let followers = [Follower::Reports(NOT_FOUND), Follower::Reports(NOT_FOUND)];

        // When
        let run = run_attempt(NOT_FOUND, followers, THRESHOLD).await;

        // Then
        let signed = run.leader_result.unwrap();
        let NodeOutcome::Verdict(not_found) = NOT_FOUND else {
            unreachable!()
        };
        assert_eq!(signed.verdict, not_found);
        let expected_hash = request()
            .sign_payload(not_found.into())
            .unwrap()
            .compute_msg_hash()
            .unwrap();
        assert_eq!(signed.payload_hash, expected_hash);
        let msg_hash = Scalar::from_repr(expected_hash.0.into()).unwrap();
        assert!(
            signed
                .signature
                .verify(&signed.public_key.to_element().to_affine(), &msg_hash)
        );
        assert_eq!(run.evidence.len(), THRESHOLD);
    })
    .await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn v2_leader_computation__should_end_the_attempt_at_once_when_verdicts_differ() {
    start_root_task_with_periodic_dump(async {
        // Given
        let followers = [Follower::Reports(VERIFIED), Follower::Reports(NOT_FOUND)];

        // When
        let run = run_attempt(VERIFIED, followers, THRESHOLD).await;

        // Then
        assert_matches!(
            run.leader_result.err(),
            Some(AttemptFailure::Disagreement(
                AttemptEnd::VerdictsDiffer { .. }
            ))
        );
        assert!(run.elapsed < FAIL_FAST_BOUND, "took {:?}", run.elapsed);
        assert_eq!(signers(&run.evidence), run.participants);
    })
    .await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn v2_leader_computation__should_end_the_attempt_at_once_when_a_node_has_no_verdict() {
    start_root_task_with_periodic_dump(async {
        // Given
        let no_verdict = NodeOutcome::NoVerdict(NoVerdictReason::Transient);
        let followers = [Follower::Reports(VERIFIED), Follower::Reports(no_verdict)];

        // When
        let run = run_attempt(VERIFIED, followers, THRESHOLD).await;

        // Then
        assert_matches!(
            run.leader_result.err(),
            Some(AttemptFailure::Transient { participant }) if participant == run.participants[2]
        );
        assert!(run.elapsed < FAIL_FAST_BOUND, "took {:?}", run.elapsed);
        assert_eq!(signers(&run.evidence), run.participants);
    })
    .await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn v2_leader_computation__should_end_the_attempt_at_once_when_a_follower_refuses() {
    start_root_task_with_periodic_dump(async {
        // Given
        let followers = [Follower::Reports(VERIFIED), Follower::Refuses];

        // When
        let run = run_attempt(VERIFIED, followers, 2).await;

        // Then
        assert_matches!(
            run.leader_result.err(),
            Some(AttemptFailure::Aborted(aborted)) if aborted.participant == run.participants[2]
        );
        assert!(run.elapsed < FAIL_FAST_BOUND, "took {:?}", run.elapsed);
        assert_eq!(signers(&run.evidence), run.participants[..2]);
    })
    .await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn v2_leader_computation__should_keep_an_outcome_that_arrives_after_the_attempt_ended() {
    start_root_task_with_periodic_dump(async {
        // Given
        let late = Follower::ReportsLate(
            NodeOutcome::NoVerdict(NoVerdictReason::Transient),
            Arc::new(Notify::new()),
        );
        let followers = [Follower::Reports(NOT_FOUND), late];

        // When
        let run = run_attempt(VERIFIED, followers, THRESHOLD).await;

        // Then
        assert!(run.leader_result.is_err());
        assert_eq!(signers(&run.evidence), run.participants);
        let late_statement = run.evidence.last().unwrap();
        assert_eq!(
            late_statement.outcome,
            NodeOutcome::NoVerdict(NoVerdictReason::Transient)
        );
    })
    .await;
}

#[test_log::test(tokio::test(start_paused = true))]
async fn v2_leader_computation__should_fail_thirteen_seconds_after_start_when_a_follower_stays_silent()
 {
    start_root_task_with_periodic_dump(async {
        // Given
        let followers = [
            Follower::Reports(VERIFIED),
            Follower::Silent(Arc::new(Notify::new())),
        ];

        // When
        let run = run_attempt(VERIFIED, followers, 2).await;

        // Then
        assert_matches!(
            run.leader_result.err(),
            Some(AttemptFailure::DeadlineExceeded { silent })
                if silent == BTreeSet::from([run.participants[2]])
        );
        assert_eq!(run.elapsed, Duration::from_secs(13));
    })
    .await;
}
