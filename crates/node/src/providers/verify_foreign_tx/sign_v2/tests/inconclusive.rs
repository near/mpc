use super::follower::{TestProvider, attempt_participants, leader_of_rank};
use super::leader::DealtShares;
use super::*;
use crate::network::computation::ComputationTimeout;
use crate::network::testing::run_test_clients;
use crate::network::wire_format::MpcTaskId;
use crate::primitives::ChannelId;
use crate::providers::ecdsa::OnlinePresignSignComputation;
use crate::providers::verify_foreign_tx::inconclusive_evidence::{
    InconclusiveCause, InconclusiveEvidence,
};
use crate::providers::verify_foreign_tx::inconclusive_round::InconclusiveRoundComputation;
use crate::tests::into_participant_ids;
use crate::tracking::testing::start_root_task_with_periodic_dump;
use k256::Scalar;
use k256::elliptic_curve::PrimeField;
use near_mpc_contract_interface::types::Tweak;
use std::collections::HashMap;
use threshold_signatures::test_utils::generate_participants;
use tokio::sync::Notify;

/// Evidence that the first two of `participants` found different verdicts in an attempt of
/// `leader`.
fn disagreement(leader: ParticipantId, participants: &[ParticipantId]) -> InconclusiveEvidence {
    let attempt = AttemptId(ChannelId(UniqueId::new(leader, 1, 0)));
    let outcomes = [(participants[0], VERIFIED), (participants[1], NOT_FOUND)]
        .map(|(signer, outcome)| {
            let statement = NodeOutcomeStatement {
                yield_id: request().yield_id,
                leader,
                attempt,
                signer,
                outcome,
            };
            signing_key(signer)
                .sign(statement)
                .unwrap()
                .verify(&keys(participants))
                .unwrap()
        })
        .to_vec();
    InconclusiveEvidence {
        cause: InconclusiveCause::VerdictsDiffer {
            first: participants[0],
            second: participants[1],
        },
        outcomes,
    }
}

fn inconclusive_payload_hash() -> dtos::Hash256 {
    request()
        .sign_payload(dtos::ForeignTxVerificationOutcome::Inconclusive {})
        .unwrap()
        .compute_msg_hash()
        .unwrap()
}

/// What a simulated signer does once it receives the Start of an inconclusive round.
#[derive(Clone)]
enum Signer {
    Signs,
    /// Sends nothing until the leader's round ended.
    Silent(Arc<Notify>),
}

struct RoundRun {
    leader_result: anyhow::Result<SignedOutcome>,
    elapsed: Duration,
    evidence: InconclusiveEvidence,
}

enum ClientRun {
    Leader(Box<RoundRun>),
    /// The node outcomes a signer received from the leader.
    Signer(Vec<SignedNodeOutcome>),
}

/// Runs one inconclusive round among three participants, where each signer acts as given.
/// Returns the leader's run, and the node outcomes each signer that signs received.
async fn run_round(signers: [Signer; 2]) -> (RoundRun, Vec<Vec<SignedNodeOutcome>>) {
    let ts_participants = generate_participants(THRESHOLD);
    let participants = into_participant_ids(&ts_participants);
    let leader = participants[0];
    let shares = Arc::new(DealtShares::new(&ts_participants));
    let behaviours: Arc<HashMap<ParticipantId, Signer>> =
        Arc::new(participants[1..].iter().copied().zip(signers).collect());
    let evidence = disagreement(leader, &participants);

    let results = run_test_clients(participants.clone(), move |client, mut receiver| {
        let shares = shares.clone();
        let participants = participants.clone();
        let behaviours = behaviours.clone();
        let evidence = evidence.clone();
        async move {
            let me = client.my_participant_id();
            let (keygen_out, triples) = shares.by_participant[&me].clone();
            if me != leader {
                let mut channel = receiver.recv().await.context("no channel received")?;
                let received = match behaviours[&me].clone() {
                    Signer::Silent(leader_done) => {
                        leader_done.notified().await;
                        Vec::new()
                    }
                    Signer::Signs => {
                        let PeerNodeOutcomes { outcomes, .. } =
                            channel.receive_node_outcomes().await?;
                        OnlinePresignSignComputation {
                            keygen_out,
                            reconstruction_threshold: ReconstructionThreshold::from(THRESHOLD),
                            triples,
                            msg_hash: inconclusive_payload_hash().into(),
                            tweak: Tweak::new([0; 32]),
                        }
                        .perform_leader_centric_computation(channel, Duration::from_mins(1))
                        .await
                        .inspect_err(|err| tracing::info!(%me, %err, "signer ended"))
                        .ok();
                        outcomes
                    }
                };
                return Ok(ClientRun::Signer(received));
            }
            let channel = client.new_channel_for_task(
                VerifyForeignTxTaskId::Inconclusive {
                    yield_id: request().yield_id,
                    paired_triple_id: UniqueId::new(me, 1, 1),
                },
                participants,
            )?;
            let started = tokio::time::Instant::now();
            let leader_result = InconclusiveRoundComputation {
                evidence: evidence.clone(),
                signing: OutcomeSigning {
                    request: request(),
                    keygen_out,
                    reconstruction_threshold: ReconstructionThreshold::from(THRESHOLD),
                    triples,
                },
            }
            .run(channel)
            .await;
            let elapsed = started.elapsed();
            for behaviour in behaviours.values() {
                if let Signer::Silent(leader_done) = behaviour {
                    leader_done.notify_one();
                }
            }
            Ok(ClientRun::Leader(Box::new(RoundRun {
                leader_result,
                elapsed,
                evidence,
            })))
        }
    })
    .await
    .unwrap();
    let mut leader_run = None;
    let mut received = Vec::new();
    for result in results {
        match result {
            ClientRun::Leader(run) => leader_run = Some(*run),
            ClientRun::Signer(outcomes) if !outcomes.is_empty() => received.push(outcomes),
            ClientRun::Signer(_) => {}
        }
    }
    (leader_run.unwrap(), received)
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn inconclusive_round_computation__should_show_the_evidence_and_sign_the_inconclusive() {
    start_root_task_with_periodic_dump(async {
        // When
        let (run, received) = run_round([Signer::Signs, Signer::Signs]).await;

        // Then
        let signed = run.leader_result.unwrap();
        assert_eq!(
            signed.outcome,
            dtos::ForeignTxVerificationOutcome::Inconclusive {}
        );
        assert_eq!(signed.payload_hash, inconclusive_payload_hash());
        let msg_hash = Scalar::from_repr(signed.payload_hash.0.into()).unwrap();
        assert!(
            signed
                .signature
                .verify(&signed.public_key.to_element().to_affine(), &msg_hash)
        );
        assert_eq!(received, vec![run.evidence.signed_outcomes(); 2]);
    })
    .await;
}

#[test_log::test(tokio::test(start_paused = true))]
async fn inconclusive_round_computation__should_fail_five_seconds_after_start_when_a_signer_stays_silent()
 {
    start_root_task_with_periodic_dump(async {
        // When
        let (run, _) = run_round([Signer::Signs, Signer::Silent(Arc::new(Notify::new()))]).await;

        // Then
        let error = run.leader_result.err().unwrap();
        assert!(error.is::<ComputationTimeout>(), "{error:#}");
        assert_eq!(run.elapsed, Duration::from_secs(5));
    })
    .await;
}

/// The Start of an inconclusive round at `request()` between the [`attempt_participants`], seen
/// from the signer.
struct InconclusiveFollowerRun {
    leader_rank: usize,
    open_requests: Arc<OpenVerifyForeignTxRequestsV2>,
    /// The participant whose triple pair the round names, the leader when `None`.
    triple_owner: Option<ParticipantId>,
}

impl InconclusiveFollowerRun {
    fn new(open_requests: Arc<OpenVerifyForeignTxRequestsV2>) -> Self {
        Self {
            leader_rank: 0,
            open_requests,
            triple_owner: None,
        }
    }

    /// The reason the leader receives once the signer refuses.
    async fn refusal(self) -> String {
        let Self {
            leader_rank,
            open_requests,
            triple_owner,
        } = self;
        let participants = attempt_participants();
        let leader = leader_of_rank(leader_rank);
        let results = run_test_clients(participants.clone(), move |client, mut receiver| {
            let participants = participants.clone();
            let open_requests = open_requests.clone();
            async move {
                let me = client.my_participant_id();
                if me == leader {
                    let mut channel = client.new_channel_for_task(
                        VerifyForeignTxTaskId::Inconclusive {
                            yield_id: request().yield_id,
                            paired_triple_id: UniqueId::new(triple_owner.unwrap_or(leader), 1, 0),
                        },
                        participants,
                    )?;
                    channel.sender().send_evidence(Vec::new())?;
                    let refusal = match channel.receive().await {
                        Ok(_) => "the signer did not refuse".to_string(),
                        Err(err) => err.to_string(),
                    };
                    return Ok(vec![refusal]);
                }
                let channel = receiver.recv().await.context("no channel received")?;
                let MpcTaskId::VerifyForeignTxTaskId(VerifyForeignTxTaskId::Inconclusive {
                    yield_id,
                    paired_triple_id,
                }) = channel.task_id()
                else {
                    anyhow::bail!("unexpected task {:?}", channel.task_id());
                };
                let node = TestProvider::with_ethereum_supporters(
                    client,
                    "http://127.0.0.1:1",
                    open_requests,
                    &attempt_participants(),
                );
                let _ = node
                    .provider
                    .make_verify_foreign_tx_inconclusive_follower(
                        channel,
                        yield_id,
                        paired_triple_id,
                    )
                    .await;
                Ok(vec![])
            }
        })
        .await
        .unwrap();
        results.into_iter().flatten().next().unwrap()
    }
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn make_verify_foreign_tx_inconclusive_follower__should_refuse_a_node_that_is_not_an_acting_leader()
 {
    start_root_task_with_periodic_dump(async {
        // Given
        let backup_before_its_turn = 1;

        // When
        let refusal = InconclusiveFollowerRun {
            leader_rank: backup_before_its_turn,
            ..InconclusiveFollowerRun::new(open_requests_with(request()))
        }
        .refusal()
        .await;

        // Then
        assert!(refusal.contains("is not an acting leader"), "{refusal}");
    })
    .await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn make_verify_foreign_tx_inconclusive_follower__should_refuse_a_fourth_round_of_one_leader()
{
    start_root_task_with_periodic_dump(async {
        // Given
        let open_requests = open_requests_with(request());
        for _ in 0..3 {
            open_requests
                .join_inconclusive_round(request().id, leader_of_rank(0))
                .unwrap();
        }

        // When
        let refusal = InconclusiveFollowerRun::new(open_requests).refusal().await;

        // Then
        assert!(
            refusal.contains("already joined 3 inconclusive rounds"),
            "{refusal}"
        );
    })
    .await;
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn make_verify_foreign_tx_inconclusive_follower__should_refuse_a_triple_pair_of_another_node()
{
    start_root_task_with_periodic_dump(async {
        // Given
        let signer = leader_of_rank(1);

        // When
        let refusal = InconclusiveFollowerRun {
            triple_owner: Some(signer),
            ..InconclusiveFollowerRun::new(open_requests_with(request()))
        }
        .refusal()
        .await;

        // Then
        assert!(refusal.contains("belongs to participant"), "{refusal}");
    })
    .await;
}
