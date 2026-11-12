use super::*;
use crate::network::testing::{new_task_channel_for_test, new_test_client};
use crate::network::wire_format::VerifyForeignTxTaskId;
use crate::providers::verify_foreign_tx::node_outcome::NodeOutcome;
use crate::providers::verify_foreign_tx::node_outcome_statement::NodeOutcomeStatement;
use crate::providers::verify_foreign_tx::node_outcome_statement::testing::{
    outcome_public_keys, outcome_signing_key, signed_by_its_signer,
};
use crate::providers::verify_foreign_tx::open_requests::test_chain::TestChain;
use crate::providers::verify_foreign_tx::open_requests::{JoinRoundRefusal, MAX_ROUNDS_PER_LEADER};
use crate::providers::verify_foreign_tx::testing::{TestProvider, bitcoin_request, open_with};
use crate::requests::queue::leader_selection_order;
use near_mpc_contract_interface::types::ForeignTxVerificationNegativeVerdict;
use near_time::FakeClock;
use std::assert_matches;

const THRESHOLD: usize = 3;
const ME: ParticipantId = ParticipantId::from_raw(0);
const YIELD: YieldId = YieldId([4; 32]);
const NOT_FOUND: NodeVerdict =
    NodeVerdict::Negative(ForeignTxVerificationNegativeVerdict::TransactionNotFound);

fn participant(id: u32) -> ParticipantId {
    ParticipantId::from_raw(id)
}

fn statement(signer: u32, outcome: NodeOutcome) -> NodeOutcomeStatement {
    NodeOutcomeStatement {
        yield_id: YIELD,
        signer: participant(signer),
        outcome,
    }
}

fn not_found_by(signers: &[u32]) -> Vec<SignedNodeOutcome> {
    signers
        .iter()
        .map(|signer| signed_by_its_signer(statement(*signer, NodeOutcome::Verdict(NOT_FOUND))))
        .collect()
}

fn outcome_keys() -> OutcomePublicKeys {
    outcome_public_keys(&(0..4).map(participant).collect::<Vec<_>>())
}

fn supporters() -> BTreeSet<ParticipantId> {
    (0..4).map(participant).collect()
}

fn check(evidence: Vec<SignedNodeOutcome>, own: &[SignedNodeOutcome]) -> Result<(), RoundRefusal> {
    let outcome_keys = outcome_keys();
    let own: Vec<VerifiedNodeOutcome> = own
        .iter()
        .map(|outcome| outcome.clone().verify(&outcome_keys).unwrap())
        .collect();
    VerdictCheck {
        me: ME,
        yield_id: YIELD,
        verdict: NOT_FOUND,
        outcome_keys: &outcome_keys,
        supporters: &supporters(),
        threshold: THRESHOLD,
    }
    .check(evidence, &own)
}

#[test]
fn verdict_check__should_accept_t_backers_including_this_node() {
    // Given
    let evidence = not_found_by(&[0, 1, 2]);

    // When
    let checked = check(evidence, &not_found_by(&[0]));

    // Then
    checked.unwrap();
}

#[test]
fn verdict_check__should_refuse_evidence_without_its_own_statement() {
    // Given
    let evidence = not_found_by(&[1, 2, 3]);

    // When
    let checked = check(evidence, &not_found_by(&[0]));

    // Then
    assert_matches!(checked, Err(RoundRefusal::WithoutOwnStatement));
}

#[test]
fn verdict_check__should_refuse_a_forged_statement() {
    // Given
    let mut evidence = not_found_by(&[0, 1]);
    evidence.push(
        outcome_signing_key(participant(1))
            .sign(statement(2, NodeOutcome::Verdict(NOT_FOUND)))
            .unwrap(),
    );

    // When
    let checked = check(evidence, &not_found_by(&[0]));

    // Then
    assert_matches!(
        checked,
        Err(RoundRefusal::Unverified(
            NodeOutcomeVerificationError::BadSignature
        ))
    );
}

#[test]
fn verdict_check__should_refuse_a_statement_for_another_yield() {
    // Given
    let mut evidence = not_found_by(&[0, 1]);
    evidence.push(signed_by_its_signer(NodeOutcomeStatement {
        yield_id: YieldId([5; 32]),
        ..statement(2, NodeOutcome::Verdict(NOT_FOUND))
    }));

    // When
    let checked = check(evidence, &not_found_by(&[0]));

    // Then
    assert_matches!(checked, Err(RoundRefusal::OtherYield));
}

#[test]
fn verdict_check__should_refuse_a_verdict_this_node_did_not_sign() {
    // Given
    let mut evidence = not_found_by(&[1, 2, 3]);
    evidence.push(signed_by_its_signer(statement(
        0,
        NodeOutcome::Verdict(NodeVerdict::Verified),
    )));

    // When
    let checked = check(evidence, &[]);

    // Then
    assert_matches!(checked, Err(RoundRefusal::NotABacker(NOT_FOUND)));
}

#[test]
fn verdict_check__should_refuse_when_its_own_statement_conflicts_with_the_evidence() {
    // Given
    let evidence = not_found_by(&[0, 1, 2]);
    let own_after_restart =
        signed_by_its_signer(statement(0, NodeOutcome::Verdict(NodeVerdict::Verified)));

    // When
    let checked = check(evidence, &[own_after_restart]);

    // Then
    assert_matches!(checked, Err(RoundRefusal::NotABacker(NOT_FOUND)));
}

#[test]
fn verdict_check__should_refuse_fewer_than_t_backers() {
    // Given
    let evidence = not_found_by(&[0, 1]);

    // When
    let checked = check(evidence, &not_found_by(&[0]));

    // Then
    assert_matches!(
        checked,
        Err(RoundRefusal::BelowThreshold {
            backers: 2,
            threshold: THRESHOLD,
            ..
        })
    );
}

#[test]
fn verdict_check__should_not_count_a_signer_that_does_not_support_the_chain() {
    // Given
    let mut evidence = not_found_by(&[0, 1]);
    let keys = outcome_public_keys(&(0..8).map(participant).collect::<Vec<_>>());
    evidence.extend(not_found_by(&[6]));

    // When
    let checked = VerdictCheck {
        me: ME,
        yield_id: YIELD,
        verdict: NOT_FOUND,
        outcome_keys: &keys,
        supporters: &supporters(),
        threshold: THRESHOLD,
    }
    .check(evidence, &[]);

    // Then
    assert_matches!(
        checked,
        Err(RoundRefusal::BelowThreshold { backers: 2, .. })
    );
}

#[test]
fn verdict_check__should_refuse_more_statements_than_supporters_before_verifying_them() {
    // Given
    let mut evidence = not_found_by(&[0, 1, 2, 3]);
    evidence.push(
        outcome_signing_key(participant(1))
            .sign(statement(2, NodeOutcome::Verdict(NOT_FOUND)))
            .unwrap(),
    );

    // When
    let checked = check(evidence, &not_found_by(&[0]));

    // Then
    assert_matches!(
        checked,
        Err(RoundRefusal::TooManyStatements {
            statements: 5,
            supporters: 4,
        })
    );
}

#[tokio::test]
async fn check_round__should_refuse_a_sender_that_is_not_an_acting_leader_before_its_evidence() {
    // Given
    let participants: Vec<_> = (0..3).map(participant).collect();
    let order = leader_selection_order(&participants, bitcoin_request().id);
    let (backup, me) = (order[1], order[2]);
    let (open_requests, _chain) = open_with(bitcoin_request(), FakeClock::default().clock());
    let node = TestProvider::new(
        new_test_client(order.clone(), me),
        open_requests,
        bitcoin_request().request.chain(),
        order.iter().copied().collect(),
    );
    let round_id = UniqueId::new(backup, 1, 0);
    let (mut channel, _from_peers) = new_task_channel_for_test(
        VerifyForeignTxTaskId::SignOutcome {
            yield_id: bitcoin_request().yield_id,
            outcome: RoundOutcome::Verdict(NOT_FOUND),
            paired_triple_id: round_id,
        }
        .into(),
        backup,
        me,
        order,
    );

    // When
    let checked = node
        .provider
        .check_round(
            &mut channel,
            bitcoin_request().yield_id,
            RoundOutcome::Verdict(NOT_FOUND),
        )
        .await;

    // Then
    assert_matches!(
        checked.unwrap_err().downcast_ref::<RoundRefusal>(),
        Some(RoundRefusal::Leader(LeaderRefusal::NotActing(leader))) if *leader == backup
    );
}

/// A signer for which [`bitcoin_request`] is open, among three participants that all support
/// Bitcoin and have an outcome key, with a signing threshold of two.
struct JoiningSigner {
    node: TestProvider,
    _chain: TestChain,
}

impl JoiningSigner {
    const THRESHOLD: usize = 2;

    fn new() -> Self {
        let participants: Vec<_> = (0..3).map(participant).collect();
        let network = new_test_client(participants.clone(), ME);
        network
            .node_outcomes()
            .set_outcome_keys(outcome_public_keys(&participants));
        let (open_requests, chain) = open_with(bitcoin_request(), FakeClock::default().clock());
        let node = TestProvider::new(
            network,
            open_requests,
            bitcoin_request().request.chain(),
            participants.into_iter().collect(),
        );
        Self {
            node,
            _chain: chain,
        }
    }

    fn join(&self, leader: ParticipantId, evidence_by: &[u32]) -> Result<(), RoundRefusal> {
        let evidence = evidence_by
            .iter()
            .map(|signer| {
                signed_by_its_signer(NodeOutcomeStatement {
                    yield_id: bitcoin_request().yield_id,
                    signer: participant(*signer),
                    outcome: NodeOutcome::Verdict(NOT_FOUND),
                })
            })
            .collect();
        self.node.provider.join_round_with_evidence(
            &bitcoin_request(),
            ActingLeader::assumed(bitcoin_request().id, leader),
            NOT_FOUND,
            evidence,
            Self::THRESHOLD,
        )
    }
}

#[tokio::test]
async fn join_round_with_evidence__should_refuse_a_round_past_the_limit_per_leader() {
    // Given
    let signer = JoiningSigner::new();
    let leader = participant(1);
    let joined: Vec<_> = (0..MAX_ROUNDS_PER_LEADER)
        .map(|_| signer.join(leader, &[0, 1]))
        .collect();

    // When
    let past_the_limit = signer.join(leader, &[0, 1]);

    // Then
    assert!(joined.iter().all(Result::is_ok), "{joined:?}");
    assert_matches!(
        past_the_limit,
        Err(RoundRefusal::Join(JoinRoundRefusal::RoundLimit(refused))) if refused == leader
    );
}

#[tokio::test]
async fn join_round_with_evidence__should_not_count_a_refused_round() {
    // Given
    let signer = JoiningSigner::new();
    let leader = participant(1);
    let refused = signer.join(leader, &[1, 2]);

    // When
    let joined: Vec<_> = (0..MAX_ROUNDS_PER_LEADER)
        .map(|_| signer.join(leader, &[0, 1]))
        .collect();

    // Then
    assert_matches!(refused, Err(RoundRefusal::WithoutOwnStatement));
    assert!(joined.iter().all(Result::is_ok), "{joined:?}");
}
