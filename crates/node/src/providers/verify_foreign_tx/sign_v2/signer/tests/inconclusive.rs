use super::*;
use crate::providers::verify_foreign_tx::node_outcome::NoVerdictReason;

const TRANSIENT: NodeOutcome = NodeOutcome::NoVerdict(NoVerdictReason::Transient);
const VERIFIED: NodeOutcome = NodeOutcome::Verdict(NodeVerdict::Verified);

fn signed(signer: u32, outcome: NodeOutcome) -> SignedNodeOutcome {
    signed_by_its_signer(statement(signer, outcome))
}

fn check_inconclusive(
    evidence: Vec<SignedNodeOutcome>,
    own: &[SignedNodeOutcome],
) -> Result<(), RoundRefusal> {
    let outcome_keys = outcome_keys();
    let own: Vec<VerifiedNodeOutcome> = own
        .iter()
        .map(|outcome| outcome.clone().verify(&outcome_keys).unwrap())
        .collect();
    EvidenceCheck {
        me: ME,
        yield_id: YIELD,
        outcome: RoundOutcome::Inconclusive,
        participants: &round_participants(),
        outcome_keys: &outcome_keys,
        supporters: &supporters(),
        threshold: THRESHOLD,
    }
    .check(evidence, &own)
}

#[test]
fn evidence_check__should_accept_an_inconclusive_with_transient_errors_from_s_minus_t_plus_one() {
    // Given
    let evidence = vec![
        signed(0, TRANSIENT),
        signed(1, TRANSIENT),
        signed(2, VERIFIED),
    ];

    // When
    let checked = check_inconclusive(evidence, &[signed(0, TRANSIENT)]);

    // Then
    checked.unwrap();
}

#[test]
fn evidence_check__should_refuse_an_inconclusive_with_transient_errors_from_s_minus_t() {
    // Given
    let evidence = vec![
        signed(0, TRANSIENT),
        signed(1, VERIFIED),
        signed(2, VERIFIED),
    ];

    // When
    let checked = check_inconclusive(evidence, &[signed(0, TRANSIENT)]);

    // Then
    assert_matches!(checked, Err(RoundRefusal::VerdictCanReachThreshold));
}

#[test]
fn evidence_check__should_refuse_an_inconclusive_when_the_left_out_statement_could_make_t() {
    // Given
    let not_found = NodeOutcome::Verdict(NOT_FOUND);
    let evidence = vec![
        signed(0, TRANSIENT),
        signed(1, not_found),
        signed(2, not_found),
    ];

    // When
    let checked = check_inconclusive(evidence, &[signed(0, TRANSIENT)]);

    // Then
    assert_matches!(checked, Err(RoundRefusal::VerdictCanReachThreshold));
}

#[test]
fn evidence_check__should_refuse_an_inconclusive_without_a_statement_of_a_round_participant() {
    // Given
    let evidence = vec![signed(0, TRANSIENT), signed(1, TRANSIENT)];

    // When
    let checked = check_inconclusive(evidence, &[signed(0, TRANSIENT)]);

    // Then
    assert_matches!(
        checked,
        Err(RoundRefusal::ParticipantNotHeard(missing)) if missing == participant(2)
    );
}

#[test]
fn evidence_check__should_refuse_an_inconclusive_when_its_own_statement_conflicts() {
    // Given
    let evidence = vec![
        signed(0, TRANSIENT),
        signed(1, TRANSIENT),
        signed(2, VERIFIED),
    ];
    let own_after_restart = signed(0, NodeOutcome::Verdict(NOT_FOUND));

    // When
    let checked = check_inconclusive(evidence, &[own_after_restart]);

    // Then
    assert_matches!(checked, Err(RoundRefusal::ParticipantNotHeard(ME)));
}

#[test]
fn evidence_check__should_refuse_an_inconclusive_without_its_own_statement() {
    // Given
    let evidence = vec![
        signed(1, TRANSIENT),
        signed(2, TRANSIENT),
        signed(3, VERIFIED),
    ];

    // When
    let checked = check_inconclusive(evidence, &[]);

    // Then
    assert_matches!(checked, Err(RoundRefusal::WithoutOwnStatement));
}

#[test]
fn evidence_check__should_refuse_more_than_two_statements_per_supporter_before_verifying_them() {
    // Given
    let forged = outcome_signing_key(participant(1))
        .sign(statement(2, TRANSIENT))
        .unwrap();
    let evidence = vec![forged; 9];

    // When
    let checked = check_inconclusive(evidence, &[]);

    // Then
    assert_matches!(
        checked,
        Err(RoundRefusal::TooManyStatements {
            statements: 9,
            max: 8,
        })
    );
}

#[tokio::test]
async fn check_round__should_refuse_an_inconclusive_from_a_sender_that_is_not_an_acting_leader() {
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
    let (mut channel, _from_peers) = new_task_channel_for_test(
        VerifyForeignTxTaskId::SignOutcome {
            yield_id: bitcoin_request().yield_id,
            outcome: RoundOutcome::Inconclusive,
            paired_triple_id: UniqueId::new(backup, 1, 0),
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
            RoundOutcome::Inconclusive,
        )
        .await;

    // Then
    assert_matches!(
        checked.unwrap_err().downcast_ref::<RoundRefusal>(),
        Some(RoundRefusal::Leader(LeaderRefusal::NotActing(leader))) if *leader == backup
    );
}

#[tokio::test]
async fn join_round_with_evidence__should_count_verdict_and_inconclusive_rounds_against_one_limit()
{
    // Given
    let signer = JoiningSigner::new();
    let leader = participant(1);
    let inconclusive_evidence = || {
        vec![
            signed_for_request(0, TRANSIENT),
            signed_for_request(1, TRANSIENT),
        ]
    };
    let verdict_rounds: Vec<_> = (0..MAX_ROUNDS_PER_LEADER - 1)
        .map(|_| signer.join(leader, &[0, 1]))
        .collect();
    let inconclusive_round =
        signer.join_with(leader, RoundOutcome::Inconclusive, inconclusive_evidence());

    // When
    let past_the_limit =
        signer.join_with(leader, RoundOutcome::Inconclusive, inconclusive_evidence());

    // Then
    assert!(
        verdict_rounds.iter().all(Result::is_ok),
        "{verdict_rounds:?}"
    );
    inconclusive_round.unwrap();
    assert_matches!(
        past_the_limit,
        Err(RoundRefusal::Join(JoinRoundRefusal::RoundLimit(refused))) if refused == leader
    );
}
