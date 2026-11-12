use super::*;
use crate::providers::verify_foreign_tx::node_outcome::NodeOutcome;
use crate::providers::verify_foreign_tx::node_outcome_statement::NodeOutcomeStatement;
use crate::providers::verify_foreign_tx::node_outcome_statement::testing::{
    outcome_public_keys, outcome_signing_key, signed_by_its_signer,
};
use near_mpc_contract_interface::types::ForeignTxVerificationNegativeVerdict;
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
