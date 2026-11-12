use super::*;
use crate::providers::verify_foreign_tx::node_outcome::{NoVerdictReason, NodeOutcome};
use crate::providers::verify_foreign_tx::node_outcome_statement::NodeOutcomeStatement;
use crate::providers::verify_foreign_tx::node_outcome_statement::testing::{
    outcome_public_keys, signed_by_its_signer,
};
use near_mpc_contract_interface::types::{ForeignTxVerificationNegativeVerdict, YieldId};
use std::assert_matches;

const THRESHOLD: usize = 3;
const NOT_FOUND: NodeVerdict =
    NodeVerdict::Negative(ForeignTxVerificationNegativeVerdict::TransactionNotFound);

fn participant(id: u32) -> ParticipantId {
    ParticipantId::from_raw(id)
}

fn participants(ids: &[u32]) -> BTreeSet<ParticipantId> {
    ids.iter().copied().map(participant).collect()
}

fn signed(signer: u32, outcome: NodeOutcome) -> SignedNodeOutcome {
    signed_by_its_signer(NodeOutcomeStatement {
        yield_id: YieldId([4; 32]),
        signer: participant(signer),
        outcome,
    })
}

fn verified(outcomes: &[SignedNodeOutcome]) -> Vec<VerifiedNodeOutcome> {
    let keys = outcome_public_keys(&(0..8).map(participant).collect::<Vec<_>>());
    outcomes
        .iter()
        .map(|outcome| outcome.clone().verify(&keys).unwrap())
        .collect()
}

#[test]
fn verdict_to_sign__should_return_the_backers_statements_once_t_signed_the_verdict() {
    // Given
    let backer_statements = [
        signed(0, NodeOutcome::Verdict(NOT_FOUND)),
        signed(2, NodeOutcome::Verdict(NOT_FOUND)),
        signed(3, NodeOutcome::Verdict(NOT_FOUND)),
    ];
    let mut outcomes = backer_statements.to_vec();
    outcomes.insert(1, signed(1, NodeOutcome::Verdict(NodeVerdict::Verified)));

    // When
    let to_sign = verdict_to_sign(
        &verified(&outcomes),
        participant(0),
        &participants(&[0, 1, 2, 3]),
        THRESHOLD,
    );

    // Then
    assert_eq!(
        to_sign,
        Ok(Some(VerdictEvidence {
            verdict: NOT_FOUND,
            backers: participants(&[0, 2, 3]),
            statements: backer_statements.to_vec(),
        }))
    );
}

#[test]
fn verdict_to_sign__should_wait_while_a_verdict_can_still_reach_t() {
    // Given
    let outcomes = [
        signed(0, NodeOutcome::Verdict(NOT_FOUND)),
        signed(1, NodeOutcome::Verdict(NOT_FOUND)),
    ];

    // When
    let to_sign = verdict_to_sign(
        &verified(&outcomes),
        participant(0),
        &participants(&[0, 1, 2, 3]),
        THRESHOLD,
    );

    // Then
    assert_eq!(to_sign, Ok(None));
}

#[test]
fn verdict_to_sign__should_stop_a_leader_that_did_not_sign_the_verdict() {
    // Given
    let outcomes = [
        signed(0, NodeOutcome::NoVerdict(NoVerdictReason::Transient)),
        signed(1, NodeOutcome::Verdict(NOT_FOUND)),
        signed(2, NodeOutcome::Verdict(NOT_FOUND)),
        signed(3, NodeOutcome::Verdict(NOT_FOUND)),
    ];

    // When
    let to_sign = verdict_to_sign(
        &verified(&outcomes),
        participant(0),
        &participants(&[0, 1, 2, 3]),
        THRESHOLD,
    );

    // Then
    assert_eq!(to_sign, Err(StopLeading::NotABacker(NOT_FOUND)));
}

#[test]
fn verdict_to_sign__should_stop_when_no_verdict_can_reach_t() {
    // Given
    let transient = NodeOutcome::NoVerdict(NoVerdictReason::Transient);
    let outcomes = [signed(0, transient), signed(1, transient)];

    // When
    let to_sign = verdict_to_sign(
        &verified(&outcomes),
        participant(0),
        &participants(&[0, 1, 2, 3]),
        THRESHOLD,
    );

    // Then
    assert_matches!(to_sign, Err(StopLeading::NoVerdictCanReachThreshold));
}

#[test]
fn round_candidates__should_keep_only_backers_that_speak_the_v2_messages() {
    // Given
    let backers = participants(&[0, 2, 3, 5]);
    let v2_capable: HashSet<ParticipantId> = [0, 1, 2, 5].into_iter().map(participant).collect();

    // When
    let candidates = round_candidates(&backers, &v2_capable);

    // Then
    assert_eq!(
        candidates,
        vec![participant(0), participant(2), participant(5)]
    );
}
