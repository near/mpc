use super::*;

const TRANSIENT: NodeOutcome = NodeOutcome::NoVerdict(NoVerdictReason::Transient);

#[test]
fn evidence_to_sign__should_prove_an_inconclusive_with_every_statement_of_a_supporter() {
    // Given
    let supporter_statements = vec![
        signed(0, TRANSIENT),
        signed(1, NodeOutcome::Verdict(NOT_FOUND)),
        signed(2, NodeOutcome::Verdict(NodeVerdict::Verified)),
        signed(3, NodeOutcome::Verdict(NodeVerdict::Verified)),
        signed(3, NodeOutcome::Verdict(NOT_FOUND)),
    ];
    let mut outcomes = supporter_statements.clone();
    outcomes.push(signed(7, NodeOutcome::Verdict(NOT_FOUND)));

    // When
    let to_sign = evidence_to_sign(
        &verified(&outcomes),
        participant(0),
        &participants(&[0, 1, 2, 3]),
        THRESHOLD,
    );

    // Then
    assert_eq!(
        to_sign,
        Ok(Some(RoundEvidence {
            proven: ProvenOutcome::Inconclusive(InconclusiveCause::VerdictsDiffer),
            eligible: participants(&[0, 1, 2]),
            statements: supporter_statements,
        }))
    );
}

#[test]
fn evidence_to_sign__should_wait_for_its_own_outcome_before_an_inconclusive() {
    // Given
    let outcomes = [signed(1, TRANSIENT), signed(2, TRANSIENT)];

    // When
    let to_sign = evidence_to_sign(
        &verified(&outcomes),
        participant(0),
        &participants(&[0, 1, 2, 3]),
        THRESHOLD,
    );

    // Then
    assert_eq!(to_sign, Ok(None));
}

#[test]
fn evidence_to_sign__should_stop_a_leader_that_signed_two_outcomes() {
    // Given
    let outcomes = [
        signed(0, TRANSIENT),
        signed(0, NodeOutcome::Verdict(NOT_FOUND)),
        signed(1, TRANSIENT),
        signed(2, TRANSIENT),
    ];

    // When
    let to_sign = evidence_to_sign(
        &verified(&outcomes),
        participant(0),
        &participants(&[0, 1, 2, 3]),
        THRESHOLD,
    );

    // Then
    assert_eq!(to_sign, Err(StopLeading::ConflictingOwnOutcome));
}

#[test]
fn evidence_to_sign__should_sign_the_verdict_when_one_divergent_node_leaves_t_in_agreement() {
    // Given
    let outcomes = [
        signed(0, NodeOutcome::Verdict(NOT_FOUND)),
        signed(1, NodeOutcome::Verdict(NodeVerdict::Verified)),
        signed(2, NodeOutcome::Verdict(NOT_FOUND)),
        signed(3, NodeOutcome::Verdict(NOT_FOUND)),
    ];

    // When
    let to_sign = evidence_to_sign(
        &verified(&outcomes),
        participant(0),
        &participants(&[0, 1, 2, 3]),
        THRESHOLD,
    );

    // Then
    assert_eq!(
        to_sign.unwrap().map(|evidence| evidence.proven),
        Some(ProvenOutcome::Verdict(NOT_FOUND))
    );
}

#[tokio::test]
async fn round_wait__should_take_an_asset_among_the_heard_supporters_for_an_inconclusive() {
    // Given
    let view = LeaderView::new();
    for signer in [0, 1, 2] {
        view.receive_outcome(signer, TRANSIENT);
    }
    let asset = OneAsset::among(&[0, 1, 2]);

    // When
    let result = tokio::time::timeout(Duration::from_secs(5), view.evidence_and_asset(&asset))
        .await
        .unwrap();

    // Then
    let EvidenceAndAsset { evidence, asset: _ } = result.unwrap();
    assert_eq!(
        evidence.proven,
        ProvenOutcome::Inconclusive(InconclusiveCause::Transient)
    );
    assert_eq!(evidence.outcome(), RoundOutcome::Inconclusive);
    assert_eq!(
        asset.eligible_sets.lock().unwrap().first(),
        Some(&vec![participant(0), participant(1), participant(2)])
    );
}
