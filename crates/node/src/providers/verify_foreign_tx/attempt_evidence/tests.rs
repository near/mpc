use super::*;
use crate::config::{ParticipantInfo, PersistentSecrets};
use crate::primitives::{ChannelId, UniqueId};
use crate::providers::verify_foreign_tx::node_outcome::{NodeOutcome, NodeVerdict};
use crate::providers::verify_foreign_tx::node_outcome_statement::{
    NodeOutcomeSigningKey, NodeOutcomeStatement,
};
use ed25519_dalek::SigningKey;
use rstest::rstest;
use std::assert_matches;

const LEADER: ParticipantId = ParticipantId::from_raw(1);
const FOLLOWER: ParticipantId = ParticipantId::from_raw(2);
const OUTSIDER: ParticipantId = ParticipantId::from_raw(3);
const YIELD: YieldId = YieldId([7; 32]);

fn tls_key(participant: ParticipantId) -> SigningKey {
    SigningKey::from_bytes(&[u8::try_from(participant.raw()).unwrap(); 32])
}

fn keys() -> Arc<ParticipantsConfig> {
    let participants = [LEADER, FOLLOWER, OUTSIDER]
        .into_iter()
        .map(|id| ParticipantInfo {
            id,
            address: "127.0.0.1".to_string(),
            port: 3000,
            p2p_public_key: tls_key(id).verifying_key(),
            near_account_id: format!("p{}.near", id.raw()).parse().unwrap(),
        })
        .collect();
    Arc::new(ParticipantsConfig {
        threshold: 2,
        participants,
    })
}

fn attempt_id(counter: u32) -> AttemptId {
    AttemptId(ChannelId(UniqueId::new(LEADER, 1_700_000_000, counter)))
}

fn led_attempt(counter: u32) -> LedAttempt {
    led_attempt_at(counter, YIELD)
}

fn led_attempt_at(counter: u32, yield_id: YieldId) -> LedAttempt {
    LedAttempt {
        id: attempt_id(counter),
        yield_id,
        leader: LEADER,
        participants: vec![LEADER, FOLLOWER],
        keys: keys(),
    }
}

fn statement(signer: ParticipantId) -> NodeOutcomeStatement {
    NodeOutcomeStatement {
        yield_id: YIELD,
        leader: LEADER,
        attempt: attempt_id(1),
        signer,
        outcome: NodeOutcome::Verdict(NodeVerdict::Verified),
    }
}

fn signed_by(key_owner: ParticipantId, statement: NodeOutcomeStatement) -> SignedNodeOutcome {
    NodeOutcomeSigningKey::from(&PersistentSecrets {
        p2p_private_key: tls_key(key_owner),
        near_signer_key: SigningKey::from_bytes(&[0xff; 32]),
    })
    .sign(statement)
    .unwrap()
}

fn signed(signer: ParticipantId) -> SignedNodeOutcome {
    signed_by(signer, statement(signer))
}

#[test]
fn led_attempt_accept__should_accept_the_outcome_a_participant_signed_for_this_attempt() {
    // Given
    let attempt = led_attempt(1);

    // When
    let accepted = attempt.accept(FOLLOWER, vec![signed(FOLLOWER)]);

    // Then
    assert_eq!(accepted.unwrap().statement(), &statement(FOLLOWER));
}

#[rstest]
#[case::none(vec![])]
#[case::two(vec![signed(FOLLOWER), signed(FOLLOWER)])]
fn led_attempt_accept__should_reject_a_message_without_exactly_one_outcome(
    #[case] outcomes: Vec<SignedNodeOutcome>,
) {
    // Given
    let attempt = led_attempt(1);

    // When
    let accepted = attempt.accept(FOLLOWER, outcomes);

    // Then
    assert_matches!(accepted, Err(NodeOutcomeRejection::NotExactlyOne(_)));
}

#[test]
fn led_attempt_accept__should_reject_an_outcome_from_outside_the_attempt() {
    // Given
    let attempt = led_attempt(1);

    // When
    let accepted = attempt.accept(OUTSIDER, vec![signed(OUTSIDER)]);

    // Then
    assert_matches!(accepted, Err(NodeOutcomeRejection::NotInAttempt(OUTSIDER)));
}

#[test]
fn led_attempt_accept__should_reject_an_outcome_another_participant_signed() {
    // Given
    let attempt = led_attempt(1);

    // When
    let accepted = attempt.accept(FOLLOWER, vec![signed(LEADER)]);

    // Then
    assert_matches!(
        accepted,
        Err(NodeOutcomeRejection::SignedByAnother {
            from: FOLLOWER,
            signer: LEADER
        })
    );
}

#[test]
fn led_attempt_accept__should_reject_an_outcome_for_another_leader() {
    // Given
    let attempt = led_attempt(1);
    let outcome = signed_by(
        FOLLOWER,
        NodeOutcomeStatement {
            leader: OUTSIDER,
            ..statement(FOLLOWER)
        },
    );

    // When
    let accepted = attempt.accept(FOLLOWER, vec![outcome]);

    // Then
    assert_matches!(accepted, Err(NodeOutcomeRejection::OtherLeader(OUTSIDER)));
}

#[test]
fn led_attempt_accept__should_reject_an_outcome_for_another_attempt() {
    // Given
    let attempt = led_attempt(2);

    // When
    let accepted = attempt.accept(FOLLOWER, vec![signed(FOLLOWER)]);

    // Then
    assert_matches!(accepted, Err(NodeOutcomeRejection::OtherAttempt));
}

#[test]
fn led_attempt_accept__should_reject_an_outcome_for_another_yield() {
    // Given
    let attempt = led_attempt(1);
    let outcome = signed_by(
        FOLLOWER,
        NodeOutcomeStatement {
            yield_id: YieldId([8; 32]),
            ..statement(FOLLOWER)
        },
    );

    // When
    let accepted = attempt.accept(FOLLOWER, vec![outcome]);

    // Then
    assert_matches!(accepted, Err(NodeOutcomeRejection::OtherYield));
}

#[test]
fn led_attempt_accept__should_reject_a_signature_from_another_key() {
    // Given
    let attempt = led_attempt(1);

    // When
    let accepted = attempt.accept(FOLLOWER, vec![signed_by(LEADER, statement(FOLLOWER))]);

    // Then
    assert_matches!(
        accepted,
        Err(NodeOutcomeRejection::Verification(
            NodeOutcomeVerificationError::BadSignature
        ))
    );
}

#[test]
fn attempt_evidence_record_received__should_keep_one_outcome_per_participant() {
    // Given
    let evidence = AttemptEvidence::new();
    evidence.open(led_attempt(1));
    evidence
        .record_received(FOLLOWER, attempt_id(1), vec![signed(FOLLOWER)])
        .unwrap();

    // When
    let second = evidence.record_received(FOLLOWER, attempt_id(1), vec![signed(FOLLOWER)]);

    // Then
    assert_matches!(second, Err(ReceivedNodeOutcomeError::AlreadyKept(FOLLOWER)));
    let kept: Vec<_> = evidence
        .outcomes_for(YIELD)
        .iter()
        .map(|outcome| outcome.statement().clone())
        .collect();
    assert_eq!(kept, vec![statement(FOLLOWER)]);
}

#[test]
fn attempt_evidence_record_received__should_reject_an_attempt_it_does_not_keep() {
    // Given
    let evidence = AttemptEvidence::new();

    // When
    let recorded = evidence.record_received(FOLLOWER, attempt_id(1), vec![signed(FOLLOWER)]);

    // Then
    assert_matches!(recorded, Err(ReceivedNodeOutcomeError::UnknownAttempt(_)));
    assert!(evidence.outcomes_for(YIELD).is_empty());
}

#[test]
fn attempt_evidence_record_received__should_reject_an_outcome_the_attempt_rejects() {
    // Given
    let evidence = AttemptEvidence::new();
    evidence.open(led_attempt(1));

    // When
    let recorded = evidence.record_received(OUTSIDER, attempt_id(1), vec![signed(OUTSIDER)]);

    // Then
    assert_matches!(
        recorded,
        Err(ReceivedNodeOutcomeError::Rejected(
            NodeOutcomeRejection::NotInAttempt(OUTSIDER)
        ))
    );
    assert!(evidence.outcomes_for(YIELD).is_empty());
}

#[test]
fn attempt_evidence_open__should_keep_the_evidence_of_a_yield_while_other_yields_open_attempts() {
    // Given
    let evidence = AttemptEvidence::new();
    evidence.open(led_attempt(1));
    evidence
        .record_received(FOLLOWER, attempt_id(1), vec![signed(FOLLOWER)])
        .unwrap();

    // When
    for counter in 2..2000_u32 {
        let mut other_yield = [0xaa; 32];
        other_yield[..4].copy_from_slice(&counter.to_le_bytes());
        evidence.open(led_attempt_at(counter, YieldId(other_yield)));
    }

    // Then
    assert_eq!(evidence.outcomes_for(YIELD).len(), 1);
}

#[test]
fn attempt_evidence_open__should_drop_the_first_attempt_of_a_yield_past_its_bound() {
    // Given
    let evidence = AttemptEvidence::new();
    evidence.open(led_attempt(1));
    for counter in 2..=u32::try_from(MAX_ATTEMPTS_KEPT_PER_YIELD + 1).unwrap() {
        evidence.open(led_attempt(counter));
    }

    // When
    let first = evidence.record_received(FOLLOWER, attempt_id(1), vec![signed(FOLLOWER)]);

    // Then
    assert_eq!(
        evidence.attempts_kept_for(YIELD),
        MAX_ATTEMPTS_KEPT_PER_YIELD
    );
    assert_matches!(first, Err(ReceivedNodeOutcomeError::UnknownAttempt(_)));
}

#[test]
fn attempt_evidence_forget__should_drop_the_evidence_of_a_closed_request() {
    // Given
    let evidence = AttemptEvidence::new();
    let other_yield = YieldId([8; 32]);
    evidence.open(led_attempt(1));
    evidence.open(led_attempt_at(2, other_yield));
    evidence
        .record_received(FOLLOWER, attempt_id(1), vec![signed(FOLLOWER)])
        .unwrap();

    // When
    evidence.forget(&[YIELD]);

    // Then
    assert!(evidence.outcomes_for(YIELD).is_empty());
    assert_eq!(evidence.attempts_kept_for(YIELD), 0);
    assert_eq!(evidence.attempts_kept_for(other_yield), 1);
}
