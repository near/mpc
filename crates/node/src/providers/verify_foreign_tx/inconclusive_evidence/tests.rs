use super::*;
use crate::config::{ParticipantInfo, PersistentSecrets};
use crate::primitives::{ChannelId, UniqueId};
use crate::providers::verify_foreign_tx::attempt_evidence::{AttemptEvidence, LedAttempt};
use crate::providers::verify_foreign_tx::node_outcome::NodeVerdict;
use crate::providers::verify_foreign_tx::node_outcome_statement::{
    AttemptId, NodeOutcomeSigningKey, NodeOutcomeStatement,
};
use ed25519_dalek::SigningKey;
use near_mpc_contract_interface::types::ForeignTxVerificationNegativeVerdict;
use rstest::rstest;
use std::assert_matches;
use std::sync::Arc;
use std::time::Duration;

const LEADER: ParticipantId = ParticipantId::from_raw(1);
const FOLLOWER: ParticipantId = ParticipantId::from_raw(2);
const OTHER_FOLLOWER: ParticipantId = ParticipantId::from_raw(3);
const LAST_FOLLOWER: ParticipantId = ParticipantId::from_raw(4);
const PARTICIPANTS: [ParticipantId; 4] = [LEADER, FOLLOWER, OTHER_FOLLOWER, LAST_FOLLOWER];
const YIELD: YieldId = YieldId([7; 32]);
/// Four chain supporters and a signing threshold of three.
const QUORUM_OF_TWO: TransientQuorum = TransientQuorum(NonZeroUsize::new(2).unwrap());

const VERIFIED: NodeOutcome = NodeOutcome::Verdict(NodeVerdict::Verified);
const NOT_FOUND: NodeOutcome = NodeOutcome::Verdict(NodeVerdict::Negative(
    ForeignTxVerificationNegativeVerdict::TransactionNotFound,
));
const TRANSIENT: NodeOutcome = NodeOutcome::NoVerdict(NoVerdictReason::Transient);
const INSPECTORS_DISAGREE: NodeOutcome =
    NodeOutcome::NoVerdict(NoVerdictReason::InspectorsDisagree);

fn tls_key(participant: ParticipantId) -> SigningKey {
    SigningKey::from_bytes(&[u8::try_from(participant.raw()).unwrap(); 32])
}

fn participants() -> ParticipantsConfig {
    let participants = PARTICIPANTS
        .into_iter()
        .map(|id| ParticipantInfo {
            id,
            address: "127.0.0.1".to_string(),
            port: 3000,
            p2p_public_key: tls_key(id).verifying_key(),
            near_account_id: format!("p{}.near", id.raw()).parse().unwrap(),
        })
        .collect();
    ParticipantsConfig {
        threshold: 3,
        participants,
    }
}

fn attempt_of(leader: ParticipantId, counter: u32) -> AttemptId {
    AttemptId(ChannelId(UniqueId::new(leader, 1_700_000_000, counter)))
}

/// The statement `signer` makes about attempt `attempt` of [`LEADER`].
fn statement(signer: ParticipantId, attempt: u32, outcome: NodeOutcome) -> NodeOutcomeStatement {
    NodeOutcomeStatement {
        yield_id: YIELD,
        leader: LEADER,
        attempt: attempt_of(LEADER, attempt),
        signer,
        outcome,
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

fn signed(signer: ParticipantId, attempt: u32, outcome: NodeOutcome) -> SignedNodeOutcome {
    signed_by(signer, statement(signer, attempt, outcome))
}

fn verified(signer: ParticipantId, attempt: u32, outcome: NodeOutcome) -> VerifiedNodeOutcome {
    signed(signer, attempt, outcome)
        .verify(&participants())
        .unwrap()
}

fn check(outcomes: Vec<SignedNodeOutcome>) -> Result<InconclusiveEvidence, EvidenceRejection> {
    let participants = participants();
    InconclusiveEvidence::check(
        outcomes,
        &EvidenceRequirements {
            leader: LEADER,
            yield_id: YIELD,
            participants: &participants,
            transient_quorum: QUORUM_OF_TWO,
        },
    )
}

#[rstest]
#[case::four_supporters_threshold_three(4, 3, 2)]
#[case::supporters_at_the_threshold(3, 3, 1)]
#[case::fewer_supporters_than_the_threshold(2, 3, 1)]
fn transient_quorum__should_be_one_more_than_the_supporters_beyond_the_threshold(
    #[case] chain_supporters: usize,
    #[case] signing_threshold: usize,
    #[case] expected: usize,
) {
    // When
    let quorum = TransientQuorum::new(chain_supporters, signing_threshold);

    // Then
    assert_eq!(quorum.0.get(), expected);
}

#[rstest]
#[case::verdicts_differ(
    vec![signed(LEADER, 1, VERIFIED), signed(FOLLOWER, 1, NOT_FOUND)],
    InconclusiveCause::VerdictsDiffer { first: LEADER, second: FOLLOWER },
)]
#[case::inspectors_disagree(
    vec![signed(OTHER_FOLLOWER, 1, INSPECTORS_DISAGREE)],
    InconclusiveCause::InspectorsDisagree { participant: OTHER_FOLLOWER },
)]
#[case::transient_errors_across_attempts(
    vec![signed(FOLLOWER, 1, TRANSIENT), signed(OTHER_FOLLOWER, 2, TRANSIENT)],
    InconclusiveCause::Transient,
)]
fn inconclusive_evidence_check__should_accept_each_kind_of_evidence(
    #[case] outcomes: Vec<SignedNodeOutcome>,
    #[case] cause: InconclusiveCause,
) {
    // When
    let evidence = check(outcomes.clone());

    // Then
    let evidence = evidence.unwrap();
    assert_eq!(evidence.cause, cause);
    assert_eq!(evidence.signed_outcomes(), outcomes);
}

#[rstest]
#[case::nothing(vec![])]
#[case::transient_errors_from_too_few_nodes(vec![signed(FOLLOWER, 1, TRANSIENT)])]
#[case::one_node_reporting_twice(vec![signed(FOLLOWER, 1, TRANSIENT), signed(FOLLOWER, 2, TRANSIENT)])]
#[case::verdicts_of_different_attempts(
    vec![signed(LEADER, 1, VERIFIED), signed(FOLLOWER, 2, NOT_FOUND)]
)]
#[case::matching_verdicts(vec![signed(LEADER, 1, NOT_FOUND), signed(FOLLOWER, 1, NOT_FOUND)])]
fn inconclusive_evidence_check__should_reject_evidence_without_a_cause(
    #[case] outcomes: Vec<SignedNodeOutcome>,
) {
    // When
    let evidence = check(outcomes);

    // Then
    assert_matches!(evidence, Err(EvidenceRejection::NoCause));
}

#[test]
fn inconclusive_evidence_check__should_reject_more_outcomes_than_participants() {
    // Given
    let outcomes = vec![signed(FOLLOWER, 1, INSPECTORS_DISAGREE); PARTICIPANTS.len() + 1];

    // When
    let evidence = check(outcomes);

    // Then
    assert_matches!(
        evidence,
        Err(EvidenceRejection::TooManyOutcomes { count: 5, max: 4 })
    );
}

#[test]
fn inconclusive_evidence_check__should_reject_an_outcome_another_key_signed() {
    // Given
    let forged = signed_by(LEADER, statement(FOLLOWER, 1, NOT_FOUND));

    // When
    let evidence = check(vec![signed(LEADER, 1, VERIFIED), forged]);

    // Then
    assert_matches!(
        evidence,
        Err(EvidenceRejection::Verification(
            NodeOutcomeVerificationError::BadSignature
        ))
    );
}

#[test]
fn inconclusive_evidence_check__should_reject_an_outcome_replayed_from_another_yield() {
    // Given
    let replayed = signed_by(
        FOLLOWER,
        NodeOutcomeStatement {
            yield_id: YieldId([8; 32]),
            ..statement(FOLLOWER, 1, INSPECTORS_DISAGREE)
        },
    );

    // When
    let evidence = check(vec![replayed]);

    // Then
    assert_matches!(evidence, Err(EvidenceRejection::OtherYield));
}

#[test]
fn inconclusive_evidence_check__should_reject_an_outcome_replayed_from_another_leader() {
    // Given
    let replayed = signed_by(
        FOLLOWER,
        NodeOutcomeStatement {
            leader: OTHER_FOLLOWER,
            attempt: attempt_of(OTHER_FOLLOWER, 1),
            ..statement(FOLLOWER, 1, INSPECTORS_DISAGREE)
        },
    );

    // When
    let evidence = check(vec![replayed]);

    // Then
    assert_matches!(
        evidence,
        Err(EvidenceRejection::OtherLeader(OTHER_FOLLOWER))
    );
}

#[test]
fn inconclusive_evidence_check__should_reject_an_attempt_of_another_leader() {
    // Given
    let outcome = signed_by(
        FOLLOWER,
        NodeOutcomeStatement {
            attempt: attempt_of(OTHER_FOLLOWER, 1),
            ..statement(FOLLOWER, 1, INSPECTORS_DISAGREE)
        },
    );

    // When
    let evidence = check(vec![outcome]);

    // Then
    assert_matches!(
        evidence,
        Err(EvidenceRejection::Verification(
            NodeOutcomeVerificationError::AttemptOfAnotherLeader(LEADER)
        ))
    );
}

#[test]
fn inconclusive_evidence_find__should_prefer_a_disagreement_and_show_the_fewest_outcomes() {
    // Given
    let outcomes = [
        verified(LEADER, 1, VERIFIED),
        verified(FOLLOWER, 1, TRANSIENT),
        verified(OTHER_FOLLOWER, 1, TRANSIENT),
        verified(LAST_FOLLOWER, 1, NOT_FOUND),
    ];

    // When
    let evidence = InconclusiveEvidence::find(&outcomes, QUORUM_OF_TWO);

    // Then
    assert_eq!(
        evidence,
        Some(InconclusiveEvidence {
            cause: InconclusiveCause::VerdictsDiffer {
                first: LEADER,
                second: LAST_FOLLOWER,
            },
            outcomes: vec![outcomes[0].clone(), outcomes[3].clone()],
        })
    );
}

#[test]
fn inconclusive_evidence_find__should_show_one_transient_outcome_per_node_up_to_the_quorum() {
    // Given
    let outcomes = [
        verified(FOLLOWER, 1, TRANSIENT),
        verified(FOLLOWER, 2, TRANSIENT),
        verified(OTHER_FOLLOWER, 2, TRANSIENT),
        verified(LAST_FOLLOWER, 3, TRANSIENT),
    ];

    // When
    let evidence = InconclusiveEvidence::find(&outcomes, QUORUM_OF_TWO);

    // Then
    assert_eq!(
        evidence,
        Some(InconclusiveEvidence {
            cause: InconclusiveCause::Transient,
            outcomes: vec![outcomes[0].clone(), outcomes[2].clone()],
        })
    );
}

fn led_attempt(counter: u32) -> LedAttempt {
    LedAttempt {
        id: attempt_of(LEADER, counter),
        yield_id: YIELD,
        leader: LEADER,
        participants: vec![LEADER, FOLLOWER, OTHER_FOLLOWER],
        keys: Arc::new(participants()),
    }
}

#[tokio::test]
async fn attempt_evidence_wait_for__should_count_a_transient_report_that_arrives_after_its_attempt()
{
    // Given
    let evidence = AttemptEvidence::new();
    evidence.open(led_attempt(1));
    evidence
        .record_received(
            FOLLOWER,
            attempt_of(LEADER, 1),
            vec![signed(FOLLOWER, 1, TRANSIENT)],
        )
        .unwrap();
    evidence.open(led_attempt(2));
    let waiting = evidence.wait_for(YIELD, |outcomes| {
        InconclusiveEvidence::find(outcomes, QUORUM_OF_TWO)
    });

    // When
    let (found, late) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(5), waiting),
        async {
            evidence.record_received(
                OTHER_FOLLOWER,
                attempt_of(LEADER, 1),
                vec![signed(OTHER_FOLLOWER, 1, TRANSIENT)],
            )
        }
    );

    // Then
    late.unwrap();
    let found = found.expect("the late report completes the evidence");
    assert_eq!(found.cause, InconclusiveCause::Transient);
    let signers: Vec<_> = found
        .outcomes
        .iter()
        .map(|outcome| outcome.statement().signer)
        .collect();
    assert_eq!(signers, [FOLLOWER, OTHER_FOLLOWER]);
}
