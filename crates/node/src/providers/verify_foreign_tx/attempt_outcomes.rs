use std::collections::{BTreeMap, BTreeSet};

use crate::primitives::ParticipantId;
use crate::providers::verify_foreign_tx::node_outcome::{
    NoVerdictReason, NodeOutcome, NodeVerdict,
};

/// The node outcomes the leader of a V2 attempt has so far. The attempt signs once every
/// participant found the same verdict, and ends at the first node outcome that rules that out.
pub(crate) struct AttemptOutcomes {
    awaited: BTreeSet<ParticipantId>,
    verdicts: BTreeMap<ParticipantId, NodeVerdict>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttemptStatus {
    Pending,
    Agreed(NodeVerdict),
    Ended(AttemptEnd),
}

/// The finding that ends an attempt before it signs.
// TODO(#5126): end the request with an inconclusive on a disagreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum AttemptEnd {
    #[error("participant {participant} reached no verdict: {reason:?}")]
    NoVerdict {
        participant: ParticipantId,
        reason: NoVerdictReason,
    },
    #[error(
        "participants {} and {} found different verdicts: {:?} and {:?}",
        first.participant, second.participant, first.verdict, second.verdict
    )]
    VerdictsDiffer {
        first: ParticipantVerdict,
        second: ParticipantVerdict,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ParticipantVerdict {
    pub(crate) participant: ParticipantId,
    pub(crate) verdict: NodeVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("participant {0} is not awaited in this attempt")]
pub(crate) struct UnexpectedNodeOutcome(pub(crate) ParticipantId);

impl AttemptOutcomes {
    pub(crate) fn new(participants: impl IntoIterator<Item = ParticipantId>) -> Self {
        Self {
            awaited: participants.into_iter().collect(),
            verdicts: BTreeMap::new(),
        }
    }

    /// Takes the node outcome of `participant`. Each participant reports once.
    pub(crate) fn record(
        &mut self,
        participant: ParticipantId,
        outcome: NodeOutcome,
    ) -> Result<AttemptStatus, UnexpectedNodeOutcome> {
        if !self.awaited.remove(&participant) {
            return Err(UnexpectedNodeOutcome(participant));
        }
        let verdict = match outcome {
            NodeOutcome::Verdict(verdict) => verdict,
            NodeOutcome::NoVerdict(reason) => {
                return Ok(AttemptStatus::Ended(AttemptEnd::NoVerdict {
                    participant,
                    reason,
                }));
            }
        };
        if let Some((&other, &other_verdict)) = self
            .verdicts
            .iter()
            .find(|(_, other_verdict)| **other_verdict != verdict)
        {
            return Ok(AttemptStatus::Ended(AttemptEnd::VerdictsDiffer {
                first: ParticipantVerdict {
                    participant: other,
                    verdict: other_verdict,
                },
                second: ParticipantVerdict {
                    participant,
                    verdict,
                },
            }));
        }
        self.verdicts.insert(participant, verdict);
        Ok(if self.awaited.is_empty() {
            AttemptStatus::Agreed(verdict)
        } else {
            AttemptStatus::Pending
        })
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use near_mpc_contract_interface::types::ForeignTxVerificationNegativeVerdict;
    use std::assert_matches;

    const LEADER: ParticipantId = ParticipantId::from_raw(1);
    const FOLLOWER: ParticipantId = ParticipantId::from_raw(2);
    const OTHER_FOLLOWER: ParticipantId = ParticipantId::from_raw(3);

    const VERIFIED: NodeOutcome = NodeOutcome::Verdict(NodeVerdict::Verified);
    const NOT_FOUND: NodeOutcome = NodeOutcome::Verdict(NodeVerdict::Negative(
        ForeignTxVerificationNegativeVerdict::TransactionNotFound,
    ));

    fn three_participants() -> AttemptOutcomes {
        AttemptOutcomes::new([LEADER, FOLLOWER, OTHER_FOLLOWER])
    }

    #[test]
    fn attempt_outcomes__should_agree_once_every_participant_found_the_same_verdict() {
        // Given
        let mut outcomes = three_participants();

        // When
        let first = outcomes.record(FOLLOWER, NOT_FOUND).unwrap();
        let second = outcomes.record(LEADER, NOT_FOUND).unwrap();
        let last = outcomes.record(OTHER_FOLLOWER, NOT_FOUND).unwrap();

        // Then
        assert_eq!(first, AttemptStatus::Pending);
        assert_eq!(second, AttemptStatus::Pending);
        let NodeOutcome::Verdict(not_found) = NOT_FOUND else {
            unreachable!()
        };
        assert_eq!(last, AttemptStatus::Agreed(not_found));
    }

    #[test]
    fn attempt_outcomes__should_end_at_the_first_verdict_that_differs() {
        // Given
        let mut outcomes = three_participants();
        outcomes.record(FOLLOWER, VERIFIED).unwrap();

        // When
        let status = outcomes.record(LEADER, NOT_FOUND).unwrap();

        // Then
        assert_matches!(
            status,
            AttemptStatus::Ended(AttemptEnd::VerdictsDiffer {
                first: ParticipantVerdict {
                    participant: FOLLOWER,
                    verdict: NodeVerdict::Verified,
                },
                second: ParticipantVerdict {
                    participant: LEADER,
                    verdict: NodeVerdict::Negative(_),
                },
            })
        );
    }

    #[test]
    fn attempt_outcomes__should_end_when_two_followers_differ_before_the_leader_reports() {
        // Given
        let mut outcomes = three_participants();
        outcomes.record(FOLLOWER, VERIFIED).unwrap();

        // When
        let status = outcomes.record(OTHER_FOLLOWER, NOT_FOUND).unwrap();

        // Then
        assert_matches!(
            status,
            AttemptStatus::Ended(AttemptEnd::VerdictsDiffer { .. })
        );
    }

    #[test]
    fn attempt_outcomes__should_end_at_the_first_participant_without_a_verdict() {
        // Given
        let mut outcomes = three_participants();

        // When
        let status = outcomes
            .record(
                OTHER_FOLLOWER,
                NodeOutcome::NoVerdict(NoVerdictReason::Transient),
            )
            .unwrap();

        // Then
        assert_eq!(
            status,
            AttemptStatus::Ended(AttemptEnd::NoVerdict {
                participant: OTHER_FOLLOWER,
                reason: NoVerdictReason::Transient,
            })
        );
    }

    #[test]
    fn attempt_outcomes__should_reject_a_second_outcome_from_one_participant() {
        // Given
        let mut outcomes = three_participants();
        outcomes.record(FOLLOWER, VERIFIED).unwrap();

        // When
        let status = outcomes.record(FOLLOWER, VERIFIED);

        // Then
        assert_eq!(status, Err(UnexpectedNodeOutcome(FOLLOWER)));
    }

    #[test]
    fn attempt_outcomes__should_reject_an_outcome_from_outside_the_attempt() {
        // Given
        let mut outcomes = AttemptOutcomes::new([LEADER, FOLLOWER]);

        // When
        let status = outcomes.record(OTHER_FOLLOWER, VERIFIED);

        // Then
        assert_eq!(status, Err(UnexpectedNodeOutcome(OTHER_FOLLOWER)));
    }
}
