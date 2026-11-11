use std::collections::BTreeMap;
use std::num::NonZeroUsize;

use near_mpc_contract_interface::types::YieldId;

use crate::config::ParticipantsConfig;
use crate::primitives::ParticipantId;
use crate::providers::verify_foreign_tx::node_outcome::{NoVerdictReason, NodeOutcome};
use crate::providers::verify_foreign_tx::node_outcome_statement::{
    NodeOutcomeVerificationError, SignedNodeOutcome, VerifiedNodeOutcome,
};

#[cfg(test)]
#[expect(non_snake_case)]
mod tests;

/// The signed node outcomes an acting leader shows to get the network to sign an inconclusive,
/// with the cause they prove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InconclusiveEvidence {
    pub(crate) cause: InconclusiveCause,
    pub(crate) outcomes: Vec<VerifiedNodeOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InconclusiveCause {
    /// Two nodes found different verdicts in one attempt.
    VerdictsDiffer {
        first: ParticipantId,
        second: ParticipantId,
    },
    InspectorsDisagree {
        participant: ParticipantId,
    },
    /// Transient errors kept a [`TransientQuorum`] of nodes from a verdict.
    Transient,
}

/// The requirements a signer of an inconclusive round places on the evidence it receives.
pub(crate) struct EvidenceRequirements<'a> {
    /// The node that asks for the inconclusive.
    pub(crate) leader: ParticipantId,
    pub(crate) yield_id: YieldId,
    /// The participant set that holds the TLS key each node outcome is verified against.
    pub(crate) participants: &'a ParticipantsConfig,
    pub(crate) transient_quorum: TransientQuorum,
}

/// The number of distinct nodes whose transient errors prove an inconclusive: the number of nodes
/// that support the chain, less the signing threshold, plus one. Fewer nodes than the signing
/// threshold then answered without a transient error, too few to sign a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransientQuorum(NonZeroUsize);

#[derive(Debug, thiserror::Error)]
pub(crate) enum EvidenceRejection {
    #[error("the evidence holds {count} node outcomes, more than the {max} participants")]
    TooManyOutcomes { count: usize, max: usize },
    #[error("a node outcome names another leader {0}")]
    OtherLeader(ParticipantId),
    #[error("a node outcome names another yield")]
    OtherYield,
    #[error(transparent)]
    Verification(#[from] NodeOutcomeVerificationError),
    #[error("the evidence shows no disagreement and too few nodes with transient errors")]
    NoCause,
}

impl TransientQuorum {
    pub(crate) fn new(chain_supporters: usize, signing_threshold: usize) -> Self {
        Self(NonZeroUsize::MIN.saturating_add(chain_supporters.saturating_sub(signing_threshold)))
    }
}

impl InconclusiveEvidence {
    /// Picks from `outcomes` the fewest node outcomes that prove a cause. A disagreement comes
    /// before transient errors. Each node counts once.
    pub(crate) fn find(
        outcomes: &[VerifiedNodeOutcome],
        transient_quorum: TransientQuorum,
    ) -> Option<Self> {
        inspectors_disagree(outcomes)
            .or_else(|| verdicts_differ(outcomes))
            .or_else(|| transient_errors(outcomes, transient_quorum))
    }

    /// Checks the evidence that the leader of an inconclusive round sent. The number of node
    /// outcomes and the names in them are checked before any signature.
    pub(crate) fn check(
        outcomes: Vec<SignedNodeOutcome>,
        requirements: &EvidenceRequirements<'_>,
    ) -> Result<Self, EvidenceRejection> {
        let max = requirements.participants.participants.len();
        if outcomes.len() > max {
            return Err(EvidenceRejection::TooManyOutcomes {
                count: outcomes.len(),
                max,
            });
        }
        for statement in outcomes.iter().map(SignedNodeOutcome::unverified_statement) {
            if statement.leader != requirements.leader {
                return Err(EvidenceRejection::OtherLeader(statement.leader));
            }
            if statement.yield_id != requirements.yield_id {
                return Err(EvidenceRejection::OtherYield);
            }
        }
        let verified = outcomes
            .into_iter()
            .map(|outcome| outcome.verify(requirements.participants))
            .collect::<Result<Vec<_>, _>>()?;
        Self::find(&verified, requirements.transient_quorum).ok_or(EvidenceRejection::NoCause)
    }

    pub(crate) fn signed_outcomes(&self) -> Vec<SignedNodeOutcome> {
        self.outcomes
            .iter()
            .cloned()
            .map(VerifiedNodeOutcome::into_signed)
            .collect()
    }
}

fn inspectors_disagree(outcomes: &[VerifiedNodeOutcome]) -> Option<InconclusiveEvidence> {
    let outcome = outcomes.iter().find(|outcome| {
        outcome.statement().outcome == NodeOutcome::NoVerdict(NoVerdictReason::InspectorsDisagree)
    })?;
    Some(InconclusiveEvidence {
        cause: InconclusiveCause::InspectorsDisagree {
            participant: outcome.statement().signer,
        },
        outcomes: vec![outcome.clone()],
    })
}

fn verdicts_differ(outcomes: &[VerifiedNodeOutcome]) -> Option<InconclusiveEvidence> {
    outcomes.iter().enumerate().find_map(|(index, first)| {
        let first_statement = first.statement();
        let NodeOutcome::Verdict(first_verdict) = first_statement.outcome else {
            return None;
        };
        let second = outcomes.iter().skip(index.saturating_add(1)).find(|second| {
            let second = second.statement();
            second.attempt == first_statement.attempt
                && second.signer != first_statement.signer
                && matches!(second.outcome, NodeOutcome::Verdict(verdict) if verdict != first_verdict)
        })?;
        Some(InconclusiveEvidence {
            cause: InconclusiveCause::VerdictsDiffer {
                first: first_statement.signer,
                second: second.statement().signer,
            },
            outcomes: vec![first.clone(), second.clone()],
        })
    })
}

fn transient_errors(
    outcomes: &[VerifiedNodeOutcome],
    quorum: TransientQuorum,
) -> Option<InconclusiveEvidence> {
    let mut by_signer = BTreeMap::new();
    for outcome in outcomes.iter().filter(|outcome| {
        outcome.statement().outcome == NodeOutcome::NoVerdict(NoVerdictReason::Transient)
    }) {
        by_signer
            .entry(outcome.statement().signer)
            .or_insert(outcome);
    }
    (by_signer.len() >= quorum.0.get()).then(|| InconclusiveEvidence {
        cause: InconclusiveCause::Transient,
        outcomes: by_signer
            .into_values()
            .take(quorum.0.get())
            .cloned()
            .collect(),
    })
}
