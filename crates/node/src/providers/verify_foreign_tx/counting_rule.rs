use std::collections::{BTreeMap, BTreeSet};

use crate::primitives::ParticipantId;
use crate::providers::verify_foreign_tx::node_outcome::{NodeOutcome, NodeVerdict};
use crate::providers::verify_foreign_tx::node_outcome_statement::NodeOutcomeStatement;

/// What an acting leader does with the node outcomes it holds for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decision {
    /// At least t supporters signed `verdict`, and `backers` are all of them.
    Verdict {
        verdict: NodeVerdict,
        backers: BTreeSet<ParticipantId>,
    },
    /// No verdict can reach t, even if every supporter not heard from yet signed it. `heard` are
    /// the supporters that signed exactly one outcome.
    Inconclusive {
        heard: BTreeSet<ParticipantId>,
    },
    Wait,
}

/// The node outcomes of one request, one entry per signer. A signer of two different statements
/// counts as heard, but for no outcome.
#[derive(Debug, Default)]
pub(crate) struct Tally(BTreeMap<ParticipantId, Heard>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Heard {
    One(NodeOutcome),
    Conflicting,
}

impl Tally {
    /// Applies the counting rule. Only `supporters` count, and when two verdicts reach
    /// `threshold`, the one whose first backer has the lowest participant id wins.
    pub(crate) fn decide(
        &self,
        supporters: &BTreeSet<ParticipantId>,
        threshold: usize,
    ) -> Decision {
        let mut verdicts: Vec<(NodeVerdict, BTreeSet<ParticipantId>)> = Vec::new();
        let mut heard_count: usize = 0;
        let mut heard = BTreeSet::new();
        for (signer, outcome) in self.of(supporters) {
            heard_count = heard_count.saturating_add(1);
            let Heard::One(outcome) = outcome else {
                continue;
            };
            heard.insert(signer);
            let NodeOutcome::Verdict(verdict) = outcome else {
                continue;
            };
            match verdicts.iter_mut().find(|(known, _)| *known == verdict) {
                Some((_, backers)) => {
                    backers.insert(signer);
                }
                None => verdicts.push((verdict, BTreeSet::from([signer]))),
            }
        }
        if let Some((verdict, backers)) = verdicts
            .iter()
            .find(|(_, backers)| backers.len() >= threshold)
        {
            return Decision::Verdict {
                verdict: *verdict,
                backers: backers.clone(),
            };
        }
        let unheard = supporters.len().saturating_sub(heard_count);
        let most_backers = verdicts
            .iter()
            .map(|(_, backers)| backers.len())
            .max()
            .unwrap_or(0);
        if most_backers.saturating_add(unheard) < threshold {
            return Decision::Inconclusive { heard };
        }
        Decision::Wait
    }

    /// The supporters that signed exactly one outcome, `verdict`.
    pub(crate) fn backers_of(
        &self,
        verdict: NodeVerdict,
        supporters: &BTreeSet<ParticipantId>,
    ) -> BTreeSet<ParticipantId> {
        self.of(supporters)
            .filter(|(_, outcome)| *outcome == Heard::One(NodeOutcome::Verdict(verdict)))
            .map(|(signer, _)| signer)
            .collect()
    }

    fn of<'a>(
        &'a self,
        supporters: &'a BTreeSet<ParticipantId>,
    ) -> impl Iterator<Item = (ParticipantId, Heard)> + 'a {
        self.0
            .iter()
            .filter(|(signer, _)| supporters.contains(signer))
            .map(|(signer, outcome)| (*signer, *outcome))
    }
}

impl<'a> FromIterator<&'a NodeOutcomeStatement> for Tally {
    fn from_iter<I: IntoIterator<Item = &'a NodeOutcomeStatement>>(statements: I) -> Self {
        statements
            .into_iter()
            .fold(Self::default(), |mut tally, statement| {
                tally
                    .0
                    .entry(statement.signer)
                    .and_modify(|heard| {
                        if *heard != Heard::One(statement.outcome) {
                            *heard = Heard::Conflicting;
                        }
                    })
                    .or_insert(Heard::One(statement.outcome));
                tally
            })
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use crate::providers::verify_foreign_tx::node_outcome::NoVerdictReason;
    use near_mpc_contract_interface::types::{ForeignTxVerificationNegativeVerdict, YieldId};
    use rstest::rstest;

    const THRESHOLD: usize = 3;
    const VERIFIED: NodeOutcome = NodeOutcome::Verdict(NodeVerdict::Verified);
    const NOT_FOUND: NodeOutcome = NodeOutcome::Verdict(NodeVerdict::Negative(
        ForeignTxVerificationNegativeVerdict::TransactionNotFound,
    ));
    const TRANSIENT: NodeOutcome = NodeOutcome::NoVerdict(NoVerdictReason::Transient);

    fn participants(ids: &[u32]) -> BTreeSet<ParticipantId> {
        ids.iter().copied().map(ParticipantId::from_raw).collect()
    }

    fn statement(signer: u32, outcome: NodeOutcome) -> NodeOutcomeStatement {
        NodeOutcomeStatement {
            yield_id: YieldId([1; 32]),
            signer: ParticipantId::from_raw(signer),
            outcome,
        }
    }

    fn verdict_of(outcome: NodeOutcome, backers: &[u32]) -> Decision {
        let NodeOutcome::Verdict(verdict) = outcome else {
            panic!("{outcome:?} is not a verdict");
        };
        Decision::Verdict {
            verdict,
            backers: participants(backers),
        }
    }

    #[rstest]
    #[case::t_matching_with_others_silent(
        vec![statement(0, VERIFIED), statement(1, VERIFIED), statement(2, VERIFIED)],
        verdict_of(VERIFIED, &[0, 1, 2])
    )]
    #[case::one_divergent_node(
        vec![
            statement(0, NOT_FOUND),
            statement(1, VERIFIED),
            statement(2, NOT_FOUND),
            statement(3, NOT_FOUND),
        ],
        verdict_of(NOT_FOUND, &[0, 2, 3])
    )]
    #[case::conflicting_node_counts_for_no_verdict(
        vec![
            statement(0, VERIFIED),
            statement(1, VERIFIED),
            statement(2, VERIFIED),
            statement(2, NOT_FOUND),
        ],
        Decision::Wait
    )]
    #[case::non_supporters_ignored(
        vec![statement(0, VERIFIED), statement(1, VERIFIED), statement(7, VERIFIED)],
        Decision::Wait
    )]
    #[case::too_few_gives_wait(
        vec![statement(0, VERIFIED), statement(1, VERIFIED)],
        Decision::Wait
    )]
    #[case::repeated_statement_counts_once(
        vec![statement(0, VERIFIED), statement(0, VERIFIED), statement(1, VERIFIED)],
        Decision::Wait
    )]
    #[case::transient_errors_from_s_minus_t_plus_one(
        vec![statement(0, TRANSIENT), statement(1, TRANSIENT), statement(2, VERIFIED)],
        Decision::Inconclusive { heard: participants(&[0, 1, 2]) }
    )]
    #[case::split_no_verdict_can_reach_t(
        vec![
            statement(0, VERIFIED),
            statement(1, VERIFIED),
            statement(2, NOT_FOUND),
            statement(3, NOT_FOUND),
        ],
        Decision::Inconclusive { heard: participants(&[0, 1, 2, 3]) }
    )]
    fn tally_decide__should_apply_the_counting_rule(
        #[case] statements: Vec<NodeOutcomeStatement>,
        #[case] expected: Decision,
    ) {
        // Given
        let supporters = participants(&[0, 1, 2, 3]);

        // When
        let decision = statements
            .iter()
            .collect::<Tally>()
            .decide(&supporters, THRESHOLD);

        // Then
        assert_eq!(decision, expected);
    }

    #[test]
    fn tally_decide__should_pick_one_verdict_when_two_reach_the_threshold() {
        // Given
        let supporters = participants(&[0, 1, 2, 3, 4, 5]);
        let statements = [
            statement(0, NOT_FOUND),
            statement(1, VERIFIED),
            statement(2, NOT_FOUND),
            statement(3, VERIFIED),
            statement(4, NOT_FOUND),
            statement(5, VERIFIED),
        ];

        // When
        let decision = statements
            .iter()
            .collect::<Tally>()
            .decide(&supporters, THRESHOLD);

        // Then
        assert_eq!(decision, verdict_of(NOT_FOUND, &[0, 2, 4]));
    }

    #[test]
    fn tally_backers_of__should_leave_out_conflicting_signers_and_non_supporters() {
        // Given
        let supporters = participants(&[0, 1, 2]);
        let statements = [
            statement(0, VERIFIED),
            statement(1, VERIFIED),
            statement(1, TRANSIENT),
            statement(2, NOT_FOUND),
            statement(5, VERIFIED),
        ];
        let NodeOutcome::Verdict(verified) = VERIFIED else {
            unreachable!()
        };

        // When
        let backers = statements
            .iter()
            .collect::<Tally>()
            .backers_of(verified, &supporters);

        // Then
        assert_eq!(backers, participants(&[0]));
    }
}
