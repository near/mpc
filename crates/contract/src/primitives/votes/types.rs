use std::collections::BTreeSet;
use std::hash::Hash;

use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{Deref, From, Into};
use near_sdk::near;

pub trait ProposalBounds: BorshSerialize + BorshDeserialize + Ord + Clone + Hash {}
pub trait VoterBounds: BorshSerialize + BorshDeserialize + Ord + Clone {}

impl<T: BorshSerialize + BorshDeserialize + Ord + Clone + Hash> ProposalBounds for T {}
impl<T: BorshSerialize + BorshDeserialize + Ord + Clone> VoterBounds for T {}

#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Clone, Copy, From, Deref, Into)]
pub struct ProposalId(pub(crate) u64);

impl ProposalId {
    pub(super) fn next(&self) -> Self {
        let (next, overflow) = self.0.overflowing_add(1);
        if overflow {
            near_sdk::env::panic_str("overflow in proposal id")
        }
        ProposalId(next)
    }
}

/// The set of voters who voted for a particular proposal. Always non-empty when stored
/// inside `VotesByProposal`.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct VoterSet<V>(pub(super) BTreeSet<V>)
where
    V: VoterBounds;

impl<V> VoterSet<V>
where
    V: VoterBounds,
{
    pub(super) fn new() -> Self {
        Self(BTreeSet::new())
    }

    // counts all the votes for which `predicate` returns true
    pub fn count_for(&self, predicate: impl Fn(&V) -> bool) -> usize {
        self.0.iter().filter(|voter| predicate(voter)).count()
    }

    // returns Some(remaining_votes) in case a vote was removed
    pub(super) fn remove(&mut self, vote: &V) -> Option<usize> {
        if self.0.remove(vote) {
            Some(self.0.len())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use borsh::{BorshDeserialize, BorshSerialize};

    use crate::primitives::votes::types::{ProposalId, VoterSet};

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, BorshDeserialize, BorshSerialize)]
    struct TestVoter(String);

    #[test]
    fn proposal_id_next_increments_by_one() {
        let pid = ProposalId(7);

        let next = pid.next();

        assert_eq!(next, ProposalId(8));
        assert_eq!(pid, ProposalId(7));
    }

    #[test]
    #[should_panic(expected = "overflow in proposal id")]
    fn proposal_id_next_panics_on_overflow() {
        let pid = ProposalId(u64::MAX);

        let _ = pid.next();
    }

    #[test]
    fn voter_set_new_is_empty() {
        let voter_set = VoterSet::<TestVoter>::new();

        assert!(voter_set.0.is_empty());
    }

    #[test]
    fn voter_set_count_for_counts_only_matching_votes() {
        let alice = TestVoter("alice".to_string());
        let bob = TestVoter("bob".to_string());
        let carol = TestVoter("carol".to_string());

        let voter_set = VoterSet([alice.clone(), bob.clone(), carol.clone()].into());

        let count = voter_set.count_for(|voter| voter.0.contains('a'));

        assert_eq!(count, 2);
    }

    #[test]
    fn voter_set_count_for_returns_zero_for_empty_set() {
        let voter_set = VoterSet::<TestVoter>::new();

        let count = voter_set.count_for(|_| true);

        assert_eq!(count, 0);
    }

    #[test]
    fn voter_set_remove_existing_vote_returns_remaining_count() {
        let alice = TestVoter("alice".to_string());
        let bob = TestVoter("bob".to_string());

        let mut voter_set = VoterSet([alice.clone(), bob.clone()].into());

        let remaining = voter_set.remove(&alice);

        assert_eq!(remaining, Some(1));
        assert_eq!(voter_set.0, [bob.clone()].into());
    }

    #[test]
    fn voter_set_remove_last_vote_returns_zero() {
        let alice = TestVoter("alice".to_string());

        let mut voter_set = VoterSet([alice.clone()].into());

        let remaining = voter_set.remove(&alice);

        assert_eq!(remaining, Some(0));
        assert!(voter_set.0.is_empty());
    }

    #[test]
    fn voter_set_remove_missing_vote_returns_none_and_leaves_set_unchanged() {
        let alice = TestVoter("alice".to_string());
        let bob = TestVoter("bob".to_string());

        let mut voter_set = VoterSet([alice.clone()].into());

        let remaining = voter_set.remove(&bob);

        assert_eq!(remaining, None);
        assert_eq!(voter_set.0, [alice.clone()].into());
    }
}
