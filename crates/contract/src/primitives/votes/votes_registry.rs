use std::collections::BTreeMap;
use std::collections::BTreeSet;

use near_sdk::near;
use near_sdk::require;

use super::types::VoterSet;
use super::types::{ProposalId, VoterBounds};

/// Helper struct to keep track of submitted votes.
/// Allows efficient look-up of votes by voter and votes by proposal.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub(super) struct VoteRegistry<V>
where
    V: VoterBounds,
{
    votes_by_voter: BTreeMap<V, ProposalId>,
    votes_by_proposal: BTreeMap<ProposalId, VoterSet<V>>,
}

impl<V> VoteRegistry<V>
where
    V: VoterBounds,
{
    pub(super) fn new() -> Self {
        Self {
            votes_by_voter: BTreeMap::new(),
            votes_by_proposal: BTreeMap::new(),
        }
    }

    /// Registers a vote by `voter` for [`ProposalId`].
    /// In case this voter already has a vote for a different proposal id, the previous vote is removed.
    /// Returns a [`VoteResult`], indicating if by removing any existing votes, there is a proposal
    /// without any votes.
    pub(super) fn register(&mut self, voter: V, proposal: ProposalId) -> VoteResult<'_, V> {
        // if necessary, remove existing votes
        let proposal_without_votes = match self.votes_by_voter.get(&voter) {
            // if the voter has an existing vote for a different proposal, remove that vote.
            Some(existing_vote) if *existing_vote != proposal => self.remove_vote(&voter),
            Some(_) => {
                // voter has already voted for this proposal, just return the current voter set
                return VoteResult {
                    votes_for_proposal: self
                        .votes_by_proposal
                        .get(&proposal)
                        .expect("require consistent vote registry"),
                    proposal_without_votes: None,
                };
            }
            // voter has no existing vote, proceeed.
            None => None,
        };

        // register the vote for the voter
        require!(
            self.votes_by_voter
                .insert(voter.clone(), proposal)
                .is_none(),
            "inconsistent voter registry"
        );

        // register the vote for the proposal
        let votes_for_proposal = self
            .votes_by_proposal
            .entry(proposal)
            .or_insert_with(VoterSet::new);
        votes_for_proposal.0.insert(voter);

        VoteResult {
            votes_for_proposal,
            proposal_without_votes,
        }
    }

    /// Removes any votes by voter V.
    /// Returns Some(ProposalId) if removing this vote leaves [`ProposalId`] without any votes.
    pub(super) fn remove_vote(&mut self, voter: &V) -> Option<ProposalId> {
        let proposal = self.votes_by_voter.get(voter)?;
        let casted_votes = self
            .votes_by_proposal
            .get_mut(proposal)
            .expect("inconsistent votes registry");
        // remove the vote from the proposal
        let remaining = casted_votes
            .remove(voter)
            .expect("inconistent vote registry");
        let res = if remaining == 0 {
            // remove the proposal if it has no more votes
            self.votes_by_proposal.remove(proposal);
            Some(*proposal)
        } else {
            None
        };
        // remove the voter
        self.votes_by_voter.remove(voter);
        res
    }

    /// Removes any votes for proposal with [`ProposalId`], together with any voters that voted for
    /// [`ProposalId`].
    pub(super) fn remove_votes_for_proposal(&mut self, proposal: &ProposalId) {
        let Some(voters) = self.votes_by_proposal.remove(proposal) else {
            return;
        };
        for voter in &voters.0 {
            self.votes_by_voter.remove(voter);
        }
    }

    /// Retains votes for which `predicate` returns true
    /// Returns a vector of any proposal ids that were removed in the process
    pub(super) fn retain_votes(&mut self, predicate: impl Fn(&V) -> bool) -> Vec<ProposalId> {
        let votes_to_remove: Vec<V> = self
            .votes_by_voter
            .keys()
            .filter(|voter| !predicate(voter))
            .cloned()
            .collect();
        let mut removed_proposal_ids = vec![];
        for voter in votes_to_remove {
            if let Some(proposal) = self.remove_vote(&voter) {
                removed_proposal_ids.push(proposal);
            }
        }
        removed_proposal_ids
    }

    pub(super) fn clear(&mut self) {
        self.votes_by_voter.clear();
        self.votes_by_proposal.clear();
    }

    pub(super) fn all(&self) -> BTreeMap<ProposalId, BTreeSet<V>> {
        self.votes_by_proposal
            .iter()
            .map(|(pid, voter_set)| (*pid, voter_set.0.clone()))
            .collect()
    }
}

/// Return value for a vote
/// s the current votes for the proposal and indicates if any proposal was orphaned due to
/// this vote.
/// For example:
/// 1. Alice votes for proposal 0
/// 2. Alice changes her vote to proposal 1, leaving proposal 0 without any votes
pub(super) struct VoteResult<'a, V>
where
    V: VoterBounds,
{
    pub(super) votes_for_proposal: &'a VoterSet<V>,
    pub(super) proposal_without_votes: Option<ProposalId>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, BorshDeserialize, BorshSerialize)]
    struct TestVoter(String);

    fn assert_registry_state(
        registry: &VoteRegistry<TestVoter>,
        expected: impl IntoIterator<Item = (ProposalId, BTreeSet<TestVoter>)>,
    ) {
        let expected: BTreeMap<ProposalId, BTreeSet<TestVoter>> = expected.into_iter().collect();
        assert_eq!(registry.all(), expected);
    }

    #[test]
    fn new_is_empty() {
        let registry = VoteRegistry::<TestVoter>::new();

        assert_registry_state(&registry, []);
        assert_eq!(registry.votes_by_voter.len(), 0);
        assert_eq!(registry.votes_by_proposal.len(), 0);
    }

    #[test]
    fn register_first_vote_creates_entry_and_returns_current_votes() {
        let mut registry = VoteRegistry::<TestVoter>::new();

        let pid = ProposalId(7);
        let voter = TestVoter("alice".to_string());
        let result = registry.register(voter.clone(), pid);

        assert_eq!(result.proposal_without_votes, None);
        assert_eq!(result.votes_for_proposal.0, [voter.clone()].into());

        assert_eq!(registry.votes_by_voter.get(&voter), Some(&pid));
        assert_registry_state(&registry, [(pid, [voter.clone()].into())]);
    }

    #[test]
    fn register_same_vote_is_idempotent() {
        let mut registry = VoteRegistry::<TestVoter>::new();

        let pid = ProposalId(1);
        let voter = TestVoter("alice".to_string());

        let first = registry.register(voter.clone(), pid);
        assert_eq!(first.proposal_without_votes, None);
        assert_eq!(first.votes_for_proposal.0, [voter.clone()].into());

        let second = registry.register(voter.clone(), pid);

        assert_eq!(second.proposal_without_votes, None);
        assert_eq!(second.votes_for_proposal.0, [voter.clone()].into());

        assert_eq!(registry.votes_by_voter.len(), 1);
        assert_eq!(registry.votes_by_proposal.len(), 1);
        assert_registry_state(&registry, [(pid, [voter.clone()].into())]);
    }

    #[test]
    fn register_switches_vote_and_reports_orphaned_old_proposal() {
        let mut registry = VoteRegistry::<TestVoter>::new();

        let old_pid = ProposalId(1);
        let new_pid = ProposalId(2);
        let voter = TestVoter("alice".to_string());

        registry.register(voter.clone(), old_pid);
        let result = registry.register(voter.clone(), new_pid);

        assert_eq!(result.proposal_without_votes, Some(old_pid));
        assert_eq!(result.votes_for_proposal.0, [voter.clone()].into());

        assert_eq!(registry.votes_by_voter.get(&voter), Some(&new_pid));
        assert_registry_state(&registry, [(new_pid, [voter.clone()].into())]);
    }

    #[test]
    fn register_switches_vote_without_orphaning_if_old_proposal_still_has_other_votes() {
        let mut registry = VoteRegistry::<TestVoter>::new();

        let old_pid = ProposalId(1);
        let new_pid = ProposalId(2);
        let alice = TestVoter("alice".to_string());
        let bob = TestVoter("bob".to_string());

        registry.register(alice.clone(), old_pid);
        registry.register(bob.clone(), old_pid);

        let result = registry.register(alice.clone(), new_pid);

        assert_eq!(result.proposal_without_votes, None);
        assert_eq!(result.votes_for_proposal.0, [alice.clone()].into());

        assert_eq!(registry.votes_by_voter.get(&alice), Some(&new_pid));
        assert_eq!(registry.votes_by_voter.get(&bob), Some(&old_pid));

        assert_registry_state(
            &registry,
            [
                (old_pid, [bob.clone()].into()),
                (new_pid, [alice.clone()].into()),
            ],
        );
    }

    #[test]
    fn remove_vote_of_unknown_voter_is_noop() {
        let mut registry = VoteRegistry::<TestVoter>::new();

        let pid = ProposalId(3);
        let alice = TestVoter("alice".to_string());
        let bob = TestVoter("bob".to_string());

        registry.register(alice.clone(), pid);

        let removed = registry.remove_vote(&bob);

        assert_eq!(removed, None);
        assert_registry_state(&registry, [(pid, [alice.clone()].into())]);
    }

    #[test]
    fn remove_votes_for_unknown_proposal_is_noop() {
        let mut registry = VoteRegistry::<TestVoter>::new();

        let pid1 = ProposalId(1);
        let pid2 = ProposalId(2);
        let alice = TestVoter("alice".to_string());
        let bob = TestVoter("bob".to_string());

        registry.register(alice.clone(), pid1);
        registry.register(bob.clone(), pid2);

        registry.remove_votes_for_proposal(&ProposalId(999));

        assert_registry_state(
            &registry,
            [(pid1, [alice.clone()].into()), (pid2, [bob.clone()].into())],
        );
    }

    #[test]
    fn remove_vote_returns_none_when_proposal_still_has_other_votes() {
        let mut registry = VoteRegistry::<TestVoter>::new();

        let pid = ProposalId(5);
        let alice = TestVoter("alice".to_string());
        let bob = TestVoter("bob".to_string());

        registry.register(alice.clone(), pid);
        registry.register(bob.clone(), pid);

        let removed = registry.remove_vote(&alice);

        assert_eq!(removed, None);
        assert_eq!(registry.votes_by_voter.get(&alice), None);
        assert_eq!(registry.votes_by_voter.get(&bob), Some(&pid));

        assert_registry_state(&registry, [(pid, [bob.clone()].into())]);
    }

    #[test]
    fn remove_vote_returns_proposal_id_when_last_vote_is_removed() {
        let mut registry = VoteRegistry::<TestVoter>::new();

        let pid = ProposalId(9);
        let voter = TestVoter("alice".to_string());

        registry.register(voter.clone(), pid);

        let removed = registry.remove_vote(&voter);

        assert_eq!(removed, Some(pid));
        assert_eq!(registry.votes_by_voter.get(&voter), None);
        assert_registry_state(&registry, []);
    }

    #[test]
    fn remove_votes_for_proposal_removes_both_proposal_and_reverse_index() {
        let mut registry = VoteRegistry::<TestVoter>::new();

        let pid1 = ProposalId(1);
        let pid2 = ProposalId(2);
        let alice = TestVoter("alice".to_string());
        let bob = TestVoter("bob".to_string());
        let carol = TestVoter("carol".to_string());

        registry.register(alice.clone(), pid1);
        registry.register(bob.clone(), pid1);
        registry.register(carol.clone(), pid2);

        registry.remove_votes_for_proposal(&pid1);

        assert_eq!(registry.votes_by_voter.get(&alice), None);
        assert_eq!(registry.votes_by_voter.get(&bob), None);
        assert_eq!(registry.votes_by_voter.get(&carol), Some(&pid2));

        assert_registry_state(&registry, [(pid2, [carol.clone()].into())]);

        let result = registry.register(alice.clone(), pid2);
        assert_eq!(result.proposal_without_votes, None);
        assert_eq!(
            result.votes_for_proposal.0,
            [alice.clone(), carol.clone()].into()
        );

        assert_registry_state(&registry, [(pid2, [alice.clone(), carol.clone()].into())]);
    }

    #[test]
    fn retain_votes_removes_disallowed_voters_and_returns_orphaned_proposals() {
        let mut registry = VoteRegistry::<TestVoter>::new();

        let pid1 = ProposalId(1);
        let pid2 = ProposalId(2);
        let pid3 = ProposalId(3);

        let alice = TestVoter("alice".to_string());
        let bob = TestVoter("bob".to_string());
        let carol = TestVoter("carol".to_string());
        let dave = TestVoter("dave".to_string());

        registry.register(alice.clone(), pid1);
        registry.register(bob.clone(), pid1);
        registry.register(carol.clone(), pid2);
        registry.register(dave.clone(), pid3);

        let mut removed = registry.retain_votes(|v| v == &carol);
        removed.sort();

        // we expect pid2 and pid3 to be removed
        assert_eq!(removed, vec![pid1, pid3]);
        // only pid 2 and carols vote should remain
        assert_registry_state(&registry, [(pid2, [carol.clone()].into())]);
        // additional sanity checks
        assert_eq!(registry.votes_by_voter.len(), 1);
        assert_eq!(registry.votes_by_voter.get(&carol), Some(&pid2));
    }

    #[test]
    fn clear_removes_everything() {
        let mut registry = VoteRegistry::<TestVoter>::new();

        let pid1 = ProposalId(1);
        let pid2 = ProposalId(2);
        let alice = TestVoter("alice".to_string());
        let bob = TestVoter("bob".to_string());

        registry.register(alice.clone(), pid1);
        registry.register(bob.clone(), pid2);

        registry.clear();

        assert_registry_state(&registry, []);
        assert_eq!(registry.votes_by_voter.len(), 0);
        assert_eq!(registry.votes_by_proposal.len(), 0);
    }
}
