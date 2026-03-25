use std::hash::Hash;
use std::{collections::BTreeMap, collections::BTreeSet, collections::HashMap};

use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{Deref, From, Into};
use near_sdk::{near, store::IterableMap, IntoStorageKey};

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Clone, From, Deref, Into)]
#[near(serializers=[borsh])]
pub struct ProposalId(pub(crate) u64);

#[near(serializers=[borsh])]
pub struct Votes<VoterId, Proposal>
where
    VoterId: BorshSerialize + BorshDeserialize + Ord + Clone,
    Proposal: BorshSerialize + BorshDeserialize + Ord + Clone + Hash,
{
    id_by_proposal: HashMap<Proposal, ProposalId>,
    votes: BTreeMap<VoterId, ProposalId>,
    proposals: IterableMap<ProposalId, Proposal>,
    // this struct is useful for internal book keeping
    proposal_votes: BTreeMap<ProposalId, u64>,
    next_id: ProposalId,
}

impl<VoterId, Proposal> Votes<VoterId, Proposal>
where
    VoterId: BorshSerialize + BorshDeserialize + Ord + Clone,
    Proposal: BorshSerialize + BorshDeserialize + Ord + Clone + Hash,
{
    pub fn new<S>(proposals_key: S) -> Self
    where
        S: IntoStorageKey,
    {
        Self {
            id_by_proposal: HashMap::new(),
            votes: BTreeMap::new(),
            proposals: IterableMap::new(proposals_key),
            proposal_votes: BTreeMap::new(),
            next_id: 0.into(),
        }
    }

    /// Creates a new proposal and returns its `ProposalId`.
    /// If a proposal with the same value already exists, returns its existing id.
    pub fn propose(&mut self, proposal: Proposal) -> ProposalId {
        if let Some(existing_id) = self.id_by_proposal.get(&proposal) {
            return existing_id.clone();
        }
        let proposal_id = self.next_id.clone();
        self.next_id = Into::<u64>::into(proposal_id.clone())
            .overflowing_add(1)
            .0
            .into();
        self.id_by_proposal
            .insert(proposal.clone(), proposal_id.clone());
        self.proposals.insert(proposal_id.clone(), proposal);
        self.proposal_votes.insert(proposal_id.clone(), 0);
        proposal_id
    }

    fn vote_by_id(&mut self, voter_id: VoterId, proposal_id: ProposalId) -> u64 {
        assert!(
            self.proposals.contains_key(&proposal_id),
            "proposal_id does not exist"
        );
        assert!(
            self.votes.get(&voter_id).is_none(),
            "voter already registered"
        );

        // Record the vote
        self.votes.insert(voter_id, proposal_id.clone());
        let count = self.proposal_votes.get_mut(&proposal_id).unwrap();
        *count += 1;
        *count
    }

    /// Convenience method: votes for a proposal by value.
    /// If a matching proposal already exists, votes for it; otherwise creates a new one.
    /// Returns the number of votes for the proposal after this vote.
    pub fn vote_for(&mut self, voter_id: VoterId, proposal: Proposal) -> u64 {
        self.remove_vote(&voter_id);
        let proposal_id = self.propose(proposal);
        self.vote_by_id(voter_id, proposal_id)
    }

    /// Removes any vote by `voter_id`. Returns `true` if a vote was removed.
    pub fn remove_vote(&mut self, voter_id: &VoterId) -> bool {
        let Some(proposal_id) = self.votes.remove(voter_id) else {
            return false;
        };
        let count = self
            .proposal_votes
            .get_mut(&proposal_id)
            .expect("proposal for existing vote must exist");
        // use saturating sub instead
        *count -= 1;
        if *count == 0 {
            self.proposal_votes.remove(&proposal_id);
            if let Some(proposal) = self.proposals.remove(&proposal_id) {
                self.id_by_proposal.remove(&proposal);
            }
        }
        true
    }

    /// Removes all votes and proposals.
    pub fn clear(&mut self) {
        self.votes.clear();
        // Drain proposals to clean up the reverse lookup map
        let proposal_ids: Vec<ProposalId> = self.proposals.keys().cloned().collect();
        for pid in proposal_ids {
            if let Some(proposal) = self.proposals.remove(&pid) {
                self.id_by_proposal.remove(&proposal);
            }
        }
        self.proposal_votes.clear();
    }

    /// Removes any vote not belonging to a voter in `voter_ids_to_keep`.
    pub fn retain_votes(&mut self, voter_ids_to_keep: &BTreeSet<VoterId>) {
        let to_remove: Vec<VoterId> = self
            .votes
            .keys()
            .filter(|vid| !voter_ids_to_keep.contains(vid))
            .cloned()
            .collect();
        for voter_id in to_remove {
            self.remove_vote(&voter_id);
        }
    }

    /// Counts votes for `proposal` where the voter satisfies `predicate`.
    /// Looks up the proposal by value, then filters voters.
    pub fn count_where(&self, proposal: &Proposal, predicate: impl Fn(&VoterId) -> bool) -> u64 {
        let Some(proposal_id) = self.id_by_proposal.get(proposal) else {
            return 0;
        };
        self.votes
            .iter()
            .filter(|(vid, pid)| **pid == *proposal_id && predicate(vid))
            .count() as u64
    }

    /// Returns the number of distinct proposals with at least one vote.
    pub fn num_proposals(&self) -> usize {
        self.proposals.len() as usize
    }

    /// Returns the number of voters.
    pub fn num_voters(&self) -> usize {
        self.votes.len()
    }

    /// Returns true if there are no votes.
    pub fn is_empty(&self) -> bool {
        self.votes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshSerialize;
    use near_sdk::BorshStorageKey;
    use std::collections::BTreeSet;

    #[derive(BorshStorageKey, BorshSerialize)]
    #[borsh(crate = "borsh")]
    enum StorageKeys {
        Proposals,
    }

    fn new_votes() -> Votes<u64, String> {
        Votes::new(StorageKeys::Proposals)
    }

    fn count_all(votes: &Votes<u64, String>, proposal: &str) -> u64 {
        votes.count_where(&proposal.to_string(), |_| true)
    }

    #[test]
    fn test_votes_constructor() {
        let votes = new_votes();
        assert!(votes.is_empty());
        assert_eq!(votes.num_proposals(), 0);
    }

    #[test]
    fn test_propose_basic() {
        let mut votes = new_votes();
        let _pid = votes.propose("hello world".to_string());
        assert!(votes.is_empty()); // no votes yet, just a proposal
        assert_eq!(votes.num_proposals(), 1);
    }

    #[test]
    fn test_propose_deduplicates() {
        let mut votes = new_votes();
        let pid1 = votes.propose("same".to_string());
        let pid2 = votes.propose("same".to_string());
        assert_eq!(pid1, pid2);
        assert_eq!(votes.num_proposals(), 1);
    }

    #[test]
    fn test_vote_for_basic() {
        let mut votes = new_votes();
        let count = votes.vote_for(1, "proposal_a".to_string());
        assert_eq!(count, 1);
        assert_eq!(count_all(&votes, "proposal_a"), 1);
    }

    #[test]
    fn test_vote_for_multiple_voters_same_proposal() {
        let mut votes = new_votes();
        votes.vote_for(1, "proposal_a".to_string());
        let count = votes.vote_for(2, "proposal_a".to_string());
        assert_eq!(count, 2);
        assert_eq!(count_all(&votes, "proposal_a"), 2);
    }

    #[test]
    fn test_vote_for_replacement() {
        let mut votes = new_votes();
        votes.vote_for(1, "proposal_a".to_string());
        assert_eq!(count_all(&votes, "proposal_a"), 1);

        // Switch vote from A to B
        let count = votes.vote_for(1, "proposal_b".to_string());
        assert_eq!(count, 1);
        assert_eq!(count_all(&votes, "proposal_b"), 1);
        // A should be removed (0 votes)
        assert_eq!(count_all(&votes, "proposal_a"), 0);
        assert_eq!(votes.num_proposals(), 1);
    }

    #[test]
    fn test_vote_for_idempotent() {
        let mut votes = new_votes();
        votes.vote_for(1, "proposal_a".to_string());
        let count = votes.vote_for(1, "proposal_a".to_string());
        assert_eq!(count, 1);
    }

    #[test]
    fn test_remove_vote_exists() {
        let mut votes = new_votes();
        votes.vote_for(1, "proposal_a".to_string());

        assert!(votes.remove_vote(&1));
        assert!(votes.is_empty());
        assert_eq!(votes.num_proposals(), 0);
    }

    #[test]
    fn test_remove_vote_nonexistent() {
        let mut votes = new_votes();
        assert!(!votes.remove_vote(&1));
    }

    #[test]
    fn test_remove_vote_preserves_other_votes() {
        let mut votes = new_votes();
        votes.vote_for(1, "proposal_a".to_string());
        votes.vote_for(2, "proposal_a".to_string());

        assert!(votes.remove_vote(&1));
        assert_eq!(count_all(&votes, "proposal_a"), 1);
        assert_eq!(votes.num_proposals(), 1);
    }

    #[test]
    fn test_clear() {
        let mut votes = new_votes();
        votes.vote_for(1, "proposal_a".to_string());
        votes.vote_for(2, "proposal_b".to_string());

        votes.clear();
        assert!(votes.is_empty());
        assert_eq!(votes.num_proposals(), 0);
    }

    #[test]
    fn test_retain_votes() {
        let mut votes = new_votes();
        votes.vote_for(1, "proposal_a".to_string());
        votes.vote_for(2, "proposal_a".to_string());
        votes.vote_for(3, "proposal_b".to_string());

        let keep = BTreeSet::from([1, 3]);
        votes.retain_votes(&keep);

        assert_eq!(count_all(&votes, "proposal_a"), 1);
        assert_eq!(count_all(&votes, "proposal_b"), 1);
        assert_eq!(votes.num_voters(), 2);
    }

    #[test]
    fn test_retain_votes_removes_empty_proposals() {
        let mut votes = new_votes();
        votes.vote_for(1, "proposal_a".to_string());

        let keep = BTreeSet::new();
        votes.retain_votes(&keep);

        assert!(votes.is_empty());
        assert_eq!(votes.num_proposals(), 0);
    }

    #[test]
    fn test_vote_for_convenience() {
        let mut votes = new_votes();

        let count = votes.vote_for(1, "proposal_a".to_string());
        assert_eq!(count, 1);
        assert_eq!(votes.num_proposals(), 1);

        let count = votes.vote_for(2, "proposal_a".to_string());
        assert_eq!(count, 2);
        assert_eq!(votes.num_proposals(), 1);

        let count = votes.vote_for(3, "proposal_b".to_string());
        assert_eq!(count, 1);
        assert_eq!(votes.num_proposals(), 2);
    }

    #[test]
    fn test_count_where() {
        let mut votes = new_votes();
        votes.vote_for(1, "proposal_a".to_string());
        votes.vote_for(2, "proposal_a".to_string());
        votes.vote_for(3, "proposal_b".to_string());

        // Count only even voter ids for proposal_a
        assert_eq!(
            votes.count_where(&"proposal_a".to_string(), |vid| *vid % 2 == 0),
            1
        );
        // Count all for proposal_a
        assert_eq!(count_all(&votes, "proposal_a"), 2);
        // Count for nonexistent proposal
        assert_eq!(count_all(&votes, "nonexistent"), 0);
    }
}
