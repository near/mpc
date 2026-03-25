use std::collections::BTreeSet;

use near_sdk::{store::IterableMap, IntoStorageKey};

use super::types::{ProposalBounds, ProposalEntry, ProposalId, VoterIdBounds, Votes};

impl<VoterId, Proposal> Votes<VoterId, Proposal>
where
    VoterId: VoterIdBounds,
    Proposal: ProposalBounds,
{
    pub fn new<S>(votes_key: S, proposals_key: S) -> Self
    where
        S: IntoStorageKey,
    {
        Self {
            votes: IterableMap::new(votes_key),
            proposals: IterableMap::new(proposals_key),
            next_id: 0.into(),
        }
    }

    /// Creates a new proposal and returns its `ProposalId`.
    pub fn propose(&mut self, proposal: Proposal) -> ProposalId {
        let proposal_id = self.next_id.clone();
        let proposal_entry = ProposalEntry {
            proposed: proposal,
            num_votes: 0,
        };
        self.proposals.insert(proposal_id.clone(), proposal_entry);
        self.next_id += 1;
        proposal_id
    }

    /// Casts a vote by `voter_id` for the given `proposal_id`.
    /// If the voter already voted for a different proposal, the old vote is replaced.
    /// Returns the number of votes for `proposal_id` after this vote is cast.
    ///
    /// # Panics
    /// Panics if `proposal_id` does not exist.
    pub fn vote(&mut self, voter_id: VoterId, proposal_id: ProposalId) -> u64 {
        assert!(
            self.proposals.contains_key(&proposal_id),
            "proposal_id does not exist"
        );

        // Check if voter already has a vote
        if let Some(old_proposal_id) = self.votes.get(&voter_id) {
            if *old_proposal_id == proposal_id {
                // Already voting for this proposal — no-op
                return self.proposals.get(&proposal_id).unwrap().num_votes;
            }
            // Decrement old proposal's vote count
            let old_proposal_id = old_proposal_id.clone();
            let old_entry = self.proposals.get_mut(&old_proposal_id).unwrap();
            old_entry.num_votes -= 1;
            if old_entry.num_votes == 0 {
                self.proposals.remove(&old_proposal_id);
            }
        }

        // Record the vote
        self.votes.insert(voter_id, proposal_id.clone());

        // Increment the proposal's vote count
        let entry = self.proposals.get_mut(&proposal_id).unwrap();
        entry.num_votes += 1;
        entry.num_votes
    }

    /// Removes any vote by `voter_id`. Returns `true` if a vote was removed.
    pub fn remove_vote(&mut self, voter_id: &VoterId) -> bool {
        let Some((_voter_id, proposal_id)) = self.votes.remove_entry(voter_id) else {
            return false;
        };

        let entry = self
            .proposals
            .get_mut(&proposal_id)
            .expect("proposal for existing vote must exist");
        entry.num_votes -= 1;
        if entry.num_votes == 0 {
            self.proposals.remove(&proposal_id);
        }
        true
    }

    /// Removes all votes and proposals.
    pub fn clear(&mut self) {
        self.votes.clear();
        self.proposals.clear();
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

    /// Finds an existing proposal by value, returning its `ProposalId` if found.
    pub fn find_proposal(&self, proposal: &Proposal) -> Option<ProposalId> {
        self.proposals
            .iter()
            .find(|(_id, entry)| entry.proposed == *proposal)
            .map(|(id, _entry)| id.clone())
    }

    /// Convenience method: votes for a proposal by value.
    /// If a matching proposal already exists, votes for it; otherwise creates a new one.
    /// Returns the number of votes for the proposal after this vote.
    pub fn vote_for(&mut self, voter_id: VoterId, proposal: Proposal) -> u64 {
        let proposal_id = self
            .find_proposal(&proposal)
            .unwrap_or_else(|| self.propose(proposal));
        self.vote(voter_id, proposal_id)
    }

    /// Returns the number of votes for the given `proposal_id`, or 0 if it doesn't exist.
    pub fn n_votes(&self, proposal_id: &ProposalId) -> u64 {
        self.proposals
            .get(proposal_id)
            .map_or(0, |entry| entry.num_votes)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use borsh::BorshSerialize;
    use near_sdk::{store::IterableMap, BorshStorageKey};

    use crate::primitives::votes::types::{ProposalBounds, VoterIdBounds, Votes};

    type VoterId = u64;
    type Proposal = String;
    impl VoterIdBounds for u64 {}
    impl ProposalBounds for String {}

    #[derive(BorshStorageKey, BorshSerialize)]
    #[borsh(crate = "borsh")]
    enum StorageKeys {
        VotesStorageKey,
        ProposalsStorageKey,
    }

    fn new_votes() -> Votes<VoterId, Proposal> {
        Votes::new(StorageKeys::VotesStorageKey, StorageKeys::ProposalsStorageKey)
    }

    #[test]
    fn test_votes_constructor() {
        let votes = new_votes();
        assert_eq!(votes.next_id, 0.into());
        assert!(votes.proposals.is_empty());
        assert!(votes.votes.is_empty());
    }

    #[test]
    fn test_votes_propose_basic() {
        let expected_proposal_id = 42u64;
        let mut votes = Votes::<VoterId, Proposal> {
            votes: IterableMap::new(StorageKeys::VotesStorageKey),
            proposals: IterableMap::new(StorageKeys::ProposalsStorageKey),
            next_id: expected_proposal_id.into(),
        };

        let proposal: Proposal = "hello world".into();
        let proposal_id = votes.propose(proposal.clone());
        assert_eq!(proposal_id.0, expected_proposal_id);
        assert_eq!(votes.next_id.0, expected_proposal_id + 1);
        assert!(votes.votes.is_empty());
        assert_eq!(votes.proposals.len(), 1);
        let entry = votes.proposals.get(&proposal_id).unwrap();
        assert_eq!(entry.proposed, proposal);
        assert_eq!(entry.num_votes, 0);
    }

    #[test]
    fn test_vote_basic() {
        let mut votes = new_votes();
        let pid = votes.propose("proposal_a".to_string());
        let count = votes.vote(1, pid.clone());
        assert_eq!(count, 1);
        assert_eq!(votes.n_votes(&pid), 1);
    }

    #[test]
    fn test_vote_multiple_voters_same_proposal() {
        let mut votes = new_votes();
        let pid = votes.propose("proposal_a".to_string());
        votes.vote(1, pid.clone());
        let count = votes.vote(2, pid.clone());
        assert_eq!(count, 2);
        assert_eq!(votes.n_votes(&pid), 2);
    }

    #[test]
    fn test_vote_replacement() {
        let mut votes = new_votes();
        let pid_a = votes.propose("proposal_a".to_string());
        let pid_b = votes.propose("proposal_b".to_string());

        votes.vote(1, pid_a.clone());
        assert_eq!(votes.n_votes(&pid_a), 1);

        // Switch vote from A to B
        let count = votes.vote(1, pid_b.clone());
        assert_eq!(count, 1);
        assert_eq!(votes.n_votes(&pid_b), 1);
        // A should be removed (0 votes)
        assert_eq!(votes.n_votes(&pid_a), 0);
        assert!(!votes.proposals.contains_key(&pid_a));
    }

    #[test]
    fn test_vote_idempotent() {
        let mut votes = new_votes();
        let pid = votes.propose("proposal_a".to_string());
        votes.vote(1, pid.clone());
        let count = votes.vote(1, pid.clone());
        assert_eq!(count, 1);
    }

    #[test]
    #[should_panic(expected = "proposal_id does not exist")]
    fn test_vote_invalid_proposal_id() {
        let mut votes = new_votes();
        votes.vote(1, 999u64.into());
    }

    #[test]
    fn test_remove_vote_exists() {
        let mut votes = new_votes();
        let pid = votes.propose("proposal_a".to_string());
        votes.vote(1, pid.clone());

        assert!(votes.remove_vote(&1));
        assert!(votes.votes.is_empty());
        // Proposal should be removed since it has 0 votes
        assert!(!votes.proposals.contains_key(&pid));
    }

    #[test]
    fn test_remove_vote_nonexistent() {
        let mut votes = new_votes();
        assert!(!votes.remove_vote(&1));
    }

    #[test]
    fn test_remove_vote_preserves_other_votes() {
        let mut votes = new_votes();
        let pid = votes.propose("proposal_a".to_string());
        votes.vote(1, pid.clone());
        votes.vote(2, pid.clone());

        assert!(votes.remove_vote(&1));
        assert_eq!(votes.n_votes(&pid), 1);
        // Proposal should still exist since voter 2 still has a vote
        assert!(votes.proposals.contains_key(&pid));
    }

    #[test]
    fn test_clear() {
        let mut votes = new_votes();
        let pid = votes.propose("proposal_a".to_string());
        votes.vote(1, pid);
        let pid_b = votes.propose("proposal_b".to_string());
        votes.vote(2, pid_b);

        votes.clear();
        assert!(votes.votes.is_empty());
        assert!(votes.proposals.is_empty());
        // next_id should remain monotonic
        assert_eq!(votes.next_id.0, 2);
    }

    #[test]
    fn test_retain_votes() {
        let mut votes = new_votes();
        let pid_a = votes.propose("proposal_a".to_string());
        let pid_b = votes.propose("proposal_b".to_string());
        votes.vote(1, pid_a.clone());
        votes.vote(2, pid_a.clone());
        votes.vote(3, pid_b.clone());

        let keep = BTreeSet::from([1, 3]);
        votes.retain_votes(&keep);

        assert_eq!(votes.n_votes(&pid_a), 1); // only voter 1 remains
        assert_eq!(votes.n_votes(&pid_b), 1); // voter 3 remains
        assert_eq!(votes.votes.len(), 2);
    }

    #[test]
    fn test_retain_votes_removes_empty_proposals() {
        let mut votes = new_votes();
        let pid = votes.propose("proposal_a".to_string());
        votes.vote(1, pid.clone());

        let keep = BTreeSet::new(); // keep nobody
        votes.retain_votes(&keep);

        assert!(votes.votes.is_empty());
        assert!(!votes.proposals.contains_key(&pid));
    }

    #[test]
    fn test_vote_for_convenience() {
        let mut votes = new_votes();

        // First vote creates the proposal
        let count = votes.vote_for(1, "proposal_a".to_string());
        assert_eq!(count, 1);
        assert_eq!(votes.proposals.len(), 1);

        // Second vote for same value reuses the proposal
        let count = votes.vote_for(2, "proposal_a".to_string());
        assert_eq!(count, 2);
        assert_eq!(votes.proposals.len(), 1);

        // Vote for different value creates a new proposal
        let count = votes.vote_for(3, "proposal_b".to_string());
        assert_eq!(count, 1);
        assert_eq!(votes.proposals.len(), 2);
    }

    #[test]
    fn test_vote_for_replacement() {
        let mut votes = new_votes();
        votes.vote_for(1, "proposal_a".to_string());
        let count = votes.vote_for(1, "proposal_b".to_string());
        assert_eq!(count, 1);
        // proposal_a should be gone (0 votes)
        assert_eq!(votes.proposals.len(), 1);
    }

    #[test]
    fn test_find_proposal() {
        let mut votes = new_votes();
        let pid = votes.propose("proposal_a".to_string());
        assert_eq!(votes.find_proposal(&"proposal_a".to_string()), Some(pid));
        assert_eq!(votes.find_proposal(&"nonexistent".to_string()), None);
    }
}
