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
    /// returns the `ProposalId`
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

    //    /// returns the number of votes for [`ProposalId`]
    pub fn vote(&mut self, voter_id: VoterId, proposal_id: ProposalId) -> u64 {
        0
    }

    /// removes any vote by `voter_id`
    pub fn remove_vote(&mut self, voter_id: VoterId) -> bool {
        true
    }
    /// removes all votes and proposals
    pub fn clear(&mut self) {}
    /// removes any vote not belonging to an element in [`BTreeSet<VoterId>`]
    pub fn retain_votes(voter_ids_to_keep: BTreeSet<VoterId>) {}
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use borsh::BorshSerialize;
    use near_sdk::{store::IterableMap, BorshStorageKey};

    use crate::primitives::votes::types::{ProposalBounds, ProposalEntry, VoterIdBounds, Votes};

    type VoterId = u64;
    type Proposal = String;
    impl VoterIdBounds for u64 {}
    impl ProposalBounds for String {}

    #[derive(BorshStorageKey, BorshSerialize)]
    enum StorageKeys {
        VotesStorageKey,
        ProposalsStorageKey,
    }

    #[test]
    fn test_votes_constructor() {
        let votes: Votes<VoterId, Proposal> = Votes::new(
            StorageKeys::VotesStorageKey,
            StorageKeys::ProposalsStorageKey,
        );
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
        let ProposalEntry {
            proposed,
            num_votes,
        } = votes.proposals.get(&proposal_id).unwrap();
        assert_eq!(*proposed, proposal);
        assert_eq!(*num_votes, 0);
    }

    struct ExpectedVotes {
        votes: BTreeMap<VoterId, Proposal>,
        proposals: BTreeMap<u64, ProposalEntry<Proposal>>,
        next_id: u64,
    }
    // make above, but more complicated: generate random state and give expected value
    fn gen_random_state() -> (Votes<VoterId, Proposal>, ExpectedVotes) {
        let mut rng = rand::thread_rng();
        let x: usize = rng.gen_range(0..=10);
    }
}
