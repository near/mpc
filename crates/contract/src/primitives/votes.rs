use std::hash::Hash;
use std::{collections::BTreeMap, collections::BTreeSet, collections::HashMap};

use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{Deref, From, Into};
use near_sdk::{log, near, store::IterableMap, IntoStorageKey};

use super::thresholds::ThresholdParameters;
use super::{key_state::AuthenticatedAccountId, participants::Participants};

// ---------------------------------------------------------------------------
// Generic Votes<VoterId, Proposal>
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Clone, From, Deref, Into)]
#[near(serializers=[borsh])]
pub struct ProposalId(pub(crate) u64);

#[near(serializers=[borsh])]
pub struct Votes<VoterId, Proposal>
where
    VoterId: BorshSerialize + BorshDeserialize + Ord + Clone,
    Proposal: BorshSerialize + BorshDeserialize + Ord + Clone + Hash,
{
    pub(crate) id_by_proposal: HashMap<Proposal, ProposalId>,
    pub(crate) votes: BTreeMap<VoterId, ProposalId>,
    pub(crate) proposals: IterableMap<ProposalId, Proposal>,
    pub(crate) proposal_votes: BTreeMap<ProposalId, u64>,
    pub(crate) next_id: ProposalId,
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
                return *self.proposal_votes.get(&proposal_id).unwrap();
            }
            let old_proposal_id = old_proposal_id.clone();
            self.decrement_proposal_votes(&old_proposal_id);
        }

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
        let proposal_id = self.propose(proposal);
        self.vote(voter_id, proposal_id)
    }

    /// Removes any vote by `voter_id`. Returns `true` if a vote was removed.
    pub fn remove_vote(&mut self, voter_id: &VoterId) -> bool {
        let Some(proposal_id) = self.votes.remove(voter_id) else {
            return false;
        };
        self.decrement_proposal_votes(&proposal_id);
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

    /// Returns the number of votes for the given `proposal_id`, or 0 if it doesn't exist.
    pub fn n_votes(&self, proposal_id: &ProposalId) -> u64 {
        self.proposal_votes.get(proposal_id).copied().unwrap_or(0)
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

    /// Decrements vote count for a proposal, removing it entirely if count reaches 0.
    fn decrement_proposal_votes(&mut self, proposal_id: &ProposalId) {
        let count = self
            .proposal_votes
            .get_mut(proposal_id)
            .expect("proposal for existing vote must exist");
        *count -= 1;
        if *count == 0 {
            self.proposal_votes.remove(proposal_id);
            if let Some(proposal) = self.proposals.remove(proposal_id) {
                self.id_by_proposal.remove(&proposal);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ThresholdParametersVotes (existing concrete type)
// ---------------------------------------------------------------------------

/// Tracks votes for ThresholdParameters (new participants and threshold).
/// Each current participant can maintain one vote.
#[near(serializers=[borsh, json])]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThresholdParametersVotes {
    pub(crate) proposal_by_account: BTreeMap<AuthenticatedAccountId, ThresholdParameters>,
}

impl ThresholdParametersVotes {
    /// return the number of votes for `proposal` casted by members of `participants`
    pub fn n_votes(&self, proposal: &ThresholdParameters, participants: &Participants) -> u64 {
        self.proposal_by_account
            .iter()
            .filter(|&(acc, prop)| {
                participants
                    .participants()
                    .iter()
                    .any(|(acc_id, _, _)| acc.get() == acc_id)
                    && prop == proposal
            })
            .count() as u64
    }
    /// Registers a vote by `participant` for `proposal`.
    /// Removes any existing votes by `participant`.
    /// Returns the number of participants who have voted for the same proposal (including the new
    /// vote).
    pub fn vote(
        &mut self,
        proposal: &ThresholdParameters,
        participant: AuthenticatedAccountId,
    ) -> u64 {
        if self
            .proposal_by_account
            .insert(participant, proposal.clone())
            .is_some()
        {
            log!("removed one vote for signer");
        }
        self.proposal_by_account
            .values()
            .filter(|&prop| prop == proposal)
            .count() as u64
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{
        key_state::AuthenticatedAccountId,
        participants::Participants,
        test_utils::{gen_participant, gen_threshold_params},
    };
    use near_sdk::{test_utils::VMContextBuilder, testing_env, BorshStorageKey};

    // -- ThresholdParametersVotes tests --

    #[test]
    fn test_voting_and_removal() {
        let mut participants = Participants::default();
        let p0 = gen_participant(0);
        participants.insert(p0.0.clone(), p0.1).expect("error");
        let mut ctx = VMContextBuilder::new();
        ctx.signer_account_id(p0.0);
        testing_env!(ctx.build());
        let participant =
            AuthenticatedAccountId::new(&participants).expect("expected authentication");
        let params = gen_threshold_params(30);
        let mut votes = ThresholdParametersVotes::default();
        assert_eq!(votes.vote(&params, participant.clone()), 1);
        assert_eq!(votes.n_votes(&params, &participants), 1);
        let params2 = gen_threshold_params(30);
        assert_eq!(votes.vote(&params2, participant), 1);
        assert_eq!(votes.n_votes(&params2, &participants), 1);
        assert_eq!(votes.n_votes(&params, &participants), 0);

        // new participant
        let p1 = gen_participant(1);
        participants.insert(p1.0.clone(), p1.1).expect("error");
        ctx.signer_account_id(p1.0);
        testing_env!(ctx.build());
        let participant =
            AuthenticatedAccountId::new(&participants).expect("expected authentication");
        assert_eq!(votes.vote(&params, participant.clone()), 1);
        assert_eq!(votes.n_votes(&params2, &participants), 1);
        assert_eq!(votes.vote(&params2, participant), 2);
        assert_eq!(votes.n_votes(&params2, &participants), 2);
        assert_eq!(votes.n_votes(&params2, params2.participants()), 0);
        assert_eq!(votes.n_votes(&params, &participants), 0);
    }

    #[test]
    fn test_non_participant_votes_not_counted() {
        let mut old_participants = Participants::default();
        let (p0, p1) = (gen_participant(0), gen_participant(1));
        old_participants.insert(p0.0.clone(), p0.1.clone()).unwrap();
        old_participants.insert(p1.0.clone(), p1.1.clone()).unwrap();

        let mut ctx = VMContextBuilder::new();
        let auth_p0 = {
            ctx.signer_account_id(p0.0);
            testing_env!(ctx.build());
            AuthenticatedAccountId::new(&old_participants).unwrap()
        };
        let auth_p1 = {
            ctx.signer_account_id(p1.0);
            testing_env!(ctx.build());
            AuthenticatedAccountId::new(&old_participants).unwrap()
        };

        let params = gen_threshold_params(30);
        let mut votes = ThresholdParametersVotes::default();
        votes.vote(&params, auth_p0);
        votes.vote(&params, auth_p1);
        assert_eq!(votes.n_votes(&params, &old_participants), 2);

        let mut new_participants = Participants::default();
        let p2 = gen_participant(2);
        new_participants.insert(p2.0.clone(), p2.1).unwrap();

        assert_eq!(votes.n_votes(&params, &new_participants), 0);

        ctx.signer_account_id(p2.0);
        testing_env!(ctx.build());
        let auth_p2 = AuthenticatedAccountId::new(&new_participants).unwrap();
        votes.vote(&params, auth_p2);
        assert_eq!(votes.n_votes(&params, &new_participants), 1);
    }

    // -- Generic Votes tests --

    #[derive(BorshStorageKey, BorshSerialize)]
    #[borsh(crate = "borsh")]
    enum StorageKeys {
        Proposals,
    }

    fn new_votes() -> Votes<u64, String> {
        Votes::new(StorageKeys::Proposals)
    }

    #[test]
    fn test_votes_constructor() {
        let votes = new_votes();
        assert_eq!(votes.next_id, 0.into());
        assert!(votes.proposals.is_empty());
        assert!(votes.votes.is_empty());
        assert!(votes.proposal_votes.is_empty());
    }

    #[test]
    fn test_propose_basic() {
        let mut votes = new_votes();
        let pid = votes.propose("hello world".to_string());
        assert_eq!(pid.0, 0);
        assert_eq!(votes.next_id.0, 1);
        assert!(votes.votes.is_empty());
        assert_eq!(votes.proposals.len(), 1);
        assert_eq!(
            *votes.proposals.get(&pid).unwrap(),
            "hello world".to_string()
        );
        assert_eq!(*votes.proposal_votes.get(&pid).unwrap(), 0);
    }

    #[test]
    fn test_propose_deduplicates() {
        let mut votes = new_votes();
        let pid1 = votes.propose("same".to_string());
        let pid2 = votes.propose("same".to_string());
        assert_eq!(pid1, pid2);
        assert_eq!(votes.proposals.len(), 1);
        assert_eq!(votes.next_id.0, 1);
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
        assert!(votes.proposals.contains_key(&pid));
    }

    #[test]
    fn test_clear() {
        let mut votes = new_votes();
        let pid_a = votes.propose("proposal_a".to_string());
        votes.vote(1, pid_a);
        let pid_b = votes.propose("proposal_b".to_string());
        votes.vote(2, pid_b);

        votes.clear();
        assert!(votes.votes.is_empty());
        assert!(votes.proposals.is_empty());
        assert!(votes.proposal_votes.is_empty());
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

        assert_eq!(votes.n_votes(&pid_a), 1);
        assert_eq!(votes.n_votes(&pid_b), 1);
        assert_eq!(votes.votes.len(), 2);
    }

    #[test]
    fn test_retain_votes_removes_empty_proposals() {
        let mut votes = new_votes();
        let pid = votes.propose("proposal_a".to_string());
        votes.vote(1, pid.clone());

        let keep = BTreeSet::new();
        votes.retain_votes(&keep);

        assert!(votes.votes.is_empty());
        assert!(!votes.proposals.contains_key(&pid));
    }

    #[test]
    fn test_vote_for_convenience() {
        let mut votes = new_votes();

        let count = votes.vote_for(1, "proposal_a".to_string());
        assert_eq!(count, 1);
        assert_eq!(votes.proposals.len(), 1);

        let count = votes.vote_for(2, "proposal_a".to_string());
        assert_eq!(count, 2);
        assert_eq!(votes.proposals.len(), 1);

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
        assert_eq!(votes.proposals.len(), 1);
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
        assert_eq!(votes.count_where(&"proposal_a".to_string(), |_| true), 2);
        // Count for nonexistent proposal
        assert_eq!(votes.count_where(&"nonexistent".to_string(), |_| true), 0);
    }
}
