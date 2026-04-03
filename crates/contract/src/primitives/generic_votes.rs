use std::hash::Hash;
use std::{collections::BTreeMap, collections::BTreeSet, collections::HashMap};

use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{Deref, From, Into};
use near_sdk::require;
use near_sdk::{near, store::IterableMap, IntoStorageKey};

/// Keeps track of proposals and votes.
/// Invariants:
/// - Each voter has at most one active vote.
/// - Each proposal has at least one vote.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct Votes<V, P>
where
    V: VoterBounds,
    P: ProposalBounds,
{
    proposal_registry: ProposalRegistry<P>,
    vote_registry: VoteRegistry<V>,
}

pub trait ProposalBounds: BorshSerialize + BorshDeserialize + Ord + Clone + Hash {}
pub trait VoterBounds: BorshSerialize + BorshDeserialize + Ord + Clone {}

impl<T: BorshSerialize + BorshDeserialize + Ord + Clone + Hash> ProposalBounds for T {}
impl<T: BorshSerialize + BorshDeserialize + Ord + Clone> VoterBounds for T {}

impl<V, P> Votes<V, P>
where
    V: VoterBounds,
    P: ProposalBounds,
{
    pub fn new(storage_key: impl IntoStorageKey) -> Self {
        Self {
            proposal_registry: ProposalRegistry::new(storage_key),
            vote_registry: VoteRegistry::new(),
        }
    }

    pub fn vote_for(&mut self, voter: V, proposal_id: ProposalId) -> &VoterSet<V> {
        if !self.proposal_registry.contains(&proposal_id) {
            panic!("inconsistent Votes");
        }
        let VoteResult {
            votes_for_proposal,
            orphaned_proposal,
        } = self.vote_registry.vote(voter, proposal_id);
        if let Some(removed_proposal) = orphaned_proposal {
            self.proposal_registry.remove(&removed_proposal);
        }
        votes_for_proposal
    }

    pub fn vote(&mut self, voter: V, proposal: P) -> &VoterSet<V> {
        let proposal_id = self.proposal_registry.register(proposal);
        self.vote_for(voter, proposal_id)
    }

    pub fn snapshot(&self) -> BTreeMap<P, BTreeSet<V>> {
        let mut result = BTreeMap::new();
        for (proposal_id, proposal) in self.proposal_registry.proposals_by_id.iter() {
            let voters = self
                .vote_registry
                .votes_by_proposal
                .get(proposal_id)
                .map(|vs| vs.0.clone())
                .unwrap_or_default();
            result.insert(proposal.clone(), voters);
        }
        result
    }

    pub fn remove_vote(&mut self, voter: &V) {
        if let Some(proposal_id) = self.vote_registry.remove_vote(voter) {
            self.proposal_registry.remove(&proposal_id);
        }
    }

    pub fn remove_proposal(&mut self, proposal_id: &ProposalId) {
        self.proposal_registry.remove(proposal_id);
        self.vote_registry.remove_votes_for_proposal(proposal_id);
    }

    pub fn retain_votes(&mut self, keep: impl Fn(&V) -> bool) {
        let proposals_without_votes = self.vote_registry.retain_votes(keep);
        for proposal in &proposals_without_votes {
            self.proposal_registry.remove(proposal);
        }
    }

    pub fn clear(&mut self) {
        self.retain_votes(|_| false);
    }

    pub fn votes_by_voter(&self) -> BTreeMap<V, P> {
        self.vote_registry
            .votes_by_voter
            .iter()
            .filter_map(|(voter, pid)| {
                self.proposal_registry
                    .proposals_by_id
                    .get(pid)
                    .map(|proposal| (voter.clone(), proposal.clone()))
            })
            .collect()
    }
}

#[near(serializers=[borsh])]
#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Clone, Copy, From, Deref, Into)]
pub struct ProposalId(pub(crate) u64);

impl ProposalId {
    fn next(&self) -> Self {
        let (next, overflow) = self.0.overflowing_add(1);
        if overflow {
            near_sdk::env::panic_str("overflow in proposal id")
        }
        ProposalId(next)
    }
}

/// Keeps track of proposals and assigns stable ids.
/// `id_by_proposal` and `proposals_by_id` are inverse of one another.
/// `next_id` is the next ID to assign (monotonically increasing).
#[near(serializers=[borsh])]
#[derive(Debug)]
struct ProposalRegistry<T>
where
    T: ProposalBounds,
{
    id_by_proposal: HashMap<T, ProposalId>,
    // reverse lookup
    proposals_by_id: IterableMap<ProposalId, T>,
    next_id: ProposalId,
}

impl<T> ProposalRegistry<T>
where
    T: ProposalBounds,
{
    fn new(storage_key: impl IntoStorageKey) -> Self {
        Self {
            id_by_proposal: HashMap::new(),
            proposals_by_id: IterableMap::new(storage_key),
            next_id: ProposalId(0),
        }
    }

    fn register(&mut self, proposal: T) -> ProposalId {
        if let Some(proposal_id) = self.id_by_proposal.get(&proposal) {
            return *proposal_id;
        }
        let proposal_id = self.next_id;
        self.next_id = self.next_id.next();
        self.id_by_proposal.insert(proposal.clone(), proposal_id);
        self.proposals_by_id.insert(proposal_id, proposal);
        proposal_id
    }

    fn remove(&mut self, proposal_id: &ProposalId) {
        if let Some(proposal) = self.proposals_by_id.remove(proposal_id) {
            self.id_by_proposal.remove(&proposal);
        }
    }

    fn contains(&self, proposal_id: &ProposalId) -> bool {
        self.proposals_by_id.contains_key(proposal_id)
    }
}

/// Tracks which voter voted for which proposal. `votes_by_voter` and `votes_by_proposal`
/// are kept in sync — every entry in one has a corresponding entry in the other.
#[near(serializers=[borsh])]
#[derive(Debug)]
struct VoteRegistry<V>
where
    V: VoterBounds,
{
    votes_by_voter: BTreeMap<V, ProposalId>,
    votes_by_proposal: VotesByProposal<V>,
}

impl<V> VoteRegistry<V>
where
    V: VoterBounds,
{
    fn new() -> Self {
        Self {
            votes_by_voter: BTreeMap::new(),
            votes_by_proposal: VotesByProposal::new(),
        }
    }

    // returns Some(ProposalId) if removing this vote lead to the removal of a proposal id
    fn remove_vote(&mut self, voter: &V) -> Option<ProposalId> {
        let proposal = self.votes_by_voter.get(voter)?;
        let res = self.votes_by_proposal.remove_vote(voter, proposal);
        self.votes_by_voter.remove(voter);
        res
    }

    fn remove_votes_for_proposal(&mut self, proposal: &ProposalId) {
        let Some(voters) = self.votes_by_proposal.remove_all(proposal) else {
            return;
        };
        for voter in &voters.0 {
            self.votes_by_voter.remove(voter);
        }
    }

    fn retain_votes(&mut self, keep: impl Fn(&V) -> bool) -> Vec<ProposalId> {
        let votes_to_remove: Vec<V> = self
            .votes_by_voter
            .keys()
            .filter(|voter| !keep(voter))
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

    fn vote(&mut self, voter: V, proposal: ProposalId) -> VoteResult<'_, V> {
        let removed_vote = match self.votes_by_voter.get(&voter) {
            Some(existing_vote) if *existing_vote != proposal => self.remove_vote(&voter),
            Some(_) => {
                return VoteResult {
                    votes_for_proposal: self
                        .votes_by_proposal
                        .get(&proposal)
                        .expect("require consistent vote registry"),
                    orphaned_proposal: None,
                }
            }
            None => None,
        };
        // add new vote
        require!(
            self.votes_by_voter
                .insert(voter.clone(), proposal)
                .is_none(),
            "inconsistent voter registry"
        );
        VoteResult {
            votes_for_proposal: self.votes_by_proposal.cast_vote(voter, proposal),
            orphaned_proposal: removed_vote,
        }
    }
}

/// Return value of `VoteRegistry::vote()` — the current votes for the proposal, plus
/// optionally a proposal ID that was orphaned (lost its last vote) due to the voter switching.
struct VoteResult<'a, V>
where
    V: VoterBounds,
{
    votes_for_proposal: &'a VoterSet<V>,
    orphaned_proposal: Option<ProposalId>,
}

/// Maps proposal IDs to the set of voters. An entry exists only if at least one voter
/// has voted for that proposal (no empty entries).
#[near(serializers=[borsh])]
#[derive(Debug)]
struct VotesByProposal<V>(BTreeMap<ProposalId, VoterSet<V>>)
where
    V: VoterBounds;

impl<V> VotesByProposal<V>
where
    V: VoterBounds,
{
    fn new() -> Self {
        Self(BTreeMap::new())
    }

    fn cast_vote(&mut self, voter: V, proposal: ProposalId) -> &VoterSet<V> {
        let entry = self.0.entry(proposal).or_insert_with(VoterSet::new);
        entry.0.insert(voter);
        entry
    }
    // returns Some(proposal_id) in case there are no more votes for `proposal_id`
    fn remove_vote(&mut self, voter: &V, proposal: &ProposalId) -> Option<ProposalId> {
        let casted_votes = self.0.get_mut(proposal)?;
        let remaining = casted_votes.remove(voter)?;
        if remaining == 0 {
            self.0.remove(proposal);
            Some(*proposal)
        } else {
            None
        }
    }
    fn remove_all(&mut self, proposal: &ProposalId) -> Option<VoterSet<V>> {
        self.0.remove(proposal)
    }
    fn get(&self, proposal: &ProposalId) -> Option<&VoterSet<V>> {
        self.0.get(proposal)
    }
}

/// The set of voters who voted for a particular proposal. Always non-empty when stored
/// inside `VotesByProposal`.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct VoterSet<V>(BTreeSet<V>)
where
    V: VoterBounds;

impl<V> VoterSet<V>
where
    V: VoterBounds,
{
    fn new() -> Self {
        Self(BTreeSet::new())
    }

    // counts all the votes for which `predicate` returns true
    pub fn count_for(&self, predicate: impl Fn(&V) -> bool) -> usize {
        self.0.iter().filter(|voter| predicate(voter)).count()
    }

    // returns Some(remaining_votes) in case a vote was removed
    fn remove(&mut self, vote: &V) -> Option<usize> {
        if self.0.remove(vote) {
            Some(self.0.len())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::{test_utils::VMContextBuilder, testing_env, BorshStorageKey};

    #[near(serializers=[borsh])]
    #[derive(BorshStorageKey, Hash, Clone, Debug, PartialEq, Eq)]
    enum TestStorageKey {
        Proposals,
    }

    fn setup() -> Votes<u64, String> {
        testing_env!(VMContextBuilder::new().build());
        Votes::new(TestStorageKey::Proposals)
    }

    /// Helper to build expected snapshots concisely.
    fn snap(entries: &[(&str, &[u64])]) -> BTreeMap<String, BTreeSet<u64>> {
        entries
            .iter()
            .map(|(p, vs)| (p.to_string(), vs.iter().copied().collect()))
            .collect()
    }

    #[test]
    fn test_vote_for() {
        let mut votes = setup();
        let casted = votes.vote(1, "p".to_string());
        assert_eq!(casted.count_for(|_| true), 1);
        assert_eq!(votes.snapshot(), snap(&[("p", &[1])]));
    }

    #[test]
    fn test_voter_can_switch_votes() {
        let mut votes = setup();
        votes.vote(1, "a".to_string());
        votes.vote(1, "b".to_string());
        assert_eq!(votes.snapshot(), snap(&[("b", &[1])]));
    }

    #[test]
    fn test_remove_vote_then_vote_again() {
        let mut votes = setup();
        votes.vote(1, "a".to_string());
        votes.remove_vote(&1);
        votes.vote(1, "b".to_string());
        assert_eq!(votes.snapshot(), snap(&[("b", &[1])]));
    }

    #[test]
    fn test_no_empty_casted_votes_entries() {
        let mut votes = setup();
        votes.vote(1, "p".to_string());
        votes.remove_vote(&1);
        assert_eq!(votes.snapshot(), snap(&[]));
    }

    #[test]
    fn test_multiple_voters_same_proposal() {
        let mut votes = setup();
        votes.vote(1, "p".to_string());
        let casted = votes.vote(2, "p".to_string());
        assert_eq!(casted.count_for(|_| true), 2);
        assert_eq!(votes.snapshot(), snap(&[("p", &[1, 2])]));
    }

    #[test]
    fn test_vote_idempotent() {
        let mut votes = setup();
        votes.vote(1, "p".to_string());
        assert_eq!(votes.snapshot(), snap(&[("p", &[1])]));
        votes.vote(1, "p".to_string());
        assert_eq!(votes.snapshot(), snap(&[("p", &[1])]));
    }

    #[test]
    fn test_retain_removes_empty() {
        let mut votes = setup();
        votes.vote(1, "p".to_string());
        votes.retain_votes(|_| false);
        assert_eq!(votes.snapshot(), snap(&[]));
    }

    #[test]
    fn test_retain_keeps_voted() {
        let mut votes = setup();
        votes.vote(1, "a".to_string());
        votes.vote(2, "a".to_string());
        votes.vote(3, "b".to_string());
        votes.retain_votes(|v| *v == 1);
        assert_eq!(votes.snapshot(), snap(&[("a", &[1])]));
    }

    #[test]
    fn test_remove_proposal() {
        let mut votes = setup();
        votes.vote(1, "p".to_string());
        let pid = votes.proposal_registry.id_by_proposal["p"];
        votes.remove_proposal(&pid);
        votes.vote(1, "q".to_string());
        assert_eq!(votes.snapshot(), snap(&[("q", &[1])]));
    }

    #[test]
    fn test_vote_convenience() {
        let mut votes = setup();
        votes.vote(1, "a".to_string());
        votes.vote(2, "a".to_string());
        votes.vote(3, "b".to_string());
        assert_eq!(votes.snapshot(), snap(&[("a", &[1, 2]), ("b", &[3])]));
    }

    // -- idempotency tests --

    #[test]
    fn test_vote_for_idempotent() {
        let mut votes = setup();
        votes.vote(1, "p".to_string());
        let expected = snap(&[("p", &[1])]);
        assert_eq!(votes.snapshot(), expected);
        // vote_for same voter+proposal again
        let pid = votes.proposal_registry.id_by_proposal["p"];
        votes.vote_for(1, pid);
        assert_eq!(votes.snapshot(), expected);
    }

    #[test]
    fn test_remove_vote_idempotent() {
        let mut votes = setup();
        votes.vote(1, "p".to_string());
        votes.remove_vote(&1);
        let expected = snap(&[]);
        assert_eq!(votes.snapshot(), expected);
        votes.remove_vote(&1); // no-op
        assert_eq!(votes.snapshot(), expected);
    }

    #[test]
    fn test_remove_proposal_idempotent() {
        let mut votes = setup();
        votes.vote(1, "p".to_string());
        let pid = votes.proposal_registry.id_by_proposal["p"];
        votes.remove_proposal(&pid);
        let expected = snap(&[]);
        assert_eq!(votes.snapshot(), expected);
        votes.remove_proposal(&pid); // no-op
        assert_eq!(votes.snapshot(), expected);
    }

    #[test]
    fn test_retain_votes_idempotent() {
        let mut votes = setup();
        votes.vote(1, "a".to_string());
        votes.vote(2, "b".to_string());
        votes.retain_votes(|v| *v == 1);
        let expected = snap(&[("a", &[1])]);
        assert_eq!(votes.snapshot(), expected);
        votes.retain_votes(|v| *v == 1); // no-op
        assert_eq!(votes.snapshot(), expected);
    }

    #[test]
    fn test_register_idempotent() {
        let mut votes = setup();
        let id1 = votes.proposal_registry.register("x".to_string());
        let id2 = votes.proposal_registry.register("x".to_string());
        assert_eq!(id1, id2);
    }
}
