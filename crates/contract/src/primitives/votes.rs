use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::hash::Hash;

use borsh::{BorshDeserialize, BorshSerialize};

use near_sdk::near;
use near_sdk::require;
use near_sdk::store::IterableMap;
use near_sdk::IntoStorageKey;

/// Helper struct to keep track of submitted votes.
/// Allows efficient look-up of votes by voter and votes by proposal.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct VoteRegistry<V>
where
    V: VoterBounds,
{
    proposal_by_voter: IterableMap<V, ProposalHash>,
    votes_by_proposal: IterableMap<ProposalHash, VoterSet<V>>,
}

impl<V> VoteRegistry<V>
where
    V: VoterBounds,
{
    pub fn new(
        proposal_by_voter: impl IntoStorageKey,
        votes_by_proposal: impl IntoStorageKey,
    ) -> Self {
        Self {
            proposal_by_voter: IterableMap::new(proposal_by_voter),
            votes_by_proposal: IterableMap::new(votes_by_proposal),
        }
    }

    /// Registers a vote by `voter` for `proposal`.
    /// Stores proposal in case it is new, removes differing votes by `voter`.
    /// This method is idempotent.
    /// Returns the [`ProposalHash`] and votes for proposal.
    pub fn vote<P: ProposalHashEncoding>(
        &mut self,
        voter: V,
        proposal: P,
    ) -> (ProposalHash, &VoterSet<V>) {
        let encoded = proposal.bytes_for_hash();
        let hash: [u8; PROPOSAL_HASH_BYTES] = near_sdk::env::sha256(encoded)
            .try_into()
            .expect("require 32 bytes");
        let proposal_hash = hash.into();
        let votes = self.register(voter, proposal_hash);
        (proposal_hash, votes)
    }

    /// Registers a vote by `voter` for [`ProposalHash`].
    /// In case this voter already has a vote for a different proposal id, the previous vote is removed.
    /// Returns the [`VoterSet`], containing all votes for the given proposal hash.
    fn register(&mut self, voter: V, proposal: ProposalHash) -> &VoterSet<V> {
        // if necessary, remove existing votes
        if let Some(existing_vote) = self.proposal_by_voter.get(&voter) {
            // if the voter has an existing vote for a different proposal, remove that vote.
            if *existing_vote != proposal {
                self.remove_vote(&voter)
            } else {
                // voter has already voted for this proposal, just return the current voter set
                return self
                    .votes_by_proposal
                    .get(&proposal)
                    .expect("require consistent vote registry");
            }
        }

        // register the vote for the voter
        require!(
            self.proposal_by_voter
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

        votes_for_proposal
    }

    /// Removes any votes by voter V.
    pub fn remove_vote(&mut self, voter: &V) {
        let Some(proposal) = self.proposal_by_voter.get(voter) else {
            return;
        };
        let casted_votes = self
            .votes_by_proposal
            .get_mut(proposal)
            .expect("inconsistent votes registry");
        // remove the vote from the proposal
        let remaining = casted_votes
            .remove(voter)
            .expect("inconistent vote registry");
        if remaining == 0 {
            // remove the proposal if it has no more votes
            self.votes_by_proposal.remove(proposal);
        }
        // remove the voter
        self.proposal_by_voter.remove(voter);
    }

    /// Removes any votes for proposal with [`ProposalHash`], together with any voters that voted for
    /// [`ProposalHash`].
    pub fn remove_votes_for_proposal(&mut self, proposal: &ProposalHash) {
        let Some(voters) = self.votes_by_proposal.remove(proposal) else {
            return;
        };
        for voter in &voters.0 {
            self.proposal_by_voter.remove(voter);
        }
    }

    /// Retains votes for which `predicate` returns true
    /// Returns a vector of any proposal ids that were removed in the process
    pub fn retain_votes(&mut self, predicate: impl Fn(&V) -> bool) {
        let votes_to_remove: Vec<V> = self
            .proposal_by_voter
            .keys()
            .filter(|voter| !predicate(voter))
            .cloned()
            .collect();
        for voter in votes_to_remove {
            self.remove_vote(&voter);
        }
    }

    pub fn clear(&mut self) {
        self.proposal_by_voter.clear();
        self.votes_by_proposal.clear();
    }

    pub fn all(&self) -> BTreeMap<ProposalHash, BTreeSet<V>> {
        self.votes_by_proposal
            .iter()
            .map(|(p_hash, voter_set)| (*p_hash, voter_set.0.clone()))
            .collect()
    }
}

pub const PROPOSAL_HASH_BYTES: usize = 32;
mpc_primitives::define_hash!(ProposalHash, 32);

/// This trait allows the user to create their own proposal hash encoding
pub trait ProposalHashEncoding {
    fn bytes_for_hash(&self) -> Vec<u8>;
}

pub trait VoterBounds: BorshSerialize + BorshDeserialize + Ord + Clone {}

impl<T: BorshSerialize + BorshDeserialize + Ord + Clone> VoterBounds for T {}

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

    use near_sdk::{
        borsh::{self, BorshDeserialize, BorshSerialize},
        BorshStorageKey,
    };
    use sha2::Digest;
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::LazyLock,
    };

    use crate::primitives::votes::{ProposalHash, VoteRegistry, VoterSet, PROPOSAL_HASH_BYTES};

    use super::ProposalHashEncoding;

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, BorshDeserialize, BorshSerialize)]
    struct TestVoter(String);
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, BorshDeserialize, BorshSerialize)]
    struct TestProposal(String);

    impl ProposalHashEncoding for TestProposal {
        fn bytes_for_hash(&self) -> Vec<u8> {
            borsh::to_vec(&self).expect("borsh serialization of String must succeed")
        }
    }

    #[derive(Hash, Clone, Debug, PartialEq, Eq, BorshSerialize, BorshStorageKey)]
    pub enum TestStorageKey {
        ProposalByVoter,
        VotesByProposal,
    }

    fn setup() -> VoteRegistry<TestVoter> {
        VoteRegistry::<TestVoter>::new(
            TestStorageKey::ProposalByVoter,
            TestStorageKey::VotesByProposal,
        )
    }

    fn expected_hash(proposal: &TestProposal) -> ProposalHash {
        let encoded = borsh::to_vec(&proposal).expect("borsh serialization must succeed");
        let hash: [u8; PROPOSAL_HASH_BYTES] = sha2::Sha256::digest(encoded).into();
        hash.into()
    }

    fn make_all_from_hash(
        expected: &[(&ProposalHash, &[&TestVoter])],
    ) -> BTreeMap<ProposalHash, BTreeSet<TestVoter>> {
        expected
            .iter()
            .map(|(hash, voter)| {
                (
                    (*hash).clone(),
                    voter.iter().map(|voter| (*voter).clone()).collect(),
                )
            })
            .collect()
    }

    fn make_all(
        expected: &[(&TestProposal, &[&TestVoter])],
    ) -> BTreeMap<ProposalHash, BTreeSet<TestVoter>> {
        expected
            .iter()
            .map(|(proposal, voter)| {
                (
                    expected_hash(proposal),
                    voter.iter().map(|voter| (*voter).clone()).collect(),
                )
            })
            .collect()
    }

    fn make_proposal_hash(i: usize) -> ProposalHash {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&i.to_be_bytes());
        ProposalHash::new(bytes)
    }

    static ALICE: LazyLock<TestVoter> = LazyLock::new(|| TestVoter("alice".to_string()));
    static BOB: LazyLock<TestVoter> = LazyLock::new(|| TestVoter("bob".to_string()));

    static PROPOSAL_A: LazyLock<TestProposal> =
        LazyLock::new(|| TestProposal("proposal a".to_string()));
    static PROPOSAL_B: LazyLock<TestProposal> =
        LazyLock::new(|| TestProposal("proposal b".to_string()));

    #[test]
    fn new_is_empty() {
        let registry = setup();
        assert_eq!(registry.all(), BTreeMap::new());
        assert_eq!(registry.proposal_by_voter.len(), 0);
        assert_eq!(registry.votes_by_proposal.len(), 0);
    }

    #[test]
    fn register_first_vote_creates_entry_and_returns_current_votes() {
        let mut registry = setup();

        let p_hash = make_proposal_hash(7);
        let result = registry.register(ALICE.clone(), p_hash);

        assert_eq!(result.0, [ALICE.clone()].into());

        assert_eq!(registry.proposal_by_voter.get(&ALICE), Some(&p_hash));
        assert_eq!(registry.all(), make_all_from_hash(&[(&p_hash, &[&ALICE])]));
    }

    #[test]
    fn register_is_idempotent() {
        let mut registry = setup();

        let p_hash = make_proposal_hash(1);

        let first = registry.register(ALICE.clone(), p_hash);
        assert_eq!(first.0, [ALICE.clone()].into());

        let second = registry.register(ALICE.clone(), p_hash);

        assert_eq!(second.0, [ALICE.clone()].into());

        assert_eq!(registry.proposal_by_voter.len(), 1);
        assert_eq!(registry.votes_by_proposal.len(), 1);
        assert_eq!(registry.all(), make_all_from_hash(&[(&p_hash, &[&ALICE])]));
    }

    #[test]
    fn remove_vote_removes_orphaned_proposals() {
        let mut registry = setup();

        let p_hash = make_proposal_hash(9);

        registry.register(ALICE.clone(), p_hash);

        registry.remove_vote(&ALICE);

        assert_eq!(registry.proposal_by_voter.get(&ALICE), None);
        assert_eq!(registry.all(), make_all_from_hash(&[]));
    }

    #[test]
    fn remove_vote_keeps_non_orphaned_proposal() {
        let mut registry = setup();

        let p_hash = make_proposal_hash(5);

        registry.register(ALICE.clone(), p_hash);
        registry.register(BOB.clone(), p_hash);

        registry.remove_vote(&ALICE);

        assert_eq!(registry.proposal_by_voter.get(&ALICE), None);
        assert_eq!(registry.proposal_by_voter.get(&BOB), Some(&p_hash));
        assert_eq!(registry.all(), make_all_from_hash(&[(&p_hash, &[&BOB])]));
    }

    #[test]
    fn register_switches_vote_and_removes_orphaned_proposals() {
        let mut registry = setup();

        let old_pid = make_proposal_hash(1);
        let new_pid = make_proposal_hash(2);

        registry.register(ALICE.clone(), old_pid);
        let result = registry.register(ALICE.clone(), new_pid);

        assert_eq!(result.0, [ALICE.clone()].into());

        assert_eq!(registry.proposal_by_voter.get(&ALICE), Some(&new_pid));
        assert_eq!(registry.all(), make_all_from_hash(&[(&new_pid, &[&ALICE])]));
    }

    #[test]
    fn register_switches_vote_and_keeps_non_orphaned_proposals() {
        let mut registry = setup();

        let old_pid = make_proposal_hash(1);
        let new_pid = make_proposal_hash(2);

        registry.register(ALICE.clone(), old_pid);
        registry.register(BOB.clone(), old_pid);

        let result = registry.register(ALICE.clone(), new_pid);

        assert_eq!(result.0, [ALICE.clone()].into());

        assert_eq!(registry.proposal_by_voter.get(&ALICE), Some(&new_pid));
        assert_eq!(registry.proposal_by_voter.get(&BOB), Some(&old_pid));
        assert_eq!(
            registry.all(),
            make_all_from_hash(&[(&new_pid, &[&ALICE]), (&old_pid, &[&BOB])])
        );
    }

    #[test]
    fn remove_vote_of_unknown_voter_is_noop() {
        let mut registry = setup();

        let p_hash = make_proposal_hash(3);

        registry.register(ALICE.clone(), p_hash);

        registry.remove_vote(&BOB);
        assert_eq!(registry.all(), make_all_from_hash(&[(&p_hash, &[&ALICE])]));
    }

    #[test]
    fn remove_votes_for_unknown_proposal_is_noop() {
        let mut registry = setup();

        let proposal_hash_1 = make_proposal_hash(1);
        let proposal_hash_2 = make_proposal_hash(2);

        registry.register(ALICE.clone(), proposal_hash_1);
        registry.register(BOB.clone(), proposal_hash_2);

        registry.remove_votes_for_proposal(&make_proposal_hash(999));
        assert_eq!(
            registry.all(),
            make_all_from_hash(&[(&proposal_hash_1, &[&ALICE]), (&proposal_hash_2, &[&BOB])])
        );
    }

    #[test]
    fn remove_votes_for_proposal_removes_both_proposal_and_reverse_index() {
        let mut registry = setup();

        let proposal_hash_1 = make_proposal_hash(1);
        let proposal_hash_2 = make_proposal_hash(2);
        let carol = TestVoter("carol".to_string());

        registry.register(ALICE.clone(), proposal_hash_1);
        registry.register(BOB.clone(), proposal_hash_1);
        registry.register(carol.clone(), proposal_hash_2);

        registry.remove_votes_for_proposal(&proposal_hash_1);

        assert_eq!(registry.proposal_by_voter.get(&ALICE), None);
        assert_eq!(registry.proposal_by_voter.get(&BOB), None);
        assert_eq!(
            registry.proposal_by_voter.get(&carol),
            Some(&proposal_hash_2)
        );

        assert_eq!(
            registry.all(),
            make_all_from_hash(&[(&proposal_hash_2, &[&carol])])
        );

        let result = registry.register(ALICE.clone(), proposal_hash_2);
        assert_eq!(result.0, [ALICE.clone(), carol.clone()].into());
        assert_eq!(
            registry.all(),
            make_all_from_hash(&[(&proposal_hash_2, &[&ALICE, &carol])])
        );
    }

    #[test]
    fn retain_votes_removes_disallowed_voters_and_orphaned_proposals() {
        let mut registry = setup();

        let proposal_hash_1 = make_proposal_hash(1);
        let proposal_hash_2 = make_proposal_hash(2);
        let proposal_hash_3 = make_proposal_hash(3);

        let carol = TestVoter("carol".to_string());
        let dave = TestVoter("dave".to_string());

        registry.register(ALICE.clone(), proposal_hash_1);
        registry.register(BOB.clone(), proposal_hash_1);
        registry.register(carol.clone(), proposal_hash_2);
        registry.register(dave.clone(), proposal_hash_3);

        // only p_hash 2 and carols vote should remain
        assert_eq!(
            registry.all(),
            make_all_from_hash(&[
                (&proposal_hash_1, &[&ALICE, &BOB]),
                (&proposal_hash_2, &[&carol]),
                (&proposal_hash_3, &[&dave])
            ])
        );

        registry.retain_votes(|v| v == &carol);

        // only p_hash 2 and carols vote should remain
        assert_eq!(
            registry.all(),
            make_all_from_hash(&[(&proposal_hash_2, &[&carol])])
        );
        // additional sanity checks
        assert_eq!(registry.proposal_by_voter.len(), 1);
        assert_eq!(
            registry.proposal_by_voter.get(&carol),
            Some(&proposal_hash_2)
        );
    }

    #[test]
    fn clear_removes_everything() {
        let mut registry = setup();

        let proposal_hash_1 = make_proposal_hash(1);
        let proposal_hash_2 = make_proposal_hash(2);

        registry.register(ALICE.clone(), proposal_hash_1);
        registry.register(BOB.clone(), proposal_hash_2);

        registry.clear();

        assert_eq!(registry.all(), make_all_from_hash(&[]));
        assert_eq!(registry.proposal_by_voter.len(), 0);
        assert_eq!(registry.votes_by_proposal.len(), 0);
    }

    #[test]
    fn vote_is_idempotent() {
        let mut registry = setup();
        let (p_hash, casted) = registry.vote(ALICE.clone(), PROPOSAL_A.clone());
        assert_eq!(casted.0, [ALICE.clone()].into_iter().collect());
        assert_eq!(registry.all(), make_all(&[(&PROPOSAL_A, &[&ALICE])]));
        // vote is idempotent
        let (p_id_2, casted) = registry.vote(ALICE.clone(), PROPOSAL_A.clone());
        assert_eq!(p_hash, p_id_2);
        assert_eq!(casted.0, [ALICE.clone()].into_iter().collect());
        assert_eq!(registry.all(), make_all(&[(&PROPOSAL_A, &[&ALICE])]));
    }

    #[test]
    fn vote_can_switch_votes() {
        let mut registry = setup();
        let (p_hash, casted) = registry.vote(ALICE.clone(), PROPOSAL_A.clone());
        assert_eq!(casted.0, [ALICE.clone()].into_iter().collect());
        assert_eq!(registry.all(), make_all(&[(&PROPOSAL_A, &[&ALICE])]));
        // vote can be changed
        let (p_id_2, casted) = registry.vote(ALICE.clone(), PROPOSAL_B.clone());
        assert_ne!(p_hash, p_id_2);
        assert_eq!(casted.0, [ALICE.clone()].into_iter().collect());
        assert_eq!(registry.all(), make_all(&[(&PROPOSAL_B, &[&ALICE])]));
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
