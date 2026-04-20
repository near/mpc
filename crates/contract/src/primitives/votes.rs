use std::collections::BTreeMap;
use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};

use near_sdk::near;
use near_sdk::require;
use near_sdk::store::IterableMap;
use near_sdk::IntoStorageKey;

/// Helper struct to keep track of submitted votes.
/// Allows efficient look-up of votes by voter and votes by proposal.
#[near(serializers=[borsh])]
pub struct Votes<V>
where
    V: BorshSerialize + Ord,
{
    proposal_by_voter: IterableMap<V, ProposalHash>,
    votes_by_proposal: IterableMap<ProposalHash, VoterSet<V>>,
}

impl<V> Votes<V>
where
    V: BorshSerialize + Ord + BorshDeserialize + Clone,
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

    /// Registers a vote by `voter` for [`ProposalHash`].
    /// In case this voter already has a vote for a different proposal hash, the previous vote is removed.
    /// Returns the [`VoterSet`], containing all votes for the given proposal hash.
    pub fn vote(&mut self, voter: V, proposal: ProposalHash) -> &VoterSet<V> {
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
            .expect("inconsistent vote registry");
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

impl<T> From<T> for ProposalHash
where
    T: ProposalHashEncoding,
{
    fn from(value: T) -> Self {
        let encoded = value.bytes_for_hash();
        let hash: [u8; PROPOSAL_HASH_BYTES] = near_sdk::env::sha256(encoded)
            .try_into()
            .expect("require 32 bytes");
        hash.into()
    }
}

/// This trait allows the user to create their own proposal hash encoding
pub trait ProposalHashEncoding {
    fn bytes_for_hash(&self) -> Vec<u8>;
}

/// The set of voters who voted for a particular proposal. Always non-empty when stored
/// inside `VotesByProposal`.
#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct VoterSet<V>(pub(super) BTreeSet<V>)
where
    V: Ord;

impl<V> VoterSet<V>
where
    V: Ord,
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
    use std::{
        collections::{BTreeMap, BTreeSet},
        hash::Hash,
        sync::LazyLock,
    };

    use crate::primitives::votes::{ProposalHash, VoterSet, Votes};

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

    fn setup() -> Votes<TestVoter> {
        Votes::<TestVoter>::new(
            TestStorageKey::ProposalByVoter,
            TestStorageKey::VotesByProposal,
        )
    }

    fn make_all(
        expected: &[(ProposalHash, &[&TestVoter])],
    ) -> BTreeMap<ProposalHash, BTreeSet<TestVoter>> {
        expected
            .iter()
            .map(|(hash, voter)| (*hash, voter.iter().map(|voter| (*voter).clone()).collect()))
            .collect()
    }

    fn make_proposal_hash(i: usize) -> ProposalHash {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&i.to_be_bytes());
        ProposalHash::new(bytes)
    }

    static ALICE: LazyLock<TestVoter> = LazyLock::new(|| TestVoter("alice".to_string()));
    static BOB: LazyLock<TestVoter> = LazyLock::new(|| TestVoter("bob".to_string()));

    #[test]
    #[expect(non_snake_case)]
    fn votes_new__should_be_empty() {
        let votes_registry = setup();
        assert_eq!(votes_registry.all(), BTreeMap::new());
        assert_eq!(votes_registry.proposal_by_voter.len(), 0);
        assert_eq!(votes_registry.votes_by_proposal.len(), 0);
    }

    #[test]
    #[expect(non_snake_case)]
    fn vote__should_create_entry_and_return_current_votes() {
        let mut votes_registry = setup();

        let p_hash = make_proposal_hash(7);
        let result = votes_registry.vote(ALICE.clone(), p_hash);

        assert_eq!(result.0, [ALICE.clone()].into());

        assert_eq!(votes_registry.proposal_by_voter.get(&ALICE), Some(&p_hash));
        assert_eq!(votes_registry.all(), make_all(&[(p_hash, &[&ALICE])]));
    }

    #[test]
    #[expect(non_snake_case)]
    fn vote__should_be_idempotent() {
        let mut votes_registry = setup();

        let p_hash = make_proposal_hash(1);

        let first = votes_registry.vote(ALICE.clone(), p_hash);
        assert_eq!(first.0, [ALICE.clone()].into());

        let second = votes_registry.vote(ALICE.clone(), p_hash);

        assert_eq!(second.0, [ALICE.clone()].into());

        assert_eq!(votes_registry.proposal_by_voter.len(), 1);
        assert_eq!(votes_registry.votes_by_proposal.len(), 1);
        assert_eq!(votes_registry.all(), make_all(&[(p_hash, &[&ALICE])]));
    }

    #[test]
    #[expect(non_snake_case)]
    fn remove_vote__should_remove_orphaned_proposals() {
        let mut votes_registry = setup();

        let p_hash = make_proposal_hash(9);

        votes_registry.vote(ALICE.clone(), p_hash);

        votes_registry.remove_vote(&ALICE);

        assert_eq!(votes_registry.proposal_by_voter.get(&ALICE), None);
        assert_eq!(votes_registry.all(), make_all(&[]));
    }

    #[test]
    #[expect(non_snake_case)]
    fn remove_vote__should_keep_non_orphaned_proposal() {
        let mut votes_registry = setup();

        let p_hash = make_proposal_hash(5);

        votes_registry.vote(ALICE.clone(), p_hash);
        votes_registry.vote(BOB.clone(), p_hash);

        votes_registry.remove_vote(&ALICE);

        assert_eq!(votes_registry.proposal_by_voter.get(&ALICE), None);
        assert_eq!(votes_registry.proposal_by_voter.get(&BOB), Some(&p_hash));
        assert_eq!(votes_registry.all(), make_all(&[(p_hash, &[&BOB])]));
    }

    #[test]
    #[expect(non_snake_case)]
    fn vote__should_switch_vote_and_remove_orphaned_proposal() {
        let mut votes_registry = setup();

        let old_pid = make_proposal_hash(1);
        let new_pid = make_proposal_hash(2);

        votes_registry.vote(ALICE.clone(), old_pid);
        let result = votes_registry.vote(ALICE.clone(), new_pid);

        assert_eq!(result.0, [ALICE.clone()].into());

        assert_eq!(votes_registry.proposal_by_voter.get(&ALICE), Some(&new_pid));
        assert_eq!(votes_registry.all(), make_all(&[(new_pid, &[&ALICE])]));
    }

    #[test]
    #[expect(non_snake_case)]
    fn vote__should_switch_vote_and_keep_non_orphaned_proposals() {
        let mut votes_registry = setup();

        let old_pid = make_proposal_hash(1);
        let new_pid = make_proposal_hash(2);

        votes_registry.vote(ALICE.clone(), old_pid);
        votes_registry.vote(BOB.clone(), old_pid);

        let result = votes_registry.vote(ALICE.clone(), new_pid);

        assert_eq!(result.0, [ALICE.clone()].into());

        assert_eq!(votes_registry.proposal_by_voter.get(&ALICE), Some(&new_pid));
        assert_eq!(votes_registry.proposal_by_voter.get(&BOB), Some(&old_pid));
        assert_eq!(
            votes_registry.all(),
            make_all(&[(new_pid, &[&ALICE]), (old_pid, &[&BOB])])
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn remove_vote__should_be_noop_for_unknown_voter() {
        let mut votes_registry = setup();

        let p_hash = make_proposal_hash(3);

        votes_registry.vote(ALICE.clone(), p_hash);

        votes_registry.remove_vote(&BOB);
        assert_eq!(votes_registry.all(), make_all(&[(p_hash, &[&ALICE])]));
    }

    #[test]
    #[expect(non_snake_case)]
    fn remove_votes__should_be_noop_for_unknown_proposal() {
        let mut votes_registry = setup();

        let proposal_hash_1 = make_proposal_hash(1);
        let proposal_hash_2 = make_proposal_hash(2);

        votes_registry.vote(ALICE.clone(), proposal_hash_1);
        votes_registry.vote(BOB.clone(), proposal_hash_2);

        votes_registry.remove_votes_for_proposal(&make_proposal_hash(999));
        assert_eq!(
            votes_registry.all(),
            make_all(&[(proposal_hash_1, &[&ALICE]), (proposal_hash_2, &[&BOB])])
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn remove_votes_for_proposal__should_remove_both_proposal_and_reverse_index() {
        let mut votes_registry = setup();

        let proposal_hash_1 = make_proposal_hash(1);
        let proposal_hash_2 = make_proposal_hash(2);
        let carol = TestVoter("carol".to_string());

        votes_registry.vote(ALICE.clone(), proposal_hash_1);
        votes_registry.vote(BOB.clone(), proposal_hash_1);
        votes_registry.vote(carol.clone(), proposal_hash_2);

        votes_registry.remove_votes_for_proposal(&proposal_hash_1);

        assert_eq!(votes_registry.proposal_by_voter.get(&ALICE), None);
        assert_eq!(votes_registry.proposal_by_voter.get(&BOB), None);
        assert_eq!(
            votes_registry.proposal_by_voter.get(&carol),
            Some(&proposal_hash_2)
        );

        assert_eq!(
            votes_registry.all(),
            make_all(&[(proposal_hash_2, &[&carol])])
        );

        let result = votes_registry.vote(ALICE.clone(), proposal_hash_2);
        assert_eq!(result.0, [ALICE.clone(), carol.clone()].into());
        assert_eq!(
            votes_registry.all(),
            make_all(&[(proposal_hash_2, &[&ALICE, &carol])])
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn retain_votes__should_remove_disallowed_voters_and_orphaned_proposals() {
        let mut votes_registry = setup();

        let proposal_hash_1 = make_proposal_hash(1);
        let proposal_hash_2 = make_proposal_hash(2);
        let proposal_hash_3 = make_proposal_hash(3);

        let carol = TestVoter("carol".to_string());
        let dave = TestVoter("dave".to_string());

        votes_registry.vote(ALICE.clone(), proposal_hash_1);
        votes_registry.vote(BOB.clone(), proposal_hash_1);
        votes_registry.vote(carol.clone(), proposal_hash_2);
        votes_registry.vote(dave.clone(), proposal_hash_3);

        // only p_hash 2 and carols vote should remain
        assert_eq!(
            votes_registry.all(),
            make_all(&[
                (proposal_hash_1, &[&ALICE, &BOB]),
                (proposal_hash_2, &[&carol]),
                (proposal_hash_3, &[&dave])
            ])
        );

        votes_registry.retain_votes(|v| v == &carol);

        // only p_hash 2 and carols vote should remain
        assert_eq!(
            votes_registry.all(),
            make_all(&[(proposal_hash_2, &[&carol])])
        );
        // additional sanity checks
        assert_eq!(votes_registry.proposal_by_voter.len(), 1);
        assert_eq!(
            votes_registry.proposal_by_voter.get(&carol),
            Some(&proposal_hash_2)
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn clear__should_remove_everything() {
        let mut votes_registry = setup();

        let proposal_hash_1 = make_proposal_hash(1);
        let proposal_hash_2 = make_proposal_hash(2);

        votes_registry.vote(ALICE.clone(), proposal_hash_1);
        votes_registry.vote(BOB.clone(), proposal_hash_2);

        votes_registry.clear();

        assert_eq!(votes_registry.all(), make_all(&[]));
        assert_eq!(votes_registry.proposal_by_voter.len(), 0);
        assert_eq!(votes_registry.votes_by_proposal.len(), 0);
    }

    #[test]
    #[expect(non_snake_case)]
    fn voter_set_new__should_be_empty() {
        let voter_set = VoterSet::<TestVoter>::new();

        assert!(voter_set.0.is_empty());
    }

    #[test]
    #[expect(non_snake_case)]
    fn voter_set_count_for__should_count_only_matching_votes() {
        let alice = TestVoter("alice".to_string());
        let bob = TestVoter("bob".to_string());
        let carol = TestVoter("carol".to_string());

        let voter_set = VoterSet([alice.clone(), bob.clone(), carol.clone()].into());

        let count = voter_set.count_for(|voter| voter.0.contains('a'));

        assert_eq!(count, 2);
    }

    #[test]
    #[expect(non_snake_case)]
    fn voter_set_count_for__should_return_zero_for_empty_set() {
        let voter_set = VoterSet::<TestVoter>::new();

        let count = voter_set.count_for(|_| true);

        assert_eq!(count, 0);
    }

    #[test]
    #[expect(non_snake_case)]
    fn voter_set_remove__should_return_remaining_count() {
        let alice = TestVoter("alice".to_string());
        let bob = TestVoter("bob".to_string());

        let mut voter_set = VoterSet([alice.clone(), bob.clone()].into());

        let remaining = voter_set.remove(&alice);

        assert_eq!(remaining, Some(1));
        assert_eq!(voter_set.0, [bob.clone()].into());
    }

    #[test]
    #[expect(non_snake_case)]
    fn voter_set_remove__should_return_zero_when_removing_last_vote() {
        let alice = TestVoter("alice".to_string());

        let mut voter_set = VoterSet([alice.clone()].into());

        let remaining = voter_set.remove(&alice);

        assert_eq!(remaining, Some(0));
        assert!(voter_set.0.is_empty());
    }

    #[test]
    #[expect(non_snake_case)]
    fn voter_set_remove__should_return_none_and_leave_set_unchanged_when_removing_unknown_vote() {
        let alice = TestVoter("alice".to_string());
        let bob = TestVoter("bob".to_string());

        let mut voter_set = VoterSet([alice.clone()].into());

        let remaining = voter_set.remove(&bob);

        assert_eq!(remaining, None);
        assert_eq!(voter_set.0, [alice.clone()].into());
    }
}
