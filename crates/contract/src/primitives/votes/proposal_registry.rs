use std::collections::BTreeMap;

use near_sdk::{near, store::IterableMap, IntoStorageKey};

use super::types::{ProposalBounds, ProposalHash, ProposalId, PROPOSAL_HASH_BYTES};

/// Keeps track of proposals and assigns stable ids.
/// `id_by_proposal` and `proposals_by_id` are inverse of one another.
/// `next_id` is the next ID to assign (monotonically increasing).
#[near(serializers=[borsh])]
#[derive(Debug)]
pub(super) struct ProposalRegistry<P>
where
    P: ProposalBounds,
{
    id_by_proposal: BTreeMap<ProposalHash, ProposalId>,
    proposals_by_id: IterableMap<ProposalId, (ProposalHash, P)>,
    next_id: ProposalId,
}

impl<P> ProposalRegistry<P>
where
    P: ProposalBounds,
{
    /// builds a new proposal. The caller is responsibe for ensuring that `storage_key` is empty.
    pub(super) fn new(storage_key: impl IntoStorageKey) -> Self {
        Self {
            id_by_proposal: BTreeMap::new(),
            proposals_by_id: IterableMap::new(storage_key),
            // we should probably set this.
            next_id: ProposalId(0),
        }
    }

    /// Stores the proposal if new, or looks up the existing matching proposal.
    /// Returns the proposal id for this proposal.
    pub(super) fn register(&mut self, proposal: P) -> ProposalId {
        let encoded = borsh::to_vec(&proposal).expect("borsh serialization failed");
        let hash: [u8; PROPOSAL_HASH_BYTES] = near_sdk::env::sha256(encoded)
            .try_into()
            .expect("require 32 bytes");
        let proposal_hash: ProposalHash = hash.into();
        if let Some(proposal_id) = self.id_by_proposal.get(&proposal_hash) {
            return *proposal_id;
        }
        let proposal_id = self.next_id;
        self.next_id = self.next_id.next();
        self.id_by_proposal.insert(proposal_hash, proposal_id);
        self.proposals_by_id
            .insert(proposal_id, (proposal_hash, proposal));
        proposal_id
    }

    /// Removes the proposal under [`ProposalId`]
    pub(super) fn remove(&mut self, proposal_id: &ProposalId) {
        if let Some((proposal_hash, _)) = self.proposals_by_id.remove(proposal_id) {
            self.id_by_proposal.remove(&proposal_hash);
        }
    }

    /// Returns true if a proposal exists for [`ProposalId`], returns false otherwise.
    pub(super) fn contains(&self, proposal_id: &ProposalId) -> bool {
        self.proposals_by_id.contains_key(proposal_id)
    }

    /// clears the maps
    pub(super) fn clear(&mut self) {
        self.id_by_proposal.clear();
        self.proposals_by_id.clear();
    }

    /// Returns the registry in a form fit for json serialization.
    pub(super) fn all(&self) -> BTreeMap<ProposalId, (ProposalHash, P)> {
        self.proposals_by_id
            .iter()
            .map(|(id, p)| (*id, p.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
    use near_sdk::BorshStorageKey;
    use sha2::Digest;
    use std::collections::BTreeMap;

    #[derive(BorshSerialize, BorshStorageKey)]
    enum TestStorageKey {
        Proposals,
    }

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, BorshDeserialize, BorshSerialize)]
    struct TestProposal(String);

    impl TestProposal {
        fn new(value: &str) -> Self {
            Self(value.to_string())
        }
    }

    /// Helper to build expected snapshots concisely.
    fn make_all(
        entries: &[(ProposalId, TestProposal)],
    ) -> BTreeMap<ProposalId, (ProposalHash, TestProposal)> {
        entries
            .iter()
            .map(|(pid, p)| {
                let hash: [u8; PROPOSAL_HASH_BYTES] =
                    sha2::Sha256::digest(borsh::to_vec(&p).expect("borsh must succeed")).into();
                ((*pid), (ProposalHash::new(hash), p.clone()))
            })
            .collect()
    }

    #[test]
    fn new_is_empty() {
        let registry = ProposalRegistry::<TestProposal>::new(TestStorageKey::Proposals);

        assert!(registry.all().is_empty());
        assert_eq!(*registry.next_id, 0);
        assert!(!registry.contains(&ProposalId(0)));
    }

    #[test]
    fn register_is_idempotent() {
        let mut registry = ProposalRegistry::<TestProposal>::new(TestStorageKey::Proposals);
        let proposal = TestProposal::new("p1");

        let first_id = registry.register(proposal.clone());
        let second_id = registry.register(proposal.clone());

        assert_eq!(*first_id, 0);
        assert_eq!(second_id, first_id);
        assert!(registry.contains(&first_id));
        assert_eq!(registry.all(), make_all(&[(first_id, proposal)]));
    }

    #[test]
    fn register_assigns_monotonic_ids_to_distinct_proposals() {
        let mut registry = ProposalRegistry::<TestProposal>::new(TestStorageKey::Proposals);

        let p1 = TestProposal::new("p1");
        let p2 = TestProposal::new("p2");
        let p3 = TestProposal::new("p3");

        let id1 = registry.register(p1.clone());
        let id2 = registry.register(p2.clone());
        let id3 = registry.register(p3.clone());

        assert_eq!(*id1, 0);
        assert_eq!(*id2, 1);
        assert_eq!(*id3, 2);

        assert_eq!(registry.all(), make_all(&[(id1, p1), (id2, p2), (id3, p3)]));
    }

    #[test]
    fn remove_deletes_from_both_indexes_and_reregister_gets_new_id() {
        let mut registry = ProposalRegistry::<TestProposal>::new(TestStorageKey::Proposals);
        let proposal = TestProposal::new("p1");

        let first_id = registry.register(proposal.clone());
        registry.remove(&first_id);

        assert!(!registry.contains(&first_id));
        assert!(registry.all().is_empty());

        let second_id = registry.register(proposal.clone());

        assert_eq!(*second_id, 1);
        assert_ne!(second_id, first_id);
        assert_eq!(registry.all(), make_all(&[(second_id, proposal)]));
    }

    #[test]
    fn removing_unknown_id_is_a_noop() {
        let mut registry = ProposalRegistry::<TestProposal>::new(TestStorageKey::Proposals);

        let id = registry.register(TestProposal::new("p1"));
        let before = registry.all();

        registry.remove(&ProposalId(999));

        assert!(registry.contains(&id));
        assert_eq!(registry.all(), before);
    }

    #[test]
    fn clear_removes_everything_but_does_not_reset_id_counter() {
        let mut registry = ProposalRegistry::<TestProposal>::new(TestStorageKey::Proposals);

        let id1 = registry.register(TestProposal::new("p1"));
        let id2 = registry.register(TestProposal::new("p2"));
        assert_eq!(*id1, 0);
        assert_eq!(*id2, 1);

        registry.clear();

        assert!(registry.all().is_empty());
        assert!(!registry.contains(&id1));
        assert!(!registry.contains(&id2));

        let id3 = registry.register(TestProposal::new("p3"));
        assert_eq!(*id3, 2);
    }
}
