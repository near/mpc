mod proposal_registry;
pub mod types;
mod votes_registry;

use std::{collections::BTreeMap, collections::BTreeSet};

use near_sdk::{near, IntoStorageKey};
use proposal_registry::ProposalRegistry;
use types::{ProposalBounds, ProposalId, VoterBounds, VoterSet};
use votes_registry::{VoteRegistry, VoteResult};

use crate::errors::VoteError;

/// Keeps track of proposals and votes.
/// Invariants:
/// - Each voter has exactly one vote.
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

impl<V, P> Votes<V, P>
where
    V: VoterBounds,
    P: ProposalBounds,
{
    /// Constructs a enw Votes struct. Prpoosals will be stored in an iterable map under
    /// `storage_key`.
    pub fn new(storage_key: impl IntoStorageKey) -> Self {
        Self {
            proposal_registry: ProposalRegistry::new(storage_key),
            vote_registry: VoteRegistry::new(),
        }
    }

    /// Registers a vote by `voter` for `proposal`.
    /// Stores proposal in case it is new, removes differing votes by `voter`.
    /// This method is idempotent.
    /// Returns the [`ProposalId`] and votes for proposal.
    pub fn vote(&mut self, voter: V, proposal: P) -> (ProposalId, &VoterSet<V>) {
        let proposal_id = self.proposal_registry.register(proposal);
        let votes = self
            .vote_for(voter, proposal_id)
            .expect("proposal id is expect do exist");
        (proposal_id, votes)
    }

    /// Registers a vote by `voter` for proposal with `proposal_id`
    pub fn vote_for(
        &mut self,
        voter: V,
        proposal_id: ProposalId,
    ) -> Result<&VoterSet<V>, VoteError> {
        if !self.proposal_registry.contains(&proposal_id) {
            return Err(VoteError::ProposalIdDoesNotExist(*proposal_id));
        }
        let VoteResult {
            votes_for_proposal,
            proposal_without_votes,
        } = self.vote_registry.register(voter, proposal_id);
        if let Some(orphaned_proposal) = proposal_without_votes {
            self.proposal_registry.remove(&orphaned_proposal);
        }
        Ok(votes_for_proposal)
    }

    /// removes any votes by `voter`. If no more votes remain, then the proposal is removed from
    /// the registry.
    pub fn remove_vote(&mut self, voter: &V) {
        if let Some(proposal_id) = self.vote_registry.remove_vote(voter) {
            // we removed the last vote for this proposal, lets remove the propoal from the
            // registry.
            self.proposal_registry.remove(&proposal_id);
        }
    }

    /// removes proposal with `proposal_id` and any votes casted for that proposal
    pub fn remove_proposal(&mut self, proposal_id: &ProposalId) {
        self.proposal_registry.remove(proposal_id);
        self.vote_registry.remove_votes_for_proposal(proposal_id);
    }

    /// Retains votes for which keep(vote) returns true
    /// Removes proposals without votes
    pub fn retain_votes(&mut self, keep: impl Fn(&V) -> bool) {
        let orphaned_proposals = self.vote_registry.retain_votes(keep);
        for proposal in &orphaned_proposals {
            self.proposal_registry.remove(proposal);
        }
    }

    pub fn clear(&mut self) {
        self.proposal_registry.clear();
        self.vote_registry.clear();
    }

    /// Returns a snapshot of the current state, that can be serde deserialized.
    /// Specifically, returns a map from proposal to votes
    pub fn snapshot(&self) -> BTreeMap<ProposalId, (P, BTreeSet<V>)> {
        let all_proposals = self.proposal_registry.all();
        let all_votes = self.vote_registry.all();
        let merged: BTreeMap<ProposalId, (P, BTreeSet<V>)> = all_proposals
            .into_iter()
            .map(|(pid, proposal)| {
                let votes = all_votes.get(&pid).cloned().unwrap_or_default();
                (pid, (proposal, votes))
            })
            .collect();
        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use near_sdk::BorshStorageKey;

    #[near(serializers=[borsh])]
    #[derive(BorshStorageKey, Hash, Clone, Debug, PartialEq, Eq)]
    enum TestStorageKey {
        Proposals,
    }

    /// Helper to build expected snapshots concisely.
    fn snap(
        entries: &[(ProposalId, (&str, &[&str]))],
    ) -> BTreeMap<ProposalId, (String, BTreeSet<String>)> {
        entries
            .iter()
            .map(|(pid, (p, vs))| {
                (
                    (*pid),
                    (p.to_string(), vs.iter().map(|s| s.to_string()).collect()),
                )
            })
            .collect()
    }
    const ALICE: &str = "alice";
    const BOB: &str = "bob";
    const PROPOSAL_A: &str = "proposal a";
    const PROPOSAL_B: &str = "proposal b";

    #[test]
    fn test_vote_idempotent() {
        let mut votes = Votes::new(TestStorageKey::Proposals);
        let (p_id, casted) = votes.vote(ALICE.to_string(), PROPOSAL_A.to_string());
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());
        assert_eq!(votes.snapshot(), snap(&[(p_id, (PROPOSAL_A, &[ALICE]))]));
        // vote is idempotent
        let (p_id_2, casted) = votes.vote(ALICE.to_string(), PROPOSAL_A.to_string());
        assert_eq!(p_id, p_id_2);
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());
        assert_eq!(votes.snapshot(), snap(&[(p_id, (PROPOSAL_A, &[ALICE]))]));
    }

    #[test]
    fn test_vote_can_switch_votes() {
        let mut votes = Votes::new(TestStorageKey::Proposals);
        let (p_id, casted) = votes.vote(ALICE.to_string(), PROPOSAL_A.to_string());
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());
        assert_eq!(votes.snapshot(), snap(&[(p_id, (PROPOSAL_A, &[ALICE]))]));
        // vote can be changed
        let (p_id_2, casted) = votes.vote(ALICE.to_string(), PROPOSAL_B.to_string());
        assert_ne!(p_id, p_id_2);
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());
        assert_eq!(votes.snapshot(), snap(&[(p_id_2, (PROPOSAL_B, &[ALICE]))]));
    }

    // test vote_for
    #[test]
    fn test_vote_for_success() {
        let mut votes = Votes::new(TestStorageKey::Proposals);
        let (p_id, casted) = votes.vote(ALICE.to_string(), PROPOSAL_A.to_string());
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());
        assert_eq!(votes.snapshot(), snap(&[(p_id, (PROPOSAL_A, &[ALICE]))]));
        let casted = votes.vote_for(BOB.to_string(), p_id).unwrap();
        assert_eq!(
            casted.0,
            [ALICE.to_string(), BOB.to_string()].into_iter().collect()
        );
        assert_eq!(
            votes.snapshot(),
            snap(&[(p_id, (PROPOSAL_A, &[ALICE, BOB]))])
        );
    }

    #[test]
    fn test_vote_for_errors_if_proposal_does_not_exist() {
        let mut votes = Votes::new(TestStorageKey::Proposals);
        let (p_id, casted) = votes.vote(ALICE.to_string(), PROPOSAL_A.to_string());
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());
        assert_eq!(votes.snapshot(), snap(&[(p_id, (PROPOSAL_A, &[ALICE]))]));

        let missing_id = p_id.next();
        let casted = votes.vote_for(BOB.to_string(), missing_id);

        assert_matches!(
            casted,
            Err(VoteError::ProposalIdDoesNotExist(id)) if id == *missing_id
        );
        assert_eq!(votes.snapshot(), snap(&[(p_id, (PROPOSAL_A, &[ALICE]))]));
    }

    #[test]
    fn test_vote_for_can_switch_vote_and_remove_orphaned_proposal() {
        let mut votes = Votes::new(TestStorageKey::Proposals);

        let (p_id_a, casted) = votes.vote(ALICE.to_string(), PROPOSAL_A.to_string());
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());

        let (p_id_b, casted) = votes.vote(BOB.to_string(), PROPOSAL_B.to_string());
        assert_eq!(casted.0, [BOB.to_string()].into_iter().collect());

        let casted = votes.vote_for(ALICE.to_string(), p_id_b).unwrap();
        assert_eq!(
            casted.0,
            [ALICE.to_string(), BOB.to_string()].into_iter().collect()
        );

        assert_eq!(
            votes.snapshot(),
            snap(&[(p_id_b, (PROPOSAL_B, &[ALICE, BOB]))])
        );
        assert_ne!(p_id_a, p_id_b);
    }

    #[test]
    fn test_vote_for_can_switch_vote_without_removing_old_proposal() {
        let mut votes = Votes::new(TestStorageKey::Proposals);

        let carol = "carol";

        let (p_id_a, casted) = votes.vote(ALICE.to_string(), PROPOSAL_A.to_string());
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());

        let casted = votes.vote(BOB.to_string(), PROPOSAL_A.to_string()).1;
        assert_eq!(
            casted.0,
            [ALICE.to_string(), BOB.to_string()].into_iter().collect()
        );

        let (p_id_b, casted) = votes.vote(carol.to_string(), PROPOSAL_B.to_string());
        assert_eq!(casted.0, [carol.to_string()].into_iter().collect());

        let casted = votes.vote_for(ALICE.to_string(), p_id_b).unwrap();
        assert_eq!(
            casted.0,
            [ALICE.to_string(), carol.to_string()].into_iter().collect()
        );

        assert_eq!(
            votes.snapshot(),
            snap(&[
                (p_id_a, (PROPOSAL_A, &[BOB])),
                (p_id_b, (PROPOSAL_B, &[ALICE, carol])),
            ])
        );
    }

    #[test]
    fn test_remove_vote_removes_last_vote_and_proposal() {
        let mut votes = Votes::new(TestStorageKey::Proposals);

        let (p_id, casted) = votes.vote(ALICE.to_string(), PROPOSAL_A.to_string());
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());

        votes.remove_vote(&ALICE.to_string());

        assert_eq!(votes.snapshot(), snap(&[]));
        // sanity check that the old proposal id is really gone
        assert_matches!(
            votes.vote_for(BOB.to_string(), p_id),
            Err(VoteError::ProposalIdDoesNotExist(id)) if id == *p_id
        );
    }

    #[test]
    fn test_remove_vote_removes_only_voter_if_other_votes_remain() {
        let mut votes = Votes::new(TestStorageKey::Proposals);

        let (p_id, casted) = votes.vote(ALICE.to_string(), PROPOSAL_A.to_string());
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());

        let casted = votes.vote(BOB.to_string(), PROPOSAL_A.to_string()).1;
        assert_eq!(
            casted.0,
            [ALICE.to_string(), BOB.to_string()].into_iter().collect()
        );

        votes.remove_vote(&ALICE.to_string());

        assert_eq!(votes.snapshot(), snap(&[(p_id, (PROPOSAL_A, &[BOB]))]));
    }

    #[test]
    fn test_remove_vote_of_unknown_voter_is_noop() {
        let mut votes = Votes::new(TestStorageKey::Proposals);

        let (p_id, casted) = votes.vote(ALICE.to_string(), PROPOSAL_A.to_string());
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());

        votes.remove_vote(&BOB.to_string());

        assert_eq!(votes.snapshot(), snap(&[(p_id, (PROPOSAL_A, &[ALICE]))]));
    }

    #[test]
    fn test_remove_proposal_removes_proposal_and_all_its_votes() {
        let mut votes = Votes::new(TestStorageKey::Proposals);

        let carol = "carol";

        let (p_id_a, casted) = votes.vote(ALICE.to_string(), PROPOSAL_A.to_string());
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());

        let casted = votes.vote(BOB.to_string(), PROPOSAL_A.to_string()).1;
        assert_eq!(
            casted.0,
            [ALICE.to_string(), BOB.to_string()].into_iter().collect()
        );

        let (p_id_b, casted) = votes.vote(carol.to_string(), PROPOSAL_B.to_string());
        assert_eq!(casted.0, [carol.to_string()].into_iter().collect());

        votes.remove_proposal(&p_id_a);

        assert_eq!(votes.snapshot(), snap(&[(p_id_b, (PROPOSAL_B, &[carol]))]));

        let casted = votes.vote_for(ALICE.to_string(), p_id_b).unwrap();
        assert_eq!(
            casted.0,
            [ALICE.to_string(), carol.to_string()].into_iter().collect()
        );

        assert_eq!(
            votes.snapshot(),
            snap(&[(p_id_b, (PROPOSAL_B, &[ALICE, carol]))])
        );
    }

    #[test]
    fn test_remove_proposal_of_unknown_id_is_noop() {
        let mut votes = Votes::new(TestStorageKey::Proposals);

        let (p_id, casted) = votes.vote(ALICE.to_string(), PROPOSAL_A.to_string());
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());

        votes.remove_proposal(&p_id.next());

        assert_eq!(votes.snapshot(), snap(&[(p_id, (PROPOSAL_A, &[ALICE]))]));
    }

    #[test]
    fn test_retain_votes_keeps_matching_votes_and_removes_orphaned_proposals() {
        let mut votes = Votes::new(TestStorageKey::Proposals);

        let carol = "carol";
        let proposal_c = "proposal c";

        let (p_id_a, casted) = votes.vote(ALICE.to_string(), PROPOSAL_A.to_string());
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());

        let casted = votes.vote(BOB.to_string(), PROPOSAL_A.to_string()).1;
        assert_eq!(
            casted.0,
            [ALICE.to_string(), BOB.to_string()].into_iter().collect()
        );

        let (p_id_b, casted) = votes.vote(carol.to_string(), PROPOSAL_B.to_string());
        assert_eq!(casted.0, [carol.to_string()].into_iter().collect());

        let (_p_id_c, casted) = votes.vote("dave".to_string(), proposal_c.to_string());
        assert_eq!(casted.0, ["dave".to_string()].into_iter().collect());

        votes.retain_votes(|voter| voter == ALICE || voter == carol);

        assert_eq!(
            votes.snapshot(),
            snap(&[
                (p_id_a, (PROPOSAL_A, &[ALICE])),
                (p_id_b, (PROPOSAL_B, &[carol])),
            ])
        );
    }

    #[test]
    fn test_retain_votes_can_clear_everything() {
        let mut votes = Votes::new(TestStorageKey::Proposals);

        let (p_id, casted) = votes.vote(ALICE.to_string(), PROPOSAL_A.to_string());
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());

        votes.retain_votes(|_| false);

        assert_eq!(votes.snapshot(), snap(&[]));
        assert_matches!(
            votes.vote_for(BOB.to_string(), p_id),
            Err(VoteError::ProposalIdDoesNotExist(id)) if id == *p_id
        );
    }

    #[test]
    fn test_clear_removes_all_votes_and_proposals() {
        let mut votes = Votes::new(TestStorageKey::Proposals);

        let (_p_id_a, casted) = votes.vote(ALICE.to_string(), PROPOSAL_A.to_string());
        assert_eq!(casted.0, [ALICE.to_string()].into_iter().collect());

        let (_p_id_b, casted) = votes.vote(BOB.to_string(), PROPOSAL_B.to_string());
        assert_eq!(casted.0, [BOB.to_string()].into_iter().collect());

        votes.clear();

        assert_eq!(votes.snapshot(), snap(&[]));
    }
}
