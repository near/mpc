use std::collections::BTreeSet;

use anyhow;

use super::types::{ProposalBounds, ProposalIdBounds, VoterIdBounds, Votes};

impl<VoterId, ProposalId, Proposal> Votes<VoterId, ProposalId, Proposal>
where
    VoterId: VoterIdBounds,
    ProposalId: ProposalIdBounds,
    Proposal: ProposalBounds,
{
    /// returns the `ProposalId`
    pub fn propose(&mut self, proposal: Proposal) -> ProposalId {
        self.next_id.clone()
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
