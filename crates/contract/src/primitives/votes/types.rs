use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::store::IterableMap;

pub(crate) trait VoterIdBounds: BorshSerialize + Ord {}
pub(crate) trait ProposalIdBounds: BorshSerialize + BorshDeserialize + Ord + Clone {}
pub(crate) trait ProposalBounds: BorshSerialize + BorshDeserialize + Ord {}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Votes<VoterId, ProposalId, Proposal>
where
    VoterId: VoterIdBounds,
    ProposalId: ProposalIdBounds,
    Proposal: ProposalBounds,
{
    pub votes: IterableMap<VoterId, ProposalId>,
    pub proposals: IterableMap<ProposalId, ProposalEntry<Proposal>>,
    pub next_id: ProposalId,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ProposalEntry<Proposal>
where
    Proposal: ProposalBounds,
{
    pub proposed: Proposal,
    pub num_votes: u64,
}
