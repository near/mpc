use std::ops::AddAssign;

use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::From;
use near_sdk::{near, store::IterableMap};

pub(crate) trait VoterIdBounds: BorshSerialize + Ord {}
//pub(crate) trait ProposalIdBounds:
//    BorshSerialize + BorshDeserialize + Ord + Clone + AddAssign<u64>
//{
//}
pub(crate) trait ProposalBounds: BorshSerialize + BorshDeserialize + Ord {}

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Clone, From)]
#[near(serializers=[borsh])]
pub struct ProposalId(pub(crate) u64);

impl AddAssign<u64> for ProposalId {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

#[near(serializers=[borsh])]
pub struct Votes<VoterId, Proposal>
where
    VoterId: VoterIdBounds,
    Proposal: ProposalBounds,
{
    pub(crate) votes: IterableMap<VoterId, ProposalId>,
    pub(crate) proposals: IterableMap<ProposalId, ProposalEntry<Proposal>>,
    pub(crate) next_id: ProposalId,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ProposalEntry<Proposal>
where
    Proposal: ProposalBounds,
{
    pub proposed: Proposal,
    pub num_votes: u64,
}
