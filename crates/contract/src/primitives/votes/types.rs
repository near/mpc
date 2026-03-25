use std::{collections::BTreeMap, ops::AddAssign};

use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::From;
use near_sdk::{
    near,
    store::{IterableMap, LookupMap},
};

pub(crate) trait VoterIdBounds: BorshSerialize + BorshDeserialize + Ord + Clone {}
pub(crate) trait ProposalBounds:
    BorshSerialize + BorshDeserialize + Ord + Clone + PartialEq
{
}

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
    pub(crate) id_by_proposal: LookupMap<Proposal, ProposalId>,
    pub(crate) votes: BTreeMap<VoterId, ProposalId>,
    pub(crate) proposals: IterableMap<ProposalId, Proposal>,
    pub(crate) proposal_votes: BTreeMap<ProposalId, u64>,
    pub(crate) next_id: ProposalId,
}
