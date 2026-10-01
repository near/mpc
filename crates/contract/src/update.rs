use crate::{
    primitives::{
        key_state::AuthenticatedAccountId,
        proposal_hash::{Json, Sha256, ToProposalHash},
        votes::Votes,
    },
    storage_keys::StorageKey,
};
use derive_more::{Deref, DerefMut};
use near_mpc_contract_interface::types as dtos;
use near_sdk::near;

#[near(serializers=[borsh])]
#[derive(Debug, Deref, DerefMut)]
pub struct ContractUpdateVotes(Votes<AuthenticatedAccountId>);

impl Default for ContractUpdateVotes {
    fn default() -> Self {
        Self(Votes::new(
            StorageKey::ContractUpdateVotesByVoter,
            StorageKey::ContractUpdateVotesByProposal,
        ))
    }
}

impl ToProposalHash for dtos::UpdateHash {
    type Serializer = Json;
    type Hasher = Sha256;
}
