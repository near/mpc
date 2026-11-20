use crate::{
    primitives::{
        key_state::AuthenticatedAccountId,
        proposal_hash::{Identity, ToProposalHash},
        votes::Votes,
    },
    storage_keys::StorageKey,
};
use derive_more::{Deref, DerefMut};
use mpc_primitives::hash::GenesisHash;
use near_sdk::near;

#[near(serializers=[borsh])]
#[derive(Debug, Deref, DerefMut)]
pub struct GenesisHashVotes(Votes<AuthenticatedAccountId>);

impl Default for GenesisHashVotes {
    fn default() -> Self {
        Self(Votes::new(
            StorageKey::GenesisHashVotesByVoter,
            StorageKey::GenesisHashVotesByProposal,
        ))
    }
}

impl ToProposalHash for GenesisHash {
    type Serializer = Identity;
    type Hasher = Identity;
}
