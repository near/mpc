use borsh::{BorshDeserialize, BorshSerialize};
use mpc_contract::primitives::domain::DomainId;

pub mod covering;
pub mod owned;
pub mod queue;
pub mod types;

#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug)]
pub enum AssetPrefix {
    EcdsaTriple,
    EcdsaPresignature(DomainId),
}
