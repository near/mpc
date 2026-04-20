use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{From, FromStr};
use serde::{Deserialize, Serialize};

/// A Near AccountId
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    From,
    FromStr,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct AccountId(pub String);

pub use mpc_primitives::domain::DomainId;
pub use near_mpc_crypto_types::Tweak;
