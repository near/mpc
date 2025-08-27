use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{Deref, From, Into};
use serde::{Deserialize, Serialize};

#[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
use alloc::string::ToString;

#[derive(
    Debug,
    Clone,
    From,
    Into,
    Deref,
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub struct QuoteBytes(Vec<u8>);
