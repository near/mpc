use alloc::string::ToString;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use derive_more::{Deref, From, Into};
use serde::{Deserialize, Serialize};

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
    BorshSchema,
)]
pub struct QuoteBytes(Vec<u8>);
