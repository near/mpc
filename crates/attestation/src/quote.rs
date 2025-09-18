use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
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
)]

pub struct QuoteBytes(Vec<u8>);
