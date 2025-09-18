use alloc::vec::Vec;
use derive_more::{Deref, From, Into};
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, From, Into, Deref, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct QuoteBytes(Vec<u8>);
