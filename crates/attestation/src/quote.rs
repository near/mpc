use alloc::vec::Vec;
use derive_more::{Deref, From, Into};

#[derive(Debug, Clone, From, Into, Deref, PartialEq, Eq, PartialOrd, Ord)]
pub struct QuoteBytes(Vec<u8>);
