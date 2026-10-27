use borsh::{BorshDeserialize, BorshSerialize};
use core::ops::Add;
use serde::{Deserialize, Serialize};

/// Height of a NEAR block. Later blocks compare greater.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Display,
    derive_more::From,
    derive_more::Into,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct BlockHeight(u64);

impl BlockHeight {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    pub fn saturating_add(self, delta: u64) -> Self {
        Self(self.0.saturating_add(delta))
    }

    pub fn saturating_sub(self, delta: u64) -> Self {
        Self(self.0.saturating_sub(delta))
    }

    /// Block distance from `earlier` to `self`. Saturates to `0` if `earlier > self`.
    pub fn blocks_since(self, earlier: BlockHeight) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// A number of blocks: a distance between heights or a timeout measured in blocks.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Display,
    derive_more::From,
    derive_more::Into,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct BlockCount(u64);

impl BlockCount {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

impl Add<BlockCount> for BlockHeight {
    type Output = BlockHeight;

    fn add(self, count: BlockCount) -> BlockHeight {
        BlockHeight(self.0 + count.0)
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{BlockCount, BlockHeight};

    #[test]
    fn block_height__should_encode_as_the_bare_integer() {
        // Given
        let height = BlockHeight::new(7);

        // When
        let json = serde_json::to_string(&height).unwrap();
        let bytes = borsh::to_vec(&height).unwrap();

        // Then
        assert_eq!(json, "7");
        assert_eq!(bytes, 7u64.to_le_bytes());
        assert_eq!(serde_json::from_str::<BlockHeight>(&json).unwrap(), height);
        assert_eq!(borsh::from_slice::<BlockHeight>(&bytes).unwrap(), height);
    }

    #[test]
    fn blocks_since__should_saturate_at_zero() {
        // Given
        let earlier = BlockHeight::new(10);
        let later = BlockHeight::new(13);

        // When
        let forward = later.blocks_since(earlier);
        let backward = earlier.blocks_since(later);

        // Then
        assert_eq!((forward, backward), (3, 0));
    }

    #[test]
    fn add__should_advance_the_height_by_the_count() {
        // Given
        let height = BlockHeight::new(10);
        let count = BlockCount::new(5);

        // When
        let later = height + count;

        // Then
        assert_eq!(later, BlockHeight::new(15));
    }
}
