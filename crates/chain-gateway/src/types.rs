use derive_more::{Display, From, Into};
use near_indexer_primitives::CryptoHash;
use serde::{Deserialize, Serialize};

#[derive(Clone, Into, Debug)]
pub struct BlockEntropy([u8; 32]);

impl BlockEntropy {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<CryptoHash> for BlockEntropy {
    fn from(value: CryptoHash) -> Self {
        BlockEntropy(value.into())
    }
}

#[derive(
    Into, From, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Debug, Display,
)]
pub struct BlockHeight(u64);

impl BlockHeight {
    pub fn saturating_add(self, delta: u64) -> Self {
        BlockHeight(self.0.saturating_add(delta))
    }
    pub fn saturating_sub(self, delta: u64) -> Self {
        BlockHeight(self.0.saturating_sub(delta))
    }
    /// Block distance from `earlier` to `self`. Saturates to `0` if `earlier > self`.
    pub fn blocks_since(self, earlier: BlockHeight) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// Height and hash of the latest final block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatestFinalBlockInfo {
    pub height: BlockHeight,
    pub hash: CryptoHash,
}
