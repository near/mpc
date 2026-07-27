use derive_more::Into;
use near_indexer_primitives::CryptoHash;
use near_indexer_primitives::types::Gas;

use near_contract_transport::{NearGas, ObservedState};

pub(crate) fn to_action_gas(gas: NearGas) -> Gas {
    Gas::from_gas(gas.as_gas())
}

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

/// block height and block hash
pub type LatestFinalBlockInfo = ObservedState<CryptoHash>;
