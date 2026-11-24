use near_indexer_primitives::CryptoHash;
use near_indexer_primitives::types::Gas;

use near_contract_transport::{NearGas, ObservedState};

pub(crate) fn to_action_gas(gas: NearGas) -> Gas {
    Gas::from_gas(gas.as_gas())
}

/// block height and block hash
pub type LatestFinalBlockInfo = ObservedState<CryptoHash>;
