use crate::hash::hash_newtype;
use near_mpc_contract_interface::types::StarknetLog;

pub mod inspector;

hash_newtype!(StarknetBlockHash);
hash_newtype!(StarknetTransactionHash);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StarknetExtractedValue {
    BlockHash(StarknetBlockHash),
    Log(StarknetLog),
}
