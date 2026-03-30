use near_mpc_contract_interface::types::StarknetLog;

pub mod inspector;

pub struct StarknetBlockHashMarker;
pub type StarknetBlockHash = mpc_primitives::hash::Hash<StarknetBlockHashMarker, 32>;

pub struct StarknetTransactionHashMarker;
pub type StarknetTransactionHash = mpc_primitives::hash::Hash<StarknetTransactionHashMarker, 32>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StarknetExtractedValue {
    BlockHash(StarknetBlockHash),
    Log(StarknetLog),
}
