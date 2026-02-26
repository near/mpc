use contract_interface::types::StarknetLog;
use mpc_primitives::hash::Hash32;

pub mod inspector;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StarknetBlock;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StarknetTransaction;

pub type StarknetBlockHash = Hash32<StarknetBlock>;
pub type StarknetTransactionHash = Hash32<StarknetTransaction>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StarknetExtractedValue {
    BlockHash(StarknetBlockHash),
    Log(StarknetLog)
}
