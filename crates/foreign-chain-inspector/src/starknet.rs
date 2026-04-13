use near_mpc_contract_interface::types::StarknetLog;

pub mod inspector;

mpc_primitives::define_hash!(StarknetBlockHash, 32);
mpc_primitives::define_hash!(StarknetTransactionHash, 32);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StarknetExtractedValue {
    BlockHash(StarknetBlockHash),
    Log(StarknetLog),
}
