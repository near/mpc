use near_mpc_contract_interface::types::StarknetLog;

pub mod inspector;

/// `SN_MAIN` in ASCII, the canonical form `starknet_chainId` reports.
pub const MAINNET_CHAIN_ID: &str = "0x534e5f4d41494e";
/// `SN_SEPOLIA` in ASCII.
pub const SEPOLIA_CHAIN_ID: &str = "0x534e5f5345504f4c4941";

mpc_primitives::define_hash!(StarknetBlockHash, 32);
mpc_primitives::define_hash!(StarknetTransactionHash, 32);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StarknetExtractedValue {
    BlockHash(StarknetBlockHash),
    Log(StarknetLog),
}
