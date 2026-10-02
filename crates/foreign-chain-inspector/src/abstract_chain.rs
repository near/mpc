pub use ethereum_types;

pub mod inspector;

pub const MAINNET_CHAIN_ID: u64 = 2741;
pub const TESTNET_CHAIN_ID: u64 = 11124;

mpc_primitives::define_hash!(AbstractBlockHash, 32);
mpc_primitives::define_hash!(AbstractTransactionHash, 32);
