pub use ethereum_types;

pub mod inspector;

pub const MAINNET_CHAIN_ID: u64 = 8453;

mpc_primitives::define_hash!(BaseBlockHash, 32);
mpc_primitives::define_hash!(BaseTransactionHash, 32);
