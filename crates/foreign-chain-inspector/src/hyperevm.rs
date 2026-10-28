pub use ethereum_types;

pub mod inspector;

pub const MAINNET_CHAIN_ID: u64 = 999;

mpc_primitives::define_hash!(HyperEvmBlockHash, 32);
mpc_primitives::define_hash!(HyperEvmTransactionHash, 32);
