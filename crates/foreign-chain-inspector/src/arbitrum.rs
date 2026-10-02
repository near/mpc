pub use ethereum_types;

pub mod inspector;

pub const MAINNET_CHAIN_ID: u64 = 42161;

mpc_primitives::define_hash!(ArbitrumBlockHash, 32);
mpc_primitives::define_hash!(ArbitrumTransactionHash, 32);
