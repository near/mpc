pub use ethereum_types;

pub mod inspector;

pub const MAINNET_CHAIN_ID: u64 = 43114;

mpc_primitives::define_hash!(AvalancheBlockHash, 32);
mpc_primitives::define_hash!(AvalancheTransactionHash, 32);
