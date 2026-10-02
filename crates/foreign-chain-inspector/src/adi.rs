pub use ethereum_types;

pub mod inspector;

pub const MAINNET_CHAIN_ID: u64 = 36900;

mpc_primitives::define_hash!(AdiBlockHash, 32);
mpc_primitives::define_hash!(AdiTransactionHash, 32);
