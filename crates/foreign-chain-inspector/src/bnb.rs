pub use ethereum_types;

pub mod inspector;

pub const MAINNET_CHAIN_ID: u64 = 56;

mpc_primitives::define_hash!(BnbBlockHash, 32);
mpc_primitives::define_hash!(BnbTransactionHash, 32);
