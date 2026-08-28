pub use ethereum_types;

pub mod inspector;

pub const MAINNET_CHAIN_ID: u64 = 1;

mpc_primitives::define_hash!(EthereumBlockHash, 32);
mpc_primitives::define_hash!(EthereumTransactionHash, 32);
