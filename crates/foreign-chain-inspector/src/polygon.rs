pub use ethereum_types;

pub mod inspector;

pub const MAINNET_CHAIN_ID: u64 = 137;

mpc_primitives::define_hash!(PolygonBlockHash, 32);
mpc_primitives::define_hash!(PolygonTransactionHash, 32);
