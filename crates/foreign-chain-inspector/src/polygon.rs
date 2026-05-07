pub use ethereum_types;

pub mod inspector;

mpc_primitives::define_hash!(PolygonBlockHash, 32);
mpc_primitives::define_hash!(PolygonTransactionHash, 32);
