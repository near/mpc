pub use ethereum_types;

pub mod inspector;

mpc_primitives::define_hash!(AbstractBlockHash, 32);
mpc_primitives::define_hash!(AbstractTransactionHash, 32);
