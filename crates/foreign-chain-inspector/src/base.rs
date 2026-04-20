pub use ethereum_types;

pub mod inspector;

mpc_primitives::define_hash!(BaseBlockHash, 32);
mpc_primitives::define_hash!(BaseTransactionHash, 32);
