pub use ethereum_types;

pub mod inspector;

mpc_primitives::define_hash!(HyperEvmBlockHash, 32);
mpc_primitives::define_hash!(HyperEvmTransactionHash, 32);
