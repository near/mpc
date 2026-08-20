pub use ethereum_types;

pub mod inspector;

mpc_primitives::define_hash!(AvalancheBlockHash, 32);
mpc_primitives::define_hash!(AvalancheTransactionHash, 32);
