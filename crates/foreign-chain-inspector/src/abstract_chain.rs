pub use ethereum_types;

pub mod inspector;

pub struct AbstractBlockHashMarker;
pub type AbstractBlockHash = mpc_primitives::hash::Hash<AbstractBlockHashMarker, 32>;

pub struct AbstractTransactionHashMarker;
pub type AbstractTransactionHash = mpc_primitives::hash::Hash<AbstractTransactionHashMarker, 32>;
