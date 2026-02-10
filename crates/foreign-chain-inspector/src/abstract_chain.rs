use mpc_primitives::hash::Hash32;

pub mod inspector;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbstractBlock;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbstractTransaction;

pub type AbstractBlockHash = Hash32<AbstractBlock>;
pub type AbstractTransactionHash = Hash32<AbstractTransaction>;
