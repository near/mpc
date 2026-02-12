use mpc_primitives::hash::Hash32;

pub mod inspector;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbstractBlock;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbstractTransaction;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Log;

pub type AbstractBlockHash = Hash32<AbstractBlock>;
pub type AbstractTransactionHash = Hash32<AbstractTransaction>;
pub type LogHash = Hash32<Log>;
