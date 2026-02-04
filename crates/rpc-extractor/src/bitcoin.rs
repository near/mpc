use mpc_primitives::hash::Hash32;

pub mod inspector;
pub mod rpc_client;

#[derive(Debug, Clone)]
pub struct BitcoinBlock;
#[derive(Debug, Clone)]
pub struct BitcoinTransaction;

pub type BitcoinBlockHash = Hash32<BitcoinBlock>;
pub type BitcoinTransactionHash = Hash32<BitcoinTransaction>;
