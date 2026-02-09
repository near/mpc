use mpc_primitives::hash::Hash32;

use crate::BlockConfirmations;

pub mod inspector;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinBlock;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinTransaction;

pub type BitcoinBlockHash = Hash32<BitcoinBlock>;
pub type BitcoinTransactionHash = Hash32<BitcoinTransaction>;

/// Normalized response.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinRpcResponse {
    pub block_hash: BitcoinBlockHash,
    pub confirmations: BlockConfirmations,
}
