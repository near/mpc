use mpc_primitives::hash::Hash32;

pub mod inspector;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinBlock;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinTransaction;

pub type BitcoinBlockHash = Hash32<BitcoinBlock>;
pub type BitcoinTransactionHash = Hash32<BitcoinTransaction>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BitcoinExtractedValue {
    BlockHash(BitcoinBlockHash),
}
