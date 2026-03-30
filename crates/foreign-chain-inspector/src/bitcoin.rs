pub mod inspector;

pub struct BitcoinBlockHashMarker;
pub type BitcoinBlockHash = mpc_primitives::hash::Hash<BitcoinBlockHashMarker, 32>;

pub struct BitcoinTransactionHashMarker;
pub type BitcoinTransactionHash = mpc_primitives::hash::Hash<BitcoinTransactionHashMarker, 32>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BitcoinExtractedValue {
    BlockHash(BitcoinBlockHash),
}
