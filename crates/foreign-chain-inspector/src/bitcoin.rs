use crate::hash::hash_newtype;

pub mod inspector;

hash_newtype!(BitcoinBlockHash);
hash_newtype!(BitcoinTransactionHash);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BitcoinExtractedValue {
    BlockHash(BitcoinBlockHash),
}
