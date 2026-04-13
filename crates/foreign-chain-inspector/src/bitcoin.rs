pub mod inspector;

mpc_primitives::define_hash!(BitcoinBlockHash, 32);
mpc_primitives::define_hash!(BitcoinTransactionHash, 32);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BitcoinExtractedValue {
    BlockHash(BitcoinBlockHash),
}
