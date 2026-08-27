pub mod inspector;

/// Bitcoin networks are told apart by their genesis block hash.
pub const MAINNET_GENESIS_BLOCK_HASH: &str =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
pub const TESTNET3_GENESIS_BLOCK_HASH: &str =
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";

mpc_primitives::define_hash!(BitcoinBlockHash, 32);
mpc_primitives::define_hash!(BitcoinTransactionHash, 32);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BitcoinExtractedValue {
    BlockHash(BitcoinBlockHash),
}
