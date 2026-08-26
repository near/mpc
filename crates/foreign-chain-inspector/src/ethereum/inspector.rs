use crate::{
    ethereum::{EthereumBlockHash, EthereumTransactionHash},
    evm::inspector::EvmChain,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ethereum;

impl EvmChain for Ethereum {
    type BlockHash = EthereumBlockHash;
    type TransactionHash = EthereumTransactionHash;
}

pub type EthereumInspector<Client> = crate::evm::inspector::EvmInspector<Client, Ethereum>;
pub type EthereumExtractedValue = crate::evm::inspector::EvmExtractedValue<Ethereum>;
pub type EthereumExtractor = crate::evm::inspector::EvmExtractor;
