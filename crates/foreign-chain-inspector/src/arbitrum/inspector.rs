use crate::{
    arbitrum::{ArbitrumBlockHash, ArbitrumTransactionHash},
    evm::inspector::EvmChain,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Arbitrum;

impl EvmChain for Arbitrum {
    const NAME: &'static str = "Arbitrum";
    type BlockHash = ArbitrumBlockHash;
    type TransactionHash = ArbitrumTransactionHash;
}

pub type ArbitrumInspector<Client> = crate::evm::inspector::EvmInspector<Client, Arbitrum>;
pub type ArbitrumExtractedValue = crate::evm::inspector::EvmExtractedValue<Arbitrum>;
pub type ArbitrumExtractor = crate::evm::inspector::EvmExtractor;
