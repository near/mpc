use crate::{
    avalanche::{AvalancheBlockHash, AvalancheTransactionHash},
    evm::inspector::EvmChain,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Avalanche;

impl EvmChain for Avalanche {
    type BlockHash = AvalancheBlockHash;
    type TransactionHash = AvalancheTransactionHash;
}

pub type AvalancheInspector<Client> = crate::evm::inspector::EvmInspector<Client, Avalanche>;
pub type AvalancheExtractedValue = crate::evm::inspector::EvmExtractedValue<Avalanche>;
pub type AvalancheExtractor = crate::evm::inspector::EvmExtractor;
