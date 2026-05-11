use crate::{
    abstract_chain::{AbstractBlockHash, AbstractTransactionHash},
    evm::inspector::EvmChain,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Abstract;

impl EvmChain for Abstract {
    const NAME: &'static str = "Abstract";
    type BlockHash = AbstractBlockHash;
    type TransactionHash = AbstractTransactionHash;
}

pub type AbstractInspector<Client> = crate::evm::inspector::EvmInspector<Client, Abstract>;
pub type AbstractExtractedValue = crate::evm::inspector::EvmExtractedValue<Abstract>;
pub type AbstractExtractor = crate::evm::inspector::EvmExtractor;
