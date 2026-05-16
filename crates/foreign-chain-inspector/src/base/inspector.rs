use crate::{
    base::{BaseBlockHash, BaseTransactionHash},
    evm::inspector::EvmChain,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Base;

impl EvmChain for Base {
    const NAME: &'static str = "Base";
    type BlockHash = BaseBlockHash;
    type TransactionHash = BaseTransactionHash;
}

pub type BaseInspector<Client> = crate::evm::inspector::EvmInspector<Client, Base>;
pub type BaseExtractedValue = crate::evm::inspector::EvmExtractedValue<Base>;
pub type BaseExtractor = crate::evm::inspector::EvmExtractor;
