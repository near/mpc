use crate::{
    evm::inspector::EvmChain,
    hyperevm::{HyperEvmBlockHash, HyperEvmTransactionHash},
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HyperEvm;

impl EvmChain for HyperEvm {
    const NAME: &'static str = "HyperEVM";
    type BlockHash = HyperEvmBlockHash;
    type TransactionHash = HyperEvmTransactionHash;
}

pub type HyperEvmInspector<Client> = crate::evm::inspector::EvmInspector<Client, HyperEvm>;
pub type HyperEvmExtractedValue = crate::evm::inspector::EvmExtractedValue<HyperEvm>;
pub type HyperEvmExtractor = crate::evm::inspector::EvmExtractor;
