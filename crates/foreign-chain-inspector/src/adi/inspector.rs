use crate::{
    adi::{AdiBlockHash, AdiTransactionHash},
    evm::inspector::EvmChain,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Adi;

impl EvmChain for Adi {
    type BlockHash = AdiBlockHash;
    type TransactionHash = AdiTransactionHash;
}

pub type AdiInspector<Client> = crate::evm::inspector::EvmInspector<Client, Adi>;
pub type AdiExtractedValue = crate::evm::inspector::EvmExtractedValue<Adi>;
pub type AdiExtractor = crate::evm::inspector::EvmExtractor;
