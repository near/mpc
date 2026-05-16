use crate::{
    bnb::{BnbBlockHash, BnbTransactionHash},
    evm::inspector::EvmChain,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bnb;

impl EvmChain for Bnb {
    const NAME: &'static str = "BNB";
    type BlockHash = BnbBlockHash;
    type TransactionHash = BnbTransactionHash;
}

pub type BnbInspector<Client> = crate::evm::inspector::EvmInspector<Client, Bnb>;
pub type BnbExtractedValue = crate::evm::inspector::EvmExtractedValue<Bnb>;
pub type BnbExtractor = crate::evm::inspector::EvmExtractor;
