use crate::{
    evm::inspector::EvmChain,
    polygon::{PolygonBlockHash, PolygonTransactionHash},
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Polygon;

impl EvmChain for Polygon {
    type BlockHash = PolygonBlockHash;
    type TransactionHash = PolygonTransactionHash;
}

pub type PolygonInspector<Client> = crate::evm::inspector::EvmInspector<Client, Polygon>;
pub type PolygonExtractedValue = crate::evm::inspector::EvmExtractedValue<Polygon>;
pub type PolygonExtractor = crate::evm::inspector::EvmExtractor;
