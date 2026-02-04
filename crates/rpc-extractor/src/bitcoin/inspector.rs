use crate::{
    BlockConfirmations, ForeignChainInspector,
    bitcoin::{BitcoinBlockHash, BitcoinTransactionHash},
};

struct BitcoinRpcExtractor;
struct Bitcoin;

enum BitcoinExtractedValue {
    Hash,
}

enum BitcoinExtractor {
    BlockHash(BitcoinBlockHash),
}

impl ForeignChainInspector for BitcoinRpcExtractor {
    // type Chain = Bitcoin;
    type Extractor = BitcoinExtractor;
    type Finality = BlockConfirmations;
    type ExtractedValue = BitcoinExtractedValue;
    type TxId = BitcoinTransactionHash;

    async fn extract(
        tx_id: Self::TxId,
        extractors: Vec<Self::Extractor>,
        finality: Self::Finality,
    ) -> Self::ExtractedValue {
        todo!()
    }
}
