use crate::{
    BlockConfirmations, ForeignChainInspector, RpcClient,
    bitcoin::{BitcoinBlockHash, BitcoinTransactionHash},
};

pub struct BitcoinInspector<Client> {
    client: Client,
    extractor: BitcoinExtractor,
}

struct Bitcoin;

pub enum BitcoinExtractedValue {
    Hash,
}

pub enum BitcoinExtractor {
    BlockHash(BitcoinBlockHash),
}

impl<Client> ForeignChainInspector for BitcoinInspector<Client>
where
    Client: RpcClient,
{
    // type Chain = Bitcoin;
    type Extractor = BitcoinExtractor;
    type Finality = BlockConfirmations;
    type ExtractedValue = BitcoinExtractedValue;
    type TxId = BitcoinTransactionHash;

    async fn extract(
        &self,
        tx_id: Self::TxId,
        extractors: Vec<Self::Extractor>,
        finality: Self::Finality,
    ) -> Self::ExtractedValue {
        let response = self.client.get(tx_id, finality).await;

        todo!();
    }
}
