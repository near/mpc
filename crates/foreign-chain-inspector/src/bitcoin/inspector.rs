use crate::{
    BlockConfirmations, ForeignChainInspectionError, ForeignChainInspector, ForeignChainRpcClient,
    bitcoin::{BitcoinBlockHash, BitcoinRpcResponse, BitcoinTransactionHash},
};

pub struct BitcoinInspector<Client> {
    client: Client,
}

impl<Client> ForeignChainInspector for BitcoinInspector<Client>
where
    Client: ForeignChainRpcClient<
            TransactionId = BitcoinTransactionHash,
            Finality = BlockConfirmations,
            RpcResponse = BitcoinRpcResponse,
        >,
{
    type TransactionId = BitcoinTransactionHash;
    type Finality = BlockConfirmations;
    type Extractor = BitcoinExtractor;
    type ExtractedValue = BitcoinExtractedValue;

    async fn extract(
        &self,
        tx_id: BitcoinTransactionHash,
        block_confirmations_threshold: BlockConfirmations,
        extractors: Vec<BitcoinExtractor>,
    ) -> Result<Vec<BitcoinExtractedValue>, ForeignChainInspectionError> {
        let response = self
            .client
            .get(tx_id, block_confirmations_threshold)
            .await?;

        let enough_block_confirmations = block_confirmations_threshold <= response.confirmations;

        if !enough_block_confirmations {
            return Err(ForeignChainInspectionError::NotEnoughBlockConfirmations {
                expected: block_confirmations_threshold,
                got: response.confirmations,
            });
        }

        let extracted_values = extractors
            .iter()
            .map(|extractor| extractor.extract_value(&response))
            .collect();

        Ok(extracted_values)
    }
}

impl<Client> BitcoinInspector<Client>
where
    Client: ForeignChainRpcClient<
            TransactionId = BitcoinTransactionHash,
            Finality = BlockConfirmations,
            RpcResponse = BitcoinRpcResponse,
        >,
{
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BitcoinExtractedValue {
    BlockHash(BitcoinBlockHash),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BitcoinExtractor {
    BlockHash,
}

impl BitcoinExtractor {
    fn extract_value(&self, rpc_response: &BitcoinRpcResponse) -> BitcoinExtractedValue {
        match self {
            BitcoinExtractor::BlockHash => {
                BitcoinExtractedValue::BlockHash(rpc_response.block_hash.clone())
            }
        }
    }
}
