use crate::{
    BlockConfirmations, ForeignChainInspectionError, ForeignChainInspector, ForeignChainRpcClient,
    abstract_chain::{AbstractBlockHash, AbstractRpcResponse, AbstractTransactionHash},
};

pub struct AbstractInspector<Client> {
    client: Client,
}

impl<Client> ForeignChainInspector for AbstractInspector<Client>
where
    Client: ForeignChainRpcClient<
            TransactionId = AbstractTransactionHash,
            Finality = BlockConfirmations,
            RpcResponse = AbstractRpcResponse,
        >,
{
    type TransactionId = AbstractTransactionHash;
    type Finality = BlockConfirmations;
    type Extractor = AbstractExtractor;
    type ExtractedValue = AbstractExtractedValue;

    async fn extract(
        &self,
        tx_id: AbstractTransactionHash,
        block_confirmations_threshold: BlockConfirmations,
        extractors: Vec<AbstractExtractor>,
    ) -> Result<Vec<AbstractExtractedValue>, ForeignChainInspectionError> {
        let response = self
            .client
            .get(tx_id, block_confirmations_threshold)
            .await?;

        // let enough_block_confirmations = block_confirmations_threshold <= response.confirmations;

        // if !enough_block_confirmations {
        //     return Err(ForeignChainInspectionError::NotEnoughBlockConfirmations {
        //         expected: block_confirmations_threshold,
        //         got: response.confirmations,
        //     });
        // }

        let extracted_values = extractors
            .iter()
            .map(|extractor| extractor.extract_value(&response))
            .collect();

        Ok(extracted_values)
    }
}

impl<Client> AbstractInspector<Client>
where
    Client: ForeignChainRpcClient<
            TransactionId = AbstractTransactionHash,
            Finality = BlockConfirmations,
            RpcResponse = AbstractRpcResponse,
        >,
{
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AbstractExtractedValue {
    BlockHash(AbstractBlockHash),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AbstractExtractor {
    BlockHash,
}

impl AbstractExtractor {
    fn extract_value(&self, rpc_response: &AbstractRpcResponse) -> AbstractExtractedValue {
        match self {
            AbstractExtractor::BlockHash => {
                AbstractExtractedValue::BlockHash(rpc_response.block_hash.clone())
            }
        }
    }
}
