use jsonrpsee::core::client::ClientT;

use crate::{
    EthereumFinality, ForeignChainInspectionError, ForeignChainInspector,
    abstract_chain::{AbstractBlockHash, AbstractTransactionHash},
};

use crate::rpc_schema::ethereum::{
    FinalityTag, GetBlockByNumberArgs, GetBlockByNumberResponse, GetTransactionByHashArgs,
    GetTransactionByHashResponse, ReturnFullTransactionHash,
};

const GET_TRANSACTION_RECEIPT_METHOD: &str = "eth_getTransactionReceipt";
// const GET_BLOCK_NUMBER_METHOD: &str = "eth_blockNumber";
const GET_BLOCK_BY_FINALITY_METHOD: &str = "eth_getBlockByNumber";

pub struct AbstractInspector<Client> {
    client: Client,
}

impl<Client> ForeignChainInspector for AbstractInspector<Client>
where
    Client: ClientT + Send + Sync,
{
    type TransactionId = AbstractTransactionHash;
    type Finality = EthereumFinality;
    type Extractor = AbstractExtractor;
    type ExtractedValue = AbstractExtractedValue;

    async fn extract(
        &self,
        transaction: AbstractTransactionHash,
        finality: EthereumFinality,
        extractors: Vec<AbstractExtractor>,
    ) -> Result<Vec<AbstractExtractedValue>, ForeignChainInspectionError> {
        // get latest block with given finality level
        let finality_tag = match finality {
            EthereumFinality::Finalized => FinalityTag::Finalized,
            EthereumFinality::Safe => FinalityTag::Safe,
        };
        let return_full_transaction_hash = ReturnFullTransactionHash::from(false);
        let tx_args = GetBlockByNumberArgs::new(finality_tag, return_full_transaction_hash);

        let latest_block_with_finality_level: GetBlockByNumberResponse = self
            .client
            .request(GET_BLOCK_BY_FINALITY_METHOD, &tx_args)
            .await?;

        // Get the transaction to retrieve blockHash and blockNumber
        let get_transaction_args = GetTransactionByHashArgs {
            transaction_hash: ethereum_types::H256(transaction.into()),
        };

        let transaction_metadata: GetTransactionByHashResponse = self
            .client
            .request(GET_TRANSACTION_RECEIPT_METHOD, &get_transaction_args)
            .await?;

        let finality_is_ok =
            latest_block_with_finality_level.number >= transaction_metadata.block_number;

        if !finality_is_ok {
            return Err(ForeignChainInspectionError::NotFinalized);
        }

        let transaction_success = ethereum_types::U64::one() == transaction_metadata.status;

        if !transaction_success {
            return Err(ForeignChainInspectionError::TransactionFailed);
        }

        let extracted_values = extractors
            .iter()
            .map(|extractor| extractor.extract_value(&transaction_metadata))
            .collect();

        Ok(extracted_values)
    }
}

impl<Client> AbstractInspector<Client>
where
    Client: ClientT + Send + Sync,
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
    fn extract_value(&self, rpc_response: &GetTransactionByHashResponse) -> AbstractExtractedValue {
        match self {
            AbstractExtractor::BlockHash => AbstractExtractedValue::BlockHash(From::from(
                *rpc_response.block_hash.as_fixed_bytes(),
            )),
        }
    }
}
