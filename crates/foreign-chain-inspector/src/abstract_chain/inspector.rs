use jsonrpsee::core::client::ClientT;

use crate::{
    EthereumFinality, ForeignChainInspectionError, ForeignChainInspector,
    abstract_chain::{AbstractBlockHash, AbstractTransactionHash},
};

use foreign_chain_rpc_interfaces::evm::{
    FinalityTag, GetBlockByNumberArgs, GetBlockByNumberResponse, GetTransactionReceiptARgs,
    GetTransactionReceiptResponse, Log, ReturnFullTransactionObjects,
};

const GET_TRANSACTION_RECEIPT_METHOD: &str = "eth_getTransactionReceipt";
const GET_BLOCK_BY_FINALITY_METHOD: &str = "eth_getBlockByNumber";

pub struct AbstractInspector<Client> {
    client: Client,
}

impl<Client> ForeignChainInspector for AbstractInspector<Client>
where
    Client: ClientT + Send,
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
        let get_latest_block_by_finality_args =
            GetBlockByNumberArgs::new(finality_tag, ReturnFullTransactionObjects::from(false));

        let latest_block_with_finality_level: GetBlockByNumberResponse = self
            .client
            .request(
                GET_BLOCK_BY_FINALITY_METHOD,
                &get_latest_block_by_finality_args,
            )
            .await?;

        let get_transaction_receipt_args = GetTransactionReceiptARgs {
            transaction_hash: ethereum_types::H256(transaction.into()),
        };

        let transaction_receipt: GetTransactionReceiptResponse = self
            .client
            .request(
                GET_TRANSACTION_RECEIPT_METHOD,
                &get_transaction_receipt_args,
            )
            .await?;

        let finality_is_ok =
            latest_block_with_finality_level.number >= transaction_receipt.block_number;

        if !finality_is_ok {
            return Err(ForeignChainInspectionError::NotFinalized);
        }

        let transaction_success = ethereum_types::U64::one() == transaction_receipt.status;

        if !transaction_success {
            return Err(ForeignChainInspectionError::TransactionFailed);
        }

        extractors
            .iter()
            .map(|extractor| extractor.extract_value(&transaction_receipt))
            .collect()
    }
}

impl<Client> AbstractInspector<Client>
where
    Client: ClientT + Send,
{
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AbstractExtractedValue {
    BlockHash(AbstractBlockHash),
    Log(Log),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AbstractExtractor {
    BlockHash,
    Log { log_index: usize },
}

impl AbstractExtractor {
    fn extract_value(
        &self,
        rpc_response: &GetTransactionReceiptResponse,
    ) -> Result<AbstractExtractedValue, ForeignChainInspectionError> {
        match self {
            AbstractExtractor::BlockHash => Ok(AbstractExtractedValue::BlockHash(From::from(
                *rpc_response.block_hash.as_fixed_bytes(),
            ))),
            AbstractExtractor::Log { log_index } => {
                let log = rpc_response
                    .logs
                    .get(*log_index)
                    .cloned()
                    .ok_or(ForeignChainInspectionError::LogIndexOutOfBounds)?;

                Ok(AbstractExtractedValue::Log(log))
            }
        }
    }
}
