use jsonrpsee::core::client::ClientT;

use crate::{
    EthereumFinality, ForeignChainInspectionError, ForeignChainInspector,
    bnb::{BnbBlockHash, BnbTransactionHash},
};

use foreign_chain_rpc_interfaces::evm::{
    FinalityTag, GetBlockByNumberArgs, GetBlockByNumberResponse, GetTransactionReceiptARgs,
    GetTransactionReceiptResponse, Log, ReturnFullTransactionObjects,
};

const GET_TRANSACTION_RECEIPT_METHOD: &str = "eth_getTransactionReceipt";
const GET_BLOCK_BY_FINALITY_METHOD: &str = "eth_getBlockByNumber";

pub struct BnbInspector<Client> {
    client: Client,
}

impl<Client> ForeignChainInspector for BnbInspector<Client>
where
    Client: ClientT + Send,
{
    type TransactionId = BnbTransactionHash;
    type Finality = EthereumFinality;
    type Extractor = BnbExtractor;
    type ExtractedValue = BnbExtractedValue;

    async fn extract(
        &self,
        transaction: BnbTransactionHash,
        finality: EthereumFinality,
        extractors: Vec<BnbExtractor>,
    ) -> Result<Vec<BnbExtractedValue>, ForeignChainInspectionError> {
        // get latest block with given finality level
        let finality_tag = match finality {
            EthereumFinality::Finalized => FinalityTag::Finalized,
            EthereumFinality::Safe => FinalityTag::Safe,
            EthereumFinality::Latest => FinalityTag::Latest,
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

impl<Client> BnbInspector<Client>
where
    Client: ClientT + Send,
{
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BnbExtractedValue {
    BlockHash(BnbBlockHash),
    Log(Log),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BnbExtractor {
    BlockHash,
    Log { log_index: u64 },
}

impl BnbExtractor {
    fn extract_value(
        &self,
        rpc_response: &GetTransactionReceiptResponse,
    ) -> Result<BnbExtractedValue, ForeignChainInspectionError> {
        match self {
            BnbExtractor::BlockHash => Ok(BnbExtractedValue::BlockHash(From::from(
                *rpc_response.block_hash.as_fixed_bytes(),
            ))),
            BnbExtractor::Log { log_index } => {
                let target_index = ethereum_types::U64::from(*log_index);
                let log = rpc_response
                    .logs
                    .iter()
                    .find(|log| log.log_index == target_index)
                    .cloned()
                    .ok_or(ForeignChainInspectionError::LogIndexOutOfBounds)?;

                Ok(BnbExtractedValue::Log(log))
            }
        }
    }
}
