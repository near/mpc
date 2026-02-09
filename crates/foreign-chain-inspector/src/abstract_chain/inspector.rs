use jsonrpsee::core::client::ClientT;

use crate::{
    BlockConfirmations, EthereumFinality, ForeignChainInspectionError, ForeignChainInspector,
    abstract_chain::{AbstractBlockHash, AbstractRpcResponse, AbstractTransactionHash},
};

use crate::{
    RpcError,
    rpc_schema::{
        self,
        ethereum::{
            FinalityTag, GetBlockByNumberArgs, GetBlockByNumberResponse, GetTransactionByHashArgs,
            GetTransactionByHashResponse, ReturnFullTransactionHash,
        },
    },
};

const GET_TRANSACTION_RECEIPT_METHOD: &str = "eth_getTransactionReceipt";
// const GET_BLOCK_NUMBER_METHOD: &str = "eth_blockNumber";
const GET_BLOCK_BY_FINALITY_METHOD: &str = "eth_getBlockByNumber";

const LATEST_SAFE_BLOCK_TAG: &str = "safe";
const LATEST_FINALIZED_BLOCK_TAG: &str = "finalized";

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
        let response = self.get(transaction, finality).await?;

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
    Client: ClientT + Send + Sync,
{
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    async fn get(
        &self,
        transaction: AbstractTransactionHash,
        finality: EthereumFinality,
    ) -> Result<AbstractRpcResponse, RpcError> {
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
        let block_hash_bytes = transaction_metadata.block_hash.0;

        if finality_is_ok {
            Ok(AbstractRpcResponse {
                block_hash: block_hash_bytes.into(),
            })
        } else {
            Err(RpcError::NotFinalized)
        }
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
