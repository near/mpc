use crate::{
    BlockConfirmations, ForeignChainRpcClient, RpcError,
    abstract_chain::{AbstractBlockHash, AbstractRpcResponse, AbstractTransactionHash},
};
use jsonrpsee::core::{client::ClientT, params::ArrayParams};
use serde::{Deserialize, Serialize};

/// Standard Ethereum JSON-RPC methods that Abstract supports
const GET_TRANSACTION_BY_HASH_METHOD: &str = "eth_getTransactionByHash";
const GET_BLOCK_NUMBER_METHOD: &str = "eth_blockNumber";

#[derive(Debug, Clone)]
pub struct AbstractRpcClient<Client> {
    client: Client,
}

impl<Client> AbstractRpcClient<Client> {
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

impl<Client> ForeignChainRpcClient for AbstractRpcClient<Client>
where
    Client: ClientT + Send + Sync,
{
    type TransactionId = AbstractTransactionHash;
    type Finality = BlockConfirmations;
    type RpcResponse = AbstractRpcResponse;

    async fn get(
        &self,
        transaction: AbstractTransactionHash,
        _finality: BlockConfirmations,
    ) -> Result<AbstractRpcResponse, RpcError> {
        // Get the transaction to retrieve blockHash and blockNumber
        let tx_response: Option<TransactionResponse> = self
            .client
            .request(GET_TRANSACTION_BY_HASH_METHOD, (transaction,))
            .await?;

        let tx_response = tx_response.ok_or_else(|| {
            RpcError::ClientError(jsonrpsee::core::client::error::Error::Custom(
                "Transaction not found".to_string(),
            ))
        })?;

        // Get current block number to calculate confirmations
        let current_block_hex: String = self
            .client
            .request(GET_BLOCK_NUMBER_METHOD, ArrayParams::new())
            .await?;

        let current_block = u64::from_str_radix(current_block_hex.trim_start_matches("0x"), 16)
            .map_err(|e| {
                RpcError::ClientError(jsonrpsee::core::client::error::Error::Custom(format!(
                    "Failed to parse block number: {}",
                    e
                )))
            })?;

        // Calculate confirmations: current_block - tx_block + 1
        let tx_block = u64::from_str_radix(tx_response.block_number.trim_start_matches("0x"), 16)
            .map_err(|e| {
            RpcError::ClientError(jsonrpsee::core::client::error::Error::Custom(format!(
                "Failed to parse transaction block number: {}",
                e
            )))
        })?;

        let confirmations = if current_block >= tx_block {
            current_block - tx_block + 1
        } else {
            0
        };

        Ok(AbstractRpcResponse {
            block_hash: tx_response.block_hash,
            confirmations: confirmations.into(),
        })
    }
}

/// Response from eth_getTransactionByHash
/// See: https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_gettransactionbyhash
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionResponse {
    /// Hash of the block where this transaction was in
    block_hash: AbstractBlockHash,
    /// Block number where this transaction was in (hex string)
    block_number: String,
}
