use crate::{
    BlockConfirmations, BlockHeight, ForeignChainRpcClient, RpcError,
    abstract_chain::{AbstractBlockHash, AbstractRpcResponse, AbstractTransactionHash},
    rpc_schema::ethereum::{
        BlockNumberResponse, GetTransactionByHashArgs, GetTransactionByHashResponse,
    },
};
use jsonrpsee::core::{client::ClientT, params::ArrayParams};

const GET_TRANSACTION_RECEIPT_METHOD: &str = "eth_getTransactionReceipt";
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
        let get_transaction_args = GetTransactionByHashArgs {
            transaction_hash: ethereum_types::H256(transaction.into()),
        };

        let tx_response: GetTransactionByHashResponse = self
            .client
            .request(GET_TRANSACTION_RECEIPT_METHOD, &get_transaction_args)
            .await?;

        let latest_block_height: BlockNumberResponse = self
            .client
            .request(GET_BLOCK_NUMBER_METHOD, ArrayParams::new())
            .await?;

        let block_hash_bytes: [u8; 32] = tx_response.block_hash.into();

        Ok(AbstractRpcResponse {
            block_hash: AbstractBlockHash::from(block_hash_bytes),
            latest_block_height: BlockHeight::from(latest_block_height.0.as_u64()),
        })
    }
}
