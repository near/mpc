use std::fmt::Debug;
use std::hash::Hash;

use jsonrpsee::core::client::ClientT;

use crate::{EthereumFinality, ForeignChainInspectionError, ForeignChainInspector};

use foreign_chain_rpc_interfaces::evm::{
    BlockNumberOrTag, FinalityTag, GetBlockByNumberArgs, GetBlockByNumberResponse,
    GetTransactionReceiptARgs, GetTransactionReceiptResponse, Log, ReturnFullTransactionObjects,
};

const GET_TRANSACTION_RECEIPT_METHOD: &str = "eth_getTransactionReceipt";
const GET_BLOCK_BY_NUMBER_METHOD: &str = "eth_getBlockByNumber";

/// Marker trait for EVM-compatible chain type parameters.
///
/// Each chain provides its own block-hash and transaction-hash newtypes so that
/// different chains remain type-incompatible at the call site, while sharing the
/// single [`EvmInspector`] implementation.
pub trait EvmChain {
    type BlockHash: From<[u8; 32]> + Into<[u8; 32]> + Clone + Debug + PartialEq + Eq + Hash;
    type TransactionHash: From<[u8; 32]> + Into<[u8; 32]> + Clone + Debug + PartialEq + Eq + Hash;
}

pub struct EvmInspector<Client, Chain> {
    client: Client,
    _chain: std::marker::PhantomData<Chain>,
}

impl<Client, Chain> ForeignChainInspector for EvmInspector<Client, Chain>
where
    Client: ClientT + Send,
    Chain: EvmChain + Send,
{
    type TransactionId = Chain::TransactionHash;
    type Finality = EthereumFinality;
    type Extractor = EvmExtractor;
    type ExtractedValue = EvmExtractedValue<Chain>;

    async fn extract(
        &self,
        transaction: Chain::TransactionHash,
        finality: EthereumFinality,
        extractors: Vec<EvmExtractor>,
    ) -> Result<Vec<EvmExtractedValue<Chain>>, ForeignChainInspectionError> {
        // get latest block with given finality level
        let finality_tag = match finality {
            EthereumFinality::Finalized => FinalityTag::Finalized,
            EthereumFinality::Safe => FinalityTag::Safe,
            EthereumFinality::Latest => FinalityTag::Latest,
        };
        let get_latest_block_by_finality_args = GetBlockByNumberArgs::new(
            BlockNumberOrTag::Tag(finality_tag),
            ReturnFullTransactionObjects::from(false),
        );

        let latest_block_with_finality_level: GetBlockByNumberResponse = self
            .client
            .request(
                GET_BLOCK_BY_NUMBER_METHOD,
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

        // Defense in depth: a number-only check accepts any receipt whose block height is at or
        // below the finalized head, but a malicious or out-of-sync RPC could still return a
        // receipt from a side block. Re-fetch the canonical block at that height and reject
        // when its hash does not match the receipt's block hash.
        let get_canonical_block_args = GetBlockByNumberArgs::new(
            BlockNumberOrTag::Number(transaction_receipt.block_number),
            ReturnFullTransactionObjects::from(false),
        );
        let canonical_block: GetBlockByNumberResponse = self
            .client
            .request(GET_BLOCK_BY_NUMBER_METHOD, &get_canonical_block_args)
            .await?;

        if canonical_block.hash != transaction_receipt.block_hash {
            return Err(ForeignChainInspectionError::NonCanonicalBlock);
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

impl<Client, Chain> EvmInspector<Client, Chain>
where
    Client: ClientT + Send,
    Chain: EvmChain,
{
    pub fn new(client: Client) -> Self {
        Self {
            client,
            _chain: std::marker::PhantomData,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvmExtractedValue<Chain: EvmChain> {
    BlockHash(Chain::BlockHash),
    Log(Log),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvmExtractor {
    BlockHash,
    Log { log_index: u64 },
}

impl EvmExtractor {
    fn extract_value<Chain: EvmChain>(
        &self,
        rpc_response: &GetTransactionReceiptResponse,
    ) -> Result<EvmExtractedValue<Chain>, ForeignChainInspectionError> {
        match self {
            EvmExtractor::BlockHash => Ok(EvmExtractedValue::BlockHash(From::from(
                *rpc_response.block_hash.as_fixed_bytes(),
            ))),
            EvmExtractor::Log { log_index } => {
                let target_index = ethereum_types::U64::from(*log_index);
                let log = rpc_response
                    .logs
                    .iter()
                    .find(|log| log.log_index == target_index)
                    .cloned()
                    .ok_or(ForeignChainInspectionError::LogIndexOutOfBounds)?;

                Ok(EvmExtractedValue::Log(log))
            }
        }
    }
}
