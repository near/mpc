use std::fmt::Debug;
use std::hash::Hash;

use jsonrpsee::core::client::ClientT;
use near_mpc_bounded_collections::NonEmptyVec;

use crate::{
    EthereumFinality, ForeignChainInspectionError, ForeignChainInspector, fan_out_and_match,
};

use foreign_chain_rpc_interfaces::evm::{
    BlockNumberOrTag, FinalityTag, GetBlockByNumberArgs, GetBlockByNumberResponse,
    GetTransactionReceiptARgs, GetTransactionReceiptResponse, H256, Log,
    ReturnFullTransactionObjects, U64,
};

const GET_TRANSACTION_RECEIPT_METHOD: &str = "eth_getTransactionReceipt";
const GET_BLOCK_BY_NUMBER_METHOD: &str = "eth_getBlockByNumber";

/// Marker trait for EVM-compatible chain type parameters.
///
/// Each chain provides its own block-hash and transaction-hash newtypes so that
/// different chains remain type-incompatible at the call site, while sharing the
/// single [`EvmInspector`] implementation.
pub trait EvmChain: PartialEq + Eq {
    type BlockHash: From<[u8; 32]> + Into<[u8; 32]> + Clone + Debug + PartialEq + Eq + Hash;
    type TransactionHash: From<[u8; 32]> + Into<[u8; 32]> + Clone + Debug + PartialEq + Eq + Hash;
}

pub struct EvmInspector<Client, Chain> {
    clients: NonEmptyVec<Client>,
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
        let (first_client, rest_clients) = self.clients.split_last();

        fan_out_and_match(
            extract_with_client::<Client, Chain>(
                first_client,
                transaction.clone(),
                finality,
                &extractors,
            ),
            rest_clients.iter().map(|client| {
                extract_with_client::<Client, Chain>(
                    client,
                    transaction.clone(),
                    finality,
                    &extractors,
                )
            }),
        )
        .await
    }
}

impl<Client, Chain> EvmInspector<Client, Chain>
where
    Client: ClientT + Send,
    Chain: EvmChain,
{
    pub fn new(clients: NonEmptyVec<Client>) -> Self {
        Self {
            clients,
            _chain: std::marker::PhantomData,
        }
    }
}

async fn extract_with_client<Client, Chain>(
    client: &Client,
    transaction: Chain::TransactionHash,
    finality: EthereumFinality,
    extractors: &[EvmExtractor],
) -> Result<Vec<EvmExtractedValue<Chain>>, ForeignChainInspectionError>
where
    Client: ClientT + Send,
    Chain: EvmChain,
{
    let get_transaction_receipt_args = GetTransactionReceiptARgs {
        transaction_hash: H256(transaction.into()),
    };
    let transaction_receipt: GetTransactionReceiptResponse = client
        .request(
            GET_TRANSACTION_RECEIPT_METHOD,
            &get_transaction_receipt_args,
        )
        .await?;

    verify_finality_level(client, transaction_receipt.block_number, finality).await?;
    verify_block_is_canonical(
        client,
        transaction_receipt.block_number,
        transaction_receipt.block_hash,
    )
    .await?;

    let transaction_success = transaction_receipt.status == U64::one();

    if !transaction_success {
        return Err(ForeignChainInspectionError::TransactionFailed);
    }

    extractors
        .iter()
        .map(|extractor| extractor.extract_value(&transaction_receipt))
        .collect()
}

/// Checks that the receipt's block has reached the requested finality level — i.e. that the
/// head of the chain at `finality` is at or past `receipt_block_number`.
async fn verify_finality_level<Client: ClientT + Send>(
    client: &Client,
    receipt_block_number: U64,
    finality: EthereumFinality,
) -> Result<(), ForeignChainInspectionError> {
    let finality_tag = match finality {
        EthereumFinality::Finalized => FinalityTag::Finalized,
        EthereumFinality::Safe => FinalityTag::Safe,
        EthereumFinality::Latest => FinalityTag::Latest,
    };
    let args = GetBlockByNumberArgs::new(
        BlockNumberOrTag::Tag(finality_tag),
        ReturnFullTransactionObjects::from(false),
    );
    let head: GetBlockByNumberResponse = client.request(GET_BLOCK_BY_NUMBER_METHOD, &args).await?;

    if head.number < receipt_block_number {
        return Err(ForeignChainInspectionError::NotFinalized);
    }
    Ok(())
}

/// Checks that the receipt's block is on the canonical chain by re-fetching the canonical
/// block at `receipt_block_number` and comparing hashes. `eth_getBlockByNumber` only ever
/// resolves to a canonical block, so a mismatch means the receipt was indexed against a
/// side block (stale tx index, partially-applied reorg, divergent RPC backend, etc.).
async fn verify_block_is_canonical<Client: ClientT + Send>(
    client: &Client,
    receipt_block_number: U64,
    receipt_block_hash: H256,
) -> Result<(), ForeignChainInspectionError> {
    let args = GetBlockByNumberArgs::new(
        BlockNumberOrTag::Number(receipt_block_number),
        ReturnFullTransactionObjects::from(false),
    );
    let canonical: GetBlockByNumberResponse =
        client.request(GET_BLOCK_BY_NUMBER_METHOD, &args).await?;

    if canonical.hash != receipt_block_hash {
        return Err(ForeignChainInspectionError::NonCanonicalBlock {
            block_number: receipt_block_number,
            receipt_hash: receipt_block_hash,
            canonical_hash: canonical.hash,
        });
    }
    Ok(())
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
