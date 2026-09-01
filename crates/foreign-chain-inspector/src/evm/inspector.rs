use std::fmt::Debug;
use std::hash::Hash;

use jsonrpsee::core::client::ClientT;

use crate::{
    ClassifyRpcOutcome, EthereumFinality, ForeignChainInspectionError, ForeignChainInspector,
    NO_PARAMS, NetworkFingerprint, NetworkFingerprintInspector, Verdict,
};

use foreign_chain_rpc_interfaces::evm::{
    BlockNumberOrTag, ChainIdResponse, FinalityTag, GetBlockByNumberArgs, GetBlockByNumberResponse,
    GetTransactionReceiptARgs, GetTransactionReceiptResponse, H256, Log,
    ReturnFullTransactionObjects, U64,
};

const GET_TRANSACTION_RECEIPT_METHOD: &str = "eth_getTransactionReceipt";
const GET_BLOCK_BY_NUMBER_METHOD: &str = "eth_getBlockByNumber";
const CHAIN_ID_METHOD: &str = "eth_chainId";

/// Marker trait for EVM-compatible chain type parameters.
///
/// Each chain provides its own block-hash and transaction-hash newtypes so that
/// different chains remain type-incompatible at the call site, while sharing the
/// single [`EvmInspector`] implementation.
pub trait EvmChain {
    type BlockHash: From<[u8; 32]> + Into<[u8; 32]> + Clone + Debug + PartialEq + Eq + Hash + Send;
    type TransactionHash: From<[u8; 32]>
        + Into<[u8; 32]>
        + Clone
        + Debug
        + PartialEq
        + Eq
        + Hash
        + Send;
}

#[derive(Clone)]
pub struct EvmInspector<Client, Chain> {
    client: Client,
    _chain: std::marker::PhantomData<Chain>,
}

impl<Client, Chain> NetworkFingerprintInspector for EvmInspector<Client, Chain>
where
    Client: ClientT + Send + Sync,
    Chain: Send + Sync,
{
    async fn network_fingerprint(&self) -> Result<NetworkFingerprint, ForeignChainInspectionError> {
        let chain_id: ChainIdResponse = self
            .client
            .request(CHAIN_ID_METHOD, NO_PARAMS)
            .await
            .classified()?;
        Ok(NetworkFingerprint::new(chain_id.canonical_text()))
    }

    fn canonical_fingerprint(fingerprint: &str) -> NetworkFingerprint {
        NetworkFingerprint::new(ChainIdResponse(fingerprint.to_owned()).canonical_text())
    }
}

impl<Client, Chain> ForeignChainInspector for EvmInspector<Client, Chain>
where
    Client: ClientT + Send + Sync,
    Chain: EvmChain + Send + Sync,
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
    ) -> Result<Verdict<EvmExtractedValue<Chain>>, ForeignChainInspectionError> {
        let get_transaction_receipt_args = GetTransactionReceiptARgs {
            transaction_hash: H256(transaction.into()),
        };
        let transaction_receipt: Option<GetTransactionReceiptResponse> = self
            .client
            .request(
                GET_TRANSACTION_RECEIPT_METHOD,
                &get_transaction_receipt_args,
            )
            .await
            .classified()?;
        let Some(transaction_receipt) = transaction_receipt else {
            return Ok(Verdict::TransactionNotFound);
        };

        // Defensive: `eth_getTransactionReceipt` looks the receipt up *by hash*, so a
        // well-behaved backend always echoes back the hash we queried.
        if transaction_receipt.transaction_hash != get_transaction_receipt_args.transaction_hash {
            return Err(ForeignChainInspectionError::InconsistentRpcResponse {
                requested_hash: get_transaction_receipt_args.transaction_hash.into(),
                returned_hash: transaction_receipt.transaction_hash.into(),
            });
        }

        self.verify_finality_level(transaction_receipt.block_number, finality)
            .await?;

        let canonical = self
            .canonical_block_at(transaction_receipt.block_number)
            .await?;
        if canonical.number != transaction_receipt.block_number {
            return Err(ForeignChainInspectionError::MalformedRpcResponse(format!(
                "the canonical block lookup at height {} answered with the block at height {}",
                transaction_receipt.block_number, canonical.number,
            )));
        }
        if canonical.hash != transaction_receipt.block_hash {
            return Ok(Verdict::NonCanonicalBlock {
                block_number: transaction_receipt.block_number.as_u64(),
                receipt_hash: transaction_receipt.block_hash.into(),
                canonical_hash: canonical.hash.into(),
            });
        }

        let transaction_success = transaction_receipt.status == U64::one();

        if !transaction_success {
            return Ok(Verdict::TransactionFailed);
        }

        let mut extracted_values = Vec::with_capacity(extractors.len());
        for extractor in &extractors {
            let Some(value) = extractor.extract_value(&transaction_receipt)? else {
                return Ok(Verdict::LogIndexOutOfBounds);
            };
            extracted_values.push(value);
        }
        Ok(Verdict::Extracted(extracted_values))
    }
}

impl<Client, Chain> EvmInspector<Client, Chain>
where
    Client: ClientT + Send + Sync,
    Chain: EvmChain,
{
    pub fn new(client: Client) -> Self {
        Self {
            client,
            _chain: std::marker::PhantomData,
        }
    }

    /// Checks that the receipt's block has reached the requested finality level — i.e. that the
    /// head of the chain at `finality` is at or past `receipt_block_number`.
    async fn verify_finality_level(
        &self,
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
        let head: GetBlockByNumberResponse = self
            .client
            .request(GET_BLOCK_BY_NUMBER_METHOD, &args)
            .await
            .classified()?;

        if head.number < receipt_block_number {
            return Err(ForeignChainInspectionError::NotFinalized);
        }
        Ok(())
    }

    /// The canonical block at `block_number`. `eth_getBlockByNumber` only ever resolves to a
    /// canonical block, so a receipt whose block disagrees with it was indexed against a side
    /// block (stale tx index, partially applied reorg, divergent RPC backend, etc.). The caller
    /// checks the height first: an answer from a different height is the provider's own fault,
    /// not a statement about the chain.
    async fn canonical_block_at(
        &self,
        block_number: U64,
    ) -> Result<GetBlockByNumberResponse, ForeignChainInspectionError> {
        let args = GetBlockByNumberArgs::new(
            BlockNumberOrTag::Number(block_number),
            ReturnFullTransactionObjects::from(false),
        );
        self.client
            .request(GET_BLOCK_BY_NUMBER_METHOD, &args)
            .await
            .classified()
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
    ) -> Result<Option<EvmExtractedValue<Chain>>, ForeignChainInspectionError> {
        match self {
            EvmExtractor::BlockHash => Ok(Some(EvmExtractedValue::BlockHash(From::from(
                *rpc_response.block_hash.as_fixed_bytes(),
            )))),
            EvmExtractor::Log { log_index } => {
                let target_index = ethereum_types::U64::from(*log_index);
                let Some(log) = rpc_response
                    .logs
                    .iter()
                    .find(|log| log.log_index == target_index)
                    .cloned()
                else {
                    return Ok(None);
                };

                // The receipt's transaction hash has already been checked against the
                // requested one, so binding the log to the receipt transitively binds
                // it to the requested transaction.
                let log_bound_to_receipt = log.transaction_hash == rpc_response.transaction_hash
                    && log.block_hash == rpc_response.block_hash
                    && log.block_number == rpc_response.block_number;
                if !log_bound_to_receipt {
                    return Err(ForeignChainInspectionError::LogNotBoundToReceipt {
                        log_index: *log_index,
                        log_transaction_hash: log.transaction_hash.into(),
                        log_block_hash: log.block_hash.into(),
                        log_block_number: log.block_number.as_u64(),
                        receipt_transaction_hash: rpc_response.transaction_hash.into(),
                        receipt_block_hash: rpc_response.block_hash.into(),
                        receipt_block_number: rpc_response.block_number.as_u64(),
                    });
                }

                Ok(Some(EvmExtractedValue::Log(log)))
            }
        }
    }
}
