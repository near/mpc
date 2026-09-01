use crate::starknet::{StarknetExtractedValue, StarknetTransactionHash};
use crate::{
    ClassifyRpcOutcome, ForeignChainInspectionError, ForeignChainInspector, NO_PARAMS,
    NetworkFingerprint, NetworkFingerprintInspector, Verdict,
};
use foreign_chain_rpc_interfaces::starknet::{
    BlockId, ChainIdResponse, GetBlockWithTxHashesArgs, GetBlockWithTxHashesResponse,
    GetTransactionReceiptArgs, GetTransactionReceiptResponse, H256, StarknetExecutionStatus,
    StarknetFinalityStatus,
};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::client::error::Error as RpcClientError;
use near_mpc_contract_interface::types::{StarknetFelt, StarknetLog};

const GET_TRANSACTION_RECEIPT_METHOD: &str = "starknet_getTransactionReceipt";
const GET_BLOCK_WITH_TX_HASHES_METHOD: &str = "starknet_getBlockWithTxHashes";
const CHAIN_ID_METHOD: &str = "starknet_chainId";

/// `TXN_HASH_NOT_FOUND` in the Starknet API spec
const TRANSACTION_HASH_NOT_FOUND_CODE: i32 = 29;

#[derive(Clone)]
pub struct StarknetInspector<Client> {
    client: Client,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StarknetFinality {
    AcceptedOnL2,
    AcceptedOnL1,
}

impl<Client> NetworkFingerprintInspector for StarknetInspector<Client>
where
    Client: ClientT + Send + Sync,
{
    async fn network_fingerprint(&self) -> Result<NetworkFingerprint, ForeignChainInspectionError> {
        let chain_id: ChainIdResponse = self
            .client
            .request(CHAIN_ID_METHOD, NO_PARAMS)
            .await
            .classified()?;
        Ok(Self::canonical_fingerprint(&chain_id.0))
    }

    fn canonical_fingerprint(fingerprint: &str) -> NetworkFingerprint {
        NetworkFingerprint::new(ChainIdResponse(fingerprint.to_owned()).canonical_text())
    }
}

impl<Client> ForeignChainInspector for StarknetInspector<Client>
where
    Client: ClientT + Send + Sync,
{
    type TransactionId = StarknetTransactionHash;
    type Finality = StarknetFinality;
    type Extractor = StarknetExtractor;
    type ExtractedValue = StarknetExtractedValue;

    async fn extract(
        &self,
        transaction: StarknetTransactionHash,
        finality: StarknetFinality,
        extractors: Vec<StarknetExtractor>,
    ) -> Result<Verdict<StarknetExtractedValue>, ForeignChainInspectionError> {
        let request_parameters = GetTransactionReceiptArgs {
            transaction_hash: H256(transaction.into()),
        };

        let rpc_response: GetTransactionReceiptResponse = match self
            .client
            .request(GET_TRANSACTION_RECEIPT_METHOD, &request_parameters)
            .await
        {
            Err(RpcClientError::Call(object))
                if object.code() == TRANSACTION_HASH_NOT_FOUND_CODE =>
            {
                return Ok(Verdict::TransactionNotFound);
            }
            other => other.classified()?,
        };

        let actual_finality = parse_finality_status(&rpc_response.finality_status)?;

        let finality_sufficient = match finality {
            StarknetFinality::AcceptedOnL2 => true,
            StarknetFinality::AcceptedOnL1 => actual_finality == StarknetFinality::AcceptedOnL1,
        };

        if !finality_sufficient {
            return Err(ForeignChainInspectionError::NotFinalized);
        }

        let canonical = self.canonical_block_at(rpc_response.block_number).await?;
        if canonical.block_number != rpc_response.block_number {
            return Err(ForeignChainInspectionError::MalformedRpcResponse(format!(
                "the canonical block lookup at height {} answered with the block at height {}",
                rpc_response.block_number, canonical.block_number,
            )));
        }
        if canonical.block_hash != rpc_response.block_hash {
            return Ok(Verdict::NonCanonicalBlock {
                block_number: rpc_response.block_number,
                receipt_hash: rpc_response.block_hash.into(),
                canonical_hash: canonical.block_hash.into(),
            });
        }

        if rpc_response.execution_status != StarknetExecutionStatus::Succeeded {
            return Ok(Verdict::TransactionFailed);
        }

        let mut extracted_values = Vec::with_capacity(extractors.len());
        for extractor in &extractors {
            let Some(value) = extractor.extract_value(&rpc_response) else {
                return Ok(Verdict::LogIndexOutOfBounds);
            };
            extracted_values.push(value);
        }
        Ok(Verdict::Extracted(extracted_values))
    }
}

impl<Client> StarknetInspector<Client>
where
    Client: ClientT + Send + Sync,
{
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// The canonical block at `block_number`. `starknet_getBlockWithTxHashes` only ever
    /// resolves to a canonical block, so a receipt whose block disagrees with it was indexed
    /// against a side block (stale tx index, partially applied reorg, divergent RPC backend,
    /// etc.). The caller checks the height first: an answer from a different height is the
    /// provider's own fault, not a statement about the chain.
    async fn canonical_block_at(
        &self,
        block_number: u64,
    ) -> Result<GetBlockWithTxHashesResponse, ForeignChainInspectionError> {
        let args = GetBlockWithTxHashesArgs {
            block_id: BlockId::Number { block_number },
        };
        self.client
            .request(GET_BLOCK_WITH_TX_HASHES_METHOD, &args)
            .await
            .classified()
    }
}

fn parse_finality_status(
    status: &StarknetFinalityStatus,
) -> Result<StarknetFinality, ForeignChainInspectionError> {
    match status {
        StarknetFinalityStatus::AcceptedOnL2 => Ok(StarknetFinality::AcceptedOnL2),
        StarknetFinalityStatus::AcceptedOnL1 => Ok(StarknetFinality::AcceptedOnL1),
        StarknetFinalityStatus::Received => Err(ForeignChainInspectionError::NotFinalized),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StarknetExtractor {
    BlockHash,
    Log { log_index: usize },
}

impl StarknetExtractor {
    fn extract_value(
        &self,
        rpc_response: &GetTransactionReceiptResponse,
    ) -> Option<StarknetExtractedValue> {
        match self {
            StarknetExtractor::BlockHash => Some(StarknetExtractedValue::BlockHash(
                (*rpc_response.block_hash.as_fixed_bytes()).into(),
            )),
            StarknetExtractor::Log { log_index } => {
                let event = rpc_response.events.get(*log_index)?;
                Some(StarknetExtractedValue::Log(StarknetLog {
                    block_hash: StarknetFelt(*rpc_response.block_hash.as_fixed_bytes()),
                    block_number: rpc_response.block_number,
                    data: event
                        .data
                        .iter()
                        .map(|h| StarknetFelt(*h.as_fixed_bytes()))
                        .collect(),
                    from_address: StarknetFelt(*event.from_address.as_fixed_bytes()),
                    keys: event
                        .keys
                        .iter()
                        .map(|h| StarknetFelt(*h.as_fixed_bytes()))
                        .collect(),
                }))
            }
        }
    }
}
