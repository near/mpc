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
use near_mpc_contract_interface::types::{StarknetFelt, StarknetLog};

const GET_TRANSACTION_RECEIPT_METHOD: &str = "starknet_getTransactionReceipt";
const GET_BLOCK_WITH_TX_HASHES_METHOD: &str = "starknet_getBlockWithTxHashes";
const CHAIN_ID_METHOD: &str = "starknet_chainId";

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

        let rpc_response: GetTransactionReceiptResponse = self
            .client
            .request(GET_TRANSACTION_RECEIPT_METHOD, &request_parameters)
            .await
            .classified()?;

        let actual_finality = parse_finality_status(&rpc_response.finality_status)?;

        let finality_sufficient = match finality {
            StarknetFinality::AcceptedOnL2 => true,
            StarknetFinality::AcceptedOnL1 => actual_finality == StarknetFinality::AcceptedOnL1,
        };

        if !finality_sufficient {
            return Err(ForeignChainInspectionError::NotFinalized);
        }

        if let Some(non_canonical) = self
            .non_canonical_block_verdict(rpc_response.block_number, rpc_response.block_hash)
            .await?
        {
            return Ok(non_canonical);
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

    /// Checks that the receipt's block is on the canonical chain by re-fetching the canonical
    /// block at `receipt_block_number` and comparing hashes, returning the
    /// [`Verdict::NonCanonicalBlock`] verdict on a mismatch and [`None`] when the block is
    /// canonical. `starknet_getBlockWithTxHashes` only ever resolves to a canonical block, so a
    /// mismatch means the receipt was indexed against a side block (stale tx index,
    /// partially-applied reorg, divergent RPC backend, etc.).
    ///
    /// The canonical block's height is also asserted against the requested one — a divergent
    /// RPC that returns a hash from a different height would otherwise sneak past a
    /// hash-only check.
    async fn non_canonical_block_verdict(
        &self,
        receipt_block_number: u64,
        receipt_block_hash: H256,
    ) -> Result<Option<Verdict<StarknetExtractedValue>>, ForeignChainInspectionError> {
        let args = GetBlockWithTxHashesArgs {
            block_id: BlockId::Number {
                block_number: receipt_block_number,
            },
        };
        let canonical: GetBlockWithTxHashesResponse = self
            .client
            .request(GET_BLOCK_WITH_TX_HASHES_METHOD, &args)
            .await
            .classified()?;

        let hash_matches = canonical.block_hash == receipt_block_hash;
        let height_matches = canonical.block_number == receipt_block_number;
        if !hash_matches || !height_matches {
            return Ok(Some(Verdict::NonCanonicalBlock {
                block_number: receipt_block_number,
                receipt_hash: receipt_block_hash.into(),
                canonical_hash: canonical.block_hash.into(),
            }));
        }
        Ok(None)
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
    /// The extracted value, or [`None`] when the receipt has no event at the requested index —
    /// a [`Verdict::LogIndexOutOfBounds`] verdict, which is the caller's to return.
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
