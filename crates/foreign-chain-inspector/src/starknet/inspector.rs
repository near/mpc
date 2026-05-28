use crate::starknet::{StarknetExtractedValue, StarknetTransactionHash};
use crate::{ForeignChainInspectionError, ForeignChainInspector};
use foreign_chain_rpc_interfaces::starknet::{
    BlockId, GetBlockWithTxHashesArgs, GetBlockWithTxHashesResponse, GetTransactionReceiptArgs,
    GetTransactionReceiptResponse, H256, StarknetExecutionStatus, StarknetFinalityStatus,
};
use jsonrpsee::core::client::ClientT;
use near_mpc_contract_interface::types::{StarknetFelt, StarknetLog};

const GET_TRANSACTION_RECEIPT_METHOD: &str = "starknet_getTransactionReceipt";
const GET_BLOCK_WITH_TX_HASHES_METHOD: &str = "starknet_getBlockWithTxHashes";

pub struct StarknetInspector<Client> {
    client: Client,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StarknetFinality {
    AcceptedOnL2,
    AcceptedOnL1,
}

impl<Client> ForeignChainInspector for StarknetInspector<Client>
where
    Client: ClientT + Send,
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
    ) -> Result<Vec<StarknetExtractedValue>, ForeignChainInspectionError> {
        let request_parameters = GetTransactionReceiptArgs {
            transaction_hash: H256(transaction.into()),
        };

        let rpc_response: GetTransactionReceiptResponse = self
            .client
            .request(GET_TRANSACTION_RECEIPT_METHOD, &request_parameters)
            .await?;

        if rpc_response.execution_status != StarknetExecutionStatus::Succeeded {
            return Err(ForeignChainInspectionError::TransactionFailed);
        }

        let actual_finality = parse_finality_status(&rpc_response.finality_status)?;

        let finality_sufficient = match finality {
            StarknetFinality::AcceptedOnL2 => true,
            StarknetFinality::AcceptedOnL1 => actual_finality == StarknetFinality::AcceptedOnL1,
        };

        if !finality_sufficient {
            return Err(ForeignChainInspectionError::NotFinalized);
        }

        self.verify_block_is_canonical(rpc_response.block_number, rpc_response.block_hash)
            .await?;

        let extracted_values = extractors
            .iter()
            .map(|extractor| extractor.extract_value(&rpc_response))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(extracted_values)
    }
}

impl<Client> StarknetInspector<Client>
where
    Client: ClientT + Send,
{
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Checks that the receipt's block is on the canonical chain by re-fetching the canonical
    /// block at `receipt_block_number` and comparing hashes. `starknet_getBlockWithTxHashes`
    /// only ever resolves to a canonical block, so a mismatch means the receipt was indexed
    /// against a side block (stale tx index, partially-applied reorg, divergent RPC backend,
    /// etc.).
    async fn verify_block_is_canonical(
        &self,
        receipt_block_number: u64,
        receipt_block_hash: H256,
    ) -> Result<(), ForeignChainInspectionError> {
        let args = GetBlockWithTxHashesArgs {
            block_id: BlockId::Number {
                block_number: receipt_block_number,
            },
        };
        let canonical: GetBlockWithTxHashesResponse = self
            .client
            .request(GET_BLOCK_WITH_TX_HASHES_METHOD, &args)
            .await?;

        if canonical.block_hash != receipt_block_hash {
            return Err(ForeignChainInspectionError::NonCanonicalBlock {
                block_number: receipt_block_number,
                receipt_hash: receipt_block_hash.as_bytes().to_vec().into(),
                canonical_hash: canonical.block_hash.as_bytes().to_vec().into(),
            });
        }
        Ok(())
    }
}

fn parse_finality_status(
    status: &StarknetFinalityStatus,
) -> Result<StarknetFinality, ForeignChainInspectionError> {
    match status {
        StarknetFinalityStatus::AcceptedOnL2 => Ok(StarknetFinality::AcceptedOnL2),
        StarknetFinalityStatus::AcceptedOnL1 => Ok(StarknetFinality::AcceptedOnL1),
        StarknetFinalityStatus::Received => Err(ForeignChainInspectionError::ClientError(
            jsonrpsee::core::client::error::Error::Custom(format!(
                "unsupported finality status: {status:?}"
            )),
        )),
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
    ) -> Result<StarknetExtractedValue, ForeignChainInspectionError> {
        match self {
            StarknetExtractor::BlockHash => Ok(StarknetExtractedValue::BlockHash(
                (*rpc_response.block_hash.as_fixed_bytes()).into(),
            )),
            StarknetExtractor::Log { log_index } => {
                let event = rpc_response
                    .events
                    .get(*log_index)
                    .ok_or(ForeignChainInspectionError::LogIndexOutOfBounds)?;
                Ok(StarknetExtractedValue::Log(StarknetLog {
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
