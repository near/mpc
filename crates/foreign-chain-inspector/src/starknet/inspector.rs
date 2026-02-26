use jsonrpsee::core::client::ClientT;
use contract_interface::types::{StarknetFelt, StarknetLog};
use crate::starknet::{StarknetExtractedValue, StarknetTransactionHash};
use crate::{ForeignChainInspectionError, ForeignChainInspector};
use foreign_chain_rpc_interfaces::starknet::{
    GetTransactionReceiptArgs, GetTransactionReceiptResponse, H256, StarknetExecutionStatus,
    StarknetFinalityStatus,
};

const GET_TRANSACTION_RECEIPT_METHOD: &str = "starknet_getTransactionReceipt";

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
    Log { log_index: u64 },
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
                let event =
                    rpc_response
                        .events
                        .get(*log_index as usize)
                        .ok_or_else(|| {
                            ForeignChainInspectionError::ClientError(
                                jsonrpsee::core::client::error::Error::Custom(format!(
                                    "log index {log_index} out of bounds, receipt has {} events",
                                    rpc_response.events.len()
                                )),
                            )
                        })?;
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
