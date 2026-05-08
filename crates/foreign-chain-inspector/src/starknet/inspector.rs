use crate::starknet::{StarknetExtractedValue, StarknetTransactionHash};
use crate::{ForeignChainInspectionError, ForeignChainInspector, fan_out_and_match};
use foreign_chain_rpc_interfaces::starknet::{
    GetTransactionReceiptArgs, GetTransactionReceiptResponse, H256, StarknetExecutionStatus,
    StarknetFinalityStatus,
};
use jsonrpsee::core::client::ClientT;
use near_mpc_contract_interface::types::{StarknetFelt, StarknetLog};

const GET_TRANSACTION_RECEIPT_METHOD: &str = "starknet_getTransactionReceipt";

/// A Starknet inspector that fans every `extract` call out to **all** of its
/// configured clients in parallel. The call only succeeds if every client
/// produces the same extracted values.
pub struct StarknetInspector<Client> {
    clients: Vec<Client>,
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
        fan_out_and_match(
            self.clients.iter().map(|client| {
                extract_with_client(client, transaction, finality.clone(), &extractors)
            }),
        )
        .await
    }
}

impl<Client> StarknetInspector<Client>
where
    Client: ClientT + Send,
{
    pub fn new(clients: Vec<Client>) -> Self {
        Self { clients }
    }
}

async fn extract_with_client<Client: ClientT + Send>(
    client: &Client,
    transaction: StarknetTransactionHash,
    finality: StarknetFinality,
    extractors: &[StarknetExtractor],
) -> Result<Vec<StarknetExtractedValue>, ForeignChainInspectionError> {
    let request_parameters = GetTransactionReceiptArgs {
        transaction_hash: H256(transaction.into()),
    };

    let rpc_response: GetTransactionReceiptResponse = client
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

    extractors
        .iter()
        .map(|extractor| extractor.extract_value(&rpc_response))
        .collect()
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
