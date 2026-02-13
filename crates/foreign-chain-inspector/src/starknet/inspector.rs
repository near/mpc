use jsonrpsee::core::client::ClientT;

use crate::starknet::{StarknetExtractedValue, StarknetTransactionHash};
use crate::{ForeignChainInspectionError, ForeignChainInspector};
use foreign_chain_rpc_interfaces::starknet::{
    GetTransactionReceiptArgs, GetTransactionReceiptResponse,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StarknetExtractor {
    BlockHash,
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
        let tx_hash_hex = format!("0x{}", hex::encode(*transaction));

        let request_parameters = GetTransactionReceiptArgs {
            transaction_hash: tx_hash_hex,
        };

        let rpc_response: GetTransactionReceiptResponse = self
            .client
            .request(GET_TRANSACTION_RECEIPT_METHOD, &request_parameters)
            .await?;

        if rpc_response.execution_status != "SUCCEEDED" {
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

fn parse_finality_status(status: &str) -> Result<StarknetFinality, ForeignChainInspectionError> {
    match status {
        "ACCEPTED_ON_L2" => Ok(StarknetFinality::AcceptedOnL2),
        "ACCEPTED_ON_L1" => Ok(StarknetFinality::AcceptedOnL1),
        other => Err(ForeignChainInspectionError::ClientError(
            jsonrpsee::core::client::error::Error::Custom(format!(
                "unknown finality status: {other}"
            )),
        )),
    }
}

impl StarknetExtractor {
    fn extract_value(
        &self,
        rpc_response: &GetTransactionReceiptResponse,
    ) -> Result<StarknetExtractedValue, ForeignChainInspectionError> {
        match self {
            StarknetExtractor::BlockHash => {
                let bytes = parse_felt_hex(&rpc_response.block_hash)?;
                Ok(StarknetExtractedValue::BlockHash(bytes.into()))
            }
        }
    }
}

/// Parse a 0x-prefixed variable-length hex string into a 32-byte array.
/// Starknet field elements (felts) are 252-bit values, so the hex
/// representation may have fewer than 64 hex characters. We left-pad
/// with zeros to fill the 32-byte array.
pub fn parse_felt_hex(hex_str: &str) -> Result<[u8; 32], ForeignChainInspectionError> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if stripped.len() > 64 {
        return Err(ForeignChainInspectionError::ClientError(
            jsonrpsee::core::client::error::Error::Custom(format!(
                "felt hex string too long: {hex_str}"
            )),
        ));
    }
    let padded = format!("{:0>64}", stripped);
    let bytes = hex::decode(&padded).map_err(|e| {
        ForeignChainInspectionError::ClientError(jsonrpsee::core::client::error::Error::Custom(
            format!("invalid hex in felt: {e}"),
        ))
    })?;
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}
