use crate::to_rpc_params_impl;

use jsonrpsee::core::traits::ToRpcParams;
use mpc_primitives::hash::Hash32;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StarknetBlockHashMarker;
pub type TransportStarknetBlockHash = Hash32<StarknetBlockHashMarker>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StarknetFinalityStatus {
    Received,
    AcceptedOnL2,
    AcceptedOnL1,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StarknetExecutionStatus {
    Succeeded,
    Reverted,
    Rejected,
}

/// Partial RPC response for `starknet_getTransactionReceipt`.
/// https://www.alchemy.com/docs/chains/starknet/starknet-api-endpoints/starknet-get-transaction-receipt
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GetTransactionReceiptResponse {
    #[serde(
        deserialize_with = "deserialize_starknet_felt_hash",
        serialize_with = "serialize_starknet_felt_hash"
    )]
    pub block_hash: TransportStarknetBlockHash,
    pub finality_status: StarknetFinalityStatus,
    pub execution_status: StarknetExecutionStatus,
}

/// Request args for `starknet_getTransactionReceipt`.
pub struct GetTransactionReceiptArgs {
    pub transaction_hash: String,
}

impl Serialize for GetTransactionReceiptArgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // `starknet_getTransactionReceipt` expects a single-element array: [transaction_hash]
        let request_parameters = [&self.transaction_hash];
        request_parameters.serialize(serializer)
    }
}

impl ToRpcParams for &GetTransactionReceiptArgs {
    to_rpc_params_impl!();
}

fn deserialize_starknet_felt_hash<'de, D>(
    deserializer: D,
) -> Result<TransportStarknetBlockHash, D::Error>
where
    D: Deserializer<'de>,
{
    let hash = String::deserialize(deserializer)?;
    let stripped = hash.strip_prefix("0x").unwrap_or(&hash);

    if stripped.len() > 64 {
        return Err(serde::de::Error::custom(format!(
            "felt hex string too long: {hash}"
        )));
    }

    let padded = format!("{stripped:0>64}");
    padded.parse().map_err(|error| {
        serde::de::Error::custom(format!("invalid starknet felt hash {hash}: {error}"))
    })
}

fn serialize_starknet_felt_hash<S>(
    hash: &TransportStarknetBlockHash,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hash.as_hex_with_prefix("0x"))
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::{
        GetTransactionReceiptResponse, StarknetExecutionStatus, StarknetFinalityStatus,
        TransportStarknetBlockHash,
    };

    #[test]
    fn deserialize_receipt__should_accept_short_hex_block_hash() {
        let json = r#"
        {
            "block_hash": "0x05",
            "finality_status": "ACCEPTED_ON_L1",
            "execution_status": "SUCCEEDED"
        }
        "#;

        let receipt: GetTransactionReceiptResponse = serde_json::from_str(json).unwrap();

        let expected_bytes = {
            let mut bytes = [0u8; 32];
            bytes[31] = 5;
            bytes
        };
        let expected_hash = TransportStarknetBlockHash::from(expected_bytes);
        assert_eq!(receipt.block_hash, expected_hash);
        assert_eq!(
            receipt.finality_status,
            StarknetFinalityStatus::AcceptedOnL1
        );
        assert_eq!(receipt.execution_status, StarknetExecutionStatus::Succeeded);
    }
}
