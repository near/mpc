use crate::to_rpc_params_impl;

pub use ethereum_types::H256;
use jsonrpsee::core::traits::ToRpcParams;
use serde::{Deserialize, Deserializer, Serialize};

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
/// <https://www.alchemy.com/docs/chains/starknet/starknet-api-endpoints/starknet-get-transaction-receipt>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GetTransactionReceiptResponse {
    #[serde(deserialize_with = "deserialize_starknet_felt")]
    pub block_hash: H256,
    pub finality_status: StarknetFinalityStatus,
    pub execution_status: StarknetExecutionStatus,
}

/// Request args for `starknet_getTransactionReceipt`.
pub struct GetTransactionReceiptArgs {
    pub transaction_hash: H256,
}

impl Serialize for GetTransactionReceiptArgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // `starknet_getTransactionReceipt` expects a single-element array: [transaction_hash]
        let request_parameters = [self.transaction_hash];
        request_parameters.serialize(serializer)
    }
}

impl ToRpcParams for &GetTransactionReceiptArgs {
    to_rpc_params_impl!();
}

/// Starknet felt values use `0x`-prefixed hex like Ethereum, but may omit leading
/// zeros (e.g. `"0x5"` instead of `"0x0000…0005"`). This function zero-pads
/// short representations so they can be parsed as an [`H256`].
fn deserialize_starknet_felt<'de, D>(deserializer: D) -> Result<H256, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let stripped = s.strip_prefix("0x").unwrap_or(&s);

    if stripped.len() > 64 {
        return Err(serde::de::Error::custom(format!(
            "felt hex string too long: {s}"
        )));
    }

    let padded = format!("0x{stripped:0>64}");
    padded.parse().map_err(serde::de::Error::custom)
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::{
        GetTransactionReceiptResponse, H256, StarknetExecutionStatus, StarknetFinalityStatus,
    };

    #[test]
    fn deserialize_receipt__should_accept_short_hex_block_hash() {
        let json = r#"
        {
            "block_hash": "0x5",
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
        let expected_hash = H256::from(expected_bytes);
        assert_eq!(receipt.block_hash, expected_hash);
        assert_eq!(
            receipt.finality_status,
            StarknetFinalityStatus::AcceptedOnL1
        );
        assert_eq!(receipt.execution_status, StarknetExecutionStatus::Succeeded);
    }
}
