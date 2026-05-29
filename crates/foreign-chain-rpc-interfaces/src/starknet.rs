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
    pub block_number: u64,
    pub events: Vec<StarknetEvent>,
    pub finality_status: StarknetFinalityStatus,
    pub execution_status: StarknetExecutionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StarknetEvent {
    #[serde(deserialize_with = "deserialize_starknet_felt_vec")]
    pub data: Vec<H256>,
    #[serde(deserialize_with = "deserialize_starknet_felt")]
    pub from_address: H256,
    #[serde(deserialize_with = "deserialize_starknet_felt_vec")]
    pub keys: Vec<H256>,
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

/// Block identifier accepted by Starknet block-lookup RPCs. The inspector's canonical-chain
/// check uses `Number`; add more variants only when a caller actually needs them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BlockId {
    Number { block_number: u64 },
}

/// Partial RPC response for `starknet_getBlockWithTxHashes`.
/// <https://www.alchemy.com/docs/chains/starknet/starknet-api-endpoints/starknet-get-block-with-tx-hashes>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GetBlockWithTxHashesResponse {
    #[serde(deserialize_with = "deserialize_starknet_felt")]
    pub block_hash: H256,
    pub block_number: u64,
}

/// Request args for `starknet_getBlockWithTxHashes`.
pub struct GetBlockWithTxHashesArgs {
    pub block_id: BlockId,
}

impl Serialize for GetBlockWithTxHashesArgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // `starknet_getBlockWithTxHashes` expects a single-element array: [block_id]
        let request_parameters = [&self.block_id];
        request_parameters.serialize(serializer)
    }
}

impl ToRpcParams for &GetBlockWithTxHashesArgs {
    to_rpc_params_impl!();
}

/// Starknet felt values use `0x`-prefixed hex like Ethereum, but may omit leading
/// zeros (e.g. `"0x5"` instead of `"0x0000…0005"`). This function zero-pads
/// short representations so they can be parsed as an [`H256`].
fn parse_felt(s: &str) -> Result<H256, String> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);

    if stripped.len() > 64 {
        return Err(format!("felt hex string too long: {s}"));
    }

    let padded = format!("0x{stripped:0>64}");
    padded.parse().map_err(|e| format!("{e}"))
}

fn deserialize_starknet_felt<'de, D>(deserializer: D) -> Result<H256, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_felt(&s).map_err(serde::de::Error::custom)
}

fn deserialize_starknet_felt_vec<'de, D>(deserializer: D) -> Result<Vec<H256>, D::Error>
where
    D: Deserializer<'de>,
{
    let strings: Vec<String> = Vec::deserialize(deserializer)?;
    strings
        .iter()
        .map(|s| parse_felt(s).map_err(serde::de::Error::custom))
        .collect()
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{
        BlockId, GetBlockWithTxHashesArgs, GetBlockWithTxHashesResponse,
        GetTransactionReceiptResponse, H256, StarknetExecutionStatus, StarknetFinalityStatus,
        parse_felt,
    };

    const TEST_BLOCK_NUMBER: u64 = 842_750;
    const TEST_RECEIPT_BLOCK_NUMBER: u64 = 6_195_041;
    const SHORT_HEX_BLOCK_HASH: &str = "0x5";

    fn short_hex_block_hash_as_h256() -> H256 {
        // `SHORT_HEX_BLOCK_HASH` zero-padded to a 32-byte hash.
        let mut bytes = [0u8; 32];
        bytes[31] = 5;
        H256::from(bytes)
    }

    #[test]
    fn deserialize_receipt__should_accept_short_hex_block_hash() {
        let json = serde_json::json!({
            "block_hash": SHORT_HEX_BLOCK_HASH,
            "block_number": TEST_RECEIPT_BLOCK_NUMBER,
            "events": [
              {
                "data": ["0x2b"],
                "from_address": "0x387b62e702a722396a056e60b6affecebaddc258170446b07d57e47c541a0dd",
                "keys": [
                  "0x2b0cdef3c28f9d954382f060df168ae56204d5937d2f0cd1fd9ce759afaf095",
                  "0x4322cec55a56b85793864e0cfd27a563849ac9209d4307621d65bcd616c1dd8",
                ],
              },
            ],
            "finality_status": "ACCEPTED_ON_L1",
            "execution_status": "SUCCEEDED",
        });

        let receipt: GetTransactionReceiptResponse = serde_json::from_value(json).unwrap();

        assert_eq!(receipt.block_hash, short_hex_block_hash_as_h256());
        assert_eq!(receipt.block_number, TEST_RECEIPT_BLOCK_NUMBER);
        assert_eq!(
            receipt.finality_status,
            StarknetFinalityStatus::AcceptedOnL1
        );
        assert_eq!(receipt.execution_status, StarknetExecutionStatus::Succeeded);

        assert_eq!(receipt.events.len(), 1);
        let event = &receipt.events[0];

        assert_eq!(event.data, vec![parse_felt("0x2b").unwrap()]);
        assert_eq!(
            event.from_address,
            parse_felt("0x387b62e702a722396a056e60b6affecebaddc258170446b07d57e47c541a0dd")
                .unwrap()
        );
        assert_eq!(
            event.keys,
            vec![
                parse_felt("0x2b0cdef3c28f9d954382f060df168ae56204d5937d2f0cd1fd9ce759afaf095")
                    .unwrap(),
                parse_felt("0x4322cec55a56b85793864e0cfd27a563849ac9209d4307621d65bcd616c1dd8")
                    .unwrap(),
            ]
        );
    }

    #[test]
    fn serialize_get_block_with_tx_hashes_args__should_wrap_block_id_in_array() {
        // given
        let args = GetBlockWithTxHashesArgs {
            block_id: BlockId::Number {
                block_number: TEST_BLOCK_NUMBER,
            },
        };

        // when
        let serialized = serde_json::to_value(&args).unwrap();

        // then
        assert_eq!(
            serialized,
            serde_json::json!([{ "block_number": TEST_BLOCK_NUMBER }])
        );
    }

    #[test]
    fn deserialize_get_block_with_tx_hashes_response__should_accept_short_hex_block_hash() {
        let json = serde_json::json!({
            "block_hash": SHORT_HEX_BLOCK_HASH,
            "block_number": TEST_BLOCK_NUMBER,
        });

        let response: GetBlockWithTxHashesResponse = serde_json::from_value(json).unwrap();

        assert_eq!(
            response,
            GetBlockWithTxHashesResponse {
                block_hash: short_hex_block_hash_as_h256(),
                block_number: TEST_BLOCK_NUMBER,
            }
        );
    }
}
