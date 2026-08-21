use crate::to_rpc_params_impl;

use base64::Engine as _;
use jsonrpsee::core::traits::ToRpcParams;
use serde::{Deserialize, Serialize};

/// Commitment level accepted by SVM JSON-RPC query methods.
///
/// `processed` is deliberately absent: `getTransaction` does not serve it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Commitment {
    Confirmed,
    Finalized,
}

/// Partial RPC response for `getTransaction` with `encoding: "json"`.
/// <https://solana.com/docs/rpc/http/gettransaction>
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTransactionResponse {
    pub slot: u64,
    pub transaction: TransactionJson,
    /// [`None`] when the node has no status metadata for the transaction.
    pub meta: Option<TransactionMeta>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionJson {
    /// Base58-encoded signatures; the first one is the transaction id.
    pub signatures: Vec<String>,
    pub message: TransactionMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionMessage {
    pub account_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionMeta {
    /// [`Null`](serde_json::Value::Null) iff the transaction succeeded. Deliberately not
    /// an [`Option`]: serde maps an *absent* field to [`None`], which would read a provider
    /// that omits the field as reporting success.
    pub err: serde_json::Value,
    /// [`None`] when inner instruction recording was disabled on the serving node.
    #[serde(default)]
    pub inner_instructions: Option<Vec<InnerInstructionsEntry>>,
    /// Addresses loaded from lookup tables (v0 transactions); absent for legacy ones.
    #[serde(default)]
    pub loaded_addresses: Option<LoadedAddresses>,
}

/// Inner instructions produced by one top-level instruction, flattened in CPI order.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InnerInstructionsEntry {
    /// Index of the top-level instruction these inner instructions originate from.
    pub index: u8,
    pub instructions: Vec<CompiledInstruction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompiledInstruction {
    /// Index into the transaction's full account list (static keys, then loaded
    /// addresses). `u8` mirrors the wire format: a wider type would let a provider
    /// inflate one response ~16x in memory once indices resolve to 32-byte pubkeys.
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    /// Base58-encoded instruction data.
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadedAddresses {
    pub writable: Vec<String>,
    pub readonly: Vec<String>,
}

/// Request args for `getTransaction`: `[signature, config]`.
pub struct GetTransactionArgs {
    pub signature: String,
    pub commitment: Commitment,
}

impl Serialize for GetTransactionArgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Config {
            commitment: Commitment,
            encoding: &'static str,
            max_supported_transaction_version: u8,
        }
        let config = Config {
            commitment: self.commitment,
            encoding: "json",
            max_supported_transaction_version: 0,
        };
        (&self.signature, config).serialize(serializer)
    }
}

impl ToRpcParams for &GetTransactionArgs {
    to_rpc_params_impl!();
}

/// Partial RPC response for `getAccountInfo`: the `RpcResponse` envelope with the
/// account under `value`. <https://solana.com/docs/rpc/http/getaccountinfo>
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAccountInfoResponse {
    pub context: ResponseContext,
    /// [`None`] when no account exists at the queried address. `deserialize_with`
    /// makes the field required: serde maps an *absent* field to [`None`], which would read a
    /// provider that omits the field as reporting an absent account.
    #[serde(deserialize_with = "Option::deserialize")]
    pub value: Option<AccountInfo>,
}

/// The slot an `RpcResponse` was served at. Required, so that a provider omitting it cannot
/// pass a freshness check a provider reporting a stale slot would fail.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseContext {
    pub slot: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub owner: String,
    pub data: AccountData,
}

/// Account data as served with `encoding: "base64"`: a `[data, encoding]` pair.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct AccountData(pub String, pub String);

impl AccountData {
    /// Decodes the payload, rejecting a provider that answered in an encoding other
    /// than the requested `base64`.
    pub fn decode(&self) -> Result<Vec<u8>, String> {
        let AccountData(payload, encoding) = self;
        if encoding != "base64" {
            // A bounded prefix only: the tag is provider-controlled and logged in full.
            let shown: String = encoding.chars().take(16).collect();
            let marker = if shown.len() < encoding.len() {
                "…"
            } else {
                ""
            };
            return Err(format!(
                "account data answered in encoding {shown:?}{marker}, expected \"base64\""
            ));
        }
        base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|e| format!("invalid base64 account data: {e}"))
    }
}

/// Request args for `getAccountInfo`: `[pubkey, config]`.
pub struct GetAccountInfoArgs {
    pub pubkey: String,
    pub commitment: Commitment,
}

impl Serialize for GetAccountInfoArgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Config {
            commitment: Commitment,
            encoding: &'static str,
        }
        let config = Config {
            commitment: self.commitment,
            encoding: "base64",
        };
        (&self.pubkey, config).serialize(serializer)
    }
}

impl ToRpcParams for &GetAccountInfoArgs {
    to_rpc_params_impl!();
}

/// Request args for `getSlot`: `[config]`. Answers the latest slot at the commitment.
pub struct GetSlotArgs {
    pub commitment: Commitment,
}

impl Serialize for GetSlotArgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Config {
            commitment: Commitment,
        }
        [Config {
            commitment: self.commitment,
        }]
        .serialize(serializer)
    }
}

impl ToRpcParams for &GetSlotArgs {
    to_rpc_params_impl!();
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn serialize_get_transaction_args__should_produce_signature_and_config_pair() {
        // Given
        let args = GetTransactionArgs {
            signature: "5j7s6NiJS3JAkvgkoc18WVAsiSaci2pxB2A6ueCJP4tprA2TFg9wSyTLeYouxPBJEMzJinENTkpA52YStRW5Dia7"
                .to_string(),
            commitment: Commitment::Confirmed,
        };

        // When
        let serialized = serde_json::to_value(&args).unwrap();

        // Then
        assert_eq!(
            serialized,
            serde_json::json!([
                "5j7s6NiJS3JAkvgkoc18WVAsiSaci2pxB2A6ueCJP4tprA2TFg9wSyTLeYouxPBJEMzJinENTkpA52YStRW5Dia7",
                {
                    "commitment": "confirmed",
                    "encoding": "json",
                    "maxSupportedTransactionVersion": 0,
                },
            ])
        );
    }

    #[test]
    fn serialize_get_account_info_args__should_produce_pubkey_and_config_pair() {
        // Given
        let args = GetAccountInfoArgs {
            pubkey: "vines1vzrYbzLMRdu58ou5XTby4qAqVRLmqo36NKPTg".to_string(),
            commitment: Commitment::Finalized,
        };

        // When
        let serialized = serde_json::to_value(&args).unwrap();

        // Then
        assert_eq!(
            serialized,
            serde_json::json!([
                "vines1vzrYbzLMRdu58ou5XTby4qAqVRLmqo36NKPTg",
                { "commitment": "finalized", "encoding": "base64" },
            ])
        );
    }

    #[test]
    fn serialize_get_slot_args__should_wrap_config_in_array() {
        // Given
        let args = GetSlotArgs {
            commitment: Commitment::Finalized,
        };

        // When
        let serialized = serde_json::to_value(&args).unwrap();

        // Then
        assert_eq!(
            serialized,
            serde_json::json!([{ "commitment": "finalized" }])
        );
    }

    #[test]
    fn deserialize_get_transaction_response__should_accept_versioned_transaction_fields() {
        // Given — the fields the inspector reads, as a mainnet node renders them.
        let json = serde_json::json!({
            "slot": 430,
            "blockTime": 1_700_000_000,
            "transaction": {
                "message": {
                    "accountKeys": [
                        "3z9vL1zjN6qyAFHhHQdWYRTFAcy69pJydkZmSFBKHg1R",
                        "11111111111111111111111111111111",
                    ],
                    "recentBlockhash": "9zb7PDoEQzHXYCCJVUhu1MHkroCMomj8ByfXY3ihm4kV",
                    "instructions": [],
                },
                "signatures": [
                    "5j7s6NiJS3JAkvgkoc18WVAsiSaci2pxB2A6ueCJP4tprA2TFg9wSyTLeYouxPBJEMzJinENTkpA52YStRW5Dia7",
                ],
            },
            "meta": {
                "err": null,
                "fee": 5000,
                "innerInstructions": [
                    {
                        "index": 1,
                        "instructions": [
                            { "programIdIndex": 1, "accounts": [0], "data": "3Bxs4NN8M2Yn4TLb", "stackHeight": 2 },
                        ],
                    },
                ],
                "loadedAddresses": { "writable": [], "readonly": [] },
            },
        });

        // When
        let response: GetTransactionResponse = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(response.slot, 430);
        let meta = response.meta.unwrap();
        assert!(meta.err.is_null());
        let inner = meta.inner_instructions.unwrap();
        assert_eq!(inner[0].index, 1);
        assert_eq!(inner[0].instructions[0].program_id_index, 1);
        assert_eq!(inner[0].instructions[0].accounts, vec![0]);
        assert_eq!(inner[0].instructions[0].data, "3Bxs4NN8M2Yn4TLb");
    }

    #[test]
    fn deserialize_get_transaction_response__should_accept_legacy_meta_without_optional_fields() {
        // Given — a legacy transaction: no loadedAddresses, null innerInstructions.
        let json = serde_json::json!({
            "slot": 1,
            "transaction": {
                "message": { "accountKeys": [] },
                "signatures": [],
            },
            "meta": { "err": { "InstructionError": [0, "Custom"] }, "innerInstructions": null },
        });

        // When
        let response: GetTransactionResponse = serde_json::from_value(json).unwrap();

        // Then
        let meta = response.meta.unwrap();
        assert!(!meta.err.is_null());
        assert_eq!(meta.inner_instructions, None);
        assert_eq!(meta.loaded_addresses, None);
    }

    #[test]
    fn deserialize_transaction_meta__should_reject_a_response_that_omits_err() {
        // Given — a provider that leaves the field out entirely. Were `err` an `Option`,
        // serde would map the absence to `None` and the transaction would read as
        // successful; the status of a transaction must never be inferred from silence.
        let json = serde_json::json!({ "innerInstructions": [] });

        // When
        let result = serde_json::from_value::<TransactionMeta>(json);

        // Then
        result.unwrap_err();
    }

    #[test]
    fn deserialize_transaction_meta__should_read_explicit_null_err_as_success() {
        // Given
        let json = serde_json::json!({ "err": null, "innerInstructions": [] });

        // When
        let meta: TransactionMeta = serde_json::from_value(json).unwrap();

        // Then
        assert!(meta.err.is_null());
    }

    #[rstest]
    #[case::base64("dGVzdCBkYXRh", "base64", Ok(b"test data".to_vec()))]
    #[case::wrong_encoding("dGVzdA==", "base58", Err(()))]
    #[case::invalid_payload("not!!base64", "base64", Err(()))]
    fn account_data_decode__should_only_accept_the_requested_base64_encoding(
        #[case] payload: &str,
        #[case] encoding: &str,
        #[case] expected: Result<Vec<u8>, ()>,
    ) {
        // Given
        let data = AccountData(payload.to_string(), encoding.to_string());

        // When
        let decoded = data.decode();

        // Then
        assert_eq!(decoded.map_err(|_| ()), expected);
    }
}
