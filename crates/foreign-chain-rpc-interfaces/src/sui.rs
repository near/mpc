use crate::to_rpc_params_impl;

use jsonrpsee::core::traits::ToRpcParams;
use serde::{Deserialize, Serialize};

/// Request args for `sui_getTransactionBlock`.
pub struct GetTransactionBlockArgs {
    /// Base58-encoded 32-byte transaction digest.
    pub digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransactionBlockResponseOptions {
    show_effects: bool,
    show_events: bool,
}

impl Serialize for GetTransactionBlockArgs {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // `sui_getTransactionBlock` expects [digest, options]. Effects and events are the
        // only response sections the inspector verifies; requesting nothing else keeps the
        // cross-provider divergence surface minimal.
        let options = TransactionBlockResponseOptions {
            show_effects: true,
            show_events: true,
        };
        (&self.digest, options).serialize(serializer)
    }
}

impl ToRpcParams for &GetTransactionBlockArgs {
    to_rpc_params_impl!();
}

/// Partial RPC response for `sui_getTransactionBlock`, limited to the fields the
/// inspector verifies so that envelope additions by providers keep deserializing.
/// <https://docs.sui.io/sui-api-ref#sui_gettransactionblock>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionBlockResponse {
    /// Base58-encoded digest of the transaction, echoing the query key.
    pub digest: String,
    /// Present when requested via `showEffects`; carries the execution status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effects: Option<TransactionBlockEffects>,
    /// Events in `eventSeq` order; empty when the transaction emitted none or failed.
    #[serde(default)]
    pub events: Vec<SuiEventResponse>,
    /// Sequence number (decimal string) of the checkpoint that includes the transaction.
    /// Omitted until the transaction is included in a certified checkpoint, so its
    /// presence is the finality signal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionBlockEffects {
    pub status: ExecutionStatus,
}

/// `{"status":"success"}` or `{"status":"failure","error":"…"}`. The `error` prose is
/// node-generated (not certified data), so only `status` is modelled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionStatus {
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuiEventResponse {
    pub id: SuiEventId,
    pub package_id: String,
    pub transaction_module: String,
    pub sender: String,
    #[serde(rename = "type")]
    pub event_type: String,
    /// BCS-serialized event contents, encoded per `bcs_encoding`.
    pub bcs: String,
    /// `"base64"` on current nodes; pre-1.26 nodes emitted base58 without this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bcs_encoding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SuiEventId {
    pub tx_digest: String,
    /// Zero-based index (decimal string) of the event within the transaction.
    pub event_seq: String,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn serialize_get_transaction_block_args__should_emit_digest_and_options() {
        // Given
        let args = GetTransactionBlockArgs {
            digest: "88XKXHJRmGzkfwJa8PhoeDkqt4kxz8AEsB1UTzAbtd3z".to_string(),
        };

        // When
        let serialized = serde_json::to_value(&args).unwrap();

        // Then
        assert_eq!(
            serialized,
            serde_json::json!([
                "88XKXHJRmGzkfwJa8PhoeDkqt4kxz8AEsB1UTzAbtd3z",
                { "showEffects": true, "showEvents": true }
            ])
        );
    }

    #[test]
    fn deserialize_transaction_block__should_parse_checkpointed_transaction_with_event() {
        // Given — a mainnet fullnode response (non-verified fields trimmed for brevity;
        // `timestampMs` kept to show extra fields are tolerated).
        let json = serde_json::json!({
            "digest": "88XKXHJRmGzkfwJa8PhoeDkqt4kxz8AEsB1UTzAbtd3z",
            "effects": {
                "messageVersion": "v1",
                "status": { "status": "success" },
                "executedEpoch": "1182",
                "eventsDigest": "9R3ac9bP8QUDTjj5s6u1n9DsH6vMEFdwW1oSR9seSR1w"
            },
            "events": [
                {
                    "id": {
                        "txDigest": "88XKXHJRmGzkfwJa8PhoeDkqt4kxz8AEsB1UTzAbtd3z",
                        "eventSeq": "0"
                    },
                    "packageId": "0x55300367a2d40813727ccac4ecee977a39fb9cdb46f2e6b2c354b9798f5de2c0",
                    "transactionModule": "pyth",
                    "sender": "0x782439361331665cf8a79162fa3769d90338ece1ea9f7a78481c0afa7873aa3d",
                    "type": "0x55300367a2d40813727ccac4ecee977a39fb9cdb46f2e6b2c354b9798f5de2c0::event::PriceFeedUpdateEvent",
                    "parsedJson": { "timestamp": "1783511682" },
                    "bcsEncoding": "base64",
                    "bcs": "IOugcyOV+une"
                }
            ],
            "timestampMs": "1783511682250",
            "checkpoint": "296112296"
        });

        // When
        let tx: TransactionBlockResponse = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(tx.digest, "88XKXHJRmGzkfwJa8PhoeDkqt4kxz8AEsB1UTzAbtd3z");
        assert_eq!(tx.checkpoint.as_deref(), Some("296112296"));
        assert_eq!(tx.effects.unwrap().status.status, "success");
        assert_eq!(tx.events.len(), 1);
        let event = &tx.events[0];
        assert_eq!(event.id.event_seq, "0");
        assert_eq!(event.transaction_module, "pyth");
        assert_eq!(event.bcs_encoding.as_deref(), Some("base64"));
        assert_eq!(
            event.event_type,
            "0x55300367a2d40813727ccac4ecee977a39fb9cdb46f2e6b2c354b9798f5de2c0::event::PriceFeedUpdateEvent"
        );
    }

    #[test]
    fn deserialize_transaction_block__should_parse_failed_transaction() {
        // Given — a failed execution: `error` prose alongside the status is ignored.
        let json = serde_json::json!({
            "digest": "3MZKT3GiqcZJFtn18S1Qufd3jLZTmf5rBL2gCMofkVbn",
            "effects": {
                "status": {
                    "status": "failure",
                    "error": "MoveAbort(MoveLocation { … }, 3) in command 1"
                }
            },
            "events": [],
            "checkpoint": "296112100"
        });

        // When
        let tx: TransactionBlockResponse = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(tx.effects.unwrap().status.status, "failure");
        assert!(tx.events.is_empty());
    }

    #[test]
    fn deserialize_transaction_block__should_parse_uncheckpointed_transaction() {
        // Given — a locally-executed transaction not yet included in a checkpoint: the
        // `checkpoint` key is omitted entirely (never null).
        let json = serde_json::json!({
            "digest": "88XKXHJRmGzkfwJa8PhoeDkqt4kxz8AEsB1UTzAbtd3z",
            "effects": { "status": { "status": "success" } },
            "events": []
        });

        // When
        let tx: TransactionBlockResponse = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(tx.checkpoint, None);
    }

    #[test]
    fn deserialize_event__should_tolerate_missing_bcs_encoding() {
        // Given — the pre-1.26 event shape: base58 `bcs`, no `bcsEncoding` field.
        let json = serde_json::json!({
            "id": { "txDigest": "88XKXHJRmGzkfwJa8PhoeDkqt4kxz8AEsB1UTzAbtd3z", "eventSeq": "0" },
            "packageId": "0x0000000000000000000000000000000000000000000000000000000000000003",
            "transactionModule": "sui_system",
            "sender": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "type": "0x3::validator_set::ValidatorEpochInfoEventV2",
            "bcs": "3mJr7AoUXx2Wqd"
        });

        // When
        let event: SuiEventResponse = serde_json::from_value(json).unwrap();

        // Then
        assert_eq!(event.bcs_encoding, None);
        assert_eq!(event.bcs, "3mJr7AoUXx2Wqd");
    }
}
