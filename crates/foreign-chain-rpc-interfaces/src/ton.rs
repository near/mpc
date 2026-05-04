use serde::{Deserialize, Serialize};
use tonlib_core::types::TonAddress;

// `#[serde(default)]` policy for this module:
//
// All optional fields use `#[serde(default)]` so the deserializer returns a
// type-default (empty `Vec`, `false`, `None`) when a field is absent in the
// JSON. This is necessary because `serde_json` errors on missing fields by
// default — even for `Option<T>` — and toncenter v3 omits irrelevant fields
// (e.g. `compute_ph` on tick/tock transactions) instead of emitting `null`.

/// Top-level response from `GET /api/v3/transactions?...`. The `transactions`
/// array is always present; an empty array means no transaction matched the
/// lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetTransactionsResponse {
    #[serde(default)]
    pub transactions: Vec<TonTransaction>,
}

/// A single TON transaction record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TonTransaction {
    /// Account that produced this transaction. `tonlib_core::TonAddress`
    /// accepts the raw `<workchain>:<hex>` form via its `FromStr` impl.
    pub account: TonAddress,

    /// Transaction hash, base64-encoded (44 chars including `=` padding; may
    /// contain `+` and `/`).
    pub hash: String,

    /// Masterchain block seqno that references this transaction's shard block.
    ///
    /// * `Some(_)` — the shard block has been referenced by a masterchain block;
    ///   per TON consensus, masterchain inclusion is irreversible and the
    ///   transaction is final.
    /// * `None` — the transaction is not yet masterchain-included. The MPC
    ///   inspector rejects such transactions with `NotFinalized`.
    ///
    /// `0` is a valid genesis seqno and must be treated as finalized — check
    /// `.is_some()`, not `> 0`.
    #[serde(default)]
    pub mc_block_seqno: Option<u64>,

    /// Execution outcome summary.
    pub description: TonTransactionDescription,

    /// Outgoing messages produced by this transaction, in TVM emission order.
    /// The MPC inspector filters these to keep only ext-out messages.
    #[serde(default)]
    pub out_msgs: Vec<TonMessage>,
}

/// Subset of the transaction description object.
///
/// Only `aborted`, `destroyed`, and the optional `compute_ph` are parsed; the
/// rest of the description (storage phase, action phase, etc.) is ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TonTransactionDescription {
    #[serde(default)]
    pub aborted: bool,

    #[serde(default)]
    pub destroyed: bool,

    /// Compute-phase summary. Absent on tick/tock/storage-only transactions.
    #[serde(default)]
    pub compute_ph: Option<TonComputePhase>,
}

/// Compute-phase summary.
///
/// The compute phase has two on-wire shapes: a "skipped" shape (no `success`
/// field) and a "normal" shape with `success: bool`. Modelling `success` as
/// `Option<bool>` captures both: `None` on skipped, `Some(true|false)` on
/// normal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TonComputePhase {
    #[serde(default)]
    pub success: Option<bool>,
}

/// An outgoing (or incoming) message record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TonMessage {
    /// Source account. `None` for ext-in messages (external to the chain).
    #[serde(default)]
    pub source: Option<TonAddress>,

    /// Destination account. `None` for ext-out messages (destination =
    /// `addr_none`, meaning external to the chain). This is the primary
    /// discriminator for ext-out filtering.
    #[serde(default)]
    pub destination: Option<TonAddress>,

    /// Logical time at which the TVM created this message. Within a single
    /// transaction, every emitted message has a distinct, monotonically
    /// increasing `created_lt` — this is a TON protocol invariant
    /// (`SENDRAWMSG` snapshots and bumps the lt counter). The MPC inspector
    /// parses this and uses it to sort ext-out messages so that ext-out
    /// indexing is independent of the upstream serialization order.
    ///
    /// Wire format: JSON string (the underlying TON type is a 64-bit unsigned
    /// integer that doesn't always fit safely into a JSON number). The
    /// inspector rejects the request if any ext-out message is missing or has
    /// an unparseable `created_lt`.
    #[serde(default)]
    pub created_lt: Option<String>,

    /// Serialized body cell. Absent on messages with empty bodies.
    #[serde(default)]
    pub message_content: Option<TonCellBoc>,
}

/// A TON cell serialized as a Bag-of-Cells.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TonCellBoc {
    /// Base64-encoded BoC bytes.
    pub body: String,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn deserialize__should_accept_minimal_tx_with_no_out_msgs() {
        let json = r#"
        {
          "account": "0:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
          "hash": "0000000000000000000000000000000000000000000000000000000000000001",
          "mc_block_seqno": 12345,
          "description": {
            "aborted": false,
            "destroyed": false,
            "compute_ph": { "success": true }
          },
          "out_msgs": []
        }
        "#;

        let tx: TonTransaction = serde_json::from_str(json).unwrap();
        assert_eq!(tx.mc_block_seqno, Some(12345));
        assert!(!tx.description.aborted);
        assert_eq!(
            tx.description.compute_ph.as_ref().and_then(|c| c.success),
            Some(true)
        );
        assert!(tx.out_msgs.is_empty());
    }

    // 64-char hex tail — TonAddress::from_hex_str expects exactly 32 bytes.
    const ADDR_AA: &str = "0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ADDR_BB: &str = "0:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn deserialize__should_treat_missing_mc_block_seqno_as_none() {
        let json = format!(
            r#"
        {{
          "account": "{ADDR_AA}",
          "hash": "00",
          "description": {{}},
          "out_msgs": []
        }}
        "#
        );

        let tx: TonTransaction = serde_json::from_str(&json).unwrap();
        assert_eq!(tx.mc_block_seqno, None);
    }

    #[test]
    fn deserialize__should_treat_null_mc_block_seqno_as_none() {
        let json = format!(
            r#"
        {{
          "account": "{ADDR_AA}",
          "hash": "00",
          "mc_block_seqno": null,
          "description": {{}},
          "out_msgs": []
        }}
        "#
        );

        let tx: TonTransaction = serde_json::from_str(&json).unwrap();
        assert_eq!(tx.mc_block_seqno, None);
    }

    #[test]
    fn deserialize__should_accept_skipped_compute_phase() {
        let json = format!(
            r#"
        {{
          "account": "{ADDR_AA}",
          "hash": "00",
          "mc_block_seqno": 1,
          "description": {{
            "aborted": false,
            "destroyed": false,
            "compute_ph": {{}}
          }},
          "out_msgs": []
        }}
        "#
        );

        let tx: TonTransaction = serde_json::from_str(&json).unwrap();
        assert!(tx.description.compute_ph.is_some());
        assert_eq!(
            tx.description.compute_ph.as_ref().and_then(|c| c.success),
            None
        );
    }

    #[test]
    fn deserialize__should_distinguish_ext_out_from_internal_msg() {
        // destination=null is ext-out; destination="0:..." is internal.
        let json = format!(
            r#"
        [
          {{
            "source": "{ADDR_AA}",
            "destination": null,
            "message_content": {{ "body": "te6cckEBAQEAAgAAAEysuc0=" }}
          }},
          {{
            "source": "{ADDR_AA}",
            "destination": "{ADDR_BB}",
            "message_content": {{ "body": "te6cckEBAQEAAgAAAEysuc0=" }}
          }}
        ]
        "#
        );

        let msgs: Vec<TonMessage> = serde_json::from_str(&json).unwrap();
        assert!(msgs[0].destination.is_none());
        assert!(msgs[1].destination.is_some());
    }

    #[test]
    fn deserialize__should_accept_message_without_body() {
        let json = format!(
            r#"
        {{
          "source": "{ADDR_AA}",
          "destination": null
        }}
        "#
        );

        let msg: TonMessage = serde_json::from_str(&json).unwrap();
        assert!(msg.message_content.is_none());
    }
}
