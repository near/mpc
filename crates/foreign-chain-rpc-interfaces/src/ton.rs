use serde::{Deserialize, Serialize};

/// Top-level response from `GET /api/v3/transactions?...`.
///
/// toncenter returns the transactions array even when no transactions match —
/// in that case it is empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetTransactionsResponse {
    #[serde(default)]
    pub transactions: Vec<TonTransaction>,
}

/// A single TON transaction record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TonTransaction {
    /// Raw account address in `"<workchain>:<hex>"` format (e.g. `"0:a1b2…"`).
    pub account: String,

    /// Transaction hash. toncenter v3 returns lowercase hex (64 chars).
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

/// Subset of the `description` object returned by toncenter v3.
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
/// toncenter serializes two shapes: a "skipped" shape (no `success` field) and
/// a "normal" shape with `success: bool`. Modelling `success` as
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
    /// Source account (`"<workchain>:<hex>"`). `None` for ext-in messages
    /// (external to the chain).
    #[serde(default)]
    pub source: Option<String>,

    /// Destination account. `None` for ext-out messages (destination =
    /// `addr_none`, meaning external to the chain). This is the primary
    /// discriminator for ext-out filtering.
    #[serde(default)]
    pub destination: Option<String>,

    /// Logical time at which the TVM created this message. Within a single
    /// transaction, every emitted message has a distinct, monotonically
    /// increasing `created_lt` — this is a TON protocol invariant
    /// (`SENDRAWMSG` snapshots and bumps the lt counter), not a
    /// toncenter-specific guarantee. The MPC inspector parses this and uses
    /// it to sort ext-out messages so that ext-out indexing is independent of
    /// the order toncenter happens to serialize them in.
    ///
    /// toncenter v3 returns the value as a JSON string (the underlying TON
    /// type is a 64-bit unsigned integer that doesn't always fit safely into
    /// a JSON number). The inspector rejects the request if any ext-out
    /// message is missing or has an unparseable `created_lt`.
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

    #[test]
    fn deserialize__should_treat_missing_mc_block_seqno_as_none() {
        let json = r#"
        {
          "account": "0:00",
          "hash": "00",
          "description": {},
          "out_msgs": []
        }
        "#;

        let tx: TonTransaction = serde_json::from_str(json).unwrap();
        assert_eq!(tx.mc_block_seqno, None);
    }

    #[test]
    fn deserialize__should_treat_null_mc_block_seqno_as_none() {
        let json = r#"
        {
          "account": "0:00",
          "hash": "00",
          "mc_block_seqno": null,
          "description": {},
          "out_msgs": []
        }
        "#;

        let tx: TonTransaction = serde_json::from_str(json).unwrap();
        assert_eq!(tx.mc_block_seqno, None);
    }

    #[test]
    fn deserialize__should_accept_skipped_compute_phase() {
        let json = r#"
        {
          "account": "0:00",
          "hash": "00",
          "mc_block_seqno": 1,
          "description": {
            "aborted": false,
            "destroyed": false,
            "compute_ph": {}
          },
          "out_msgs": []
        }
        "#;

        let tx: TonTransaction = serde_json::from_str(json).unwrap();
        assert!(tx.description.compute_ph.is_some());
        assert_eq!(
            tx.description.compute_ph.as_ref().and_then(|c| c.success),
            None
        );
    }

    #[test]
    fn deserialize__should_distinguish_ext_out_from_internal_msg() {
        // destination=null is ext-out; destination="0:..." is internal.
        let json = r#"
        [
          {
            "source": "0:aa",
            "destination": null,
            "message_content": { "body": "te6cckEBAQEAAgAAAEysuc0=" }
          },
          {
            "source": "0:aa",
            "destination": "0:bb",
            "message_content": { "body": "te6cckEBAQEAAgAAAEysuc0=" }
          }
        ]
        "#;

        let msgs: Vec<TonMessage> = serde_json::from_str(json).unwrap();
        assert!(msgs[0].destination.is_none());
        assert_eq!(msgs[1].destination.as_deref(), Some("0:bb"));
    }

    #[test]
    fn deserialize__should_accept_message_without_body() {
        let json = r#"
        {
          "source": "0:aa",
          "destination": null
        }
        "#;

        let msg: TonMessage = serde_json::from_str(json).unwrap();
        assert!(msg.message_content.is_none());
    }
}
