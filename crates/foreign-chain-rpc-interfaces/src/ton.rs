//! Response DTOs for the TON HTTP API v3 (`GET /api/v3/...`), the standardized
//! REST interface implemented by TON RPC providers.
//!
//! Only the subset of fields the inspector consumes is modelled; unknown fields
//! in the JSON are ignored. Addresses use [`tonlib_core::types::TonAddress`],
//! which deserializes from the v3 API's raw `"<workchain>:<hex>"` form.

use serde::{Deserialize, Serialize};
use tonlib_core::types::TonAddress;

/// Response of `GET /api/v3/transactions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTransactionsResponse {
    pub transactions: Vec<TonTransaction>,
}

/// A single transaction entry from `GET /api/v3/transactions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TonTransaction {
    /// Account the transaction belongs to.
    pub account: TonAddress,
    /// Base64-encoded transaction hash, as returned by the v3 API.
    pub hash: String,
    /// Seqno of the masterchain block this transaction was committed under.
    /// `None` until the transaction is referenced by a masterchain block —
    /// the signal we use for [`crate::ton`]-style finality.
    #[serde(default)]
    pub mc_block_seqno: Option<u64>,
    pub description: TonTransactionDescription,
    /// Outbound messages. Ext-out messages (those with no `destination`) carry
    /// the contract's emitted logs.
    #[serde(default)]
    pub out_msgs: Vec<TonMessage>,
}

/// Transaction `description` subset used to decide success/finality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TonTransactionDescription {
    #[serde(default)]
    pub aborted: bool,
    #[serde(default)]
    pub destroyed: bool,
    #[serde(default)]
    pub compute_ph: Option<TonComputePhase>,
    /// Action phase, where outbound messages (including the ext-out logs we
    /// attest) are actually sent. The compute phase can succeed while the
    /// action phase fails (e.g. too many output actions, insufficient funds for
    /// fwd fees), in which case the emitted messages are *not* committed — so a
    /// failed action phase must be treated as a failed transaction even when
    /// `aborted` is not set.
    #[serde(default)]
    pub action: Option<TonActionPhase>,
}

/// Compute phase subset. `success` is absent when the phase was skipped (e.g.
/// no code to run), which we do not treat as a failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TonComputePhase {
    #[serde(default)]
    pub success: Option<bool>,
}

/// Action phase subset. `success` is absent when the phase did not run, which
/// we do not treat as a failure; an explicit `Some(false)` means the outbound
/// messages were not committed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TonActionPhase {
    #[serde(default)]
    pub success: Option<bool>,
}

/// An outbound message of a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TonMessage {
    #[serde(default)]
    pub source: Option<TonAddress>,
    /// The inspector treats a `None` destination as the marker of an ext-out
    /// (logging) message and `Some` as an internal message to another contract.
    ///
    /// This relies on the v3 API serializing the external destination of an
    /// ext-out message (a TON `addr_extern`/`addr_none`) as JSON `null` rather
    /// than as a populated address. That holds for the contracts we attest,
    /// which emit logs to the empty external address, and is exercised by the
    /// live-provider test in `tests/ton_rpc_manual.rs`. A provider that instead
    /// rendered a non-empty external destination here would have its ext-outs
    /// misclassified as internal and skipped — validate this against any
    /// provider before whitelisting it.
    #[serde(default)]
    pub destination: Option<TonAddress>,
    /// Logical time the message was created, as a decimal string. Used to order
    /// ext-out messages deterministically.
    #[serde(default)]
    pub created_lt: Option<String>,
    #[serde(default)]
    pub message_content: Option<TonCellBoc>,
}

/// A message body, serialized as a base64 [BoC](https://docs.ton.org/blockchain-basics/primitives/serialization/boc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TonCellBoc {
    pub body: String,
}
