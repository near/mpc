//! Response DTOs for the TON HTTP API v3 (`GET /api/v3/...`), the standardized
//! REST interface implemented by TON RPC providers.
//!
//! Only the subset of fields the inspector consumes is modelled; unknown fields
//! in the JSON are ignored. Addresses use [`TonRawAddress`], which
//! (de)serializes the v3 API's raw `"<workchain>:<hex>"` form.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::fmt;

/// A TON account address in raw form, as the v3 API renders it:
/// `"<workchain>:<64 lowercase hex>"` (e.g. `"0:3e5f…5588"`).
///
/// Replaces the third-party `tonlib_core::types::TonAddress` so the crate parses
/// this attacker-influenced field with a small, audited implementation rather
/// than pulling in (and trusting) an external library. Only the raw form is
/// accepted — the user-friendly base64 form some providers also emit is not used
/// by the v3 `/transactions` endpoint for these fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TonRawAddress {
    /// Workchain id (`int8` in the TON address format; `0` for the basechain,
    /// `-1` for the masterchain).
    pub workchain: i8,
    /// The 256-bit account identifier within the workchain.
    pub hash: [u8; 32],
}

/// The canonical raw string form, `"<workchain>:<lowercase hex>"`.
impl fmt::Display for TonRawAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.workchain, hex::encode(self.hash))
    }
}

impl Serialize for TonRawAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TonRawAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let (workchain, hash_hex) = raw
            .split_once(':')
            .ok_or_else(|| D::Error::custom("TON address missing ':' separator"))?;
        let workchain: i8 = workchain
            .parse()
            .map_err(|_| D::Error::custom("TON address workchain is not an int8"))?;
        let bytes =
            hex::decode(hash_hex).map_err(|_| D::Error::custom("TON address hash is not hex"))?;
        let hash: [u8; 32] = bytes
            .try_into()
            .map_err(|_| D::Error::custom("TON address hash is not 32 bytes"))?;
        Ok(TonRawAddress { workchain, hash })
    }
}

/// Response of `GET /api/v3/transactions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTransactionsResponse {
    pub transactions: Vec<TonTransaction>,
}

/// A single transaction entry from `GET /api/v3/transactions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TonTransaction {
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
    pub destination: Option<TonRawAddress>,
    #[serde(default)]
    pub message_content: Option<TonCellBoc>,
}

/// A message body, serialized as a base64 [BoC](https://docs.ton.org/blockchain-basics/primitives/serialization/boc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TonCellBoc {
    pub body: String,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn ton_raw_address__should_display_as_workchain_and_lowercase_hex() {
        let address = TonRawAddress {
            workchain: 0,
            hash: [0xab; 32],
        };

        assert_eq!(
            address.to_string(),
            "0:abababababababababababababababababababababababababababababababab"
        );
    }

    #[test]
    fn ton_raw_address__should_roundtrip_through_serde() {
        let json = "\"-1:abababababababababababababababababababababababababababababababab\"";

        let address: TonRawAddress = serde_json::from_str(json).unwrap();

        assert_eq!(
            address,
            TonRawAddress {
                workchain: -1,
                hash: [0xab; 32],
            }
        );
        assert_eq!(serde_json::to_string(&address).unwrap(), json);
    }
}
