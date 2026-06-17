//! State for an in-flight `Dstack` attestation submission.
//!
//! `submit_participant_info` for a `Dstack` attestation is asynchronous: it
//! yields, fires a cross-contract `verify_quote` call to the trusted verifier,
//! and resumes from the response callback. Everything the callback needs that
//! is not re-readable from contract state at callback time is stashed here,
//! keyed by the submitter's `AccountId`, until the verification resolves (or
//! the yield times out).
//!
//! Used in a later step (the async `submit_participant_info` flip); defined
//! here so the state field and storage key land first.

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation::DstackAttestation;
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_sdk::{CryptoHash, NearToken};

/// One in-flight verification per submitter account.
//
// Plain borsh (not `#[near(serializers=[borsh])]`): this is internal contract
// state that never appears in a public method signature, so it does not need a
// `BorshSchema` for ABI generation — and avoiding it keeps `DstackAttestation`
// out of the ABI schema requirement.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct PendingAttestation {
    /// The submitted `Dstack` payload — RTMR3 event log, app-compose, and the
    /// quote/collateral — that the post-DCAP checks consume once the verifier
    /// returns its report.
    pub dstack: DstackAttestation,
    /// The submitter's TLS public key, hashed with its account public key and
    /// compared against the quote's report-data during the post-DCAP checks.
    pub tls_public_key: Ed25519PublicKey,
    /// Deposit attached at submit time. `env::attached_deposit()` is not visible
    /// from the callback receipt, so it is stashed here: consumed for storage
    /// staking on success, refunded on failure.
    pub attached_deposit: NearToken,
    /// Whether the submitter was a non-participant at submit time. Together with
    /// "is this a new attestation", this decides whether the caller pays for
    /// storage (preserving the synchronous contract's charging rule). Captured
    /// at submit time because participant status is re-derived from the caller,
    /// which the callback receipt no longer is.
    pub caller_is_not_participant: bool,
    /// Yield handle from `env::promise_yield_create`. The resolution callback
    /// reads it back to `promise_yield_resume` with the final outcome.
    pub data_id: CryptoHash,
}

/// Outcome the resolution callback resumes the yielded promise with. The
/// yield-callback maps it back to a `Result` for the original caller.
//
// `FinalOutcome` reaches ABI generation as the `#[callback_result]` argument
// type of `on_attestation_verified`, so it needs a `BorshSchema` under `abi`
// (unlike `PendingAttestation`, which is pure state). Both its variants are
// schema-able (`()` and `String`).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub enum FinalOutcome {
    Ok,
    Err(String),
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn final_outcome__should_round_trip_borsh() {
        for original in [FinalOutcome::Ok, FinalOutcome::Err("rejected".to_string())] {
            let bytes = borsh::to_vec(&original).expect("serialize");
            let decoded: FinalOutcome = borsh::from_slice(&bytes).expect("deserialize");
            assert_eq!(original, decoded);
        }
    }

    /// Pin the exact wire bytes. `FinalOutcome` is serialized into a live
    /// `promise_yield_resume` payload, so a variant reorder would flip the tag
    /// and silently break callback receipts in flight across an upgrade — a
    /// regression the round-trip test above cannot catch. The tag is the
    /// variant index (`Ok` = 0, `Err` = 1); `String` is borsh-encoded as a
    /// little-endian `u32` length followed by the UTF-8 bytes.
    #[test]
    fn final_outcome__should_have_pinned_borsh_layout() {
        assert_eq!(borsh::to_vec(&FinalOutcome::Ok).unwrap(), vec![0]);
        assert_eq!(
            borsh::to_vec(&FinalOutcome::Err("x".to_string())).unwrap(),
            vec![1, 1, 0, 0, 0, b'x'],
        );
    }
}
