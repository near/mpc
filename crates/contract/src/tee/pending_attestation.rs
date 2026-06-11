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

use mpc_attestation::attestation::DstackAttestation;
use borsh::{BorshDeserialize, BorshSerialize};
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
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
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
}
