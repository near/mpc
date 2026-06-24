//! State for an in-flight [`Attestation::Dstack`] submission.
//!
//! A [`Attestation::Dstack`] submission is asynchronous: it yields, fires a
//! cross-contract verify-quote call, and resumes from the response callback.
//! What the callback needs but cannot re-read from contract state is stashed
//! here, keyed by the submitter's [`AccountId`], until the yield resolves.
//!
//! [`Attestation::Dstack`]: mpc_attestation::attestation::Attestation::Dstack
//! [`AccountId`]: near_sdk::AccountId

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation::DstackAttestation;
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_sdk::{CryptoHash, NearToken};

/// One in-flight verification per submitter account.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct PendingAttestation {
    /// The submitted payload the post-DCAP checks consume once the verifier
    /// returns its report.
    pub dstack: DstackAttestation,
    /// Checked against the quote's report-data during the post-DCAP checks.
    pub tls_public_key: Ed25519PublicKey,
    /// Stashed because the deposit is not visible from the callback receipt:
    /// consumed for storage on success, refunded on failure.
    pub attached_deposit: NearToken,
    /// Participant status at submit time, which decides whether the caller pays
    /// for storage. Captured because the callback receipt is no longer the
    /// caller, so it can no longer be re-derived.
    pub caller_is_not_participant: bool,
    /// Yield handle, read back by the callback to resume the yield.
    pub data_id: CryptoHash,
}

/// Outcome the resolution callback resumes the yield with.
///
/// Appears in a public callback signature, so it derives `BorshSchema` under
/// the `abi` feature (unlike [`PendingAttestation`], which is pure state).
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

    /// Pins the wire bytes: a variant reorder would flip the borsh tag and
    /// silently break callback receipts in flight across an upgrade, which the
    /// round-trip test above cannot catch.
    #[test]
    fn final_outcome__should_have_pinned_borsh_layout() {
        assert_eq!(borsh::to_vec(&FinalOutcome::Ok).unwrap(), vec![0]);
        assert_eq!(
            borsh::to_vec(&FinalOutcome::Err("x".to_string())).unwrap(),
            vec![1, 1, 0, 0, 0, b'x'],
        );
    }
}
