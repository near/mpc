//! State for an in-flight [`DstackAttestation`] submission.
//!
//! A [`DstackAttestation`] submission is asynchronous: it yields, fires a cross-contract
//! verify-quote call, and resumes from the response callback. What the callback
//! needs but cannot re-read from contract state is stashed here, keyed by the
//! submitter's account id, until the yield resolves.

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_attestation::attestation::DstackAttestation;
use near_mpc_contract_interface::types::Ed25519PublicKey;
use near_sdk::{CryptoHash, NearToken, near};

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
    pub caller_is_participant: bool,
    /// Yield handle, read back by the callback to resume the yield.
    pub data_id: CryptoHash,
}

#[near(serializers = [json])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationResult {
    Ok,
    Err(String),
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(AttestationResult::Ok)]
    #[case(AttestationResult::Err("rejected".to_string()))]
    fn attestation_result__should_round_trip_json(#[case] original: AttestationResult) {
        let bytes = serde_json::to_vec(&original).expect("serialize");
        let decoded: AttestationResult = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(original, decoded);
    }
}
