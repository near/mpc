//! Cross-contract interface to the external TEE attestation verifier.
//!
//! This contract no longer runs DCAP/TDX quote verification itself. The heavy
//! `dcap-qvl` call is delegated to a dedicated verifier contract via a
//! cross-contract call from `submit_participant_info`. The verifier returns
//! the matched `ExpectedMeasurements` (or panics with a descriptive error),
//! and an `on_dstack_attestation_verified` callback records the result.
//!
//! The verifier address is hardcoded for the PoC. Promote it to a `Config`
//! field with a state migration before this ships.

use std::str::FromStr;

use near_mpc_contract_interface::types as dtos;
use near_sdk::{ext_contract, AccountId, Gas};

use crate::tee::measurements::ContractExpectedMeasurements;

/// Number of bytes in the TDX report data field. Mirrors
/// `attestation::report_data::REPORT_DATA_SIZE`. The verifier contract is
/// expected to reject calls whose `expected_report_data` length is not this.
pub const REPORT_DATA_SIZE: usize = 64;

/// PoC: hardcoded address of the external TEE verifier contract.
/// TODO: move to `Config` once the verifier is deployed at a stable address.
pub fn tee_verifier_account_id() -> AccountId {
    AccountId::from_str("tee-verifier.near").expect("hardcoded account id is valid")
}

/// Gas attached to the cross-contract `verify_dstack_attestation` call. DCAP
/// verification is heavy (cert-chain validation, ECDSA, RTMR replay).
pub const VERIFY_DSTACK_ATTESTATION_GAS: Gas = Gas::from_tgas(150);

/// Gas reserved for the `on_dstack_attestation_verified` callback. Storage
/// writes plus a refund Promise.
pub const ON_DSTACK_ATTESTATION_VERIFIED_GAS: Gas = Gas::from_tgas(20);

#[ext_contract(ext_tee_verifier)]
pub trait TeeVerifier {
    /// Run DCAP/TDX verification on a Dstack attestation. On success, returns
    /// the matched element of `accepted_measurements`. On failure, the
    /// verifier contract panics with a descriptive message; the caller's
    /// callback observes a `PromiseError`.
    fn verify_dstack_attestation(
        &self,
        attestation: dtos::DstackAttestation,
        expected_report_data: Vec<u8>,
        accepted_measurements: Vec<ContractExpectedMeasurements>,
        timestamp_seconds: u64,
    ) -> ContractExpectedMeasurements;
}
