//! Wire types shared between the `test-tee-verifier` stub contract and the
//! `mpc-contract` sandbox tests that drive it.
//!
//! Kept in a plain (non-`#[near]`) crate so both a contract crate and a test
//! binary can depend on the same definition: importing the stub contract itself
//! would emit a duplicate contract-ABI symbol and unify its `abi` feature under
//! `cargo test --all-features`.

use borsh::{BorshDeserialize, BorshSerialize};

/// What the stub verifier's verify-quote method should return, chosen by the
/// test at deploy time.
#[expect(clippy::large_enum_variant)]
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub enum StubResponse {
    /// Return [`tee_verifier_interface::VerificationResult::Verified`] with this
    /// exact report. Tests that want the post-DCAP checks to pass supply the
    /// report obtained from the real fixture quote.
    Verified(tee_verifier_interface::VerifiedReport),
    /// Return [`tee_verifier_interface::VerificationResult::Rejected`] with this
    /// reason.
    Rejected(String),
    /// Panic, simulating an unreachable or crashing verifier: the verify-quote
    /// receipt fails, which mpc-contract reports as the verifier being unavailable.
    Panic,
}
