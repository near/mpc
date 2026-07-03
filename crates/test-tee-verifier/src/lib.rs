//! Test-only stub of the `tee-verifier` contract.
//!
//! [`TestTeeVerifier::verify_quote`] ignores its inputs and returns a response
//! fixed at init time, instead of running real `dcap_qvl::verify`. This lets
//! `mpc-contract` sandbox tests drive every branch of the async attestation flow
//! deterministically: a [`StubResponse::Verified`] report (which the test
//! supplies so it matches the fixture's post-DCAP expectations), a
//! [`StubResponse::Rejected`] verdict, or a panic (the no-verdict /
//! verifier-unreachable path).

use borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::{env, near};
use tee_verifier_interface::{Collateral, QuoteBytes, VerificationResult, VerifierError};

// Match the real verifier's getrandom handling on wasm so the crate links.
#[cfg(target_arch = "wasm32")]
fn randomness_unsupported(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(randomness_unsupported);

/// What the stub's [`TestTeeVerifier::verify_quote`] should do, chosen by the
/// test at deploy time.
#[expect(clippy::large_enum_variant)]
// KEEP THE VARIANT ORDER IN SYNC with the `StubResponse` mirror in
// `crates/contract/tests/sandbox/tee_verifier.rs`: the test serializes with that
// copy and this contract deserializes with this one, so the Borsh discriminants
// (declaration index) must match. That mirror's `stub_response_discriminants`
// test pins the indices.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(borsh::BorshSchema)
)]
pub enum StubResponse {
    /// Return [`VerificationResult::Verified`] with this exact report. Tests that
    /// want the post-DCAP checks to pass supply the report obtained from the
    /// real fixture quote.
    Verified(tee_verifier_interface::VerifiedReport),
    /// Return [`VerificationResult::Rejected`] with this reason.
    Rejected(String),
    /// Panic, simulating an unreachable / crashing verifier (the no-verdict
    /// path that mpc-contract resolves via the yield timeout).
    Panic,
}

#[derive(Debug)]
#[near(contract_state)]
pub struct TestTeeVerifier {
    response: StubResponse,
}

impl Default for TestTeeVerifier {
    fn default() -> Self {
        // A contract must be initialized via `new`; default would never be used
        // by a test, but `#[near(contract_state)]` requires the bound.
        env::panic_str("TestTeeVerifier must be initialized with `new`")
    }
}

#[near]
impl TestTeeVerifier {
    #[init]
    pub fn new(#[serializer(borsh)] response: StubResponse) -> Self {
        Self { response }
    }

    /// Stub mirror of the real `tee-verifier` contract's verify-quote method:
    /// ignores the quote and collateral and returns the canned response. Panics
    /// on [`StubResponse::Panic`].
    #[result_serializer(borsh)]
    pub fn verify_quote(
        &self,
        #[serializer(borsh)] _quote: QuoteBytes,
        #[serializer(borsh)] _collateral: Collateral,
    ) -> VerificationResult {
        match &self.response {
            StubResponse::Verified(report) => VerificationResult::Verified(report.clone()),
            StubResponse::Rejected(reason) => {
                VerificationResult::Rejected(VerifierError::DcapVerification(reason.to_string()))
            }
            StubResponse::Panic => env::panic_str("stub verifier: simulated crash"),
        }
    }
}
