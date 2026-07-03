//! Test-only stub of the `tee-verifier` contract.
//!
//! [`TestTeeVerifier::verify_quote`] ignores its inputs and returns a response
//! fixed at init time, instead of running real `dcap_qvl::verify`. This lets
//! `mpc-contract` sandbox tests drive every branch of the async attestation flow
//! deterministically: a [`StubResponse::Verified`] report (which the test
//! supplies so it matches the fixture's post-DCAP expectations), a
//! [`StubResponse::Rejected`] verdict, or a panic (the no-verdict /
//! verifier-unreachable path).

use near_sdk::{env, near};
use tee_verifier_interface::{Collateral, QuoteBytes, VerificationResult, VerifierError};
use test_tee_verifier_types::StubResponse;

#[cfg(target_arch = "wasm32")]
fn randomness_unsupported(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(randomness_unsupported);

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
