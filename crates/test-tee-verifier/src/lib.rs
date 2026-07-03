//! Test-only stub of the `tee-verifier` contract.
//!
//! [`TestTeeVerifier::verify_quote`] returns a [`StubResponse`] fixed at init
//! time instead of running real `dcap_qvl::verify`.

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

    /// Ignores its inputs and returns the configured response, panicking on
    /// [`StubResponse::Panic`].
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
