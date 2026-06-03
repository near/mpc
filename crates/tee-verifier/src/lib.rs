//! Stateless TEE attestation verifier contract.
//!
//! Wraps `dcap_qvl::verify::verify` in a single `verify_quote` method. The
//! contract holds no state and has no admin; verifier-internal policy (the
//! `dcap-qvl` version, Intel root certs, etc.) is bound to the deployed
//! code hash. Per-team allowlists, report-data binding, and other
//! post-DCAP checks live in the caller, not here.
//!
//! See `docs/design/attestation-verifier-contract.md` for the design.

use near_sdk::{FunctionError, env, near};
use tee_verifier_interface::{Collateral, QuoteBytes, VerifiedReport};

mod conversions;
use conversions::{IntoDcapType as _, IntoInterfaceType as _};

/// Failure returned by [`TeeVerifier::verify_quote`].
#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    /// `dcap_qvl::verify::verify` rejected the quote / collateral.
    #[error("dcap verification failed: {0}")]
    DcapVerification(String),
}

impl FunctionError for VerifierError {
    fn panic(&self) -> ! {
        env::panic_str(&self.to_string())
    }
}

// `dcap-qvl`'s `contract` feature pulls in `getrandom` but doesn't enable
// any backend. On `wasm32-unknown-unknown` we register a custom impl that
// returns `UNSUPPORTED`. Quote verification should not draw any randomness;
// if it ever does, the call fails loudly rather than silently with zeros.
#[cfg(target_arch = "wasm32")]
fn randomness_unsupported(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(randomness_unsupported);

#[derive(Debug, Default)]
#[near(contract_state)]
pub struct TeeVerifier {}

#[near]
impl TeeVerifier {
    /// Verify a TDX quote against Intel collateral.
    ///
    /// Calls `dcap_qvl::verify::verify` with the current block timestamp
    /// and returns the parsed `VerifiedReport` on success. The caller is
    /// responsible for any post-DCAP policy (RTMR3 replay, report-data
    /// binding, measurement allowlist matching, etc.).
    #[handle_result]
    #[result_serializer(borsh)]
    pub fn verify_quote(
        &self,
        #[serializer(borsh)] quote: QuoteBytes,
        #[serializer(borsh)] collateral: Collateral,
    ) -> Result<VerifiedReport, VerifierError> {
        let now_seconds = env::block_timestamp_ms() / 1000;
        let quote_bytes: Vec<u8> = quote.into_dcap_type();
        let collateral = collateral.into_dcap_type();
        dcap_qvl::verify::verify(&quote_bytes, &collateral, now_seconds)
            .map(|report| report.into_interface_type())
            .map_err(|err| VerifierError::DcapVerification(format!("{err}")))
    }
}
