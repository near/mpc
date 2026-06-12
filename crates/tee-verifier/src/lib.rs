//! Stateless TEE attestation verifier contract.
//!
//! Wraps `dcap_qvl::verify::verify` in a single `verify_quote` method. The
//! contract holds no state and has no admin; verifier-internal policy (the
//! `dcap-qvl` version, Intel root certs, etc.) is bound to the deployed
//! code hash. Per-team allowlists, report-data binding, and other
//! post-DCAP checks live in the caller, not here.
//!
//! See `docs/design/attestation-verifier-contract.md` for the design.

use near_sdk::{env, near};
use tee_verifier_interface::{Collateral, QuoteBytes, VerificationResult, VerifierError};

mod conversions;
use conversions::{IntoDcapType as _, IntoInterfaceType as _};

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
    /// and returns `VerificationResult::Verified(report)` on success. The
    /// caller is responsible for any post-DCAP policy (RTMR3 replay,
    /// report-data binding, measurement allowlist matching, etc.).
    ///
    /// A rejected quote returns [`VerificationResult::Rejected`] as the
    /// **value** of a *successful* receipt — deliberately not via
    /// `#[handle_result]`. near-sdk serializes the returned enum through
    /// `env::value_return`, so an on-chain caller's `#[callback_result]` sees
    /// `Ok(VerificationResult::Rejected(_))` and can distinguish "verifier
    /// rejected this quote" from `Err(PromiseError::Failed)` ("verifier
    /// unreachable / crashed / timed out"). A failed receipt would carry no
    /// payload and collapse both into the same opaque failure.
    #[result_serializer(borsh)]
    pub fn verify_quote(
        &self,
        #[serializer(borsh)] quote: QuoteBytes,
        #[serializer(borsh)] collateral: Collateral,
    ) -> VerificationResult {
        let now_seconds = env::block_timestamp_ms() / 1000;
        let quote_bytes: Vec<u8> = quote.into_dcap_type();
        let collateral = collateral.into_dcap_type();
        match dcap_qvl::verify::verify(&quote_bytes, &collateral, now_seconds) {
            Ok(report) => VerificationResult::Verified(report.into_interface_type()),
            Err(err) => {
                VerificationResult::Rejected(VerifierError::DcapVerification(err.to_string()))
            }
        }
    }
}
