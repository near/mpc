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
use tee_verifier_interface::{Collateral, QuoteBytes, VerifiedReport};

mod conversions;

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
    /// Verify a TDX / SGX quote against Intel collateral.
    ///
    /// Calls `dcap_qvl::verify::verify` with the current block timestamp
    /// and returns the parsed `VerifiedReport` on success. The caller is
    /// responsible for any post-DCAP policy (RTMR3 replay, report-data
    /// binding, measurement allowlist matching, etc.).
    ///
    /// On verification failure, panics with the upstream error rendered as
    /// a string. Callers should treat this as a `PromiseResult::Failed` in
    /// their callback.
    ///
    /// Borsh I/O on both arguments and return value.
    #[result_serializer(borsh)]
    pub fn verify_quote(
        &self,
        #[serializer(borsh)] quote: QuoteBytes,
        #[serializer(borsh)] collateral: Collateral,
    ) -> VerifiedReport {
        let now_seconds = env::block_timestamp_ms() / 1000;
        let quote_bytes = conversions::quote_bytes_to_vec(quote);
        let collateral = conversions::collateral_to_dcap(collateral);
        match dcap_qvl::verify::verify(&quote_bytes, &collateral, now_seconds) {
            Ok(report) => conversions::verified_report(report),
            Err(err) => env::panic_str(&format!("dcap verification failed: {err:?}")),
        }
    }
}
