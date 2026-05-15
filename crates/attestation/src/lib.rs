#![no_std]

extern crate alloc;

pub mod attestation;

// All DTOs and post-DCAP helpers live in `attestation-types`. The
// `attestation` crate exists only to host `DstackAttestation::verify`
// (the local `dcap_qvl::verify::verify` call site) and the conversion
// helpers between `attestation-types` shapes and the `dcap_qvl` upstream
// types.
//
// Re-export the modules at the historical `attestation::*` paths so
// existing consumers keep their imports.
pub use attestation_types::{
    app_compose, collateral, dstack_attestation, measurements, quote, report_data, tcb_info,
    verify_post_dcap,
};

/// Convenience re-export so existing code that imports
/// `attestation::collateral::Collateral` keeps compiling.
pub use attestation_types::collateral::Collateral;

/// Convenience re-export so existing code that imports
/// `attestation::quote::QuoteBytes` keeps compiling.
pub use attestation_types::quote::QuoteBytes;

/// Convert a `dcap_qvl::QuoteCollateralV3` into the wasm-friendly
/// `attestation_types::Collateral` mirror.
///
/// Used by off-chain code (e.g. `tee-authority`) that fetches collateral
/// via `dcap_qvl::collateral::CollateralClient`. Lives here rather than
/// as a `From` impl because the orphan rule forbids implementing a
/// foreign trait between two foreign types from a third crate.
pub fn collateral_from_dcap(value: dcap_qvl::QuoteCollateralV3) -> Collateral {
    Collateral {
        pck_crl_issuer_chain: value.pck_crl_issuer_chain,
        root_ca_crl: value.root_ca_crl,
        pck_crl: value.pck_crl,
        tcb_info_issuer_chain: value.tcb_info_issuer_chain,
        tcb_info: value.tcb_info,
        tcb_info_signature: value.tcb_info_signature,
        qe_identity_issuer_chain: value.qe_identity_issuer_chain,
        qe_identity: value.qe_identity,
        qe_identity_signature: value.qe_identity_signature,
        pck_certificate_chain: value.pck_certificate_chain,
    }
}

/// Convert an `attestation_types::Collateral` mirror into the
/// `dcap_qvl::QuoteCollateralV3` shape that `dcap_qvl::verify::verify`
/// consumes.
pub fn collateral_to_dcap(value: Collateral) -> dcap_qvl::QuoteCollateralV3 {
    dcap_qvl::QuoteCollateralV3 {
        pck_crl_issuer_chain: value.pck_crl_issuer_chain,
        root_ca_crl: value.root_ca_crl,
        pck_crl: value.pck_crl,
        tcb_info_issuer_chain: value.tcb_info_issuer_chain,
        tcb_info: value.tcb_info,
        tcb_info_signature: value.tcb_info_signature,
        qe_identity_issuer_chain: value.qe_identity_issuer_chain,
        qe_identity: value.qe_identity,
        qe_identity_signature: value.qe_identity_signature,
        pck_certificate_chain: value.pck_certificate_chain,
    }
}
