//! `dcap-qvl` [`Config`] backend built on `asn1_der` instead of
//! `x509-cert` + `der`.
//!
//! # Why
//!
//! `dcap-qvl`'s default audited backends ([`dcap_qvl::x509::X509CertBackend`]
//! and [`dcap_qvl::signature::DerSigEncoder`]) pull in `x509-cert` + `der`,
//! which add roughly 37 KiB on `wasm32-unknown-unknown` (`lto="fat"` +
//! `wasm-opt -O`). For the MPC smart contract's binary-size budget this is
//! significant.
//!
//! [`Asn1DerCertBackend`] and [`Asn1DerSigEncoder`] reimplement the same
//! surface using the `asn1_der` crate, which is already a transitive
//! dependency of `dcap-qvl`. No new dependencies are introduced.
//!
//! Typical usage from the contract's attestation code:
//!
//! ```ignore
//! use dcap_qvl_asn1_backend::Asn1DerConfig;
//! let report = dcap_qvl::verify::verify_with::<Asn1DerConfig>(
//!     &raw_quote,
//!     &collateral,
//!     now_secs,
//! )?;
//! ```
//!
//! # Audit boundary
//!
//! Custom `Config` impls are out of `dcap-qvl`'s audit scope by design.
//! `tests/conformance.rs` asserts byte-for-byte equivalence with
//! [`dcap_qvl::configs::DefaultConfig`] on the bundled SGX/TDX sample
//! corpus (cert parsing, issuer DN substring match, extension bytes,
//! ECDSA sig DER encoding, full `verify` end-to-end).
//!
//! Ported from the reference example in
//! <https://github.com/Phala-Network/dcap-qvl/pull/145>.

mod sig;
mod x509;

pub use sig::Asn1DerSigEncoder;
pub use x509::{Asn1DerCertBackend, Asn1DerParsedCert};

use dcap_qvl::config::Config;

/// `Config` bundle pairing the `asn1_der`-based backends with `dcap-qvl`'s
/// `ring` crypto provider. Drop-in replacement for
/// [`dcap_qvl::configs::RingConfig`] that avoids pulling `der` and
/// `x509-cert` into the build.
pub struct Asn1DerConfig;

impl Config for Asn1DerConfig {
    type X509 = Asn1DerCertBackend;
    type SigEncoder = Asn1DerSigEncoder;
    type Crypto = dcap_qvl::crypto::RingCrypto;
}
