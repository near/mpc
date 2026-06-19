//! Conversions between `dcap_qvl`'s types and the Borsh-mirrored types in
//! `tee-verifier-interface`, for the off-chain `verify_locally` path.
//!
//! Re-exported from `tee-verifier-conversions` so the on-chain `tee-verifier`
//! contract and this off-chain crate share a single definition (and a single
//! Borsh-layout pin test suite) instead of duplicating the mappings.

pub use tee_verifier_conversions::{
    IntoDcapType, IntoInterfaceType, collateral_from_dcap, collateral_into_dcap,
};
