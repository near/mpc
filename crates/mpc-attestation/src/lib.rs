#![no_std]

extern crate alloc;

pub mod attestation;
pub mod report_data;

pub use attestation_types::{collateral, quote, tcb_info};

/// Re-exports of the off-chain `attestation` crate's `dcap-qvl`
/// conversion helpers, gated on a feature flag so that on-chain
/// consumers (`mpc-contract`) don't pull `dcap-qvl` into their WASM.
///
/// Off-chain consumers (`tee-authority`, `attestation-cli`, integration
/// tests) enable this feature.
#[cfg(feature = "local-verify")]
pub use ::attestation::{collateral_from_dcap, collateral_to_dcap};
