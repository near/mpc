//! TEE attestation types and post-DCAP verification helpers, decoupled from
//! `dcap-qvl`.
//!
//! Crate contents:
//! - DTOs that `mpc-contract` and other consumers exchange and store:
//!   [`tcb_info::TcbInfo`], [`app_compose::AppCompose`],
//!   [`measurements::Measurements`] / [`measurements::ExpectedMeasurements`],
//!   [`report_data::ReportData`].
//! - The post-DCAP verification helpers ([`verify_post_dcap`]): RTMR3 replay,
//!   app-compose validation, TCB-status / advisory-id checks, measurement
//!   matching. These operate on the
//!   [`tee_verifier_interface::VerifiedReport`] mirror — *not* on the
//!   `dcap_qvl` type — so this crate has no `dcap-qvl` dependency and can
//!   be linked into consumer contracts without dragging in
//!   `ring`/`webpki`/X.509.
//!
//! The `dcap_qvl::verify::verify` call itself lives elsewhere — in the
//! `attestation` crate for off-chain local verify, and in the
//! `tee-verifier` contract for cross-contract verify.

#![no_std]

extern crate alloc;

pub mod app_compose;
pub mod measurements;
pub mod report_data;
pub mod tcb_info;
pub mod verify_post_dcap;
