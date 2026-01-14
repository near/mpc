#![no_std]
#![deny(clippy::mod_module_files)]

extern crate alloc;

pub mod attestation;
pub mod report_data;

pub use ::attestation::{collateral, quote, tcb_info};
