#![deny(clippy::mod_module_files)]

mod attestation;
mod expected_measurements;

pub use attestation::verify;
