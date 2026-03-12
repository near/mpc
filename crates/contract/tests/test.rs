#![expect(
    clippy::mod_module_files,
    reason = "each file in /tests is compiled as a separate crate, thus mod.rs files are needed for common helper crate"
)]
pub mod inprocess;
pub mod sandbox;
