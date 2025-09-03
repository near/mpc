#![deny(unused_crate_dependencies)]
#![deny(clippy::mod_module_files)]
#![cfg_attr(not(all(feature = "abi", not(target_arch = "wasm32"))), no_std)]

extern crate alloc;

pub mod hash;
