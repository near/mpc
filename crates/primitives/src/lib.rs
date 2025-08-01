#![deny(unused_crate_dependencies)]
#![cfg_attr(not(not(target_arch = "wasm32")), no_std)]

extern crate alloc;

pub mod hash;
