#![deny(unused_crate_dependencies)]
#![cfg_attr(not(all(feature = "abi", not(target_arch = "wasm32"))), no_std)]

mod block_height;

pub use block_height::{BlockCount, BlockHeight};
