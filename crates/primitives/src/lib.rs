#![deny(unused_crate_dependencies)]
#![cfg_attr(not(all(feature = "abi", not(target_arch = "wasm32"))), no_std)]

extern crate alloc;

pub mod hash;

/// Re-exports used by the [`define_hash!`] macro. Not part of the public API.
#[doc(hidden)]
pub mod _macro_deps {
    pub use ::borsh;
    pub use ::hex;
    pub use ::serde;
}
