#![deny(unused_crate_dependencies)]
#![cfg_attr(not(all(feature = "abi", not(target_arch = "wasm32"))), no_std)]

extern crate alloc;

pub mod hash;

/// Re-exports used by the `hash_newtype!` macro when invoked from external crates.
#[doc(hidden)]
pub mod _macro_deps {
    pub extern crate alloc;
    pub use borsh;
    pub use derive_more;
    pub use hex;
    pub use serde;

    #[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
    pub use schemars;
}
