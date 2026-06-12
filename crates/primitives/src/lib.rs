#![deny(unused_crate_dependencies)]
#![cfg_attr(not(all(feature = "abi", not(target_arch = "wasm32"))), no_std)]

extern crate alloc;

pub mod account_id;
pub mod domain;
pub mod hash;
pub mod key_state;
pub mod participant_id;
pub mod threshold;
pub mod yield_index;

pub use account_id::AccountId;
pub use key_state::{AttemptId, EpochId, KeyEventId};
pub use participant_id::ParticipantId;
pub use threshold::{ReconstructionThreshold, Threshold};
pub use yield_index::YieldIndex;

/// Re-exports used by the [`define_hash!`] macro. Not part of the public API.
#[doc(hidden)]
pub mod _macro_deps {
    pub use ::borsh;
    pub use ::hex;
    #[cfg(all(feature = "abi", not(target_arch = "wasm32")))]
    pub use ::schemars;
    pub use ::serde;
}
