//! NEAR contract transport: the payload and vocabulary types of contract
//! calls and views, the [`CallContract`]/[`ViewContract`] traits implemented
//! once per transport backend, and the deserializing [`ViewCall`] and
//! subscription machinery on top. Everything but the payload types lives
//! behind the opt-in `traits` feature; the `near-kit` feature adds
//! [`CallContract`]/[`ViewContract`] backends over near-kit's client.

#[cfg(all(feature = "traits", any(test, feature = "test-utils")))]
pub mod mock;
#[cfg(feature = "near-kit")]
mod near_kit_backend;
#[cfg(feature = "traits")]
mod traits;
mod types;
#[cfg(feature = "traits")]
mod views;

#[cfg(feature = "traits")]
pub use traits::CallContract;
#[cfg(feature = "traits")]
pub use views::{
    Borsh, DeserializationError, DeserializeAs, Deserializer, HasPollInterval, Json, ObservedState,
    PollInterval, SerializedObservation, TransportError, ViewArgs, ViewCall, ViewContract,
    WatchContractState,
};

#[cfg(feature = "near-kit")]
pub use near_kit_backend::{NearKitCallError, NearKitCaller, NearKitViewError};
pub use types::{BlockHeight, FunctionCallArgs, NearGas, NearToken};
