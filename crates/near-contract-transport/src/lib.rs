//! NEAR contract transport: the payload and vocabulary types of contract
//! calls and views, plus the [`CallContract`]/[`ViewContract`] traits,
//! implemented once per transport backend. The traits and the view
//! types live behind the opt-in `traits` feature.

#[cfg(feature = "traits")]
mod traits;
mod types;
#[cfg(feature = "traits")]
mod views;

#[cfg(feature = "traits")]
pub use traits::CallContract;
#[cfg(feature = "traits")]
pub use views::{
    DeserializationError, Deserializer, HasPollInterval, ObservedState, PollInterval,
    SerializedObservation, TransportError, ViewArgs, ViewContract, WatchContractState, borsh_de,
    json_de,
};

pub use types::{BlockHeight, FunctionCallArgs, NearGas, NearToken};
