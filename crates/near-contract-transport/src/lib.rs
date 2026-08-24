//! NEAR contract transport: the payload and vocabulary types of contract
//! calls and views, plus the [`CallContract`]/[`ViewContract`] traits,
//! implemented once per transport backend. The traits live behind the
//! opt-in `traits` feature.

#[cfg(feature = "traits")]
mod monitoring;
#[cfg(feature = "traits")]
mod subscription;
#[cfg(feature = "traits")]
mod traits;
mod types;

#[cfg(feature = "traits")]
pub use monitoring::{Observations, poll_observations, publish_if_changed};
#[cfg(feature = "traits")]
pub use subscription::{ViewError, WatchContractState};
#[cfg(feature = "traits")]
pub use traits::{CallContract, ObserveContract, PollInterval, ViewCall, ViewContract};
pub use types::{
    BlockHeight, FunctionCallArgs, NearGas, NearToken, ObservedState, TransportError, ViewArgs,
};
