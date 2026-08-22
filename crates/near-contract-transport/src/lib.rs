//! NEAR contract transport: the payload and vocabulary types of contract
//! calls and views, plus the [`CallContract`]/[`ViewContract`] traits,
//! implemented once per transport backend. The traits live behind the
//! opt-in `traits` feature.

#[cfg(feature = "monitoring")]
mod monitoring;
#[cfg(feature = "monitoring")]
mod subscription;
#[cfg(feature = "traits")]
mod traits;
mod types;

#[cfg(feature = "traits")]
pub use traits::{CallContract, ViewCall, ViewContract};
pub use types::{BlockHeight, FunctionCallArgs, NearGas, NearToken, ObservedState, ViewArgs};
