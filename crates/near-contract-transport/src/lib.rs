//! NEAR contract transport: the payload and vocabulary types of contract
//! calls and views, plus the `ViewContract` trait, implemented once per
//! transport backend. The trait lives behind the opt-in `traits` feature.

#[cfg(feature = "traits")]
mod traits;
mod types;

#[cfg(feature = "traits")]
pub use traits::ViewContract;
pub use types::{BlockHeight, FunctionCallArgs, NearGas, NearToken, ObservedState, ViewArgs};
