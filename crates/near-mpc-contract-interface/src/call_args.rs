//! Typed helpers for building and executing MPC contract calls.
//!
//! [`request_factory`] builds a [`FunctionCallArgs`](mpc_call_args::FunctionCallArgs) for each
//! contract method; the [`CallContract`] trait plus the per-method call helpers (written once
//! against it) let those calls run on any backend that implements the trait.

mod consts;
mod error;
mod request_factory;
mod traits;

pub use error::CallError;
pub use request_factory::*;
pub use traits::*;
