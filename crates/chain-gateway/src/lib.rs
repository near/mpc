//! Embedded NEAR gateway and reusable block tracking types.
//!
//! The default `embedded-node` feature enables node startup and transaction helpers.
//! Disable default features to use [`event_subscriber::recent_blocks_tracker`] and
//! block types without a NEAR node runtime dependency.

#[cfg(feature = "embedded-node")]
pub mod chain_gateway;
pub mod errors;
pub mod event_subscriber;
#[cfg(all(feature = "embedded-node", any(test, feature = "test-utils")))]
pub mod mock;
#[cfg(feature = "embedded-node")]
pub mod primitives;
#[cfg(feature = "embedded-node")]
pub mod transaction_sender;
pub mod types;

#[cfg(feature = "embedded-node")]
mod near_internals_wrapper;

#[cfg(feature = "embedded-node")]
pub use chain_gateway::{ChainGateway, NodeHandle};
