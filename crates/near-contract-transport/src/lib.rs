//! Polling for NEAR contract views: [`watch::Subscribe`] turns any near-kit
//! view into a [`tokio::sync::watch`] channel of its changes, and
//! [`watch::wait_for`] waits on one until a predicate holds.

pub mod watch;
