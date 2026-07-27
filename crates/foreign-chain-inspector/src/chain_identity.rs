//! Asking a foreign-chain RPC provider which network it is serving.
//!
//! A provider pointed at the wrong network of the right chain family answers transaction
//! lookups with a plain "not found", which [`crate::FanOut`] treats as a substantive verdict —
//! so one such provider breaks verification for the whole chain. Network identity is the
//! cheapest thing to check that catches this, and unlike a reference transaction it never
//! rots: providers prune transaction history, but not their genesis block or chain id.

use std::future::Future;
use std::pin::Pin;

use crate::ForeignChainInspectionError;

/// The network a provider is serving, as the chain natively reports it.
///
/// Opaque: the value is only ever compared against the operator's configured expectation,
/// never interpreted. Each [`ChainIdentityProbe`] implementation documents the exact text form
/// it produces, since that is what an operator has to write into their config.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    derive_more::Display,
    derive_more::From,
    derive_more::Into,
)]
pub struct ChainIdentity(String);

impl ChainIdentity {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Future returned by [`ChainIdentityProbe::chain_identity`].
///
/// Boxed rather than `impl Future` so that inspectors for unrelated chains — which share no
/// types at all — can be collected into one `Vec<Box<dyn ChainIdentityProbe>>` and driven by a
/// single loop. The check runs once per process at startup, never on a signing path, so the
/// allocation buys a lot of simplicity for nothing.
pub type ChainIdentityFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ChainIdentity, ForeignChainInspectionError>> + Send + 'a>>;

/// Asks a single RPC provider which network it serves.
///
/// Implemented by the per-chain inspectors, so a caller checks identity through exactly the
/// client (URL, auth, transport) that transaction verification would use.
pub trait ChainIdentityProbe: Send + Sync {
    fn chain_identity(&self) -> ChainIdentityFuture<'_>;
}
