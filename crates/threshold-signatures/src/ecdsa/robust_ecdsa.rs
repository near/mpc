//! Insecure stub standing in for a robust threshold ECDSA scheme.
//!
//! # Do not enable this in production
//!
//! This module intentionally contains **no secure signing scheme**. It is a
//! placeholder: the implementation that used to live here was removed, and only its
//! type and protocol surface was kept so that a future robust scheme can be dropped
//! in without rebuilding the node and contract plumbing around it.
//!
//! [`sign()`] opens with a nonce generation round that broadcasts the nonce `k` in
//! the clear, so every signer learns it. Given the resulting signature `(R, s)`, the
//! signing key follows immediately from `x = (s * k - h) / R_x`. Signatures are
//! otherwise valid and verify against the derived public key, which is what lets the
//! surrounding node code and its tests run unchanged.
//!
//! This is a deliberate placeholder, not a vulnerability to report. It is safe only
//! because no production domain is served by it: never add a domain for this
//! protocol on mainnet or testnet while the stub is in place. Reintroducing a real
//! robust scheme means replacing the nonce generation round in `nonce_generation`; the
//! signing round in `sign` is scheme-agnostic.
//!
//! TODO(#4383): replace this stub with a real robust scheme.

pub mod sign;

mod nonce_generation;

#[cfg(test)]
mod test;

pub use nonce_generation::SignArguments;
pub use sign::sign;
