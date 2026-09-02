//! Insecure stub standing in for a robust threshold ECDSA scheme.
//!
//! # Do not enable this in production
//!
//! This module intentionally contains **no secure signing scheme**. It is a
//! placeholder: the implementation of [DJNPO20](https://eprint.iacr.org/2020/501)
//! that used to live here was removed, and only its type and protocol surface was
//! kept so that a future robust scheme can be dropped in without rebuilding the
//! node and contract plumbing around it.
//!
//! [`presign::presign`] broadcasts the nonce `k` in the clear, so every presigning
//! participant learns it. Given any signature `(R, s)` produced from that
//! presignature, the signing key follows immediately from `x = (s * k - h) / R_x`.
//! Signatures are otherwise valid and verify against the derived public key, which
//! is what lets the surrounding node code and its tests run unchanged.
//!
//! This is a deliberate placeholder, not a vulnerability to report. It is safe only
//! because no production domain is served by it: never add a domain for this
//! protocol on mainnet or testnet while the stub is in place. Reintroducing a real
//! robust scheme means replacing the presigning protocol in [`presign`]; the rest of
//! the module, including [`sign::sign`] and presignature rerandomization, is
//! scheme-agnostic.

pub mod presign;
pub mod sign;

#[cfg(test)]
mod test;

pub use presign::{PresignArguments, PresignOutput, RerandomizedPresignOutput};
