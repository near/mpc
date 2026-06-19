//! Cheetah curve + Tip5 hash + Goldilocks field — the pure-Rust cryptographic
//! primitives for the SchnorrCheetah ciphersuite (`crate::frost::cheetah`).
//!
//! Vendored verbatim from nockchain's `nockchain-math` with the `nockvm` /
//! `noun-serde` coupling removed (no Nock VM dependency). The single intentional
//! change is [`cheetah::f6_inv`], reimplemented via Fermat (`f^(p^6-2)`) to drop
//! the `bpoly`/`poly`/`felt` modules — a field inverse is unique, so the result is
//! identical, guarded by the `test_f6inv` known-answer test.
//!
//! Byte-exact parity with the on-chain Nockchain verifier and `@nockchain/rose-ts`
//! is enforced by the in-file known-answer tests (Tip5 public vectors, `3·G`,
//! F6 mul/inv/div, MDS reference). Previously the standalone `cheetah-tip5` crate.

// Vendored verbatim: keep the full primitive API (not all of it is used by the
// ciphersuite yet) and don't hold third-party code to this crate's style lints.
#![allow(dead_code)]
#![allow(clippy::all, clippy::pedantic, clippy::nursery)]

#[macro_use]
pub mod belt;
pub mod cheetah;
pub mod tip5;

#[cfg(test)]
mod golden;
