use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Each domain corresponds to a specific root key on a specific elliptic curve. There may be
/// multiple domains per curve. The domain ID uniquely identifies a domain.
#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    derive_more::Into,
    derive_more::From,
    derive_more::AsRef,
    derive_more::FromStr,
    derive_more::Display,
    derive_more::Deref,
    Default,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub struct DomainId(pub u64);

impl DomainId {
    /// Returns the DomainId of the single ECDSA key present in the contract before V2.
    pub fn legacy_ecdsa_id() -> Self {
        Self(0)
    }
}

/// Elliptic curve used by a domain.
// When adding new curves, both Borsh *and* JSON serialization must be kept compatible.
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Default,
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub enum Curve {
    #[default]
    Secp256k1,
    // Accepts "Ed25519" for compat with pre-3.9.0 contracts. Remove after 3.9.0 deployment.
    #[serde(alias = "Ed25519")]
    Edwards25519,
    Bls12381,
    /// Robust ECDSA variant.
    V2Secp256k1,
}
