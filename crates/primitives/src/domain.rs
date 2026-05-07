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
    Edwards25519,
    Bls12381,
}

/// MPC protocol run for a domain.
// When adding new protocols, both Borsh *and* JSON serialization must be kept compatible.
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
)]
#[cfg_attr(
    all(feature = "abi", not(target_arch = "wasm32")),
    derive(schemars::JsonSchema, borsh::BorshSchema)
)]
pub enum Protocol {
    CaitSith,
    Frost,
    ConfidentialKeyDerivation,
    DamgardEtAl,
}

impl From<Protocol> for Curve {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::CaitSith | Protocol::DamgardEtAl => Curve::Secp256k1,
            Protocol::Frost => Curve::Edwards25519,
            Protocol::ConfidentialKeyDerivation => Curve::Bls12381,
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn from_protocol_for_curve__should_map_cait_sith_to_secp256k1() {
        assert_eq!(Curve::from(Protocol::CaitSith), Curve::Secp256k1);
    }

    #[test]
    fn from_protocol_for_curve__should_map_damgard_et_al_to_secp256k1() {
        assert_eq!(Curve::from(Protocol::DamgardEtAl), Curve::Secp256k1);
    }

    #[test]
    fn from_protocol_for_curve__should_map_frost_to_edwards25519() {
        assert_eq!(Curve::from(Protocol::Frost), Curve::Edwards25519);
    }

    #[test]
    fn from_protocol_for_curve__should_map_confidential_key_derivation_to_bls12381() {
        assert_eq!(
            Curve::from(Protocol::ConfidentialKeyDerivation),
            Curve::Bls12381
        );
    }
}
