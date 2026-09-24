use crate::threshold::ReconstructionThreshold;
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
    RobustEcdsa,
}

impl From<Protocol> for Curve {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::CaitSith | Protocol::RobustEcdsa => Curve::Secp256k1,
            Protocol::Frost => Curve::Edwards25519,
            Protocol::ConfidentialKeyDerivation => Curve::Bls12381,
        }
    }
}

impl Protocol {
    /// Number of participants that must be online to produce an output for a
    /// domain running this protocol at `reconstruction_threshold` `t`.
    ///
    /// Equal to `t` for every scheme except [`RobustEcdsa`](Protocol::RobustEcdsa),
    /// whose honest-majority setting needs `2t - 1` signers. Saturates at
    /// [`u64::MAX`] when `2t - 1` overflows, so the result still exceeds every
    /// participant count and such a `t` is rejected by validation.
    pub fn required_active_signers(self, reconstruction_threshold: ReconstructionThreshold) -> u64 {
        let t = reconstruction_threshold.inner();
        match self {
            // 2t - 1, evaluated as 2(t - 1) + 1 so saturation lands exactly on u64::MAX.
            Protocol::RobustEcdsa => t.saturating_sub(1).saturating_mul(2).saturating_add(1),
            Protocol::CaitSith | Protocol::Frost | Protocol::ConfidentialKeyDerivation => t,
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
    fn from_protocol_for_curve__should_map_robust_ecdsa_to_secp256k1() {
        assert_eq!(Curve::from(Protocol::RobustEcdsa), Curve::Secp256k1);
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

    #[test]
    fn required_active_signers__should_equal_reconstruction_threshold_for_non_robust_schemes() {
        // Given
        let t = ReconstructionThreshold::new(3);

        // When / Then
        for protocol in [
            Protocol::CaitSith,
            Protocol::Frost,
            Protocol::ConfidentialKeyDerivation,
        ] {
            assert_eq!(protocol.required_active_signers(t), 3, "{protocol:?}");
        }
    }

    #[test]
    fn required_active_signers__should_be_2t_minus_1_for_robust_ecdsa() {
        // Given
        let t = ReconstructionThreshold::new(3);

        // When
        let required = Protocol::RobustEcdsa.required_active_signers(t);

        // Then
        assert_eq!(required, 5);
    }

    #[test]
    fn required_active_signers__should_saturate_for_robust_ecdsa_on_overflow() {
        // Given
        let t = ReconstructionThreshold::new(u64::MAX);

        // When
        let required = Protocol::RobustEcdsa.required_active_signers(t);

        // Then
        assert_eq!(required, u64::MAX);
    }
}
