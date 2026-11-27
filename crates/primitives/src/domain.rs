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
    /// possible participant count.
    pub fn required_active_signers(self, reconstruction_threshold: ReconstructionThreshold) -> u64 {
        let t = reconstruction_threshold.value();
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
    use rstest::rstest;

    #[rstest]
    #[case::cait_sith_to_secp256k1(Protocol::CaitSith, Curve::Secp256k1)]
    #[case::robust_ecdsa_to_secp256k1(Protocol::RobustEcdsa, Curve::Secp256k1)]
    #[case::frost_to_edwards25519(Protocol::Frost, Curve::Edwards25519)]
    #[case::confidential_key_derivation_to_bls12381(
        Protocol::ConfidentialKeyDerivation,
        Curve::Bls12381
    )]
    fn from_protocol_for_curve__should_map_protocol_to_curve(
        #[case] protocol: Protocol,
        #[case] expected: Curve,
    ) {
        assert_eq!(Curve::from(protocol), expected);
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

    #[rstest]
    #[case::two_t_minus_1(3, 5)]
    #[case::saturate_on_overflow(u64::MAX, u64::MAX)]
    fn required_active_signers__should_be_saturating_2t_minus_1_for_robust_ecdsa(
        #[case] threshold: u64,
        #[case] expected: u64,
    ) {
        // Given
        let t = ReconstructionThreshold::new(threshold);

        // When
        let required = Protocol::RobustEcdsa.required_active_signers(t);

        // Then
        assert_eq!(required, expected);
    }
}
