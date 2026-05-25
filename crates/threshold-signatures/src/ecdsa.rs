//! This module serves as a wrapper for ECDSA scheme.

pub mod ot_based_ecdsa;
pub mod robust_ecdsa;

mod rerandomization;
mod signature;

pub(crate) use frost_secp256k1::{Field, Group, Secp256K1Group, Secp256K1ScalarField};
pub(crate) use k256::{AffinePoint, ProjectivePoint};

use crate::crypto::ciphersuite::{BytesOrder, Ciphersuite, ScalarSerializationFormat};

pub use frost_secp256k1::Secp256K1Sha256;
pub type KeygenOutput = crate::KeygenOutput<Secp256K1Sha256>;
pub type Tweak = crate::Tweak<Secp256K1Sha256>;
pub type Scalar = <Secp256K1ScalarField as Field>::Scalar;
pub type Element = <Secp256K1Group as Group>::Element;
pub type CoefficientCommitment = frost_core::keys::CoefficientCommitment<Secp256K1Sha256>;
pub type Polynomial = crate::crypto::polynomials::Polynomial<Secp256K1Sha256>;
pub type PolynomialCommitment = crate::crypto::polynomials::PolynomialCommitment<Secp256K1Sha256>;

pub use rerandomization::RerandomizationArguments;
pub(crate) use signature::x_coordinate;
pub use signature::{Signature, SignatureOption};

impl ScalarSerializationFormat for Secp256K1Sha256 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::BigEndian
    }
}

impl Ciphersuite for Secp256K1Sha256 {}

#[cfg(test)]
mod test {
    use crate::{
        ecdsa::{KeygenOutput, Scalar, Secp256K1Sha256},
        test_utils::{generate_participants, MockCryptoRng},
    };

    use frost_core::{keys::SigningShare, SigningKey as FrostSigningKey};
    use rand::SeedableRng;
    type C = Secp256K1Sha256;

    #[test]
    fn keygen_output_should_be_serializable() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let signing_key = FrostSigningKey::<C>::new(&mut rng);

        let keygen_output = KeygenOutput {
            private_share: SigningShare::<C>::new(Scalar::ONE),
            public_key: frost_core::VerifyingKey::<C>::from(signing_key),
        };

        // When
        let serialized_keygen_output =
            serde_json::to_string(&keygen_output).expect("should be able to serialize output");

        // Then
        assert_eq!(
            serialized_keygen_output,
            "{\"private_share\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"public_key\":\"0351177dde89242d9121d787a681bd2a0bd6013428a6b83e684a253815db96d8b3\"}"
        );
    }

    #[test]
    fn test_keygen() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let participants = generate_participants(3);
        let threshold = 2;
        crate::dkg::test::test_keygen::<C, _>(&participants, threshold, &mut rng);
    }

    #[test]
    fn test_refresh() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let participants = generate_participants(3);
        let threshold = 2;
        crate::dkg::test::test_refresh::<C, _>(&participants, threshold, &mut rng);
    }

    #[test]
    fn test_reshare() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let participants = generate_participants(3);
        let threshold0 = 2;
        let threshold1 = 3;
        crate::dkg::test::test_reshare::<C, _>(&participants, threshold0, threshold1, &mut rng);
    }

    #[test]
    fn test_keygen_determinism() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let participants = generate_participants(3);
        let threshold = 2;
        let result = crate::dkg::test::test_keygen::<C, _>(&participants, threshold, &mut rng);
        insta::assert_json_snapshot!(result);
    }

    #[test]
    fn test_refresh_determinism() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let participants = generate_participants(3);
        let threshold = 2;
        let result = crate::dkg::test::test_refresh::<C, _>(&participants, threshold, &mut rng);
        insta::assert_json_snapshot!(result);
    }

    #[test]
    fn test_reshare_determinism() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let participants = generate_participants(3);
        let threshold0 = 2;
        let threshold1 = 3;
        let result =
            crate::dkg::test::test_reshare::<C, _>(&participants, threshold0, threshold1, &mut rng);
        insta::assert_json_snapshot!(result);
    }

    #[test]
    fn test_keygen_threshold_limits() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        crate::dkg::test::keygen__should_fail_if_threshold_is_below_limit::<C, _>(&mut rng);
    }

    #[test]
    fn test_reshare_threshold_limits() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        crate::dkg::test::reshare__should_fail_if_threshold_is_below_limit::<C, _>(&mut rng);
    }
}
