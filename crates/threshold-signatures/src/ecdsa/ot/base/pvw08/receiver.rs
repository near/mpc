use frost_core::keys::CoefficientCommitment;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroize;

use super::crs::Crs;
use crate::{Ciphersuite, Element, Scalar};

/// The receiver's choice bits and secret exponents for a batch of transfers.
pub struct ReceiverSecrets<C: Ciphersuite>
where
    Scalar<C>: Zeroize,
{
    /// One bit per transfer, each 0 or 1.
    choices: Vec<u8>,
    exponents: Vec<Scalar<C>>,
}

impl<C: Ciphersuite> ReceiverSecrets<C>
where
    Scalar<C>: Zeroize,
{
    /// Samples uniform choice bits and exponents for `batch_size` transfers.
    pub fn random(batch_size: usize, rng: &mut impl CryptoRngCore) -> Self {
        let mut choices = vec![0u8; batch_size];
        rng.fill_bytes(&mut choices);
        for choice in &mut choices {
            *choice &= 1;
        }
        // A zero exponent would yield the identity, which the sender rejects.
        let exponents = (0..batch_size)
            .map(|_| frost_core::random_nonzero::<C, _>(rng))
            .collect();
        Self { choices, exponents }
    }

    /// Computes the public key of every transfer: the pair of the chosen
    /// branch of `crs`, raised to the transfer's exponent.
    pub fn public_keys(&self, crs: &Crs<C>) -> Vec<ReceiverPublicKey<C>>
    where
        Element<C>: ConditionallySelectable,
    {
        self.choices
            .iter()
            .zip(&self.exponents)
            .map(|(&choice, &exponent)| {
                let (g, h) = crs.branch(Choice::from(choice));
                ReceiverPublicKey {
                    p: CoefficientCommitment::new(g * exponent),
                    q: CoefficientCommitment::new(h * exponent),
                }
            })
            .collect()
    }
}

impl<C: Ciphersuite> Zeroize for ReceiverSecrets<C>
where
    Scalar<C>: Zeroize,
{
    fn zeroize(&mut self) {
        self.choices.zeroize();
        self.exponents.zeroize();
    }
}

impl<C: Ciphersuite> Drop for ReceiverSecrets<C>
where
    Scalar<C>: Zeroize,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// The receiver's message for one transfer. Deserialization rejects the
/// identity.
#[derive(Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct ReceiverPublicKey<C: Ciphersuite> {
    p: CoefficientCommitment<C>,
    q: CoefficientCommitment<C>,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod test {
    use rand::SeedableRng;

    use super::*;
    use crate::{ecdsa::Secp256K1Sha256, test_utils::MockCryptoRng};

    type C = Secp256K1Sha256;

    #[test]
    fn random__should_sample_one_bit_and_one_exponent_per_transfer() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let batch_size = 1000;

        // When
        let secrets = ReceiverSecrets::<C>::random(batch_size, &mut rng);

        // Then
        assert_eq!(secrets.choices.len(), batch_size);
        assert_eq!(secrets.exponents.len(), batch_size);
        assert!(secrets.choices.iter().all(|&choice| choice <= 1));
        assert!(secrets.choices.contains(&0));
        assert!(secrets.choices.contains(&1));
    }

    #[test]
    fn public_keys__should_be_decryptable_on_the_chosen_branch_only() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let (crs, trapdoor) = Crs::<C>::messy_with_trapdoor(&mut rng);
        let secrets = ReceiverSecrets::<C>::random(100, &mut rng);

        // When
        let public_keys = secrets.public_keys(&crs);

        // Then
        assert_eq!(public_keys.len(), secrets.choices.len());
        for (public_key, &choice) in public_keys.iter().zip(&secrets.choices) {
            let decryptable =
                trapdoor.decryptable_branches(&public_key.p.value(), &public_key.q.value());
            assert_eq!(decryptable, [choice == 0, choice == 1]);
        }
    }

    #[test]
    fn public_keys__should_survive_a_serialization_round_trip() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let crs = Crs::<C>::derive(b"session").unwrap();
        let public_keys = ReceiverSecrets::<C>::random(10, &mut rng).public_keys(&crs);

        // When
        let bytes = rmp_serde::to_vec(&public_keys).unwrap();
        let decoded: Vec<ReceiverPublicKey<C>> = rmp_serde::from_slice(&bytes).unwrap();

        // Then
        for (decoded, original) in decoded.iter().zip(&public_keys) {
            assert_eq!(decoded.p, original.p);
            assert_eq!(decoded.q, original.q);
        }
    }

    #[test]
    fn public_keys__should_match_snapshot() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let crs = Crs::<C>::derive(b"session").unwrap();
        let secrets = ReceiverSecrets::<C>::random(2, &mut rng);

        // When
        let public_keys = secrets.public_keys(&crs);

        // Then
        insta::assert_json_snapshot!(public_keys);
    }
}
