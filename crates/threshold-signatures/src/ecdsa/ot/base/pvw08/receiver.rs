use frost_core::keys::CoefficientCommitment;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    crs::Crs,
    kdf::{derive_key, serialize},
    sender::SenderCiphertext,
};
use crate::{
    Ciphersuite, Element, Scalar, ecdsa::ot::bits::BitMatrix, errors::ProtocolError,
    participants::Participant,
};

/// The receiver's choice bits and secret exponents for a batch of transfers.
#[derive(ZeroizeOnDrop)]
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

    /// Derives the chosen key of every transfer from `ciphertexts`, the
    /// message received from `sender`.
    ///
    /// `public_keys` must be the output of [`Self::public_keys`]. The message
    /// is rejected if it does not hold one ciphertext per transfer.
    pub fn decapsulate(
        &self,
        sid: &[u8],
        public_keys: &[ReceiverPublicKey<C>],
        sender: Participant,
        ciphertexts: &[SenderCiphertext<C>],
    ) -> Result<ReceiverOutput, ProtocolError>
    where
        Element<C>: ConditionallySelectable,
    {
        let batch_size = self.choices.len();
        if public_keys.len() != batch_size {
            return Err(ProtocolError::AssertionFailed(format!(
                "got {} public keys for {batch_size} transfers",
                public_keys.len()
            )));
        }
        if ciphertexts.len() != batch_size {
            return Err(ProtocolError::UnexpectedLength {
                expected: batch_size,
                actual: ciphertexts.len(),
                participant: sender,
            });
        }

        let transfers = self.choices.iter().zip(&self.exponents);
        let messages = public_keys.iter().zip(ciphertexts);
        let keys = transfers
            .zip(messages)
            .enumerate()
            .map(
                |(index, ((&choice, &exponent), (public_key, ciphertext)))| {
                    let u = <Element<C>>::conditional_select(
                        &ciphertext.u0.value(),
                        &ciphertext.u1.value(),
                        Choice::from(choice),
                    );
                    derive_key(
                        sid,
                        index,
                        choice,
                        serialize::<C>(&public_key.p.value())?.as_ref(),
                        serialize::<C>(&public_key.q.value())?.as_ref(),
                        serialize::<C>(&u)?.as_ref(),
                        serialize::<C>(&(u * exponent))?.as_ref(),
                    )
                },
            )
            .collect::<Result<BitMatrix, ProtocolError>>()?;

        Ok(ReceiverOutput {
            choices: self
                .choices
                .iter()
                .map(|&choice| Choice::from(choice))
                .collect(),
            keys,
        })
    }
}

/// The receiver's choice bit and chosen key for every transfer: row `i` of
/// `keys` is the key of bit `choices[i]`.
pub struct ReceiverOutput {
    pub choices: Vec<Choice>,
    pub keys: BitMatrix,
}

impl_secret_debug!(ReceiverOutput);

/// The receiver's message for one transfer. Deserialization rejects the
/// identity.
#[derive(Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct ReceiverPublicKey<C: Ciphersuite> {
    pub(super) p: CoefficientCommitment<C>,
    pub(super) q: CoefficientCommitment<C>,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod test {
    use rand::SeedableRng;
    use rstest::rstest;

    use super::*;
    use crate::{
        ecdsa::{
            Secp256K1Sha256,
            ot::{
                base::pvw08::{SenderOutput, SenderRandomness},
                bits::{BitVector, SquareBitMatrix},
            },
        },
        test_utils::MockCryptoRng,
    };

    type C = Secp256K1Sha256;

    const SID: &[u8] = b"session";

    fn sender() -> Participant {
        Participant::from(0u32)
    }

    fn receiver() -> Participant {
        Participant::from(1u32)
    }

    fn run(batch_size: usize) -> (SenderOutput, ReceiverOutput) {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let crs = Crs::<C>::derive(SID).unwrap();
        let secrets = ReceiverSecrets::<C>::random(batch_size, &mut rng);
        let public_keys = secrets.public_keys(&crs);
        let (ciphertexts, sender_output) = SenderRandomness::<C>::random(batch_size, &mut rng)
            .encapsulate(&crs, SID, receiver(), &public_keys)
            .unwrap();
        let receiver_output = secrets
            .decapsulate(SID, &public_keys, sender(), &ciphertexts)
            .unwrap();
        (sender_output, receiver_output)
    }

    #[rstest]
    #[case(1)]
    #[case(128)]
    #[case(1000)]
    fn decapsulate__should_output_the_chosen_key_only(#[case] batch_size: usize) {
        // Given / When
        let (sender_output, receiver_output) = run(batch_size);

        // Then
        assert_eq!(receiver_output.choices.len(), batch_size);
        assert_eq!(receiver_output.keys.height(), batch_size);
        let sender_keys = sender_output.k0.rows().zip(sender_output.k1.rows());
        let receiver_keys = receiver_output
            .choices
            .iter()
            .zip(receiver_output.keys.rows());
        for ((k0, k1), (&choice, key)) in sender_keys.zip(receiver_keys) {
            assert_eq!(*key, BitVector::conditional_select(k0, k1, choice));
            assert_ne!(*key, BitVector::conditional_select(k0, k1, !choice));
        }
    }

    #[test]
    fn decapsulate__should_output_what_an_ot_extension_expects_for_128_transfers() {
        // Given
        let (sender_output, receiver_output) = run(128);

        // When
        let k0 = SquareBitMatrix::try_from(sender_output.k0);
        let k1 = SquareBitMatrix::try_from(sender_output.k1);
        let keys = SquareBitMatrix::try_from(receiver_output.keys);

        // Then
        assert!(k0.is_ok());
        assert!(k1.is_ok());
        assert!(keys.is_ok());
    }

    #[test]
    fn decapsulate__should_reject_a_batch_of_the_wrong_length() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let crs = Crs::<C>::derive(SID).unwrap();
        let secrets = ReceiverSecrets::<C>::random(4, &mut rng);
        let public_keys = secrets.public_keys(&crs);
        let (mut ciphertexts, _) = SenderRandomness::<C>::random(4, &mut rng)
            .encapsulate(&crs, SID, receiver(), &public_keys)
            .unwrap();
        ciphertexts.pop();

        // When
        let result = secrets.decapsulate(SID, &public_keys, sender(), &ciphertexts);

        // Then
        assert_eq!(
            result.err(),
            Some(ProtocolError::UnexpectedLength {
                expected: 4,
                actual: 3,
                participant: sender(),
            })
        );
    }

    #[test]
    fn decapsulate__should_reject_public_keys_of_another_batch() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let crs = Crs::<C>::derive(SID).unwrap();
        let secrets = ReceiverSecrets::<C>::random(4, &mut rng);
        let public_keys = secrets.public_keys(&crs);
        let (ciphertexts, _) = SenderRandomness::<C>::random(4, &mut rng)
            .encapsulate(&crs, SID, receiver(), &public_keys)
            .unwrap();

        // When
        let result = secrets.decapsulate(SID, &public_keys[..3], sender(), &ciphertexts);

        // Then
        assert!(matches!(result, Err(ProtocolError::AssertionFailed(_))));
    }

    /// Shows why the string must be messy: in decryption mode, a receiver
    /// holding the trapdoor recovers the key of the branch it did not choose.
    #[test]
    fn decapsulate__should_open_both_keys_under_a_decryption_mode_string() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let (crs, trapdoor) = Crs::<C>::decryption_mode_with_trapdoor(&mut rng);
        let secrets = ReceiverSecrets::<C>::random(20, &mut rng);
        let public_keys = secrets.public_keys(&crs);
        let (ciphertexts, sender_output) = SenderRandomness::<C>::random(20, &mut rng)
            .encapsulate(&crs, SID, receiver(), &public_keys)
            .unwrap();

        // When
        let other_branch = ReceiverSecrets::<C> {
            choices: secrets.choices.iter().map(|choice| choice ^ 1).collect(),
            exponents: secrets
                .choices
                .iter()
                .zip(&secrets.exponents)
                .map(|(&choice, &exponent)| trapdoor.exponent_on_other_branch(choice, exponent))
                .collect(),
        };
        let other_output = other_branch
            .decapsulate(SID, &public_keys, sender(), &ciphertexts)
            .unwrap();

        // Then
        let sender_keys = sender_output.k0.rows().zip(sender_output.k1.rows());
        let other_keys = other_output.choices.iter().zip(other_output.keys.rows());
        for ((k0, k1), (&choice, key)) in sender_keys.zip(other_keys) {
            assert_eq!(*key, BitVector::conditional_select(k0, k1, choice));
        }
    }

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
