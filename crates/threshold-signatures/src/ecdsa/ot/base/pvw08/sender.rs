use frost_core::{Field, Group, keys::CoefficientCommitment};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    crs::Crs,
    kdf::{derive_key, serialize},
    receiver::ReceiverPublicKey,
};
use crate::{
    Ciphersuite, Element, Scalar,
    ecdsa::ot::bits::{BitMatrix, BitVector},
    errors::ProtocolError,
    participants::Participant,
};

/// The sender's secret exponents for a batch of transfers.
#[derive(ZeroizeOnDrop)]
pub struct SenderRandomness<C: Ciphersuite>
where
    Scalar<C>: Zeroize,
{
    /// For every transfer, the pair `(s, t)` of branch 0 and of branch 1.
    exponents: Vec<[(Scalar<C>, Scalar<C>); 2]>,
}

impl<C: Ciphersuite> SenderRandomness<C>
where
    Scalar<C>: Zeroize,
{
    /// Samples independent exponents for both branches of `batch_size` transfers.
    pub fn random(batch_size: usize, rng: &mut impl CryptoRngCore) -> Self {
        let mut scalar = || <<C::Group as Group>::Field as Field>::random(rng);
        let exponents = (0..batch_size)
            .map(|_| [(scalar(), scalar()), (scalar(), scalar())])
            .collect();
        Self { exponents }
    }

    /// Computes the sender's message and its two keys for every transfer.
    ///
    /// `public_keys` is the message received from `receiver`. It is rejected
    /// if it does not hold one key per transfer, or holds the identity.
    pub fn encapsulate(
        &self,
        crs: &Crs<C>,
        sid: &[u8],
        receiver: Participant,
        public_keys: &[ReceiverPublicKey<C>],
    ) -> Result<(Vec<SenderCiphertext<C>>, SenderOutput), ProtocolError>
    where
        Element<C>: ConditionallySelectable,
    {
        if public_keys.len() != self.exponents.len() {
            return Err(ProtocolError::UnexpectedLength {
                expected: self.exponents.len(),
                actual: public_keys.len(),
                participant: receiver,
            });
        }

        let identity = <C::Group as Group>::identity();
        let mut ciphertexts = Vec::with_capacity(public_keys.len());
        let mut k0 = Vec::with_capacity(public_keys.len());
        let mut k1 = Vec::with_capacity(public_keys.len());

        for (index, (public_key, [branch0, branch1])) in
            public_keys.iter().zip(&self.exponents).enumerate()
        {
            let (p, q) = (public_key.p.value(), public_key.q.value());
            // The identity pair is consistent with both branches of the
            // string, so it would open both keys.
            if p == identity || q == identity {
                return Err(ProtocolError::IdentityElement);
            }
            let p_bytes = serialize::<C>(&p)?;
            let q_bytes = serialize::<C>(&q)?;

            let encapsulate = |branch: u8, (s, t): (Scalar<C>, Scalar<C>)| {
                let (g, h) = crs.branch(Choice::from(branch));
                let u = g * s + h * t;
                let v = p * s + q * t;
                let key: BitVector = derive_key(
                    sid,
                    index,
                    branch,
                    p_bytes.as_ref(),
                    q_bytes.as_ref(),
                    serialize::<C>(&u)?.as_ref(),
                    serialize::<C>(&v)?.as_ref(),
                )?;
                Ok::<_, ProtocolError>((CoefficientCommitment::new(u), key))
            };
            let (u0, key0) = encapsulate(0, *branch0)?;
            let (u1, key1) = encapsulate(1, *branch1)?;

            ciphertexts.push(SenderCiphertext { u0, u1 });
            k0.push(key0);
            k1.push(key1);
        }

        let output = SenderOutput {
            k0: k0.into_iter().collect(),
            k1: k1.into_iter().collect(),
        };
        Ok((ciphertexts, output))
    }
}

/// The sender's message for one transfer. Deserialization rejects the
/// identity.
#[derive(Serialize, Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct SenderCiphertext<C: Ciphersuite> {
    pub(super) u0: CoefficientCommitment<C>,
    pub(super) u1: CoefficientCommitment<C>,
}

/// The sender's two keys for every transfer: row `i` of `k0` and of `k1`.
#[derive(Debug)]
pub struct SenderOutput {
    pub k0: BitMatrix,
    pub k1: BitMatrix,
}

#[cfg(test)]
#[expect(non_snake_case)]
mod test {
    use rand::SeedableRng;

    use super::*;
    use crate::{
        ecdsa::{Secp256K1Group, Secp256K1Sha256, ot::base::pvw08::ReceiverSecrets},
        test_utils::MockCryptoRng,
    };

    type C = Secp256K1Sha256;

    const SID: &[u8] = b"session";

    fn receiver() -> Participant {
        Participant::from(1u32)
    }

    fn setup(batch_size: usize) -> (Crs<C>, Vec<ReceiverPublicKey<C>>, SenderRandomness<C>) {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let crs = Crs::<C>::derive(SID).unwrap();
        let public_keys = ReceiverSecrets::<C>::random(batch_size, &mut rng).public_keys(&crs);
        let randomness = SenderRandomness::<C>::random(batch_size, &mut rng);
        (crs, public_keys, randomness)
    }

    #[test]
    fn encapsulate__should_output_two_distinct_keys_per_transfer() {
        // Given
        let batch_size = 50;
        let (crs, public_keys, randomness) = setup(batch_size);

        // When
        let (ciphertexts, output) = randomness
            .encapsulate(&crs, SID, receiver(), &public_keys)
            .unwrap();

        // Then
        assert_eq!(ciphertexts.len(), batch_size);
        assert_eq!(output.k0.height(), batch_size);
        assert_eq!(output.k1.height(), batch_size);
        let keys: Vec<_> = output.k0.rows().chain(output.k1.rows()).collect();
        for (i, key) in keys.iter().enumerate() {
            assert!(!keys.iter().skip(i + 1).any(|other| other == key));
        }
    }

    #[test]
    fn encapsulate__should_bind_the_keys_to_the_sid() {
        // Given
        let (crs, public_keys, randomness) = setup(4);

        // When
        let (_, output) = randomness
            .encapsulate(&crs, SID, receiver(), &public_keys)
            .unwrap();
        let (_, other_output) = randomness
            .encapsulate(&crs, b"other session", receiver(), &public_keys)
            .unwrap();

        // Then
        for (key, other_key) in output.k0.rows().zip(other_output.k0.rows()) {
            assert_ne!(key, other_key);
        }
    }

    #[test]
    fn encapsulate__should_reject_a_batch_of_the_wrong_length() {
        // Given
        let (crs, mut public_keys, randomness) = setup(4);
        public_keys.pop();

        // When
        let result = randomness.encapsulate(&crs, SID, receiver(), &public_keys);

        // Then
        assert_eq!(
            result.err(),
            Some(ProtocolError::UnexpectedLength {
                expected: 4,
                actual: 3,
                participant: receiver(),
            })
        );
    }

    #[test]
    fn encapsulate__should_reject_the_identity_as_first_point() {
        // Given
        let (crs, mut public_keys, randomness) = setup(4);
        public_keys[2].p = CoefficientCommitment::new(Secp256K1Group::identity());

        // When
        let result = randomness.encapsulate(&crs, SID, receiver(), &public_keys);

        // Then
        assert_eq!(result.err(), Some(ProtocolError::IdentityElement));
    }

    #[test]
    fn encapsulate__should_reject_the_identity_as_second_point() {
        // Given
        let (crs, mut public_keys, randomness) = setup(4);
        public_keys[2].q = CoefficientCommitment::new(Secp256K1Group::identity());

        // When
        let result = randomness.encapsulate(&crs, SID, receiver(), &public_keys);

        // Then
        assert_eq!(result.err(), Some(ProtocolError::IdentityElement));
    }

    #[test]
    fn encapsulate__should_match_snapshot() {
        // Given
        let (crs, public_keys, randomness) = setup(2);

        // When
        let (ciphertexts, output) = randomness
            .encapsulate(&crs, SID, receiver(), &public_keys)
            .unwrap();

        // Then
        insta::assert_json_snapshot!((ciphertexts, output.k0, output.k1));
    }
}
