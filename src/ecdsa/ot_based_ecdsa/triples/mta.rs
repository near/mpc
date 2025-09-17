use frost_core::{serialization::SerializableScalar, Field, Group};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use std::slice::Iter;
use subtle::{Choice, ConditionallySelectable};

use crate::{
    crypto::proofs::strobe_transcript::TranscriptRng,
    protocol::{errors::ProtocolError, internal::PrivateChannel},
};

use crate::ecdsa::{Scalar, Secp256K1Sha256};

type Secp256 = Secp256K1Sha256;

#[derive(Serialize, Deserialize)]
struct MTAScalars(Vec<(SerializableScalar<Secp256>, SerializableScalar<Secp256>)>);

impl MTAScalars {
    fn len(&self) -> usize {
        self.0.len()
    }

    fn iter(&self) -> Iter<'_, (SerializableScalar<Secp256>, SerializableScalar<Secp256>)> {
        self.0.iter()
    }
}

pub(crate) fn mta_sender_random_helper(size: usize, rng: &mut impl CryptoRngCore) -> Vec<Scalar> {
    (0..size)
        .map(|_| <<Secp256 as frost_core::Ciphersuite>::Group as Group>::Field::random(rng))
        .collect()
}

/// The sender for multiplicative to additive conversion.
pub(crate) async fn mta_sender(
    mut chan: PrivateChannel,
    v: Vec<(Scalar, Scalar)>,
    a: Scalar,
    delta: Vec<Scalar>,
) -> Result<Scalar, ProtocolError> {
    // Step 1
    // `delta` is computed in `mta_sender_random_helper`

    // Step 2
    let c: MTAScalars = MTAScalars(
        delta
            .iter()
            .zip(v.iter())
            .map(|(delta_i, (v0_i, v1_i))| {
                (
                    SerializableScalar(*v0_i + delta_i + a),
                    SerializableScalar(*v1_i + delta_i - a),
                )
            })
            .collect(),
    );
    let wait0 = chan.next_waitpoint();
    chan.send(wait0, &c)?;

    // Step 7
    let wait1 = chan.next_waitpoint();
    let (chi1, seed): (SerializableScalar<Secp256>, [u8; 32]) = chan.recv(wait1).await?;

    let mut alpha = delta[0] * chi1.0;

    let mut prng = TranscriptRng::new(&seed);
    for &delta_i in &delta[1..] {
        let chi_i =
            <<Secp256 as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut prng);
        alpha += delta_i * chi_i;
    }

    Ok(-alpha)
}

pub(crate) fn mta_receiver_random_helper(rng: &mut impl CryptoRngCore) -> [u8; 32] {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    seed
}

/// The receiver for multiplicative to additive conversion.
pub(crate) async fn mta_receiver(
    mut chan: PrivateChannel,
    tv: Vec<(Choice, Scalar)>,
    b: Scalar,
    seed: [u8; 32],
) -> Result<Scalar, ProtocolError> {
    let size = tv.len();

    // Step 3
    let wait0 = chan.next_waitpoint();
    let c: MTAScalars = chan.recv(wait0).await?;
    if c.len() != tv.len() {
        return Err(ProtocolError::AssertionFailed(
            "length of c was incorrect".to_owned(),
        ));
    }
    let mut m = tv
        .iter()
        .zip(c.iter())
        .map(|((t_i, v_i), (c0_i, c1_i))| Scalar::conditional_select(&c0_i.0, &c1_i.0, *t_i) - v_i);

    // Step 4
    // `seed` generated in `mta_receiver_random_helper`
    let mut prng = TranscriptRng::new(&seed);
    let chi: Vec<Scalar> = (1..size)
        .map(|_| <<Secp256 as frost_core::Ciphersuite>::Group as Group>::Field::random(&mut prng))
        .collect();

    let mut chi1 = Scalar::ZERO;
    for ((t_i, _), &chi_i) in tv.iter().skip(1).zip(chi.iter()) {
        chi1 += Scalar::conditional_select(&chi_i, &(-chi_i), *t_i);
    }
    chi1 = b - chi1;
    chi1.conditional_assign(&(-chi1), tv[0].0);

    // Step 5
    let mut beta = chi1 * m.next().unwrap();
    for (&chi_i, m_i) in chi.iter().zip(m) {
        beta += chi_i * m_i;
    }

    // Step 6
    let wait1 = chan.next_waitpoint();
    let chi1 = SerializableScalar::<Secp256>(chi1);
    chan.send(wait1, &(chi1, seed))?;

    Ok(beta)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ecdsa::ot_based_ecdsa::triples::constants::{BITS, SECURITY_PARAMETER};
    use crate::protocol::internal::Comms;
    use k256::Scalar;
    use rand_core::{OsRng, RngCore};

    use crate::protocol::{
        errors::ProtocolError, internal::make_protocol, test::run_two_party_protocol, Participant,
    };

    /// Run the multiplicative to additive protocol
    fn run_mta(
        (v, a): (Vec<(Scalar, Scalar)>, Scalar),
        (tv, b): (Vec<(Choice, Scalar)>, Scalar),
    ) -> Result<(Scalar, Scalar), ProtocolError> {
        let s = Participant::from(0u32);
        let r = Participant::from(1u32);
        let ctx_s = Comms::new();
        let ctx_r = Comms::new();

        run_two_party_protocol(
            s,
            r,
            &mut make_protocol(ctx_s.clone(), {
                let delta = mta_sender_random_helper(v.len(), &mut OsRng);
                mta_sender(ctx_s.private_channel(s, r), v, a, delta)
            }),
            &mut make_protocol(ctx_r.clone(), {
                let seed = mta_receiver_random_helper(&mut OsRng);
                mta_receiver(ctx_r.private_channel(r, s), tv, b, seed)
            }),
        )
    }

    #[test]
    fn test_mta() -> Result<(), ProtocolError> {
        let batch_size = BITS + SECURITY_PARAMETER;

        let v: Vec<_> = (0..batch_size)
            .map(|_| {
                (
                    Scalar::generate_biased(&mut OsRng),
                    Scalar::generate_biased(&mut OsRng),
                )
            })
            .collect();
        let tv: Vec<_> = v
            .iter()
            .map(|(v0, v1)| {
                let c = Choice::from((OsRng.next_u64() & 1) as u8);
                (c, Scalar::conditional_select(v0, v1, c))
            })
            .collect();

        let a = Scalar::generate_biased(&mut OsRng);
        let b = Scalar::generate_biased(&mut OsRng);
        let (alpha, beta) = run_mta((v, a), (tv, b))?;

        assert_eq!(a * b, alpha + beta);

        Ok(())
    }
}
