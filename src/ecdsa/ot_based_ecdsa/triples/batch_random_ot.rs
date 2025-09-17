use k256::Scalar;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConditionallySelectable;

use crate::{
    ecdsa::{
        ot_based_ecdsa::triples::bits::SEC_PARAM_64, CoefficientCommitment, Field, ProjectivePoint,
        Secp256K1ScalarField,
    },
    protocol::{errors::ProtocolError, internal::PrivateChannel},
};

use super::bits::{BitMatrix, BitVector, SquareBitMatrix, SEC_PARAM_8};
use super::constants::SECURITY_PARAMETER;

const BATCH_RANDOM_OT_HASH: &[u8] = b"Near threshold signatures batch ROT";

fn hash(
    i: usize,
    big_x_i: &CoefficientCommitment,
    big_y: &CoefficientCommitment,
    p: &CoefficientCommitment,
) -> Result<BitVector, ProtocolError> {
    let mut hasher = Sha256::new();
    hasher.update(BATCH_RANDOM_OT_HASH);
    hasher.update((i as u64).to_le_bytes());
    hasher.update(
        &big_x_i
            .serialize()
            .map_err(|_| ProtocolError::PointSerialization)?,
    );
    hasher.update(
        &big_y
            .serialize()
            .map_err(|_| ProtocolError::PointSerialization)?,
    );
    hasher.update(
        &p.serialize()
            .map_err(|_| ProtocolError::PointSerialization)?,
    );

    let bytes: [u8; 32] = hasher.finalize().into();
    // the hash output is 256 bits
    // it is possible to take the first 128 bits out
    let bytes: [u8; SEC_PARAM_8] = bytes[0..SEC_PARAM_8].try_into().unwrap();

    Ok(BitVector::from_bytes(&bytes))
}

pub(crate) type BatchRandomOTOutputSender = (SquareBitMatrix, SquareBitMatrix);

pub(crate) fn batch_random_ot_sender_helper(rng: &mut impl CryptoRngCore) -> Scalar {
    Secp256K1ScalarField::random(rng)
}

pub(crate) async fn batch_random_ot_sender(
    mut chan: PrivateChannel,
    y: Scalar,
) -> Result<BatchRandomOTOutputSender, ProtocolError> {
    // Spec 1
    // let y = Secp256K1ScalarField::random(rng);
    let big_y = ProjectivePoint::GENERATOR * y;
    let big_z = big_y * y;

    // One way to be able to serialize and send big_y a verifying key out of it
    // as it contains a private struct SerializableElement
    let ser_big_y = CoefficientCommitment::new(big_y);
    let wait0 = chan.next_waitpoint();
    chan.send(wait0, &ser_big_y)?;

    let tasks = (0..SECURITY_PARAMETER).map(|i| {
        let mut chan = chan.child(i as u64);
        async move {
            let wait0 = chan.next_waitpoint();
            let ser_big_x_i: CoefficientCommitment = chan.recv(wait0).await?;

            let y_big_x_i = ser_big_x_i.value() * y;

            let big_k0 = hash(
                i,
                &ser_big_x_i,
                &ser_big_y,
                &CoefficientCommitment::new(y_big_x_i),
            )?;
            let big_k1 = hash(
                i,
                &ser_big_x_i,
                &ser_big_y,
                &CoefficientCommitment::new(y_big_x_i - big_z),
            )?;

            Ok::<_, ProtocolError>((big_k0, big_k1))
        }
    });
    let out: Vec<(BitVector, BitVector)> = futures::future::try_join_all(tasks).await?;

    let big_k0: BitMatrix = out.iter().map(|r| r.0).collect();
    let big_k1: BitMatrix = out.iter().map(|r| r.1).collect();
    Ok((big_k0.try_into().unwrap(), big_k1.try_into().unwrap()))
}

#[allow(dead_code)]
pub(crate) async fn batch_random_ot_sender_many<const N: usize>(
    mut chan: PrivateChannel,
    mut rng: impl CryptoRngCore,
) -> Result<Vec<BatchRandomOTOutputSender>, ProtocolError> {
    assert!(N > 0);
    let mut big_y_v = vec![];
    let mut big_z_v = vec![];
    let mut yv = vec![];
    for _ in 0..N {
        // Spec 1
        let y = Secp256K1ScalarField::random(&mut rng);
        let big_y = ProjectivePoint::GENERATOR * y;
        let big_z = big_y * y;
        yv.push(y);
        big_y_v.push(big_y);
        big_z_v.push(big_z);
    }

    let wait0 = chan.next_waitpoint();
    let mut big_y_ser_v = vec![];
    for big_y_verkey in big_y_v.iter() {
        big_y_ser_v.push(CoefficientCommitment::new(*big_y_verkey));
    }
    chan.send(wait0, &big_y_ser_v)?;

    let y_v_arc = Arc::new(yv);
    let big_y_verkey_v_arc = Arc::new(big_y_ser_v);
    let big_z_v_arc = Arc::new(big_z_v);
    let tasks = (0..SECURITY_PARAMETER).map(|i| {
        let yv_arc = y_v_arc.clone();
        let big_y_verkey_v_arc = big_y_verkey_v_arc.clone();
        let big_z_v_arc = big_z_v_arc.clone();
        let mut chan = chan.child(i as u64);
        async move {
            let wait0 = chan.next_waitpoint();
            let big_x_i_verkey_v: Vec<CoefficientCommitment> = chan.recv(wait0).await?;

            let mut ret = vec![];
            for (j, big_x_i_verkey_v_j) in big_x_i_verkey_v.iter().enumerate().take(N) {
                let y = &yv_arc.as_slice()[j];
                let big_y_verkey = &big_y_verkey_v_arc.as_slice()[j];
                let big_z = &big_z_v_arc.as_slice()[j];
                let y_big_x_i = big_x_i_verkey_v_j.value() * *y;
                let big_k0 = hash(
                    i,
                    big_x_i_verkey_v_j,
                    big_y_verkey,
                    &CoefficientCommitment::new(y_big_x_i),
                )?;
                let big_k1 = hash(
                    i,
                    big_x_i_verkey_v_j,
                    big_y_verkey,
                    &CoefficientCommitment::new(y_big_x_i - big_z),
                )?;
                ret.push((big_k0, big_k1));
            }

            Ok::<_, ProtocolError>(ret)
        }
    });
    let outs: Vec<Vec<(BitVector, BitVector)>> = futures::future::try_join_all(tasks).await?;
    // batch dimension is on the inside but needs to be on the outside
    let mut reshaped_outs: Vec<Vec<_>> = Vec::new();
    for _ in 0..N {
        reshaped_outs.push(Vec::new());
    }
    for outsi in outs {
        for j in 0..N {
            reshaped_outs[j].push(outsi[j])
        }
    }
    let outs = reshaped_outs;
    let mut ret = vec![];
    for out in outs.iter().take(N) {
        let big_k0: BitMatrix = out.iter().map(|r| r.0).collect();
        let big_k1: BitMatrix = out.iter().map(|r| r.1).collect();
        ret.push((big_k0.try_into().unwrap(), big_k1.try_into().unwrap()));
    }

    Ok(ret)
}

pub(crate) type BatchRandomOTOutputReceiver = (BitVector, SquareBitMatrix);

pub(crate) fn batch_random_ot_receiver_random_helper(
    rng: &mut impl CryptoRngCore,
) -> (BitVector, [Scalar; SEC_PARAM_64 * 64]) {
    let random_delta = BitVector::random(rng);
    let mut random_x = [Scalar::ZERO; SEC_PARAM_64 * 64];
    for random_x_i in random_x.iter_mut().take(SEC_PARAM_64 * 64) {
        *random_x_i = Secp256K1ScalarField::random(rng);
    }
    (random_delta, random_x)
}

pub(crate) async fn batch_random_ot_receiver(
    mut chan: PrivateChannel,
    delta: BitVector,
    x: [Scalar; SEC_PARAM_64 * 64],
) -> Result<BatchRandomOTOutputReceiver, ProtocolError> {
    // Step 3
    let wait0 = chan.next_waitpoint();
    // deserialization prevents receiving the identity
    let big_y_verkey: CoefficientCommitment = chan.recv(wait0).await?;
    let big_y = big_y_verkey.value();
    // let delta = BitVector::random(&mut rng);

    let out = delta
        .bits()
        .enumerate()
        .map(|(i, d_i)| {
            let mut chan = chan.child(i as u64);
            // Step 4
            // let x_i = Secp256K1ScalarField::random(&mut rng);
            let x_i = x[i];
            let mut big_x_i = ProjectivePoint::GENERATOR * x_i;
            big_x_i.conditional_assign(&(big_x_i + big_y), d_i);

            // Step 6
            let wait0 = chan.next_waitpoint();
            let big_x_i_verkey = CoefficientCommitment::new(big_x_i);
            chan.send(wait0, &big_x_i_verkey)?;

            // Step 5
            hash(
                i,
                &big_x_i_verkey,
                &big_y_verkey,
                &CoefficientCommitment::new(big_y * x_i),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let big_k: BitMatrix = out.into_iter().collect();
    Ok((delta, big_k.try_into().unwrap()))
}

#[allow(dead_code)]
pub(crate) async fn batch_random_ot_receiver_many<const N: usize>(
    mut chan: PrivateChannel,
    mut rng: impl CryptoRngCore,
) -> Result<Vec<BatchRandomOTOutputReceiver>, ProtocolError> {
    assert!(N > 0);
    // Step 3
    let wait0 = chan.next_waitpoint();
    // deserialization prevents receiving the identity
    let big_y_verkey_v: Vec<CoefficientCommitment> = chan.recv(wait0).await?;

    let mut big_y_v = vec![];
    let mut deltav = vec![];
    for big_y_verkey in big_y_verkey_v.iter() {
        let big_y = big_y_verkey.value();
        let delta = BitVector::random(&mut rng);
        big_y_v.push(big_y);
        deltav.push(delta);
    }

    let big_y_v_arc = Arc::new(big_y_v);
    let big_y_verkey_v_arc = Arc::new(big_y_verkey_v);

    // inner is batch, outer is bits
    let mut choices: Vec<Vec<_>> = Vec::new();
    for _ in deltav[0].bits() {
        choices.push(Vec::new());
    }
    for deltavj in deltav.iter().take(N) {
        for (i, d_i) in deltavj.bits().enumerate() {
            choices[i].push(d_i);
        }
    }
    // wrap in arc
    let choices: Vec<_> = choices.into_iter().map(Arc::new).collect();

    let mut outs: Vec<Vec<BitVector>> = Vec::new();
    for (i, choicesi) in choices.iter().enumerate() {
        let mut chan = chan.child(i as u64);
        // clone arcs
        let d_i_v = choicesi.clone();
        let big_y_v_arc = big_y_v_arc.clone();
        let big_y_verkey_v_arc = big_y_verkey_v_arc.clone();
        let hashv = {
            let mut x_i_v = Vec::new();
            let mut big_x_i_v = Vec::new();
            for j in 0..N {
                let d_i = d_i_v[j];
                // Step 4
                let x_i = Secp256K1ScalarField::random(&mut rng);
                let mut big_x_i = ProjectivePoint::GENERATOR * x_i;
                big_x_i.conditional_assign(&(big_x_i + big_y_v_arc[j]), d_i);
                x_i_v.push(x_i);
                big_x_i_v.push(big_x_i);
            }
            // Step 6
            let wait0 = chan.next_waitpoint();

            let mut big_x_i_verkey_v = Vec::new();
            for big_x_i_verkey in big_x_i_v.iter() {
                big_x_i_verkey_v.push(CoefficientCommitment::new(*big_x_i_verkey));
            }
            chan.send(wait0, &big_x_i_verkey_v)?;

            // Step 5
            let mut hashv = Vec::new();
            for j in 0..N {
                let big_x_i_verkey = big_x_i_verkey_v[j];
                let big_y_verkey = big_y_verkey_v_arc[j];
                let big_y = big_y_v_arc[j];
                let x_i = x_i_v[j];
                hashv.push(hash(
                    i,
                    &big_x_i_verkey,
                    &big_y_verkey,
                    &CoefficientCommitment::new(big_y * x_i),
                )?);
            }
            hashv
        };
        outs.push(hashv)
    }

    // batch dimension is on the inside but needs to be on the outside
    let mut reshaped_outs: Vec<Vec<_>> = Vec::new();
    for _ in 0..N {
        reshaped_outs.push(Vec::new());
    }
    for outsi in outs.iter() {
        for j in 0..N {
            reshaped_outs[j].push(outsi[j]);
        }
    }
    let outs = reshaped_outs;
    let mut ret = Vec::new();
    for j in 0..N {
        let delta = deltav[j];
        let out = &outs[j];
        let big_k: BitMatrix = out.iter().cloned().collect();
        let h = SquareBitMatrix::try_from(big_k);
        ret.push((delta, h.unwrap()))
    }
    Ok(ret)
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::ecdsa::ot_based_ecdsa::triples::test::run_batch_random_ot;
    use crate::protocol::{
        internal::{make_protocol, Comms},
        test::run_two_party_protocol,
        Participant,
    };
    use rand_core::OsRng;

    #[test]
    fn test_batch_random_ot() {
        let ((k0, k1), (delta, k_delta)) = run_batch_random_ot().unwrap();

        // Check that we've gotten the right rows of the two matrices.
        for (((row0, row1), delta_i), row_delta) in k0
            .matrix
            .rows()
            .zip(k1.matrix.rows())
            .zip(delta.bits())
            .zip(k_delta.matrix.rows())
        {
            assert_eq!(
                BitVector::conditional_select(row0, row1, delta_i),
                *row_delta
            );
        }
    }

    /// Run the batch random OT many protocol between two parties.
    fn run_batch_random_ot_many<const N: usize>() -> Result<
        (
            Vec<BatchRandomOTOutputSender>,
            Vec<BatchRandomOTOutputReceiver>,
        ),
        ProtocolError,
    > {
        let s = Participant::from(0u32);
        let r = Participant::from(1u32);
        let comms_s = Comms::new();
        let comms_r = Comms::new();

        run_two_party_protocol(
            s,
            r,
            &mut make_protocol(
                comms_s.clone(),
                batch_random_ot_sender_many::<N>(comms_s.private_channel(s, r), OsRng),
            ),
            &mut make_protocol(
                comms_r.clone(),
                batch_random_ot_receiver_many::<N>(comms_r.private_channel(r, s), OsRng),
            ),
        )
    }

    #[test]
    fn test_batch_random_ot_many() {
        const N: usize = 10;
        let (a, b) = run_batch_random_ot_many::<N>().unwrap();
        for i in 0..N {
            let ((k0, k1), (delta, k_delta)) = (&a[i], &b[i]);
            // Check that we've gotten the right rows of the two matrices.
            for (((row0, row1), delta_i), row_delta) in k0
                .matrix
                .rows()
                .zip(k1.matrix.rows())
                .zip(delta.bits())
                .zip(k_delta.matrix.rows())
            {
                assert_eq!(
                    BitVector::conditional_select(row0, row1, delta_i),
                    *row_delta
                );
            }
        }
    }
}
