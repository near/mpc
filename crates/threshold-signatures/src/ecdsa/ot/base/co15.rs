use k256::Scalar;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use subtle::ConditionallySelectable;

use crate::{
    crypto::constants::NEAR_BATCH_RANDOM_OT_HASH,
    ecdsa::{
        CoefficientCommitment, Field, ProjectivePoint, Secp256K1ScalarField, ot::bits::SEC_PARAM_64,
    },
    errors::ProtocolError,
    protocol::internal::PrivateChannel,
};

use crate::crypto::constants::SECURITY_PARAMETER;
use crate::ecdsa::ot::bits::{BitMatrix, BitVector, SEC_PARAM_8, SquareBitMatrix};

fn hash(
    i: usize,
    big_x_i: &CoefficientCommitment,
    big_y: &CoefficientCommitment,
    p: &CoefficientCommitment,
) -> Result<BitVector, ProtocolError> {
    let mut hasher = Sha256::new();
    hasher.update(NEAR_BATCH_RANDOM_OT_HASH);
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
    let bytes: [u8; SEC_PARAM_8] = bytes[0..SEC_PARAM_8]
        .try_into()
        .expect("the hash output is 256 bits, so it is possible to take the first 128 bits out");

    Ok(BitVector::from_bytes(&bytes))
}

pub type BatchRandomOTOutputSender = (SquareBitMatrix, SquareBitMatrix);

/// Generates the random values needed in `batch_random_ot_sender`
pub fn batch_random_ot_sender_helper(rng: &mut impl CryptoRngCore) -> Scalar {
    Secp256K1ScalarField::random(rng)
}

pub async fn batch_random_ot_sender(
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

    let big_k0 = big_k0
        .try_into()
        .map_err(|err| ProtocolError::AssertionFailed(format!("{err:?}")))?;
    let big_k1 = big_k1
        .try_into()
        .map_err(|err| ProtocolError::AssertionFailed(format!("{err:?}")))?;
    Ok((big_k0, big_k1))
}

pub type BatchRandomOTOutputReceiver = (BitVector, SquareBitMatrix);

/// Generates the random values needed in `batch_random_ot_receiver`
pub fn batch_random_ot_receiver_random_helper(
    rng: &mut impl CryptoRngCore,
) -> (BitVector, [Scalar; SEC_PARAM_64 * 64]) {
    let random_delta = BitVector::random(rng);
    let mut random_x = [Scalar::ZERO; SEC_PARAM_64 * 64];
    for random_x_i in random_x.iter_mut().take(SEC_PARAM_64 * 64) {
        *random_x_i = Secp256K1ScalarField::random(rng);
    }
    (random_delta, random_x)
}

// Fixing this one breaks a test
#[allow(clippy::large_types_passed_by_value)]
pub async fn batch_random_ot_receiver(
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

    let mut out = Vec::with_capacity(SEC_PARAM_64 * 64);
    for (i, (d_i, &x_i)) in delta.bits().zip(x.iter()).enumerate() {
        let mut sub_chan =
            chan.child(u64::try_from(i).map_err(|_| ProtocolError::IntegerOverflow)?);
        let mut big_x_i = ProjectivePoint::GENERATOR * x_i;
        big_x_i.conditional_assign(&(big_x_i + big_y), d_i);

        // Step 6
        let wait0 = sub_chan.next_waitpoint();
        let big_x_i_verkey = CoefficientCommitment::new(big_x_i);
        sub_chan.send(wait0, &big_x_i_verkey)?;

        // Step 5
        out.push(hash(
            i,
            &big_x_i_verkey,
            &big_y_verkey,
            &CoefficientCommitment::new(big_y * x_i),
        )?);

        chan.yield_point().await;
    }
    let big_k: BitMatrix = out.into_iter().collect();
    let big_k = big_k
        .try_into()
        .map_err(|err| ProtocolError::AssertionFailed(format!("{err:?}")))?;
    Ok((delta, big_k))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ecdsa::ot::test::run_batch_random_ot;

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
}
