use elliptic_curve::scalar::IsHigh;
use subtle::ConditionallySelectable;

use super::PresignOutput;
use crate::{
    ecdsa::{x_coordinate, AffinePoint, FullSignature, Scalar, Secp256K1Sha256},
    participants::{ParticipantCounter, ParticipantList},
    protocol::{
        errors::{InitializationError, ProtocolError},
        internal::{make_protocol, Comms, SharedChannel},
        Participant, Protocol,
    },
};

async fn do_sign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    public_key: AffinePoint,
    presignature: PresignOutput,
    msg_hash: Scalar,
) -> Result<FullSignature, ProtocolError> {
    // Spec 1.1
    let lambda = participants.lagrange::<Secp256K1Sha256>(me)?;
    let k_i = lambda * presignature.k;

    // Spec 1.2
    let sigma_i = lambda * presignature.sigma;

    // Spec 1.3
    let r = x_coordinate(&presignature.big_r);
    let s_i = msg_hash * k_i + r * sigma_i;

    // Spec 1.4
    let wait0 = chan.next_waitpoint();
    chan.send_many(wait0, &s_i)?;

    // Spec 2.1 + 2.2
    let mut seen = ParticipantCounter::new(&participants);
    let mut s = s_i;
    seen.put(me);
    while !seen.full() {
        let (from, s_j): (_, Scalar) = chan.recv(wait0).await?;
        if !seen.put(from) {
            continue;
        }
        s += s_j
    }

    // Spec 2.3
    // Optionally, normalize s
    s.conditional_assign(&(-s), s.is_high());

    let sig = FullSignature {
        big_r: presignature.big_r,
        s,
    };
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }

    // Spec 2.4
    Ok(sig)
}

/// The signature protocol, allowing us to use a presignature to sign a message.
///
/// **WARNING** You must absolutely hash an actual message before passing it to
/// this function. Allowing the signing of arbitrary scalars *is* a security risk,
/// and this function only tolerates this risk to allow for genericity.
pub fn sign(
    participants: &[Participant],
    me: Participant,
    public_key: AffinePoint,
    presignature: PresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = FullSignature>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };

    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    })?;

    if !participants.contains(me) {
        return Err(InitializationError::BadParameters(
            "participant list does not contain me".to_string(),
        ));
    };

    let ctx = Comms::new();
    let fut = do_sign(
        ctx.shared_channel(),
        participants,
        me,
        public_key,
        presignature,
        msg_hash,
    );
    Ok(make_protocol(ctx, fut))
}

#[cfg(test)]
mod test {
    use super::{sign, x_coordinate, FullSignature, PresignOutput};
    use crate::crypto::hash::test::scalar_hash;
    use crate::{
        ecdsa::Polynomial,
        protocol::{run_protocol, Participant, Protocol},
    };
    use ecdsa::Signature;
    use k256::{ecdsa::signature::Verifier, ecdsa::VerifyingKey, ProjectivePoint, PublicKey};
    use rand_core::OsRng;
    use std::error::Error;

    #[test]
    fn test_sign() -> Result<(), Box<dyn Error>> {
        let threshold = 2;
        let msg = b"hello?";

        for _ in 0..100 {
            let f = Polynomial::generate_polynomial(None, threshold - 1, &mut OsRng)?;
            let x = f.eval_at_zero().unwrap().0;
            let public_key = (ProjectivePoint::GENERATOR * x).to_affine();

            let g = Polynomial::generate_polynomial(None, threshold - 1, &mut OsRng)?;

            let k = g.eval_at_zero().unwrap().0;
            let big_k = (ProjectivePoint::GENERATOR * k.invert().unwrap()).to_affine();

            let sigma = k * x;

            let h = Polynomial::generate_polynomial(Some(sigma), threshold - 1, &mut OsRng)?;

            let participants = vec![Participant::from(0u32), Participant::from(1u32)];
            #[allow(clippy::type_complexity)]
            let mut protocols: Vec<(
                Participant,
                Box<dyn Protocol<Output = FullSignature>>,
            )> = Vec::with_capacity(participants.len());
            for p in &participants {
                let presignature = PresignOutput {
                    big_r: big_k,
                    k: g.eval_at_participant(*p).unwrap().0,
                    sigma: h.eval_at_participant(*p).unwrap().0,
                };
                let protocol = sign(
                    &participants,
                    *p,
                    public_key,
                    presignature,
                    scalar_hash(msg),
                )?;
                protocols.push((*p, Box::new(protocol)));
            }

            let result = run_protocol(protocols)?;
            let sig = result[0].1.clone();
            let sig = Signature::from_scalars(x_coordinate(&sig.big_r), sig.s)?;
            VerifyingKey::from(&PublicKey::from_affine(public_key).unwrap())
                .verify(&msg[..], &sig)?;
        }
        Ok(())
    }
}
