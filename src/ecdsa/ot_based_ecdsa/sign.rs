use elliptic_curve::scalar::IsHigh;
use subtle::ConditionallySelectable;

use super::PresignOutput;
use crate::{
    ecdsa::{x_coordinate, AffinePoint, Scalar, Secp256K1Sha256, Signature},
    participants::{ParticipantCounter, ParticipantList},
    protocol::{
        errors::{InitializationError, ProtocolError},
        internal::{make_protocol, Comms, SharedChannel},
        Participant, Protocol,
    },
};

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
) -> Result<impl Protocol<Output = Signature>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    };

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
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

async fn do_sign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    public_key: AffinePoint,
    presignature: PresignOutput,
    msg_hash: Scalar,
) -> Result<Signature, ProtocolError> {
    // Round 1
    // Linearize ki
    // Spec 1.1
    let lambda = participants.lagrange::<Secp256K1Sha256>(me)?;
    let k_i = lambda * presignature.k;

    // Linearize sigmai
    // Spec 1.2
    let sigma_i = lambda * presignature.sigma;

    // Compute si = h * ki + Rx * sigmai
    // Spec 1.3
    let r = x_coordinate(&presignature.big_r);
    let s_i = msg_hash * k_i + r * sigma_i;

    // Send si
    // Spec 1.4
    let wait0 = chan.next_waitpoint();
    chan.send_many(wait0, &s_i)?;

    // Receive sj
    // Spec 1.5
    let mut seen = ParticipantCounter::new(&participants);
    let mut s = s_i;
    seen.put(me);
    while !seen.full() {
        let (from, s_j): (_, Scalar) = chan.recv(wait0).await?;
        if !seen.put(from) {
            continue;
        }
        // Spec 1.6
        s += s_j
    }

    // Normalize s
    // Spec 1.7
    s.conditional_assign(&(-s), s.is_high());

    let sig = Signature {
        big_r: presignature.big_r,
        s,
    };

    // Spec 1.8
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }

    Ok(sig)
}

#[cfg(test)]
mod test {
    use super::{x_coordinate, PresignOutput};
    use crate::{
        ecdsa::ot_based_ecdsa::test::run_sign, ecdsa::Polynomial, test::generate_participants,
    };
    use k256::{ecdsa::signature::Verifier, ecdsa::VerifyingKey, ProjectivePoint, PublicKey};
    use rand_core::OsRng;
    use std::error::Error;

    #[test]
    fn test_sign() -> Result<(), Box<dyn Error>> {
        let threshold = 2;
        let msg = b"Hello? Is it me you're looking for?";

        let f = Polynomial::generate_polynomial(None, threshold - 1, &mut OsRng)?;
        let x = f.eval_at_zero()?.0;
        let public_key = ProjectivePoint::GENERATOR * x;

        let g = Polynomial::generate_polynomial(None, threshold - 1, &mut OsRng)?;

        let k = g.eval_at_zero()?.0;
        let big_k = (ProjectivePoint::GENERATOR * k.invert().unwrap()).to_affine();

        let sigma = k * x;

        let h = Polynomial::generate_polynomial(Some(sigma), threshold - 1, &mut OsRng)?;

        let participants = generate_participants(2);

        let mut participants_presign = Vec::new();
        for p in &participants {
            let presignature = PresignOutput {
                big_r: big_k,
                k: g.eval_at_participant(*p)?.0,
                sigma: h.eval_at_participant(*p)?.0,
            };
            participants_presign.push((*p, presignature));
        }

        let result = run_sign(participants_presign, public_key, msg)?;
        let sig = &result[0].1;
        let sig = ecdsa::Signature::from_scalars(x_coordinate(&sig.big_r), sig.s)?;
        VerifyingKey::from(&PublicKey::from_affine(public_key.to_affine())?).verify(msg, &sig)?;
        Ok(())
    }
}
