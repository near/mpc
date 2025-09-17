use elliptic_curve::scalar::IsHigh;

use frost_core::serialization::SerializableScalar;
use subtle::ConditionallySelectable;

use super::PresignOutput;
use crate::{
    ecdsa::{AffinePoint, Polynomial, Scalar, Secp256K1Sha256, Signature},
    participants::{ParticipantCounter, ParticipantList, ParticipantMap},
    protocol::{
        errors::{InitializationError, ProtocolError},
        internal::{make_protocol, Comms, SharedChannel},
        Participant, Protocol,
    },
};
type C = Secp256K1Sha256;

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
    let s_me = msg_hash * presignature.alpha_i + presignature.beta_i;
    let s_me = SerializableScalar(s_me);

    let wait_round = chan.next_waitpoint();
    chan.send_many(wait_round, &s_me)?;

    let mut seen = ParticipantCounter::new(&participants);
    let mut s_map = ParticipantMap::new(&participants);
    s_map.put(me, s_me);

    seen.put(me);
    while !seen.full() {
        let (from, s_i): (_, SerializableScalar<C>) = chan.recv(wait_round).await?;
        if !seen.put(from) {
            continue;
        }
        s_map.put(from, s_i);
    }

    let identifiers: Vec<Scalar> = s_map
        .participants()
        .iter()
        .map(|p| p.scalar::<C>())
        .collect();

    let sshares = s_map
        .into_vec_or_none()
        .ok_or(ProtocolError::InvalidInterpolationArguments)?;

    // interpolate s
    let mut s = Polynomial::eval_interpolation(&identifiers, &sshares, None)?.0;
    // raise error if s is zero
    if s.is_zero().into() {
        return Err(ProtocolError::AssertionFailed(
            "signature part s cannot be zero".to_string(),
        ));
    }
    // Normalize s
    s.conditional_assign(&(-s), s.is_high());

    let big_r = presignature.big_r;
    let sig = Signature { big_r, s };

    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    };

    Ok(sig)
}

#[cfg(test)]
mod test {
    use std::error::Error;

    use k256::{ecdsa::signature::Verifier, ecdsa::VerifyingKey, PublicKey};
    use rand_core::OsRng;

    use super::*;
    use crate::ecdsa::{
        robust_ecdsa::test::run_sign, x_coordinate, Field, ProjectivePoint, Secp256K1ScalarField,
    };
    use crate::test::generate_participants;

    #[test]
    fn test_sign_given_presignature() -> Result<(), Box<dyn Error>> {
        let max_malicious = 2;
        let msg = b"Hello? Is it me you're looking for?";

        // Manually compute presignatures then deliver them to the signing function
        let fx = Polynomial::generate_polynomial(None, max_malicious, &mut OsRng)?;
        // master secret key
        let x = fx.eval_at_zero()?.0;
        // master public key
        let public_key = ProjectivePoint::GENERATOR * x;

        // the presignatures scheme requires the generation of 5 different polynomials
        // (fk, fa, fb, fd, fe)
        // here we do not need fb as it is only used to mask some values before sending
        // them to other participants then adding them all together to generate w
        // this sum would annihilate all the fb shares which make them useless in our case
        let fa = Polynomial::generate_polynomial(None, max_malicious, &mut OsRng)?;
        let fk = Polynomial::generate_polynomial(None, max_malicious, &mut OsRng)?;
        let fd = Polynomial::generate_polynomial(
            Some(Secp256K1ScalarField::zero()),
            2 * max_malicious,
            &mut OsRng,
        )?;
        let fe = Polynomial::generate_polynomial(
            Some(Secp256K1ScalarField::zero()),
            2 * max_malicious,
            &mut OsRng,
        )?;

        // computing k, R, Rx
        let k = fk.eval_at_zero()?.0;
        let big_r = ProjectivePoint::GENERATOR * k;
        let big_r_x_coordinate = x_coordinate(&big_r.to_affine());

        // compute the master scalar w = a * k
        let w = fa.eval_at_zero()?.0 * k;
        let w_invert = w.invert().unwrap();

        let participants = generate_participants(5);

        let mut participants_presign = Vec::new();
        // Simulate the each participant's presignature
        for p in &participants {
            let h_i = w_invert * fa.eval_at_participant(*p)?.0;
            let alpha_i = h_i + fd.eval_at_participant(*p)?.0;
            let beta_i = h_i * big_r_x_coordinate * fx.eval_at_participant(*p)?.0
                + fe.eval_at_participant(*p)?.0;

            // build the presignature
            let presignature = PresignOutput {
                big_r: big_r.to_affine(),
                alpha_i,
                beta_i,
            };
            participants_presign.push((*p, presignature));
        }

        let result = run_sign(participants_presign, public_key, msg)?;
        let sig = result[0].1.clone();
        let sig = ecdsa::Signature::from_scalars(x_coordinate(&sig.big_r), sig.s)?;

        // verify the correctness of the generated signature
        VerifyingKey::from(&PublicKey::from_affine(public_key.to_affine()).unwrap())
            .verify(&msg[..], &sig)?;
        Ok(())
    }

    #[test]
    fn test_sign_fails_if_s_is_zero() -> Result<(), Box<dyn Error>> {
        use crate::ecdsa::{ProjectivePoint, Secp256K1ScalarField};
        use crate::test::generate_participants;

        let participants = generate_participants(2);

        // presignatures with s_me = 0 for each participant
        let presignatures = participants
            .iter()
            .map(|p| {
                (
                    *p,
                    PresignOutput {
                        big_r: ProjectivePoint::IDENTITY.to_affine(),
                        alpha_i: Secp256K1ScalarField::zero(),
                        beta_i: Secp256K1ScalarField::zero(),
                    },
                )
            })
            .collect::<Vec<_>>();

        let public_key = ProjectivePoint::IDENTITY;
        let msg = [0u8; 32]; // arbitrary zero message

        let result = crate::ecdsa::robust_ecdsa::test::run_sign(presignatures, public_key, &msg);

        match result {
            Ok(_) => panic!("expected failure, got success"),
            Err(err) => {
                let text = err.to_string();
                assert!(
                    text.contains("signature part s cannot be zero"),
                    "unexpected error type: {}",
                    text
                );
            }
        }
        Ok(())
    }
}
