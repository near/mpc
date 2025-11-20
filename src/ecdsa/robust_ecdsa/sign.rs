use elliptic_curve::scalar::IsHigh;

use crate::errors::{InitializationError, ProtocolError};
use crate::participants::{Participant, ParticipantList};
use crate::{
    ecdsa::{
        robust_ecdsa::RerandomizedPresignOutput, x_coordinate, AffinePoint, Scalar,
        Secp256K1Sha256, Signature, SignatureOption,
    },
    protocol::{
        helpers::recv_from_others,
        internal::{make_protocol, Comms, SharedChannel},
        Protocol,
    },
};
use frost_core::serialization::SerializableScalar;
use subtle::ConditionallySelectable;
type C = Secp256K1Sha256;

/// Depending on whether the current participant is a coordinator or not,
/// runs the signature protocol as either a participant or a coordinator.
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }

    let ctx = Comms::new();
    let fut = fut_wrapper(
        ctx.shared_channel(),
        participants,
        coordinator,
        me,
        public_key,
        presignature,
        msg_hash,
    );
    Ok(make_protocol(ctx, fut))
}

/// Performs signing from any participant's perspective (except the coordinator)
fn do_sign_participant(
    mut chan: SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    presignature: &RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    let s_me = compute_signature_share(presignature, msg_hash, participants, me)?;
    let wait_round = chan.next_waitpoint();
    chan.send_private(wait_round, coordinator, &s_me)?;

    Ok(None)
}

/// Performs signing from only the coordinator's perspective
async fn do_sign_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    let mut s = compute_signature_share(&presignature, msg_hash, &participants, me)?.0;
    let wait_round = chan.next_waitpoint();

    for (_, s_i) in
        recv_from_others::<SerializableScalar<C>>(&chan, wait_round, &participants, me).await?
    {
        // Sum the linearized shares
        s += s_i.0;
    }

    // raise error if s is zero
    if s.is_zero().into() {
        return Err(ProtocolError::AssertionFailed(
            "signature part s cannot be zero".to_string(),
        ));
    }
    // Normalize s
    s.conditional_assign(&(-s), s.is_high());

    let sig = Signature {
        big_r: presignature.big_r,
        s,
    };

    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }

    Ok(Some(sig))
}

/// A common computation done by both the coordinator and the other participants
fn compute_signature_share(
    presignature: &RerandomizedPresignOutput,
    msg_hash: Scalar,
    participants: &ParticipantList,
    me: Participant,
) -> Result<SerializableScalar<C>, ProtocolError> {
    // (beta_i + tweak * k_i) * delta^{-1}
    let big_r = presignature.big_r;
    let big_r_x_coordinate = x_coordinate(&big_r);
    // beta * Rx + e
    let beta = presignature.beta * big_r_x_coordinate + presignature.e;

    let s_me = msg_hash * presignature.alpha + beta;
    // lambda_i * s_i
    let linearized_s_me = s_me * participants.lagrange::<C>(me)?;
    Ok(SerializableScalar::<C>(linearized_s_me))
}

/// Wraps the coordinator and the participant into a single functions to be called
async fn fut_wrapper(
    chan: SharedChannel,
    participants: ParticipantList,
    coordinator: Participant,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    if me == coordinator {
        do_sign_coordinator(chan, participants, me, public_key, presignature, msg_hash).await
    } else {
        do_sign_participant(
            chan,
            &participants,
            coordinator,
            me,
            &presignature,
            msg_hash,
        )
    }
}

#[cfg(test)]
mod test {

    use k256::{ecdsa::signature::Verifier, ecdsa::VerifyingKey, PublicKey};
    use rand_core::OsRng;

    use super::*;
    use crate::ecdsa::{
        robust_ecdsa::test::{run_sign_with_rerandomization, run_sign_without_rerandomization},
        robust_ecdsa::PresignOutput,
        Field, Polynomial, ProjectivePoint, Secp256K1ScalarField,
    };
    use crate::test_utils::generate_participants;

    type PresigSimulationOutput = (Scalar, Polynomial, Polynomial, Polynomial, ProjectivePoint);

    fn simulate_presignature(max_malicious: usize) -> PresigSimulationOutput {
        // the presignatures scheme requires the generation of 5 different polynomials
        // (fk, fa, fb, fd, fe)
        // Here we do not need fb as it is only used to mask some values before sending
        // them to other participants then adding them all together to generate w.
        // This sum would annihilate all the fb shares which make them useless in our case.
        let fk = Polynomial::generate_polynomial(None, max_malicious, &mut OsRng).unwrap();
        let fa = Polynomial::generate_polynomial(None, max_malicious, &mut OsRng).unwrap();
        let degree = 2usize.checked_mul(max_malicious).unwrap();
        let fd =
            Polynomial::generate_polynomial(Some(Secp256K1ScalarField::zero()), degree, &mut OsRng)
                .unwrap();
        let fe =
            Polynomial::generate_polynomial(Some(Secp256K1ScalarField::zero()), degree, &mut OsRng)
                .unwrap();

        // computing k, R, Rx
        let k = fk.eval_at_zero().unwrap().0;
        let big_r = ProjectivePoint::GENERATOR * k;

        // compute the master scalar w = a * k
        let w = fa.eval_at_zero().unwrap().0 * k;
        let w_invert = w.invert().unwrap();

        (w_invert, fa, fd, fe, big_r)
    }

    #[test]
    fn test_sign_given_presignature_without_rerandomization() {
        let max_malicious = 2;
        let msg = b"Hello? Is it me you're looking for?";

        // Manually compute presignatures then deliver them to the signing function
        let fx = Polynomial::generate_polynomial(None, max_malicious, &mut OsRng).unwrap();
        // master secret key
        let x = fx.eval_at_zero().unwrap().0;
        // master public key
        let public_key = ProjectivePoint::GENERATOR * x;

        let (w_invert, fa, fd, fe, big_r) = simulate_presignature(max_malicious);
        let participants = generate_participants(5);

        let mut participants_presign = Vec::new();
        // Simulate the each participant's presignature
        for p in &participants {
            let c_i = w_invert * fa.eval_at_participant(*p).unwrap().0;
            let alpha = c_i + fd.eval_at_participant(*p).unwrap().0;
            let beta = c_i * fx.eval_at_participant(*p).unwrap().0;
            let e = fe.eval_at_participant(*p).unwrap().0;
            // build the presignature
            let presignature = PresignOutput {
                big_r: big_r.to_affine(),
                alpha,
                beta,
                e,
                c: c_i,
            };
            participants_presign.push((*p, presignature));
        }

        let (_, sig) =
            run_sign_without_rerandomization(&participants_presign, public_key, msg).unwrap();
        let sig = ecdsa::Signature::from_scalars(x_coordinate(&sig.big_r), sig.s).unwrap();

        // verify the correctness of the generated signature
        VerifyingKey::from(&PublicKey::from_affine(public_key.to_affine()).unwrap())
            .verify(&msg[..], &sig)
            .unwrap();
    }

    #[test]
    fn test_sign_given_presignature_with_rerandomization() {
        let max_malicious = 2;
        let msg = b"Hello? Is it me you're looking for?";

        // Manually compute presignatures then deliver them to the signing function
        let fx = Polynomial::generate_polynomial(None, max_malicious, &mut OsRng).unwrap();
        // master secret key
        let x = fx.eval_at_zero().unwrap().0;
        // master public key
        let public_key = frost_core::VerifyingKey::new(ProjectivePoint::GENERATOR * x);

        let (w_invert, fa, fd, fe, big_r) = simulate_presignature(max_malicious);
        let participants = generate_participants(5);

        let mut participants_presign = Vec::new();
        // Simulate the each participant's presignature
        for p in &participants {
            let c_i = w_invert * fa.eval_at_participant(*p).unwrap().0;
            let alpha = c_i + fd.eval_at_participant(*p).unwrap().0;
            let beta = c_i * fx.eval_at_participant(*p).unwrap().0;
            let e = fe.eval_at_participant(*p).unwrap().0;
            // build the presignature
            let presignature = PresignOutput {
                big_r: big_r.to_affine(),
                alpha,
                beta,
                e,
                c: c_i,
            };
            participants_presign.push((*p, presignature));
        }

        let (tweak, _, sig) =
            run_sign_with_rerandomization(&participants_presign, public_key.to_element(), msg)
                .unwrap();
        let sig = ecdsa::Signature::from_scalars(x_coordinate(&sig.big_r), sig.s).unwrap();
        // derive the public key
        let public_key = tweak.derive_verifying_key(&public_key).to_element();

        // verify the correctness of the generated signature
        VerifyingKey::from(&PublicKey::from_affine(public_key.to_affine()).unwrap())
            .verify(&msg[..], &sig)
            .unwrap();
    }

    #[test]
    fn test_sign_fails_if_s_is_zero() {
        let participants = generate_participants(2);

        // presignatures with s_me = 0 for each participant
        let presignatures = participants
            .iter()
            .map(|p| {
                (
                    *p,
                    PresignOutput {
                        big_r: ProjectivePoint::IDENTITY.to_affine(),
                        alpha: Secp256K1ScalarField::zero(),
                        beta: Secp256K1ScalarField::zero(),
                        c: Secp256K1ScalarField::zero(),
                        e: Secp256K1ScalarField::zero(),
                    },
                )
            })
            .collect::<Vec<_>>();

        let public_key = ProjectivePoint::IDENTITY;
        let msg = [0u8; 32]; // arbitrary zero message

        let result = crate::ecdsa::robust_ecdsa::test::run_sign_without_rerandomization(
            &presignatures,
            public_key,
            &msg,
        );

        match result {
            Ok(_) => panic!("expected failure, got success"),
            Err(err) => {
                let text = err.to_string();
                assert!(
                    text.contains("signature part s cannot be zero"),
                    "unexpected error type: {text}"
                );
            }
        }
    }
}
