use elliptic_curve::scalar::IsHigh;
use subtle::ConditionallySelectable;

use super::RerandomizedPresignOutput;
use crate::errors::{InitializationError, ProtocolError};
use crate::participants::{Participant, ParticipantList};
use crate::{
    ecdsa::{x_coordinate, AffinePoint, Scalar, Secp256K1Sha256, Signature, SignatureOption},
    protocol::{
        helpers::recv_from_others,
        internal::{make_protocol, Comms, SharedChannel},
        Protocol,
    },
};

/// The signature protocol, allowing us to use a presignature to sign a message.
///
/// **WARNING** You must absolutely hash an actual message before passing it to
/// this function. Allowing the signing of arbitrary scalars *is* a security risk,
/// and this function only tolerates this risk to allow for genericity.
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
    // Round 1
    let s_i = compute_signature_share(participants, me, presignature, msg_hash)?;
    // Send si
    // Spec 1.4
    let wait0 = chan.next_waitpoint();
    chan.send_private(wait0, coordinator, &s_i)?;

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
    // Round 1
    let s_i = compute_signature_share(&participants, me, &presignature, msg_hash)?;
    // Spec 1.4 is non existant for a coordinator

    let wait0 = chan.next_waitpoint();
    // Receive sj
    // Spec 1.5
    let mut s = s_i;
    for (_, s_j) in recv_from_others::<Scalar>(&chan, wait0, &participants, me).await? {
        // Spec 1.6
        s += s_j;
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

    Ok(Some(sig))
}

/// A common computation done by both the coordinator and the other participants
fn compute_signature_share(
    participants: &ParticipantList,
    me: Participant,
    presignature: &RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<Scalar, ProtocolError> {
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
    Ok(msg_hash * k_i + r * sigma_i)
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
    use super::x_coordinate;
    use crate::{
        ecdsa::{
            ot_based_ecdsa::{
                test::{run_sign_with_rerandomization, run_sign_without_rerandomization},
                PresignOutput,
            },
            Polynomial,
        },
        test_utils::{generate_participants, MockCryptoRng},
    };
    use k256::{ecdsa::signature::Verifier, ecdsa::VerifyingKey, ProjectivePoint, PublicKey};
    use rand::SeedableRng;

    #[test]
    fn test_sign_without_rerandomization() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let threshold: usize = 2;
        let msg = b"Hello? Is it me you're looking for?";

        let degree = threshold.checked_sub(1).unwrap();
        let f = Polynomial::generate_polynomial(None, degree, &mut rng).unwrap();
        let x = f.eval_at_zero().unwrap().0;
        let public_key = ProjectivePoint::GENERATOR * x;

        let g = Polynomial::generate_polynomial(None, degree, &mut rng).unwrap();

        let k = g.eval_at_zero().unwrap().0;
        let big_r = (ProjectivePoint::GENERATOR * k.invert().unwrap()).to_affine();

        let sigma = k * x;

        let h = Polynomial::generate_polynomial(Some(sigma), degree, &mut rng).unwrap();

        let participants = generate_participants(2);

        let mut participants_presign = Vec::new();
        for p in &participants {
            let presignature = PresignOutput {
                big_r,
                k: g.eval_at_participant(*p).unwrap().0,
                sigma: h.eval_at_participant(*p).unwrap().0,
            };
            participants_presign.push((*p, presignature));
        }

        let (_, sig) =
            run_sign_without_rerandomization(&participants_presign, public_key, msg, &mut rng);
        let sig = ecdsa::Signature::from_scalars(x_coordinate(&sig.big_r), sig.s).unwrap();
        VerifyingKey::from(&PublicKey::from_affine(public_key.to_affine()).unwrap())
            .verify(msg, &sig)
            .unwrap();
    }

    #[test]
    fn test_sign_with_rerandomization() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let threshold: usize = 2;
        let msg = b"Hello? Is it me you're looking for?";

        let degree = threshold.checked_sub(1).unwrap();
        let f = Polynomial::generate_polynomial(None, degree, &mut rng).unwrap();
        let x = f.eval_at_zero().unwrap().0;
        let public_key = frost_core::VerifyingKey::new(ProjectivePoint::GENERATOR * x);

        let g = Polynomial::generate_polynomial(None, degree, &mut rng).unwrap();

        let k = g.eval_at_zero().unwrap().0;
        let big_r = (ProjectivePoint::GENERATOR * k.invert().unwrap()).to_affine();

        let sigma = k * x;

        let h = Polynomial::generate_polynomial(Some(sigma), degree, &mut rng).unwrap();

        let participants = generate_participants(2);

        let mut participants_presign = Vec::new();
        for p in &participants {
            let presignature = PresignOutput {
                big_r,
                k: g.eval_at_participant(*p).unwrap().0,
                sigma: h.eval_at_participant(*p).unwrap().0,
            };
            participants_presign.push((*p, presignature));
        }

        let (tweak, _, sig) = run_sign_with_rerandomization(
            &participants_presign,
            public_key.to_element(),
            msg,
            &mut rng,
        )
        .unwrap();
        let signature = ecdsa::Signature::from_scalars(x_coordinate(&sig.big_r), sig.s).unwrap();

        let public_key = tweak.derive_verifying_key(&public_key).to_element();
        VerifyingKey::from(&PublicKey::from_affine(public_key.to_affine()).unwrap())
            .verify(msg, &signature)
            .unwrap();

        insta::assert_json_snapshot!(signature);
    }
}
