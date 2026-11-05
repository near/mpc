use elliptic_curve::scalar::IsHigh;
use subtle::ConditionallySelectable;

use super::presign::PresignOutput;
use crate::errors::ProtocolError;
use crate::participants::{Participant, ParticipantList};
use crate::{
    ecdsa::{AffinePoint, Scalar, Secp256K1Sha256, Signature, SignatureOption, x_coordinate},
    protocol::{helpers::recv_from_others, internal::SharedChannel},
};

pub async fn sign_round(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    public_key: AffinePoint,
    presignature: &PresignOutput,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    if me == coordinator {
        do_sign_coordinator(chan, participants, me, public_key, presignature, msg_hash).await
    } else {
        do_sign_participant(chan, participants, coordinator, me, presignature, msg_hash)
    }
}

/// Performs signing from any participant's perspective (except the coordinator)
fn do_sign_participant(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    presignature: &PresignOutput,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    // Round 3
    let s_i = compute_signature_share(participants, me, presignature, msg_hash)?;
    // Send si
    // Spec 3.4
    let wait0 = chan.next_waitpoint();
    chan.send_private(wait0, coordinator, &s_i)?;

    Ok(None)
}

/// Performs signing from only the coordinator's perspective
async fn do_sign_coordinator(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: Participant,
    public_key: AffinePoint,
    presignature: &PresignOutput,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    // Round 3
    let s_i = compute_signature_share(participants, me, presignature, msg_hash)?;
    // Spec 3.4 is non-existent for a coordinator

    let wait0 = chan.next_waitpoint();
    // Receive sj
    // Spec 3.5
    let mut s = s_i;
    for (_, s_j) in recv_from_others::<Scalar>(chan, wait0, participants, me).await? {
        // Spec 3.6
        s += s_j;
    }

    // Normalize s
    // Spec 3.7
    s.conditional_assign(&(-s), s.is_high());

    let sig = Signature {
        big_r: presignature.big_r,
        s,
    };

    // Spec 3.8
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
    presignature: &PresignOutput,
    msg_hash: Scalar,
) -> Result<Scalar, ProtocolError> {
    // Round 3
    // Linearize ki
    // Spec 3.1
    let lambda = participants.lagrange::<Secp256K1Sha256>(me)?;
    let k_i = lambda * presignature.k;

    // Linearize sigmai
    // Spec 3.2
    let sigma_i = lambda * presignature.sigma;

    // Compute si = h * ki + Rx * sigmai
    // Spec 3.3
    let r = x_coordinate(&presignature.big_r);
    Ok(msg_hash * k_i + r * sigma_i)
}

#[cfg(test)]
#[allow(non_snake_case)]
mod test {
    use super::*;
    use crate::crypto::hash::test::scalar_hash_secp256k1;
    use crate::ecdsa::Polynomial;
    use crate::ecdsa::ot_based_ecdsa::presign_and_sign::OT_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES;
    use crate::errors::InitializationError;
    use crate::protocol::{
        Protocol,
        internal::{Comms, make_protocol},
    };
    use crate::test_utils::{
        MockCryptoRng, check_one_coordinator_output, generate_participants, run_sign,
    };
    use k256::{ProjectivePoint, PublicKey, ecdsa::VerifyingKey, ecdsa::signature::Verifier};
    use rand::SeedableRng;

    fn simulate_presignatures(
        participants: &[Participant],
        threshold: usize,
        rng: &mut MockCryptoRng,
    ) -> (ProjectivePoint, Vec<(Participant, PresignOutput)>) {
        let degree = threshold - 1;
        let f = Polynomial::generate_polynomial(None, degree, rng).unwrap();
        let x = f.eval_at_zero().unwrap().0;
        let public_key = ProjectivePoint::GENERATOR * x;
        let g = Polynomial::generate_polynomial(None, degree, rng).unwrap();
        let k = g.eval_at_zero().unwrap().0;
        let big_r = (ProjectivePoint::GENERATOR * k.invert().unwrap()).to_affine();
        let sigma = k * x;
        let h = Polynomial::generate_polynomial(Some(sigma), degree, rng).unwrap();
        let presignatures = participants
            .iter()
            .map(|p| {
                (
                    *p,
                    PresignOutput {
                        big_r,
                        k: g.eval_at_participant(*p).unwrap().0,
                        sigma: h.eval_at_participant(*p).unwrap().0,
                    },
                )
            })
            .collect();
        (public_key, presignatures)
    }

    #[test]
    fn sign_round__should_produce_signature_verifiable_under_public_key() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let threshold: usize = 2;
        let msg = b"Hello? Is it me you're looking for?";
        let participants = generate_participants(2);
        let (public_key, presignatures) =
            simulate_presignatures(&participants, threshold, &mut rng);
        let coordinator = participants[0];

        // When
        let result = run_sign::<Secp256K1Sha256, _, _, _>(
            presignatures,
            coordinator,
            public_key,
            scalar_hash_secp256k1(msg),
            |participants, coordinator, me, public_key, presignature, msg_hash| {
                let participants = ParticipantList::new(participants)
                    .ok_or(InitializationError::DuplicateParticipants)?;
                let ctx = Comms::with_buffer_capacity(
                    OT_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES,
                );
                let mut chan = ctx.shared_channel();
                let fut = async move {
                    sign_round(
                        &mut chan,
                        &participants,
                        coordinator,
                        me,
                        public_key.to_affine(),
                        &presignature,
                        msg_hash,
                    )
                    .await
                };
                Ok(Box::new(make_protocol(ctx, fut))
                    as Box<dyn Protocol<Output = SignatureOption>>)
            },
        )
        .unwrap();

        // Then
        let signature = check_one_coordinator_output(result, coordinator).unwrap();
        let signature =
            ecdsa::Signature::from_scalars(x_coordinate(&signature.big_r), signature.s).unwrap();
        VerifyingKey::from(&PublicKey::from_affine(public_key.to_affine()).unwrap())
            .verify(msg, &signature)
            .unwrap();
    }
}
