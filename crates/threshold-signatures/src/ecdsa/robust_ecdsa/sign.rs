use elliptic_curve::scalar::IsHigh;

use crate::{
    ecdsa::{
        AffinePoint, Scalar, Secp256K1Sha256, Signature, SignatureOption,
        robust_ecdsa::presign::PresignOutput, x_coordinate,
    },
    errors::ProtocolError,
    participants::{Participant, ParticipantList},
    protocol::{helpers::recv_from_others, internal::SharedChannel},
};
use frost_core::serialization::SerializableScalar;
use subtle::ConditionallySelectable;
type C = Secp256K1Sha256;

/// The signing round, run on a caller-owned channel so that it can follow presigning on the
/// same channel.
///
/// This phase is scheme-agnostic: it sums the participants' Lagrange-linearized
/// shares of `s`, so it carries over unchanged to whichever scheme replaces the
/// current presigning stub. It provides no secrecy of its own, and inherits the key
/// leak documented in the [module docs](super).
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
    let s_me = compute_signature_share(presignature, msg_hash, participants, me)?;
    let wait_round = chan.next_waitpoint();
    chan.send_private(wait_round, coordinator, &s_me)?;

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
    let mut s = compute_signature_share(presignature, msg_hash, participants, me)?.0;
    let wait_round = chan.next_waitpoint();

    for (_, s_i) in
        recv_from_others::<SerializableScalar<C>>(chan, wait_round, participants, me).await?
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
    presignature: &PresignOutput,
    msg_hash: Scalar,
    participants: &ParticipantList,
    me: Participant,
) -> Result<SerializableScalar<C>, ProtocolError> {
    let big_r = presignature.big_r;
    let big_r_x_coordinate = x_coordinate(&big_r);
    // beta * Rx + e
    let beta = presignature.beta * big_r_x_coordinate + presignature.e;

    let s_me = msg_hash * presignature.alpha + beta;
    // lambda_i * s_i
    let linearized_s_me = s_me * participants.lagrange::<C>(me)?;
    Ok(SerializableScalar::<C>(linearized_s_me))
}

#[cfg(test)]
mod test {

    use std::error::Error;

    use k256::{PublicKey, ecdsa::VerifyingKey, ecdsa::signature::Verifier};
    use rand::seq::SliceRandom as _;
    use rand_core::{CryptoRngCore, SeedableRng};

    use super::*;
    use crate::MaxMalicious;
    use crate::crypto::hash::test::scalar_hash_secp256k1;
    use crate::ecdsa::{
        Field, Polynomial, ProjectivePoint, Secp256K1ScalarField,
        robust_ecdsa::presign_and_sign::ROBUST_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES,
    };
    use crate::errors::InitializationError;
    use crate::protocol::{
        Protocol,
        internal::{Comms, make_protocol},
    };
    use crate::test_utils::{
        MockCryptoRng, check_one_coordinator_output, generate_participants, run_sign,
    };

    /// Runs only the signing round, on presignatures the caller provides.
    fn run_sign_round(
        participants_presign: Vec<(Participant, PresignOutput)>,
        public_key: ProjectivePoint,
        msg: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Participant, Signature), Box<dyn Error>> {
        let msg_hash = scalar_hash_secp256k1(msg);
        let coordinator = participants_presign
            .choose(rng)
            .expect("participant list is not empty")
            .0;

        let result = run_sign::<Secp256K1Sha256, _, _, _>(
            participants_presign,
            coordinator,
            public_key,
            msg_hash,
            |participants, coordinator, me, public_key, presignature, msg_hash| {
                let participants = ParticipantList::new(participants)
                    .ok_or(InitializationError::DuplicateParticipants)?;
                let ctx = Comms::with_buffer_capacity(
                    ROBUST_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES,
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
        )?;
        let signature = check_one_coordinator_output(result, coordinator)?;
        Ok((coordinator, signature))
    }

    type PresigSimulationOutput = (Scalar, Polynomial, Polynomial, Polynomial, ProjectivePoint);

    fn simulate_presignature(
        max_malicious: impl Into<MaxMalicious>,
        rng: &mut impl CryptoRngCore,
    ) -> PresigSimulationOutput {
        let max_malicious = max_malicious.into().value();
        // the presignatures scheme requires the generation of 5 different polynomials
        // (fk, fa, fb, fd, fe)
        // Here we do not need fb as it is only used to mask some values before sending
        // them to other participants then adding them all together to generate w.
        // This sum would annihilate all the fb shares which make them useless in our case.
        let fk = Polynomial::generate_polynomial(None, max_malicious, rng).unwrap();
        let fa = Polynomial::generate_polynomial(None, max_malicious, rng).unwrap();
        let degree = 2usize.checked_mul(max_malicious).unwrap();
        let fd = Polynomial::generate_polynomial(Some(Secp256K1ScalarField::zero()), degree, rng)
            .unwrap();
        let fe = Polynomial::generate_polynomial(Some(Secp256K1ScalarField::zero()), degree, rng)
            .unwrap();

        // computing k, R, Rx
        let k = fk.eval_at_zero().unwrap().0;
        let big_r = ProjectivePoint::GENERATOR * k;

        // compute the master scalar w = a * k
        let w = fa.eval_at_zero().unwrap().0 * k;
        let w_invert = w.invert().unwrap();

        (w_invert, fa, fd, fe, big_r)
    }

    fn simulate_sign_inputs(
        participants: &[Participant],
        max_malicious: usize,
        rng: &mut impl CryptoRngCore,
    ) -> (ProjectivePoint, Vec<(Participant, PresignOutput)>) {
        let fx = Polynomial::generate_polynomial(None, max_malicious, rng).unwrap();
        let x = fx.eval_at_zero().unwrap().0;
        let public_key = ProjectivePoint::GENERATOR * x;
        let (w_invert, fa, fd, fe, big_r) = simulate_presignature(max_malicious, rng);
        let presignatures = participants
            .iter()
            .map(|p| {
                let c_i = w_invert * fa.eval_at_participant(*p).unwrap().0;
                let alpha = c_i + fd.eval_at_participant(*p).unwrap().0;
                let beta = c_i * fx.eval_at_participant(*p).unwrap().0;
                let e = fe.eval_at_participant(*p).unwrap().0;
                (
                    *p,
                    PresignOutput {
                        big_r: big_r.to_affine(),
                        alpha,
                        beta,
                        e,
                        c: c_i,
                    },
                )
            })
            .collect();
        (public_key, presignatures)
    }

    #[test]
    fn test_sign_given_presignature() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let max_malicious = 2;
        let msg = b"Hello? Is it me you're looking for?";

        let participants = generate_participants(5);
        let (public_key, participants_presign) =
            simulate_sign_inputs(&participants, max_malicious, &mut rng);

        let (_, sig) = run_sign_round(participants_presign, public_key, msg, &mut rng).unwrap();
        let sig = ecdsa::Signature::from_scalars(x_coordinate(&sig.big_r), sig.s).unwrap();

        // verify the correctness of the generated signature
        VerifyingKey::from(&PublicKey::from_affine(public_key.to_affine()).unwrap())
            .verify(&msg[..], &sig)
            .unwrap();
    }

    #[test]
    fn test_sign_fails_if_s_is_zero() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let participants = generate_participants(3);

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

        let result = run_sign_round(presignatures, public_key, &msg, &mut rng);

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
