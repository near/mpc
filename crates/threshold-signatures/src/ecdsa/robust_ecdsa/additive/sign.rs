use elliptic_curve::scalar::IsHigh;

use crate::{
    MaxMalicious,
    ecdsa::{
        AffinePoint, Scalar, Secp256K1Sha256, Signature, SignatureOption,
        robust_ecdsa::additive::AdditiveRerandomizedPresignOutput, x_coordinate,
    },
    errors::{InitializationError, ProtocolError},
    participants::{Participant, ParticipantList},
    protocol::{
        Protocol,
        helpers::recv_from_others,
        internal::{Comms, SharedChannel, make_protocol},
    },
};
use frost_core::serialization::SerializableScalar;
use subtle::ConditionallySelectable;
type C = Secp256K1Sha256;

/// The pair of linearized shares `(mu_i, nu_i)` sent to the coordinator.
type SignatureSharePair = (SerializableScalar<C>, SerializableScalar<C>);

/// Maximum incoming buffer entries for the coordinator in the additive robust ECDSA sign protocol.
pub(crate) const ADDITIVE_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES: usize = 1;
/// Maximum incoming buffer entries for non-coordinator participants in the additive robust ECDSA sign protocol.
#[cfg(test)]
pub(crate) const ADDITIVE_SIGN_MAX_INCOMING_PARTICIPANT_ENTRIES: usize = 0;

/// Depending on whether the current participant is a coordinator or not,
/// runs the signature protocol as either a participant or a coordinator.
///
/// The coordinator opens `mu = a * (k + delta)` and `nu = a * (h + r * (x + tweak))`
/// and outputs `s = nu / mu`, completing the \[BB89\] inversion online.
///
/// WARNING:
/// The split-view constraints of the parent scheme apply unchanged: require
/// `N1 = N2 = 2 * max_malicious + 1`, ensure all participants agree on
/// `(msg_hash, tweak, participants)` when creating
/// `AdditiveRerandomizedPresignOutput`, never reuse a presignature, and do not
/// sign with `msg_hash == 0`.
pub fn sign<M>(
    participants: &[Participant],
    coordinator: Participant,
    max_malicious: M,
    me: Participant,
    public_key: AffinePoint,
    presignature: AdditiveRerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption> + use<M>, InitializationError>
where
    M: Into<MaxMalicious>,
{
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

    // ensure number of participants during the signing phase is >= 2 * max_malicious + 1
    let robust_ecdsa_threshold = max_malicious
        .into()
        .value()
        .checked_mul(2)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            InitializationError::BadParameters(
                "2*threshold+1 must be less than usize::MAX".to_string(),
            )
        })?;
    if robust_ecdsa_threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "2*max_malicious+1 must be less than or equals to participant count".to_string(),
        ));
    }

    // The next two conditions prevent split-view attacks
    // documented in docs/ecdsa/robust_ecdsa/signing.md
    if participants.len() != robust_ecdsa_threshold {
        return Err(InitializationError::BadParameters(
            "the number of participants during signing must be exactly 2*max_malicious+1 to avoid split view attacks".to_string(),
        ));
    }
    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }

    let ctx = Comms::with_buffer_capacity(ADDITIVE_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES);
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
    presignature: &AdditiveRerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    let pair_me = compute_signature_share_pair(presignature, msg_hash, participants, me)?;
    let wait_round = chan.next_waitpoint();
    chan.send_private(wait_round, coordinator, &pair_me)?;

    Ok(None)
}

/// Performs signing from only the coordinator's perspective
async fn do_sign_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    public_key: AffinePoint,
    presignature: AdditiveRerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    let (mu_me, nu_me) = compute_signature_share_pair(&presignature, msg_hash, &participants, me)?;
    let mut mu = mu_me.0;
    let mut nu = nu_me.0;
    let wait_round = chan.next_waitpoint();

    for (_, (mu_p, nu_p)) in
        recv_from_others::<SignatureSharePair>(&chan, wait_round, &participants, me).await?
    {
        // Sum the linearized shares
        mu += mu_p.0;
        nu += nu_p.0;
    }

    // raise error if mu is zero
    if mu.is_zero().into() {
        return Err(ProtocolError::AssertionFailed(
            "denominator mu cannot be zero".to_string(),
        ));
    }
    // mu is non-zero due to the previous check and so I can unwrap safely
    let mut s = nu * mu.invert().unwrap();

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
fn compute_signature_share_pair(
    presignature: &AdditiveRerandomizedPresignOutput,
    msg_hash: Scalar,
    participants: &ParticipantList,
    me: Participant,
) -> Result<SignatureSharePair, ProtocolError> {
    let big_r_x_coordinate = x_coordinate(&presignature.big_r);
    // nu_i = h * a_i + Rx * u_i + e_i
    let nu = msg_hash * presignature.a + big_r_x_coordinate * presignature.u + presignature.e;
    // lambda_i * (mu_i, nu_i)
    let lambda = participants.lagrange::<C>(me)?;
    Ok((
        SerializableScalar::<C>(lambda * presignature.mu),
        SerializableScalar::<C>(lambda * nu),
    ))
}

/// Wraps the coordinator and the participant into a single functions to be called
async fn fut_wrapper(
    chan: SharedChannel,
    participants: ParticipantList,
    coordinator: Participant,
    me: Participant,
    public_key: AffinePoint,
    presignature: AdditiveRerandomizedPresignOutput,
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
#[expect(non_snake_case)]
mod test {
    use k256::{PublicKey, ecdsa::VerifyingKey, ecdsa::signature::Verifier};
    use rand_core::{CryptoRngCore, SeedableRng};
    use rstest::rstest;

    use super::*;
    use crate::crypto::hash::test::scalar_hash_secp256k1;
    use crate::ecdsa::{
        Field, Polynomial, ProjectivePoint, Secp256K1ScalarField,
        robust_ecdsa::additive::{AdditivePresignOutput, test::run_sign_without_rerandomization},
    };
    use crate::test_utils::{
        MockCryptoRng, assert_buffer_capacity, expected_buffer_by_role, generate_participants,
    };

    /// Simulates a dealer-based additive presigning: (public key, per-participant presignatures)
    fn simulate_sign_inputs(
        participants: &[Participant],
        max_malicious: usize,
        rng: &mut impl CryptoRngCore,
    ) -> (ProjectivePoint, Vec<(Participant, AdditivePresignOutput)>) {
        let degree = 2 * max_malicious;
        let zero = Secp256K1ScalarField::zero();
        let fx = Polynomial::generate_polynomial(None, max_malicious, rng).unwrap();
        let fk = Polynomial::generate_polynomial(None, max_malicious, rng).unwrap();
        let fa = Polynomial::generate_polynomial(None, max_malicious, rng).unwrap();
        let fb = Polynomial::generate_polynomial(Some(zero), degree, rng).unwrap();
        let fd = Polynomial::generate_polynomial(Some(zero), degree, rng).unwrap();
        let fe = Polynomial::generate_polynomial(Some(zero), degree, rng).unwrap();

        let x = fx.eval_at_zero().unwrap().0;
        let public_key = ProjectivePoint::GENERATOR * x;
        let k = fk.eval_at_zero().unwrap().0;
        let big_r = (ProjectivePoint::GENERATOR * k).to_affine();

        let presignatures = participants
            .iter()
            .map(|p| {
                let a = fa.eval_at_participant(*p).unwrap().0;
                let w = a * fk.eval_at_participant(*p).unwrap().0
                    + fb.eval_at_participant(*p).unwrap().0;
                let u = a * fx.eval_at_participant(*p).unwrap().0
                    + fd.eval_at_participant(*p).unwrap().0;
                let e = fe.eval_at_participant(*p).unwrap().0;
                (*p, AdditivePresignOutput { big_r, a, w, u, e })
            })
            .collect();
        (public_key, presignatures)
    }

    #[test]
    fn additive_sign__should_produce_valid_signature_without_rerandomization() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let max_malicious = 2;
        let msg = b"Hello? Is it me you're looking for?";
        let participants = generate_participants(5);
        let (public_key, participants_presign) =
            simulate_sign_inputs(&participants, max_malicious, &mut rng);

        // When
        let (_, sig) = run_sign_without_rerandomization(
            &participants_presign,
            max_malicious.into(),
            public_key,
            msg,
            &mut rng,
        )
        .unwrap();

        // Then
        let sig = ecdsa::Signature::from_scalars(x_coordinate(&sig.big_r), sig.s).unwrap();
        VerifyingKey::from(&PublicKey::from_affine(public_key.to_affine()).unwrap())
            .verify(&msg[..], &sig)
            .unwrap();
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn additive_sign__should_buffer_expected_entries(#[case] max_malicious: usize) {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let num_participants = 2 * max_malicious + 1;
        let participants = generate_participants(num_participants);
        let (public_key, presignatures) =
            simulate_sign_inputs(&participants, max_malicious, &mut rng);
        let coordinator = participants[0];
        let msg_scalar = scalar_hash_secp256k1(b"test msg");

        // When + Then
        assert_buffer_capacity(
            &participants,
            &mut rng,
            |comms, p_list, p, _rng_p| {
                let presignature = &presignatures.iter().find(|(pp, _)| *pp == p).unwrap().1;
                let rerandomized =
                    AdditiveRerandomizedPresignOutput::new_without_rerandomization(presignature);
                fut_wrapper(
                    comms.shared_channel(),
                    p_list,
                    coordinator,
                    p,
                    public_key.to_affine(),
                    rerandomized,
                    msg_scalar,
                )
            },
            expected_buffer_by_role(
                coordinator,
                ADDITIVE_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES,
                ADDITIVE_SIGN_MAX_INCOMING_PARTICIPANT_ENTRIES,
            ),
        );
    }
}
