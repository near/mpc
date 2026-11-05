use elliptic_curve::scalar::IsHigh;
use frost_core::serialization::SerializableScalar;
use rand_core::CryptoRngCore;
use subtle::ConditionallySelectable;

use crate::ecdsa::robust_ecdsa::nonce_generation::{
    NonceGenerationOutput, SignArguments, nonce_generation_round, validate_sign_arguments,
};
use crate::ecdsa::{
    AffinePoint, Scalar, Secp256K1Sha256, Signature, SignatureOption, Tweak, x_coordinate,
};
use crate::errors::{InitializationError, ProtocolError};
use crate::participants::{Participant, ParticipantList};
use crate::protocol::{
    Protocol,
    helpers::recv_from_others,
    internal::{Comms, SharedChannel, make_protocol},
};

type C = Secp256K1Sha256;

pub(crate) const ROBUST_ECDSA_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES: usize = 2;
#[cfg(test)]
pub(crate) const ROBUST_ECDSA_SIGN_MAX_INCOMING_PARTICIPANT_ENTRIES: usize = 1;

/// Nonce generation and signing as a single protocol, run once the message is known. Only the
/// coordinator obtains the signature.
///
/// **This is a stub and leaks the signing key.** See the [module docs](super) before
/// using it for anything.
///
/// The `N = 2 * max_malicious + 1` participant count and the `msg_hash != 0`
/// rejection are retained from the removed scheme, which needed both to blunt
/// split-view attacks.
pub fn sign<R>(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    args: SignArguments,
    tweak: Tweak,
    msg_hash: Scalar,
    rng: R,
) -> Result<impl Protocol<Output = SignatureOption> + use<R>, InitializationError>
where
    R: CryptoRngCore + Send + 'static,
{
    let participants = validate_sign_arguments(participants, me, &args)?;

    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }

    if bool::from(msg_hash.is_zero()) {
        return Err(InitializationError::BadParameters(
            "msg_hash cannot be 0 to avoid potential split view attacks".to_string(),
        ));
    }

    let ctx = Comms::with_buffer_capacity(ROBUST_ECDSA_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES);
    let fut = do_sign(
        ctx.shared_channel(),
        participants,
        coordinator,
        me,
        args,
        tweak,
        msg_hash,
        rng,
    );
    Ok(make_protocol(ctx, fut))
}

#[allow(clippy::too_many_arguments)]
async fn do_sign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    coordinator: Participant,
    me: Participant,
    args: SignArguments,
    tweak: Tweak,
    msg_hash: Scalar,
    rng: impl CryptoRngCore,
) -> Result<SignatureOption, ProtocolError> {
    let derived_public_key = tweak
        .derive_verifying_key(&args.keygen_out.public_key)
        .to_element()
        .to_affine();

    let presignature = nonce_generation_round(&mut chan, &participants, me, args, rng)
        .await?
        .with_tweak(&tweak);

    sign_round(
        &mut chan,
        &participants,
        coordinator,
        me,
        derived_public_key,
        &presignature,
        msg_hash,
    )
    .await
}

/// The signing round, run on a caller-owned channel so that it can follow nonce generation on
/// the same channel.
///
/// This phase is scheme-agnostic: it sums the participants' Lagrange-linearized
/// shares of `s`, so it carries over unchanged to whichever scheme replaces the
/// current nonce generation stub. It provides no secrecy of its own, and inherits the key
/// leak documented in the [module docs](super).
pub(crate) async fn sign_round(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    coordinator: Participant,
    me: Participant,
    public_key: AffinePoint,
    presignature: &NonceGenerationOutput,
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
    presignature: &NonceGenerationOutput,
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
    presignature: &NonceGenerationOutput,
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
    presignature: &NonceGenerationOutput,
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
#[allow(non_snake_case)]
mod test {
    use super::*;
    use crate::MaxMalicious;
    use crate::crypto::hash::test::scalar_hash_secp256k1;
    use crate::ecdsa::{Field, KeygenOutput, Polynomial, ProjectivePoint, Secp256K1ScalarField};
    use crate::test_utils::{
        GenProtocol, MockCryptoRng, assert_buffer_capacity, check_one_coordinator_output,
        expected_buffer_by_role, generate_participants, run_keygen, run_protocol, run_sign,
    };
    use k256::{PublicKey, ecdsa::VerifyingKey, ecdsa::signature::Verifier};
    use rand::seq::SliceRandom as _;
    use rand_core::{RngCore, SeedableRng};
    use rstest::rstest;
    use std::{assert_matches, error::Error};

    const MSG: &[u8] = b"presign and sign in one go";

    struct Setup {
        participants: Vec<Participant>,
        max_malicious: usize,
        key_packages: Vec<(Participant, KeygenOutput)>,
        rng_seeds: Vec<u64>,
        tweak: Tweak,
        msg_hash: Scalar,
    }

    impl Setup {
        fn new(max_malicious: usize, rng: &mut MockCryptoRng) -> Self {
            let participants = generate_participants(2 * max_malicious + 1);
            let key_packages = run_keygen(&participants, max_malicious + 1, rng);
            let rng_seeds = participants.iter().map(|_| rng.next_u64()).collect();
            let tweak = Tweak::new(frost_core::random_nonzero::<Secp256K1Sha256, _>(rng));
            Self {
                participants,
                max_malicious,
                key_packages,
                rng_seeds,
                tweak,
                msg_hash: scalar_hash_secp256k1(MSG),
            }
        }

        fn args_for(&self, index: usize) -> SignArguments {
            SignArguments {
                keygen_out: self.key_packages[index].1.clone(),
                max_malicious: self.max_malicious.into(),
            }
        }

        fn rng_for(&self, index: usize) -> MockCryptoRng {
            MockCryptoRng::seed_from_u64(self.rng_seeds[index])
        }

        fn derived_verifying_key(&self) -> VerifyingKey {
            let derived = self
                .tweak
                .derive_verifying_key(&self.key_packages[0].1.public_key)
                .to_element()
                .to_affine();
            VerifyingKey::from(&PublicKey::from_affine(derived).unwrap())
        }

        fn run_sign(&self, coordinator: Participant) -> Vec<(Participant, SignatureOption)> {
            let mut protocols: GenProtocol<SignatureOption> =
                Vec::with_capacity(self.participants.len());
            for (i, p) in self.participants.iter().enumerate() {
                let protocol = sign(
                    &self.participants,
                    coordinator,
                    *p,
                    self.args_for(i),
                    self.tweak,
                    self.msg_hash,
                    self.rng_for(i),
                )
                .unwrap();
                protocols.push((*p, Box::new(protocol)));
            }
            run_protocol(protocols).unwrap()
        }
    }

    fn to_k256_signature(signature: &Signature) -> ecdsa::Signature<k256::Secp256k1> {
        ecdsa::Signature::from_scalars(x_coordinate(&signature.big_r), signature.s).unwrap()
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn sign__should_produce_signature_verifiable_under_derived_key(#[case] max_malicious: usize) {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(max_malicious, &mut rng);
        let coordinator = setup.participants[setup.participants.len() - 1];

        // When
        let result = setup.run_sign(coordinator);

        // Then
        let signature = check_one_coordinator_output(result, coordinator).unwrap();
        setup
            .derived_verifying_key()
            .verify(MSG, &to_k256_signature(&signature))
            .unwrap();
    }

    #[test]
    fn sign__should_return_signature_only_to_coordinator() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(2, &mut rng);
        let coordinator = setup.participants[1];

        // When
        let result = setup.run_sign(coordinator);

        // Then
        assert_eq!(result.len(), 5);
        for (participant, output) in &result {
            assert_eq!(output.is_some(), *participant == coordinator);
        }
    }

    #[test]
    fn sign__should_reject_coordinator_outside_participants() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(1, &mut rng);
        let outsider = Participant::from(999u32);

        // When
        let result = sign(
            &setup.participants,
            outsider,
            setup.participants[0],
            setup.args_for(0),
            setup.tweak,
            setup.msg_hash,
            setup.rng_for(0),
        );

        // Then
        assert_matches!(
            result.err(),
            Some(InitializationError::MissingParticipant {
                role: "coordinator",
                participant
            }) if participant == outsider
        );
    }

    #[test]
    fn sign__should_reject_zero_msg_hash() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(1, &mut rng);

        // When
        let result = sign(
            &setup.participants,
            setup.participants[0],
            setup.participants[0],
            setup.args_for(0),
            setup.tweak,
            Scalar::ZERO,
            setup.rng_for(0),
        );

        // Then
        assert_matches!(result.err(), Some(InitializationError::BadParameters(_)));
    }

    #[rstest]
    #[case::fewer_than_two_max_malicious_plus_one(1, 2)]
    #[case::more_than_two_max_malicious_plus_one(2, 1)]
    fn sign__should_reject_participant_count_other_than_two_max_malicious_plus_one(
        #[case] setup_max_malicious: usize,
        #[case] args_max_malicious: usize,
    ) {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(setup_max_malicious, &mut rng);
        let mut args = setup.args_for(0);
        args.max_malicious = args_max_malicious.into();

        // When
        let result = sign(
            &setup.participants,
            setup.participants[0],
            setup.participants[0],
            args,
            setup.tweak,
            setup.msg_hash,
            setup.rng_for(0),
        );

        // Then
        assert_matches!(result.err(), Some(InitializationError::BadParameters(_)));
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn sign__should_bound_message_buffer_by_role(#[case] max_malicious: usize) {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(max_malicious, &mut rng);
        let coordinator = setup.participants[0];

        // When + Then
        assert_buffer_capacity(
            &setup.participants,
            &mut rng,
            |comms, p_list, p, rng_p| {
                let index = setup.participants.iter().position(|q| *q == p).unwrap();
                do_sign(
                    comms.shared_channel(),
                    p_list,
                    coordinator,
                    p,
                    setup.args_for(index),
                    setup.tweak,
                    setup.msg_hash,
                    rng_p,
                )
            },
            expected_buffer_by_role(
                coordinator,
                ROBUST_ECDSA_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES,
                ROBUST_ECDSA_SIGN_MAX_INCOMING_PARTICIPANT_ENTRIES,
            ),
        );
    }

    /// Runs only the signing round, on presignatures the caller provides.
    fn run_sign_round(
        participants_presign: Vec<(Participant, NonceGenerationOutput)>,
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
                let ctx =
                    Comms::with_buffer_capacity(ROBUST_ECDSA_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES);
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
    ) -> (ProjectivePoint, Vec<(Participant, NonceGenerationOutput)>) {
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
                    NonceGenerationOutput {
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
                    NonceGenerationOutput {
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
