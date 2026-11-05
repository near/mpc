use elliptic_curve::scalar::IsHigh;
use subtle::ConditionallySelectable;

use crate::ecdsa::ot_based_ecdsa::nonce_generation::{
    NonceGenerationOutput, SignArguments, nonce_generation_rounds, validate_sign_arguments,
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

/// Maximum incoming buffer entries for the coordinator: the two waitpoints before signing
/// plus the signature-share waitpoint.
pub(crate) const OT_ECDSA_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES: usize = 3;
/// Maximum incoming buffer entries for non-coordinator participants: the two waitpoints
/// before signing.
#[cfg(test)]
pub(crate) const OT_ECDSA_SIGN_MAX_INCOMING_PARTICIPANT_ENTRIES: usize = 2;

/// Nonce generation and signing as a single protocol, consuming two triples directly.
///
/// The output of nonce generation never leaves this computation and is never stored; the
/// key-derivation `tweak` is applied locally between the nonce generation rounds and the signing
/// round. Only the coordinator obtains the signature.
///
/// # Safety contract
///
/// Each triple, not just the pair, must be used at most once (see [`SignArguments`]). In
/// particular, `big_r` is determined by `triple0` alone and is known to every participant once
/// round 1 completes. Nothing binds `big_r` to `msg_hash`, so a second run on the same `triple0`
/// under a different `tweak` or `msg_hash` leaks the private key.
///
/// **WARNING** You must absolutely hash an actual message before passing it to
/// this function. Allowing the signing of arbitrary scalars *is* a security risk,
/// and this function only tolerates this risk to allow for genericity.
pub fn sign(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    args: SignArguments,
    tweak: Tweak,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption> + use<>, InitializationError> {
    let participants = validate_sign_arguments(participants, me, &args)?;

    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }

    let ctx = Comms::with_buffer_capacity(OT_ECDSA_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES);
    let fut = do_sign(
        ctx.shared_channel(),
        participants,
        coordinator,
        me,
        args,
        tweak,
        msg_hash,
    );
    Ok(make_protocol(ctx, fut))
}

async fn do_sign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    coordinator: Participant,
    me: Participant,
    args: SignArguments,
    tweak: Tweak,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    let derived_public_key = tweak
        .derive_verifying_key(&args.keygen_out.public_key)
        .to_element()
        .to_affine();

    let presignature = nonce_generation_rounds(&mut chan, &participants, me, args)
        .await?
        .with_tweak(&tweak);
    chan.yield_point().await;

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
    presignature: &NonceGenerationOutput,
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
    presignature: &NonceGenerationOutput,
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
    use crate::ecdsa::ot_based_ecdsa::triples::{TriplePub, TripleShare};
    use crate::ecdsa::{KeygenOutput, Polynomial};
    use crate::test_utils::{
        GenProtocol, MockCryptoRng, assert_buffer_capacity, check_one_coordinator_output,
        deal_triple, expected_buffer_by_role, generate_participants, run_keygen, run_protocol,
        run_sign,
    };
    use k256::{ProjectivePoint, PublicKey, ecdsa::VerifyingKey, ecdsa::signature::Verifier};
    use rand_core::SeedableRng;
    use rstest::rstest;
    use std::{assert_matches, collections::HashMap};

    const MSG: &[u8] = b"presign and sign in one go";

    struct Setup {
        participants: Vec<Participant>,
        threshold: usize,
        key_packages: Vec<(Participant, KeygenOutput)>,
        triple0: (TriplePub, Vec<TripleShare>),
        triple1: (TriplePub, Vec<TripleShare>),
        tweak: Tweak,
        msg_hash: Scalar,
    }

    impl Setup {
        fn new(num_participants: usize, threshold: usize, rng: &mut MockCryptoRng) -> Self {
            let participants = generate_participants(num_participants);
            let key_packages = run_keygen(&participants, threshold, rng);
            let triple0 = deal_triple(rng, &participants, threshold.into()).unwrap();
            let triple1 = deal_triple(rng, &participants, threshold.into()).unwrap();
            let tweak = Tweak::new(frost_core::random_nonzero::<Secp256K1Sha256, _>(rng));
            Self {
                participants,
                threshold,
                key_packages,
                triple0,
                triple1,
                tweak,
                msg_hash: scalar_hash_secp256k1(MSG),
            }
        }

        fn args_for(&self, index: usize) -> SignArguments {
            SignArguments {
                triple0: (self.triple0.1[index].clone(), self.triple0.0.clone()),
                triple1: (self.triple1.1[index].clone(), self.triple1.0.clone()),
                keygen_out: self.key_packages[index].1.clone(),
                threshold: self.threshold.into(),
            }
        }

        fn args_by_participant(&self) -> HashMap<Participant, SignArguments> {
            (0..self.participants.len())
                .map(|i| (self.participants[i], self.args_for(i)))
                .collect()
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
    #[case(2, 2)]
    #[case(3, 3)]
    #[case(5, 3)]
    fn sign__should_produce_signature_verifiable_under_derived_key(
        #[case] num_participants: usize,
        #[case] threshold: usize,
    ) {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(num_participants, threshold, &mut rng);
        let coordinator = setup.participants[num_participants - 1];

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
        let setup = Setup::new(4, 3, &mut rng);
        let coordinator = setup.participants[1];

        // When
        let result = setup.run_sign(coordinator);

        // Then
        assert_eq!(result.len(), 4);
        for (participant, output) in &result {
            assert_eq!(output.is_some(), *participant == coordinator);
        }
    }

    #[test]
    fn sign__should_produce_deterministic_signature() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(3, 2, &mut rng);
        let coordinator = setup.participants[0];

        // When
        let result = setup.run_sign(coordinator);

        // Then
        let signature = check_one_coordinator_output(result, coordinator).unwrap();
        insta::assert_json_snapshot!(to_k256_signature(&signature));
    }

    #[test]
    fn sign__should_reject_coordinator_outside_participants() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(3, 2, &mut rng);
        let outsider = Participant::from(999u32);

        // When
        let result = sign(
            &setup.participants,
            outsider,
            setup.participants[0],
            setup.args_for(0),
            setup.tweak,
            setup.msg_hash,
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
    fn sign__should_reject_threshold_mismatch_with_triples() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(3, 2, &mut rng);
        let mut args = setup.args_for(0);
        args.threshold = 3.into();

        // When
        let result = sign(
            &setup.participants,
            setup.participants[0],
            setup.participants[0],
            args,
            setup.tweak,
            setup.msg_hash,
        );

        // Then
        assert_matches!(result.err(), Some(InitializationError::BadParameters(_)));
    }

    #[test]
    fn sign__should_reject_threshold_above_participant_count() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(3, 3, &mut rng);
        let signers = &setup.participants[..2];

        // When
        let result = sign(
            signers,
            signers[0],
            signers[0],
            setup.args_for(0),
            setup.tweak,
            setup.msg_hash,
        );

        // Then
        assert_matches!(
            result.err(),
            Some(InitializationError::ThresholdTooLarge {
                threshold: 3,
                max: 2
            })
        );
    }

    #[rstest]
    #[case(3, 2)]
    #[case(5, 3)]
    fn sign__should_bound_message_buffer_by_role(
        #[case] num_participants: usize,
        #[case] threshold: usize,
    ) {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(num_participants, threshold, &mut rng);
        let coordinator = setup.participants[0];
        let args = setup.args_by_participant();

        // When + Then
        assert_buffer_capacity(
            &setup.participants,
            &mut rng,
            |comms, p_list, p, _rng_p| {
                do_sign(
                    comms.shared_channel(),
                    p_list,
                    coordinator,
                    p,
                    args[&p].clone(),
                    setup.tweak,
                    setup.msg_hash,
                )
            },
            expected_buffer_by_role(
                coordinator,
                OT_ECDSA_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES,
                OT_ECDSA_SIGN_MAX_INCOMING_PARTICIPANT_ENTRIES,
            ),
        );
    }

    fn simulate_presignatures(
        participants: &[Participant],
        threshold: usize,
        rng: &mut MockCryptoRng,
    ) -> (ProjectivePoint, Vec<(Participant, NonceGenerationOutput)>) {
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
                    NonceGenerationOutput {
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
                let ctx =
                    Comms::with_buffer_capacity(OT_ECDSA_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES);
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
