use crate::ecdsa::ot_based_ecdsa::presign::{
    PresignArguments, presign_rounds, validate_presign_arguments,
};
use crate::ecdsa::ot_based_ecdsa::sign::sign_round;
use crate::ecdsa::{Scalar, SignatureOption, Tweak};
use crate::errors::{InitializationError, ProtocolError};
use crate::participants::{Participant, ParticipantList};
use crate::protocol::{
    Protocol,
    internal::{Comms, SharedChannel, make_protocol},
};

/// Maximum incoming buffer entries for the coordinator: the two waitpoints before signing
/// plus the signature-share waitpoint.
pub(crate) const OT_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES: usize = 3;
/// Maximum incoming buffer entries for non-coordinator participants: the two waitpoints
/// before signing.
#[cfg(test)]
pub(crate) const OT_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_PARTICIPANT_ENTRIES: usize = 2;

/// Presigning and signing as a single protocol, consuming two triples directly.
///
/// The presignature never leaves this computation and is never stored; the key-derivation
/// `tweak` is applied locally between the presigning rounds and the signing round. Only the
/// coordinator obtains the signature.
///
/// # Safety contract
///
/// Each triple, not just the pair, must be used at most once (see [`PresignArguments`]). In
/// particular, `big_r` is determined by `triple0` alone and is known to every participant once
/// round 1 completes. Nothing binds `big_r` to `msg_hash`, so a second run on the same `triple0`
/// under a different `tweak` or `msg_hash` leaks the private key.
///
/// **WARNING** You must absolutely hash an actual message before passing it to
/// this function. Allowing the signing of arbitrary scalars *is* a security risk,
/// and this function only tolerates this risk to allow for genericity.
pub fn presign_and_sign(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    args: PresignArguments,
    tweak: Tweak,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = SignatureOption> + use<>, InitializationError> {
    let participants = validate_presign_arguments(participants, me, &args)?;

    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }

    let ctx =
        Comms::with_buffer_capacity(OT_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES);
    let fut = do_presign_and_sign(
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

async fn do_presign_and_sign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    coordinator: Participant,
    me: Participant,
    args: PresignArguments,
    tweak: Tweak,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    let derived_public_key = tweak
        .derive_verifying_key(&args.keygen_out.public_key)
        .to_element()
        .to_affine();

    let presignature = presign_rounds(&mut chan, &participants, me, args)
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

#[cfg(test)]
#[allow(non_snake_case)]
mod test {
    use super::*;
    use crate::crypto::hash::test::scalar_hash_secp256k1;
    use crate::ecdsa::ot_based_ecdsa::triples::{TriplePub, TripleShare};
    use crate::ecdsa::{KeygenOutput, Secp256K1Sha256, Signature, x_coordinate};
    use crate::test_utils::{
        GenProtocol, MockCryptoRng, assert_buffer_capacity, check_one_coordinator_output,
        deal_triple, expected_buffer_by_role, generate_participants, run_keygen, run_protocol,
    };
    use k256::{PublicKey, ecdsa::VerifyingKey, ecdsa::signature::Verifier};
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

        fn args_for(&self, index: usize) -> PresignArguments {
            PresignArguments {
                triple0: (self.triple0.1[index].clone(), self.triple0.0.clone()),
                triple1: (self.triple1.1[index].clone(), self.triple1.0.clone()),
                keygen_out: self.key_packages[index].1.clone(),
                threshold: self.threshold.into(),
            }
        }

        fn args_by_participant(&self) -> HashMap<Participant, PresignArguments> {
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

        fn run_presign_and_sign(
            &self,
            coordinator: Participant,
        ) -> Vec<(Participant, SignatureOption)> {
            let mut protocols: GenProtocol<SignatureOption> =
                Vec::with_capacity(self.participants.len());
            for (i, p) in self.participants.iter().enumerate() {
                let protocol = presign_and_sign(
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
    fn presign_and_sign__should_produce_signature_verifiable_under_derived_key(
        #[case] num_participants: usize,
        #[case] threshold: usize,
    ) {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(num_participants, threshold, &mut rng);
        let coordinator = setup.participants[num_participants - 1];

        // When
        let result = setup.run_presign_and_sign(coordinator);

        // Then
        let signature = check_one_coordinator_output(result, coordinator).unwrap();
        setup
            .derived_verifying_key()
            .verify(MSG, &to_k256_signature(&signature))
            .unwrap();
    }

    #[test]
    fn presign_and_sign__should_return_signature_only_to_coordinator() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(4, 3, &mut rng);
        let coordinator = setup.participants[1];

        // When
        let result = setup.run_presign_and_sign(coordinator);

        // Then
        assert_eq!(result.len(), 4);
        for (participant, output) in &result {
            assert_eq!(output.is_some(), *participant == coordinator);
        }
    }

    #[test]
    fn presign_and_sign__should_produce_deterministic_signature() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(3, 2, &mut rng);
        let coordinator = setup.participants[0];

        // When
        let result = setup.run_presign_and_sign(coordinator);

        // Then
        let signature = check_one_coordinator_output(result, coordinator).unwrap();
        insta::assert_json_snapshot!(to_k256_signature(&signature));
    }

    #[test]
    fn presign_and_sign__should_reject_coordinator_outside_participants() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(3, 2, &mut rng);
        let outsider = Participant::from(999u32);

        // When
        let result = presign_and_sign(
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
    fn presign_and_sign__should_reject_threshold_mismatch_with_triples() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(3, 2, &mut rng);
        let mut args = setup.args_for(0);
        args.threshold = 3.into();

        // When
        let result = presign_and_sign(
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
    fn presign_and_sign__should_reject_threshold_above_participant_count() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(3, 3, &mut rng);
        let signers = &setup.participants[..2];

        // When
        let result = presign_and_sign(
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
    fn presign_and_sign__should_bound_message_buffer_by_role(
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
                do_presign_and_sign(
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
                OT_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES,
                OT_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_PARTICIPANT_ENTRIES,
            ),
        );
    }
}
