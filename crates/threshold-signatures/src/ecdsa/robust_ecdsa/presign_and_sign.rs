use rand_core::CryptoRngCore;

use crate::ecdsa::robust_ecdsa::presign::{
    PresignArguments, presign_round, validate_presign_arguments,
};
use crate::ecdsa::robust_ecdsa::sign::sign_round;
use crate::ecdsa::{Scalar, SignatureOption, Tweak};
use crate::errors::{InitializationError, ProtocolError};
use crate::participants::{Participant, ParticipantList};
use crate::protocol::{
    Protocol,
    internal::{Comms, SharedChannel, make_protocol},
};

pub(crate) const ROBUST_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES: usize = 2;
#[cfg(test)]
pub(crate) const ROBUST_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_PARTICIPANT_ENTRIES: usize = 1;

/// Presigning and signing as a single protocol, run once the message is known. Only the
/// coordinator obtains the signature.
///
/// **This is a stub and leaks the signing key.** See the [module docs](super) before
/// using it for anything.
///
/// The `N = 2 * max_malicious + 1` participant count and the `msg_hash != 0`
/// rejection are retained from the removed scheme, which needed both to blunt
/// split-view attacks.
pub fn presign_and_sign<R>(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    args: PresignArguments,
    tweak: Tweak,
    msg_hash: Scalar,
    rng: R,
) -> Result<impl Protocol<Output = SignatureOption> + use<R>, InitializationError>
where
    R: CryptoRngCore + Send + 'static,
{
    let participants = validate_presign_arguments(participants, me, &args)?;

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

    let ctx =
        Comms::with_buffer_capacity(ROBUST_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES);
    let fut = do_presign_and_sign(
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
async fn do_presign_and_sign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    coordinator: Participant,
    me: Participant,
    args: PresignArguments,
    tweak: Tweak,
    msg_hash: Scalar,
    rng: impl CryptoRngCore,
) -> Result<SignatureOption, ProtocolError> {
    let derived_public_key = tweak
        .derive_verifying_key(&args.keygen_out.public_key)
        .to_element()
        .to_affine();

    let presignature = presign_round(&mut chan, &participants, me, args, rng)
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

#[cfg(test)]
#[allow(non_snake_case)]
mod test {
    use super::*;
    use crate::crypto::hash::test::scalar_hash_secp256k1;
    use crate::ecdsa::{KeygenOutput, Secp256K1Sha256, Signature, x_coordinate};
    use crate::test_utils::{
        GenProtocol, MockCryptoRng, assert_buffer_capacity, check_one_coordinator_output,
        expected_buffer_by_role, generate_participants, run_keygen, run_protocol,
    };
    use k256::{PublicKey, ecdsa::VerifyingKey, ecdsa::signature::Verifier};
    use rand_core::{RngCore, SeedableRng};
    use rstest::rstest;
    use std::assert_matches;

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

        fn args_for(&self, index: usize) -> PresignArguments {
            PresignArguments {
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
    fn presign_and_sign__should_produce_signature_verifiable_under_derived_key(
        #[case] max_malicious: usize,
    ) {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(max_malicious, &mut rng);
        let coordinator = setup.participants[setup.participants.len() - 1];

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
        let setup = Setup::new(2, &mut rng);
        let coordinator = setup.participants[1];

        // When
        let result = setup.run_presign_and_sign(coordinator);

        // Then
        assert_eq!(result.len(), 5);
        for (participant, output) in &result {
            assert_eq!(output.is_some(), *participant == coordinator);
        }
    }

    #[test]
    fn presign_and_sign__should_reject_coordinator_outside_participants() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(1, &mut rng);
        let outsider = Participant::from(999u32);

        // When
        let result = presign_and_sign(
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
    fn presign_and_sign__should_reject_zero_msg_hash() {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(1, &mut rng);

        // When
        let result = presign_and_sign(
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
    fn presign_and_sign__should_reject_participant_count_other_than_two_max_malicious_plus_one(
        #[case] setup_max_malicious: usize,
        #[case] args_max_malicious: usize,
    ) {
        // Given
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let setup = Setup::new(setup_max_malicious, &mut rng);
        let mut args = setup.args_for(0);
        args.max_malicious = args_max_malicious.into();

        // When
        let result = presign_and_sign(
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
    fn presign_and_sign__should_bound_message_buffer_by_role(#[case] max_malicious: usize) {
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
                do_presign_and_sign(
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
                ROBUST_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_COORDINATOR_ENTRIES,
                ROBUST_ECDSA_PRESIGN_AND_SIGN_MAX_INCOMING_PARTICIPANT_ENTRIES,
            ),
        );
    }
}
