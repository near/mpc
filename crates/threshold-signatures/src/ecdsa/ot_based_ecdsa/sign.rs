use elliptic_curve::scalar::IsHigh;
use subtle::ConditionallySelectable;

use crate::ReconstructionThreshold;
use crate::ecdsa::ot_based_ecdsa::triples::{TriplePub, TripleShare};
use crate::ecdsa::{
    AffinePoint, KeygenOutput, ProjectivePoint, Scalar, Secp256K1Sha256, Signature,
    SignatureOption, Tweak, x_coordinate,
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

/// The arguments needed to create a signature.
///
/// Each triple must be an unmodified triple generation output, used at most once.
#[derive(Debug, Clone)]
pub struct SignArguments {
    /// The first triple's public information, and our share.
    pub triple0: (TripleShare, TriplePub),
    /// Ditto, for the second triple.
    pub triple1: (TripleShare, TriplePub),
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    /// This is of type `KeygenOutput<Secp256K1Sha256>` from Frost implementation
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the signature, which must match the original threshold
    pub threshold: ReconstructionThreshold,
}

/// The signing protocol, consuming two triples directly.
///
/// The nonce never leaves this computation and is never stored; the key-derivation `tweak` is
/// applied locally in round 2. Only the coordinator obtains the signature.
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
    let participants = validate_sign_arguments(participants, coordinator, me, &args)?;

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

/// Checks the participant set against `args` and returns it as a [`ParticipantList`].
fn validate_sign_arguments(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    args: &SignArguments,
) -> Result<ParticipantList, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    // Spec 1.1
    if args.threshold.value() > participants.len() {
        return Err(InitializationError::ThresholdTooLarge {
            threshold: args.threshold.value(),
            max: participants.len(),
        });
    }

    // NOTE: We omit the check that the new participant set was present for
    // the triple generation, because presumably they need to have been present
    // in order to have shares.

    // Also check that we have enough participants to reconstruct shares.
    if args.threshold != args.triple0.1.threshold || args.threshold != args.triple1.1.threshold {
        return Err(InitializationError::BadParameters(
            "New threshold must match the threshold of both triples".to_string(),
        ));
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }

    Ok(participants)
}

#[allow(clippy::too_many_lines)]
async fn do_sign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    coordinator: Participant,
    me: Participant,
    args: SignArguments,
    tweak: Tweak,
    msg_hash: Scalar,
) -> Result<SignatureOption, ProtocolError> {
    // Round 1
    // Extracting triples private variables (ai, bi, ci)
    let a_i = args.triple1.0.a;
    let b_i = args.triple1.0.b;
    let c_i = args.triple1.0.c;

    // Extracting triples public variables (A, B, _)
    // notice C is not used
    let big_a: ProjectivePoint = args.triple1.1.big_a.into();
    let big_b: ProjectivePoint = args.triple1.1.big_b.into();

    // Extracting triples private variables (ki, _, ei)
    // notice di is not used
    let k_i = args.triple0.0.a;
    let e_i = args.triple0.0.c;

    // Extracting triples public variables (K, D, E)
    let big_k: ProjectivePoint = args.triple0.1.big_a.into();
    let big_d = args.triple0.1.big_b;
    let big_e = args.triple0.1.big_c;

    // linearize ki ei ai bi ci xi
    // Spec 1.1
    let lambda_me = participants.lagrange::<Secp256K1Sha256>(me)?;

    let k_prime_i = lambda_me * k_i;
    let e_i: Scalar = lambda_me * e_i;

    let a_prime_i = lambda_me * a_i;
    let b_prime_i = lambda_me * b_i;

    let big_x: ProjectivePoint = args.keygen_out.public_key.to_element();
    let private_share = args.keygen_out.private_share.to_scalar();
    let x_prime_i = lambda_me * private_share;

    // Send ei
    // Spec 1.2
    let wait0 = chan.next_waitpoint();
    chan.send_many(wait0, &e_i)?;

    // Receive ej and compute e = SUM_j ej
    // Spec 1.3
    let mut e = e_i;

    for (_, e_j) in recv_from_others::<Scalar>(&chan, wait0, &participants, me).await? {
        if e_j.is_zero().into() {
            return Err(ProtocolError::AssertionFailed(
                "Received zero share of kd, indicating a triple wasn't available.".to_string(),
            ));
        }

        // Spec 1.4
        e += e_j;
    }

    // E =?= e*G
    // Spec 1.5
    if big_e != (ProjectivePoint::GENERATOR * e).to_affine() {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of kd".to_string(),
        ));
    }

    // Round 2
    // alphai = ki' + ai'
    // Spec 2.1
    let alpha_i: Scalar = k_prime_i + a_prime_i;
    // betai = xi' + bi'
    let beta_i: Scalar = x_prime_i + b_prime_i;

    // Send alphai and betai
    // Spec 2.2
    let wait1 = chan.next_waitpoint();
    chan.send_many(wait1, &(alpha_i, beta_i))?;

    // Receive and compute alpha = SUM_j alphaj
    // Receive and compute beta = SUM_j betaj
    // Spec 2.3
    let mut alpha = alpha_i;
    let mut beta = beta_i;

    for (_, (alpha_j, beta_j)) in
        recv_from_others::<(Scalar, Scalar)>(&chan, wait1, &participants, me).await?
    {
        // Spec 2.4
        alpha += alpha_j;
        beta += beta_j;
    }

    // alpha*G =?= K + A
    // beta*G =?= X + B
    // Spec 2.5
    if (ProjectivePoint::GENERATOR * alpha != big_k + big_a)
        || (ProjectivePoint::GENERATOR * beta != big_x + big_b)
    {
        return Err(ProtocolError::AssertionFailed(
            "received incorrect shares of additive triple phase.".to_string(),
        ));
    }

    // Compute R = 1/e * D
    // Spec 2.6
    let e_inv: Option<Scalar> = e.invert().into();
    let e_inv =
        e_inv.ok_or_else(|| ProtocolError::AssertionFailed("failed to invert kd".to_string()))?;
    let big_r: AffinePoint = (big_d * e_inv).into();

    // sigmai = alpha*xi - beta*ai + ci + tweak*ki
    // Spec 2.7
    let sigma_i = alpha * private_share - (beta * a_i - c_i) + tweak.value() * k_i;
    chan.yield_point().await;

    // Round 3
    // Linearize ki
    // Spec 3.1
    let k_i = k_prime_i;

    // Linearize sigmai
    // Spec 3.2
    let sigma_i = lambda_me * sigma_i;

    // Compute si = h * ki + Rx * sigmai
    // Spec 3.3
    let r = x_coordinate(&big_r);
    let s_i = msg_hash * k_i + r * sigma_i;

    let wait2 = chan.next_waitpoint();
    if me != coordinator {
        // Send si
        // Spec 3.4
        chan.send_private(wait2, coordinator, &s_i)?;
        return Ok(None);
    }

    // Receive sj
    // Spec 3.5
    let mut s = s_i;
    for (_, s_j) in recv_from_others::<Scalar>(&chan, wait2, &participants, me).await? {
        // Spec 3.6
        s += s_j;
    }

    // Normalize s
    // Spec 3.7
    s.conditional_assign(&(-s), s.is_high());

    let sig = Signature { big_r, s };

    // Spec 3.8
    let public_key = tweak
        .derive_verifying_key(&args.keygen_out.public_key)
        .to_element()
        .to_affine();
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }

    Ok(Some(sig))
}

#[cfg(test)]
#[allow(non_snake_case)]
mod test {
    use super::*;
    use crate::crypto::hash::test::scalar_hash_secp256k1;
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
}
