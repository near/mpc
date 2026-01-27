use crate::crypto::hash::{hash, HashOutput};
use crate::eddsa::redjubjub::{
    presign::presign, sign::sign, KeygenOutput, PresignArguments, PresignOutput, SignatureOption,
};
use crate::participants::{Participant, ParticipantList};
use crate::protocol::Protocol;
use crate::test_utils::{
    assert_public_key_invariant, generate_participants, generate_participants_with_random_ids,
    one_coordinator_output, run_keygen, run_protocol, run_refresh, run_reshare, GenOutput,
    GenProtocol, MockCryptoRng,
};

use frost_core::{Field, Scalar};
use rand::Rng;
use rand::SeedableRng;
use rand_core::{CryptoRngCore, RngCore};
use reddsa::frost::redjubjub::{
    keys::{generate_with_dealer, IdentifierList, SigningShare},
    round1::{commit, SigningCommitments, SigningNonces},
    Identifier, JubjubBlake2b512, JubjubScalarField, Randomizer, SigningKey, VerifyingKey,
};
use std::collections::BTreeMap;
use std::error::Error;

type C = JubjubBlake2b512;

/// this is a centralized key generation
pub fn build_key_packages_with_dealer(
    max_signers: u16,
    min_signers: u16,
    rng: &mut impl CryptoRngCore,
) -> GenOutput<C> {
    use std::collections::BTreeMap;

    let mut identifiers = Vec::with_capacity(max_signers.into());
    for _ in 0..max_signers {
        // from 1 to avoid assigning 0 to a ParticipantId
        identifiers.push(Participant::from(rng.next_u32()));
    }

    let from_frost_identifiers = identifiers
        .iter()
        .map(|&x| (x.to_identifier().unwrap(), x))
        .collect::<BTreeMap<_, _>>();

    let identifiers_list = from_frost_identifiers.keys().copied().collect::<Vec<_>>();

    let (shares, pubkey_package) = generate_with_dealer(
        max_signers,
        min_signers,
        IdentifierList::Custom(identifiers_list.as_slice()),
        rng,
    )
    .unwrap();

    shares
        .into_iter()
        .map(|(id, share)| {
            (
                from_frost_identifiers[&id],
                KeygenOutput {
                    private_share: *share.signing_share(),
                    public_key: *pubkey_package.verifying_key(),
                },
            )
        })
        .collect::<Vec<_>>()
}

pub fn test_run_presignature(
    participants: &[(Participant, KeygenOutput)],
    threshold: usize,
    actual_signers: usize,
) -> Result<Vec<(Participant, PresignOutput)>, Box<dyn Error>> {
    let mut protocols: GenProtocol<PresignOutput> = Vec::with_capacity(participants.len());

    let participants_list = participants
        .iter()
        .take(actual_signers)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();

    for (participant, keygen_out) in participants.iter().take(actual_signers) {
        let rng = MockCryptoRng::seed_from_u64(42);
        let args = PresignArguments {
            keygen_out: keygen_out.clone(),
            threshold,
        };
        // run the signing scheme
        let protocol = presign(&participants_list, *participant, &args, rng)?;

        protocols.push((*participant, Box::new(protocol)));
    }

    Ok(run_protocol(protocols)?)
}

#[allow(clippy::panic_in_result_fn)]
#[allow(clippy::missing_panics_doc)]
pub fn test_run_signature(
    participants: &[(Participant, KeygenOutput)],
    actual_signers: usize,
    coordinators: &[Participant],
    threshold: usize,
    msg_hash: HashOutput,
) -> Result<Vec<(Participant, SignatureOption)>, Box<dyn Error>> {
    let mut rng = MockCryptoRng::seed_from_u64(644_221);
    let randomizer_scalar = JubjubScalarField::random(&mut rng);
    // only for testing
    let randomizer = Randomizer::from_scalar(randomizer_scalar);

    let mut protocols: GenProtocol<SignatureOption> = Vec::with_capacity(participants.len());
    let presig = test_run_presignature(participants, threshold, actual_signers)?;

    let participants_list = participants
        .iter()
        .take(actual_signers)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();
    let coordinators = ParticipantList::new(coordinators).unwrap();
    for ((participant, key_pair), (participant_redundancy, presignature)) in
        participants.iter().zip(presig.iter())
    {
        assert_eq!(participant, participant_redundancy);
        let mut rng_p = MockCryptoRng::seed_from_u64(42);
        let mut coordinator = *participant;
        if !coordinators.contains(coordinator) {
            // pick any coordinator
            let index = rng_p.next_u32() as usize % coordinators.len();
            coordinator = coordinators.get_participant(index).unwrap();
        }
        let randomize = if *participant == coordinator {
            Some(randomizer)
        } else {
            None
        };
        // run the signing scheme
        let protocol = sign(
            &participants_list,
            threshold,
            *participant,
            coordinator,
            key_pair.clone(),
            presignature.clone(),
            msg_hash.as_ref().to_vec(),
            randomize,
        )?;
        protocols.push((*participant, Box::new(protocol)));
    }

    Ok(run_protocol(protocols)?)
}

#[test]
#[allow(non_snake_case)]
fn keygen_output__should_be_serializable() {
    // Given
    let mut rng = MockCryptoRng::seed_from_u64(42u64);
    let signing_key = SigningKey::new(&mut rng);

    let keygen_output = KeygenOutput {
        private_share: SigningShare::new(Scalar::<C>::from(7_u64)),
        public_key: VerifyingKey::from(signing_key),
    };

    // When
    let serialized_keygen_output =
        serde_json::to_string(&keygen_output).expect("should be able to serialize output");

    // Then
    assert_eq!(
        serialized_keygen_output,
        "{\"private_share\":\"0700000000000000000000000000000000000000000000000000000000000000\",\"public_key\":\"cee9f1be0b483c2760c22acdf87b79e3a6b89ff755d697a3ba3933d6e6807499\"}"
    );
}

#[test]
fn test_keygen() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(3);
    let threshold = 2;
    crate::dkg::test::test_keygen::<C, _>(&participants, threshold, &mut rng);
}

#[test]
fn test_refresh() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(3);
    let threshold = 2;
    crate::dkg::test::test_refresh::<C, _>(&participants, threshold, &mut rng);
}

#[test]
fn test_reshare() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(3);
    let threshold0 = 2;
    let threshold1 = 3;
    crate::dkg::test::test_reshare::<C, _>(&participants, threshold0, threshold1, &mut rng);
}

#[test]
fn test_keygen_determinism() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(3);
    let threshold = 2;
    let result = crate::dkg::test::test_keygen::<C, _>(&participants, threshold, &mut rng);
    insta::assert_json_snapshot!(result);
}

#[test]
fn test_refresh_determinism() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(3);
    let threshold = 2;
    let result = crate::dkg::test::test_refresh::<C, _>(&participants, threshold, &mut rng);
    insta::assert_json_snapshot!(result);
}

#[test]
fn test_reshare_determinism() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(3);
    let threshold0 = 2;
    let threshold1 = 3;
    let result =
        crate::dkg::test::test_reshare::<C, _>(&participants, threshold0, threshold1, &mut rng);
    insta::assert_json_snapshot!(result);
}

#[test]
fn test_keygen_threshold_limits() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    crate::dkg::test::keygen__should_fail_if_threshold_is_below_limit::<C, _>(&mut rng);
}

#[test]
fn test_reshare_threshold_limits() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    crate::dkg::test::reshare__should_fail_if_threshold_is_below_limit::<C, _>(&mut rng);
}

#[test]
fn dkg_refresh_sign_test() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants_with_random_ids(4, &mut rng);
    let actual_signers = participants.len();
    let threshold = 2;

    let mut key_packages = run_keygen(&participants, threshold, &mut rng);
    // test dkg
    for i in 0..3 {
        let msg = format!("hellprotocolo_near_{i}");
        let msg_hash = hash(&msg).unwrap();
        assert_public_key_invariant(&key_packages);
        let coordinators = vec![key_packages[0].0];
        // This internally verifies with the rerandomized public key
        let data = test_run_signature(
            &key_packages,
            actual_signers,
            &coordinators,
            threshold,
            msg_hash,
        )
        .unwrap();
        one_coordinator_output(data, coordinators[0]).unwrap();
        key_packages = run_refresh(&participants, &key_packages, threshold, &mut rng);
    }
}

#[test]
fn dkg_reshare_more_participants_sign_test() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let mut participants = generate_participants_with_random_ids(4, &mut rng);
    let actual_signers = participants.len();
    let mut threshold = 2;

    let mut new_participant = participants.clone();
    let mut key_packages = run_keygen(&participants, threshold, &mut rng);
    // test dkg
    for i in 0..3 {
        let msg = format!("hello_near_{i}");
        let msg_hash = hash(&msg).unwrap();
        assert_public_key_invariant(&key_packages);
        let coordinators = vec![key_packages[0].0];
        // This internally verifies with the rerandomized public key
        let data = test_run_signature(
            &key_packages,
            actual_signers,
            &coordinators,
            threshold,
            msg_hash,
        )
        .unwrap();
        one_coordinator_output(data, coordinators[0]).unwrap();

        new_participant.push(Participant::from(20u32 + i));

        let new_threshold = threshold + 1;
        key_packages = run_reshare(
            &participants,
            &key_packages[0].1.public_key,
            &key_packages,
            threshold,
            new_threshold,
            &new_participant,
            &mut rng,
        );
        // update the old parameters
        threshold = new_threshold;
        participants.push(Participant::from(20u32 + i));
    }
}

#[test]
fn dkg_reshare_less_participants_sign_test() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let mut participants = generate_participants_with_random_ids(9, &mut rng);
    let actual_signers = participants.len();
    let mut threshold = 7;

    let mut new_participant = participants.clone();
    let mut key_packages = run_keygen(&participants, threshold, &mut rng);
    // test dkg
    for i in 0..3 {
        let msg = format!("hello_near_{i}");
        let msg_hash = hash(&msg).unwrap();
        assert_public_key_invariant(&key_packages);
        let coordinators = vec![key_packages[0].0];
        // This internally verifies with the rerandomized public key
        let data = test_run_signature(
            &key_packages,
            actual_signers,
            &coordinators,
            threshold,
            msg_hash,
        )
        .unwrap();
        one_coordinator_output(data, coordinators[0]).unwrap();

        new_participant.pop();

        let new_threshold = threshold - 1;
        key_packages = run_reshare(
            &participants,
            &key_packages[0].1.public_key,
            &key_packages,
            threshold,
            new_threshold,
            &new_participant,
            &mut rng,
        );
        // update the old parameters
        threshold = new_threshold;
        participants.pop();
    }
}

#[test]
fn test_signature_correctness() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let threshold = 6;
    let keys = build_key_packages_with_dealer(11, threshold, &mut rng);
    let public_key = keys[0].1.public_key.to_element();

    let msg = b"hello worldhello worldhello worlregerghwhrth".to_vec();
    let index = rng.gen_range(0..keys.len());
    let coordinator = keys[index as usize].0;

    let mut participants_sign_builder: Vec<(Participant, (KeygenOutput, MockCryptoRng))> = keys
        .iter()
        .map(|(p, keygen_output)| {
            let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
            (*p, (keygen_output.clone(), rng_p))
        })
        .collect();

    let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
    let mut nonces_map: BTreeMap<Participant, SigningNonces> = BTreeMap::new();
    for (p, (keygen, rng_p)) in &mut participants_sign_builder {
        // Creating two commitments and corresponding nonces
        let (nonces, commitments) = commit(&keygen.private_share, rng_p);
        commitments_map.insert(p.to_identifier().unwrap(), commitments);
        nonces_map.insert(*p, nonces);
    }

    let mut rng = MockCryptoRng::seed_from_u64(644_221);
    let randomizer_scalar = JubjubScalarField::random(&mut rng);
    // only for testing
    let randomizer = Randomizer::from_scalar(randomizer_scalar);

    // This checks the output signature validity internally
    let result =
        crate::test_utils::run_sign::<JubjubBlake2b512, (KeygenOutput, MockCryptoRng), _, _>(
            participants_sign_builder,
            coordinator,
            public_key,
            JubjubScalarField::zero(), // not important
            |participants, coordinator, me, _, (keygen_output, _), _| {
                let nonces = nonces_map.get(&me).unwrap().clone();
                let presignature = PresignOutput {
                    nonces,
                    commitments_map: commitments_map.clone(),
                };
                let randomize = if me == coordinator {
                    Some(randomizer)
                } else {
                    None
                };
                sign(
                    participants,
                    threshold as usize,
                    me,
                    coordinator,
                    keygen_output,
                    presignature,
                    msg.clone(),
                    randomize,
                )
                .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
            },
        )
        .unwrap();
    let signature = one_coordinator_output(result, coordinator).unwrap();

    insta::assert_json_snapshot!(signature);
}
