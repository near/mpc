use super::{
    presign::presign,
    sign::sign,
    triples::{test::deal, TriplePub, TripleShare},
    PresignArguments, PresignOutput,
};
use crate::ecdsa::{
    Element, KeygenOutput, ParticipantList, RerandomizationArguments, Secp256K1Sha256, Signature,
    SignatureOption, Tweak,
};
use crate::protocol::{run_protocol, Participant, Protocol};
use crate::test::{
    assert_public_key_invariant, generate_participants, generate_participants_with_random_ids,
    one_coordinator_output, run_keygen, run_refresh, run_reshare,
};
use crate::{
    crypto::hash::test::scalar_hash_secp256k1, ecdsa::ot_based_ecdsa::RerandomizedPresignOutput,
};

use rand::rngs::OsRng;
use rand::Rng;
use rand_core::RngCore;
use std::error::Error;

/// Runs signing by calling the generic `run_sign` function from `crate::test`
/// This signing does not rerandomize the presignatures and tests only the core protocol
pub fn run_sign_without_rerandomization(
    participants_presign: &[(Participant, PresignOutput)],
    public_key: Element,
    msg: &[u8],
) -> Result<(Participant, Signature), Box<dyn Error>> {
    // hash the message into secp256k1 field
    let msg_hash = scalar_hash_secp256k1(msg);
    let rerand_participants_presign = participants_presign
        .iter()
        .map(|(p, presig)| {
            (
                *p,
                RerandomizedPresignOutput::new_without_rerandomization(presig),
            )
        })
        .collect::<Vec<_>>();
    // choose a coordinator at random
    let index = OsRng.gen_range(0..participants_presign.len());
    let coordinator = participants_presign[index].0;

    // run sign instanciation with the necessary arguments
    let result = crate::test::run_sign::<Secp256K1Sha256, _, _, _>(
        rerand_participants_presign,
        coordinator,
        public_key,
        msg_hash,
        |participants, coordinator, me, pk, presignature, msg_hash| {
            let pk = pk.to_affine();
            sign(participants, coordinator, me, pk, presignature, msg_hash)
                .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
        },
    )?;
    // test one single some for the coordinator
    let signature = one_coordinator_output(result, coordinator)?;
    Ok((coordinator, signature))
}

/// Runs signing by calling the generic `run_sign` function from `crate::test`
/// This signing mimics what should happen in real world, i.e.,
/// rerandomizing the presignatures
pub fn run_sign_with_rerandomization(
    participants_presign: &[(Participant, PresignOutput)],
    public_key: Element,
    msg: &[u8],
) -> Result<(Tweak, Participant, Signature), Box<dyn Error>> {
    // hash the message into secp256k1 field
    let msg_hash = scalar_hash_secp256k1(msg);

    // generate a random tweak
    let tweak = Tweak::new(frost_core::random_nonzero::<Secp256K1Sha256, _>(&mut OsRng));
    // generate a random public entropy
    let mut entropy: [u8; 32] = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);

    let pk = public_key.to_affine();
    let big_r = participants_presign[0].1.big_r;
    let participants = ParticipantList::new(
        &participants_presign
            .iter()
            .map(|(p, _)| *p)
            .collect::<Vec<Participant>>(),
    )
    .unwrap();
    let msg_hash_bytes: [u8; 32] = msg_hash.to_bytes().into();
    let rerand_args =
        RerandomizationArguments::new(pk, msg_hash_bytes, big_r, participants, entropy);
    let public_key = frost_core::VerifyingKey::new(public_key);
    let derived_pk = tweak.derive_verifying_key(&public_key).to_element();

    let rerand_participants_presign = participants_presign
        .iter()
        .map(|(p, presig)| {
            RerandomizedPresignOutput::new(presig, &tweak, &rerand_args).map(|out| (*p, out))
        })
        .collect::<Result<_, _>>()?;

    // choose a coordinator at random
    let index = OsRng.gen_range(0..participants_presign.len());
    let coordinator = participants_presign[index].0;

    // run sign instanciation with the necessary arguments
    let result = crate::test::run_sign::<Secp256K1Sha256, _, _, _>(
        rerand_participants_presign,
        coordinator,
        derived_pk,
        msg_hash,
        |participants, coordinator, me, pk, presignature, msg_hash| {
            let pk = pk.to_affine();
            sign(participants, coordinator, me, pk, presignature, msg_hash)
                .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
        },
    )?;

    // test one single some for the coordinator
    let signature = one_coordinator_output(result, coordinator)?;
    Ok((tweak, coordinator, signature))
}

pub fn run_presign(
    participants: Vec<(Participant, KeygenOutput)>,
    shares0: Vec<TripleShare>,
    shares1: Vec<TripleShare>,
    pub0: &TriplePub,
    pub1: &TriplePub,
    threshold: usize,
) -> Result<Vec<(Participant, PresignOutput)>, Box<dyn Error>> {
    assert!(participants.len() == shares0.len());
    assert!(participants.len() == shares1.len());

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)> =
        Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

    for (((p, keygen_out), share0), share1) in participants
        .into_iter()
        .zip(shares0.into_iter())
        .zip(shares1.into_iter())
    {
        let protocol = presign(
            &participant_list,
            p,
            PresignArguments {
                triple0: (share0, pub0.clone()),
                triple1: (share1, pub1.clone()),
                keygen_out,
                threshold,
            },
        )
        .unwrap();
        protocols.push((p, Box::new(protocol)));
    }

    let mut result = run_protocol(protocols)?;
    result.sort_by_key(|(p, _)| *p);
    Ok(result)
}

#[test]
fn test_refresh() -> Result<(), Box<dyn Error>> {
    let participants = generate_participants(11);
    let max_malicious = 5;
    let threshold = max_malicious + 1;
    let keys = run_keygen(&participants, threshold)?;
    assert_public_key_invariant(&keys);
    // run refresh on these
    let key_packages = run_refresh(&participants, &keys, threshold)?;
    let public_key = key_packages[0].1.public_key;
    assert_public_key_invariant(&key_packages);
    let (pub0, shares0) = deal(&mut OsRng, &participants, threshold)?;
    let (pub1, shares1) = deal(&mut OsRng, &participants, threshold)?;

    // Presign
    let presign_result = run_presign(key_packages, shares0, shares1, &pub0, &pub1, threshold)?;

    let msg = b"hello world";
    // internally verifies the signature's validity
    run_sign_without_rerandomization(&presign_result, public_key.to_element(), msg)?;
    Ok(())
}

#[test]
fn test_reshare_sign_more_participants() -> Result<(), Box<dyn Error>> {
    let participants = generate_participants(5);
    let threshold = 3;
    let result0 = run_keygen(&participants, threshold)?;
    assert_public_key_invariant(&result0);

    let pub_key = result0[2].1.public_key;

    // Run heavy reshare
    let new_threshold = 5;
    let mut new_participant = participants.clone();
    new_participant.push(Participant::from(31u32));
    new_participant.push(Participant::from(32u32));
    new_participant.push(Participant::from(33u32));
    let key_packages = run_reshare(
        &participants,
        &pub_key,
        &result0,
        threshold,
        new_threshold,
        &new_participant,
    )?;
    assert_public_key_invariant(&key_packages);

    let public_key = key_packages[0].1.public_key;
    // Prepare triples
    let (pub0, shares0) = deal(&mut OsRng, &new_participant, new_threshold)?;
    let (pub1, shares1) = deal(&mut OsRng, &new_participant, new_threshold)?;

    // Presign
    let presign_result = run_presign(key_packages, shares0, shares1, &pub0, &pub1, new_threshold)?;

    let msg = b"hello world";
    // internally verifies the signature's validity
    run_sign_without_rerandomization(&presign_result, public_key.to_element(), msg)?;
    Ok(())
}

#[test]
fn test_reshare_sign_less_participants() -> Result<(), Box<dyn Error>> {
    let participants = generate_participants(5);
    let threshold = 4;
    let mut rng = OsRng;
    let result0 = run_keygen(&participants, threshold)?;
    assert_public_key_invariant(&result0);

    let pub_key = result0[2].1.public_key;

    // Run heavy reshare
    let new_threshold = 3;
    let mut new_participant = participants.clone();
    new_participant.pop();
    let key_packages = run_reshare(
        &participants,
        &pub_key,
        &result0,
        threshold,
        new_threshold,
        &new_participant,
    )?;
    assert_public_key_invariant(&key_packages);

    let public_key = key_packages[0].1.public_key;
    // Prepare triples
    let (pub0, shares0) = deal(&mut rng, &new_participant, new_threshold)?;
    let (pub1, shares1) = deal(&mut rng, &new_participant, new_threshold)?;

    let presign_result = run_presign(key_packages, shares0, shares1, &pub0, &pub1, new_threshold)?;

    let msg = b"hello world";
    // internally verifies the signature's validity
    run_sign_without_rerandomization(&presign_result, public_key.to_element(), msg)?;
    Ok(())
}

#[test]
fn test_e2e() -> Result<(), Box<dyn Error>> {
    let participants = generate_participants(3);
    let threshold = 3;

    let mut rng = OsRng;
    let key_packages = run_keygen(&participants.clone(), threshold)?;

    assert_public_key_invariant(&key_packages);
    let public_key = key_packages[0].1.public_key;

    let (pub0, shares0) = deal(&mut rng, &participants, threshold)?;
    let (pub1, shares1) = deal(&mut rng, &participants, threshold)?;

    let presign_result = run_presign(key_packages, shares0, shares1, &pub0, &pub1, threshold)?;

    let msg = b"hello world";
    // internally verifies the signature's validity
    run_sign_without_rerandomization(&presign_result, public_key.to_element(), msg)?;
    Ok(())
}

#[test]
fn test_e2e_random_identifiers() -> Result<(), Box<dyn Error>> {
    let participants_count = 3;
    let mut rng = OsRng;
    let participants = generate_participants_with_random_ids(participants_count, &mut rng);
    let threshold = 3;

    let key_packages = run_keygen(&participants.clone(), threshold)?;
    assert_public_key_invariant(&key_packages);

    let public_key = key_packages[0].1.public_key;

    let (pub0, shares0) = deal(&mut rng, &participants, threshold)?;
    let (pub1, shares1) = deal(&mut rng, &participants, threshold)?;

    let presign_result = run_presign(key_packages, shares0, shares1, &pub0, &pub1, threshold)?;

    let msg = b"hello world";
    // internally verifies the signature's validity
    run_sign_without_rerandomization(&presign_result, public_key.to_element(), msg)?;
    Ok(())
}

#[test]
fn test_e2e_random_identifiers_with_rerandomization() -> Result<(), Box<dyn Error>> {
    let participants_count = 3;
    let mut rng = OsRng;
    let participants = generate_participants_with_random_ids(participants_count, &mut rng);
    let threshold = 3;

    let key_packages = run_keygen(&participants.clone(), threshold)?;
    assert_public_key_invariant(&key_packages);

    let public_key = key_packages[0].1.public_key;

    let (pub0, shares0) = deal(&mut rng, &participants, threshold)?;
    let (pub1, shares1) = deal(&mut rng, &participants, threshold)?;

    let presign_result = run_presign(key_packages, shares0, shares1, &pub0, &pub1, threshold)?;

    let msg = b"hello world";
    // internally verifies the signature's validity
    run_sign_with_rerandomization(&presign_result, public_key.to_element(), msg)?;
    Ok(())
}
