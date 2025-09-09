use super::{
    presign::presign,
    sign::sign,
    triples::{test::deal, TriplePub, TripleShare},
    PresignArguments, PresignOutput,
};
use crate::ecdsa::{test::run_sign, AffinePoint, FullSignature, KeygenOutput, Scalar};
use crate::protocol::{errors::InitializationError, run_protocol, Participant, Protocol};
use crate::test::{assert_public_key_invariant, run_keygen, run_refresh, run_reshare};
use crate::test::{generate_participants, generate_participants_with_random_ids};
use rand_core::OsRng;
use std::error::Error;

fn sign_box(
    participants: &[Participant],
    me: Participant,
    public_key: AffinePoint,
    presignature: PresignOutput,
    msg_hash: Scalar,
) -> Result<Box<dyn Protocol<Output = FullSignature>>, InitializationError> {
    sign(participants, me, public_key, presignature, msg_hash)
        .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = FullSignature>>)
}

pub fn run_presign(
    participants: Vec<(Participant, KeygenOutput)>,
    shares0: Vec<TripleShare>,
    shares1: Vec<TripleShare>,
    pub0: &TriplePub,
    pub1: &TriplePub,
    threshold: usize,
) -> Vec<(Participant, PresignOutput)> {
    assert!(participants.len() == shares0.len());
    assert!(participants.len() == shares1.len());

    #[allow(clippy::type_complexity)]
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
        );
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

#[test]
fn test_refresh() -> Result<(), Box<dyn Error>> {
    let participants = generate_participants(11);
    let max_malicious = 5;
    let threshold = max_malicious + 1;
    let keys = run_keygen(&participants, threshold)?;
    assert_public_key_invariant(&keys);
    // run refresh on these
    let mut key_packages = run_refresh(&participants, keys, threshold)?;
    key_packages.sort_by_key(|(p, _)| *p);
    let public_key = key_packages[0].1.public_key;
    assert_public_key_invariant(&key_packages);
    let (pub0, shares0) = deal(&mut OsRng, &participants, threshold).unwrap();
    let (pub1, shares1) = deal(&mut OsRng, &participants, threshold).unwrap();

    // Presign
    let mut presign_result = run_presign(key_packages, shares0, shares1, &pub0, &pub1, threshold);
    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";
    // internally verifies the signature's validity
    run_sign(
        presign_result,
        public_key.to_element().to_affine(),
        msg,
        sign_box,
    );

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
    let mut key_packages = run_reshare(
        &participants,
        &pub_key,
        result0,
        threshold,
        new_threshold,
        new_participant.clone(),
    )?;
    assert_public_key_invariant(&key_packages);
    key_packages.sort_by_key(|(p, _)| *p);

    let public_key = key_packages[0].1.public_key;
    // Prepare triples
    let (pub0, shares0) = deal(&mut OsRng, &new_participant, new_threshold).unwrap();
    let (pub1, shares1) = deal(&mut OsRng, &new_participant, new_threshold).unwrap();

    // Presign
    let mut presign_result =
        run_presign(key_packages, shares0, shares1, &pub0, &pub1, new_threshold);
    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    // internally verifies the signature's validity
    run_sign(
        presign_result,
        public_key.to_element().to_affine(),
        msg,
        sign_box,
    );
    Ok(())
}

#[test]
fn test_reshare_sign_less_participants() -> Result<(), Box<dyn Error>> {
    let participants = generate_participants(5);
    let threshold = 4;
    let result0 = run_keygen(&participants, threshold)?;
    assert_public_key_invariant(&result0);

    let pub_key = result0[2].1.public_key;

    // Run heavy reshare
    let new_threshold = 3;
    let mut new_participant = participants.clone();
    new_participant.pop();
    let mut key_packages = run_reshare(
        &participants,
        &pub_key,
        result0,
        threshold,
        new_threshold,
        new_participant.clone(),
    )?;
    assert_public_key_invariant(&key_packages);
    key_packages.sort_by_key(|(p, _)| *p);

    let public_key = key_packages[0].1.public_key;
    // Prepare triples
    let (pub0, shares0) = deal(&mut OsRng, &new_participant, new_threshold).unwrap();
    let (pub1, shares1) = deal(&mut OsRng, &new_participant, new_threshold).unwrap();

    // Presign
    let mut presign_result =
        run_presign(key_packages, shares0, shares1, &pub0, &pub1, new_threshold);
    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    // internally verifies the signature's validity
    run_sign(
        presign_result,
        public_key.to_element().to_affine(),
        msg,
        sign_box,
    );
    Ok(())
}

#[test]
fn test_e2e() -> Result<(), Box<dyn Error>> {
    let participants = generate_participants(3);
    let threshold = 3;

    let mut keygen_result = run_keygen(&participants.clone(), threshold)?;
    keygen_result.sort_by_key(|(p, _)| *p);

    let public_key = keygen_result[0].1.public_key;
    assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
    assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

    let (pub0, shares0) = deal(&mut OsRng, &participants, threshold).unwrap();
    let (pub1, shares1) = deal(&mut OsRng, &participants, threshold).unwrap();

    let mut presign_result = run_presign(keygen_result, shares0, shares1, &pub0, &pub1, threshold);
    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    // internally verifies the signature's validity
    run_sign(
        presign_result,
        public_key.to_element().to_affine(),
        msg,
        sign_box,
    );
    Ok(())
}

#[test]
fn test_e2e_random_identifiers() -> Result<(), Box<dyn Error>> {
    let participants_count = 3;
    let participants = generate_participants_with_random_ids(participants_count);
    let threshold = 3;

    let mut keygen_result = run_keygen(&participants.clone(), threshold)?;
    keygen_result.sort_by_key(|(p, _)| *p);

    let public_key = keygen_result[0].1.public_key;
    assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
    assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

    let (pub0, shares0) = deal(&mut OsRng, &participants, threshold).unwrap();
    let (pub1, shares1) = deal(&mut OsRng, &participants, threshold).unwrap();

    let mut presign_result = run_presign(keygen_result, shares0, shares1, &pub0, &pub1, threshold);
    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    // internally verifies the signature's validity
    run_sign(
        presign_result,
        public_key.to_element().to_affine(),
        msg,
        sign_box,
    );
    Ok(())
}
