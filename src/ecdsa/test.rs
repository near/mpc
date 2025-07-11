use k256::{AffinePoint, Secp256k1};
use std::error::Error;

use crate::compat::scalar_hash;

use crate::ecdsa::dkg_ecdsa::{keygen, refresh, reshare};
use crate::ecdsa::{
    presign::{presign, PresignArguments, PresignOutput},
    sign::{sign, FullSignature},
    triples::{self, TriplePub, TripleShare},
    KeygenOutput,
};
use crate::protocol::{run_protocol, Participant, Protocol};

use frost_secp256k1::VerifyingKey;
use rand_core::OsRng;

/// runs distributed keygen
pub(crate) fn run_keygen(
    participants: &[Participant],
    threshold: usize,
) -> Result<Vec<(Participant, KeygenOutput)>, Box<dyn Error>> {
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
        Vec::with_capacity(participants.len());

    for p in participants.iter() {
        let protocol = keygen(participants, *p, threshold)?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
    Ok(result)
}

/// runs distributed refresh
pub(crate) fn run_refresh(
    participants: &[Participant],
    keys: Vec<(Participant, KeygenOutput)>,
    threshold: usize,
) -> Result<Vec<(Participant, KeygenOutput)>, Box<dyn Error>> {
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
        Vec::with_capacity(participants.len());

    for (p, out) in keys.iter() {
        let protocol = refresh(
            Some(out.private_share),
            out.public_key,
            participants,
            threshold,
            *p,
        )?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
    Ok(result)
}

/// runs distributed reshare
pub(crate) fn run_reshare(
    participants: &[Participant],
    pub_key: &VerifyingKey,
    keys: Vec<(Participant, KeygenOutput)>,
    old_threshold: usize,
    new_threshold: usize,
    new_participants: Vec<Participant>,
) -> Result<Vec<(Participant, KeygenOutput)>, Box<dyn Error>> {
    assert!(!new_participants.is_empty());
    let mut setup: Vec<_> = vec![];

    for new_participant in &new_participants {
        let mut is_break = false;
        for (p, k) in &keys {
            if p == new_participant {
                setup.push((*p, (Some(k.private_share), k.public_key)));
                is_break = true;
                break;
            }
        }
        if !is_break {
            setup.push((*new_participant, (None, *pub_key)));
        }
    }

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput>>)> =
        Vec::with_capacity(participants.len());

    for (p, out) in setup.iter() {
        let protocol = reshare(
            participants,
            old_threshold,
            out.0,
            out.1,
            &new_participants,
            new_threshold,
            *p,
        )?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
    Ok(result)
}

/// Assert that each participant has the same view of the public key
pub(crate) fn assert_public_key_invariant(
    participants: &[(Participant, KeygenOutput)],
) -> Result<(), Box<dyn Error>> {
    let public_key_package = participants.first().unwrap().1.public_key;

    if participants
        .iter()
        .any(|(_, key_pair)| key_pair.public_key != public_key_package)
    {
        panic!("public key package is not the same for all participants");
    }

    Ok(())
}

pub fn run_presign(
    participants: Vec<(Participant, KeygenOutput)>,
    shares0: Vec<TripleShare<Secp256k1>>,
    shares1: Vec<TripleShare<Secp256k1>>,
    pub0: &TriplePub<Secp256k1>,
    pub1: &TriplePub<Secp256k1>,
    threshold: usize,
) -> Vec<(Participant, PresignOutput<Secp256k1>)> {
    assert!(participants.len() == shares0.len());
    assert!(participants.len() == shares1.len());

    #[allow(clippy::type_complexity)]
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = PresignOutput<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

    for (((p, keygen_out), share0), share1) in participants
        .into_iter()
        .zip(shares0.into_iter())
        .zip(shares1.into_iter())
    {
        let protocol = presign(
            &participant_list,
            p,
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

#[allow(clippy::type_complexity)]
pub fn run_sign(
    participants: Vec<(Participant, PresignOutput<Secp256k1>)>,
    public_key: AffinePoint,
    msg: &[u8],
) -> Vec<(Participant, FullSignature<Secp256k1>)> {
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = FullSignature<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

    for (p, presign_out) in participants.into_iter() {
        let protocol = sign(
            &participant_list,
            p,
            public_key,
            presign_out,
            scalar_hash(msg),
        );
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

#[test]
fn test_e2e() -> Result<(), Box<dyn Error>> {
    let participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
    ];
    let threshold = 3;

    let mut keygen_result = run_keygen(&participants.clone(), threshold)?;
    keygen_result.sort_by_key(|(p, _)| *p);

    let public_key = keygen_result[0].1.public_key;
    assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
    assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

    let (pub0, shares0) = triples::deal(&mut OsRng, &participants, threshold);
    let (pub1, shares1) = triples::deal(&mut OsRng, &participants, threshold);

    let mut presign_result = run_presign(keygen_result, shares0, shares1, &pub0, &pub1, threshold);
    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    run_sign(presign_result, public_key.to_element().to_affine(), msg);
    Ok(())
}

#[test]
fn test_e2e_random_identifiers() -> Result<(), Box<dyn Error>> {
    let participants_count = 3;
    let mut participants: Vec<_> = (0..participants_count)
        .map(|_| Participant::from(rand::random::<u32>()))
        .collect();
    participants.sort();
    let threshold = 3;

    let mut keygen_result = run_keygen(&participants.clone(), threshold)?;
    keygen_result.sort_by_key(|(p, _)| *p);

    let public_key = keygen_result[0].1.public_key;
    assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
    assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

    let (pub0, shares0) = triples::deal(&mut OsRng, &participants, threshold);
    let (pub1, shares1) = triples::deal(&mut OsRng, &participants, threshold);

    let mut presign_result = run_presign(keygen_result, shares0, shares1, &pub0, &pub1, threshold);
    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    run_sign(presign_result, public_key.to_element().to_affine(), msg);
    Ok(())
}
