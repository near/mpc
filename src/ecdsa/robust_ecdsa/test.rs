use std::error::Error;

use rand_core::OsRng;

use super::{presign::presign, sign::sign, PresignArguments, PresignOutput};

use crate::crypto::hash::test::scalar_hash_secp256k1;
use crate::ecdsa::{Element, KeygenOutput, Secp256K1Sha256, Signature};
use crate::protocol::{run_protocol, Participant, Protocol};
use crate::test::{
    assert_public_key_invariant, generate_participants, generate_participants_with_random_ids,
    run_keygen, run_refresh, run_reshare,
};

/// Runs signing by calling the generic run_sign function from crate::test
pub fn run_sign(
    participants_presign: Vec<(Participant, PresignOutput)>,
    public_key: Element,
    msg: &[u8],
) -> Result<Vec<(Participant, Signature)>, Box<dyn Error>> {
    // hash the message into secp256k1 field
    let msg_hash = scalar_hash_secp256k1(msg);
    // run sign instanciation with the necessary arguments
    crate::test::run_sign::<Secp256K1Sha256, _, _, _>(
        participants_presign,
        public_key,
        msg_hash,
        |participants, me, pk, presignature, msg_hash| {
            let pk = pk.to_affine();
            sign(participants, me, pk, presignature, msg_hash)
                .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = Signature>>)
        },
    )
}

pub fn run_presign(
    participants: Vec<(Participant, KeygenOutput)>,
    max_malicious: usize,
) -> Result<Vec<(Participant, PresignOutput)>, Box<dyn Error>> {
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)> =
        Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

    for (p, keygen_out) in participants.into_iter() {
        let protocol = presign(
            &participant_list,
            p,
            PresignArguments {
                keygen_out,
                threshold: max_malicious,
            },
            OsRng,
        )?;
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
    let key_packages = run_refresh(&participants, keys, threshold)?;
    let public_key = key_packages[0].1.public_key;
    assert_public_key_invariant(&key_packages);
    let presign_result = run_presign(key_packages, max_malicious)?;

    let msg = b"hello world";
    run_sign(presign_result, public_key.to_element(), msg)?;

    Ok(())
}

#[test]
/// Tests the resharing protocol when more participants are added to the pool
fn test_reshare_sign_more_participants() -> Result<(), Box<dyn Error>> {
    let participants = generate_participants(11);

    let max_malicious = 3;
    let threshold = max_malicious + 1;
    let result0 = run_keygen(&participants, threshold)?;
    assert_public_key_invariant(&result0);

    let pub_key = result0[2].1.public_key;

    // Run heavy reshare
    let max_malicious = 4;
    let new_threshold = max_malicious + 1;

    let mut new_participant = participants.clone();
    new_participant.push(Participant::from(31u32));
    new_participant.push(Participant::from(32u32));
    new_participant.push(Participant::from(33u32));
    let key_packages = run_reshare(
        &participants,
        &pub_key,
        result0,
        threshold,
        new_threshold,
        new_participant.clone(),
    )?;
    assert_public_key_invariant(&key_packages);

    let public_key = key_packages[0].1.public_key;
    // Presign
    let presign_result = run_presign(key_packages, max_malicious)?;

    let msg = b"hello world";

    run_sign(presign_result, public_key.to_element(), msg)?;
    Ok(())
}

#[test]
/// Tests the resharing protocol when participants are kicked out of the pool
fn test_reshare_sign_less_participants() -> Result<(), Box<dyn Error>> {
    let participants = generate_participants(5);

    let max_malicious = 2;
    let threshold = max_malicious + 1;
    let result0 = run_keygen(&participants, threshold)?;
    assert_public_key_invariant(&result0);

    let pub_key = result0[2].1.public_key;

    // Run heavy reshare
    let max_malicious = 1;
    let new_threshold = max_malicious + 1;
    let mut new_participant = participants.clone();
    new_participant.pop();
    let key_packages = run_reshare(
        &participants,
        &pub_key,
        result0,
        threshold,
        new_threshold,
        new_participant.clone(),
    )?;
    assert_public_key_invariant(&key_packages);
    let public_key = key_packages[0].1.public_key;
    // Presign
    let presign_result = run_presign(key_packages, max_malicious)?;

    let msg = b"hello world";

    run_sign(presign_result, public_key.to_element(), msg)?;
    Ok(())
}

#[test]
fn test_e2e() -> Result<(), Box<dyn Error>> {
    let participants = generate_participants(8);
    let max_malicious = 3;

    let keygen_result = run_keygen(&participants.clone(), max_malicious + 1)?;

    let public_key = keygen_result[0].1.public_key;
    assert_public_key_invariant(&keygen_result);
    let presign_result = run_presign(keygen_result, max_malicious)?;

    let msg = b"hello world";

    run_sign(presign_result, public_key.to_element(), msg)?;
    Ok(())
}

#[test]
fn test_e2e_random_identifiers() -> Result<(), Box<dyn Error>> {
    let participants_count = 7;
    let participants = generate_participants_with_random_ids(participants_count, &mut OsRng);
    let max_malicious = 3;

    let keygen_result = run_keygen(&participants.clone(), max_malicious + 1)?;
    assert_public_key_invariant(&keygen_result);

    let public_key = keygen_result[0].1.public_key;
    assert_public_key_invariant(&keygen_result);
    let presign_result = run_presign(keygen_result, max_malicious)?;

    let msg = b"hello world";
    run_sign(presign_result, public_key.to_element(), msg)?;
    Ok(())
}
