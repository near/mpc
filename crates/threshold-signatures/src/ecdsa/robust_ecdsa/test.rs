use std::error::Error;

use super::{PresignArguments, presign_and_sign};

use crate::crypto::hash::test::scalar_hash_secp256k1;
use crate::ecdsa::{KeygenOutput, Secp256K1Sha256, SignatureOption, Tweak, x_coordinate};
use crate::participants::Participant;
use crate::test_utils::{
    GenProtocol, MockCryptoRng, assert_public_key_invariant, check_one_coordinator_output,
    generate_participants, generate_participants_with_random_ids, run_keygen, run_protocol,
    run_refresh, run_reshare,
};

use k256::{PublicKey, ecdsa::VerifyingKey, ecdsa::signature::Verifier};
use rand::seq::SliceRandom as _;
use rand_core::{RngCore, SeedableRng};

/// Signs `msg` with every party in `key_packages` under a random tweak and coordinator, and
/// checks the coordinator's signature against the derived public key.
pub fn run_sign_and_verify(
    key_packages: &[(Participant, KeygenOutput)],
    max_malicious: usize,
    msg: &[u8],
    rng: &mut MockCryptoRng,
) -> Result<(), Box<dyn Error>> {
    let msg_hash = scalar_hash_secp256k1(msg);
    let tweak = Tweak::new(frost_core::random_nonzero::<Secp256K1Sha256, _>(rng));
    let participants: Vec<Participant> = key_packages.iter().map(|(p, _)| *p).collect();
    let coordinator = *participants
        .choose(rng)
        .expect("participant list is not empty");

    let mut protocols: GenProtocol<SignatureOption> = Vec::with_capacity(participants.len());
    for (p, keygen_out) in key_packages {
        let protocol = presign_and_sign(
            &participants,
            coordinator,
            *p,
            PresignArguments {
                keygen_out: keygen_out.clone(),
                max_malicious: max_malicious.into(),
            },
            tweak,
            msg_hash,
            MockCryptoRng::seed_from_u64(rng.next_u64()),
        )?;
        protocols.push((*p, Box::new(protocol)));
    }
    let signature = check_one_coordinator_output(run_protocol(protocols)?, coordinator)?;

    let derived_public_key = tweak
        .derive_verifying_key(&key_packages[0].1.public_key)
        .to_element()
        .to_affine();
    let signature = ecdsa::Signature::from_scalars(x_coordinate(&signature.big_r), signature.s)?;
    VerifyingKey::from(&PublicKey::from_affine(derived_public_key)?).verify(msg, &signature)?;
    Ok(())
}

#[test]
fn test_refresh() -> Result<(), Box<dyn Error>> {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(11);
    let max_malicious = 5;
    let threshold = max_malicious + 1;
    let keys = run_keygen(&participants, threshold, &mut rng);
    assert_public_key_invariant(&keys);
    // run refresh on these
    let key_packages = run_refresh(&participants, &keys, threshold, &mut rng);
    assert_public_key_invariant(&key_packages);

    run_sign_and_verify(&key_packages, max_malicious, b"hello world", &mut rng)
}

#[test]
/// Tests the resharing protocol when more participants are added to the pool
fn test_reshare_sign_more_participants() -> Result<(), Box<dyn Error>> {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(12);

    let max_malicious = 3;
    let threshold = max_malicious + 1;
    let result0 = run_keygen(&participants, threshold, &mut rng);
    assert_public_key_invariant(&result0);

    let pub_key = result0[2].1.public_key;

    // Run heavy reshare
    let max_malicious = 7;
    let new_threshold = max_malicious + 1;

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
        &mut rng,
    );
    assert_public_key_invariant(&key_packages);

    run_sign_and_verify(&key_packages, max_malicious, b"hello world", &mut rng)
}

#[test]
/// Tests the resharing protocol when participants are kicked out of the pool
fn test_reshare_sign_less_participants() -> Result<(), Box<dyn Error>> {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(6);

    let max_malicious = 3;
    let threshold = max_malicious + 1;
    let result0 = run_keygen(&participants, threshold, &mut rng);
    assert_public_key_invariant(&result0);

    let pub_key = result0[2].1.public_key;

    // Run heavy reshare
    let max_malicious = 2;
    let new_threshold = max_malicious + 1;
    let mut new_participant = participants.clone();
    new_participant.pop();
    let key_packages = run_reshare(
        &participants,
        &pub_key,
        &result0,
        threshold,
        new_threshold,
        &new_participant,
        &mut rng,
    );
    assert_public_key_invariant(&key_packages);

    run_sign_and_verify(&key_packages, max_malicious, b"hello world", &mut rng)
}

#[test]
fn test_e2e() -> Result<(), Box<dyn Error>> {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(7);
    let max_malicious = 3;

    let keygen_result = run_keygen(&participants, max_malicious + 1, &mut rng);
    assert_public_key_invariant(&keygen_result);

    run_sign_and_verify(&keygen_result, max_malicious, b"hello world", &mut rng)
}

#[test]
fn test_e2e_random_identifiers() -> Result<(), Box<dyn Error>> {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants_count = 7;
    let participants = generate_participants_with_random_ids(participants_count, &mut rng);
    let max_malicious = 3;
    let threshold = max_malicious + 1;

    let keygen_result = run_keygen(&participants, threshold, &mut rng);
    assert_public_key_invariant(&keygen_result);

    run_sign_and_verify(&keygen_result, max_malicious, b"hello world", &mut rng)
}
