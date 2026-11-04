use super::{
    PresignArguments, presign_and_sign,
    triples::{TriplePub, TripleShare, generate_triple_many},
};
use crate::test_utils::{
    GenProtocol, MockCryptoRng, assert_public_key_invariant, check_one_coordinator_output,
    deal_triple, generate_participants, generate_participants_with_random_ids, run_keygen,
    run_protocol, run_refresh, run_reshare,
};
use crate::{Participant, protocol::Protocol};

use crate::crypto::hash::test::scalar_hash_secp256k1;
use crate::ecdsa::{KeygenOutput, Secp256K1Sha256, SignatureOption, Tweak, x_coordinate};

use k256::{PublicKey, ecdsa::VerifyingKey, ecdsa::signature::Verifier};
use rand::seq::SliceRandom as _;
use rand_core::{RngCore, SeedableRng};

/// Deals two triples to the parties in `key_packages` and signs `msg` with them, see
/// `run_sign_with_triples_and_verify`.
fn run_sign_and_verify(
    key_packages: &[(Participant, KeygenOutput)],
    threshold: usize,
    msg: &[u8],
    rng: &mut MockCryptoRng,
) {
    let participants: Vec<Participant> = key_packages.iter().map(|(p, _)| *p).collect();
    let triple0 = deal_triple(rng, &participants, threshold.into()).unwrap();
    let triple1 = deal_triple(rng, &participants, threshold.into()).unwrap();
    run_sign_with_triples_and_verify(key_packages, triple0, triple1, threshold, msg, rng);
}

/// Signs `msg` with every party in `key_packages` under a random tweak and coordinator,
/// consuming `triple0` and `triple1`, and checks the coordinator's signature against the
/// derived public key. The triple shares must be ordered as `key_packages`.
fn run_sign_with_triples_and_verify(
    key_packages: &[(Participant, KeygenOutput)],
    (pub0, shares0): (TriplePub, Vec<TripleShare>),
    (pub1, shares1): (TriplePub, Vec<TripleShare>),
    threshold: usize,
    msg: &[u8],
    rng: &mut MockCryptoRng,
) {
    let msg_hash = scalar_hash_secp256k1(msg);
    let tweak = Tweak::new(frost_core::random_nonzero::<Secp256K1Sha256, _>(rng));
    let participants: Vec<Participant> = key_packages.iter().map(|(p, _)| *p).collect();
    let coordinator = *participants
        .choose(rng)
        .expect("participant list is not empty");

    let mut protocols: GenProtocol<SignatureOption> = Vec::with_capacity(participants.len());
    for (((p, keygen_out), share0), share1) in key_packages.iter().zip(shares0).zip(shares1) {
        let protocol = presign_and_sign(
            &participants,
            coordinator,
            *p,
            PresignArguments {
                triple0: (share0, pub0.clone()),
                triple1: (share1, pub1.clone()),
                keygen_out: keygen_out.clone(),
                threshold: threshold.into(),
            },
            tweak,
            msg_hash,
        )
        .unwrap();
        protocols.push((*p, Box::new(protocol)));
    }
    let signature =
        check_one_coordinator_output(run_protocol(protocols).unwrap(), coordinator).unwrap();

    let derived_public_key = tweak
        .derive_verifying_key(&key_packages[0].1.public_key)
        .to_element()
        .to_affine();
    let signature =
        ecdsa::Signature::from_scalars(x_coordinate(&signature.big_r), signature.s).unwrap();
    VerifyingKey::from(&PublicKey::from_affine(derived_public_key).unwrap())
        .verify(msg, &signature)
        .unwrap();
}

#[test]
fn test_refresh() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(11);
    let max_malicious = 5;
    let threshold = max_malicious + 1;
    let keys = run_keygen(&participants, threshold, &mut rng);
    assert_public_key_invariant(&keys);
    // run refresh on these
    let key_packages = run_refresh(&participants, &keys, threshold, &mut rng);
    assert_public_key_invariant(&key_packages);

    run_sign_and_verify(&key_packages, threshold, b"hello world", &mut rng);
}

#[test]
fn test_reshare_sign_more_participants() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(5);
    let threshold = 3;
    let result0 = run_keygen(&participants, threshold, &mut rng);
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
        &mut rng,
    );
    assert_public_key_invariant(&key_packages);

    run_sign_and_verify(&key_packages, new_threshold, b"hello world", &mut rng);
}

#[test]
fn test_reshare_sign_less_participants() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(5);
    let threshold = 4;
    let result0 = run_keygen(&participants, threshold, &mut rng);
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
        &mut rng,
    );
    assert_public_key_invariant(&key_packages);

    run_sign_and_verify(&key_packages, new_threshold, b"hello world", &mut rng);
}

#[test]
fn test_e2e() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(3);
    let threshold = 3;

    let key_packages = run_keygen(&participants, threshold, &mut rng);
    assert_public_key_invariant(&key_packages);

    run_sign_and_verify(&key_packages, threshold, b"hello world", &mut rng);
}

#[test]
fn test_e2e_random_identifiers() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants_count = 3;
    let participants = generate_participants_with_random_ids(participants_count, &mut rng);
    let threshold = 3;

    let key_packages = run_keygen(&participants, threshold, &mut rng);
    assert_public_key_invariant(&key_packages);

    run_sign_and_verify(&key_packages, threshold, b"hello world", &mut rng);
}

fn split_even_odd<T: Clone>(v: Vec<T>) -> (Vec<T>, Vec<T>) {
    let mut even = Vec::with_capacity(v.len() / 2 + 1);
    let mut odd = Vec::with_capacity(v.len() / 2);
    for (i, x) in v.into_iter().enumerate() {
        if i.is_multiple_of(2) {
            even.push(x);
        } else {
            odd.push(x);
        }
    }
    (even, odd)
}

#[test]
fn test_robustness() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants_count = 7;
    let mut participants = generate_participants_with_random_ids(participants_count, &mut rng);
    let threshold = 4;

    let mut key_packages = run_keygen(&participants.clone(), threshold, &mut rng);
    assert_public_key_invariant(&key_packages);

    // Now remove a participant
    // You can remove the same index because both participants and key_packages are sorted in the same way
    participants.remove(0);
    key_packages.remove(0);

    let mut protocols: Vec<(_, Box<dyn Protocol<Output = _>>)> =
        Vec::with_capacity(participants.len());
    // Generate triples with 6 participants
    for &p in &participants {
        let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
        let protocol = generate_triple_many(&participants, p, threshold, 2, rng_p);
        let protocol = protocol.unwrap();
        protocols.push((p, Box::new(protocol)));
    }

    let two_triples = run_protocol(protocols).unwrap();
    let (shares, pubs): (Vec<_>, Vec<_>) = two_triples.into_iter().flat_map(|(_, vec)| vec).unzip();
    // split shares into shares0 and shares 1 and pubs into pubs0 and pubs1
    let (mut shares0, mut shares1) = split_even_odd(shares);
    // split shares into shares0 and shares 1 and pubs into pubs0 and pubs1
    let (pub0, pub1) = split_even_odd(pubs);

    // Test robustness for signing with fewer parties than generated the triples
    key_packages.remove(0);
    shares0.remove(0);
    shares1.remove(0);
    run_sign_with_triples_and_verify(
        &key_packages,
        (pub0[0].clone(), shares0),
        (pub1[0].clone(), shares1),
        threshold,
        b"hello world",
        &mut rng,
    );
}
