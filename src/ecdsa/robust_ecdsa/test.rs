use std::error::Error;

use super::{presign::presign, sign::sign, PresignArguments, PresignOutput};

use crate::crypto::hash::test::scalar_hash_secp256k1;
use crate::ecdsa::robust_ecdsa::RerandomizedPresignOutput;
use crate::ecdsa::{
    Element, ParticipantList, RerandomizationArguments, Secp256K1Sha256, Signature,
    SignatureOption, Tweak,
};
use crate::participants::Participant;
use crate::protocol::Protocol;
use crate::test_utils::{
    assert_public_key_invariant, check_one_coordinator_output, generate_participants,
    generate_participants_with_random_ids, run_keygen, run_protocol, run_refresh, run_reshare,
    run_sign, GenOutput, GenProtocol, MockCryptoRng,
};

use rand::Rng;
use rand_core::{CryptoRngCore, SeedableRng};

/// Runs signing by calling the generic `run_sign` function from `crate::test`
/// This signing does not rerandomize the presignatures and tests only the core protocol
pub fn run_sign_without_rerandomization(
    participants_presign: &[(Participant, PresignOutput)],
    public_key: Element,
    msg: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<(Participant, Signature), Box<dyn Error>> {
    // hash the message into secp256k1 field
    let msg_hash = scalar_hash_secp256k1(msg);

    // choose a coordinator at random
    let index = rng.gen_range(0..participants_presign.len());
    let coordinator = participants_presign[index].0;

    // run sign instanciation with the necessary arguments
    let result = run_sign::<Secp256K1Sha256, _, _, _>(
        participants_presign.to_vec(),
        coordinator,
        public_key,
        msg_hash,
        |participants, coordinator, me, pk, presignature, msg_hash| {
            let pk = pk.to_affine();
            let rerand_presig =
                RerandomizedPresignOutput::new_without_rerandomization(&presignature);
            sign(participants, coordinator, me, pk, rerand_presig, msg_hash)
                .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
        },
    )?;
    // test one single some for the coordinator
    let signature = check_one_coordinator_output(result, coordinator)?;

    Ok((coordinator, signature))
}

/// Runs signing by calling the generic `run_sign` function from `crate::test`
/// This signing mimics what should happen in real world, i.e.,
/// rerandomizing the presignatures
pub fn run_sign_with_rerandomization(
    participants_presign: &[(Participant, PresignOutput)],
    public_key: Element,
    msg: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<(Tweak, Participant, Signature), Box<dyn Error>> {
    // hash the message into secp256k1 field
    let msg_hash = scalar_hash_secp256k1(msg);

    // generate a random tweak
    let tweak = Tweak::new(frost_core::random_nonzero::<Secp256K1Sha256, _>(rng));
    // generate a random public entropy
    let mut entropy: [u8; 32] = [0u8; 32];
    rng.fill_bytes(&mut entropy);

    let big_r = participants_presign[0].1.big_r;
    let participants = ParticipantList::new(
        &participants_presign
            .iter()
            .map(|(p, _)| *p)
            .collect::<Vec<Participant>>(),
    )
    .unwrap();
    let msg_hash_bytes: [u8; 32] = msg_hash.to_bytes().into();
    let public_key = frost_core::VerifyingKey::new(public_key);
    let derived_pk = tweak.derive_verifying_key(&public_key).to_element();
    let rerand_args = RerandomizationArguments::new(
        derived_pk.to_affine(),
        tweak,
        msg_hash_bytes,
        big_r,
        participants,
        entropy,
    );

    let rerand_participants_presign = participants_presign
        .iter()
        .map(|(p, presig)| {
            RerandomizedPresignOutput::rerandomize_presign(presig, &rerand_args)
                .map(|out| (*p, out))
        })
        .collect::<Result<_, _>>()?;

    // choose a coordinator at random
    let index = rng.gen_range(0..participants_presign.len());
    let coordinator = participants_presign[index].0;

    // run sign instantiation with the necessary arguments
    let result = run_sign::<Secp256K1Sha256, _, _, _>(
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
    let signature = check_one_coordinator_output(result, coordinator)?;
    Ok((tweak, coordinator, signature))
}

pub fn run_presign<R: CryptoRngCore + SeedableRng + Send + 'static>(
    participants: GenOutput<Secp256K1Sha256>,
    max_malicious: usize,
    rng: &mut R,
) -> Vec<(Participant, PresignOutput)> {
    let mut protocols: GenProtocol<PresignOutput> = Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

    for (p, keygen_out) in participants {
        let rng_p = R::seed_from_u64(rng.next_u64());
        let protocol = presign(
            &participant_list,
            p,
            PresignArguments {
                keygen_out,
                threshold: max_malicious,
            },
            rng_p,
        )
        .unwrap();
        protocols.push((p, Box::new(protocol)));
    }

    let mut result = run_protocol(protocols).unwrap();
    result.sort_by_key(|(p, _)| *p);
    result
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
    let public_key = key_packages[0].1.public_key;
    assert_public_key_invariant(&key_packages);
    let presign_result = run_presign(key_packages, max_malicious, &mut rng);

    let msg = b"hello world";
    run_sign_without_rerandomization(&presign_result, public_key.to_element(), msg, &mut rng)?;

    Ok(())
}

#[test]
/// Tests the resharing protocol when more participants are added to the pool
fn test_reshare_sign_more_participants() -> Result<(), Box<dyn Error>> {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(11);

    let max_malicious = 3;
    let threshold = max_malicious + 1;
    let result0 = run_keygen(&participants, threshold, &mut rng);
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
        &result0,
        threshold,
        new_threshold,
        &new_participant,
        &mut rng,
    );
    assert_public_key_invariant(&key_packages);

    let public_key = key_packages[0].1.public_key;
    // Presign
    let presign_result = run_presign(key_packages, max_malicious, &mut rng);

    let msg = b"hello world";
    run_sign_without_rerandomization(&presign_result, public_key.to_element(), msg, &mut rng)?;
    Ok(())
}

#[test]
/// Tests the resharing protocol when participants are kicked out of the pool
fn test_reshare_sign_less_participants() -> Result<(), Box<dyn Error>> {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(5);

    let max_malicious = 2;
    let threshold = max_malicious + 1;
    let result0 = run_keygen(&participants, threshold, &mut rng);
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
        &result0,
        threshold,
        new_threshold,
        &new_participant,
        &mut rng,
    );
    assert_public_key_invariant(&key_packages);
    let public_key = key_packages[0].1.public_key;
    // Presign
    let presign_result = run_presign(key_packages, max_malicious, &mut rng);

    let msg = b"hello world";
    run_sign_without_rerandomization(&presign_result, public_key.to_element(), msg, &mut rng)?;
    Ok(())
}

#[test]
fn test_e2e() -> Result<(), Box<dyn Error>> {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(8);
    let max_malicious = 3;

    let keygen_result = run_keygen(&participants, max_malicious + 1, &mut rng);

    let public_key = keygen_result[0].1.public_key;
    assert_public_key_invariant(&keygen_result);
    let presign_result = run_presign(keygen_result, max_malicious, &mut rng);

    let msg = b"hello world";
    run_sign_without_rerandomization(&presign_result, public_key.to_element(), msg, &mut rng)?;
    Ok(())
}

#[test]
fn test_e2e_random_identifiers() -> Result<(), Box<dyn Error>> {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants_count = 7;
    let participants = generate_participants_with_random_ids(participants_count, &mut rng);
    let max_malicious = 3;

    let keygen_result = run_keygen(&participants, max_malicious + 1, &mut rng);
    assert_public_key_invariant(&keygen_result);

    let public_key = keygen_result[0].1.public_key;
    assert_public_key_invariant(&keygen_result);
    let presign_result = run_presign(keygen_result, max_malicious, &mut rng);

    let msg = b"hello world";
    run_sign_without_rerandomization(&presign_result, public_key.to_element(), msg, &mut rng)?;
    Ok(())
}

#[test]
fn test_e2e_random_identifiers_with_rerandomization() -> Result<(), Box<dyn Error>> {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants_count = 7;
    let participants = generate_participants_with_random_ids(participants_count, &mut rng);
    let max_malicious = 3;

    let keygen_result = run_keygen(&participants, max_malicious + 1, &mut rng);
    assert_public_key_invariant(&keygen_result);

    let public_key = keygen_result[0].1.public_key;
    assert_public_key_invariant(&keygen_result);
    let presign_result = run_presign(keygen_result, max_malicious, &mut rng);

    let msg = b"hello world";
    run_sign_with_rerandomization(&presign_result, public_key.to_element(), msg, &mut rng)?;
    Ok(())
}

#[test]
fn test_robustness_without_rerandomization() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    // Without robustness, the signature verification would fail
    test_robustness(run_sign_with_rerandomization, &mut rng)
        .expect("robustness test should succeed");
}

#[test]
fn test_robustness_with_rerandomization() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    // Without robustness, the signature verification would fail
    test_robustness(run_sign_with_rerandomization, &mut rng)
        .expect("robustness test should succeed");
}

fn test_robustness<T, F, R: CryptoRngCore + SeedableRng + Send + 'static>(
    run_sign: F,
    rng: &mut R,
) -> Result<(), Box<dyn Error>>
where
    F: Fn(&[(Participant, PresignOutput)], Element, &[u8], &mut R) -> Result<T, Box<dyn Error>>,
{
    let participants_count = 11;
    let mut participants = generate_participants_with_random_ids(participants_count, rng);
    let max_malicious = 4;

    let mut keygen_result = run_keygen(&participants.clone(), max_malicious + 1, rng);
    assert_public_key_invariant(&keygen_result);

    // Now remove a participant
    // You can remove the same index because both participants and key_packages are sorted in the same way
    participants.remove(0);
    keygen_result.remove(0);

    let public_key = keygen_result[0].1.public_key;
    assert_public_key_invariant(&keygen_result);
    let mut presign_result = run_presign(keygen_result, max_malicious, rng);

    // Use less presignatures to sign
    presign_result.remove(0);

    let msg = b"hello world";
    run_sign(&presign_result, public_key.to_element(), msg, rng)?;
    Ok(())
}
