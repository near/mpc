use crate::{
    crypto::hash::HashOutput,
    frost::eddsa::{
        sign::{sign_v1, sign_v2},
        KeygenOutput, PresignOutput, SignatureOption,
    },
    test_utils::{generate_participants, run_protocol, GenProtocol, MockCryptoRng},
    Participant, ReconstructionLowerBound,
};

use std::error::Error;

use frost_core::Scalar;
use frost_ed25519::{keys::SigningShare, Ed25519Sha512, SigningKey, VerifyingKey};
use rand::SeedableRng;
use rand_core::CryptoRngCore;

type C = Ed25519Sha512;

pub fn run_sign_v1(
    participants: &[(Participant, KeygenOutput)],
    actual_signers: usize,
    coordinator: Participant,
    threshold: impl Into<ReconstructionLowerBound> + Copy + 'static,
    msg_hash: HashOutput,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<(Participant, SignatureOption)>, Box<dyn Error>> {
    let mut protocols: GenProtocol<SignatureOption> = Vec::with_capacity(participants.len());

    let participants_list = participants
        .iter()
        .take(actual_signers)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();

    let mut is_valid_coordinator = false;
    for (participant, key_pair) in participants.iter().take(actual_signers) {
        let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
        if coordinator == *participant {
            is_valid_coordinator = true;
        }
        // run the signing scheme
        let protocol = sign_v1(
            &participants_list,
            threshold,
            *participant,
            coordinator,
            key_pair.clone(),
            msg_hash.as_ref().to_vec(),
            rng_p,
        )?;
        protocols.push((*participant, Box::new(protocol)));
    }
    if !is_valid_coordinator {
        return Err("Invalid Coordinator".into());
    }
    Ok(run_protocol(protocols)?)
}

pub fn run_presign(
    participants: &[(Participant, KeygenOutput)],
    threshold: impl Into<ReconstructionLowerBound> + Copy,
    actual_signers: usize,
    rng: impl CryptoRngCore + Send + Clone + 'static,
) -> Result<Vec<(Participant, PresignOutput)>, Box<dyn Error>> {
    crate::test_utils::frost_run_presignature(participants, threshold, actual_signers, rng)
}

pub fn run_sign_v2(
    participants: &[(Participant, KeygenOutput)],
    actual_signers: usize,
    coordinator: Participant,
    threshold: impl Into<ReconstructionLowerBound> + Copy + 'static,
    msg_hash: HashOutput,
    rng: impl CryptoRngCore + Send + Clone + 'static,
) -> Result<Vec<(Participant, SignatureOption)>, Box<dyn Error>> {
    let presig = run_presign(participants, threshold, actual_signers, rng)?;
    let mut protocols: GenProtocol<SignatureOption> = Vec::with_capacity(participants.len());

    let participants_list = participants
        .iter()
        .take(actual_signers)
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();

    let mut is_valid_coordinator = false;
    for ((participant, key_pair), (participant_redundancy, presignature)) in
        participants.iter().zip(presig.iter())
    {
        if coordinator == *participant {
            is_valid_coordinator = true;
        }

        if participant != participant_redundancy {
            return Err("Incompatible Participants".into());
        }

        // run the signing scheme
        let protocol = sign_v2(
            &participants_list,
            threshold,
            *participant,
            coordinator,
            key_pair.clone(),
            presignature.clone(),
            msg_hash.as_ref().to_vec(),
        )?;
        protocols.push((*participant, Box::new(protocol)));
    }
    if !is_valid_coordinator {
        return Err("Invalid Coordinator".into());
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
        private_share: SigningShare::new(Scalar::<C>::from(7_u32)),
        public_key: VerifyingKey::from(signing_key),
    };

    // When
    let serialized_keygen_output =
        serde_json::to_string(&keygen_output).expect("should be able to serialize output");

    // Then
    assert_eq!(
        serialized_keygen_output,
        "{\"private_share\":\"0700000000000000000000000000000000000000000000000000000000000000\",\"public_key\":\"a80ed62da91a8c6f266d82c4b2017cc0be13e6acba26af04494635b15ac86b57\"}"
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
