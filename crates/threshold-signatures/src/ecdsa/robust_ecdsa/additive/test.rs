use std::error::Error;

use super::AdditiveRerandomizedPresignOutput;
use super::presign::{AdditivePresignOutput, presign};
use super::sign::sign;

use crate::crypto::hash::test::scalar_hash_secp256k1;
use crate::ecdsa::robust_ecdsa::PresignArguments;
use crate::ecdsa::{
    Element, RerandomizationArguments, Secp256K1Sha256, Signature, SignatureOption, Tweak,
    x_coordinate,
};
use crate::participants::{Participant, ParticipantList};
use crate::protocol::Protocol;
use crate::test_utils::{
    GenOutput, GenProtocol, MockCryptoRng, check_one_coordinator_output, generate_participants,
    run_keygen, run_protocol, run_sign,
};
use crate::thresholds::MaxMalicious;

use k256::{PublicKey, ecdsa::VerifyingKey, ecdsa::signature::Verifier};
use rand::seq::SliceRandom as _;
use rand_core::{CryptoRngCore, SeedableRng};

/// Runs signing by calling the generic `run_sign` function from `crate::test`
/// This signing does not rerandomize the presignatures and tests only the core protocol
pub fn run_sign_without_rerandomization(
    participants_presign: &[(Participant, AdditivePresignOutput)],
    max_malicious: MaxMalicious,
    public_key: Element,
    msg: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<(Participant, Signature), Box<dyn Error>> {
    // hash the message into secp256k1 field
    let msg_hash = scalar_hash_secp256k1(msg);

    // choose a coordinator at random
    let coordinator = participants_presign
        .choose(rng)
        .expect("participant list is not empty")
        .0;

    // run sign instanciation with the necessary arguments
    let result = run_sign::<Secp256K1Sha256, _, _, _>(
        participants_presign.to_vec(),
        coordinator,
        public_key,
        msg_hash,
        |participants, coordinator, me, pk, presignature, msg_hash| {
            let pk = pk.to_affine();
            let rerand_presig =
                AdditiveRerandomizedPresignOutput::new_without_rerandomization(&presignature);
            sign(
                participants,
                coordinator,
                max_malicious,
                me,
                pk,
                rerand_presig,
                msg_hash,
            )
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
    participants_presign: &[(Participant, AdditivePresignOutput)],
    max_malicious: impl Into<MaxMalicious> + Copy + 'static,
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
            AdditiveRerandomizedPresignOutput::rerandomize_presign(presig, &rerand_args)
                .map(|out| (*p, out))
        })
        .collect::<Result<_, _>>()?;

    // choose a coordinator at random
    let coordinator = participants_presign
        .choose(rng)
        .expect("participant list is not empty")
        .0;

    // run sign instantiation with the necessary arguments
    let result = run_sign::<Secp256K1Sha256, _, _, _>(
        rerand_participants_presign,
        coordinator,
        derived_pk,
        msg_hash,
        |participants, coordinator, me, pk, presignature, msg_hash| {
            let pk = pk.to_affine();
            sign(
                participants,
                coordinator,
                max_malicious,
                me,
                pk,
                presignature,
                msg_hash,
            )
            .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
        },
    )?;
    // test one single some for the coordinator
    let signature = check_one_coordinator_output(result, coordinator)?;
    Ok((tweak, coordinator, signature))
}

pub fn run_presign<R: CryptoRngCore + SeedableRng + Send + 'static>(
    participants: GenOutput<Secp256K1Sha256>,
    max_malicious: impl Into<MaxMalicious> + Copy,
    rng: &mut R,
) -> Vec<(Participant, AdditivePresignOutput)> {
    let mut protocols: GenProtocol<AdditivePresignOutput> = Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

    for (p, keygen_out) in participants {
        let rng_p = R::seed_from_u64(rng.next_u64());
        let protocol = presign(
            &participant_list,
            p,
            PresignArguments {
                keygen_out,
                max_malicious: max_malicious.into(),
            },
            rng_p,
        )
        .unwrap();
        protocols.push((p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

#[test]
fn additive_scheme__should_produce_valid_rerandomized_signature_e2e() -> Result<(), Box<dyn Error>>
{
    // Given
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let max_malicious = 2;
    let participants = generate_participants(5);
    let keygen_result = run_keygen(&participants, max_malicious + 1, &mut rng);
    let public_key = keygen_result[0].1.public_key;

    // When
    let presign_result = run_presign(keygen_result, max_malicious, &mut rng);
    let msg = b"hello world";
    let (tweak, _, signature) = run_sign_with_rerandomization(
        &presign_result,
        max_malicious,
        public_key.to_element(),
        msg,
        &mut rng,
    )?;

    // Then
    let sig = ecdsa::Signature::from_scalars(x_coordinate(&signature.big_r), signature.s)?;
    let derived_pk = tweak.derive_verifying_key(&public_key).to_element();
    VerifyingKey::from(&PublicKey::from_affine(derived_pk.to_affine())?).verify(&msg[..], &sig)?;
    Ok(())
}
