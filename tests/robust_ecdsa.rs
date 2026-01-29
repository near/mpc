#![allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod common;

use common::{choose_coordinator_at_random, generate_participants, run_keygen, run_reshare};
use std::collections::HashMap;

use rand_core::{OsRng, RngCore};

use threshold_signatures::{
    self,
    ecdsa::{
        robust_ecdsa::{
            presign::presign, sign::sign, PresignArguments, PresignOutput,
            RerandomizedPresignOutput,
        },
        RerandomizationArguments, Secp256K1Sha256, Signature, SignatureOption,
    },
    frost_secp256k1::VerifyingKey,
    participants::Participant,
    Element, ParticipantList,
};

// Note: This is required to use Scalar::from_repr
use elliptic_curve::ff::PrimeField;

use crate::common::{run_protocol, GenProtocol};

type C = Secp256K1Sha256;
type KeygenOutput = threshold_signatures::KeygenOutput<C>;
type Scalar = threshold_signatures::Scalar<C>;
type Tweak = threshold_signatures::Tweak<C>;

fn run_presign(
    participants: HashMap<Participant, KeygenOutput>,
    max_malicious: usize,
) -> Vec<(Participant, PresignOutput)> {
    let mut protocols: GenProtocol<PresignOutput> = Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.keys().copied().collect();

    for (p, keygen_out) in participants {
        let protocol = presign(
            &participant_list,
            p,
            PresignArguments {
                keygen_out,
                max_malicious: max_malicious.into(),
            },
            OsRng,
        )
        .unwrap();
        protocols.push((p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

fn run_sign(
    participants_presign: Vec<(Participant, RerandomizedPresignOutput)>,
    max_malicious: usize,
    coordinator: Participant,
    public_key: Element<C>,
    msg_hash: [u8; 32],
) -> Vec<(Participant, SignatureOption)> {
    let msg_hash = Scalar::from_repr(msg_hash.into())
        .into_option()
        .expect("Couldn't construct k256 point");

    let mut protocols: GenProtocol<SignatureOption> =
        Vec::with_capacity(participants_presign.len());

    let participants: Vec<Participant> = participants_presign.iter().map(|(p, _)| *p).collect();
    for (p, presignature) in participants_presign {
        let protocol = sign(
            &participants,
            coordinator,
            max_malicious,
            p,
            public_key.to_affine(),
            presignature,
            msg_hash,
        )
        .unwrap();

        protocols.push((p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

fn run_sign_with_rerandomization(
    participants_presign: &[(Participant, PresignOutput)],
    max_malicious: usize,
    public_key: VerifyingKey,
    msg_hash: [u8; 32],
    tweak: [u8; 32],
    entropy: [u8; 32],
) -> Signature {
    let tweak = Tweak::new(
        Scalar::from_repr(tweak.into())
            .into_option()
            .expect("Couldn't construct k256 point"),
    );

    let big_r = participants_presign[0].1.big_r;
    let participants = participants_presign
        .iter()
        .map(|(p, _)| *p)
        .collect::<Vec<Participant>>();

    let derived_pk = tweak.derive_verifying_key(&public_key).to_element();
    let rerand_args = RerandomizationArguments::new(
        derived_pk.to_affine(),
        tweak,
        msg_hash,
        big_r,
        ParticipantList::new(&participants).unwrap(),
        entropy,
    );

    let rerand_participants_presign = participants_presign
        .iter()
        .map(|(p, presig)| {
            RerandomizedPresignOutput::rerandomize_presign(presig, &rerand_args)
                .map(|out| (*p, out))
        })
        .collect::<Result<_, _>>()
        .unwrap();

    let coordinator = choose_coordinator_at_random(&participants);

    // run sign instantiation with the necessary arguments
    let all_sigs = run_sign(
        rerand_participants_presign,
        max_malicious,
        coordinator,
        derived_pk,
        msg_hash,
    );

    let signature = all_sigs
        .into_iter()
        .filter(|(p, sig)| *p == coordinator && sig.is_some())
        .collect::<Vec<_>>()
        .first()
        .unwrap()
        .1
        .clone();
    signature.unwrap()
}

#[test]
fn test_sign() {
    let participants = generate_participants(11);
    let max_malicious = 5;
    let threshold = max_malicious + 1;
    let keys = run_keygen(&participants, threshold.into());
    assert_eq!(keys.len(), participants.len());
    let public_key = keys.get(&participants[0]).unwrap().public_key;
    let presign_result = run_presign(keys.clone(), max_malicious);

    let msg_hash = *b"hello worldhello worldhello worl";
    // generate a random tweak
    let mut tweak = [0u8; 32];
    OsRng.fill_bytes(&mut tweak);
    // generate a random public entropy
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);

    let signature = run_sign_with_rerandomization(
        &presign_result,
        max_malicious,
        public_key,
        msg_hash,
        tweak,
        entropy,
    );

    // Note: this interface to check a signature is clearly sub-optimal
    let msg_hash_scalar = Scalar::from_repr(msg_hash.into())
        .into_option()
        .expect("Couldn't construct k256 point");
    let tweak = Tweak::new(
        Scalar::from_repr(tweak.into())
            .into_option()
            .expect("Couldn't construct k256 point"),
    );

    let derived_pk = tweak.derive_verifying_key(&public_key).to_element();
    assert!(signature.verify(&derived_pk.to_affine(), &msg_hash_scalar));

    let participant_keys = keys.into_iter().collect::<Vec<_>>();

    let mut new_participants = participants.clone();
    new_participants.push(Participant::from(20u32));
    let new_threshold = 6;

    let new_keys = run_reshare(
        &participants,
        &public_key,
        participant_keys.as_slice(),
        threshold.into(),
        new_threshold.into(),
        &new_participants,
    );
    let new_public_key = new_keys.get(&participants[0]).unwrap().public_key;

    assert_eq!(public_key, new_public_key);
}
