#![allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod common;

use common::{choose_coordinator_at_random, generate_participants, run_keygen, run_reshare};
use std::collections::HashMap;

use rand_core::{OsRng, RngCore};

use threshold_signatures::{
    self, MaxMalicious,
    ecdsa::{
        Secp256K1Sha256, Signature, SignatureOption,
        robust_ecdsa::{PresignArguments, presign_and_sign},
    },
    participants::Participant,
};

// Note: This is required to use Scalar::from_repr
use elliptic_curve::ff::PrimeField;

use crate::common::{GenProtocol, run_protocol};

type C = Secp256K1Sha256;
type KeygenOutput = threshold_signatures::KeygenOutput<C>;
type Scalar = threshold_signatures::Scalar<C>;
type Tweak = threshold_signatures::Tweak<C>;

fn run_sign(
    participants: HashMap<Participant, KeygenOutput>,
    max_malicious: MaxMalicious,
    coordinator: Participant,
    tweak: Tweak,
    msg_hash: Scalar,
) -> Signature {
    let mut protocols: GenProtocol<SignatureOption> = Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.keys().copied().collect();
    for (p, keygen_out) in participants {
        let protocol = presign_and_sign(
            &participant_list,
            coordinator,
            p,
            PresignArguments {
                keygen_out,
                max_malicious,
            },
            tweak,
            msg_hash,
            OsRng,
        )
        .unwrap();
        protocols.push((p, Box::new(protocol)));
    }

    run_protocol(protocols)
        .unwrap()
        .into_iter()
        .find_map(|(p, signature)| (p == coordinator).then_some(signature).flatten())
        .unwrap()
}

#[test]
fn test_run_sign() {
    let participants = generate_participants(11);
    let max_malicious = 5;
    let threshold = max_malicious + 1;
    let keys = run_keygen(&participants, threshold.into());
    let public_key = keys.get(&participants[0]).unwrap().public_key;
    assert_eq!(keys.len(), participants.len());

    let msg_hash = *b"hello worldhello worldhello worl";
    let msg_hash = Scalar::from_repr(msg_hash.into())
        .into_option()
        .expect("Couldn't construct k256 point");
    // generate a random tweak
    let mut tweak = [0u8; 32];
    OsRng.fill_bytes(&mut tweak);
    let tweak = Tweak::new(
        Scalar::from_repr(tweak.into())
            .into_option()
            .expect("Couldn't construct k256 point"),
    );
    let coordinator = choose_coordinator_at_random(&participants);

    let signature = run_sign(
        keys.clone(),
        max_malicious.into(),
        coordinator,
        tweak,
        msg_hash,
    );

    let derived_pk = tweak.derive_verifying_key(&public_key).to_element();
    assert!(signature.verify(&derived_pk.to_affine(), &msg_hash));

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
