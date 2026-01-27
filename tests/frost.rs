#![allow(clippy::unwrap_used)]
mod common;

use common::{
    choose_coordinator_at_random, generate_participants, run_keygen, run_protocol, run_reshare,
    GenProtocol,
};

use rand_core::OsRng;

use threshold_signatures::{
    self,
    eddsa::frost::{sign::sign, Ed25519Sha512, SignatureOption},
    participants::Participant,
};

type C = Ed25519Sha512;
type KeygenOutput = threshold_signatures::KeygenOutput<C>;

fn run_sign(
    threshold: usize,
    participants: &[(Participant, KeygenOutput)],
    coordinator: Participant,
    msg_hash: &[u8],
) -> Vec<(Participant, SignatureOption)> {
    let mut protocols: GenProtocol<SignatureOption> = Vec::with_capacity(participants.len());

    let participants_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();
    for (p, keygen_output) in participants {
        let protocol = sign(
            &participants_list,
            threshold,
            *p,
            coordinator,
            keygen_output.clone(),
            msg_hash.to_vec(),
            OsRng,
        )
        .unwrap();

        protocols.push((*p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

#[test]
fn test_sign() {
    let participants = generate_participants(5);
    let threshold = 4;
    let keys = run_keygen::<C>(&participants, threshold);
    assert_eq!(keys.len(), participants.len());
    let public_key = keys.get(&participants[0]).unwrap().public_key;

    let msg_hash = *b"hello worldhello worldhello worlregerghwhrth";
    let coordinator = choose_coordinator_at_random(&participants);
    let participant_keys = keys.into_iter().collect::<Vec<_>>();
    let all_sigs = run_sign(
        threshold,
        participant_keys.as_slice(),
        coordinator,
        &msg_hash,
    );

    let signature = all_sigs
        .into_iter()
        .filter(|(p, sig)| *p == coordinator && sig.is_some())
        .collect::<Vec<_>>()
        .first()
        .unwrap()
        .1
        .unwrap();

    assert!(public_key.verify(&msg_hash, &signature).is_ok());

    let mut new_participants = participants.clone();
    new_participants.push(Participant::from(20u32));
    let new_threshold = 5;

    let new_keys = run_reshare(
        &participants,
        &public_key,
        participant_keys.as_slice(),
        threshold,
        new_threshold,
        &new_participants,
    );
    let new_public_key = new_keys.get(&participants[0]).unwrap().public_key;

    assert_eq!(public_key, new_public_key);
}
