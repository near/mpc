#![allow(clippy::unwrap_used)]
mod common;

use common::{choose_coordinator_at_random, generate_participants, run_keygen};

use rand_core::OsRng;

use threshold_signatures::{
    self,
    eddsa::{sign::sign, Ed25519Sha512, SignatureOption},
    participants::Participant,
};

use crate::common::{run_protocol, GenProtocol};

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
    let max_malicious = 3;
    let threshold = max_malicious + 1;
    let keys = run_keygen::<C>(&participants, threshold);
    assert_eq!(keys.len(), participants.len());
    let public_key = keys.get(&participants[0]).unwrap().public_key;

    let msg_hash = *b"hello worldhello worldhello worlregerghwhrth";
    let coordinator = choose_coordinator_at_random(&participants);
    let participants = keys.into_iter().collect::<Vec<_>>();
    let all_sigs = run_sign(threshold, participants.as_slice(), coordinator, &msg_hash);

    let signature = all_sigs
        .into_iter()
        .filter(|(p, sig)| *p == coordinator && sig.is_some())
        .collect::<Vec<_>>()
        .first()
        .unwrap()
        .1
        .unwrap();

    assert!(public_key.verify(&msg_hash, &signature).is_ok());
}
