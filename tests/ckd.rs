mod common;

use rand_core::OsRng;
use std::collections::HashMap;

use common::{choose_coordinator_at_random, generate_participants, run_keygen, run_reshare};
use threshold_signatures::{
    confidential_key_derivation::{
        ciphersuite::{verify_signature, Field, G1Projective, Group},
        protocol::ckd,
        AppId, CKDOutputOption,
    },
    participants::Participant,
};

use crate::common::{run_protocol, GenProtocol};
type C = threshold_signatures::confidential_key_derivation::BLS12381SHA256;
type Scalar = threshold_signatures::Scalar<C>;

#[test]
fn test_ckd() {
    let mut rng = OsRng;

    // Create the app necessary items
    let app_id = AppId::try_from(b"Near App").unwrap();
    let app_sk = Scalar::random(&mut rng);
    let app_pk = G1Projective::generator() * app_sk;

    // create participants
    let threshold = 2;
    let participants = generate_participants(3);

    let keys = run_keygen(&participants, threshold.into());

    assert!(keys.len() == participants.len());

    let public_key = keys[0].1.public_key;
    let keys: HashMap<_, _> = keys.into_iter().collect();
    let coordinator = choose_coordinator_at_random(&participants);

    let mut protocols: GenProtocol<CKDOutputOption> = Vec::with_capacity(participants.len());

    for p in &participants {
        let key_pair = keys.get(p).unwrap();

        let protocol = ckd(
            &participants,
            coordinator,
            *p,
            key_pair.clone(),
            app_id.clone(),
            app_pk,
            OsRng,
        )
        .unwrap();

        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols).unwrap();

    // test one single some for the coordinator
    let mut some_iter = result.into_iter().filter(|(_, ckd)| ckd.is_some());

    let ckd = some_iter
        .next()
        .map(|(_, c)| c.unwrap())
        .expect("Expected exactly one Some(CKDCoordinatorOutput)");
    assert!(
        some_iter.next().is_none(),
        "More than one Some(CKDCoordinatorOutput)"
    );

    // compute msk . H(app_id)
    let confidential_key = ckd.unmask(app_sk);
    assert!(verify_signature(&public_key, &app_id, &confidential_key).is_ok());

    let participant_keys = keys.into_iter().collect::<Vec<_>>();

    let mut new_participants = participants.clone();
    new_participants.push(Participant::from(20u32));
    let new_threshold = 3;

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
