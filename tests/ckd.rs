use std::{collections::HashMap, error::Error};

use rand_core::{OsRng, RngCore};
use threshold_signatures::{
    confidential_key_derivation::{
        ciphersuite::{verify_signature, BLS12381Scalar, Field, G1Projective, Group},
        protocol::ckd,
        AppId, CKDOutputOption, KeygenOutput,
    },
    keygen,
    protocol::{run_protocol, Participant, Protocol},
};

type C = threshold_signatures::confidential_key_derivation::ciphersuite::BLS12381SHA256;
type Scalar = BLS12381Scalar;

type ParticipantAndProtocol<T> = (Participant, Box<dyn Protocol<Output = T>>);

fn make_keygen(
    participants: &[Participant],
    threshold: usize,
) -> HashMap<Participant, KeygenOutput> {
    let mut protocols: Vec<ParticipantAndProtocol<KeygenOutput>> = Vec::new();
    for participant in participants {
        protocols.push((
            *participant,
            Box::new(keygen::<C>(participants, *participant, threshold, OsRng).unwrap()),
        ));
    }
    run_protocol(protocols).unwrap().into_iter().collect()
}

#[test]
fn test_ckd() -> Result<(), Box<dyn Error>> {
    let mut rng = OsRng;

    // Create the app necessary items
    let app_id = AppId::from(b"Near App");
    let app_sk = Scalar::random(&mut rng);
    let app_pk = G1Projective::generator() * app_sk;

    // create participants
    let threshold = 3;
    let participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
    ];

    let result = make_keygen(&participants, threshold);

    assert!(result.len() == participants.len());

    let public_key = result.get(&participants[0]).unwrap().public_key;

    // choose a coordinator at random
    let index = OsRng.next_u32() % participants.len() as u32;
    let coordinator = participants[index as usize];

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = CKDOutputOption>>)> =
        Vec::with_capacity(participants.len());

    for p in &participants {
        let private_share = result.get(p).unwrap().private_share;

        let protocol = ckd(
            &participants,
            coordinator,
            *p,
            private_share,
            app_id.clone(),
            app_pk,
            OsRng,
        )?;

        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;

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

    Ok(())
}
