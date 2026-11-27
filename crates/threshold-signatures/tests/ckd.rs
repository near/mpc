#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use blstrs::G2Projective;
use rand_core::OsRng;

use common::{choose_coordinator_at_random, generate_participants, run_keygen, run_reshare};
use threshold_signatures::{
    confidential_key_derivation::{
        AppId, CKDOutputOption, KeygenOutput, PublicVerificationKey,
        ciphersuite::{Field as _, G1Projective, Group as _, verify_signature},
        ckd_pv,
        protocol::ckd,
    },
    participants::Participant,
    protocol::Protocol,
};

use crate::common::{GenProtocol, run_protocol};
type C = threshold_signatures::confidential_key_derivation::BLS12381SHA256;
type Scalar = threshold_signatures::Scalar<C>;

fn run_ckd_and_reshare<P>(
    app_sk: Scalar,
    build_protocol: impl Fn(&[Participant], Participant, Participant, KeygenOutput, AppId) -> P,
) where
    P: Protocol<Output = CKDOutputOption> + 'static,
{
    let app_id = AppId::try_from(b"Near App").unwrap();

    let threshold = 2;
    let participants = generate_participants(3);

    let keys = run_keygen(&participants, threshold.into());

    assert_eq!(keys.len(), participants.len());

    let public_key = keys.get(&participants[0]).unwrap().public_key;
    let coordinator = choose_coordinator_at_random(&participants);

    let mut protocols: GenProtocol<CKDOutputOption> = Vec::with_capacity(participants.len());

    for p in &participants {
        let key_pair = keys.get(p).unwrap();

        let protocol = build_protocol(
            &participants,
            coordinator,
            *p,
            key_pair.clone(),
            app_id.clone(),
        );

        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols).unwrap();

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

#[test]
fn test_ckd() {
    let app_sk = Scalar::random(&mut OsRng);
    let app_pk = G1Projective::generator() * app_sk;

    run_ckd_and_reshare(app_sk, |participants, coordinator, me, key_pair, app_id| {
        ckd(
            participants,
            coordinator,
            me,
            key_pair,
            app_id,
            app_pk,
            OsRng,
        )
        .unwrap()
    });
}

#[test]
fn test_ckd_pv() {
    let app_sk = Scalar::random(&mut OsRng);
    let app_pk = PublicVerificationKey::new(
        G1Projective::generator() * app_sk,
        G2Projective::generator() * app_sk,
    );

    run_ckd_and_reshare(app_sk, |participants, coordinator, me, key_pair, app_id| {
        ckd_pv(
            participants,
            coordinator,
            me,
            key_pair,
            app_id,
            app_pk.clone(),
            OsRng,
        )
        .unwrap()
    });
}
