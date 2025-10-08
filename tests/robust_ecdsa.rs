mod common;

use common::{choose_coordinator_at_random, generate_participants, run_keygen};
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
    protocol::{run_protocol, Participant},
    Element, ParticipantList,
};

// TODO: This is required to use Scalar::from_repr
use elliptic_curve::ff::PrimeField;

use crate::common::GenProtocol;

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
                threshold: max_malicious,
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

    let pk = public_key.to_element().to_affine();
    let big_r = participants_presign[0].1.big_r;
    let participants = participants_presign
        .iter()
        .map(|(p, _)| *p)
        .collect::<Vec<Participant>>();
    let rerand_args = RerandomizationArguments::new(
        pk,
        msg_hash,
        big_r,
        ParticipantList::new(&participants).unwrap(),
        entropy,
    );
    let derived_pk = tweak.derive_verifying_key(&public_key).to_element();

    let rerand_participants_presign = participants_presign
        .iter()
        .map(|(p, presig)| {
            RerandomizedPresignOutput::rerandomize_presign(presig, &tweak, &rerand_args)
                .map(|out| (*p, out))
        })
        .collect::<Result<_, _>>()
        .unwrap();

    let coordinator = choose_coordinator_at_random(&participants);

    // run sign instantiation with the necessary arguments
    let all_sigs = run_sign(
        rerand_participants_presign,
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
    let keys = run_keygen(&participants, threshold);
    assert_eq!(keys.len(), participants.len());
    let public_key = keys.get(&participants[0]).unwrap().public_key;
    let presign_result = run_presign(keys, max_malicious);

    let msg_hash = *b"hello worldhello worldhello worl";
    // generate a random tweak
    let mut tweak = [0u8; 32];
    OsRng.fill_bytes(&mut tweak);
    // generate a random public entropy
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);

    let signature =
        run_sign_with_rerandomization(&presign_result, public_key, msg_hash, tweak, entropy);

    // TODO: this interface to check a signature is clearly sub-optimal
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
}
