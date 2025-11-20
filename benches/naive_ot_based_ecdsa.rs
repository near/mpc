use criterion::{criterion_group, Criterion};
use frost_secp256k1::{Secp256K1Sha256, VerifyingKey};
use rand::Rng;
use rand_core::OsRng;

use threshold_signatures::{
    ecdsa::{
        ot_based_ecdsa::{
            presign::presign,
            sign::sign,
            triples::{generate_triple_many, TriplePub, TripleShare},
            PresignArguments, PresignOutput, RerandomizedPresignOutput,
        },
        SignatureOption,
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        ecdsa_generate_rerandpresig_args, generate_participants_with_random_ids, run_keygen,
        run_protocol,
    },
};

use std::{env, sync::LazyLock};

// fix malicious number of participants
pub static MAX_MALICIOUS: LazyLock<usize> = std::sync::LazyLock::new(|| {
    env::var("MAX_MALICIOUS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6)
});

fn threshold() -> usize {
    *crate::MAX_MALICIOUS + 1
}

fn participants_num() -> usize {
    *crate::MAX_MALICIOUS + 1
}

/// Benches the triples protocol
fn bench_triples(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut group = c.benchmark_group("triples");
    group.measurement_time(std::time::Duration::from_secs(200));

    group.bench_function(
        format!("ot_ecdsa_triples_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_triples(participants_num()),
                run_protocol,
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut group = c.benchmark_group("presign");
    group.measurement_time(std::time::Duration::from_secs(300));

    let protocols = prepare_triples(participants_num());
    let two_triples = run_protocol(protocols).expect("Running triple preparations should succeed");

    group.bench_function(
        format!("ot_ecdsa_presign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_presign(&two_triples),
                |(protocols, _)| run_protocol(protocols),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

/// Benches the signing protocol
fn bench_sign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;

    let mut group = c.benchmark_group("sign");
    group.measurement_time(std::time::Duration::from_secs(300));

    let protocols = prepare_triples(participants_num());
    let two_triples = run_protocol(protocols).expect("Running triples preparation should succeed");

    let (protocols, pk) = prepare_presign(&two_triples);
    let mut result = run_protocol(protocols).expect("Running presign preparation should succeed");
    result.sort_by_key(|(p, _)| *p);

    group.bench_function(
        format!("ot_ecdsa_sign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_sign(&result, pk),
                run_protocol,
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

type PreparedTriples = Vec<(
    Participant,
    Box<dyn Protocol<Output = Vec<(TripleShare, TriplePub)>>>,
)>;
fn prepare_triples(participant_num: usize) -> PreparedTriples {
    let mut protocols: Vec<(_, Box<dyn Protocol<Output = _>>)> =
        Vec::with_capacity(participant_num);
    let participants = generate_participants_with_random_ids(participant_num, &mut OsRng);

    for p in participants.clone() {
        let protocol = generate_triple_many::<2>(&participants, p, threshold(), OsRng)
            .expect("Triple generation should succeed");
        protocols.push((p, Box::new(protocol)));
    }
    protocols
}

type PreparedPresig = (
    Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)>,
    VerifyingKey,
);
fn prepare_presign(two_triples: &[(Participant, Vec<(TripleShare, TriplePub)>)]) -> PreparedPresig {
    let mut two_triples = two_triples.to_owned();
    two_triples.sort_by_key(|(p, _)| *p);

    // collect all participants
    let participants: Vec<Participant> = two_triples
        .iter()
        .map(|(participant, _)| *participant)
        .collect();

    let (shares, pubs): (Vec<_>, Vec<_>) = two_triples.into_iter().flat_map(|(_, vec)| vec).unzip();
    // split shares into shares0 and shares 1 and pubs into pubs0 and pubs1
    let (shares0, shares1) = split_even_odd(shares);
    // split shares into shares0 and shares 1 and pubs into pubs0 and pubs1
    let (pub0, pub1) = split_even_odd(pubs);

    let key_packages = run_keygen::<Secp256K1Sha256>(&participants, threshold());
    let pk = key_packages[0].1.public_key;

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)> =
        Vec::with_capacity(participants.len());

    for (((p, keygen_out), share0), share1) in key_packages.into_iter().zip(shares0).zip(shares1) {
        let protocol = presign(
            &participants,
            p,
            PresignArguments {
                triple0: (share0, pub0[0].clone()),
                triple1: (share1, pub1[0].clone()),
                keygen_out,
                threshold: threshold(),
            },
        )
        .expect("Presigning should succeed");
        protocols.push((p, Box::new(protocol)));
    }
    (protocols, pk)
}

fn prepare_sign(
    result: &[(Participant, PresignOutput)],
    pk: VerifyingKey,
) -> Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)> {
    // collect all participants
    let participants: Vec<Participant> =
        result.iter().map(|(participant, _)| *participant).collect();

    // choose a coordinator at random
    let index = OsRng.gen_range(0..result.len());
    let coordinator = result[index].0;

    let (args, msg_hash) =
        ecdsa_generate_rerandpresig_args(&mut OsRng, &participants, pk, result[0].1.big_r);
    let derived_pk = args
        .tweak
        .derive_verifying_key(&pk)
        .to_element()
        .to_affine();

    let result = result
        .iter()
        .map(|(p, presig)| {
            (
                *p,
                RerandomizedPresignOutput::rerandomize_presign(presig, &args)
                    .expect("Rerandomizing presignature should succeed"),
            )
        })
        .collect::<Vec<_>>();

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)> =
        Vec::with_capacity(result.len());

    for (p, presignature) in result {
        let protocol = sign(
            args.participants.participants(),
            coordinator,
            p,
            derived_pk,
            presignature,
            msg_hash,
        )
        .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
        .expect("Signing should succeed");
        protocols.push((p, protocol));
    }
    protocols
}

fn split_even_odd<T: Clone>(v: Vec<T>) -> (Vec<T>, Vec<T>) {
    let mut even = Vec::with_capacity(v.len() / 2 + 1);
    let mut odd = Vec::with_capacity(v.len() / 2);
    for (i, x) in v.into_iter().enumerate() {
        if i % 2 == 0 {
            even.push(x);
        } else {
            odd.push(x);
        }
    }
    (even, odd)
}

criterion_group!(benches, bench_triples, bench_presign, bench_sign);
criterion::criterion_main!(benches);
