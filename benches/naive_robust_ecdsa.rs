mod utils;
use criterion::{criterion_group, Criterion};
use frost_secp256k1::{Secp256K1Sha256, VerifyingKey};
use rand::Rng;
use rand_core::OsRng;
use utils::ecdsa_generate_rerandpresig_args;

use threshold_signatures::{
    ecdsa::{
        robust_ecdsa::{
            presign::presign, sign::sign, PresignArguments, PresignOutput,
            RerandomizedPresignOutput,
        },
        SignatureOption,
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{generate_participants_with_random_ids, run_keygen, run_protocol},
};

use utils::MAX_MALICIOUS;

fn participants_num() -> usize {
    2 * *crate::MAX_MALICIOUS + 1
}

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut group = c.benchmark_group("presign");
    group.measurement_time(std::time::Duration::from_secs(300));
    group.bench_function(
        format!("robust_ecdsa_presign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_presign(participants_num()),
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

    let (protocols, pk) = prepare_presign(participants_num());
    let mut result = run_protocol(protocols).expect("Prepare sign should not");
    result.sort_by_key(|(p, _)| *p);

    group.bench_function(
        format!("robust_ecdsa_sign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_sign(&result, pk),
                run_protocol,
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

/// Benches the presigning protocol
type PreparedPresig = (
    Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)>,
    VerifyingKey,
);
fn prepare_presign(num_participants: usize) -> PreparedPresig {
    let participants = generate_participants_with_random_ids(num_participants, &mut OsRng);
    let key_packages = run_keygen::<Secp256K1Sha256>(&participants, *MAX_MALICIOUS + 1);
    let pk = key_packages[0].1.public_key;
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)> =
        Vec::with_capacity(participants.len());

    for (p, keygen_out) in key_packages {
        let protocol = presign(
            &participants,
            p,
            PresignArguments {
                keygen_out,
                threshold: *MAX_MALICIOUS,
            },
            OsRng,
        )
        .map(|presig| Box::new(presig) as Box<dyn Protocol<Output = PresignOutput>>)
        .expect("Presignature should succeed");
        protocols.push((p, protocol));
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

criterion_group!(benches, bench_presign, bench_sign);
criterion::criterion_main!(benches);
