use criterion::{criterion_group, Criterion};
use frost_secp256k1::VerifyingKey;
use rand::{Rng, SeedableRng};
use rand_core::CryptoRngCore;

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
    test_utils::{
        ecdsa_generate_rerandpresig_args, generate_participants_with_random_ids, run_keygen,
        run_protocol, MockCryptoRng,
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

fn participants_num() -> usize {
    2 * *crate::MAX_MALICIOUS + 1
}

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut group = c.benchmark_group("presign");
    group.measurement_time(std::time::Duration::from_secs(300));
    group.bench_function(
        format!("robust_ecdsa_presign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_presign(participants_num(), &mut rng),
                |(protocols, _)| run_protocol(protocols),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

/// Benches the signing protocol
fn bench_sign(c: &mut Criterion) {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut group = c.benchmark_group("sign");
    group.measurement_time(std::time::Duration::from_secs(300));

    let (protocols, pk) = prepare_presign(participants_num(), &mut rng);
    let mut result = run_protocol(protocols).expect("Prepare sign should not");
    result.sort_by_key(|(p, _)| *p);

    group.bench_function(
        format!("robust_ecdsa_sign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_sign(&result, pk, &mut rng),
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
fn prepare_presign<R: CryptoRngCore + SeedableRng + Send + 'static>(
    num_participants: usize,
    rng: &mut R,
) -> PreparedPresig {
    let participants = generate_participants_with_random_ids(num_participants, rng);
    let key_packages = run_keygen(&participants, *MAX_MALICIOUS + 1, rng);
    let pk = key_packages[0].1.public_key;
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)> =
        Vec::with_capacity(participants.len());

    for (p, keygen_out) in key_packages {
        let rng_p = R::seed_from_u64(rng.next_u64());
        let protocol = presign(
            &participants,
            p,
            PresignArguments {
                keygen_out,
                threshold: *MAX_MALICIOUS,
            },
            rng_p,
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
    rng: &mut impl CryptoRngCore,
) -> Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)> {
    // collect all participants
    let participants: Vec<Participant> =
        result.iter().map(|(participant, _)| *participant).collect();

    // choose a coordinator at random
    let index = rng.gen_range(0..result.len());
    let coordinator = result[index].0;

    let (args, msg_hash) =
        ecdsa_generate_rerandpresig_args(rng, &participants, pk, result[0].1.big_r);
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
