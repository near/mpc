use criterion::{criterion_group, Criterion};
mod bench_utils;
use crate::bench_utils::{
    ot_ecdsa_prepare_presign, ot_ecdsa_prepare_sign, ot_ecdsa_prepare_triples, MAX_MALICIOUS,
};
use rand_core::SeedableRng;
use threshold_signatures::test_utils::{run_protocol, MockCryptoRng};

fn threshold() -> usize {
    *MAX_MALICIOUS + 1
}

fn participants_num() -> usize {
    *MAX_MALICIOUS + 1
}

/// Benches the triples protocol
fn bench_triples(c: &mut Criterion) {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut group = c.benchmark_group("triples");
    group.measurement_time(std::time::Duration::from_secs(200));

    group.bench_function(
        format!("ot_ecdsa_triples_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || ot_ecdsa_prepare_triples(participants_num(), threshold(), &mut rng),
                |preps| run_protocol(preps.protocols),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut group = c.benchmark_group("presign");
    group.measurement_time(std::time::Duration::from_secs(300));

    let preps = ot_ecdsa_prepare_triples(participants_num(), threshold(), &mut rng);
    let two_triples =
        run_protocol(preps.protocols).expect("Running triple preparations should succeed");

    group.bench_function(
        format!("ot_ecdsa_presign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || ot_ecdsa_prepare_presign(&two_triples, threshold(), &mut rng),
                |preps| run_protocol(preps.protocols),
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

    let preps = ot_ecdsa_prepare_triples(participants_num(), threshold(), &mut rng);
    let two_triples =
        run_protocol(preps.protocols).expect("Running triples preparation should succeed");

    let preps = ot_ecdsa_prepare_presign(&two_triples, threshold(), &mut rng);
    let pk = preps.key_packages[0].1.public_key;
    let result = run_protocol(preps.protocols).expect("Running presign preparation should succeed");

    group.bench_function(
        format!("ot_ecdsa_sign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || ot_ecdsa_prepare_sign(&result, pk, &mut rng),
                |preps| run_protocol(preps.protocols),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, bench_triples, bench_presign, bench_sign);
criterion::criterion_main!(benches);
