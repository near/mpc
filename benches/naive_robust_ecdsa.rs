#![allow(clippy::indexing_slicing)]

use criterion::{criterion_group, Criterion};
mod bench_utils;
use crate::bench_utils::{
    robust_ecdsa_prepare_presign, robust_ecdsa_prepare_sign, MAX_MALICIOUS, SAMPLE_SIZE,
};
use rand_core::SeedableRng;
use threshold_signatures::test_utils::{run_protocol, MockCryptoRng};

fn participants_num() -> usize {
    2 * *MAX_MALICIOUS + 1
}

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;

    let mut group = c.benchmark_group("presign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("robust_ecdsa_presign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || robust_ecdsa_prepare_presign(num, &mut rng),
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
    group.sample_size(*SAMPLE_SIZE);

    let preps = robust_ecdsa_prepare_presign(num, &mut rng);
    let result = run_protocol(preps.protocols).expect("Prepare sign should not");
    let pk = preps.key_packages[0].1.public_key;

    group.bench_function(
        format!("robust_ecdsa_sign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || robust_ecdsa_prepare_sign(&result, max_malicious, pk, &mut rng),
                |preps| run_protocol(preps.protocols),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, bench_presign, bench_sign);
criterion::criterion_main!(benches);
