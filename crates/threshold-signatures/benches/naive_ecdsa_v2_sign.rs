#![allow(clippy::indexing_slicing)]

use criterion::{Criterion, criterion_group};
mod bench_utils;
use crate::bench_utils::{MAX_MALICIOUS, SAMPLE_SIZE, robust_ecdsa_v2_prepare_sign};
use rand_core::SeedableRng;
use threshold_signatures::test_utils::{MockCryptoRng, run_protocol};

fn participants_num() -> usize {
    2 * *MAX_MALICIOUS + 1
}

/// Benches the v2 signing protocol
fn bench_sign(c: &mut Criterion) {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;

    let mut group = c.benchmark_group("sign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("robust_ecdsa_v2_sign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || robust_ecdsa_v2_prepare_sign(num, &mut rng),
                |preps| run_protocol(preps.protocols).expect("protocol should complete"),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, bench_sign);
criterion::criterion_main!(benches);
