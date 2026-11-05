#![allow(clippy::indexing_slicing)]

use criterion::{Criterion, criterion_group};
mod bench_utils;
use crate::bench_utils::{
    MAX_MALICIOUS, SAMPLE_SIZE, ot_ecdsa_prepare_presign_and_sign, ot_ecdsa_prepare_triples,
};
use rand_core::SeedableRng;
use threshold_signatures::{
    ReconstructionThreshold,
    test_utils::{MockCryptoRng, run_protocol},
};

fn threshold() -> ReconstructionThreshold {
    ReconstructionThreshold::from(*MAX_MALICIOUS + 1)
}

fn participants_num() -> usize {
    *MAX_MALICIOUS + 1
}

/// Benches the triples protocol
fn bench_triples(c: &mut Criterion) {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;

    let threshold = threshold();
    let mut group = c.benchmark_group("triples");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("ot_ecdsa_triples_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || ot_ecdsa_prepare_triples(participants_num(), threshold, &mut rng),
                |preps| run_protocol(preps.protocols).expect("protocol should complete"),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

/// Benches the presign and sign protocol
fn bench_presign_and_sign(c: &mut Criterion) {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let threshold = threshold();

    let preps = ot_ecdsa_prepare_triples(participants_num(), threshold, &mut rng);
    let two_triples =
        run_protocol(preps.protocols).expect("Running triple preparations should succeed");

    let mut group = c.benchmark_group("presign_and_sign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("ot_ecdsa_presign_and_sign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || ot_ecdsa_prepare_presign_and_sign(&two_triples, threshold, &mut rng),
                |preps| run_protocol(preps.protocols).expect("protocol should complete"),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, bench_triples, bench_presign_and_sign);
criterion::criterion_main!(benches);
