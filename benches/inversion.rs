#![allow(clippy::unwrap_used)]
use criterion::{criterion_group, criterion_main, Criterion};
use frost_core::{Field, Group};
use frost_secp256k1::{Secp256K1ScalarField, Secp256K1Sha256};
use rand::SeedableRng;
use std::hint::black_box;
use threshold_signatures::{batch_invert, test_utils::MockCryptoRng};

fn bench_inversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("Single_vs_Batch_Inversion");
    let mut rng = MockCryptoRng::seed_from_u64(42);

    group.measurement_time(std::time::Duration::from_secs(10));

    let num_inversions = 10_000;
    let values: Vec<_> = (0..num_inversions)
        .map(|_| Secp256K1ScalarField::random(&mut rng))
        .collect();

    group.bench_function("single_inversion", |b| {
        b.iter(|| {
            black_box(values
                .iter()
                .map(|v| {
                    <<Secp256K1Sha256 as frost_core::Ciphersuite>::Group as Group>::Field::invert(v)
                        .unwrap()
                })
                .collect::<Vec<_>>())
        });
    });

    group.bench_function("batch_inversion", |b| {
        b.iter(|| black_box(batch_invert::<Secp256K1Sha256>(&values).unwrap()));
    });
}

fn bench_inversion_vs_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("Inversion_vs_Multiplication");
    let mut rng = MockCryptoRng::seed_from_u64(42);

    group.bench_function("single_inversion", |b| {
        b.iter(|| {
            let value_to_invert = Secp256K1ScalarField::random(&mut rng);
            black_box(value_to_invert.invert().unwrap());
        });
    });

    group.bench_function("three_multiplications", |b| {
        b.iter(|| {
            let a = Secp256K1ScalarField::random(&mut rng);
            let b = Secp256K1ScalarField::random(&mut rng);
            let c = Secp256K1ScalarField::random(&mut rng);
            black_box(a * b * c);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_inversion, bench_inversion_vs_multiplication,);

criterion_main!(benches);
