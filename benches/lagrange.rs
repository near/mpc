#![allow(clippy::unwrap_used)]
use criterion::{criterion_group, criterion_main, Criterion};
use frost_core::Field;
use frost_secp256k1::{Secp256K1ScalarField, Secp256K1Sha256};
use rand::SeedableRng;
use std::hint::black_box;
use threshold_signatures::{
    batch_compute_lagrange_coefficients, compute_lagrange_coefficient, participants::Participant,
    test_utils::MockCryptoRng,
};

type C = Secp256K1Sha256;

fn bench_lagrange_computation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Lagrange");
    let mut rng = MockCryptoRng::seed_from_u64(42);

    for degree in &[1u32, 100, 1_000] {
        let participants = (0..=*degree).map(Participant::from).collect::<Vec<_>>();
        let ids = participants
            .iter()
            .map(Participant::scalar::<C>)
            .collect::<Vec<_>>();
        let point = Some(Secp256K1ScalarField::random(&mut rng));

        group.bench_with_input(
            format!("sequential_degree_{degree}"),
            &(ids.clone(), point),
            |b, (ids, point)| {
                b.iter(|| {
                    for id in ids {
                        let coeff =
                            compute_lagrange_coefficient::<C>(ids, id, point.as_ref()).unwrap();
                        black_box(coeff);
                    }
                });
            },
        );

        group.bench_with_input(
            format!("batch_degree_{degree}"),
            &(ids.clone(), point),
            |b, (ids, point)| {
                b.iter(|| {
                    let coeff =
                        batch_compute_lagrange_coefficients::<C>(ids, point.as_ref()).unwrap();
                    black_box(coeff);
                });
            },
        );

        // x = 0
        let point_x0 = Some(Secp256K1ScalarField::zero());
        group.bench_with_input(
            format!("batch_x0_degree_{degree}"),
            &(ids.clone(), point_x0),
            |b, (ids, point)| {
                b.iter(|| {
                    let coeff =
                        batch_compute_lagrange_coefficients::<C>(ids, point.as_ref()).unwrap();
                    black_box(coeff);
                });
            },
        );
    }
    group.finish();
}

pub fn bench_inversion_vs_multiplication(c: &mut Criterion) {
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

criterion_group!(benches, bench_lagrange_computation);

criterion_main!(benches);
