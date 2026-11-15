use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::SeedableRng;
use std::hint::black_box;
use threshold_signatures::{
    ecdsa::{
        Secp256K1Sha256,
        pvw08::{Crs, ReceiverSecrets, SenderRandomness},
        run_batch_random_ot, run_pvw08_batch_random_ot,
    },
    participants::Participant,
    test_utils::MockCryptoRng,
};

type C = Secp256K1Sha256;

const SID: &[u8] = b"pvw08 benchmark session";
const BATCH_SIZES: [usize; 2] = [128, 1024];
/// The batch size of the CO15 base OT, which is not configurable.
const CO15_BATCH_SIZE: usize = 128;

fn bench_crs(c: &mut Criterion) {
    c.bench_function("PVW08/crs_derive", |b| {
        b.iter(|| black_box(Crs::<C>::derive(black_box(SID)).expect("derivation should succeed")));
    });
}

fn bench_steps(c: &mut Criterion) {
    let mut group = c.benchmark_group("PVW08");
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let sender = Participant::from(0u32);
    let receiver = Participant::from(1u32);
    let crs = Crs::<C>::derive(SID).expect("derivation should succeed");

    for batch_size in BATCH_SIZES {
        let secrets = ReceiverSecrets::<C>::random(batch_size, &mut rng);
        let randomness = SenderRandomness::<C>::random(batch_size, &mut rng);
        let public_keys = secrets.public_keys(&crs);
        let (ciphertexts, _) = randomness
            .encapsulate(&crs, SID, receiver, &public_keys)
            .expect("encapsulation should succeed");

        println!(
            "PVW08 batch of {batch_size}: receiver message {} bytes, sender message {} bytes",
            rmp_serde::to_vec(&public_keys)
                .expect("public keys should serialize")
                .len(),
            rmp_serde::to_vec(&ciphertexts)
                .expect("ciphertexts should serialize")
                .len(),
        );

        group.bench_function(BenchmarkId::new("receiver_public_keys", batch_size), |b| {
            b.iter(|| black_box(secrets.public_keys(&crs)));
        });
        group.bench_function(BenchmarkId::new("sender_encapsulate", batch_size), |b| {
            b.iter(|| {
                black_box(
                    randomness
                        .encapsulate(&crs, SID, receiver, &public_keys)
                        .expect("encapsulation should succeed"),
                )
            });
        });
        group.bench_function(BenchmarkId::new("receiver_decapsulate", batch_size), |b| {
            b.iter(|| {
                black_box(
                    secrets
                        .decapsulate(SID, &public_keys, sender, &ciphertexts)
                        .expect("decapsulation should succeed"),
                )
            });
        });
    }
    group.finish();
}

/// Both protocols run end to end, including the sampling of their randomness.
fn bench_against_co15(c: &mut Criterion) {
    let mut group = c.benchmark_group("Base_OT_128");

    group.bench_function("pvw08", |b| {
        b.iter(|| {
            black_box(
                run_pvw08_batch_random_ot(CO15_BATCH_SIZE, CO15_BATCH_SIZE, SID, SID)
                    .expect("protocol should succeed"),
            )
        });
    });
    group.bench_function("co15", |b| {
        b.iter(|| black_box(run_batch_random_ot().expect("protocol should succeed")));
    });
    group.finish();
}

criterion_group!(benches, bench_crs, bench_steps, bench_against_co15);

criterion_main!(benches);
