#![allow(clippy::indexing_slicing)]

use criterion::{criterion_group, criterion_main, Criterion};
use rand::seq::SliceRandom as _;
use rand_core::SeedableRng;

mod bench_utils;
use crate::bench_utils::{
    analyze_received_sizes, prepare_dkg, PreparedOutputs, MAX_MALICIOUS, SAMPLE_SIZE,
};

use threshold_signatures::{
    confidential_key_derivation::ciphersuite::BLS12381SHA256,
    frost_ed25519::Ed25519Sha512,
    frost_secp256k1::Secp256K1Sha256,
    keygen,
    protocol::Protocol,
    test_utils::{
        run_protocol_and_take_snapshots, run_simulated_protocol, MockCryptoRng, Simulator,
    },
    Ciphersuite, Element, KeygenOutput, ReconstructionLowerBound, Scalar,
};

fn threshold() -> ReconstructionLowerBound {
    ReconstructionLowerBound::from(*MAX_MALICIOUS + 1)
}

fn participants_num() -> usize {
    *MAX_MALICIOUS + 1
}

type PreparedSimulatedDkg<C> = PreparedOutputs<KeygenOutput<C>>;

/// Benches the DKG protocol for Secp256k1
fn bench_dkg_secp256k1(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut sizes = Vec::with_capacity(*SAMPLE_SIZE);

    let mut group = c.benchmark_group("dkg");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("dkg_secp256k1_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || {
                    let preps = prepare_simulated_dkg::<Secp256K1Sha256>(threshold());
                    sizes.push(preps.simulator.get_view_size());
                    preps
                },
                |preps| run_simulated_protocol(preps.participant, preps.protocol, preps.simulator),
                criterion::BatchSize::SmallInput,
            );
        },
    );
    analyze_received_sizes(&sizes, true);
}

/// Benches the DKG protocol for Ed25519
fn bench_dkg_ed25519(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut sizes = Vec::with_capacity(*SAMPLE_SIZE);

    let mut group = c.benchmark_group("dkg");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("dkg_ed25519_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || {
                    let preps = prepare_simulated_dkg::<Ed25519Sha512>(threshold());
                    sizes.push(preps.simulator.get_view_size());
                    preps
                },
                |preps| run_simulated_protocol(preps.participant, preps.protocol, preps.simulator),
                criterion::BatchSize::SmallInput,
            );
        },
    );
    analyze_received_sizes(&sizes, true);
}

/// Benches the DKG protocol for BLS12-381
fn bench_dkg_bls12381(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut sizes = Vec::with_capacity(*SAMPLE_SIZE);

    let mut group = c.benchmark_group("dkg");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("dkg_bls12381_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || {
                    let preps = prepare_simulated_dkg::<BLS12381SHA256>(threshold());
                    sizes.push(preps.simulator.get_view_size());
                    preps
                },
                |preps| run_simulated_protocol(preps.participant, preps.protocol, preps.simulator),
                criterion::BatchSize::SmallInput,
            );
        },
    );
    analyze_received_sizes(&sizes, true);
}

criterion_group!(
    benches,
    bench_dkg_secp256k1,
    bench_dkg_ed25519,
    bench_dkg_bls12381
);
criterion_main!(benches);

/****************************** Helpers ******************************/
/// Used to simulate DKG keygen for benchmarking
fn prepare_simulated_dkg<C: Ciphersuite>(
    threshold: ReconstructionLowerBound,
) -> PreparedSimulatedDkg<C>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let preps = prepare_dkg::<C, _>(participants_num(), threshold, &mut rng);
    let participants: Vec<_> = preps.iter().map(|(p, _)| *p).collect();
    let (_, protocol_snapshot) = run_protocol_and_take_snapshots(preps)
        .expect("Running protocol with snapshot should not have issues");

    // choose the real_participant at random
    let real_participant = *participants
        .choose(&mut rng)
        .expect("participant list is not empty");

    let real_protocol = keygen::<C>(&participants, real_participant, threshold, rng)
        .map(|p| Box::new(p) as Box<dyn Protocol<Output = KeygenOutput<C>>>)
        .expect("Keygen should succeed");

    // now preparing the simulator
    let simulated_protocol =
        Simulator::new(real_participant, protocol_snapshot).expect("Simulator should not be empty");

    PreparedSimulatedDkg {
        participant: real_participant,
        protocol: real_protocol,
        simulator: simulated_protocol,
    }
}
