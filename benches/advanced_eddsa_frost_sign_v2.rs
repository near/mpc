#![allow(clippy::indexing_slicing)]

use criterion::{criterion_group, criterion_main, Criterion};
use rand::{Rng, RngCore};
use rand_core::SeedableRng;

mod bench_utils;
use crate::bench_utils::{
    analyze_received_sizes, ed25519_prepare_presign, ed25519_prepare_sign_v2, PreparedOutputs,
    MAX_MALICIOUS, SAMPLE_SIZE,
};
use threshold_signatures::{
    frost::eddsa::{presign, sign::sign_v2, PresignArguments, PresignOutput, SignatureOption},
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        run_protocol, run_protocol_and_take_snapshots, run_simulated_protocol, MockCryptoRng,
        Simulator,
    },
    ReconstructionLowerBound,
};

type PreparedPresig = PreparedOutputs<PresignOutput>;
type PreparedSimulatedSig = PreparedOutputs<SignatureOption>;

fn threshold() -> ReconstructionLowerBound {
    ReconstructionLowerBound::from(*MAX_MALICIOUS + 1)
}

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let num = threshold().value();
    let max_malicious = *MAX_MALICIOUS;
    let mut sizes = Vec::with_capacity(*SAMPLE_SIZE);

    let mut group = c.benchmark_group("presign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("frost_ed25519_presign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || {
                    let preps = prepare_simulate_presign(num);
                    // collecting data sizes
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

/// Benches the signing protocol
fn bench_sign(c: &mut Criterion) {
    let num = threshold().value();
    let max_malicious = *MAX_MALICIOUS;
    let mut sizes = Vec::with_capacity(*SAMPLE_SIZE);

    let mut group = c.benchmark_group("sign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("frost_ed25519_sign_v2_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || {
                    let preps = prepare_simulated_sign(threshold());
                    // collecting data sizes
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

criterion_group!(benches, bench_presign, bench_sign);
criterion_main!(benches);

/****************************** Helpers ******************************/
/// Used to simulate Frost Ed25519 presignatures for benchmarking
fn prepare_simulate_presign(num_participants: usize) -> PreparedPresig {
    // Running presign a first time with snapshots
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let preps = ed25519_prepare_presign(num_participants, &mut rng);

    let (_, protocolsnapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    // choose the real_participant at random
    let index_real_participant = rng.gen_range(0..num_participants);
    let (real_participant, keygen_out) = preps.key_packages[index_real_participant].clone();

    // recreate rng using by real_participant to generate triples
    let mut rng_copy = MockCryptoRng::seed_from_u64(42);
    for _ in 0..index_real_participant - 1 {
        rng_copy.next_u64();
    }
    let real_participant_rng = MockCryptoRng::seed_from_u64(rng_copy.next_u64());

    let real_protocol = presign(
        &preps.participants,
        real_participant,
        &PresignArguments {
            keygen_out,
            threshold: threshold(),
        },
        real_participant_rng, // provide the exact same randomness
    )
    .map(|presig| Box::new(presig) as Box<dyn Protocol<Output = PresignOutput>>)
    .expect("Presignature should succeed");

    // now preparing the simulator
    let simulated_protocol =
        Simulator::new(real_participant, protocolsnapshot).expect("Simulator should not be empty");

    PreparedPresig {
        participant: real_participant,
        protocol: real_protocol,
        simulator: simulated_protocol,
    }
}

/// Used to simulate Frost Ed25519 signatures for benchmarking
fn prepare_simulated_sign(threshold: ReconstructionLowerBound) -> PreparedSimulatedSig {
    let mut rng = MockCryptoRng::seed_from_u64(41);
    let preps = ed25519_prepare_presign(threshold.value(), &mut rng);
    let result = run_protocol(preps.protocols).expect("Prepare sign should not fail");
    let preps = ed25519_prepare_sign_v2(&result, threshold, &mut rng);
    let (_, protocolsnapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    let participants: Vec<Participant> = preps
        .key_packages
        .iter()
        .map(|(participant, _)| *participant)
        .collect();

    // choose the real_participant being the coordinator
    let (real_participant, keygen_out) = preps.key_packages[preps.index].clone();
    let real_protocol = sign_v2(
        &participants,
        threshold,
        real_participant,
        real_participant,
        keygen_out,
        preps.presig,
        preps.message,
    )
    .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
    .expect("Presignature should succeed");

    // now preparing the simulator
    let simulated_protocol =
        Simulator::new(real_participant, protocolsnapshot).expect("Simulator should not be empty");

    PreparedSimulatedSig {
        participant: real_participant,
        protocol: real_protocol,
        simulator: simulated_protocol,
    }
}
