#![allow(clippy::indexing_slicing)]

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::SeedableRng;

mod bench_utils;
use crate::bench_utils::{
    analyze_received_sizes, ed25519_prepare_sign, PreparedOutputs, MAX_MALICIOUS, SAMPLE_SIZE,
};
use threshold_signatures::{
    frost::eddsa::{sign::sign_v1, SignatureOption},
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        run_protocol_and_take_snapshots, run_simulated_protocol, MockCryptoRng, Simulator,
    },
    ReconstructionLowerBound,
};

type PreparedSimulatedSig = PreparedOutputs<SignatureOption>;

fn threshold() -> ReconstructionLowerBound {
    ReconstructionLowerBound::from(*MAX_MALICIOUS + 1)
}

/// Benches the signing protocol
fn bench_sign(c: &mut Criterion) {
    let num = threshold().value();
    let max_malicious = *MAX_MALICIOUS;
    let mut sizes = Vec::with_capacity(*SAMPLE_SIZE);

    let mut group = c.benchmark_group("sign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("frost_ed25519_sign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
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

criterion_group!(benches, bench_sign);
criterion_main!(benches);

/****************************** Helpers ******************************/
/// Used to simulate robust ecdsa signatures for benchmarking
fn prepare_simulated_sign(threshold: ReconstructionLowerBound) -> PreparedSimulatedSig {
    let mut rng = MockCryptoRng::seed_from_u64(41);
    let preps = ed25519_prepare_sign(threshold, &mut rng);
    let (_, protocolsnapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    let participants: Vec<Participant> = preps
        .key_packages
        .iter()
        .map(|(participant, _)| *participant)
        .collect();

    // choose the real_participant being the coordinator
    let (real_participant, keygen_out) = preps.key_packages[preps.index].clone();
    let real_protocol = sign_v1(
        &participants,
        threshold,
        real_participant,
        real_participant,
        keygen_out,
        preps.message,
        rng,
    )
    .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
    .expect("Signing should succeed");

    // now preparing the simulator
    let simulated_protocol =
        Simulator::new(real_participant, protocolsnapshot).expect("Simulator should not be empty");

    PreparedSimulatedSig {
        participant: real_participant,
        protocol: real_protocol,
        simulator: simulated_protocol,
    }
}
