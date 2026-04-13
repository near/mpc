#![allow(clippy::indexing_slicing)]

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::SeedableRng;

mod bench_utils;
use crate::bench_utils::{
    analyze_received_sizes, ed25519_prepare_sign_v1, PreparedOutputs, MAX_MALICIOUS,
    RECONSTRUCTION_LOWER_BOUND, SAMPLE_SIZE,
};
use threshold_signatures::{
    frost::eddsa::{sign::sign_v1, KeygenOutput, SignatureOption},
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        run_protocol_and_take_snapshots, run_simulated_protocol, MockCryptoRng, Simulator,
    },
    ReconstructionLowerBound,
};

type PreparedSimulatedSig = PreparedOutputs<SignatureOption>;

/// Benches the signing protocol
fn bench_sign(c: &mut Criterion) {
    let num = RECONSTRUCTION_LOWER_BOUND.value();
    let max_malicious = *MAX_MALICIOUS;

    let setup = setup_sign_snapshot(*RECONSTRUCTION_LOWER_BOUND);
    let size = setup.cached_simulator.get_view_size();

    let mut group = c.benchmark_group("sign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("frost_ed25519_sign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_sign(&setup, *RECONSTRUCTION_LOWER_BOUND),
                |preps| run_simulated_protocol(preps.participant, preps.protocol, preps.simulator),
                criterion::BatchSize::SmallInput,
            );
        },
    );
    analyze_received_sizes(&[size], true);
}

criterion_group!(benches, bench_sign);
criterion_main!(benches);

struct SignSetup {
    participants: Vec<Participant>,
    real_participant: Participant,
    keygen_out: KeygenOutput,
    message: Vec<u8>,
    rng_for_protocol: MockCryptoRng,
    cached_simulator: Simulator,
}

/// Expensive one-time setup: runs the full N-party protocol to capture snapshots
fn setup_sign_snapshot(threshold: ReconstructionLowerBound) -> SignSetup {
    let mut rng = MockCryptoRng::seed_from_u64(41);
    let preps = ed25519_prepare_sign_v1(threshold, &mut rng);
    let (_, protocol_snapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    let participants: Vec<Participant> = preps
        .key_packages
        .iter()
        .map(|(participant, _)| *participant)
        .collect();

    // choose the real_participant being the coordinator
    let (real_participant, keygen_out) = preps.key_packages[preps.index].clone();

    let cached_simulator = Simulator::new(real_participant, &protocol_snapshot)
        .expect("Simulator should not be empty");

    SignSetup {
        participants,
        real_participant,
        keygen_out,
        message: preps.message,
        rng_for_protocol: rng,
        cached_simulator,
    }
}

/// Cheap per-sample setup: creates fresh sign protocol and clones the cached simulator
fn prepare_simulated_sign(
    setup: &SignSetup,
    threshold: ReconstructionLowerBound,
) -> PreparedSimulatedSig {
    let real_protocol = sign_v1(
        &setup.participants,
        threshold,
        setup.real_participant,
        setup.real_participant,
        setup.keygen_out.clone(),
        setup.message.clone(),
        setup.rng_for_protocol.clone(),
    )
    .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
    .expect("Signing should succeed");

    PreparedSimulatedSig {
        participant: setup.real_participant,
        protocol: real_protocol,
        simulator: setup.cached_simulator.clone(),
    }
}
