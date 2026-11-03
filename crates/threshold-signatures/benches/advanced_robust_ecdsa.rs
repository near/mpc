#![allow(clippy::indexing_slicing)]

use criterion::{Criterion, criterion_group, criterion_main};
use rand_core::SeedableRng;

mod bench_utils;
use crate::bench_utils::{
    MAX_MALICIOUS, PreparedOutputs, SAMPLE_SIZE, analyze_received_sizes, participant_rng,
    robust_ecdsa_prepare_sign,
};
use threshold_signatures::{
    ecdsa::{
        KeygenOutput, Scalar, SignatureOption, Tweak,
        robust_ecdsa::{PresignArguments, presign_and_sign},
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        MockCryptoRng, Simulator, run_protocol_and_take_snapshots, run_simulated_protocol,
    },
};

type PreparedSimulatedSig = PreparedOutputs<SignatureOption>;

fn participants_num() -> usize {
    2 * *MAX_MALICIOUS + 1
}

/// Benches the signing protocol
fn bench_sign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;

    let setup = setup_sign_snapshot(num);
    let size = setup.cached_simulator.get_view_size();

    let mut group = c.benchmark_group("sign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("robust_ecdsa_sign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_sign(&setup),
                |preps| {
                    run_simulated_protocol(preps.participant, preps.protocol, preps.simulator)
                        .expect("simulated replay should complete")
                },
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
    real_participant_rng: MockCryptoRng,
    tweak: Tweak,
    msg_hash: Scalar,
    cached_simulator: Simulator,
}

/// Expensive one-time setup for sign: runs the full N-party protocol to capture snapshots
fn setup_sign_snapshot(num_participants: usize) -> SignSetup {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let preps = robust_ecdsa_prepare_sign(num_participants, &mut rng);

    let (_, protocol_snapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    // choose the real_participant being the coordinator
    let real_participant = preps.coordinator;
    let (_, keygen_out) = preps
        .key_packages
        .into_iter()
        .find(|(p, _)| *p == real_participant)
        .expect("the coordinator has a key package");

    // rebuild the exact rng the real participant used during snapshot capture
    let real_participant_rng = participant_rng(&preps.seeds, real_participant);

    let cached_simulator = Simulator::new(real_participant, &protocol_snapshot)
        .expect("Simulator should not be empty");

    SignSetup {
        participants: preps.participants,
        real_participant,
        keygen_out,
        real_participant_rng,
        tweak: preps.tweak,
        msg_hash: preps.msg_hash,
        cached_simulator,
    }
}

/// Cheap per-sample setup: creates fresh sign protocol and clones the cached simulator
fn prepare_simulated_sign(setup: &SignSetup) -> PreparedSimulatedSig {
    let real_protocol = presign_and_sign(
        &setup.participants,
        setup.real_participant,
        setup.real_participant,
        PresignArguments {
            keygen_out: setup.keygen_out.clone(),
            max_malicious: (*MAX_MALICIOUS).into(),
        },
        setup.tweak,
        setup.msg_hash,
        setup.real_participant_rng.clone(), // provide the exact same randomness
    )
    .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
    .expect("Signing should succeed");

    PreparedSimulatedSig {
        participant: setup.real_participant,
        protocol: real_protocol,
        simulator: setup.cached_simulator.clone(),
    }
}
