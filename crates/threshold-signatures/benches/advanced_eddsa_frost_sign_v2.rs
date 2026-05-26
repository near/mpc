#![allow(clippy::indexing_slicing)]

use criterion::{criterion_group, criterion_main, Criterion};
use rand::{Rng, RngCore};
use rand_core::SeedableRng;

mod bench_utils;
use crate::bench_utils::{
    analyze_received_sizes, ed25519_prepare_presign, ed25519_prepare_sign_v2, PreparedOutputs,
    MAX_MALICIOUS, RECONSTRUCTION_LOWER_BOUND, SAMPLE_SIZE,
};
use threshold_signatures::{
    frost::eddsa::{
        presign, sign::sign_v2, KeygenOutput, PresignArguments, PresignOutput, SignatureOption,
    },
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

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let num = RECONSTRUCTION_LOWER_BOUND.value();
    let max_malicious = *MAX_MALICIOUS;

    let setup = setup_presign_snapshot(num);
    let size = setup.cached_simulator.get_view_size();

    let mut group = c.benchmark_group("presign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("frost_ed25519_presign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_simulate_presign(&setup),
                |preps| run_simulated_protocol(preps.participant, preps.protocol, preps.simulator),
                criterion::BatchSize::SmallInput,
            );
        },
    );
    analyze_received_sizes(&[size], true);
}

/// Benches the signing protocol
fn bench_sign(c: &mut Criterion) {
    let num = RECONSTRUCTION_LOWER_BOUND.value();
    let max_malicious = *MAX_MALICIOUS;

    let setup = setup_sign_snapshot(*RECONSTRUCTION_LOWER_BOUND);
    let size = setup.cached_simulator.get_view_size();

    let mut group = c.benchmark_group("sign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("frost_ed25519_sign_v2_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
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

criterion_group!(benches, bench_presign, bench_sign);
criterion_main!(benches);

struct PresignSetup {
    participants: Vec<Participant>,
    real_participant: Participant,
    keygen_out: KeygenOutput,
    real_participant_rng: MockCryptoRng,
    cached_simulator: Simulator,
}

/// Expensive one-time setup for presign: runs the full N-party protocol to capture snapshots
fn setup_presign_snapshot(num_participants: usize) -> PresignSetup {
    // Running presign a first time with snapshots
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let preps = ed25519_prepare_presign(num_participants, &mut rng);

    let (_, protocol_snapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    // choose the real_participant at random
    let index_real_participant = rng.gen_range(0..num_participants);
    let (real_participant, keygen_out) = preps.key_packages[index_real_participant].clone();

    // recreate rng using by real_participant to generate presignatures
    let mut real_participant_rng = MockCryptoRng::seed_from_u64(42);
    for (i, _) in preps.key_packages.iter().enumerate() {
        let seed = real_participant_rng.next_u64();

        if i == index_real_participant {
            real_participant_rng = MockCryptoRng::seed_from_u64(seed);
            break;
        }
    }

    let cached_simulator = Simulator::new(real_participant, &protocol_snapshot)
        .expect("Simulator should not be empty");

    PresignSetup {
        participants: preps.participants,
        real_participant,
        keygen_out,
        real_participant_rng,
        cached_simulator,
    }
}

/// Cheap per-sample setup: creates fresh presign protocol and clones the cached simulator
fn prepare_simulate_presign(setup: &PresignSetup) -> PreparedPresig {
    let real_protocol = presign(
        &setup.participants,
        setup.real_participant,
        &PresignArguments {
            keygen_out: setup.keygen_out.clone(),
            threshold: *RECONSTRUCTION_LOWER_BOUND,
        },
        setup.real_participant_rng.clone(), // provide the exact same randomness
    )
    .map(|presig| Box::new(presig) as Box<dyn Protocol<Output = PresignOutput>>)
    .expect("Presignature should succeed");

    PreparedPresig {
        participant: setup.real_participant,
        protocol: real_protocol,
        simulator: setup.cached_simulator.clone(),
    }
}

struct SignSetup {
    participants: Vec<Participant>,
    real_participant: Participant,
    keygen_out: KeygenOutput,
    presig: PresignOutput,
    message: Vec<u8>,
    cached_simulator: Simulator,
}

/// Expensive one-time setup for sign: runs the full N-party protocol to capture snapshots
fn setup_sign_snapshot(threshold: ReconstructionLowerBound) -> SignSetup {
    let mut rng = MockCryptoRng::seed_from_u64(41);
    let preps = ed25519_prepare_presign(threshold.value(), &mut rng);
    let result = run_protocol(preps.protocols).expect("Prepare sign should not fail");
    let preps = ed25519_prepare_sign_v2(&result, preps.key_packages, threshold, &mut rng);
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
        presig: preps.presig,
        message: preps.message,
        cached_simulator,
    }
}

/// Cheap per-sample setup: creates fresh sign protocol and clones the cached simulator
fn prepare_simulated_sign(
    setup: &SignSetup,
    threshold: ReconstructionLowerBound,
) -> PreparedSimulatedSig {
    let real_protocol = sign_v2(
        &setup.participants,
        threshold,
        setup.real_participant,
        setup.real_participant,
        setup.keygen_out.clone(),
        setup.presig.clone(),
        setup.message.clone(),
    )
    .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
    .expect("Presignature should succeed");

    PreparedSimulatedSig {
        participant: setup.real_participant,
        protocol: real_protocol,
        simulator: setup.cached_simulator.clone(),
    }
}
