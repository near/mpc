#![allow(clippy::indexing_slicing)]

use criterion::{criterion_group, criterion_main, Criterion};
use frost_secp256k1::VerifyingKey;
use rand::{seq::SliceRandom as _, RngCore};
use rand_core::SeedableRng;

mod bench_utils;
use crate::bench_utils::{
    analyze_received_sizes, robust_ecdsa_prepare_presign, robust_ecdsa_prepare_sign,
    PreparedOutputs, MAX_MALICIOUS, SAMPLE_SIZE,
};
use threshold_signatures::{
    ecdsa::{
        robust_ecdsa::{
            presign::presign, sign::sign, PresignArguments, PresignOutput,
            RerandomizedPresignOutput,
        },
        KeygenOutput, SignatureOption,
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        run_protocol, run_protocol_and_take_snapshots, run_simulated_protocol, MockCryptoRng,
        Simulator,
    },
};

use k256::AffinePoint;
use threshold_signatures::ecdsa::Scalar;

type PreparedPresig = PreparedOutputs<PresignOutput>;
type PreparedSimulatedSig = PreparedOutputs<SignatureOption>;

fn participants_num() -> usize {
    2 * *MAX_MALICIOUS + 1
}

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;

    let setup = setup_presign_snapshot(num);
    let size = setup.cached_simulator.get_view_size();

    let mut group = c.benchmark_group("presign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("robust_ecdsa_presign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
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
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;

    let mut rng = MockCryptoRng::seed_from_u64(42);
    let preps = robust_ecdsa_prepare_presign(num, &mut rng);
    let result = run_protocol(preps.protocols).expect("Prepare sign should not fail");
    let pk = preps.key_packages[0].1.public_key;

    let setup = setup_sign_snapshot(&result, max_malicious, pk);
    let size = setup.cached_simulator.get_view_size();

    let mut group = c.benchmark_group("sign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("robust_ecdsa_sign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_sign(&setup, max_malicious),
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
    let preps = robust_ecdsa_prepare_presign(num_participants, &mut rng);

    let (_, protocol_snapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    // choose the real_participant at random
    let (real_participant, keygen_out) = preps
        .key_packages
        .choose(&mut rng)
        .expect("participant list is not empty")
        .clone();

    // recreate rng using by real_participant to generate presignatures
    let mut rng_copy = MockCryptoRng::seed_from_u64(42);
    for p in &preps.participants {
        if *p == real_participant {
            break;
        }
        rng_copy.next_u64();
    }
    let real_participant_rng = MockCryptoRng::seed_from_u64(rng_copy.next_u64());

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
        PresignArguments {
            keygen_out: setup.keygen_out.clone(),
            max_malicious: (*MAX_MALICIOUS).into(),
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
    derived_pk: AffinePoint,
    presig: RerandomizedPresignOutput,
    msg_hash: Scalar,
    cached_simulator: Simulator,
}

/// Expensive one-time setup for sign: runs the full N-party protocol to capture snapshots
fn setup_sign_snapshot(
    result: &[(Participant, PresignOutput)],
    max_malicious: usize,
    pk: VerifyingKey,
) -> SignSetup {
    let mut rng = MockCryptoRng::seed_from_u64(41);
    let preps = robust_ecdsa_prepare_sign(result, max_malicious.into(), pk, &mut rng);
    let (_, protocol_snapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    // collect all participants
    let participants: Vec<Participant> =
        result.iter().map(|(participant, _)| *participant).collect();
    // choose the real_participant being the coordinator
    let (real_participant, _) = result[preps.index];

    let cached_simulator = Simulator::new(real_participant, &protocol_snapshot)
        .expect("Simulator should not be empty");

    SignSetup {
        participants,
        real_participant,
        derived_pk: preps.derived_pk,
        presig: preps.presig,
        msg_hash: preps.msg_hash,
        cached_simulator,
    }
}

/// Cheap per-sample setup: creates fresh sign protocol and clones the cached simulator
fn prepare_simulated_sign(setup: &SignSetup, max_malicious: usize) -> PreparedSimulatedSig {
    let real_protocol = sign(
        &setup.participants,
        setup.real_participant,
        max_malicious,
        setup.real_participant,
        setup.derived_pk,
        setup.presig.clone(),
        setup.msg_hash,
    )
    .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
    .expect("Presignature should succeed");

    PreparedSimulatedSig {
        participant: setup.real_participant,
        protocol: real_protocol,
        simulator: setup.cached_simulator.clone(),
    }
}
