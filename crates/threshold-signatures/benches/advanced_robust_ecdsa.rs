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
        robust_ecdsa::{presign::presign, sign::sign, PresignArguments, PresignOutput},
        SignatureOption,
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        run_protocol, run_protocol_and_take_snapshots, run_simulated_protocol, MockCryptoRng,
        Simulator,
    },
};

type PreparedPresig = PreparedOutputs<PresignOutput>;
type PreparedSimulatedSig = PreparedOutputs<SignatureOption>;

fn participants_num() -> usize {
    2 * *MAX_MALICIOUS + 1
}

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut sizes = Vec::with_capacity(*SAMPLE_SIZE);

    let mut group = c.benchmark_group("presign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("robust_ecdsa_presign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
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
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut sizes = Vec::with_capacity(*SAMPLE_SIZE);

    let mut rng = MockCryptoRng::seed_from_u64(42);
    let preps = robust_ecdsa_prepare_presign(num, &mut rng);
    let result = run_protocol(preps.protocols).expect("Prepare sign should not");
    let pk = preps.key_packages[0].1.public_key;

    let mut group = c.benchmark_group("sign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("robust_ecdsa_sign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || {
                    let preps = prepare_simulated_sign(&result, max_malicious, pk);
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
/// Used to simulate robust ecdsa presignatures for benchmarking
fn prepare_simulate_presign(num_participants: usize) -> PreparedPresig {
    // Running presign a first time with snapshots
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let preps = robust_ecdsa_prepare_presign(num_participants, &mut rng);

    let (_, protocolsnapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    // choose the real_participant at random
    let (real_participant, keygen_out) = preps
        .key_packages
        .choose(&mut rng)
        .expect("participant list is not empty")
        .clone();

    // recreate rng using by real_participant to generate triples
    let mut rng_copy = MockCryptoRng::seed_from_u64(42);
    for p in &preps.participants {
        if *p == real_participant {
            break;
        }
        rng_copy.next_u64();
    }
    let real_participant_rng = MockCryptoRng::seed_from_u64(rng_copy.next_u64());

    let real_protocol = presign(
        &preps.participants,
        real_participant,
        PresignArguments {
            keygen_out,
            max_malicious: (*MAX_MALICIOUS).into(),
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

/// Used to simulate robust ecdsa signatures for benchmarking
fn prepare_simulated_sign(
    result: &[(Participant, PresignOutput)],
    max_malicious: usize,
    pk: VerifyingKey,
) -> PreparedSimulatedSig {
    let mut rng = MockCryptoRng::seed_from_u64(41);
    let preps = robust_ecdsa_prepare_sign(result, max_malicious.into(), pk, &mut rng);
    let (_, protocolsnapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    // collect all participants
    let participants: Vec<Participant> =
        result.iter().map(|(participant, _)| *participant).collect();
    // choose the real_participant being the coordinator
    let (real_participant, _) = result[preps.index];
    let real_protocol = sign(
        &participants,
        real_participant,
        max_malicious,
        real_participant,
        preps.derived_pk,
        preps.presig,
        preps.msg_hash,
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
