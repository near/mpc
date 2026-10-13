use criterion::{Criterion, criterion_group, criterion_main};
use rand::seq::SliceRandom as _;
use rand_core::SeedableRng;

mod bench_utils;
use crate::bench_utils::{
    MAX_MALICIOUS, PreparedOutputs, SAMPLE_SIZE, analyze_received_sizes, participant_rng,
    prepare_dkg,
};

use threshold_signatures::{
    Ciphersuite, Element, KeygenOutput, ReconstructionThreshold, Scalar,
    confidential_key_derivation::ciphersuite::BLS12381SHA256,
    frost_ed25519::Ed25519Sha512,
    frost_secp256k1::Secp256K1Sha256,
    keygen,
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        MockCryptoRng, Simulator, run_protocol_and_take_snapshots, run_simulated_protocol,
    },
};

fn threshold() -> ReconstructionThreshold {
    ReconstructionThreshold::from(*MAX_MALICIOUS + 1)
}

fn participants_num() -> usize {
    *MAX_MALICIOUS + 1
}

type PreparedSimulatedDkg<C> = PreparedOutputs<KeygenOutput<C>>;

fn bench_dkg<C: Ciphersuite>(c: &mut Criterion, name: &str)
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;

    let setup = setup_dkg_snapshot::<C>(threshold());
    let size = setup.cached_simulator.get_view_size();

    let mut group = c.benchmark_group("dkg");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("dkg_{name}_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_dkg::<C>(&setup, threshold()),
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

fn bench_dkg_secp256k1(c: &mut Criterion) {
    bench_dkg::<Secp256K1Sha256>(c, "secp256k1");
}
fn bench_dkg_ed25519(c: &mut Criterion) {
    bench_dkg::<Ed25519Sha512>(c, "ed25519");
}
fn bench_dkg_bls12381(c: &mut Criterion) {
    bench_dkg::<BLS12381SHA256>(c, "bls12381");
}

criterion_group!(
    benches,
    bench_dkg_secp256k1,
    bench_dkg_ed25519,
    bench_dkg_bls12381
);
criterion_main!(benches);

struct DkgSetup {
    participants: Vec<Participant>,
    real_participant: Participant,
    rng_for_protocol: MockCryptoRng,
    cached_simulator: Simulator,
}

/// Expensive one-time setup: runs the full N-party protocol to capture snapshots
fn setup_dkg_snapshot<C: Ciphersuite>(threshold: ReconstructionThreshold) -> DkgSetup
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let preps = prepare_dkg::<C, _>(participants_num(), threshold, &mut rng);
    let participants: Vec<_> = preps.protocols.iter().map(|(p, _)| *p).collect();
    let seeds = preps.seeds;
    let (_, protocol_snapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    // choose the real_participant at random
    let real_participant = *participants
        .choose(&mut rng)
        .expect("participant list is not empty");

    // rebuild the exact rng the real participant used during snapshot capture
    let rng_for_protocol = participant_rng(&seeds, real_participant);

    let cached_simulator = Simulator::new(real_participant, &protocol_snapshot)
        .expect("Simulator should not be empty");

    DkgSetup {
        participants,
        real_participant,
        rng_for_protocol,
        cached_simulator,
    }
}

/// Cheap per-sample setup: creates fresh protocol and clones the cached simulator
fn prepare_simulated_dkg<C: Ciphersuite>(
    setup: &DkgSetup,
    threshold: ReconstructionThreshold,
) -> PreparedSimulatedDkg<C>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let real_protocol = keygen::<C, _, _>(
        &setup.participants,
        setup.real_participant,
        threshold,
        setup.rng_for_protocol.clone(),
    )
    .map(|p| Box::new(p) as Box<dyn Protocol<Output = KeygenOutput<C>>>)
    .expect("Keygen should succeed");

    PreparedSimulatedDkg {
        participant: setup.real_participant,
        protocol: real_protocol,
        simulator: setup.cached_simulator.clone(),
    }
}
