#![allow(clippy::missing_panics_doc)]
#![allow(clippy::indexing_slicing)]

use criterion::{Criterion, criterion_group, criterion_main};
use rand::seq::SliceRandom as _;
use rand_core::SeedableRng;

mod bench_utils;
use crate::bench_utils::{
    MAX_MALICIOUS, PreparedOutputs, RECONSTRUCTION_LOWER_BOUND, SAMPLE_SIZE,
    analyze_received_sizes, ot_ecdsa_prepare_sign, ot_ecdsa_prepare_triples, participant_rng,
};

use threshold_signatures::{
    ecdsa::{
        KeygenOutput, Scalar, SignatureOption, Tweak,
        ot_based_ecdsa::{
            SignArguments, sign,
            triples::{TriplePub, TripleShare, generate_triple_many},
        },
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        MockCryptoRng, Simulator, run_protocol, run_protocol_and_take_snapshots,
        run_simulated_protocol,
    },
};

type PreparedSimulatedTriples = PreparedOutputs<Vec<(TripleShare, TriplePub)>>;
type PreparedSimulatedSig = PreparedOutputs<SignatureOption>;

fn participants_num() -> usize {
    *MAX_MALICIOUS + 1
}

/// Benches the triples protocol
fn bench_triples(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;

    let setup = setup_triples_snapshot(num);
    let size = setup.cached_simulator.get_view_size();

    let mut group = c.benchmark_group("triples");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("ot_ecdsa_triples_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_triples(&setup),
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

/// Benches the signing protocol
fn bench_sign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;

    let mut rng = MockCryptoRng::seed_from_u64(42);
    let preps = ot_ecdsa_prepare_triples(num, *RECONSTRUCTION_LOWER_BOUND, &mut rng);
    let two_triples =
        run_protocol(preps.protocols).expect("Running triple preparations should succeed");

    let setup = setup_sign_snapshot(&two_triples);
    let size = setup.cached_simulator.get_view_size();

    let mut group = c.benchmark_group("sign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("ot_ecdsa_sign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
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

criterion_group!(benches, bench_triples, bench_sign);
criterion_main!(benches);

struct TriplesSetup {
    participants: Vec<Participant>,
    real_participant: Participant,
    real_participant_rng: MockCryptoRng,
    cached_simulator: Simulator,
}

/// Expensive one-time setup for triples: runs the full N-party protocol to capture snapshots
fn setup_triples_snapshot(participant_num: usize) -> TriplesSetup {
    let mut rng = MockCryptoRng::seed_from_u64(42);

    let preps = ot_ecdsa_prepare_triples(participant_num, *RECONSTRUCTION_LOWER_BOUND, &mut rng);
    let (_, protocol_snapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    // choose the real_participant at random
    let real_participant = *preps
        .participants
        .choose(&mut rng)
        .expect("participant list is not empty");

    // rebuild the exact rng the real participant used during snapshot capture
    let real_participant_rng = participant_rng(&preps.seeds, real_participant);

    let cached_simulator = Simulator::new(real_participant, &protocol_snapshot)
        .expect("Simulator should not be empty");

    TriplesSetup {
        participants: preps.participants,
        real_participant,
        real_participant_rng,
        cached_simulator,
    }
}

/// Cheap per-sample setup: creates fresh triples protocol and clones the cached simulator
fn prepare_simulated_triples(setup: &TriplesSetup) -> PreparedSimulatedTriples {
    let real_protocol = generate_triple_many(
        &setup.participants,
        setup.real_participant,
        *RECONSTRUCTION_LOWER_BOUND,
        2,
        setup.real_participant_rng.clone(),
    )
    .map(|prot| Box::new(prot) as Box<dyn Protocol<Output = Vec<(TripleShare, TriplePub)>>>)
    .expect("The rerun of the triple generation should not but raising error");

    PreparedSimulatedTriples {
        participant: setup.real_participant,
        protocol: real_protocol,
        simulator: setup.cached_simulator.clone(),
    }
}

struct SignSetup {
    participants: Vec<Participant>,
    real_participant: Participant,
    keygen_out: KeygenOutput,
    share0: TripleShare,
    pub0: TriplePub,
    share1: TripleShare,
    pub1: TriplePub,
    tweak: Tweak,
    msg_hash: Scalar,
    cached_simulator: Simulator,
}

/// Expensive one-time setup for sign: runs the full N-party protocol to capture snapshots
fn setup_sign_snapshot(two_triples: &[(Participant, Vec<(TripleShare, TriplePub)>)]) -> SignSetup {
    let mut rng = MockCryptoRng::seed_from_u64(40);
    let preps = ot_ecdsa_prepare_sign(two_triples, *RECONSTRUCTION_LOWER_BOUND, &mut rng);
    let (_, protocol_snapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    // choose the real_participant being the coordinator
    let real_participant = preps.coordinator;
    let (_, keygen_out) = preps
        .key_packages
        .into_iter()
        .find(|(p, _)| *p == real_participant)
        .expect("the coordinator has a key package");
    let (_, shares) = two_triples
        .iter()
        .find(|(p, _)| *p == real_participant)
        .expect("the coordinator has triple shares");
    let (share0, pub0) = shares[0].clone();
    let (share1, pub1) = shares[1].clone();

    let cached_simulator = Simulator::new(real_participant, &protocol_snapshot)
        .expect("Simulator should not be empty");

    SignSetup {
        participants: preps.participants,
        real_participant,
        keygen_out,
        share0,
        pub0,
        share1,
        pub1,
        tweak: preps.tweak,
        msg_hash: preps.msg_hash,
        cached_simulator,
    }
}

/// Cheap per-sample setup: creates fresh sign protocol and clones the cached simulator
fn prepare_simulated_sign(setup: &SignSetup) -> PreparedSimulatedSig {
    let real_protocol = sign(
        &setup.participants,
        setup.real_participant,
        setup.real_participant,
        SignArguments {
            triple0: (setup.share0.clone(), setup.pub0.clone()),
            triple1: (setup.share1.clone(), setup.pub1.clone()),
            keygen_out: setup.keygen_out.clone(),
            threshold: *RECONSTRUCTION_LOWER_BOUND,
        },
        setup.tweak,
        setup.msg_hash,
    )
    .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
    .expect("Signing should succeed");

    PreparedSimulatedSig {
        participant: setup.real_participant,
        protocol: real_protocol,
        simulator: setup.cached_simulator.clone(),
    }
}
