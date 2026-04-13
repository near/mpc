#![allow(clippy::missing_panics_doc)]
#![allow(clippy::indexing_slicing)]

use criterion::{criterion_group, criterion_main, Criterion};
use frost_secp256k1::VerifyingKey;
use rand::{seq::SliceRandom as _, Rng, RngCore};
use rand_core::SeedableRng;

mod bench_utils;
use crate::bench_utils::{
    analyze_received_sizes, ot_ecdsa_prepare_presign, ot_ecdsa_prepare_sign,
    ot_ecdsa_prepare_triples, PreparedOutputs, MAX_MALICIOUS, RECONSTRUCTION_LOWER_BOUND,
    SAMPLE_SIZE,
};

use threshold_signatures::{
    ecdsa::{
        ot_based_ecdsa::{
            presign::presign,
            sign::sign,
            triples::{generate_triple_many, TriplePub, TripleShare},
            PresignArguments, PresignOutput, RerandomizedPresignOutput,
        },
        KeygenOutput, SignatureOption,
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        run_protocol, run_protocol_and_take_snapshots, run_simulated_protocol, MockCryptoRng,
        Simulator,
    },
    ReconstructionLowerBound,
};

use k256::AffinePoint;
use threshold_signatures::ecdsa::Scalar;

type PreparedSimulatedTriples = PreparedOutputs<Vec<(TripleShare, TriplePub)>>;
type PreparedSimulatedPresig = PreparedOutputs<PresignOutput>;
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
                |preps| run_simulated_protocol(preps.participant, preps.protocol, preps.simulator),
                criterion::BatchSize::SmallInput,
            );
        },
    );
    analyze_received_sizes(&[size], true);
}

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;

    let mut rng = MockCryptoRng::seed_from_u64(42);
    let preps = ot_ecdsa_prepare_triples(num, *RECONSTRUCTION_LOWER_BOUND, &mut rng);
    let two_triples =
        run_protocol(preps.protocols).expect("Running triple preparations should succeed");

    let setup = setup_presign_snapshot(&two_triples);
    let size = setup.cached_simulator.get_view_size();

    let mut group = c.benchmark_group("presign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("ot_ecdsa_presign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_presign(&setup),
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
    let preps = ot_ecdsa_prepare_triples(num, *RECONSTRUCTION_LOWER_BOUND, &mut rng);
    let two_triples =
        run_protocol(preps.protocols).expect("Running triples preparation should succeed");

    let preps = ot_ecdsa_prepare_presign(&two_triples, *RECONSTRUCTION_LOWER_BOUND, &mut rng);
    let result = run_protocol(preps.protocols).expect("Running presign preparation should succeed");
    let pk = preps.key_packages[0].1.public_key;

    let setup = setup_sign_snapshot(&result, *RECONSTRUCTION_LOWER_BOUND, pk);
    let size = setup.cached_simulator.get_view_size();

    let mut group = c.benchmark_group("sign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("ot_ecdsa_sign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
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

criterion_group!(benches, bench_triples, bench_presign, bench_sign);
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

    // recreate rng using by real_participant to generate triples
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

    TriplesSetup {
        participants: preps.participants,
        real_participant,
        real_participant_rng,
        cached_simulator,
    }
}

/// Cheap per-sample setup: creates fresh triples protocol and clones the cached simulator
fn prepare_simulated_triples(setup: &TriplesSetup) -> PreparedSimulatedTriples {
    let real_protocol = generate_triple_many::<2>(
        &setup.participants,
        setup.real_participant,
        *RECONSTRUCTION_LOWER_BOUND,
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

struct PresignSetup {
    participants: Vec<Participant>,
    real_participant: Participant,
    keygen_out: KeygenOutput,
    share0: TripleShare,
    pub0: TriplePub,
    share1: TripleShare,
    pub1: TriplePub,
    cached_simulator: Simulator,
}

/// Expensive one-time setup for presign: runs the full N-party protocol to capture snapshots
fn setup_presign_snapshot(
    two_triples: &[(Participant, Vec<(TripleShare, TriplePub)>)],
) -> PresignSetup {
    let mut rng = MockCryptoRng::seed_from_u64(40);
    let preps = ot_ecdsa_prepare_presign(two_triples, *RECONSTRUCTION_LOWER_BOUND, &mut rng);
    let (_, protocol_snapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    let mut rng = MockCryptoRng::seed_from_u64(41);
    // choose the real_participant at random
    let index_real_participant = rng.gen_range(0..participants_num());
    let (real_participant, keygen_out) = preps.key_packages[index_real_participant].clone();
    let (p, shares) = &two_triples[index_real_participant];
    assert_eq!(*p, real_participant);
    let (share0, pub0) = shares[0].clone();
    let (share1, pub1) = shares[1].clone();

    let cached_simulator = Simulator::new(real_participant, &protocol_snapshot)
        .expect("Simulator should not be empty");

    PresignSetup {
        participants: preps.participants,
        real_participant,
        keygen_out,
        share0,
        pub0,
        share1,
        pub1,
        cached_simulator,
    }
}

/// Cheap per-sample setup: creates fresh presign protocol and clones the cached simulator
fn prepare_simulated_presign(setup: &PresignSetup) -> PreparedSimulatedPresig {
    let real_protocol = presign(
        &setup.participants,
        setup.real_participant,
        PresignArguments {
            triple0: (setup.share0.clone(), setup.pub0.clone()),
            triple1: (setup.share1.clone(), setup.pub1.clone()),
            keygen_out: setup.keygen_out.clone(),
            threshold: *RECONSTRUCTION_LOWER_BOUND,
        },
    )
    .map(|presig| Box::new(presig) as Box<dyn Protocol<Output = PresignOutput>>)
    .expect("Presigning should succeed");

    PreparedSimulatedPresig {
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
    threshold: ReconstructionLowerBound,
    pk: VerifyingKey,
) -> SignSetup {
    let mut rng = MockCryptoRng::seed_from_u64(40);
    let preps = ot_ecdsa_prepare_sign(result, threshold, pk, &mut rng);
    let (_, protocol_snapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    // choose the real_participant at random
    let (real_participant, _) = result[preps.index];

    // collect all participants
    let participants: Vec<Participant> =
        result.iter().map(|(participant, _)| *participant).collect();

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
fn prepare_simulated_sign(
    setup: &SignSetup,
    threshold: ReconstructionLowerBound,
) -> PreparedSimulatedSig {
    let real_protocol = sign(
        &setup.participants,
        setup.real_participant,
        threshold,
        setup.real_participant,
        setup.derived_pk,
        setup.presig.clone(),
        setup.msg_hash,
    )
    .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
    .expect("Simulated signing should succeed");

    // now preparing the being the coordinator
    PreparedSimulatedSig {
        participant: setup.real_participant,
        protocol: real_protocol,
        simulator: setup.cached_simulator.clone(),
    }
}
