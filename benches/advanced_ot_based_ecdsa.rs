use criterion::{criterion_group, Criterion};
use frost_secp256k1::VerifyingKey;
use rand::{Rng, RngCore};
use rand_core::SeedableRng;

mod bench_utils;
use crate::bench_utils::{
    ot_ecdsa_prepare_presign, ot_ecdsa_prepare_sign, ot_ecdsa_prepare_triples, PreparedOutputs,
    MAX_MALICIOUS,
};

use threshold_signatures::{
    ecdsa::{
        ot_based_ecdsa::{
            presign::presign,
            sign::sign,
            triples::{generate_triple_many, TriplePub, TripleShare},
            PresignArguments, PresignOutput,
        },
        SignatureOption,
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        run_protocol, run_protocol_and_take_snapshots, run_simulated_protocol, MockCryptoRng,
        Simulator,
    },
};

type PreparedSimulatedTriples = PreparedOutputs<Vec<(TripleShare, TriplePub)>>;
type PreparedSimulatedPresig = PreparedOutputs<PresignOutput>;
type PreparedSimulatedSig = PreparedOutputs<SignatureOption>;

fn threshold() -> usize {
    *MAX_MALICIOUS + 1
}

fn participants_num() -> usize {
    *MAX_MALICIOUS + 1
}

/// Benches the triples protocol
fn bench_triples(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut group = c.benchmark_group("triples");
    group.measurement_time(std::time::Duration::from_secs(200));

    group.bench_function(
        format!("ot_ecdsa_triples_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_triples(num),
                |preps| run_simulated_protocol(preps.participant, preps.protocol, preps.simulator),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut group = c.benchmark_group("presign");
    group.measurement_time(std::time::Duration::from_secs(300));

    let mut rng = MockCryptoRng::seed_from_u64(42);
    let preps = ot_ecdsa_prepare_triples(num, threshold(), &mut rng);
    let two_triples =
        run_protocol(preps.protocols).expect("Running triple preparations should succeed");

    group.bench_function(
        format!("ot_ecdsa_presign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_presign(&two_triples),
                |preps| run_simulated_protocol(preps.participant, preps.protocol, preps.simulator),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

/// Benches the signing protocol
fn bench_sign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;

    let mut group = c.benchmark_group("sign");
    group.measurement_time(std::time::Duration::from_secs(300));

    let mut rng = MockCryptoRng::seed_from_u64(42);
    let preps = ot_ecdsa_prepare_triples(num, threshold(), &mut rng);
    let two_triples =
        run_protocol(preps.protocols).expect("Running triples preparation should succeed");

    let preps = ot_ecdsa_prepare_presign(&two_triples, threshold(), &mut rng);
    let result = run_protocol(preps.protocols).expect("Running presign preparation should succeed");
    let pk = preps.key_packages[0].1.public_key;

    group.bench_function(
        format!("ot_ecdsa_sign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_sign(&result, pk),
                |preps| run_simulated_protocol(preps.participant, preps.protocol, preps.simulator),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, bench_triples, bench_presign, bench_sign);
criterion::criterion_main!(benches);

/****************************** Helpers ******************************/
/// Used to simulate ot based ecdsa triples for benchmarking
/// # Panics
/// Would panic in case an abort happens stopping the entire benchmarking
fn prepare_simulated_triples(participant_num: usize) -> PreparedSimulatedTriples {
    let mut rng = MockCryptoRng::seed_from_u64(42);

    let preps = ot_ecdsa_prepare_triples(participant_num, threshold(), &mut rng);
    let (_, protocolsnapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    // choose the real_participant at random
    let index_real_participant = rng.gen_range(0..participant_num);
    let real_participant = preps.participants[index_real_participant];

    // recreate rng using by real_participant to generate triples
    let mut rng_copy = MockCryptoRng::seed_from_u64(42);
    for _ in 0..index_real_participant - 1 {
        rng_copy.next_u64();
    }
    let real_participant_rng = MockCryptoRng::seed_from_u64(rng_copy.next_u64());

    let real_protocol = generate_triple_many::<2>(
        &preps.participants,
        real_participant,
        threshold(),
        real_participant_rng,
    )
    .map(|prot| Box::new(prot) as Box<dyn Protocol<Output = Vec<(TripleShare, TriplePub)>>>)
    .expect("The rerun of the triple generation should not but raising error");

    // now preparing the simulator
    let simulated_protocol =
        Simulator::new(real_participant, protocolsnapshot).expect("Simulator should not be empty");
    PreparedSimulatedTriples {
        participant: real_participant,
        protocol: real_protocol,
        simulator: simulated_protocol,
    }
}

/// Used to simulate ot based ecdsa presignatures for benchmarking
/// # Panics
/// Would panic in case an abort happens stopping the entire benchmarking
fn prepare_simulated_presign(
    two_triples: &[(Participant, Vec<(TripleShare, TriplePub)>)],
) -> PreparedSimulatedPresig {
    let mut rng = MockCryptoRng::seed_from_u64(40);
    let preps = ot_ecdsa_prepare_presign(two_triples, threshold(), &mut rng);
    let (_, protocolsnapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    let mut rng = MockCryptoRng::seed_from_u64(41);
    // choose the real_participant at random
    let index_real_participant = rng.gen_range(0..participants_num());
    let (real_participant, keygen_out) = preps.key_packages[index_real_participant].clone();
    let (p, shares) = &two_triples[index_real_participant];
    assert_eq!(*p, real_participant);
    let (share0, pub0) = shares[0].clone();
    let (share1, pub1) = shares[1].clone();

    let real_protocol = presign(
        &preps.participants,
        real_participant,
        PresignArguments {
            triple0: (share0, pub0),
            triple1: (share1, pub1),
            keygen_out,
            threshold: threshold(),
        },
    )
    .map(|presig| Box::new(presig) as Box<dyn Protocol<Output = PresignOutput>>)
    .expect("Presigning should succeed");

    // now preparing the simulator
    let simulated_protocol =
        Simulator::new(real_participant, protocolsnapshot).expect("Simulator should not be empty");

    PreparedSimulatedPresig {
        participant: real_participant,
        protocol: real_protocol,
        simulator: simulated_protocol,
    }
}

/// Used to simulate ot based ecdsa signatures for benchmarking
/// # Panics
/// Would panic in case an abort happens stopping the entire benchmarking
pub fn prepare_simulated_sign(
    result: &[(Participant, PresignOutput)],
    pk: VerifyingKey,
) -> PreparedSimulatedSig {
    let mut rng = MockCryptoRng::seed_from_u64(40);
    let preps = ot_ecdsa_prepare_sign(result, pk, &mut rng);
    let (_, protocolsnapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    // choose the real_participant at random
    let (real_participant, _) = result[preps.index];

    // collect all participants
    let participants: Vec<Participant> =
        result.iter().map(|(participant, _)| *participant).collect();
    let real_protocol = sign(
        &participants,
        real_participant,
        real_participant,
        preps.derived_pk,
        preps.presig,
        preps.msg_hash,
    )
    .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
    .expect("Simulated signing should succeed");

    // now preparing the being the coordinator
    let simulated_protocol =
        Simulator::new(real_participant, protocolsnapshot).expect("Simulator should not be empty");
    PreparedSimulatedSig {
        participant: real_participant,
        protocol: real_protocol,
        simulator: simulated_protocol,
    }
}
