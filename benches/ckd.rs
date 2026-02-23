#![allow(clippy::indexing_slicing)]

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::SeedableRng;

mod bench_utils;
use crate::bench_utils::{
    analyze_received_sizes, prepare_ckd, PreparedOutputs, MAX_MALICIOUS, SAMPLE_SIZE,
};
use threshold_signatures::{
    confidential_key_derivation::{protocol::ckd, CKDOutputOption},
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        run_protocol_and_take_snapshots, run_simulated_protocol, MockCryptoRng, Simulator,
    },
    ReconstructionLowerBound,
};

type PreparedSimulatedCkd = PreparedOutputs<CKDOutputOption>;

fn threshold() -> ReconstructionLowerBound {
    ReconstructionLowerBound::from(*MAX_MALICIOUS + 1)
}

/// Benches the ckd protocol
fn bench_ckd(c: &mut Criterion) {
    let num = threshold().value();
    let max_malicious = *MAX_MALICIOUS;
    let mut sizes = Vec::with_capacity(*SAMPLE_SIZE);

    let mut group = c.benchmark_group("ckd");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("ckd_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || {
                    let preps = prepare_simulated_ckd(threshold());
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

criterion_group!(benches, bench_ckd);
criterion_main!(benches);

fn prepare_simulated_ckd(threshold: ReconstructionLowerBound) -> PreparedSimulatedCkd {
    let mut rng = MockCryptoRng::seed_from_u64(41);
    let preps = prepare_ckd(threshold, &mut rng);
    let (_, protocolsnapshot) = run_protocol_and_take_snapshots(preps.protocols)
        .expect("Running protocol with snapshot should not have issues");

    let participants: Vec<Participant> = preps
        .key_packages
        .iter()
        .map(|(participant, _)| *participant)
        .collect();

    // choose the real_participant being the coordinator
    let (real_participant, keygen_out) = preps.key_packages[preps.index].clone();
    let real_protocol = ckd(
        &participants,
        real_participant,
        real_participant,
        keygen_out,
        preps.app_id,
        preps.app_pk,
        rng,
    )
    .map(|ckd| Box::new(ckd) as Box<dyn Protocol<Output = CKDOutputOption>>)
    .expect("Ckd should succeed");

    // now preparing the simulator
    let simulated_protocol =
        Simulator::new(real_participant, protocolsnapshot).expect("Simulator should not be empty");

    PreparedSimulatedCkd {
        participant: real_participant,
        protocol: real_protocol,
        simulator: simulated_protocol,
    }
}
