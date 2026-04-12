#![allow(clippy::indexing_slicing)]

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::SeedableRng;

mod bench_utils;
use crate::bench_utils::{
    analyze_received_sizes, prepare_ckd, PreparedOutputs, MAX_MALICIOUS, SAMPLE_SIZE,
};
use threshold_signatures::{
    confidential_key_derivation::{
        protocol::ckd as ckd_protocol, AppId, CKDOutputOption, ElementG1, KeygenOutput,
    },
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

    let setup = setup_ckd_snapshot(threshold());
    let size = setup.cached_simulator.get_view_size();

    let mut group = c.benchmark_group("ckd");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("ckd_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_ckd(&setup),
                |preps| run_simulated_protocol(preps.participant, preps.protocol, preps.simulator),
                criterion::BatchSize::SmallInput,
            );
        },
    );
    analyze_received_sizes(&[size], true);
}

criterion_group!(benches, bench_ckd);
criterion_main!(benches);

struct CkdSetup {
    participants: Vec<Participant>,
    real_participant: Participant,
    keygen_out: KeygenOutput,
    app_id: AppId,
    app_pk: ElementG1,
    rng_for_protocol: MockCryptoRng,
    cached_simulator: Simulator,
}

/// Expensive one-time setup: runs the full N-party protocol to capture snapshots
fn setup_ckd_snapshot(threshold: ReconstructionLowerBound) -> CkdSetup {
    let mut rng = MockCryptoRng::seed_from_u64(41);
    let preps = prepare_ckd(threshold, &mut rng);
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

    CkdSetup {
        participants,
        real_participant,
        keygen_out,
        app_id: preps.app_id,
        app_pk: preps.app_pk,
        rng_for_protocol: rng,
        cached_simulator,
    }
}

/// Cheap per-sample setup: creates fresh ckd protocol and clones the cached simulator
fn prepare_simulated_ckd(setup: &CkdSetup) -> PreparedSimulatedCkd {
    let real_protocol = ckd_protocol(
        &setup.participants,
        setup.real_participant,
        setup.real_participant,
        setup.keygen_out.clone(),
        setup.app_id.clone(),
        setup.app_pk,
        setup.rng_for_protocol.clone(),
    )
    .map(|ckd| Box::new(ckd) as Box<dyn Protocol<Output = CKDOutputOption>>)
    .expect("Ckd should succeed");

    PreparedSimulatedCkd {
        participant: setup.real_participant,
        protocol: real_protocol,
        simulator: setup.cached_simulator.clone(),
    }
}
