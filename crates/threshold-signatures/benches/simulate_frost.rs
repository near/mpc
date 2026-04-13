#![allow(clippy::indexing_slicing, clippy::missing_panics_doc)]

use rand::RngCore;
use rand_core::SeedableRng;

mod bench_utils;
use bench_utils::ed25519_build_presign_protocols;

use threshold_signatures::{
    frost::eddsa,
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        bench_simulation, generate_participants_with_random_ids, run_simulation, BenchConfig,
        LatencyModel, MockCryptoRng, SimulationMetrics,
    },
    ReconstructionLowerBound,
};

fn main() {
    let config = BenchConfig::from_env();
    let threshold = ReconstructionLowerBound::from(config.threshold);

    println!("Protocol simulation: EdDSA FROST signing");
    println!(
        "Participants: {}, threshold: {}, latency: {}ms, samples: {}",
        config.num_participants,
        config.threshold,
        config.latency_ms(),
        config.samples
    );
    println!();

    let mut setup_rng = MockCryptoRng::seed_from_u64(42);
    let participants =
        generate_participants_with_random_ids(config.num_participants, &mut setup_rng);
    let coordinator = participants[0];
    let message = b"test message for eddsa signing benchmark".to_vec();

    eprint!("Setting up (keygen)...");
    let key_packages: Vec<(Participant, eddsa::KeygenOutput)> =
        threshold_signatures::test_utils::run_keygen(
            &participants,
            config.threshold,
            &mut setup_rng,
        );
    eprintln!(" done");

    config.warmup(&|| {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        run_sign_v1(
            &participants,
            &key_packages,
            threshold,
            coordinator,
            &message,
            &config.latency,
            &mut rng,
        );
    });

    bench_simulation(
        "frost_v1",
        &|| {
            let mut rng = MockCryptoRng::seed_from_u64(42);
            run_sign_v1(
                &participants,
                &key_packages,
                threshold,
                coordinator,
                &message,
                &config.latency,
                &mut rng,
            )
        },
        config.samples,
    );

    bench_simulation(
        "frost_v2: presign",
        &|| {
            let mut rng = MockCryptoRng::seed_from_u64(77);
            run_presign(
                &participants,
                &key_packages,
                threshold,
                &config.latency,
                &mut rng,
            )
            .1
        },
        config.samples,
    );

    let mut presign_rng = MockCryptoRng::seed_from_u64(77);
    let (presign_outputs, _) = run_presign(
        &participants,
        &key_packages,
        threshold,
        &config.latency,
        &mut presign_rng,
    );

    bench_simulation(
        "frost_v2: sign",
        &|| {
            run_sign_v2(
                &participants,
                &key_packages,
                &presign_outputs,
                threshold,
                coordinator,
                &message,
                &config.latency,
            )
        },
        config.samples,
    );
}

fn run_presign(
    participants: &[Participant],
    key_packages: &[(Participant, eddsa::KeygenOutput)],
    threshold: ReconstructionLowerBound,
    latency: &LatencyModel,
    rng: &mut MockCryptoRng,
) -> (Vec<(Participant, eddsa::PresignOutput)>, SimulationMetrics) {
    run_simulation(
        ed25519_build_presign_protocols(participants, key_packages, threshold, rng),
        latency,
    )
}

fn run_sign_v1(
    participants: &[Participant],
    key_packages: &[(Participant, eddsa::KeygenOutput)],
    threshold: ReconstructionLowerBound,
    coordinator: Participant,
    message: &[u8],
    latency: &LatencyModel,
    rng: &mut MockCryptoRng,
) -> SimulationMetrics {
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = eddsa::SignatureOption>>,
    )> = Vec::with_capacity(participants.len());
    for (p, keygen_out) in key_packages {
        let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
        let protocol = eddsa::sign::sign_v1(
            participants,
            threshold,
            *p,
            coordinator,
            keygen_out.clone(),
            message.to_vec(),
            rng_p,
        )
        .expect("sign_v1 should succeed");
        protocols.push((*p, Box::new(protocol) as Box<dyn Protocol<Output = _>>));
    }
    let (results, metrics) = run_simulation(protocols, latency);
    assert!(results.iter().any(|(_, sig)| sig.is_some()));
    metrics
}

fn run_sign_v2(
    participants: &[Participant],
    key_packages: &[(Participant, eddsa::KeygenOutput)],
    presign_outputs: &[(Participant, eddsa::PresignOutput)],
    threshold: ReconstructionLowerBound,
    coordinator: Participant,
    message: &[u8],
    latency: &LatencyModel,
) -> SimulationMetrics {
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = eddsa::SignatureOption>>,
    )> = Vec::with_capacity(participants.len());
    for ((p, keygen_out), (_, presign_out)) in key_packages.iter().zip(presign_outputs) {
        let protocol = eddsa::sign::sign_v2(
            participants,
            threshold,
            *p,
            coordinator,
            keygen_out.clone(),
            presign_out.clone(),
            message.to_vec(),
        )
        .expect("sign_v2 should succeed");
        protocols.push((*p, Box::new(protocol) as Box<dyn Protocol<Output = _>>));
    }
    let (results, metrics) = run_simulation(protocols, latency);
    assert!(results.iter().any(|(_, sig)| sig.is_some()));
    metrics
}
