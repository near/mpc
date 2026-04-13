#![allow(clippy::indexing_slicing, clippy::missing_panics_doc)]

use rand::RngCore;
use rand_core::SeedableRng;

use threshold_signatures::{
    confidential_key_derivation::{
        self as ckd,
        ciphersuite::{Field as _, Group as _},
        PublicVerificationKey,
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        bench_simulation, generate_participants_with_random_ids, run_keygen, run_simulation,
        BenchConfig, LatencyModel, MockCryptoRng, SimulationMetrics,
    },
};

fn main() {
    let config = BenchConfig::from_env();
    println!("Protocol simulation: CKD (BLS12-381)");
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

    eprint!("Setting up (keygen)...");
    let key_packages: Vec<(Participant, ckd::KeygenOutput)> =
        run_keygen(&participants, config.threshold, &mut setup_rng);
    eprintln!(" done");

    config.warmup(&|| {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        run_ckd(
            &participants,
            &key_packages,
            coordinator,
            &config.latency,
            &mut rng,
        );
    });

    bench_simulation(
        "ckd",
        &|| {
            let mut rng = MockCryptoRng::seed_from_u64(42);
            run_ckd(
                &participants,
                &key_packages,
                coordinator,
                &config.latency,
                &mut rng,
            )
        },
        config.samples,
    );

    bench_simulation(
        "ckd_pv",
        &|| {
            let mut rng = MockCryptoRng::seed_from_u64(42);
            run_ckd_pv(
                &participants,
                &key_packages,
                coordinator,
                &config.latency,
                &mut rng,
            )
        },
        config.samples,
    );
}

fn run_ckd(
    participants: &[Participant],
    key_packages: &[(Participant, ckd::KeygenOutput)],
    coordinator: Participant,
    latency: &LatencyModel,
    rng: &mut MockCryptoRng,
) -> SimulationMetrics {
    let (app_id, app_sk) = make_app_params(rng);
    let app_pk = ckd::ElementG1::generator() * app_sk;

    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = ckd::CKDOutputOption>>,
    )> = Vec::with_capacity(participants.len());
    for (p, keygen_out) in key_packages {
        let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
        let protocol = ckd::protocol::ckd(
            participants,
            coordinator,
            *p,
            keygen_out.clone(),
            app_id.clone(),
            app_pk,
            rng_p,
        )
        .expect("CKD should succeed");
        protocols.push((*p, Box::new(protocol)));
    }

    let (results, metrics) = run_simulation(protocols, latency);
    assert!(results.iter().any(|(_, out)| out.is_some()));
    metrics
}

fn run_ckd_pv(
    participants: &[Participant],
    key_packages: &[(Participant, ckd::KeygenOutput)],
    coordinator: Participant,
    latency: &LatencyModel,
    rng: &mut MockCryptoRng,
) -> SimulationMetrics {
    let (app_id, app_sk) = make_app_params(rng);
    let app_pk = PublicVerificationKey::new(
        ckd::ElementG1::generator() * app_sk,
        ckd::ElementG2::generator() * app_sk,
    );

    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = ckd::CKDOutputOption>>,
    )> = Vec::with_capacity(participants.len());
    for (p, keygen_out) in key_packages {
        let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
        let protocol = ckd::ckd_pv(
            participants,
            coordinator,
            *p,
            keygen_out.clone(),
            app_id.clone(),
            app_pk.clone(),
            rng_p,
        )
        .expect("CKD-PV should succeed");
        protocols.push((*p, Box::new(protocol)));
    }

    let (results, metrics) = run_simulation(protocols, latency);
    assert!(results.iter().any(|(_, out)| out.is_some()));
    metrics
}

fn make_app_params(rng: &mut MockCryptoRng) -> (ckd::AppId, ckd::Scalar) {
    let mut app_id_bytes: [u8; 32] = [0u8; 32];
    rng.fill_bytes(&mut app_id_bytes);
    let app_id = ckd::AppId::try_new(app_id_bytes).expect("cannot fail");
    let scalar_rng = MockCryptoRng::seed_from_u64(rng.next_u64());
    let app_sk = ckd::Scalar::random(scalar_rng);
    (app_id, app_sk)
}
