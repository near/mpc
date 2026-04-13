#![allow(clippy::indexing_slicing, clippy::missing_panics_doc)]

use rand_core::SeedableRng;

mod bench_utils;
use bench_utils::prepare_dkg;

use threshold_signatures::{
    confidential_key_derivation::ciphersuite::BLS12381SHA256,
    frost_ed25519::Ed25519Sha512,
    frost_secp256k1::Secp256K1Sha256,
    test_utils::{bench_simulation, run_simulation, BenchConfig, MockCryptoRng, SimulationMetrics},
    Ciphersuite, Element, ReconstructionLowerBound, Scalar,
};

fn main() {
    let config = BenchConfig::from_env();
    let threshold = ReconstructionLowerBound::from(config.threshold);
    let n = config.num_participants;

    println!("Protocol simulation: DKG");
    println!(
        "Participants: {n}, threshold: {}, latency: {}ms, samples: {}",
        config.threshold,
        config.latency_ms(),
        config.samples
    );
    println!();

    config.warmup(&|| {
        run_dkg::<Secp256K1Sha256>(n, threshold, &config);
    });

    bench_simulation(
        "secp256k1",
        &|| run_dkg::<Secp256K1Sha256>(n, threshold, &config),
        config.samples,
    );
    bench_simulation(
        "ed25519",
        &|| run_dkg::<Ed25519Sha512>(n, threshold, &config),
        config.samples,
    );
    bench_simulation(
        "bls12381",
        &|| run_dkg::<BLS12381SHA256>(n, threshold, &config),
        config.samples,
    );
}

fn run_dkg<C: Ciphersuite>(
    n: usize,
    threshold: ReconstructionLowerBound,
    config: &BenchConfig,
) -> SimulationMetrics
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let protocols = prepare_dkg::<C, _>(n, threshold, &mut rng);
    let (results, metrics) = run_simulation(protocols, &config.latency);
    assert_eq!(results.len(), n);
    let first_pk = results[0].1.public_key;
    for (p, output) in &results {
        assert_eq!(
            output.public_key, first_pk,
            "Participant {p:?} has different public key"
        );
    }
    metrics
}
