//! OT-based ECDSA triple generation by batch size. Like the node, it generates triples among
//! exactly `t` participants, so `NUM_PARTICIPANTS` is `t` and `THRESHOLD` is ignored.
//! `TRIPLE_BATCH_SIZES` takes a comma separated list of batch sizes.
#![allow(clippy::indexing_slicing, clippy::missing_panics_doc)]

use std::env;

use rand_core::SeedableRng;

mod bench_utils;
use bench_utils::ot_run_triples;

use threshold_signatures::{
    ReconstructionThreshold,
    test_utils::{
        BenchConfig, MockCryptoRng, bench_simulation, generate_participants_with_random_ids,
    },
};

const DEFAULT_BATCH_SIZES: [usize; 6] = [2, 4, 8, 16, 32, 64];

fn main() {
    let config = BenchConfig::from_env();
    println!("Protocol simulation: OT-based ECDSA triple generation by batch size");
    println!(
        "Participants (= threshold): {}, latency: {}ms, samples: {}",
        config.num_participants,
        config.latency_ms(),
        config.samples
    );
    println!();

    let mut setup_rng = MockCryptoRng::seed_from_u64(42);
    let participants =
        generate_participants_with_random_ids(config.num_participants, &mut setup_rng);
    let threshold = ReconstructionThreshold::from(participants.len());

    config.warmup(&|| {
        let mut rng = MockCryptoRng::seed_from_u64(55);
        ot_run_triples(&participants, threshold, 2, &config.latency, &mut rng);
    });

    for batch_size in batch_sizes_from_env() {
        bench_simulation(
            &format!("triples, batch {batch_size}"),
            &|| {
                let mut rng = MockCryptoRng::seed_from_u64(55);
                ot_run_triples(
                    &participants,
                    threshold,
                    batch_size,
                    &config.latency,
                    &mut rng,
                )
                .1
            },
            config.samples,
        );
    }
}

fn batch_sizes_from_env() -> Vec<usize> {
    env::var("TRIPLE_BATCH_SIZES").map_or_else(
        |_| DEFAULT_BATCH_SIZES.to_vec(),
        |sizes| {
            sizes
                .split(',')
                .map(|size| {
                    size.trim()
                        .parse()
                        .expect("TRIPLE_BATCH_SIZES is a comma separated list of batch sizes")
                })
                .collect()
        },
    )
}
