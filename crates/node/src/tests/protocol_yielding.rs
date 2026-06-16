//! Canary test: crypto protocol computation must yield often enough that
//! concurrent tasks on the same runtime are not starved.
//!
//! Runs a triple generation batch on a single-threaded runtime next to a
//! "canary" task that measures how long it goes unscheduled. Without the
//! yield points inside `threshold-signatures` (surfaced as `Action::Yield`),
//! a single poke burst hogs the thread for the whole batch and the canary
//! gap explodes.
//!
//! The test is `#[ignore]`d: it is timing-sensitive and calibrated for
//! test-release on an unloaded machine. Run it manually with:
//!
//! ```text
//! cargo nextest run --cargo-profile=test-release -p mpc-node \
//!     triple_generation__should_not_starve_concurrent_tasks \
//!     --run-ignored all --no-capture
//! ```

use crate::network::testing::run_test_clients;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::UniqueId;
use crate::protocol::run_protocol;
use crate::providers::ecdsa::EcdsaTaskId;
use crate::providers::ecdsa::triple::SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE;
use crate::tests::into_participant_ids;
use crate::tracking;
use anyhow::Context;
use rand::SeedableRng as _;
use std::sync::Arc;
use std::time::{Duration, Instant};
use threshold_signatures::ReconstructionThreshold;
use threshold_signatures::ecdsa::ot_based_ecdsa::triples::generate_triple_many;
use threshold_signatures::participants::Participant;
use threshold_signatures::test_utils::{MockCryptoRng, generate_participants};
use tokio::sync::{mpsc, watch};

const NUM_PARTICIPANTS: usize = 3;
const THRESHOLD: usize = 3;
/// Same batch size as production, so the canary sees the real burst shape.
const TRIPLES_PER_BATCH: usize = SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE;

/// Upper bound on how long the canary may go unscheduled. Calibrated in
/// test-release on an unloaded machine: ~130ms max gap with the yield points
/// in place vs ~8.7s with them neutered (the canary wakes up only twice
/// during the whole batch). Unoptimized builds are ~10x slower and will
/// exceed this threshold; run with `--cargo-profile=test-release`.
// TODO(#3517): the ~130ms floor comes from the OT fan-out in triple
// multiplication; tighten this once per-poll child polling is budgeted.
const CANARY_MAX_GAP: Duration = Duration::from_millis(300);

struct CanaryReport {
    max_gap: Duration,
    mean_gap: Duration,
    iterations: u64,
}

/// Yields in a loop, recording the longest time between two wake-ups.
async fn canary_loop(stop: watch::Receiver<bool>) -> CanaryReport {
    let started = Instant::now();
    let mut last = started;
    let mut max_gap = Duration::ZERO;
    let mut iterations: u64 = 0;
    while !*stop.borrow() {
        tokio::task::yield_now().await;
        let now = Instant::now();
        max_gap = max_gap.max(now - last);
        last = now;
        iterations += 1;
    }
    CanaryReport {
        max_gap,
        mean_gap: started.elapsed() / iterations.max(1) as u32,
        iterations,
    }
}

// current_thread flavor on purpose: the canary and all three participants'
// crypto share one OS thread, so any non-yielding burst shows up as a gap.
#[test_log::test(tokio::test)]
#[expect(non_snake_case)]
#[ignore = "timing-sensitive; calibrated for test-release on an unloaded machine, run manually"]
async fn triple_generation__should_not_starve_concurrent_tasks() {
    tracking::testing::start_root_task_with_periodic_dump(async {
        // Given - a canary task measuring its own scheduling gaps
        let (stop_sender, stop_receiver) = watch::channel(false);
        let canary = tracking::spawn("canary", canary_loop(stop_receiver));

        // When - a triple generation batch runs on the same thread
        run_test_clients(
            into_participant_ids(&generate_participants(NUM_PARTICIPANTS)),
            run_triple_gen_client,
        )
        .await
        .unwrap();

        stop_sender.send(true).unwrap();
        let report = canary.await.unwrap();
        println!(
            "[#3501] canary report: max_gap={:?} mean_gap={:?} iterations={}",
            report.max_gap, report.mean_gap, report.iterations
        );

        // Then - the canary was never starved for longer than the threshold
        assert!(
            report.max_gap < CANARY_MAX_GAP,
            "canary starved for {:?} (threshold {:?}); \
             crypto computation is not yielding often enough",
            report.max_gap,
            CANARY_MAX_GAP
        );
    })
    .await;
}

async fn run_triple_gen_client(
    client: Arc<MeshNetworkClient>,
    mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
) -> anyhow::Result<()> {
    let my_id = client.my_participant_id();
    let mut ids = client.all_participant_ids();
    ids.sort();

    let mut channel = if my_id == ids[0] {
        let task_id = EcdsaTaskId::ManyTriples {
            start: UniqueId::new(my_id, 0, 0),
            count: TRIPLES_PER_BATCH as u32,
        };
        client.new_channel_for_task(task_id, ids.clone())?
    } else {
        channel_receiver
            .recv()
            .await
            .context("expected a channel from the leader")?
    };

    let my_index = ids.iter().position(|&p| p == my_id).unwrap();
    let rng = MockCryptoRng::seed_from_u64(42 + my_index as u64);
    let cs_participants: Vec<Participant> = ids.into_iter().map(Into::into).collect();
    let protocol = generate_triple_many::<TRIPLES_PER_BATCH, _, _>(
        &cs_participants,
        my_id.into(),
        ReconstructionThreshold::from(THRESHOLD),
        rng,
    )?;
    let triples = run_protocol("canary triple gen", &mut channel, protocol).await?;
    assert_eq!(triples.len(), TRIPLES_PER_BATCH);
    Ok(())
}
