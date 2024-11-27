use cait_sith::{protocol::Participant};
use k256::Secp256k1;

use crate::assets::ProtocolsStorage;
use crate::background::InFlightGenerationTracker;
use crate::config::TripleConfig;
use crate::network::MeshNetworkClient;
use crate::primitives::{choose_random_participants, PairedTriple};
use crate::protocol::run_protocol;
use crate::{metrics, tracking};
use crate::{network::NetworkTaskChannel, primitives::ParticipantId};
use std::sync::{Arc};
use std::time::Duration;
use tokio::time::timeout;

/// Generates many cait-sith triples at once. This can significantly save the
/// *number* of network messages.
pub async fn run_many_triple_generation<const N: usize>(
    channel: NetworkTaskChannel,
    me: ParticipantId,
    threshold: usize,
) -> anyhow::Result<Vec<PairedTriple>> {
    assert_eq!(
        N % 2,
        0,
        "Expected to generate even number of triples in a batch"
    );
    let cs_participants = channel
        .participants
        .iter()
        .copied()
        .map(Participant::from)
        .collect::<Vec<_>>();
    let protocol = cait_sith::triples::generate_triple_many::<Secp256k1, N>(
        &cs_participants,
        me.into(),
        threshold,
    )?;
    let triples = run_protocol("many triple gen", channel, me, protocol).await?;
    metrics::MPC_NUM_TRIPLES_GENERATED.inc_by(N as u64);
    assert_eq!(
        N,
        triples.len(),
        "Unexpected triples len: expected {}, got {}",
        N,
        triples.len()
    );
    let iter = triples.into_iter();
    let pairs = iter.clone().step_by(2).zip(iter.skip(1).step_by(2));
    Ok(pairs.collect())
}

pub type TripleStorage = ProtocolsStorage<PairedTriple>;



pub const SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE: usize = 64;

/// Continuously runs triple generation in the background, using the number of threads
/// specified in the config, trying to maintain some number of available triples all the
/// time as specified in the config. Generated triples will be written to `triple_store`
/// as owned triples.
///
/// This function will not take care of the passive side of triple generation (i.e. other
/// participants of the computations this function initiates), so that needs to be
/// separately handled.
pub async fn run_background_triple_generation(
    client: Arc<MeshNetworkClient>,
    threshold: usize,
    config: Arc<TripleConfig>,
    triple_store: Arc<TripleStorage>,
) -> anyhow::Result<()> {
    let in_flight_generations = InFlightGenerationTracker::new();
    let parallelism_limiter = Arc::new(tokio::sync::Semaphore::new(config.concurrency));
    loop {
        let my_triples_count = triple_store.num_owned();
        metrics::MPC_OWNED_NUM_TRIPLES_AVAILABLE.set(my_triples_count as i64);
        if my_triples_count + in_flight_generations.num_in_flight()
            < config.desired_triples_to_buffer
            // There's no point to issue way too many in-flight computations, as they
            // will just be limited by the concurrency anyway.
            && in_flight_generations.num_in_flight()
                < config.concurrency * 2 * SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE
        {
            let current_active_participants_ids = client.all_alive_participant_ids();
            triple_store.set_alive_participants_ids(current_active_participants_ids.clone());
            if current_active_participants_ids.len() < threshold {
                // that should not happen often, so sleeping here is okay
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            let id_start = triple_store
                .generate_and_reserve_id_range(SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE as u32);
            let task_id = crate::primitives::MpcTaskId::ManyTriples {
                start: id_start,
                count: SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE as u32,
            };
            let participants = choose_random_participants(
                client.all_alive_participant_ids(),
                client.my_participant_id(),
                threshold,
            );
            let channel = client.new_channel_for_task(task_id, participants)?;
            let in_flight = in_flight_generations.in_flight(SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE);
            let client = client.clone();
            let parallelism_limiter = parallelism_limiter.clone();
            let triple_store = triple_store.clone();
            let config_clone = config.clone();
            tracking::spawn_checked(&format!("{:?}", task_id), async move {
                let _in_flight = in_flight;
                let _semaphore_guard = parallelism_limiter.acquire().await?;
                let triples = timeout(
                    Duration::from_secs(config_clone.timeout_sec),
                    run_many_triple_generation::<SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE>(
                        channel,
                        client.my_participant_id(),
                        threshold,
                    ),
                )
                .await??;

                for (i, paired_triple) in triples.into_iter().enumerate() {
                    triple_store.add_owned(id_start.add_to_counter(i as u32)?, paired_triple);
                }

                anyhow::Ok(())
            });
            // Before issuing another one, wait a bit. This can dramatically
            // improve throughput by avoiding thundering herd situations.
            // Further optimization can be done to avoid thundering herd
            // situations in the first place.
            tokio::time::sleep(std::time::Duration::from_secs(
                config.parallel_triple_generation_stagger_time_sec,
            ))
            .await;
        } else {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

#[cfg(test)]
mod tests_many {
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannel};
    use crate::primitives::{choose_random_participants, MpcTaskId};
    use crate::tracing::init_logging;
    use futures::{stream, StreamExt, TryStreamExt};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    use super::{run_many_triple_generation, PairedTriple};
    use crate::assets::UniqueId;
    use crate::tracking;

    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const PARALLELISM_PER_CLIENT: usize = 4;
    const TRIPLES_PER_BATCH: usize = 10;
    const BATCHES_TO_GENERATE_PER_CLIENT: usize = 10;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_many_triple_generation() {
        init_logging();
        tracking::testing::start_root_task_with_periodic_dump(async {
            run_test_clients(NUM_PARTICIPANTS, run_triple_gen_client)
                .await
                .unwrap();
        })
        .await;
    }

    async fn run_triple_gen_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::Receiver<NetworkTaskChannel>,
    ) -> anyhow::Result<Vec<PairedTriple>> {
        {
            let client = client.clone();
            let participant_id = client.my_participant_id();
            tracking::spawn("monitor passive channels", async move {
                loop {
                    let channel = channel_receiver.recv().await.unwrap();
                    tracking::spawn_checked(
                        &format!("passive task {:?}", channel.task_id),
                        run_many_triple_generation::<TRIPLES_PER_BATCH>(
                            channel,
                            participant_id,
                            THRESHOLD,
                        ),
                    );
                }
            });
        }

        let triples = stream::iter(0..BATCHES_TO_GENERATE_PER_CLIENT)
            .map(move |i| {
                let client = client.clone();
                async move {
                    let participant_id = client.my_participant_id();
                    let all_participant_ids = client.all_participant_ids();
                    let start_triple_id = UniqueId::new(participant_id, i as u64, 0);
                    let task_id = MpcTaskId::ManyTriples {
                        start: start_triple_id,
                        count: TRIPLES_PER_BATCH as u32,
                    };
                    let participants =
                        choose_random_participants(all_participant_ids, participant_id, THRESHOLD);
                    let result = tracking::spawn(
                        &format!("task {:?}", task_id),
                        run_many_triple_generation::<TRIPLES_PER_BATCH>(
                            client.new_channel_for_task(task_id, participants)?,
                            participant_id,
                            THRESHOLD,
                        ),
                    )
                    .await??;
                    anyhow::Ok(result)
                }
            })
            .buffered(PARALLELISM_PER_CLIENT)
            .try_collect::<Vec<_>>()
            .await?;

        Ok(triples.into_iter().flatten().collect())
    }
}
