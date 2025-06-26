use crate::assets::{DistributedAssetStorage, UniqueId};
use crate::background::InFlightGenerationTracker;
use crate::config::TripleConfig;
use crate::db::SecretDB;
use crate::metrics;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{participants_from_triples, ParticipantId};
use crate::protocol::run_protocol;
use crate::providers::ecdsa::{EcdsaSignatureProvider, EcdsaTaskId};
use crate::providers::HasParticipants;
use crate::tracking::AutoAbortTaskCollection;
use cait_sith::ecdsa::triples::TripleGenerationOutput;
use cait_sith::protocol::Participant;
use k256::Secp256k1;
use near_time::Clock;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

pub struct TripleStorage(DistributedAssetStorage<PairedTriple>);

impl TripleStorage {
    pub fn new(
        clock: Clock,
        db: Arc<SecretDB>,
        my_participant_id: ParticipantId,
        alive_participant_ids_query: Arc<dyn Fn() -> Vec<ParticipantId> + Send + Sync>,
    ) -> anyhow::Result<Self> {
        Ok(Self(DistributedAssetStorage::<PairedTriple>::new(
            clock,
            db,
            crate::db::DBCol::Triple,
            None,
            my_participant_id,
            |participants, pair| pair.is_subset_of_active_participants(participants),
            alive_participant_ids_query,
        )?))
    }
}

impl Deref for TripleStorage {
    type Target = DistributedAssetStorage<PairedTriple>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub const SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE: usize = 64;

impl EcdsaSignatureProvider {
    /// Continuously runs triple generation in the background, using the number of threads
    /// specified in the config, trying to maintain some number of available triples all the
    /// time as specified in the config. Generated triples will be written to `triple_store`
    /// as owned triples.
    ///
    /// This function will not take care of the passive side of triple generation (i.e. other
    /// participants of the computations this function initiates), so that needs to be
    /// separately handled.
    pub(super) async fn run_background_triple_generation(
        client: Arc<MeshNetworkClient>,
        threshold: usize,
        config: Arc<TripleConfig>,
        triple_store: Arc<TripleStorage>,
    ) -> anyhow::Result<()> {
        let in_flight_generations = InFlightGenerationTracker::new();
        let parallelism_limiter = Arc::new(tokio::sync::Semaphore::new(config.concurrency));
        let mut tasks = AutoAbortTaskCollection::new();
        loop {
            metrics::MPC_OWNED_NUM_TRIPLES_ONLINE.set(triple_store.num_owned_ready() as i64);
            metrics::MPC_OWNED_NUM_TRIPLES_WITH_OFFLINE_PARTICIPANT
                .set(triple_store.num_owned_offline() as i64);
            let my_triples_count = triple_store.num_owned();
            metrics::MPC_OWNED_NUM_TRIPLES_AVAILABLE.set(my_triples_count as i64);
            let should_generate = my_triples_count + in_flight_generations.num_in_flight()
                < config.desired_triples_to_buffer;

            if should_generate
                // There's no point to issue way too many in-flight computations, as they
                // will just be limited by the concurrency anyway.
                && in_flight_generations.num_in_flight()
                < config.concurrency * 2 * SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE
            {
                let participants =
                    match client.select_random_active_participants_including_me(threshold) {
                        Ok(participants) => participants,
                        Err(e) => {
                            tracing::warn!(
                                "Can't choose active participants for a triple: {}. Sleeping.",
                                e
                            );
                            // that should not happen often, so sleeping here is okay
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };

                let id_start = triple_store
                    .generate_and_reserve_id_range(SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE as u32);
                let task_id = EcdsaTaskId::ManyTriples {
                    start: id_start,
                    count: SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE as u32,
                };
                let channel = client.new_channel_for_task(task_id, participants)?;
                let in_flight =
                    in_flight_generations.in_flight(SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE);
                let parallelism_limiter = parallelism_limiter.clone();
                let triple_store = triple_store.clone();
                let config_clone = config.clone();
                tasks.spawn_checked(&format!("{:?}", task_id), async move {
                    let _in_flight = in_flight;
                    let _semaphore_guard = parallelism_limiter.acquire().await?;
                    let triples = (ManyTripleGenerationComputation::<
                        SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE,
                    > {
                        threshold,
                    })
                    .perform_leader_centric_computation(
                        channel,
                        Duration::from_secs(config_clone.timeout_sec),
                    )
                    .await?;

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
                continue;
            }

            // If the store is full, try to discard some triples which cannot be used right now
            if my_triples_count == config.desired_triples_to_buffer {
                triple_store.maybe_discard_owned(32).await;
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    pub(super) async fn run_triple_generation_follower(
        self: Arc<Self>,
        channel: NetworkTaskChannel,
        start: UniqueId,
        count: u32,
    ) -> anyhow::Result<()> {
        if count as usize != SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE {
            return Err(anyhow::anyhow!(
                "Unsupported batch size for triple generation"
            ));
        }
        FollowerManyTripleGenerationComputation::<SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE> {
            threshold: self.mpc_config.participants.threshold as usize,
            out_triple_id_start: start,
            out_triple_store: self.triple_store.clone(),
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.triple.timeout_sec),
        )
        .await?;

        Ok(())
    }
}

pub type PairedTriple = (
    TripleGenerationOutput<Secp256k1>,
    TripleGenerationOutput<Secp256k1>,
);

impl HasParticipants for PairedTriple {
    fn is_subset_of_active_participants(&self, active_participants: &[ParticipantId]) -> bool {
        let triple_participants = participants_from_triples(&self.0, &self.1);
        triple_participants
            .iter()
            .all(|p| active_participants.contains(p))
    }
}

/// Generates many cait-sith triples at once. This can significantly save the
/// *number* of network messages.
pub struct ManyTripleGenerationComputation<const N: usize> {
    pub threshold: usize,
}

#[async_trait::async_trait]
impl<const N: usize> MpcLeaderCentricComputation<Vec<PairedTriple>>
    for ManyTripleGenerationComputation<N>
{
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<Vec<PairedTriple>> {
        assert_eq!(
            N % 2,
            0,
            "Expected to generate even number of triples in a batch"
        );
        let cs_participants = channel
            .participants()
            .iter()
            .copied()
            .map(Participant::from)
            .collect::<Vec<_>>();
        let me = channel.my_participant_id();
        let protocol = cait_sith::ecdsa::triples::generate_triple_many::<Secp256k1, N>(
            &cs_participants,
            me.into(),
            self.threshold,
        )?;
        let _timer = metrics::MPC_TRIPLES_GENERATION_TIME_ELAPSED.start_timer();
        let triples = run_protocol("many triple gen", channel, protocol).await?;
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

    fn leader_waits_for_success(&self) -> bool {
        true
    }
}

/// The follower version of the triple generation. The difference is that the follower will only
/// complete the computation after successfully persisting the triples to storage.
pub struct FollowerManyTripleGenerationComputation<const N: usize> {
    pub threshold: usize,
    pub out_triple_store: Arc<TripleStorage>,
    pub out_triple_id_start: UniqueId,
}

#[async_trait::async_trait]
impl<const N: usize> MpcLeaderCentricComputation<()>
    for FollowerManyTripleGenerationComputation<N>
{
    async fn compute(self, channel: &mut NetworkTaskChannel) -> anyhow::Result<()> {
        let triples = ManyTripleGenerationComputation::<N> {
            threshold: self.threshold,
        }
        .compute(channel)
        .await?;
        for (i, paired_triple) in triples.into_iter().enumerate() {
            self.out_triple_store.add_unowned(
                self.out_triple_id_start.add_to_counter(i as u32)?,
                paired_triple,
            );
        }
        Ok(())
    }

    fn leader_waits_for_success(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests_many {
    use super::{ManyTripleGenerationComputation, PairedTriple};
    use crate::assets::UniqueId;
    use crate::network::computation::MpcLeaderCentricComputation;
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannel};
    use crate::primitives::MpcTaskId;
    use crate::providers::ecdsa::EcdsaTaskId;
    use crate::tests::TestGenerators;
    use crate::tracing::init_logging;
    use crate::tracking;
    use futures::{stream, StreamExt};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const PARALLELISM_PER_CLIENT: usize = 4;
    const TRIPLES_PER_BATCH: usize = 10;
    const BATCHES_TO_GENERATE_PER_CLIENT: usize = 10;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_many_triple_generation() {
        init_logging();
        tracking::testing::start_root_task_with_periodic_dump(async {
            let all_triples = run_test_clients(
                TestGenerators::new(NUM_PARTICIPANTS, THRESHOLD).participant_ids(),
                run_triple_gen_client,
            )
            .await
            .unwrap();

            // Sanity check that we generated the right number of triples, and
            // each triple has THRESHOLD participants.
            let mut id_to_triple_count = HashMap::new();

            for triples in &all_triples {
                for id in triples.keys() {
                    *id_to_triple_count.entry(*id).or_insert(0) += 1;
                }
            }
            assert_eq!(
                id_to_triple_count.len(),
                NUM_PARTICIPANTS * BATCHES_TO_GENERATE_PER_CLIENT * TRIPLES_PER_BATCH / 2,
            );
            for count in id_to_triple_count.values() {
                assert_eq!(*count, THRESHOLD);
            }
        })
        .await;
    }

    async fn run_triple_gen_client(
        client: Arc<MeshNetworkClient>,
        mut channel_receiver: mpsc::UnboundedReceiver<NetworkTaskChannel>,
    ) -> anyhow::Result<HashMap<UniqueId, PairedTriple>> {
        let passive_triples = tracking::spawn("monitor passive channels", async move {
            let mut tasks = Vec::new();
            for _ in 0..BATCHES_TO_GENERATE_PER_CLIENT * (THRESHOLD - 1) {
                let channel = channel_receiver.recv().await.unwrap();
                tasks.push(tracking::spawn(
                    &format!("passive task {:?}", channel.task_id()),
                    async move {
                        let MpcTaskId::EcdsaTaskId(EcdsaTaskId::ManyTriples { start, .. }) =
                            channel.task_id()
                        else {
                            panic!("Unexpected task id");
                        };
                        let triples = ManyTripleGenerationComputation::<TRIPLES_PER_BATCH> {
                            threshold: THRESHOLD,
                        }
                        .perform_leader_centric_computation(
                            channel,
                            std::time::Duration::from_secs(60),
                        )
                        .await
                        .unwrap();
                        triples
                            .into_iter()
                            .enumerate()
                            .map(|(i, pair)| (start.add_to_counter(i as u32).unwrap(), pair))
                            .collect::<Vec<_>>()
                    },
                ));
            }
            let results = futures::future::try_join_all(tasks).await.unwrap();
            results.into_iter().flatten().collect::<Vec<_>>()
        });

        let triples = stream::iter(0..BATCHES_TO_GENERATE_PER_CLIENT)
            .map(move |i| {
                let client = client.clone();
                async move {
                    let participant_id = client.my_participant_id();
                    let all_participant_ids = client.all_participant_ids();
                    let start_triple_id = UniqueId::new(participant_id, i as u64, 0);
                    let task_id = EcdsaTaskId::ManyTriples {
                        start: start_triple_id,
                        count: TRIPLES_PER_BATCH as u32,
                    };
                    // Pick threshold participants but do it in a uniform way so for the test,
                    // each node knows how many passive computations to expect.
                    let participants = {
                        let mut participants = all_participant_ids;
                        participants.sort();
                        let my_index = participants
                            .iter()
                            .position(|&p| p == participant_id)
                            .unwrap();
                        participants.rotate_left(my_index);
                        participants.truncate(THRESHOLD);
                        participants
                    };
                    let channel = client.new_channel_for_task(task_id, participants).unwrap();
                    let result = tracking::spawn(
                        &format!("task {:?}", task_id),
                        ManyTripleGenerationComputation::<TRIPLES_PER_BATCH> {
                            threshold: THRESHOLD,
                        }
                        .perform_leader_centric_computation(
                            channel,
                            std::time::Duration::from_secs(60),
                        ),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    result
                        .into_iter()
                        .enumerate()
                        .map(move |(i, pair)| {
                            (start_triple_id.add_to_counter(i as u32).unwrap(), pair)
                        })
                        .collect::<Vec<_>>()
                }
            })
            .buffered(PARALLELISM_PER_CLIENT)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        Ok(triples
            .into_iter()
            .chain(passive_triples.await.unwrap().into_iter())
            .collect())
    }
}
