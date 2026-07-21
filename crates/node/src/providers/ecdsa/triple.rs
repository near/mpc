use crate::assets::DistributedAssetStorage;
use crate::background::InFlightGenerationTracker;
use crate::config::MpcConfig;
use crate::db::{DBCol, SecretDB};
use crate::metrics;
use crate::metrics::tokio_task_metrics::ECDSA_TASK_MONITORS;
use crate::network::computation::MpcLeaderCentricComputation;
use crate::network::{MeshNetworkClient, NetworkTaskChannel};
use crate::primitives::{ParticipantId, UniqueId};
use crate::protocol::run_protocol;
use crate::providers::HasParticipants;
use crate::providers::ecdsa::{EcdsaSignatureProvider, EcdsaTaskId};
use crate::tracking::AutoAbortTaskCollection;
use mpc_node_config::TripleConfig;
use mpc_primitives::ReconstructionThreshold;
use mpc_primitives::domain::Protocol;
use near_mpc_contract_interface::types::DomainConfig;
use near_time::Clock;
use rand::rngs::OsRng;
use std::collections::BTreeSet;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use threshold_signatures::ReconstructionThreshold as TSReconstructionThreshold;
use threshold_signatures::ecdsa::ot_based_ecdsa::triples::TripleGenerationOutput;
use threshold_signatures::participants::Participant;

/// The distinct reconstruction thresholds `t` in `thresholds`. One triple store exists per `t`.
pub fn distinct_thresholds(
    thresholds: impl IntoIterator<Item = ReconstructionThreshold>,
) -> BTreeSet<ReconstructionThreshold> {
    thresholds.into_iter().collect()
}

/// The set of reconstruction thresholds `t` that CaitSith domains generate triples under. CaitSith
/// is the only protocol that uses triples.
pub fn caitsith_triple_thresholds(domains: &[DomainConfig]) -> BTreeSet<ReconstructionThreshold> {
    distinct_thresholds(
        domains
            .iter()
            .filter(|d| d.protocol == Protocol::CaitSith)
            .map(|d| d.reconstruction_threshold),
    )
}

/// Per-`t` triple store. Holds triples generated with `n = t` participants
/// (cait-sith triples are generated with exactly `t` parties, so the
/// participant count and the Shamir degree `t − 1` are equivalent
/// identifiers).
///
/// Backed by [`DBCol::TripleV2`] under prefix `t.inner().to_be_bytes()` (8 BE).
pub struct TripleStorage(DistributedAssetStorage<PairedTriple>);

impl TripleStorage {
    pub fn new(
        clock: Clock,
        db: Arc<SecretDB>,
        my_participant_id: ParticipantId,
        alive_participant_ids_query: Arc<dyn Fn() -> Vec<ParticipantId> + Send + Sync>,
        threshold: ReconstructionThreshold,
    ) -> anyhow::Result<Self> {
        Ok(Self(DistributedAssetStorage::<PairedTriple>::new(
            clock,
            db,
            DBCol::TripleV2,
            threshold.inner().to_be_bytes().to_vec(),
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

const TRIPLE_METRICS_REPORTING_INTERVAL: Duration = Duration::from_secs(5);

impl EcdsaSignatureProvider {
    /// Reports the triple-buffer gauges summed across every per-`t` store.
    /// Each generator owns a distinct store keyed by its threshold, so a single
    /// reporter prevents these unlabeled gauges from being clobbered by
    /// whichever generator ticked last.
    pub(super) async fn run_triple_metrics_reporting(triple_stores: Vec<Arc<TripleStorage>>) -> ! {
        loop {
            let mut online: i64 = 0;
            let mut offline: i64 = 0;
            let mut available: i64 = 0;
            for store in &triple_stores {
                online += i64::try_from(store.num_owned_ready()).expect("triple count fits in i64");
                offline +=
                    i64::try_from(store.num_owned_offline()).expect("triple count fits in i64");
                available += i64::try_from(store.num_owned()).expect("triple count fits in i64");
            }
            metrics::MPC_OWNED_NUM_TRIPLES_ONLINE.set(online);
            metrics::MPC_OWNED_NUM_TRIPLES_WITH_OFFLINE_PARTICIPANT.set(offline);
            metrics::MPC_OWNED_NUM_TRIPLES_AVAILABLE.set(available);
            tokio::time::sleep(TRIPLE_METRICS_REPORTING_INTERVAL).await;
        }
    }

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
        mpc_config: Arc<MpcConfig>,
        config: Arc<TripleConfig>,
        triple_store: Arc<TripleStorage>,
        threshold: TSReconstructionThreshold,
    ) -> ! {
        let in_flight_generations = InFlightGenerationTracker::new();
        let parallelism_limiter = Arc::new(tokio::sync::Semaphore::new(config.concurrency));
        let mut tasks = AutoAbortTaskCollection::new();
        let running_participants: Vec<_> = mpc_config
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .collect();

        loop {
            let my_triples_count = triple_store.num_owned();
            let should_generate = my_triples_count + in_flight_generations.num_in_flight()
                < config.desired_triples_to_buffer;

            if should_generate
                // There's no point to issue way too many in-flight computations, as they
                // will just be limited by the concurrency anyway.
                && in_flight_generations.num_in_flight()
                < config.concurrency * 2 * SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE
            {
                let participants = match client.select_random_active_participants_including_me(
                    threshold.value(),
                    &running_participants,
                ) {
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
                let channel = match client.new_channel_for_task(task_id, participants) {
                    Ok(channel) => channel,
                    Err(err) => {
                        tracing::warn!(
                            "Failed to create new channel for task {:?} with error: {}",
                            task_id,
                            err
                        );
                        continue;
                    }
                };
                let in_flight =
                    in_flight_generations.in_flight(SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE);
                let parallelism_limiter = parallelism_limiter.clone();
                let triple_store = triple_store.clone();
                let config_clone = config.clone();
                tasks.spawn_checked(
                    &format!("background triple generation; task_id: {:?}", task_id),
                    ECDSA_TASK_MONITORS
                        .triple_generation_leader
                        .instrument(async move {
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
                                triple_store.add_owned(
                                    id_start.add_to_counter(i.try_into()?)?,
                                    paired_triple,
                                );
                            }

                            anyhow::Ok(())
                        }),
                );
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
        &self,
        channel: NetworkTaskChannel,
        start: UniqueId,
        count: u32,
    ) -> anyhow::Result<()> {
        start.validate_owned_by(channel.sender().get_leader())?;
        let count: usize = count.try_into()?;
        if count != SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE {
            return Err(anyhow::anyhow!(
                "Unsupported batch size for triple generation"
            ));
        }
        // Cait-sith triple generation runs with exactly `t` participants, so we
        // can derive the store's `t` from the channel's participant list
        // without a wire-format change to `EcdsaTaskId::ManyTriples`.
        let threshold_usize: usize = channel.participants().len();
        let threshold = ReconstructionThreshold::new(threshold_usize.try_into()?);
        let triple_store = self.triple_store_for_t(threshold)?;
        FollowerManyTripleGenerationComputation::<SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE> {
            threshold: TSReconstructionThreshold::from(threshold_usize),
            out_triple_id_start: start,
            out_triple_store: triple_store,
        }
        .perform_leader_centric_computation(
            channel,
            Duration::from_secs(self.config.triple.timeout_sec),
        )
        .await?;

        Ok(())
    }
}

pub type PairedTriple = (TripleGenerationOutput, TripleGenerationOutput);

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
    pub threshold: TSReconstructionThreshold,
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
        let protocol = threshold_signatures::ecdsa::ot_based_ecdsa::triples::generate_triple_many::<
            N,
            _,
            _,
        >(&cs_participants, me.into(), self.threshold, OsRng)?;
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
    pub threshold: TSReconstructionThreshold,
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
                self.out_triple_id_start.add_to_counter(i.try_into()?)?,
                paired_triple,
            );
        }
        Ok(())
    }

    fn leader_waits_for_success(&self) -> bool {
        true
    }
}

pub fn participants_from_triples(
    triple0: &TripleGenerationOutput,
    triple1: &TripleGenerationOutput,
) -> Vec<ParticipantId> {
    triple0
        .1
        .participants
        .iter()
        .copied()
        .filter(|p| triple1.1.participants.contains(p))
        .map(|p| p.into())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        ManyTripleGenerationComputation, PairedTriple, ReconstructionThreshold, TripleStorage,
        caitsith_triple_thresholds,
    };
    use crate::assets::test_utils::{make_triple, triple_v2_key};
    use crate::db::{DBCol, SecretDB};
    use crate::network::computation::MpcLeaderCentricComputation;
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannel};
    use crate::primitives::{MpcTaskId, ParticipantId, UniqueId};
    use crate::providers::ecdsa::EcdsaTaskId;
    use crate::tests::into_participant_ids;
    use crate::tracking;
    use futures::{FutureExt, StreamExt, stream};
    use mpc_primitives::domain::{DomainId, Protocol};
    use near_mpc_contract_interface::types::{DomainConfig, DomainPurpose};
    use std::collections::{BTreeSet, HashMap};
    use std::sync::Arc;
    use threshold_signatures::ReconstructionThreshold as TSReconstructionThreshold;
    use threshold_signatures::test_utils::generate_participants;
    use tokio::sync::mpsc;

    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const PARALLELISM_PER_CLIENT: usize = 4;
    const TRIPLES_PER_BATCH: usize = 10;
    const BATCHES_TO_GENERATE_PER_CLIENT: usize = 10;

    fn domain(id: u64, protocol: Protocol, t: u64) -> DomainConfig {
        DomainConfig {
            id: DomainId(id),
            protocol,
            reconstruction_threshold: ReconstructionThreshold::new(t),
            purpose: DomainPurpose::Sign,
        }
    }

    #[test]
    #[expect(non_snake_case)]
    fn caitsith_triple_thresholds__should_dedup_and_exclude_non_caitsith() {
        // Given CaitSith domains with a duplicate `t` alongside non-CaitSith domains
        let domains = [
            domain(0, Protocol::CaitSith, 3),
            domain(1, Protocol::CaitSith, 2),
            domain(2, Protocol::CaitSith, 3),
            domain(3, Protocol::DamgardEtAl, 5),
            domain(4, Protocol::Frost, 4),
        ];

        // When / Then only the distinct CaitSith thresholds remain
        assert_eq!(
            caitsith_triple_thresholds(&domains),
            BTreeSet::from([2, 3].map(ReconstructionThreshold::new))
        );
    }

    #[test_log::test(tokio::test(flavor = "multi_thread"))]
    async fn test_many_triple_generation() {
        tracking::testing::start_root_task_with_periodic_dump(async {
            let all_triples = run_test_clients(
                into_participant_ids(&generate_participants(NUM_PARTICIPANTS)),
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
                            threshold: TSReconstructionThreshold::from(THRESHOLD),
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
                            threshold: TSReconstructionThreshold::from(THRESHOLD),
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
            .chain(passive_triples.await.unwrap())
            .collect())
    }

    fn new_triple_store(
        db: Arc<SecretDB>,
        my_participant_id: ParticipantId,
        threshold: ReconstructionThreshold,
        alive: Vec<ParticipantId>,
    ) -> TripleStorage {
        TripleStorage::new(
            near_time::FakeClock::default().clock(),
            db,
            my_participant_id,
            Arc::new(move || alive.clone()),
            threshold,
        )
        .unwrap()
    }

    /// Snapshot test pinning the on-disk DB key layout for the triple store.
    ///
    /// The exact byte layout is load-bearing: any drift in how
    /// `ReconstructionThreshold` or `UniqueId` serialize would silently change
    /// the on-disk format. The snapshot makes the layout an explicit, reviewed
    /// artifact — if it diffs, you're changing on-disk format and must think
    /// about migration.
    #[test]
    #[expect(non_snake_case)]
    fn db_key_layout__is_stable() {
        // Fixed inputs chosen so every byte position carries a visibly distinct
        // value (helps eyeball the snapshot).
        let t = ReconstructionThreshold::new(0x0102_0304_0506_0708);
        let participant = ParticipantId::from_raw(0xAABB_CCDD);
        let id = UniqueId::new(participant, 0x1122_3344_5566_7788, 0xDEAD_BEEF);

        let v2_key = triple_v2_key(t, id);

        insta::assert_snapshot!(format!("v2_key: {}", hex::encode(&v2_key)));
    }

    #[test]
    #[expect(non_snake_case)]
    fn triple_storage__should_isolate_per_t_stores() {
        // Given two per-`t` stores backed by the same DB.
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let me = ParticipantId::from_raw(42);
        let participants = vec![me];
        let store_a = new_triple_store(
            db.clone(),
            me,
            ReconstructionThreshold::new(3),
            participants.clone(),
        );
        let store_b = new_triple_store(
            db.clone(),
            me,
            ReconstructionThreshold::new(7),
            participants.clone(),
        );

        let id_a = store_a.generate_and_reserve_id();
        store_a.add_owned(id_a, make_triple(&participants));
        let id_b = store_b.generate_and_reserve_id();
        store_b.add_owned(id_b, make_triple(&participants));

        // When taking from `t = 3`.
        let (taken_id, _) = store_a.take_owned().now_or_never().unwrap();

        // Then `t = 7`'s store is unaffected.
        assert_eq!(taken_id, id_a);
        assert_eq!(store_a.num_owned(), 0);
        assert_eq!(store_b.num_owned(), 1);
    }

    #[test]
    #[expect(non_snake_case)]
    fn triple_storage_add_owned__should_write_to_triple_v2_column() {
        // Given a TripleStorage for `t = 3`.
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let me = ParticipantId::from_raw(42);
        let participants = vec![me];
        let t = ReconstructionThreshold::new(3);
        let store = new_triple_store(db.clone(), me, t, participants.clone());
        let id = store.generate_and_reserve_id();

        // When adding an owned triple.
        store.add_owned(id, make_triple(&participants));

        // Then it is persisted under the per-`t` TripleV2 key.
        assert!(
            db.get(DBCol::TripleV2, &triple_v2_key(t, id))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn triple_storage_take_owned__should_delete_from_triple_v2_column() {
        // Given a triple present in the per-`t` TripleV2 column.
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let me = ParticipantId::from_raw(42);
        let participants = vec![me];
        let t = ReconstructionThreshold::new(3);
        let store = new_triple_store(db.clone(), me, t, participants.clone());
        let id = store.generate_and_reserve_id();
        store.add_owned(id, make_triple(&participants));

        // When the triple is consumed.
        let _ = store.take_owned().now_or_never().unwrap();

        // Then it is gone from the TripleV2 column.
        assert!(
            db.get(DBCol::TripleV2, &triple_v2_key(t, id))
                .unwrap()
                .is_none()
        );
    }
}
