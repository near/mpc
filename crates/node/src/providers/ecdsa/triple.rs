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
use near_time::Clock;
use rand::rngs::OsRng;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use threshold_signatures::ReconstructionLowerBound;
use threshold_signatures::ecdsa::ot_based_ecdsa::triples::TripleGenerationOutput;
use threshold_signatures::participants::Participant;

/// Per-`t` triple store. Holds triples generated with `n = t` participants
/// (cait-sith triples are generated with exactly `t` parties, so the
/// participant count and the Shamir degree `t − 1` are equivalent
/// identifiers).
///
/// Backed by [`DBCol::TripleV2`] under prefix `t.inner().to_be_bytes()` (8 BE),
/// with dual-write to [`DBCol::Triple`] (no prefix) so that a node downgraded
/// to the previous binary can still consume triples this binary wrote. The
/// mirror is intended to be dropped in a follow-up release once the rollout
/// is complete. See [`TripleStorage::new`] for how the mirror is wired through
/// [`DistributedAssetStorage::new`]'s `legacy_col` parameter.
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
            Some(DBCol::Triple),
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

/// Rebuild [`DBCol::TripleV2`] from the legacy [`DBCol::Triple`] column.
///
/// `Triple` is the source of truth: the new binary mirrors every write/delete
/// to it via dual-write, and the old binary only knows about that column. So
/// at process startup we wipe `TripleV2` and re-populate it from whatever is
/// currently in `Triple`, bucketed under `[t as u64 BE]` prefixes derived from
/// each triple's own threshold. Legacy entries are left in place — a downgrade
/// to the previous binary still needs to see them.
///
/// Rebuilding (rather than incrementally migrating) is what keeps re-upgrade
/// after a downgrade safe: if the downgraded binary consumed triples — deleting
/// them from `Triple` but not `TripleV2` — naive incremental migration would
/// leave those stale entries in `TripleV2`, and the new binary would re-use
/// them in presign. With ECDSA that is a nonce-reuse hazard that leaks the
/// private key. Wiping `TripleV2` first drops any such orphans.
///
/// The whole rebuild commits in one atomic batch.
///
/// SAFETY: must be called before any [`TripleStorage`] is constructed for this
/// DB, and exactly once per process. The unconditional [`DBCol::TripleV2`]
/// wipe would race with a live `TripleStorage` (vending the same `UniqueId`
/// to two consumers across the wipe) — so this is invoked from `run.rs` right
/// after [`crate::db::SecretDB::new`], before the coordinator can construct
/// any provider. Do not call it from `EcdsaSignatureProvider::new` or any
/// other path that may run multiple times per process (e.g., across
/// coordinator Running ↔ Resharing transitions).
///
/// TODO(#3298): delete after 3.11 is out across the network.
pub fn migrate_legacy_triples_to_v2(db: &Arc<SecretDB>) -> anyhow::Result<usize> {
    let mut migrated = 0usize;
    let mut update = db.update();
    update.delete_all(DBCol::TripleV2)?;
    for item in db.iter_all(DBCol::Triple) {
        let (legacy_key, value_ser) = item?;
        let triple: PairedTriple = match serde_json::from_slice(&value_ser) {
            Ok(t) => t,
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "Skipping unparseable legacy triple row during migration"
                );
                continue;
            }
        };
        // Both halves of a cait-sith paired triple are generated with the same
        // participant set, so either one yields the correct `t`.
        let threshold: u64 = triple.0.1.participants.len().try_into()?;
        let mut new_key = Vec::with_capacity(std::mem::size_of::<u64>() + legacy_key.len());
        new_key.extend_from_slice(&threshold.to_be_bytes());
        new_key.extend_from_slice(&legacy_key);
        update.put(DBCol::TripleV2, &new_key, &value_ser);
        migrated += 1;
    }
    update.commit()?;
    tracing::info!(
        migrated,
        "Rebuilt TripleV2 from legacy Triple column on startup"
    );
    Ok(migrated)
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
        mpc_config: Arc<MpcConfig>,
        config: Arc<TripleConfig>,
        triple_store: Arc<TripleStorage>,
        threshold: ReconstructionLowerBound,
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
            // TODO(#3164): once per-`t` background generation lands and runs
            // alongside this loop for other thresholds, these gauges will be
            // overwritten by whichever generator ticks last. Either lift the
            // updates into a single task that sums across `triple_stores`, or
            // add a `t` label so each store reports independently.
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
            threshold: ReconstructionLowerBound::from(threshold_usize),
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
    pub threshold: ReconstructionLowerBound,
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
    pub threshold: ReconstructionLowerBound,
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
        migrate_legacy_triples_to_v2,
    };
    use crate::assets::test_utils::{legacy_triple_key, make_triple, triple_v2_key};
    use crate::db::{DBCol, SecretDB};
    use crate::network::computation::MpcLeaderCentricComputation;
    use crate::network::testing::run_test_clients;
    use crate::network::{MeshNetworkClient, NetworkTaskChannel};
    use crate::primitives::{MpcTaskId, ParticipantId, UniqueId};
    use crate::providers::ecdsa::EcdsaTaskId;
    use crate::tests::into_participant_ids;
    use crate::tracking;
    use futures::{FutureExt, StreamExt, stream};
    use std::collections::HashMap;
    use std::sync::Arc;
    use threshold_signatures::ReconstructionLowerBound;
    use threshold_signatures::test_utils::generate_participants;
    use tokio::sync::mpsc;

    const NUM_PARTICIPANTS: usize = 4;
    const THRESHOLD: usize = 3;
    const PARALLELISM_PER_CLIENT: usize = 4;
    const TRIPLES_PER_BATCH: usize = 10;
    const BATCHES_TO_GENERATE_PER_CLIENT: usize = 10;

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
                            threshold: ReconstructionLowerBound::from(THRESHOLD),
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
                            threshold: ReconstructionLowerBound::from(THRESHOLD),
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

    fn write_legacy_triple(db: &Arc<SecretDB>, id: UniqueId, triple: &PairedTriple) {
        let value = serde_json::to_vec(triple).unwrap();
        let mut update = db.update();
        update.put(DBCol::Triple, &legacy_triple_key(id), &value);
        update.commit().unwrap();
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

    /// Returns the `t` (Shamir degree + 1) baked into a triple's public part.
    fn triple_threshold(triple: &PairedTriple) -> ReconstructionThreshold {
        ReconstructionThreshold::new(triple.0.1.participants.len() as u64)
    }

    /// Snapshot test pinning the on-disk DB key layout for the triple stores.
    ///
    /// The exact byte layout is load-bearing for the dual-write / migration
    /// dance (#3298): the new binary writes both columns, and a downgraded
    /// binary must be able to read what we wrote. Any drift in how
    /// `ReconstructionThreshold` or `UniqueId` serialize would silently break
    /// that compatibility. The snapshot makes the layout an explicit, reviewed
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
        let legacy_key = legacy_triple_key(id);

        insta::assert_snapshot!(format!(
            "v2_key:     {}\nlegacy_key: {}",
            hex::encode(&v2_key),
            hex::encode(&legacy_key),
        ));
    }

    #[test]
    #[expect(non_snake_case)]
    fn migrate_legacy_triples_to_v2__should_bucket_legacy_entries_by_t() {
        // Given a DB with two legacy triples, each carrying a different `t`.
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let me = ParticipantId::from_raw(42);
        let participants_3 = vec![me, ParticipantId::from_raw(1), ParticipantId::from_raw(2)];
        let participants_4 = vec![
            me,
            ParticipantId::from_raw(1),
            ParticipantId::from_raw(2),
            ParticipantId::from_raw(3),
        ];
        let id_a = UniqueId::new(me, 100, 0);
        let id_b = UniqueId::new(me, 100, 1);
        let t3 = ReconstructionThreshold::new(3);
        let t4 = ReconstructionThreshold::new(4);
        let triple_t3 = make_triple(&participants_3);
        let triple_t4 = make_triple(&participants_4);
        assert_eq!(triple_threshold(&triple_t3), t3);
        assert_eq!(triple_threshold(&triple_t4), t4);
        write_legacy_triple(&db, id_a, &triple_t3);
        write_legacy_triple(&db, id_b, &triple_t4);

        // When the migration runs.
        let migrated = migrate_legacy_triples_to_v2(&db).unwrap();

        // Then each legacy entry appears in TripleV2 under its `t` prefix, and
        // the legacy entries are still present (downgrade-safe).
        assert_eq!(migrated, 2);
        assert!(
            db.get(DBCol::TripleV2, &triple_v2_key(t3, id_a))
                .unwrap()
                .is_some()
        );
        assert!(
            db.get(DBCol::TripleV2, &triple_v2_key(t4, id_b))
                .unwrap()
                .is_some()
        );
        assert!(
            db.get(DBCol::Triple, &legacy_triple_key(id_a))
                .unwrap()
                .is_some()
        );
        assert!(
            db.get(DBCol::Triple, &legacy_triple_key(id_b))
                .unwrap()
                .is_some()
        );

        // And the per-`t` store surfaces only the matching triples.
        let store_t3 = new_triple_store(db.clone(), me, t3, participants_3.clone());
        let store_t4 = new_triple_store(db.clone(), me, t4, participants_4.clone());
        assert_eq!(store_t3.num_owned(), 1);
        assert_eq!(store_t4.num_owned(), 1);
    }

    #[test]
    #[expect(non_snake_case)]
    fn migrate_legacy_triples_to_v2__should_be_idempotent_with_no_legacy_entries() {
        // Given a DB with only new-format (per-`t`) triple rows.
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let me = ParticipantId::from_raw(42);
        let participants = vec![me];
        let t1 = ReconstructionThreshold::new(1);
        let store = new_triple_store(db.clone(), me, t1, participants.clone());
        store.add_owned(store.generate_and_reserve_id(), make_triple(&participants));
        // `store.add_owned` also dual-writes to DBCol::Triple. The migration
        // will rewrite that row idempotently.
        let migrated_count = migrate_legacy_triples_to_v2(&db).unwrap();

        // When/Then: the migration is harmless and the store still has its one triple.
        assert_eq!(migrated_count, 1);
        let store = new_triple_store(db, me, t1, participants);
        assert_eq!(store.num_owned(), 1);
    }

    #[test]
    #[expect(non_snake_case)]
    fn migrate_legacy_triples_to_v2__should_drop_orphans_left_by_downgrade() {
        // Given a DB where `TripleV2` carries an entry that `Triple` no longer
        // has — the exact shape a downgraded binary would leave behind after
        // consuming a triple (deleting from `Triple`, unaware of `TripleV2`).
        // Reusing that triple post re-upgrade would be a nonce-reuse hazard.
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let me = ParticipantId::from_raw(42);
        let participants = vec![me, ParticipantId::from_raw(1), ParticipantId::from_raw(2)];
        let stale_id = UniqueId::new(me, 100, 0);
        let stale_triple = make_triple(&participants);
        let mut update = db.update();
        update.put(
            DBCol::TripleV2,
            &triple_v2_key(triple_threshold(&stale_triple), stale_id),
            &serde_json::to_vec(&stale_triple).unwrap(),
        );
        update.commit().unwrap();

        // When the migration runs.
        let migrated = migrate_legacy_triples_to_v2(&db).unwrap();

        // Then `TripleV2` is rebuilt from `Triple` (empty), and the orphan is
        // gone — the per-`t` store surfaces nothing.
        assert_eq!(migrated, 0);
        let store = new_triple_store(db, me, triple_threshold(&stale_triple), participants);
        assert_eq!(store.num_owned(), 0);
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
    fn triple_storage_add_owned__should_dual_write_to_legacy_column() {
        // Given a TripleStorage configured with legacy mirroring.
        let dir = tempfile::tempdir().unwrap();
        let db = SecretDB::new(dir.path(), [1; 16]).unwrap();
        let me = ParticipantId::from_raw(42);
        let participants = vec![me];
        let t = ReconstructionThreshold::new(3);
        let store = new_triple_store(db.clone(), me, t, participants.clone());
        let id = store.generate_and_reserve_id();

        // When adding an owned triple.
        store.add_owned(id, make_triple(&participants));

        // Then both columns contain the same value.
        let v2 = db.get(DBCol::TripleV2, &triple_v2_key(t, id)).unwrap();
        let legacy = db.get(DBCol::Triple, &legacy_triple_key(id)).unwrap();
        assert!(v2.is_some());
        assert!(legacy.is_some());
        assert_eq!(v2, legacy);
    }

    #[test]
    #[expect(non_snake_case)]
    fn triple_storage_take_owned__should_delete_from_both_columns() {
        // Given a triple present in both columns via dual-write.
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

        // Then it is gone from both columns.
        assert!(
            db.get(DBCol::TripleV2, &triple_v2_key(t, id))
                .unwrap()
                .is_none()
        );
        assert!(
            db.get(DBCol::Triple, &legacy_triple_key(id))
                .unwrap()
                .is_none()
        );
    }
}
