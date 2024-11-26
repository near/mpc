use cait_sith::{protocol::Participant, triples::TripleGenerationOutput};
use k256::Secp256k1;

use crate::assets::{DistributedAssetStorage, PendingUnownedAsset, UniqueId};
use crate::config::TripleConfig;
use crate::network::MeshNetworkClient;
use crate::protocol::run_protocol;
use crate::{metrics, tracking};
use crate::{network::NetworkTaskChannel, primitives::ParticipantId};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use crate::db::{DBCol, SecretDB};
use crate::primitives::choose_random_participants;

/// Generates many cait-sith triples at once. This can significantly save the
/// *number* of network messages.
pub async fn run_many_triple_generation<const N: usize>(
    channel: NetworkTaskChannel,
    me: ParticipantId,
    threshold: usize,
) -> anyhow::Result<Vec<PairedTriple>> {
    assert_eq!(N % 2, 0, "Expected to generate even number of triples in a batch");
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
    assert_eq!(N, triples.len(), "Unexpected triples len: expected {}, got {}", N, triples.len());
    let iter = triples.into_iter();
    let pairs = iter.clone().step_by(2).zip(iter.skip(1).step_by(2));
    Ok(pairs.collect())
}

// pub type TripleStorage = DistributedAssetStorage<TripleGenerationOutput<Secp256k1>>;
pub type PairedTriple = (TripleGenerationOutput<Secp256k1>, TripleGenerationOutput<Secp256k1>);

pub(crate) struct TripleStorage {
    storage: DistributedAssetStorage<PairedTriple>,
    last_active_participant_ids: Vec<ParticipantId>
}

impl TripleStorage {
    pub fn new(
        db: Arc<SecretDB>,
        col: DBCol,
        my_participant_id: ParticipantId,
        all_participant_ids: Vec<ParticipantId>
    ) -> anyhow::Result<Self> {
        Ok(Self {
            storage: DistributedAssetStorage::<PairedTriple>::new(db, col, my_participant_id)?,
            last_active_participant_ids: all_participant_ids,
        })
    }


    #[allow(dead_code)]
    pub fn refresh_active_participants_ids(&mut self, participants: &Vec<ParticipantId>) -> anyhow::Result<()> {
        if participants == &self.last_active_participant_ids {
            return Ok(());
        }
        self.last_active_participant_ids = participants.clone();
        Ok(())
    }

    pub fn generate_and_reserve_id_range(&self, count: u32) -> UniqueId {
        self.storage.generate_and_reserve_id_range(count)
    }

    pub fn num_owned(&self) -> usize {
        self.storage.num_owned() * 2
    }

    pub async fn take_owned(&self) -> (UniqueId, PairedTriple) {
        self.storage.take_owned().await
    }

    /// Adds an owned asset to the storage.
    pub fn add_owned(&self, id: UniqueId, value: PairedTriple) {
        self.storage.add_owned(id, value)
    }

    pub fn prepare_unowned(&self, id: UniqueId) -> PendingUnownedAsset<PairedTriple> {
        self.storage.prepare_unowned(id)
    }

    pub async fn take_unowned(&self, id: UniqueId) -> anyhow::Result<PairedTriple> {
        self.storage.take_unowned(id).await
    }
}


pub const SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE: usize = 64;

/// Continuously runs triple generation in the background, using the number of threads
/// specified in the config, trying to maintain some number of available triples all the
/// time as specified in the config.
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
            let id_start = triple_store
                .generate_and_reserve_id_range(SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE as u32);
            let task_id = crate::primitives::MpcTaskId::ManyTriples {
                start: id_start,
                count: SUPPORTED_TRIPLE_GENERATION_BATCH_SIZE as u32,
            };
            let participants = choose_random_participants(client.all_alive_participant_ids(), client.my_participant_id(), threshold);
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

/// Tracks number of in-flight generations so we don't generate too many at the same time.
struct InFlightGenerationTracker {
    generations_in_flight: Arc<AtomicUsize>,
}

impl InFlightGenerationTracker {
    pub fn new() -> Self {
        Self {
            generations_in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn in_flight(&self, count: usize) -> InFlightGenerations {
        InFlightGenerations::new(self.generations_in_flight.clone(), count)
    }

    pub fn num_in_flight(&self) -> usize {
        self.generations_in_flight
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Drop guard to increment and decrement number of generations in flight.
struct InFlightGenerations {
    generations_in_flight: Arc<AtomicUsize>,
    count: usize,
}

impl InFlightGenerations {
    pub fn new(generations_in_flight: Arc<AtomicUsize>, count: usize) -> Self {
        generations_in_flight.fetch_add(count, std::sync::atomic::Ordering::Relaxed);
        Self {
            generations_in_flight,
            count,
        }
    }
}

impl Drop for InFlightGenerations {
    fn drop(&mut self) {
        self.generations_in_flight
            .fetch_sub(self.count, std::sync::atomic::Ordering::Relaxed);
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

    use super::{PairedTriple, run_many_triple_generation};
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
                    let participants = choose_random_participants(all_participant_ids, participant_id, THRESHOLD);
                    let result = tracking::spawn_checked(
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

#[cfg(test)]
mod network_research {
    use cait_sith::protocol::{Participant, Protocol};
    use k256::Secp256k1;
    use serde::Serialize;
    use std::collections::VecDeque;

    const NUM_PARTICIPANTS: usize = 10;
    const THRESHOLD: usize = 7;

    /// Simulates a network of participants doing a single triple generation,
    /// and writes out a file for the network communication statistics for each
    /// round of communication, which can be visualized in a tool.
    ///
    /// The difference between the best case and worst case is:
    /// - In the best case, in each round we have each participant receive as
    ///   many messages as possible before proceeding. This gives the minimum
    ///   possible number of rounds of communication that is absolutely
    ///   necessary.
    /// - In the worst case, in each round we have each participant receive only
    ///   as many messages as needed to make any progress. This gives some kind
    ///   of worst-case estimate, even though it's not the absolute worst (which
    ///   is kind of hard to define). It can result in many more rounds of
    ///   communication.
    #[test]
    fn triple_network_research_best_case() {
        let mut protocols = Vec::new();
        let participants = (0..NUM_PARTICIPANTS)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();
        for i in 0..NUM_PARTICIPANTS {
            protocols.push(
                cait_sith::triples::generate_triple_many::<Secp256k1, 4>(
                    &participants,
                    participants[i],
                    THRESHOLD,
                )
                .unwrap(),
            );
        }

        let mut steps = Vec::<NetworkStep>::new();
        let mut completed = [false; NUM_PARTICIPANTS];
        loop {
            if completed.iter().all(|&b| b) {
                break;
            }
            let mut p2p_messages_to_send =
                vec![vec![Vec::<Vec<u8>>::new(); NUM_PARTICIPANTS]; NUM_PARTICIPANTS];
            for i in 0..NUM_PARTICIPANTS {
                if completed[i] {
                    continue;
                }
                loop {
                    match protocols[i].poke().unwrap() {
                        cait_sith::protocol::Action::Wait => break,
                        cait_sith::protocol::Action::SendMany(vec) => {
                            for j in 0..NUM_PARTICIPANTS {
                                if i == j {
                                    continue;
                                }
                                p2p_messages_to_send[i][j].push(vec.clone());
                            }
                        }
                        cait_sith::protocol::Action::SendPrivate(participant, vec) => {
                            p2p_messages_to_send[i][u32::from(participant) as usize].push(vec);
                        }
                        cait_sith::protocol::Action::Return(_) => {
                            completed[i] = true;
                            break;
                        }
                    }
                }
            }

            let mut step = NetworkStep {
                peer_to_peer: Vec::new(),
            };
            for (i, messages) in p2p_messages_to_send.into_iter().enumerate() {
                let mut peer_messages = Vec::new();
                for (j, messages) in messages.into_iter().enumerate() {
                    for message in &messages {
                        protocols[j].message(Participant::from(i as u32), message.clone());
                    }
                    let num_messages = messages.len();
                    let total_bytes = messages.iter().map(|v| v.len()).sum();
                    peer_messages.push(PeerToPeerMessageStats {
                        num_messages,
                        total_bytes,
                    });
                }
                step.peer_to_peer.push(peer_messages);
            }
            steps.push(step);
        }
        let report = NetworkResearchReport {
            num_participants: NUM_PARTICIPANTS,
            steps,
        };
        std::fs::write(
            "triple_network_report_best_case.json",
            serde_json::to_string_pretty(&report).unwrap(),
        )
        .unwrap();
        eprintln!(
            "Report written to {}/triple_network_report_best_case.json",
            std::env::current_dir().unwrap().to_string_lossy()
        );
    }

    #[test]
    fn triple_network_research_worst_case() {
        let mut protocols = Vec::new();
        let participants = (0..NUM_PARTICIPANTS)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();
        for i in 0..NUM_PARTICIPANTS {
            protocols.push(
                cait_sith::triples::generate_triple_many::<Secp256k1, 4>(
                    &participants,
                    participants[i],
                    THRESHOLD,
                )
                .unwrap(),
            );
        }

        let mut steps = Vec::<NetworkStep>::new();
        let mut completed = [false; NUM_PARTICIPANTS];
        let mut p2p_messages_to_receive =
            vec![VecDeque::<(usize, Vec<u8>)>::new(); NUM_PARTICIPANTS];
        loop {
            if completed.iter().all(|&b| b) {
                break;
            }
            let mut p2p_messages_to_send =
                vec![vec![Vec::<Vec<u8>>::new(); NUM_PARTICIPANTS]; NUM_PARTICIPANTS];
            for i in 0..NUM_PARTICIPANTS {
                if completed[i] {
                    continue;
                }
                loop {
                    let mut made_progress = false;
                    loop {
                        match protocols[i].poke().unwrap() {
                            cait_sith::protocol::Action::Wait => break,
                            cait_sith::protocol::Action::SendMany(vec) => {
                                for j in 0..NUM_PARTICIPANTS {
                                    if i == j {
                                        continue;
                                    }
                                    p2p_messages_to_send[i][j].push(vec.clone());
                                    made_progress = true;
                                }
                            }
                            cait_sith::protocol::Action::SendPrivate(participant, vec) => {
                                p2p_messages_to_send[i][u32::from(participant) as usize].push(vec);
                                made_progress = true;
                            }
                            cait_sith::protocol::Action::Return(_) => {
                                completed[i] = true;
                                made_progress = true;
                                break;
                            }
                        }
                    }
                    if made_progress {
                        break;
                    }
                    if let Some((from, message)) = p2p_messages_to_receive[i].pop_front() {
                        protocols[i].message(Participant::from(from as u32), message);
                    } else {
                        break;
                    }
                }
            }

            let mut step = NetworkStep {
                peer_to_peer: Vec::new(),
            };
            for (i, messages) in p2p_messages_to_send.into_iter().enumerate() {
                let mut peer_messages = Vec::new();
                for (j, messages) in messages.into_iter().enumerate() {
                    for message in &messages {
                        p2p_messages_to_receive[j].push_back((i, message.clone()));
                    }
                    let num_messages = messages.len();
                    let total_bytes = messages.iter().map(|v| v.len()).sum();
                    peer_messages.push(PeerToPeerMessageStats {
                        num_messages,
                        total_bytes,
                    });
                }
                step.peer_to_peer.push(peer_messages);
            }
            steps.push(step);
        }
        let report = NetworkResearchReport {
            num_participants: NUM_PARTICIPANTS,
            steps,
        };
        std::fs::write(
            "triple_network_report_worst_case.json",
            serde_json::to_string_pretty(&report).unwrap(),
        )
        .unwrap();
        eprintln!(
            "Report written to {}/triple_network_report_worst_case.json",
            std::env::current_dir().unwrap().to_string_lossy()
        );
    }

    #[derive(Debug, Serialize)]
    struct NetworkResearchReport {
        num_participants: usize,
        steps: Vec<NetworkStep>,
    }

    #[derive(Debug, Serialize)]
    struct NetworkStep {
        peer_to_peer: Vec<Vec<PeerToPeerMessageStats>>,
    }

    #[derive(Debug, Serialize)]
    struct PeerToPeerMessageStats {
        num_messages: usize,
        total_bytes: usize,
    }
}
