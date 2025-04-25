use super::types::{AssetQueueKey, ParticipantsWithSerials, QueueDesirability, QueueUsability};
use crate::asset_queues::covering::make_covering_randomly;
use crate::assets::UniqueId;
use crate::config::MpcConfig;
use crate::primitives::ParticipantId;
use rand::seq::IteratorRandom;
use rand::SeedableRng;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt::{Debug, Formatter};

pub(crate) struct AssetQueue<T> {
    items: VecDeque<(UniqueId, T)>,
    participants: ParticipantsWithSerials,
    key: AssetQueueKey,
    desirability: QueueDesirability,
}

impl<T> AssetQueue<T> {
    pub fn new(
        participants: ParticipantsWithSerials,
        initial_desirability: QueueDesirability,
    ) -> Self {
        Self {
            items: VecDeque::new(),
            key: participants.key(),
            participants,
            desirability: initial_desirability,
        }
    }

    pub fn participant_ids(&self) -> Vec<ParticipantId> {
        self.participants.participants.keys().copied().collect()
    }
}

pub struct AssetQueues<T> {
    all_participants: HashSet<ParticipantId>,
    threshold: usize,
    my_participant_id: ParticipantId,
    queues: Vec<AssetQueue<T>>,
    previous_online_participants: Option<ParticipantsWithSerials>,
}

pub enum AssetQueuesDBOperation<T> {
    CreateQueue {
        key: AssetQueueKey,
        participants: ParticipantsWithSerials,
    },
    DeleteQueue {
        key: AssetQueueKey,
    },
    DeleteAsset {
        queue_key: AssetQueueKey,
        asset_id: UniqueId,
    },
    AddAsset {
        queue_key: AssetQueueKey,
        asset_id: UniqueId,
        asset: T,
    },
}

impl<T: Clone> AssetQueues<T> {
    pub fn new(config: &MpcConfig) -> Self {
        let mut all_participants = HashSet::new();
        for participant in &config.participants.participants {
            all_participants.insert(participant.id);
        }
        let threshold = config.participants.threshold as usize;
        let queues = Vec::new();
        Self {
            queues,
            all_participants,
            threshold,
            my_participant_id: config.my_participant_id,
            previous_online_participants: None,
        }
    }

    pub fn add_queue_from_db(
        &mut self,
        participants: ParticipantsWithSerials,
        items: VecDeque<(UniqueId, T)>,
    ) {
        self.queues.push(AssetQueue {
            items,
            key: participants.key(),
            participants,
            desirability: QueueDesirability::Offline,
        });
    }

    pub fn set_online_participants(
        &mut self,
        online_participants: &ParticipantsWithSerials,
        ops: &mut Vec<AssetQueuesDBOperation<T>>,
    ) {
        if self.previous_online_participants.as_ref() == Some(online_participants) {
            // Computing the below is expensive, so if nothing changed, skip.
            return;
        }
        let desired_queues = Self::choose_desired_queues(
            online_participants,
            self.threshold,
            self.my_participant_id,
        );
        let mut desired_queues = desired_queues
            .into_iter()
            .map(|p| (p.key(), p))
            .collect::<BTreeMap<_, _>>();
        self.queues.retain_mut(|queue| {
            let usability = queue.participants.determine_usability(
                online_participants,
                &self.all_participants,
                self.threshold,
            );
            match usability {
                QueueUsability::Online => {
                    if desired_queues.remove(&queue.key).is_some() {
                        queue.desirability = QueueDesirability::OnlineAndDesirable;
                    } else {
                        queue.desirability = QueueDesirability::OnlineButUndesirable;
                    }
                    true
                }
                QueueUsability::Offline => {
                    queue.desirability = QueueDesirability::Offline;
                    true
                }
                QueueUsability::NoLongerUsable => {
                    for (id, _) in queue.items.iter() {
                        ops.push(AssetQueuesDBOperation::DeleteAsset {
                            queue_key: queue.key,
                            asset_id: *id,
                        });
                    }
                    ops.push(AssetQueuesDBOperation::DeleteQueue { key: queue.key });
                    false
                }
            }
        });

        // Add new queues that are now desired but previously non-existent.
        for (key, participants) in desired_queues {
            self.queues.push(AssetQueue::new(
                participants.clone(),
                QueueDesirability::OnlineAndDesirable,
            ));
            ops.push(AssetQueuesDBOperation::CreateQueue { key, participants });
        }

        self.previous_online_participants = Some(online_participants.clone());
    }

    /// Choose queues in a way that reasonably balances load between participants,
    /// while also trying to maximize the failure tolerance (the number of
    /// queues that are still online after some participants go offline).
    /// This function is deterministic. For the same inputs, it will always
    /// produce the same output.
    fn choose_desired_queues(
        online_participants: &ParticipantsWithSerials,
        threshold: usize,
        my_participant_id: ParticipantId,
    ) -> Vec<ParticipantsWithSerials> {
        let online_participants_list = online_participants
            .participants
            .iter()
            .map(|(id, serial)| (*id, *serial))
            .collect::<Vec<_>>();
        let my_participant_index = online_participants_list
            .iter()
            .position(|(id, _)| *id == my_participant_id)
            .expect("my_participant_id not found in online_participants");
        const MAX_DESIRED_QUEUES: usize = 50;
        let mut queues = Vec::new();
        // Seed the RNG with the participant ID so if there's any bias in the randomly
        // generated queues, it will not consistently be so across different nodes.
        let mut rng = rand_pcg::Pcg64::seed_from_u64(my_participant_id.raw() as u64);
        let covering = make_covering_randomly(
            &mut rng,
            online_participants.participants.len() - 1,
            threshold - 1,
            MAX_DESIRED_QUEUES,
        );

        for subset in covering {
            let mut participants = ParticipantsWithSerials::default();
            // Add myself, then count from there to add whichever is included in the subset.
            let myself = online_participants_list[my_participant_index];
            participants.participants.insert(myself.0, myself.1);
            for i in &subset {
                let participant = online_participants_list
                    [(my_participant_index + i + 1) % online_participants_list.len()];
                participants
                    .participants
                    .insert(participant.0, participant.1);
            }
            queues.push(participants);
        }
        queues
    }

    pub fn pick_queue_for_generation(&self) -> Option<(AssetQueueKey, Vec<ParticipantId>)> {
        // Choose a random queue that is online and desirable.
        // Why not pick the one with the smallest number of assets? Because this can lead to a
        // thundering herd situation where all parallel generations pick the same queue.
        // It's fine for generation to cause a bit uneven distribution of assets between the queues,
        // because we've still got the consumption path to help us balance them out.
        self.queues
            .iter()
            .filter(|queue| queue.desirability == QueueDesirability::OnlineAndDesirable)
            .choose(&mut rand::thread_rng())
            .map(|queue| (queue.key, queue.participant_ids()))
    }

    pub fn add_asset(
        &mut self,
        key: AssetQueueKey,
        asset_id: UniqueId,
        asset: T,
        ops: &mut Vec<AssetQueuesDBOperation<T>>,
    ) -> bool {
        if let Some(queue) = self.queues.iter_mut().find(|q| q.key == key) {
            ops.push(AssetQueuesDBOperation::AddAsset {
                queue_key: key,
                asset_id,
                asset: asset.clone(),
            });
            queue.items.push_back((asset_id, asset));
            true
        } else {
            false
        }
    }

    pub fn try_consume_asset(
        &mut self,
        ops: &mut Vec<AssetQueuesDBOperation<T>>,
    ) -> Option<(UniqueId, T)> {
        // Note: this loop iterates at most twice.
        loop {
            let best_queue = self
                .queues
                .iter_mut()
                .filter(|queue| {
                    queue.desirability == QueueDesirability::OnlineAndDesirable
                        || queue.desirability == QueueDesirability::OnlineButUndesirable
                })
                .max_by_key(|queue| {
                    let desirability_key =
                        if queue.desirability == QueueDesirability::OnlineButUndesirable {
                            1
                        } else {
                            0
                        };
                    (desirability_key, queue.items.len())
                })?;
            let item = best_queue.items.pop_front();
            let Some((asset_id, asset)) = item else {
                // If the queue is empty, there are two cases:
                //  - This is an undesirable queue that was already drained, meaning that all
                //    undesirable queues are empty (due to the sort above), so we should remove all
                //    undesirable queues and try again.
                //  - This is a desirable queue but we have no more assets left. So return None.
                if best_queue.desirability == QueueDesirability::OnlineButUndesirable {
                    self.queues.retain(|q| {
                        if q.desirability == QueueDesirability::OnlineButUndesirable {
                            ops.push(AssetQueuesDBOperation::DeleteQueue { key: q.key });
                            false
                        } else {
                            true
                        }
                    });
                    continue;
                } else {
                    return None;
                }
            };
            ops.push(AssetQueuesDBOperation::DeleteAsset {
                queue_key: best_queue.key,
                asset_id,
            });
            return Some((asset_id, asset));
        }
    }

    pub fn num_online_assets(&self) -> usize {
        self.queues
            .iter()
            .filter(|queue| {
                queue.desirability == QueueDesirability::OnlineAndDesirable
                    || queue.desirability == QueueDesirability::OnlineButUndesirable
            })
            .map(|queue| queue.items.len())
            .sum()
    }

    pub fn num_desirable_assets(&self) -> usize {
        self.queues
            .iter()
            .filter(|queue| queue.desirability == QueueDesirability::OnlineAndDesirable)
            .map(|queue| queue.items.len())
            .sum()
    }

    pub fn num_offline_assets(&self) -> usize {
        self.queues
            .iter()
            .filter(|queue| queue.desirability == QueueDesirability::Offline)
            .map(|queue| queue.items.len())
            .sum()
    }
}

impl<T: Clone> Debug for AssetQueues<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Total assets: {} desired; {} desired + online; {} offline",
            self.num_desirable_assets(),
            self.num_online_assets(),
            self.num_offline_assets()
        )?;
        writeln!(f, "Online participants:")?;
        if let Some(participants) = &self.previous_online_participants {
            for (id, serial) in &participants.participants {
                writeln!(f, "  {}: {}", id, serial)?;
            }
        } else {
            writeln!(f, "  (Not yet received)")?;
        }
        writeln!(f, "Queues:")?;
        for queue in &self.queues {
            writeln!(
                f,
                "  {:<9} {:>6} assets, participants: {:?}",
                match queue.desirability {
                    QueueDesirability::OnlineAndDesirable => "[DESIRED]",
                    QueueDesirability::OnlineButUndesirable => "[ONLINE]",
                    QueueDesirability::Offline => "[OFFLINE]",
                },
                queue.items.len(),
                queue
                    .participants
                    .participants
                    .iter()
                    .map(|(id, _)| id.raw())
                    .collect::<Vec<_>>()
            )?;
        }
        Ok(())
    }
}
