use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
};

use near_block_primitives::BlockCount;
use rand::seq::SliceRandom;
use tokio::sync::watch;

use crate::{
    assets::{AliveCheckError, CheckParticipantsAlive},
    network::{
        ReadFirstHandIndexerHeights,
        view::{
            network_link_latency::FirstHandHeight,
            primitives::{
                AdjacencyMatrixError, MeasuredNetworkConnectionsError, Uptime,
                UsableNetworkConnections,
            },
        },
    },
    primitives::ParticipantId,
    providers::{SelectParticipants, SelectParticipantsError},
    requests::queue::NetworkAPIForRequests,
};

/// The network view from this node's standpoint: the only place `me` meets the view.
pub struct LocalNetworkView {
    me: ParticipantId,
    connections: watch::Receiver<Arc<UsableNetworkConnections<ParticipantId>>>,
    heights: watch::Receiver<BTreeMap<ParticipantId, FirstHandHeight>>,
}

impl LocalNetworkView {
    pub fn new(
        me: ParticipantId,
        connections: watch::Receiver<Arc<UsableNetworkConnections<ParticipantId>>>,
        heights: watch::Receiver<BTreeMap<ParticipantId, FirstHandHeight>>,
    ) -> Self {
        Self {
            me,
            connections,
            heights,
        }
    }

    fn connections(&self) -> Arc<UsableNetworkConnections<ParticipantId>> {
        self.connections.borrow().clone()
    }

    /// Us, plus every participant we have a connection with of at least `required_uptime` that
    /// is not behind us.
    fn alive(&self, required_uptime: Uptime) -> BTreeSet<ParticipantId> {
        let heights = self.heights.borrow();
        let height_of = |participant: &ParticipantId| {
            heights
                .get(participant)
                .copied()
                .unwrap_or(FirstHandHeight::Unknown)
        };
        let my_height = height_of(&self.me);
        let mut alive: BTreeSet<ParticipantId> = self
            .connections()
            .usable_from(&self.me, required_uptime)
            .unwrap_or_default()
            .into_iter()
            .filter(|participant| not_behind(my_height, height_of(participant)))
            .collect();
        alive.insert(self.me);
        alive
    }
}

/// An unknown own height disables the filter; an unknown peer height fails it.
fn not_behind(my_height: FirstHandHeight, peer_height: FirstHandHeight) -> bool {
    match (my_height, peer_height) {
        (FirstHandHeight::Unknown, _) => true,
        (FirstHandHeight::Known(_), FirstHandHeight::Unknown) => false,
        (FirstHandHeight::Known(mine), FirstHandHeight::Known(peer)) => {
            mine <= peer.saturating_add(BlockCount::from(mpc_node_config::MAX_INDEXER_HEIGHT_DIFF))
        }
    }
}

impl NetworkAPIForRequests for LocalNetworkView {
    fn alive_participants(&self) -> HashSet<ParticipantId> {
        self.alive(Uptime::Any).into_iter().collect()
    }

    fn indexer_heights(&self) -> HashMap<ParticipantId, u64> {
        self.heights
            .borrow()
            .iter()
            .map(|(participant, height)| (*participant, u64::from(*height)))
            .collect()
    }
}

impl SelectParticipants for LocalNetworkView {
    /// Draws at random so that no fixed subset carries every computation.
    fn select_participants(
        &self,
        total: usize,
        candidates: &[ParticipantId],
        required_uptime: Uptime,
    ) -> Result<Vec<ParticipantId>, SelectParticipantsError> {
        let connections = self.connections();
        let alive = self.alive(required_uptime);
        let mut candidates: Vec<ParticipantId> = candidates
            .iter()
            .copied()
            .filter(|candidate| *candidate != self.me && alive.contains(candidate))
            .collect();
        candidates.shuffle(&mut rand::thread_rng());

        let mut chosen = vec![self.me];
        for candidate in candidates {
            if chosen.len() == total {
                break;
            }
            if chosen
                .iter()
                .all(|member| connections.are_connected(member, &candidate, required_uptime))
            {
                chosen.push(candidate);
            }
        }
        if chosen.len() < total {
            return Err(SelectParticipantsError::NotEnoughParticipants {
                needed: total,
                available: chosen.len(),
            });
        }
        Ok(chosen)
    }
}

impl CheckParticipantsAlive for LocalNetworkView {
    fn check_alive(
        &self,
        participants: &BTreeSet<ParticipantId>,
        required_uptime: Uptime,
    ) -> Result<(), AliveCheckError> {
        let alive = self.alive(required_uptime);
        if let Some(participant) = participants.iter().find(|p| !alive.contains(p)) {
            return Err(AliveCheckError::NotAlive(*participant));
        }
        self.connections()
            .can_compute_with(participants, required_uptime)
            .map_err(|error| match error {
                MeasuredNetworkConnectionsError::BrokenConnection(p, q) => {
                    AliveCheckError::Unreachable(p, q)
                }
                MeasuredNetworkConnectionsError::Participants(
                    AdjacencyMatrixError::UnknownNode(p) | AdjacencyMatrixError::Loop(p),
                ) => AliveCheckError::NotAlive(p),
            })
    }
}

impl ReadFirstHandIndexerHeights for LocalNetworkView {
    fn first_hand_indexer_heights_of(
        &self,
        peers: impl IntoIterator<Item = ParticipantId>,
    ) -> BTreeMap<ParticipantId, FirstHandHeight> {
        let heights = self.heights.borrow();
        peers
            .into_iter()
            .filter_map(|peer| heights.get(&peer).map(|height| (peer, *height)))
            .collect()
    }
}
