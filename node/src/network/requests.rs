use super::MeshNetworkClient;
use crate::primitives::ParticipantId;
use crate::queue::NetworkAPIForRequests;
use std::collections::{HashMap, HashSet};

impl NetworkAPIForRequests for MeshNetworkClient {
    fn alive_participants(&self) -> HashSet<ParticipantId> {
        self.all_alive_participant_ids().into_iter().collect()
    }

    fn indexer_heights(&self) -> HashMap<ParticipantId, u64> {
        self.get_indexer_heights()
    }
}
