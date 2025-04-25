use super::MeshNetworkClient;
use crate::primitives::ParticipantId;
use crate::signing::queue::NetworkAPIForSigning;
use std::collections::{HashMap, HashSet};

impl NetworkAPIForSigning for MeshNetworkClient {
    fn alive_participants(&self) -> HashSet<ParticipantId> {
        self.online_participants()
            .into_iter()
            .map(|(id, _)| id)
            .collect()
    }

    fn indexer_heights(&self) -> HashMap<ParticipantId, u64> {
        self.get_indexer_heights()
    }
}
