use crate::primitives::ParticipantId;
use std::collections::{HashMap, HashSet};

/// Thin API that the queue needs from the network.
pub trait NetworkAPIForRequests: Send + Sync + 'static {
    /// Returns the participants that are currently connected to us.
    fn alive_participants(&self) -> HashSet<ParticipantId>;
    /// Returns the height of each indexer, including us. This must return all
    /// participants, even those who are never connected.
    fn indexer_heights(&self) -> HashMap<ParticipantId, u64>;
}
