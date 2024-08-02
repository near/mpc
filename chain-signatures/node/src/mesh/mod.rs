use crate::protocol::contract::primitives::Participants;
use crate::protocol::ProtocolState;

pub mod connection;

#[derive(Default)]
pub struct Mesh {
    /// Pool of connections to participants. Used to check who is alive in the network.
    pub connections: connection::Pool,

    /// Participants that are active at the beginning of each protocol loop.
    pub active_participants: Participants,

    /// Potential participants that are active at the beginning of each protocol loop. This
    /// includes participants belonging to the next epoch.
    pub active_potential_participants: Participants,
}

impl Mesh {
    /// Participants that are active at the beginning of each protocol loop.
    pub fn active_participants(&self) -> &Participants {
        &self.active_participants
    }

    /// Potential participants that are active at the beginning of each protocol loop. This will
    /// be empty if not in resharing state for the protocol
    pub fn active_potential_participants(&self) -> &Participants {
        &self.active_potential_participants
    }

    /// Get all pontential participants, but they may not necessarily be active.
    pub async fn potential_participants(&self) -> Participants {
        self.connections.potential_participants().await
    }

    pub fn all_active_participants(&self) -> Participants {
        let mut participants = self.active_participants.clone();
        let active = self.active_potential_participants.keys_vec();
        tracing::info!(?active, "Getting potentially active participants");
        for (participant, info) in self.active_potential_participants.iter() {
            if !participants.contains_key(participant) {
                participants.insert(participant, info.clone());
            }
        }
        participants
    }

    /// Get active participants that have a stable connection. This is useful for arbitrary metrics to
    /// say whether or not a node is stable, such as a node being on track with the latest block height.
    ///
    /// NOTE: ping() will also ping our own node since everyone, including us, is stored in the contract state
    /// or `ProtocolState`, which eventually leads to checking our own stablitity.
    pub async fn stable_participants(&self) -> Participants {
        let mut stable = Participants::default();
        for (participant, info) in self.active_participants().iter() {
            if self.connections.is_participant_stable(participant).await {
                stable.insert(participant, info.clone());
            }
        }
        stable
    }

    pub async fn establish_participants(&mut self, contract_state: &ProtocolState) {
        self.connections
            .establish_participants(contract_state)
            .await;
        self.ping().await;

        tracing::debug!(
            active = ?self.active_participants.keys_vec(),
            active_potential = ?self.active_potential_participants.keys_vec(),
            "mesh pinging",
        );
    }

    /// Ping the active participants such that we can see who is alive.
    pub async fn ping(&mut self) {
        self.active_participants = self.connections.ping().await;
        self.active_potential_participants = self.connections.ping_potential().await;
    }
}
