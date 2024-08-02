use std::collections::HashMap;
use std::time::{Duration, Instant};

use cait_sith::protocol::Participant;
use tokio::sync::RwLock;
use url::Url;

use crate::protocol::contract::primitives::Participants;
use crate::protocol::ProtocolState;
use crate::web::StateView;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

// TODO: this is a basic connection pool and does not do most of the work yet. This is
//       mostly here just to facilitate offline node handling for now.
// TODO/NOTE: we can use libp2p to facilitate most the of low level TCP connection work.
#[derive(Default)]
pub struct Pool {
    http: reqwest::Client,
    connections: RwLock<Participants>,
    potential_connections: RwLock<Participants>,
    status: RwLock<HashMap<Participant, StateView>>,

    /// The currently active participants for this epoch.
    current_active: RwLock<Option<(Participants, Instant)>>,
    // Potentially active participants that we can use to establish a connection in the next epoch.
    potential_active: RwLock<Option<(Participants, Instant)>>,
}

impl Pool {
    pub async fn ping(&self) -> Participants {
        if let Some((ref active, timestamp)) = *self.current_active.read().await {
            if timestamp.elapsed() < DEFAULT_TIMEOUT {
                return active.clone();
            }
        }

        let connections = self.connections.read().await;

        let mut status = self.status.write().await;
        let mut participants = Participants::default();
        for (participant, info) in connections.iter() {
            let Ok(Ok(url)) = Url::parse(&info.url).map(|url| url.join("/state")) else {
                tracing::error!(
                    "Pool.ping url is invalid participant {:?} url {} /state",
                    participant,
                    info.url
                );
                continue;
            };

            let Ok(resp) = self.http.get(url.clone()).send().await else {
                tracing::warn!(
                    "Pool.ping resp err participant {:?} url {}",
                    participant,
                    url
                );
                continue;
            };

            let Ok(state): Result<StateView, _> = resp.json().await else {
                tracing::warn!(
                    "Pool.ping state view err participant {:?} url {}",
                    participant,
                    url
                );
                continue;
            };

            status.insert(*participant, state);
            participants.insert(participant, info.clone());
        }
        drop(status);

        let mut active = self.current_active.write().await;
        *active = Some((participants.clone(), Instant::now()));
        participants
    }

    pub async fn ping_potential(&self) -> Participants {
        if let Some((ref active, timestamp)) = *self.potential_active.read().await {
            if timestamp.elapsed() < DEFAULT_TIMEOUT {
                return active.clone();
            }
        }

        let connections = self.potential_connections.read().await;

        let mut status = self.status.write().await;
        let mut participants = Participants::default();
        for (participant, info) in connections.iter() {
            let Ok(Ok(url)) = Url::parse(&info.url).map(|url| url.join("/state")) else {
                continue;
            };

            let Ok(resp) = self.http.get(url).send().await else {
                continue;
            };

            let Ok(state): Result<StateView, _> = resp.json().await else {
                continue;
            };

            status.insert(*participant, state);
            participants.insert(participant, info.clone());
        }
        drop(status);

        let mut potential_active = self.potential_active.write().await;
        *potential_active = Some((participants.clone(), Instant::now()));
        participants
    }

    pub async fn establish_participants(&self, contract_state: &ProtocolState) {
        match contract_state {
            ProtocolState::Initializing(contract_state) => {
                let participants: Participants = contract_state.candidates.clone().into();
                self.set_participants(&participants).await;
            }
            ProtocolState::Running(contract_state) => {
                self.set_participants(&contract_state.participants).await;
            }
            ProtocolState::Resharing(contract_state) => {
                self.set_participants(&contract_state.old_participants)
                    .await;
                self.set_potential_participants(&contract_state.new_participants)
                    .await;
            }
        }
        tracing::debug!(
            "Pool.establish_participants set participants to {:?}",
            self.connections.read().await.clone().keys_vec()
        );
    }

    async fn set_participants(&self, participants: &Participants) {
        *self.connections.write().await = participants.clone();
    }

    async fn set_potential_participants(&self, participants: &Participants) {
        *self.potential_connections.write().await = participants.clone();
    }

    pub async fn potential_participants(&self) -> Participants {
        self.potential_connections.read().await.clone()
    }

    pub async fn is_participant_stable(&self, participant: &Participant) -> bool {
        self.status
            .read()
            .await
            .get(participant)
            .map_or(false, |state| match state {
                StateView::Running { is_stable, .. } => *is_stable,
                _ => false,
            })
    }
}
