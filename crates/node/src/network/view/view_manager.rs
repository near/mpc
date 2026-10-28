// todo: clean this file

use std::collections::BTreeSet;
use std::time::Duration;

use near_mpc_bounded_collections::NonEmptyBTreeSet;
use tokio::sync::{mpsc, watch};

use crate::{
    network::view::{
        network_link_latency::{
            BlockHeightInfoError, ConnectedPeersInfoError, NetworkIndexerBlockHeights,
            NetworkIndexerBlockHeightsReport,
        },
        primitives::{BrokenNetworkConnections, PreviousViewValidity},
    },
    primitives::{ConnectedPeersInfo, ParticipantId, PeerConnectedPeersInfo},
};

// todo: think about how to make these better

pub enum NetworkViewUpdate {
    ConnectedPeersInfo(PeerConnectedPeersInfo),
    /// A participant's own indexer height: ours from the indexer, a legacy peer's from its
    /// `IndexerHeight` message.
    IndexerHeight {
        participant: ParticipantId,
        height: u64,
    },
    // disconnectedpeers??
    /// The participants the transport is bidirectionally connected to.
    ConnectedPeers(BTreeSet<ParticipantId>),
}

pub struct NetworkViewManager {
    // todo: add bidirectionally connected views...
    // transport_view: T,
    all_participants: NonEmptyBTreeSet<ParticipantId>,
    offline_participants: BTreeSet<ParticipantId>,

    indexer_block_heights: NetworkIndexerBlockHeights,

    // everything we receive from other components
    observations: mpsc::Receiver<NetworkViewUpdate>,
    connected_peers_info_receiver: watch::Receiver<ConnectedPeersInfo>,

    // everything we send to other components
    /// as soon as a link or participant changes its status, this is updated
    broken: watch::Sender<OfflineParticipantView>,
    /// update every report_interval
    link_reports: watch::Sender<NetworkIndexerBlockHeightsReport>,
    // todo: should this be a near_time::Duration?
    report_interval: Duration,
}

impl NetworkViewManager {
    pub async fn run(mut self) {
        let mut tick = tokio::time::interval(self.report_interval);
        loop {
            // todo: handle cancellation / dropping
            tokio::select! {
                Some(o) = self.observations.recv() => {
                    if let Err(err) = self.apply(o) {
                        tracing::error!(?err, "could not apply network view update");
                    }
                }
                Ok(()) = self.connected_peers_info_receiver.changed() => {
                    // todo: fold our own ConnectedPeersInfo into the view.
                }
                _ = tick.tick() => {
                    self.link_reports.send_replace(self.indexer_block_heights.generate_report());
                }
                else => break,
            }
        }
    }
    fn apply(&mut self, update: NetworkViewUpdate) -> Result<(), NetworkViewUpdateError> {
        let validity = match update {
            NetworkViewUpdate::ConnectedPeersInfo(info) => {
                self.indexer_block_heights.update_with(info)?
            }
            NetworkViewUpdate::IndexerHeight {
                participant,
                height,
            } => {
                self.indexer_block_heights
                    .update_first_hand(participant, height.into())?;
                PreviousViewValidity::Valid
            }
            NetworkViewUpdate::ConnectedPeers(connected) => {
                let offline: BTreeSet<ParticipantId> = self
                    .all_participants
                    .difference(&connected)
                    .copied()
                    .collect();
                if offline == self.offline_participants {
                    PreviousViewValidity::Valid
                } else {
                    self.offline_participants = offline;
                    PreviousViewValidity::Superseded
                }
            }
        };
        if validity == PreviousViewValidity::Superseded {
            self.publish_offline_view();
        }
        Ok(())
    }
    fn publish_offline_view(&self) {
        self.broken.send_replace(OfflineParticipantView {
            offline_peers: self.offline_participants.clone(),
            offline_links: self.indexer_block_heights.broken_connections(),
        });
    }
}

// todo: implement NetworkAPIForRequests on top of this.
pub struct OfflineParticipantView {
    // peers we don't have a connection to.
    pub offline_peers: BTreeSet<ParticipantId>,
    // links between peers that are offline or very slow.
    pub offline_links: BrokenNetworkConnections<ParticipantId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NetworkViewUpdateError {
    #[error(transparent)]
    ConnectedPeersInfo(#[from] ConnectedPeersInfoError),
    #[error(transparent)]
    BlockHeightInfo(#[from] BlockHeightInfoError),
}
