// todo: clean this file

use std::time::Duration;

use tokio::sync::{mpsc, watch};

use crate::{
    network::view::{
        network_link_latency::{
            NetworkIndexerBlockHeights, NetworkIndexerBlockHeightsReport, NetworkViewUpdateError,
        },
        primitives::{PreviousViewValidity, UsableNetworkConnections},
    },
    primitives::{ParticipantId, PeerConnectedPeersInfo},
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
}

pub struct NetworkViewManager {
    // todo: add bidirectionally connected views...
    // transport_view: T,
    indexer_block_heights: NetworkIndexerBlockHeights,

    // everything we receive from other components
    observations: mpsc::Receiver<NetworkViewUpdate>,

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
                    .update_first_hand(participant, height)?;
                PreviousViewValidity::Valid
            }
        };
        if validity == PreviousViewValidity::Superseded {
            self.publish_offline_view();
        }
        Ok(())
    }
    fn publish_offline_view(&self) {
        self.broken.send_replace(OfflineParticipantView {
            connections: self.indexer_block_heights.usable_connections(),
        });
    }
}

// todo: implement NetworkAPIForRequests on top of this.
pub struct OfflineParticipantView {
    pub connections: UsableNetworkConnections<ParticipantId>,
}
