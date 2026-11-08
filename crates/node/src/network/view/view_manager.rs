// todo: clean this file

use std::{collections::BTreeMap, sync::Arc};

use near_mpc_bounded_collections::NonEmptyBTreeSet;
use near_time::{Clock, Duration};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::{
    network::{
        constants::{NETWORK_VIEW_UPDATES_BUFFERED_PER_PARTICIPANT, RECENT_DELAY_SAMPLES},
        view::{
            local_network_view::LocalNetworkView,
            network_link_latency::{
                FirstHandHeight, LinkHealth, NetworkIndexerBlockHeights, NetworkViewUpdateError,
            },
            primitives::{LinkReport, PreviousViewValidity, UsableNetworkConnections},
        },
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

pub struct NetworkViewHandles {
    pub local_view: LocalNetworkView,
    pub updates: mpsc::Sender<NetworkViewUpdate>,
    pub link_reports: watch::Receiver<LinkReport<ParticipantId, LinkHealth>>,
}

/// The manager runs until `cancellation_token` is cancelled or every `updates` sender is gone.
pub fn run_network_view_manager(
    me: ParticipantId,
    participants: &NonEmptyBTreeSet<ParticipantId>,
    report_interval: Duration,
    clock: Clock,
    cancellation_token: CancellationToken,
) -> NetworkViewHandles {
    let indexer_block_heights = NetworkIndexerBlockHeights::new(participants, RECENT_DELAY_SAMPLES);
    let (updates, observations) = mpsc::channel(update_buffer_size(participants.len()));
    let (connections, connections_receiver) =
        watch::channel(Arc::new(indexer_block_heights.usable_connections()));
    let (heights, heights_receiver) = watch::channel(indexer_block_heights.first_hand_heights());
    let (link_reports, link_reports_receiver) =
        watch::channel(indexer_block_heights.link_report(clock.now()));
    let manager = NetworkViewManager {
        indexer_block_heights,
        observations,
        connections,
        heights,
        link_reports,
        report_interval,
        clock,
    };
    tokio::spawn(manager.run(cancellation_token));
    NetworkViewHandles {
        local_view: LocalNetworkView::new(me, connections_receiver, heights_receiver),
        updates,
        link_reports: link_reports_receiver,
    }
}

fn update_buffer_size(participants: usize) -> usize {
    participants
        .saturating_mul(NETWORK_VIEW_UPDATES_BUFFERED_PER_PARTICIPANT)
        .max(1)
}

struct NetworkViewManager {
    // todo: add bidirectionally connected views...
    // transport_view: T,
    indexer_block_heights: NetworkIndexerBlockHeights,

    // everything we receive from other components
    observations: mpsc::Receiver<NetworkViewUpdate>,

    // everything we send to other components
    /// as soon as a connection changes its status, this is updated
    connections: watch::Sender<Arc<UsableNetworkConnections<ParticipantId>>>,
    /// updated on every height update
    heights: watch::Sender<BTreeMap<ParticipantId, FirstHandHeight>>,
    /// update every report_interval
    // todo: metrics task on this watch: mean lag and uptime per link, status per pair, as gauges,
    // to learn the healthy lag distribution and its tail
    link_reports: watch::Sender<LinkReport<ParticipantId, LinkHealth>>,
    report_interval: Duration,
    clock: Clock,
}

impl NetworkViewManager {
    async fn run(mut self, cancellation_token: CancellationToken) {
        let mut tick = tokio::time::interval(self.report_interval.unsigned_abs());
        loop {
            tokio::select! {
                _ = cancellation_token.cancelled() => break,
                update = self.observations.recv() => {
                    // a closed channel never reopens: senders can only be cloned from one another
                    let Some(update) = update else {
                        break;
                    };
                    if let Err(err) = self.apply(update) {
                        tracing::error!(?err, "could not apply network view update");
                    }
                }
                _ = tick.tick() => {
                    self.link_reports
                        .send_replace(self.indexer_block_heights.link_report(self.clock.now()));
                }
            }
        }
    }
    fn apply(&mut self, update: NetworkViewUpdate) -> Result<(), NetworkViewUpdateError> {
        let validity = match update {
            NetworkViewUpdate::ConnectedPeersInfo(info) => self
                .indexer_block_heights
                .update_with(info, self.clock.now())?,
            NetworkViewUpdate::IndexerHeight {
                participant,
                height,
            } => {
                self.indexer_block_heights
                    .update_first_hand(participant, height)?;
                PreviousViewValidity::Valid
            }
        };
        self.heights
            .send_replace(self.indexer_block_heights.first_hand_heights());
        if validity == PreviousViewValidity::Superseded {
            self.connections
                .send_replace(Arc::new(self.indexer_block_heights.usable_connections()));
        }
        Ok(())
    }
}
