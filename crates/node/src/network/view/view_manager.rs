// todo: clean this file

use std::{collections::BTreeMap, sync::Arc};

use near_mpc_bounded_collections::NonEmptyBTreeSet;
use near_time::{Clock, Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::{
    network::{
        constants::{NETWORK_VIEW_UPDATES_BUFFERED_PER_PARTICIPANT, RECENT_DELAY_SAMPLES},
        view::{
            first_hand_indexer_heights::{FirstHandHeight, FirstHandIndexerHeights},
            local_network_view::LocalNetworkView,
            primitives::{
                AdjacencyMatrixError, LinkReport, PreviousViewValidity, UsableNetworkConnections,
            },
        },
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NetworkViewUpdateError {
    #[error("{0:?} is not a participant")]
    UnknownParticipant(ParticipantId),
    #[error("message from {0:?} does not report its own block height")]
    OwnHeightMissing(ParticipantId),
    #[error("a link needs two distinct participants, got {0:?} twice")]
    SelfLink(ParticipantId),
}

impl From<AdjacencyMatrixError<ParticipantId>> for NetworkViewUpdateError {
    fn from(error: AdjacencyMatrixError<ParticipantId>) -> Self {
        match error {
            AdjacencyMatrixError::UnknownNode(participant) => Self::UnknownParticipant(participant),
            AdjacencyMatrixError::Loop(participant) => Self::SelfLink(participant),
        }
    }
}

/// What a participant reports about the peers it is connected to: each with the indexer height
/// it has for that peer, itself included. The wire encodes an unknown height as `0`.
pub struct LocalPeerReport {
    pub reporter: ParticipantId,
    pub peers: BTreeMap<ParticipantId, u64>,
}

/// Turns participants' reports into connection statuses.
pub trait MeasureNetworkConnections {
    /// The per-link status this measurement infers; what the link report carries.
    type Link;

    fn record_report(
        &mut self,
        report: &LocalPeerReport,
        first_hand_heights: &FirstHandIndexerHeights,
        now: Instant,
    ) -> Result<PreviousViewValidity, NetworkViewUpdateError>;

    fn link_report(&self, now: Instant) -> LinkReport<ParticipantId, Self::Link>;

    fn usable_connections(&self) -> UsableNetworkConnections<ParticipantId>;
}

pub struct NetworkViewHandles<Link> {
    pub local_view: LocalNetworkView,
    pub updates: mpsc::Sender<NetworkViewUpdate>,
    pub link_reports: watch::Receiver<LinkReport<ParticipantId, Link>>,
}

/// The manager runs until `cancellation_token` is cancelled or every `updates` sender is gone.
pub fn run_network_view_manager<M>(
    me: ParticipantId,
    participants: &NonEmptyBTreeSet<ParticipantId>,
    measurement: M,
    report_interval: Duration,
    clock: Clock,
    cancellation_token: CancellationToken,
) -> NetworkViewHandles<M::Link>
where
    M: MeasureNetworkConnections + Send + 'static,
    M::Link: Send + Sync + 'static,
{
    let first_hand_heights = FirstHandIndexerHeights::new(participants);
    let (updates, observations) = mpsc::channel(update_buffer_size(participants.len()));
    let (connections, connections_receiver) =
        watch::channel(Arc::new(measurement.usable_connections()));
    let (heights, heights_receiver) = watch::channel(first_hand_heights.snapshot());
    let (link_reports, link_reports_receiver) =
        watch::channel(measurement.link_report(clock.now()));
    let manager = NetworkViewManager {
        first_hand_heights,
        measurement,
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

struct NetworkViewManager<M: MeasureNetworkConnections> {
    // todo: add bidirectionally connected views...
    // transport_view: T,
    first_hand_heights: FirstHandIndexerHeights,
    measurement: M,

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
    link_reports: watch::Sender<LinkReport<ParticipantId, M::Link>>,
    report_interval: Duration,
    clock: Clock,
}

impl<M: MeasureNetworkConnections> NetworkViewManager<M> {
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
                        .send_replace(self.measurement.link_report(self.clock.now()));
                }
            }
        }
    }
    fn apply(&mut self, update: NetworkViewUpdate) -> Result<(), NetworkViewUpdateError> {
        let validity = match update {
            NetworkViewUpdate::ConnectedPeersInfo(PeerConnectedPeersInfo {
                from: reporter,
                info: ConnectedPeersInfo { peers },
            }) => {
                let report = LocalPeerReport { reporter, peers };
                let own_height = *report
                    .peers
                    .get(&reporter)
                    .ok_or(NetworkViewUpdateError::OwnHeightMissing(reporter))?;
                self.first_hand_heights.record(reporter, own_height)?;
                self.measurement.record_report(
                    &report,
                    &self.first_hand_heights,
                    self.clock.now(),
                )?
            }
            NetworkViewUpdate::IndexerHeight {
                participant,
                height,
            } => {
                self.first_hand_heights.record(participant, height)?;
                PreviousViewValidity::Valid
            }
        };
        self.heights
            .send_replace(self.first_hand_heights.snapshot());
        if validity == PreviousViewValidity::Superseded {
            self.connections
                .send_replace(Arc::new(self.measurement.usable_connections()));
        }
        Ok(())
    }
}
