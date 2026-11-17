// todo: clean this file

use std::{hash::Hash, sync::Arc};

use near_mpc_bounded_collections::NonEmptyBTreeSet;
use near_time::{Clock, Duration};
use tokio::sync::{mpsc, watch};

use crate::network::connectivity::{
    errors::PeerReportError,
    first_hand_indexer_heights::FirstHandIndexerHeights,
    graph::UnknownNodeError,
    health::{
        ConnectionChanged, ConnectionTracker, EstablishedConnections, InferConnection,
        LinkStatuses, UpdateLinkStatus,
    },
    reports::{
        DeriveLinkObservations, IndexerHeightLag, IndexerHeightReport, ObservationContext,
        PeerReport,
    },
};

struct ConnectivityMonitor<N, C, S, L> {
    // state
    clock: Clock,
    report_interval: Duration,
    first_hand_heights: FirstHandIndexerHeights<N>,
    connection_tracker: ConnectionTracker<N, C, L>,

    // everything we receive from other components
    peer_reports: mpsc::Receiver<PeerReport<N>>,

    // everything we send to other components
    /// as soon as a connection changes its status, this is updated
    connections: watch::Sender<Arc<EstablishedConnections<N, C>>>,
    /// updated on every height update
    heights: watch::Sender<FirstHandIndexerHeights<N>>,

    /// update every report_interval
    // todo: metrics task on this watch: mean lag and uptime per link, status per pair, as gauges,
    // to learn the healthy lag distribution and its tail
    link_statuses: watch::Sender<LinkStatuses<N, S>>,
}

struct DebugConnectivityView<N, S> {
    link_statuses: watch::Receiver<Arc<LinkStatuses<N, S>>>,
}

//impl<N, C, S, L> ConnectivityMonitor<N, C, S, L>
//where
//    N: Ord + Clone + std::fmt::Display,
//    L: UpdateLinkStatus<IndexerHeightLag>,
//    L::LinkStatus: InferConnection<ConnectionStatus = C>,
//    C: PartialEq,
//{
//    pub async fn new(
//        clock: Clock,
//        report_interval: Duration,
//        nodes: &NonEmptyBTreeSet<N>,
//        report_buffer_size: usize,
//    ) -> Self {
//        let first_hand_indexer_heights = FirstHandIndexerHeights::new(nodes);
//        let connection_tracker = ConnectionTracker::new(nodes);
//        let (peer_reports_sender, peer_reports_receiver) = mpsc::channel(report_buffer_size);
//    }
//}
/// The manager runs until `cancellation_token` is cancelled or every `updates` sender is gone.
//pub fn run_network_view_manager<M>(
//    me: ParticipantId,
//    participants: &NonEmptyBTreeSet<ParticipantId>,
//    measurement: M,
//    report_interval: Duration,
//    clock: Clock,
//    cancellation_token: CancellationToken,
//) -> NetworkViewHandles<M::Link>
//where
//    M: MeasureNetworkConnections + Send + 'static,
//    M::Link: Send + Sync + 'static,
//{
//    let first_hand_heights = FirstHandIndexerHeights::new(participants);
//    let (updates, observations) = mpsc::channel(update_buffer_size(participants.len()));
//    let (connections, connections_receiver) =
//        watch::channel(Arc::new(measurement.usable_connections()));
//    let (heights, heights_receiver) = watch::channel(first_hand_heights.snapshot());
//    let (link_reports, link_reports_receiver) =
//        watch::channel(measurement.link_report(clock.now()));
//    let manager = NetworkViewManager {
//        first_hand_heights,
//        measurement,
//        observations,
//        connections,
//        heights,
//        link_reports,
//        report_interval,
//        clock,
//    };
//    tokio::spawn(manager.run(cancellation_token));
//    NetworkViewHandles {
//        local_view: LocalNetworkView::new(me, connections_receiver, heights_receiver),
//        updates,
//        link_reports: link_reports_receiver,
//    }
//}

// todo: add `ConnectivityMonitorHandle`, the read side of the monitor. It must implement the traits
// the request queue defines: `crate::requests::queue::ReadAliveParticipants` and
// `crate::requests::queue::ReadIndexerHeights`.

trait ApplyPeerReport<N, R> {
    fn apply(&mut self, report: R) -> Result<ConnectionsChanged, PeerReportError<N>>;
}

/// Whether applying a report changed any connection.
enum ConnectionsChanged {
    Yes,
    No,
}

impl<N, C, S, L> ApplyPeerReport<N, IndexerHeightReport<N>> for ConnectivityMonitor<N, C, S, L>
where
    N: Ord + Hash + Clone + std::fmt::Display,
    L: UpdateLinkStatus<IndexerHeightLag>,
    L::LinkStatus: InferConnection<ConnectionStatus = C>,
    C: PartialEq,
{
    fn apply(
        &mut self,
        report: IndexerHeightReport<N>,
    ) -> Result<ConnectionsChanged, PeerReportError<N>> {
        let own_height = *report
            .indexer_heights
            .get(&report.reporter)
            .ok_or(PeerReportError::OwnHeightMissing(report.reporter.clone()))?;
        self.first_hand_heights
            .set(report.reporter.clone(), own_height)?;
        Ok(self.update_connections(&report)?)
    }
}

impl<N: Ord + Hash + Clone, C, S, L> ConnectivityMonitor<N, C, S, L> {
    /// Derives the link observations from `report` and feeds them to the tracker.
    fn update_connections<R>(
        &mut self,
        report: &R,
    ) -> Result<ConnectionsChanged, UnknownNodeError<N>>
    where
        R: DeriveLinkObservations<N>,
        L: UpdateLinkStatus<R::Observation>,
        L::LinkStatus: InferConnection<ConnectionStatus = C>,
        C: PartialEq,
    {
        let context = ObservationContext {
            first_hand_indexer_heights: &self.first_hand_heights,
        };
        let now = self.clock.now();
        let mut connections_changed = ConnectionsChanged::No;
        for observation in report.derive_link_observations(&context) {
            let connection_changed = self
                .connection_tracker
                .update_with_observation(observation, now)?;
            if let ConnectionChanged::Yes = connection_changed {
                connections_changed = ConnectionsChanged::Yes;
            }
        }
        Ok(connections_changed)
    }
}
//
//pub struct NetworkViewHandles<Link> {
//    pub local_view: LocalNetworkView,
//    pub updates: mpsc::Sender<NetworkViewUpdate>,
//    pub link_reports: watch::Receiver<LinkReport<ParticipantId, Link>>,
//}
//
//
//fn update_buffer_size(participants: usize) -> usize {
//    participants
//        .saturating_mul(NETWORK_VIEW_UPDATES_BUFFERED_PER_PARTICIPANT)
//        .max(1)
//}
