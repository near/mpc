// todo: clean this file

use std::{hash::Hash, num::NonZeroUsize, sync::Arc};

use near_mpc_bounded_collections::NonEmptyBTreeSet;
use near_time::{Clock, Duration, Interval};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::network::connectivity::{
    errors::PeerReportError,
    first_hand_indexer_heights::FirstHandIndexerHeights,
    graph::{TooManyNodesError, UnknownNodeError},
    health::{
        ConnectionChanged, ConnectionTracker, EstablishedConnections, InferConnection,
        LinkStatuses, ReportLinkStatus, UpdateLinkStatus,
    },
    reports::{
        DeriveLinkObservations, IndexerHeightLag, IndexerHeightReport, LegacyIndexerHeightReport,
        ObservationContext, PeerReport,
    },
};

struct ConnectivityMonitor<N, C, S, L> {
    // state
    clock: Clock,
    report_interval: Duration,
    heights_publish_interval: Duration,
    first_hand_heights: FirstHandIndexerHeights<N>,
    connection_tracker: ConnectionTracker<N, C, L>,

    // everything we receive from other components
    peer_reports: mpsc::Receiver<PeerReport<N>>,

    // everything we send to other components
    /// as soon as a connection changes its status, this is updated
    connections: watch::Sender<Arc<EstablishedConnections<N, C>>>,
    /// updated every heights_publish_interval
    heights: watch::Sender<FirstHandIndexerHeights<N>>,

    /// update every report_interval
    // todo: metrics task on this watch: mean lag and uptime per link, status per pair, as gauges,
    // to learn the healthy lag distribution and its tail
    link_statuses: watch::Sender<LinkStatuses<N, S>>,
}

struct DebugConnectivityView<N, S> {
    link_statuses: watch::Receiver<Arc<LinkStatuses<N, S>>>,
}

impl<N, C, S, L> ConnectivityMonitor<N, C, S, L>
where
    N: Ord + Hash + Clone,
    C: Clone,
    L: ReportLinkStatus<LinkStatus = S>,
{
    /// Returns the monitor, which the caller has to run, and its channels.
    pub fn new(
        clock: Clock,
        report_interval: Duration,
        heights_publish_interval: Duration,
        nodes: &NonEmptyBTreeSet<N>,
        report_buffer_size: NonZeroUsize,
    ) -> Result<(Self, ConnectivityMonitorHandles<N, C, S>), TooManyNodesError> {
        let first_hand_heights = FirstHandIndexerHeights::new(nodes);
        let connection_tracker: ConnectionTracker<N, C, L> = ConnectionTracker::new(nodes)?;
        let (peer_reports_sender, peer_reports) = mpsc::channel(report_buffer_size.get());
        let connections = watch::Sender::new(Arc::new(
            connection_tracker.established_connections().clone(),
        ));
        let heights = watch::Sender::new(first_hand_heights.clone());
        let link_statuses = watch::Sender::new(connection_tracker.report_link_statuses());
        let handles = ConnectivityMonitorHandles {
            peer_reports: peer_reports_sender,
            connections: connections.subscribe(),
            clock: clock.clone(),
            heights: heights.subscribe(),
            link_statuses: link_statuses.subscribe(),
        };
        let monitor = Self {
            clock,
            report_interval,
            heights_publish_interval,
            first_hand_heights,
            connection_tracker,
            peer_reports,
            connections,
            heights,
            link_statuses,
        };
        Ok((monitor, handles))
    }
}

impl<N, C, S, L> ConnectivityMonitor<N, C, S, L>
where
    N: Ord + Hash + Clone + std::fmt::Debug + std::fmt::Display,
    C: Clone + PartialEq,
    L: UpdateLinkStatus<IndexerHeightLag, LinkStatus = S>,
    S: InferConnection<ConnectionStatus = C>,
{
    /// Runs until `cancellation_token` is cancelled or every sender of peer reports is gone.
    pub async fn run(mut self, cancellation_token: CancellationToken) {
        let mut link_statuses_tick = Interval::new(self.clock.now(), self.report_interval);
        let mut heights_tick = Interval::new(self.clock.now(), self.heights_publish_interval);
        loop {
            tokio::select! {
                _ = cancellation_token.cancelled() => return,
                report = self.peer_reports.recv() => {
                    let Some(report) = report else {
                        return;
                    };
                    self.apply_and_publish(report);
                }
                _ = heights_tick.tick(&self.clock) => {
                    self.heights.send_replace(self.first_hand_heights.clone());
                }
                _ = link_statuses_tick.tick(&self.clock) => {
                    self.link_statuses
                        .send_replace(self.connection_tracker.report_link_statuses());
                }
            }
        }
    }

    fn apply_and_publish(&mut self, report: PeerReport<N>) {
        match self.apply(report) {
            Ok(ConnectionsChanged::Yes) => {
                let connections = self.connection_tracker.established_connections().clone();
                self.connections.send_replace(Arc::new(connections));
            }
            Ok(ConnectionsChanged::No) => {}
            Err(err) => tracing::warn!(%err, "peer report not applied"),
        }
    }
}

/// The channels of a [`ConnectivityMonitor`] that the other components use.
pub struct ConnectivityMonitorHandles<N, C, S> {
    pub peer_reports: mpsc::Sender<PeerReport<N>>,
    pub connections: watch::Receiver<Arc<EstablishedConnections<N, C>>>,
    /// The times stored in `connections` are from this clock, so ask them with its `now`.
    pub clock: Clock,
    pub heights: watch::Receiver<FirstHandIndexerHeights<N>>,
    pub link_statuses: watch::Receiver<LinkStatuses<N, S>>,
}

// todo: add a reader of the monitor's heights for the request queue. It must implement
// `crate::requests::queue::ReadIndexerHeights`.

trait ApplyPeerReport<N, R> {
    fn apply(&mut self, report: R) -> Result<ConnectionsChanged, PeerReportError<N>>;
}

/// Whether applying a report changed any connection.
enum ConnectionsChanged {
    Yes,
    No,
}

impl<N, C, S, L> ApplyPeerReport<N, PeerReport<N>> for ConnectivityMonitor<N, C, S, L>
where
    N: Ord + Hash + Clone + std::fmt::Display,
    L: UpdateLinkStatus<IndexerHeightLag>,
    L::LinkStatus: InferConnection<ConnectionStatus = C>,
    C: PartialEq,
{
    fn apply(&mut self, report: PeerReport<N>) -> Result<ConnectionsChanged, PeerReportError<N>> {
        match report {
            PeerReport::IndexerHeightReport(report) => self.apply(report),
            PeerReport::LegacyIndexerHeightReport(report) => self.apply(report),
        }
    }
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

impl<N, C, S, L> ApplyPeerReport<N, LegacyIndexerHeightReport<N>>
    for ConnectivityMonitor<N, C, S, L>
where
    N: Ord + Clone + std::fmt::Display,
{
    fn apply(
        &mut self,
        report: LegacyIndexerHeightReport<N>,
    ) -> Result<ConnectionsChanged, PeerReportError<N>> {
        self.first_hand_heights
            .set(report.reporter, report.indexer_height)?;
        Ok(ConnectionsChanged::No)
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
