// todo: clean this file

use std::{collections::BTreeMap, sync::Arc};

use near_time::{Clock, Duration};
use tokio::sync::{mpsc, watch};

use crate::network::view::{
    errors::NetworkViewUpdateError,
    first_hand_indexer_heights::{FirstHandIndexerHeights, ReportedIndexerHeight},
    primitives::{
        ConnectionChanged, InferConnectionStatus, LinkObservation, LiveNetworkConnections,
        NetworkConnectionsHealthTracker, NetworkLinkStatuses, UnknownNodeError, UpdateLinkStatus,
    },
};

pub struct ObservationContext<'a, N> {
    pub first_hand_indexer_heights: &'a FirstHandIndexerHeights<N>,
}

/// Implemented by an observation type: how to read it out of an update.
pub trait IntoLinkObservation<N, U>: Sized {
    fn into_link_observation(
        update: &U,
        context: &ObservationContext<'_, N>,
    ) -> Vec<LinkObservation<N, Self>>;
}

struct NetworkViewManager<N, C, S, L> {
    // state
    clock: Clock,
    report_interval: Duration,
    first_hand_heights: FirstHandIndexerHeights<N>,
    network_connection_health_tracker: NetworkConnectionsHealthTracker<N, C, L>,

    // everything we receive from other components
    observations: mpsc::Receiver<NetworkViewUpdate<N>>,

    // everything we send to other components
    /// as soon as a connection changes its status, this is updated
    connections: watch::Sender<Arc<LiveNetworkConnections<N, C>>>,
    /// updated on every height update
    heights: watch::Sender<FirstHandIndexerHeights<N>>,

    /// update every report_interval
    // todo: metrics task on this watch: mean lag and uptime per link, status per pair, as gauges,
    // to learn the healthy lag distribution and its tail
    link_report: watch::Sender<NetworkLinkStatuses<N, S>>,
}

trait ApplyNetworkViewUpdate<N, U> {
    fn apply(&mut self, update: U) -> Result<ConnectionsChanged, NetworkViewUpdateError<N>>;
}

/// Whether applying an update changed any connection.
enum ConnectionsChanged {
    Yes,
    No,
}

impl<N: Ord + Clone, C, S, L> NetworkViewManager<N, C, S, L> {
    /// Reads the link observations out of `update` and feeds them to the tracker.
    fn process_link_observations<U>(
        &mut self,
        update: &U,
    ) -> Result<ConnectionsChanged, UnknownNodeError<N>>
    where
        L: UpdateLinkStatus<U> + InferConnectionStatus<ConnectionStatus = C>,
        L::Observation: IntoLinkObservation<N, U>,
        C: PartialEq,
    {
        let context = ObservationContext {
            first_hand_indexer_heights: &self.first_hand_heights,
        };
        let now = self.clock.now();
        let mut connections_changed = ConnectionsChanged::No;
        for observation in L::Observation::into_link_observation(update, &context) {
            let connection_changed = self
                .network_connection_health_tracker
                .update_with_observation::<U>(observation, now)?;
            if let ConnectionChanged::Yes = connection_changed {
                connections_changed = ConnectionsChanged::Yes;
            }
        }
        Ok(connections_changed)
    }
}

impl<N, C, S, L> ApplyNetworkViewUpdate<N, IndexerHeightReport<N>>
    for NetworkViewManager<N, C, S, L>
where
    N: Ord + Clone + std::fmt::Display,
    L: UpdateLinkStatus<IndexerHeightReport<N>> + InferConnectionStatus<ConnectionStatus = C>,
    L::Observation: IntoLinkObservation<N, IndexerHeightReport<N>>,
    C: PartialEq,
{
    fn apply(
        &mut self,
        update: IndexerHeightReport<N>,
    ) -> Result<ConnectionsChanged, NetworkViewUpdateError<N>> {
        let own_height = *update.indexer_heights.get(&update.reporter).ok_or(
            NetworkViewUpdateError::OwnHeightMissing(update.reporter.clone()),
        )?;
        self.first_hand_heights
            .set(update.reporter.clone(), own_height)?;
        Ok(self.process_link_observations(&update)?)
    }
}
pub struct IndexerHeightReport<N> {
    pub reporter: N,
    pub indexer_heights: BTreeMap<N, ReportedIndexerHeight>,
}
// todo: think if you really need this, we can deprecate..
pub struct LegacyIndexerHeightReport<N> {
    pub reporter: N,
    pub indexer_height: ReportedIndexerHeight,
}
pub enum NetworkViewUpdate<N> {
    LegacyIndexerHeightReport(LegacyIndexerHeightReport<N>),
    IndexerHeightReport(IndexerHeightReport<N>),
}
//enum IndexerHeightLag {
//    Present(BlockCount),
//    Absent,
//}
//
//impl IndexerHeightLag {
//    fn new(
//        first_hand_indexer_height: ReportedIndexerHeight,
//        peer_reported_height: Option<ReportedIndexerHeight>,
//    ) -> Option<Self> {
//        let Some(peer_reported) = peer_reported_height else {
//            return Some(IndexerHeightLag::Absent);
//        };
//        match (first_hand_indexer_height, peer_reported) {
//            (ReportedIndexerHeight::Unknown, _) => None,
//            (_, ReportedIndexerHeight::Unknown) => None,
//            (
//                ReportedIndexerHeight::Known(first_hand),
//                ReportedIndexerHeight::Known(peer_reported),
//            ) => {
//                let count = first_hand.blocks_since(peer_reported);
//                Some(IndexerHeightLag::Present(count))
//            }
//        }
//    }
//}

//pub struct LinkObservation<N, O> {
//    pub from: N,
//    pub to: N,
//    pub observation: O,
//}

//
///// Latency of `origin --> reporter`, approximated as
///// `(origin --> us) - (origin --> reporter --> us)`, saturating at zero.
///// Link is considered absent if `reported` is `None`.
///// Returns `None` if `first_hand` is [`FirstHandHeight::Unknown`] (i.e. if we don't have a
///// first-hand account `origin --> us`) or if the reporter has no height for the origin yet (`0` on
///// the wire).
//fn observe_link(
//    first_hand: ReportedIndexerHeight,
//    reported: Option<ReportedIndexerHeight>,
//) -> Option<LinkObservation<BlockCount>> {
//    let seen = match reported {
//        None => return Some(LinkObservation::Absent),
//        Some(wire) => parse_height(wire)?,
//    };
//    let ReportedIndexerHeight::Known(own) = first_hand else {
//        return None;
//    };
//    Some(LinkObservation::Present(own.blocks_since(seen)))
//}
//
//// todo: make this generic trait for Rceording??
//pub trait RecordBlockLatencyLink {
//    type LinkStatus;
//    fn record_block_latency(&mut self) -> Result<UpdateResult<Self::LinkStatus>, ()>;
//}
//impl<N, S, L> NetworkViewManager<N, S, L> {
//    async fn run(mut self, cancellation_token: CancellationToken) {
//        let mut tick = tokio::time::interval(self.report_interval.unsigned_abs());
//        loop {
//            tokio::select! {
//                _ = cancellation_token.cancelled() => break,
//                update = self.observations.recv() => {
//                    // a closed channel never reopens: senders can only be cloned from one another
//                    let Some(update) = update else {
//                        break;
//                    };
//                    if let Err(err) = self.apply_network_view_update(update) {
//                        tracing::error!(?err, "could not apply network view update");
//                    }
//                }
//                _ = tick.tick() => {
//                    self.link_reports
//                        .send_replace(self.measurement.link_report(self.clock.now()));
//                }
//            }
//        }
//    }
//    fn apply_network_view_update(
//        &mut self,
//        update: NetworkViewUpdate,
//    ) -> Result<(), NetworkViewUpdateError> {
//        match update {
//            NetworkViewUpdate::IndexerHeightReport(height_report) => self.apply(height_report),
//            NetworkViewUpdate::LegacyIndexerHeightReport(legacy_update) => {
//                tracing::warn!("received legacy report, skiping");
//                Ok(())
//            }
//        }
//    }
//    //    let validity = match update {
//    //        NetworkViewUpdate::IndexerHeightReport(IndexerHeightReport {
//    //            reporter,
//    //            indexer_heights,
//    //        }) => {
//    //            let own_height = *indexer_heights
//    //                .peers
//    //                .get(&reporter)
//    //                .ok_or(NetworkViewUpdateError::OwnHeightMissing(reporter))?;
//    //            self.first_hand_heights.record(reporter, own_height)?;
//    //            self.measurement.record_report(
//    //                &report,
//    //                &self.first_hand_heights,
//    //                self.clock.now(),
//    //            )?
//    //        }
//    //        NetworkViewUpdate::IndexerHeight {
//    //            participant,
//    //            height,
//    //        } => {
//    //            self.first_hand_heights.record(participant, height)?;
//    //            PreviousViewValidity::Valid
//    //        }
//    //    };
//    //    self.heights
//    //        .send_replace(self.first_hand_heights.snapshot());
//    //    if validity == PreviousViewValidity::Superseded {
//    //        self.connections
//    //            .send_replace(Arc::new(self.measurement.usable_connections()));
//    //    }
//    //    Ok(())
//    //}
//}
//
//
//
///// What a participant reports about the peers it is connected to: each with the indexer height
///// it has for that peer, itself included. The wire encodes an unknown height as `0`.
//
///// Turns participants' reports into connection statuses.
//pub trait MeasureNetworkConnections {
//    /// The per-link status this measurement infers; what the link report carries.
//    type Link;
//
//    fn record_report(
//        &mut self,
//        report: &LocalPeerReport,
//        first_hand_heights: &FirstHandIndexerHeights,
//        now: Instant,
//    ) -> Result<PreviousViewValidity, NetworkViewUpdateError>;
//
//    fn link_report(&self, now: Instant) -> LinkReport<ParticipantId, Self::Link>;
//
//    fn usable_connections(&self) -> UsableNetworkConnections<ParticipantId>;
//}
//
//pub struct NetworkViewHandles<Link> {
//    pub local_view: LocalNetworkView,
//    pub updates: mpsc::Sender<NetworkViewUpdate>,
//    pub link_reports: watch::Receiver<LinkReport<ParticipantId, Link>>,
//}
//
///// The manager runs until `cancellation_token` is cancelled or every `updates` sender is gone.
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
//
//fn update_buffer_size(participants: usize) -> usize {
//    participants
//        .saturating_mul(NETWORK_VIEW_UPDATES_BUFFERED_PER_PARTICIPANT)
//        .max(1)
//}
