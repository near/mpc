//use std::{
//    collections::{BTreeMap, VecDeque},
//    num::NonZeroUsize,
//};
//
//use near_block_primitives::BlockCount;
//use near_mpc_bounded_collections::NonEmptyBTreeSet;
//use near_time::Instant;
//
//use crate::{
//    network::{
//        constants::MAX_ONLINE_DELAY_BLOCKS,
//        view::{
//            first_hand_indexer_heights::{FirstHandHeight, FirstHandIndexerHeights, parse_height},
//            primitives::{
//                ConnectionStatus, GradeLink, LinkObservation, LinkReport,
//                MeasuredNetworkConnections, PreviousViewValidity, Uptime, UsableNetworkConnections,
//            },
//            view_manager::{LocalPeerReport, MeasureNetworkConnections, NetworkViewUpdateError},
//        },
//    },
//    primitives::ParticipantId,
//};

///// Link latencies derived from the indexer heights gossiped in
///// [`ConnectedPeersInfo`](crate::primitives::ConnectedPeersInfo) messages.
/////
///// A message from a `reporter` carries the indexer heights the `reporter` thinks each peer it is
///// connected to is at. Its entry for a peer `origin` is used to approximately measure the link
///// `origin --> reporter` (the `origin`'s gossip arriving at the `reporter`). The approximated
///// latency is our first-hand height for the `origin` minus the height the `reporter` thinks the
///// `origin` is at:
///// ```text
///// approximate_latency(origin --> reporter)
/////     = first_hand(origin) - height_reported_by(reporter, origin)
///// ```
///// An `origin` the `reporter` does not list marks `origin --> reporter` as absent. Since a
///// `reporter` lists a peer only while connected to it both ways, that absence is its verdict on
///// the whole connection, not on this direction alone.
//pub struct NetworkConnectionsBlockLatency {
//    connections: MeasuredNetworkConnections<ParticipantId, RecentBlockLags>,
//}
//
///// Latency of `origin --> reporter`, approximated as
///// `(origin --> us) - (origin --> reporter --> us)`, saturating at zero.
///// Link is considered absent if `reported` is `None`.
///// Returns `None` if `first_hand` is [`FirstHandHeight::Unknown`] (i.e. if we don't have a
///// first-hand account `origin --> us`) or if the reporter has no height for the origin yet (`0` on
///// the wire).
//fn observe_link(
//    first_hand: FirstHandHeight,
//    reported: Option<u64>,
//) -> Option<LinkObservation<BlockCount>> {
//    let seen = match reported {
//        None => return Some(LinkObservation::Absent),
//        Some(wire) => parse_height(wire)?,
//    };
//    let FirstHandHeight::Known(own) = first_hand else {
//        return None;
//    };
//    Some(LinkObservation::Present(own.blocks_since(seen)))
//}
//
//impl NetworkConnectionsBlockLatency {
//    pub fn new(
//        participants: &NonEmptyBTreeSet<ParticipantId>,
//        measurement_window: NonZeroUsize,
//    ) -> Self {
//        let unmeasured = RecentBlockLags::new(measurement_window);
//        Self {
//            connections: MeasuredNetworkConnections::new(participants, unmeasured),
//        }
//    }
//}
//
//impl MeasureNetworkConnections for NetworkConnectionsBlockLatency {
//    type Link = RecentBlockLags;
//
//    fn record_report(
//        &mut self,
//        report: &LocalPeerReport,
//        first_hand_heights: &FirstHandIndexerHeights,
//        now: Instant,
//    ) -> Result<PreviousViewValidity, NetworkViewUpdateError> {
//        // A report is complete: a participant the sender does not list is unreachable from it.
//        let mut observations = BTreeMap::new();
//        for (origin, first_hand) in first_hand_heights.iter() {
//            if *origin == report.reporter {
//                continue;
//            }
//            let reported = report.peers.get(origin).copied();
//            if let Some(observation) = observe_link(*first_hand, reported) {
//                observations.insert(*origin, observation);
//            }
//        }
//        // below error only fires in case the partcipant set between network view and the lower
//        // structs have diverged. This is currently impossible, but we still propagate, as
//        // future refactors might break that invariant.
//        Ok(self
//            .connections
//            .record_observations_from(&report.reporter, observations, now)?)
//    }
//
//    fn link_report(&self, now: Instant) -> LinkReport<ParticipantId, RecentBlockLags> {
//        self.connections.link_report(now)
//    }
//
//    fn usable_connections(&self) -> UsableNetworkConnections<ParticipantId> {
//        self.connections.usable_connections()
//    }
//}
//
///// todo: not sure about all these derives
//#[derive(
//    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, derive_more::Deref, Debug, derive_more::From,
//)]
//pub struct MeanBlockLag(u64);
//
//impl MeanBlockLag {
//    pub const fn new(blocks: u64) -> Self {
//        Self(blocks)
//    }
//}
//
///// The newest `window` lags of an up link, with their sum kept alongside.
//#[derive(Debug, Clone, PartialEq, Eq)]
//pub struct RecentBlockLags {
//    window: NonZeroUsize,
//    lags: VecDeque<BlockCount>,
//    sum: u128,
//}
//
//impl RecentBlockLags {
//    pub fn new(window: NonZeroUsize) -> Self {
//        Self {
//            window,
//            lags: VecDeque::with_capacity(window.get()),
//            sum: 0,
//        }
//    }
//
//    /// Zero while unmeasured.
//    pub fn mean(&self) -> MeanBlockLag {
//        let count = u128::try_from(self.lags.len()).unwrap_or(u128::MAX);
//        let mean = self.sum.checked_div(count).unwrap_or(0);
//        MeanBlockLag(u64::try_from(mean).unwrap_or(u64::MAX))
//    }
//}
//
//impl Extend<BlockCount> for RecentBlockLags {
//    fn extend<I: IntoIterator<Item = BlockCount>>(&mut self, lags: I) {
//        for lag in lags {
//            if self.lags.len() == self.window.get()
//                && let Some(oldest) = self.lags.pop_front()
//            {
//                self.sum = self.sum.saturating_sub(u128::from(u64::from(oldest)));
//            }
//            self.lags.push_back(lag);
//            self.sum = self.sum.saturating_add(u128::from(u64::from(lag)));
//        }
//    }
//}
//
//// todo: calibrate the lag estimator on localnet with injected delay (tc netem) before deriving a
//// cutoff from it: how much of a delay shows up as lag, how the path-difference error smears it, and
//// how fast the 60-sample mean reacts
//impl GradeLink for RecentBlockLags {
//    fn grade(&self, uptime: Uptime) -> ConnectionStatus {
//        if self.mean() > MAX_ONLINE_DELAY_BLOCKS {
//            ConnectionStatus::Slow
//        } else {
//            ConnectionStatus::Live(uptime)
//        }
//    }
//}

// todo tests
// todo: test that a peer lying about heights only affects links with itself as an endpoint
