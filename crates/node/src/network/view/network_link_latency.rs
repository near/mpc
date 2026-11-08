use std::{collections::BTreeMap, num::NonZeroUsize};

use near_block_primitives::BlockCount;
use near_mpc_bounded_collections::NonEmptyBTreeSet;
use near_time::{Duration, Instant};

use crate::{
    network::{
        constants::MAX_ONLINE_DELAY_BLOCKS,
        view::{
            first_hand_indexer_heights::{FirstHandHeight, FirstHandIndexerHeights, parse_height},
            primitives::{
                GradeLink, InferLinkStatus, LinkObservation, LinkReport, LinkSpeed, LinkStatus,
                MeasuredNetworkConnections, PreviousViewValidity, RecentObservations,
                TimedObservation, Uptime, UsableNetworkConnections,
            },
            view_manager::{LocalPeerReport, MeasureNetworkConnections, NetworkViewUpdateError},
        },
    },
    primitives::ParticipantId,
};

/// Link latencies derived from the indexer heights gossiped in
/// [`ConnectedPeersInfo`](crate::primitives::ConnectedPeersInfo) messages.
///
/// A message from a `reporter` carries the indexer heights the `reporter` thinks each peer it is
/// connected to is at. Its entry for a peer `origin` is used to approximately measure the link
/// `origin --> reporter` (the `origin`'s gossip arriving at the `reporter`). The approximated
/// latency is our first-hand height for the `origin` minus the height the `reporter` thinks the
/// `origin` is at:
/// ```text
/// approximate_latency(origin --> reporter)
///     = first_hand(origin) - height_reported_by(reporter, origin)
/// ```
/// An `origin` the `reporter` does not list marks `origin --> reporter` as absent. Since a
/// `reporter` lists a peer only while connected to it both ways, that absence is its verdict on
/// the whole connection, not on this direction alone.
pub struct NetworkConnectionsBlockLatency {
    connections: MeasuredNetworkConnections<ParticipantId, LinkHealth, BlockCount>,
}

/// Latency of `origin --> reporter`, approximated as
/// `(origin --> us) - (origin --> reporter --> us)`, saturating at zero.
/// Link is considered absent if `reported` is `None`.
/// Returns `None` if `first_hand` is [`FirstHandHeight::Unknown`] (i.e. if we don't have a
/// first-hand account `origin --> us`) or if the reporter has no height for the origin yet (`0` on
/// the wire).
fn observe_link(
    first_hand: FirstHandHeight,
    reported: Option<u64>,
) -> Option<LinkObservation<BlockCount>> {
    let seen = match reported {
        None => return Some(LinkObservation::Absent),
        Some(wire) => parse_height(wire)?,
    };
    let FirstHandHeight::Known(own) = first_hand else {
        return None;
    };
    Some(LinkObservation::Present(own.blocks_since(seen)))
}

impl NetworkConnectionsBlockLatency {
    pub fn new(
        participants: &NonEmptyBTreeSet<ParticipantId>,
        measurement_window: NonZeroUsize,
    ) -> Self {
        Self {
            connections: MeasuredNetworkConnections::new(participants, measurement_window),
        }
    }
}

impl MeasureNetworkConnections for NetworkConnectionsBlockLatency {
    type Link = LinkHealth;

    fn record_report(
        &mut self,
        report: &LocalPeerReport,
        first_hand_heights: &FirstHandIndexerHeights,
        now: Instant,
    ) -> Result<PreviousViewValidity, NetworkViewUpdateError> {
        // A report is complete: a participant the sender does not list is unreachable from it.
        let mut observations = BTreeMap::new();
        for (origin, first_hand) in first_hand_heights.iter() {
            if *origin == report.reporter {
                continue;
            }
            let reported = report.peers.get(origin).copied();
            if let Some(observation) = observe_link(*first_hand, reported) {
                observations.insert(*origin, observation);
            }
        }
        // below error only fires in case the partcipant set between network view and the lower
        // structs have diverged. This is currently impossible, but we still propagate, as
        // future refactors might break that invariant.
        Ok(self
            .connections
            .record_observations_from(&report.reporter, observations, now)?)
    }

    fn link_report(&self, now: Instant) -> LinkReport<ParticipantId, LinkHealth> {
        self.connections.link_report(now)
    }

    fn usable_connections(&self) -> UsableNetworkConnections<ParticipantId> {
        self.connections.usable_connections()
    }
}

/// todo: not sure about all these derives
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, derive_more::Deref, Debug, derive_more::From,
)]
pub struct MeanBlockLag(u64);

impl MeanBlockLag {
    pub const fn new(blocks: u64) -> Self {
        Self(blocks)
    }
}

/// Mean lag over the window's present samples, and [`RecentObservations::uptime`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkHealth {
    pub mean_lag: MeanBlockLag,
    pub up_for: Duration,
}

impl InferLinkStatus<BlockCount> for LinkHealth {
    fn infer_link_status(obs: &RecentObservations<BlockCount>) -> LinkStatus<Self> {
        let LinkStatus::Present(up_for) = obs.uptime() else {
            return LinkStatus::Absent;
        };
        let mut present = obs.newest_first().filter_map(TimedObservation::present);
        let Some(newest_lag) = present.next() else {
            return LinkStatus::Absent;
        };
        let mut summed = helper::SummedLatencies::new(*newest_lag);
        for latency in present {
            summed.add(*latency);
        }
        LinkStatus::Present(LinkHealth {
            mean_lag: summed.average_latency(),
            up_for,
        })
    }
}

// todo: calibrate the lag estimator on localnet with injected delay (tc netem) before deriving a
// cutoff from it: how much of a delay shows up as lag, how the path-difference error smears it, and
// how fast the 60-sample mean reacts
impl GradeLink for LinkHealth {
    fn grade(&self) -> LinkSpeed {
        if self.mean_lag > MAX_ONLINE_DELAY_BLOCKS {
            return LinkSpeed::TooSlow;
        }
        LinkSpeed::Up(Uptime::exceeds(self.up_for))
    }
}

mod helper {
    use near_block_primitives::BlockCount;

    use crate::network::view::network_link_latency::MeanBlockLag;

    pub(crate) struct SummedLatencies {
        count: u128,
        sum: u128,
    }

    impl SummedLatencies {
        pub(super) fn new(init_latency: BlockCount) -> Self {
            Self {
                count: 1,
                sum: u128::from(u64::from(init_latency)),
            }
        }

        pub(super) fn add(&mut self, latency: BlockCount) {
            self.count = self.count.saturating_add(1);
            self.sum = self.sum.saturating_add(u128::from(u64::from(latency)));
        }
        pub(super) fn average_latency(&self) -> MeanBlockLag {
            let avg = self.sum.checked_div(self.count).unwrap_or(0);
            MeanBlockLag(u64::try_from(avg).unwrap_or(u64::MAX))
        }
    }
}

// todo tests
// todo: test that a peer lying about heights only affects links with itself as an endpoint
