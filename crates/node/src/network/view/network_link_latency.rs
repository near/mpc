use std::{collections::BTreeMap, num::NonZeroUsize};

use near_block_primitives::{BlockCount, BlockHeight};
use near_mpc_bounded_collections::{NonEmptyBTreeMap, NonEmptyBTreeSet};
use near_time::{Duration, Instant};
use time::ext::InstantExt as _;

use crate::{
    network::{
        constants::{MAX_ONLINE_DELAY_BLOCKS, UPTIME_HALF_MINUTE, UPTIME_SECONDS},
        view::primitives::{
            AdjacencyMatrixError, GradeLink, InferLinkStatus, LinkObservation, LinkReport,
            LinkSpeed, LinkStatus, MeasuredNetworkConnections, PreviousViewValidity,
            RecentObservations, TimedObservation, Uptime, UsableNetworkConnections,
        },
    },
    primitives::{ConnectedPeersInfo, ParticipantId, PeerConnectedPeersInfo},
};

/// Indexer block heights across the network, as gossiped in [`ConnectedPeersInfo`] messages,
/// and the link latencies derived from them.
///
/// A message from a `reporter` carries the indexer heights the `reporter` thinks each peer it is
/// connected to is at, itself included.
///
/// - Its own entry updates our first-hand record of the `reporter`'s height.
/// - Its entry for a peer `origin` is used to approximately measure the link
///   `origin --> reporter` (the `origin`'s gossip arriving at the `reporter`). The approximated
///   latency is our first-hand height for the `origin` minus the height the `reporter` thinks the
///   `origin` is at:
///   ```text
///   approximate_latency(origin --> reporter)
///       = first_hand(origin) - height_reported_by(reporter, origin)
///   ```
/// - An `origin` the `reporter` does not list marks `origin --> reporter` as absent. Since a
///   `reporter` lists a peer only while connected to it both ways, that absence is its verdict on
///   the whole connection, not on this direction alone.
pub struct NetworkIndexerBlockHeights {
    // list of all participants
    first_hand_heights: NonEmptyBTreeMap<ParticipantId, FirstHandHeight>,
    connections: MeasuredNetworkConnections<ParticipantId, LinkHealth, BlockCount>,
}

/// `Unknown` until the participant's first message, then whatever it last reported.
/// The wire format encodes `Unknown` as `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstHandHeight {
    Unknown,
    Known(BlockHeight),
}

impl From<u64> for FirstHandHeight {
    fn from(height: u64) -> Self {
        match height {
            0 => Self::Unknown,
            height => Self::Known(BlockHeight::from(height)),
        }
    }
}

impl From<FirstHandHeight> for u64 {
    fn from(height: FirstHandHeight) -> Self {
        match height {
            FirstHandHeight::Unknown => 0,
            FirstHandHeight::Known(height) => height.into(),
        }
    }
}

struct ParsedConnectedPeersInfo {
    own_height: FirstHandHeight,
    observations: BTreeMap<ParticipantId, LinkObservation<BlockCount>>,
}

/// Latency of `origin --> reporter`, approximated as
/// `(origin --> us) - (origin --> reporter --> us)`, saturating at zero.
/// Link is considered absent if `reported_height` is `None`.
/// Returns `None` if `first_hand` or `reported_height` is [`FirstHandHeight::Unknown`] (i.e. if we
/// don't have a first-hand account `origin --> us`, or the reporter has no height for the origin
/// yet).
fn observe_link(
    first_hand: FirstHandHeight,
    reported_height: Option<FirstHandHeight>,
) -> Option<LinkObservation<BlockCount>> {
    match (first_hand, reported_height) {
        (_, None) => Some(LinkObservation::Absent),
        (FirstHandHeight::Known(own), Some(FirstHandHeight::Known(seen))) => {
            Some(LinkObservation::Present(own.blocks_since(seen)))
        }
        (FirstHandHeight::Unknown, Some(_)) | (_, Some(FirstHandHeight::Unknown)) => None,
    }
}

impl NetworkIndexerBlockHeights {
    pub fn first_hand_heights(&self) -> BTreeMap<ParticipantId, FirstHandHeight> {
        self.first_hand_heights.clone().into()
    }

    pub fn link_report(&self, now: Instant) -> LinkReport<ParticipantId, LinkHealth> {
        self.connections.link_report(now)
    }
    /// Validates a message and translates it into what we record. Pure: a malformed message
    /// leaves the state untouched.
    fn parse_connected_peers_info(
        &self,
        reporter: ParticipantId,
        peers: BTreeMap<ParticipantId, u64>,
    ) -> Result<ParsedConnectedPeersInfo, NetworkViewUpdateError> {
        if !self.first_hand_heights.contains_key(&reporter) {
            return Err(NetworkViewUpdateError::UnknownParticipant(reporter));
        }
        let own_height = FirstHandHeight::from(
            *peers
                .get(&reporter)
                .ok_or(NetworkViewUpdateError::OwnHeightMissing(reporter))?,
        );
        // A report is complete: a participant the sender does not list is unreachable from it.
        let mut observations = BTreeMap::new();
        for (origin, first_hand) in self.first_hand_heights.iter() {
            if *origin == reporter {
                continue;
            }
            let reported_height = peers
                .get(origin)
                .map(|height| FirstHandHeight::from(*height));
            if let Some(observation) = observe_link(*first_hand, reported_height) {
                observations.insert(*origin, observation);
            }
        }
        Ok(ParsedConnectedPeersInfo {
            own_height,
            observations,
        })
    }
    pub fn new(
        participants: &NonEmptyBTreeSet<ParticipantId>,
        measurement_window: NonZeroUsize,
    ) -> Self {
        Self {
            first_hand_heights: participants
                .iter()
                .map(|&p| (p, FirstHandHeight::Unknown))
                .collect::<BTreeMap<_, _>>()
                .try_into()
                .expect("a non-empty participant set yields a non-empty map"),
            connections: MeasuredNetworkConnections::new(participants, measurement_window),
        }
    }
    /// Updates the view based on one participant's message.
    /// Returns [`PreviousViewValidity::Superseded`] in case a connection changed status.
    pub fn update_with(
        &mut self,
        PeerConnectedPeersInfo {
            from: reporter,
            info,
        }: PeerConnectedPeersInfo,
        now: Instant,
    ) -> Result<PreviousViewValidity, NetworkViewUpdateError> {
        let ConnectedPeersInfo { peers } = info;
        let ParsedConnectedPeersInfo {
            own_height,
            observations,
        } = self.parse_connected_peers_info(reporter, peers)?;
        self.record_first_hand(reporter, own_height);
        // below error only fires in case the partcipant set between network view and the lower
        // structs have diverged. This is currently impossible, but we still propagate, as
        // future refactors might break that invariant.
        Ok(self
            .connections
            .record_observations_from(&reporter, observations, now)?)
    }
    /// Records the `reporter`'s own height. Errors if the `reporter` is not a participant, so the
    /// participant set never grows.
    pub fn update_first_hand(
        &mut self,
        reporter: ParticipantId,
        height: u64,
    ) -> Result<(), NetworkViewUpdateError> {
        if !self.first_hand_heights.contains_key(&reporter) {
            return Err(NetworkViewUpdateError::UnknownParticipant(reporter));
        }
        self.record_first_hand(reporter, FirstHandHeight::from(height));
        Ok(())
    }
    /// `Unknown` leaves the record untouched.
    fn record_first_hand(&mut self, reporter: ParticipantId, height: FirstHandHeight) {
        let FirstHandHeight::Known(height) = height else {
            return;
        };
        let previous = self
            .first_hand_heights
            .insert(reporter, FirstHandHeight::Known(height));
        if let Some(FirstHandHeight::Known(previous)) = previous
            && height < previous
        {
            tracing::warn!(
                %reporter,
                %previous,
                %height,
                "indexer height moved backwards. This is unexpected, because the indexer \
                 processes blocks in order."
            );
        }
    }
    /// The read-only snapshot for readers.
    pub fn usable_connections(&self) -> UsableNetworkConnections<ParticipantId> {
        self.connections.usable_connections()
    }
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

/// Mean lag over the window's present samples, and for how long the link has been present
/// without interruption: from the first present sample after the last absent one to the newest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkHealth {
    pub mean_lag: MeanBlockLag,
    pub up_for: Duration,
}

impl InferLinkStatus<BlockCount> for LinkHealth {
    fn infer_link_status(obs: &RecentObservations<BlockCount>) -> LinkStatus<Self> {
        let newest = obs.newest();
        let LinkObservation::Present(newest_lag) = &newest.observation else {
            return LinkStatus::Absent;
        };
        let up_since = obs
            .newest_first()
            .take_while(|observation| observation.present().is_some())
            .last()
            .map_or(newest.at, |observation| observation.at);
        let mut summed = helper::SummedLatencies::new(*newest_lag);
        for latency in obs
            .newest_first()
            .skip(1)
            .filter_map(TimedObservation::present)
        {
            summed.add(*latency);
        }
        LinkStatus::Present(LinkHealth {
            mean_lag: summed.average_latency(),
            up_for: newest.at.signed_duration_since(up_since),
        })
    }
}

impl GradeLink for LinkHealth {
    fn grade(&self) -> LinkSpeed {
        if self.mean_lag > MAX_ONLINE_DELAY_BLOCKS {
            return LinkSpeed::TooSlow;
        }
        LinkSpeed::Up(if self.up_for >= UPTIME_HALF_MINUTE {
            Uptime::HalfMinute
        } else if self.up_for >= UPTIME_SECONDS {
            Uptime::Seconds
        } else {
            Uptime::Any
        })
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
