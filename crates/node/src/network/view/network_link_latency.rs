use std::{collections::BTreeMap, num::NonZeroUsize};

use near_block_primitives::{BlockCount, BlockHeight};
use near_mpc_bounded_collections::{NonEmptyBTreeMap, NonEmptyBTreeSet};

use crate::{
    network::view::primitives::{
        AdjacencyMatrixError, BrokenNetworkConnections, InferLinkStatus, LinkObservation,
        LinkReport, LinkStatus, NetworkConnectionsView, PreviousViewValidity, RecentObservations,
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
/// - Any `origin` not reported by the `reporter` assumes `origin --> reporter` is broken.
pub struct NetworkIndexerBlockHeights {
    // list of all participants
    // BlockHeight is set to 0 if we haven't yet heard from that participant
    first_hand_heights: NonEmptyBTreeMap<ParticipantId, BlockHeight>,
    network_view: NetworkConnectionsView<ParticipantId, MeanBlockLag, BlockCount>,
}

// todo: implement NetworkAPIForRequests on top of this.
pub struct NetworkIndexerBlockHeightsReport {
    pub first_hand_heights: NonEmptyBTreeMap<ParticipantId, BlockHeight>,
    pub link_report: LinkReport<ParticipantId, MeanBlockLag>,
}

struct ParsedConnectedPeersInfo {
    own_height: BlockHeight,
    observations: BTreeMap<ParticipantId, LinkObservation<BlockCount>>,
}

impl NetworkIndexerBlockHeights {
    pub fn generate_report(&self) -> NetworkIndexerBlockHeightsReport {
        let first_hand_heights = self.first_hand_heights.clone();
        let link_report = self.network_view.link_report();
        NetworkIndexerBlockHeightsReport {
            first_hand_heights,
            link_report,
        }
    }
    /// Validates a message and translates it into what we record. Pure: a malformed message
    /// leaves the state untouched.
    fn parse_connected_peers_info(
        &self,
        reporter: ParticipantId,
        peers: BTreeMap<ParticipantId, u64>,
    ) -> Result<ParsedConnectedPeersInfo, ConnectedPeersInfoError> {
        if !self.first_hand_heights.contains_key(&reporter) {
            return Err(ConnectedPeersInfoError::UnknownSender(reporter));
        }
        let own_height = *peers
            .get(&reporter)
            .ok_or(ConnectedPeersInfoError::FirstHandAccountMissing(reporter))?;
        // A report is complete: a participant the sender does not list is unreachable from it.
        let observations = self
            .first_hand_heights
            .iter()
            .filter(|(origin, _)| **origin != reporter)
            .map(|(origin, own)| {
                (
                    *origin,
                    match peers.get(origin) {
                        Some(seen) => {
                            LinkObservation::Present(own.blocks_since(BlockHeight::from(*seen)))
                        }
                        None => LinkObservation::Absent,
                    },
                )
            })
            .collect();
        Ok(ParsedConnectedPeersInfo {
            own_height: own_height.into(),
            observations,
        })
    }
    pub fn new(
        participants: &NonEmptyBTreeSet<ParticipantId>,
        measurement_window: NonZeroUsize,
        threshold: MeanBlockLag,
    ) -> Self {
        Self {
            first_hand_heights: participants
                .iter()
                .map(|&p| (p, BlockHeight::default()))
                .collect::<BTreeMap<_, _>>()
                .try_into()
                .expect("a non-empty participant set yields a non-empty map"),
            network_view: NetworkConnectionsView::new(participants, measurement_window, threshold),
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
    ) -> Result<PreviousViewValidity, ConnectedPeersInfoError> {
        let ConnectedPeersInfo { peers } = info;
        let ParsedConnectedPeersInfo {
            own_height,
            observations,
        } = self.parse_connected_peers_info(reporter, peers)?;
        self.first_hand_heights.insert(reporter, own_height);
        // below error only fires in case the partcipant set between network view and the lower
        // structs have diverged. This is currently impossible, but we still propagate, as
        // future refactors might break that invariant.
        self.network_view
            .record_observations_from(&reporter, observations)
            .map_err(|source| ConnectedPeersInfoError::Rejected {
                from: reporter,
                source,
            })
    }
    /// Records the `reporter`'s own height. Errors if the `reporter` is not a participant, so the
    /// participant set never grows.
    pub fn update_first_hand(
        &mut self,
        reporter: ParticipantId,
        height: BlockHeight,
    ) -> Result<(), BlockHeightInfoError> {
        if !self.first_hand_heights.contains_key(&reporter) {
            return Err(BlockHeightInfoError::UnknownParticipant(reporter));
        }
        self.first_hand_heights.insert(reporter, height);
        Ok(())
    }
    /// The read-only snapshot for readers.
    pub fn broken_connections(&self) -> BrokenNetworkConnections<ParticipantId> {
        self.network_view.broken_connections()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConnectedPeersInfoError {
    #[error("sender {0:?} is not a participant")]
    UnknownSender(ParticipantId),
    #[error("message from {0:?} does not report its own block height")]
    FirstHandAccountMissing(ParticipantId),
    #[error("network view rejected the report from {from:?}")]
    Rejected {
        from: ParticipantId,
        #[source]
        source: AdjacencyMatrixError<ParticipantId>,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlockHeightInfoError {
    #[error("sender {0:?} is not a known participant")]
    UnknownParticipant(ParticipantId),
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

/// Trailing average over the latest present observations.
// todo: also weigh recent interruptions: how often the link was Absent within the window.
impl InferLinkStatus<BlockCount> for MeanBlockLag {
    fn infer_link_status(obs: &RecentObservations<BlockCount>) -> LinkStatus<Self> {
        match obs.newest() {
            LinkObservation::Absent => LinkStatus::Absent,
            LinkObservation::Present(first) => {
                let mut summed = helper::SummedLatencies::new(*first);
                for latency in obs
                    .newest_first()
                    .skip(1)
                    .map_while(LinkObservation::present)
                {
                    summed.add(*latency);
                }
                LinkStatus::Present(summed.average_latency())
            }
        }
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
