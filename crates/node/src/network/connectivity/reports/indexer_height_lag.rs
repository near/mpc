use std::collections::BTreeMap;

use near_block_primitives::BlockCount;

use crate::network::connectivity::{
    first_hand_indexer_heights::ReportedIndexerHeight,
    graph::DirectedEdge,
    health::LinkObservation,
    reports::{DeriveLinkObservations, ObservationContext},
};

/// How far a reporter's height for a peer trails our first-hand height for that peer, or
/// `Absent` if the reporter does not list the peer.
///
/// Measures delay only between peers we still hear from. Once a peer's own reports stop
/// reaching us, our first-hand height for it freezes and the lag reads as zero, so a silent
/// peer looks healthy here.
pub enum IndexerHeightLag {
    Present(BlockCount),
    /// The reporter lists the peer, but a height is unknown, so there is no lag.
    Unknown,
    Absent,
}

pub struct IndexerHeightReport<N> {
    pub reporter: N,
    pub indexer_heights: BTreeMap<N, ReportedIndexerHeight>,
}
// todo: remove, with its `PeerReport` variant and the fallback to `IndexerHeightMessage` in
// `broadcast_connected_peers_info`: peers below `Oct2026` are no longer supported. A peer that
// only sends this report never gets a connection.
pub struct LegacyIndexerHeightReport<N> {
    pub reporter: N,
    pub indexer_height: ReportedIndexerHeight,
}

impl IndexerHeightLag {
    fn new(
        first_hand_indexer_height: ReportedIndexerHeight,
        peer_reported_height: Option<ReportedIndexerHeight>,
    ) -> Self {
        let Some(peer_reported) = peer_reported_height else {
            return IndexerHeightLag::Absent;
        };
        match (first_hand_indexer_height, peer_reported) {
            (ReportedIndexerHeight::Unknown, _) => IndexerHeightLag::Unknown,
            (_, ReportedIndexerHeight::Unknown) => IndexerHeightLag::Unknown,
            (
                ReportedIndexerHeight::Known(first_hand),
                ReportedIndexerHeight::Known(peer_reported),
            ) => {
                let count = first_hand
                    .blocks_since(peer_reported)
                    .unwrap_or(BlockCount::new(0));
                IndexerHeightLag::Present(count)
            }
        }
    }
}

impl<N: Ord + Clone> DeriveLinkObservations<N> for IndexerHeightReport<N> {
    type Observation = IndexerHeightLag;

    fn derive_link_observations(
        &self,
        context: &ObservationContext<'_, N>,
    ) -> Vec<LinkObservation<N, IndexerHeightLag>> {
        let IndexerHeightReport {
            reporter,
            indexer_heights,
        } = self;
        let mut res = Vec::new();
        for (my_peer, &first_hand) in context.first_hand_indexer_heights.iter() {
            let Ok(link) = DirectedEdge::new(my_peer.clone(), reporter.clone()) else {
                continue;
            };
            let peer_reported_height = indexer_heights.get(my_peer);
            let observation = IndexerHeightLag::new(first_hand, peer_reported_height.copied());
            res.push(LinkObservation { link, observation });
        }
        res
    }
}
