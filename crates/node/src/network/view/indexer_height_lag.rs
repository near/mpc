use near_block_primitives::BlockCount;

use crate::network::view::{
    first_hand_indexer_heights::ReportedIndexerHeight,
    primitives::LinkObservation,
    view_manager::{IndexerHeightReport, IntoLinkObservation, ObservationContext},
};

pub enum IndexerHeightLag {
    Present(BlockCount),
    Absent,
}

impl IndexerHeightLag {
    fn new(
        first_hand_indexer_height: ReportedIndexerHeight,
        peer_reported_height: Option<ReportedIndexerHeight>,
    ) -> Option<Self> {
        let Some(peer_reported) = peer_reported_height else {
            return Some(IndexerHeightLag::Absent);
        };
        match (first_hand_indexer_height, peer_reported) {
            (ReportedIndexerHeight::Unknown, _) => None,
            (_, ReportedIndexerHeight::Unknown) => None,
            (
                ReportedIndexerHeight::Known(first_hand),
                ReportedIndexerHeight::Known(peer_reported),
            ) => {
                let count = first_hand.blocks_since(peer_reported);
                Some(IndexerHeightLag::Present(count))
            }
        }
    }
}

impl<N: Ord + Clone> IntoLinkObservation<N, IndexerHeightReport<N>> for IndexerHeightLag {
    fn into_link_observation(
        update: &IndexerHeightReport<N>,
        context: &ObservationContext<'_, N>,
    ) -> Vec<LinkObservation<N, Self>> {
        let IndexerHeightReport {
            reporter,
            indexer_heights,
        } = update;
        let mut res = Vec::new();
        for (my_peer, &first_hand) in context.first_hand_indexer_heights.iter() {
            if my_peer == reporter {
                continue;
            }
            let peer_reported_height = indexer_heights.get(my_peer);
            let Some(observation) =
                IndexerHeightLag::new(first_hand, peer_reported_height.copied())
            else {
                continue;
            };
            res.push(LinkObservation {
                from: my_peer.clone(),
                to: reporter.clone(),
                observation,
            });
        }
        res
    }
}
