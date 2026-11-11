
mod indexer_height_lag;

pub use indexer_height_lag::{IndexerHeightLag, IndexerHeightReport, LegacyIndexerHeightReport};

use crate::network::connectivity::{
    first_hand_indexer_heights::FirstHandIndexerHeights, health::LinkObservation,
};

pub struct ObservationContext<'a, N> {
    pub first_hand_indexer_heights: &'a FirstHandIndexerHeights<N>,
}

/// Implemented by a report type: the link observations derived from it.
pub trait DeriveLinkObservations<N> {
    type Observation;
    fn derive_link_observations(
        &self,
        context: &ObservationContext<'_, N>,
    ) -> Vec<LinkObservation<N, Self::Observation>>;
}

pub enum PeerReport<N> {
    LegacyIndexerHeightReport(LegacyIndexerHeightReport<N>),
    IndexerHeightReport(IndexerHeightReport<N>),
}
