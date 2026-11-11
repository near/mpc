
mod indexer_height_lag;

pub use indexer_height_lag::{IndexerHeightLag, IndexerHeightReport, LegacyIndexerHeightReport};

use crate::network::view::{
    first_hand_indexer_heights::FirstHandIndexerHeights, health::LinkObservation,
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

pub enum NetworkViewUpdate<N> {
    LegacyIndexerHeightReport(LegacyIndexerHeightReport<N>),
    IndexerHeightReport(IndexerHeightReport<N>),
}
