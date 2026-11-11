// todo: doc
//

use std::collections::BTreeMap;

use near_mpc_bounded_collections::NonEmptyBTreeSet;

use near_time::Instant;

use crate::network::connectivity::graph::{AdjacencyMatrix, DirectedEdge, UnknownNodeError};

pub struct LinkStatuses<N, S>(BTreeMap<(N, N), S>);
impl<N: Ord, S> FromIterator<((N, N), S)> for LinkStatuses<N, S> {
    fn from_iter<I: IntoIterator<Item = ((N, N), S)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

pub struct LinkMeasurements<N, L> {
    measurements: AdjacencyMatrix<N, L, DirectedEdge<N>>,
}

impl<N: Ord + Clone, L> LinkMeasurements<N, L> {
    pub fn new(nodes: &NonEmptyBTreeSet<N>) -> Self {
        Self {
            measurements: AdjacencyMatrix::new(nodes),
        }
    }
}

pub struct LinkObservation<N, O> {
    pub link: DirectedEdge<N>,
    pub observation: O,
}

impl<N: Ord + Clone, L> LinkMeasurements<N, L> {
    /// errors if the nodes are not in the graph
    /// todo: rename to record_link_observation
    pub fn record_observation<O>(
        &mut self,
        link: &DirectedEdge<N>,
        observation: O,
        now: Instant,
    ) -> Result<LinkStatusChange<L::LinkStatus>, UnknownNodeError<N>>
    where
        L: UpdateLinkStatus<O>,
    {
        let status_change = match self.measurements.edge_mut(link)? {
            Some(measurement) => measurement.update_with_observation(observation, now),
            None => {
                let mut measurement = L::default();
                let status_change = measurement.update_with_observation(observation, now);
                self.measurements.set_edge(link, measurement)?;
                status_change
            }
        };
        Ok(status_change)
    }
    /// `None` if the link has no observations yet; errors if the nodes are not in the graph.
    pub fn status(
        &self,
        link: &DirectedEdge<N>,
    ) -> Result<Option<L::LinkStatus>, UnknownNodeError<N>>
    where
        L: ReportLinkStatus,
    {
        Ok(self.measurements.edge(link)?.map(L::link_status))
    }
    fn report_link_statuses(&self) -> LinkStatuses<N, L::LinkStatus>
    where
        L: ReportLinkStatus,
    {
        self.measurements
            .edges()
            .map(|(from, to, link)| ((from.clone(), to.clone()), link.link_status()))
            .collect()
    }
}

pub enum LinkStatusChange<S> {
    // status changed, contained is the new status
    Changed(S),
    Unchanged,
}

/// Implemented once per kind of observation `O` a link can take in.
pub trait UpdateLinkStatus<O>: ReportLinkStatus + Default {
    fn update_with_observation(
        &mut self,
        observation: O,
        at: Instant,
    ) -> LinkStatusChange<Self::LinkStatus>;
}

pub trait ReportLinkStatus {
    type LinkStatus;
    fn link_status(&self) -> Self::LinkStatus;
}

//// todo: tests
