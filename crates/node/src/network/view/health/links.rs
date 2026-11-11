// todo: doc
//

use std::collections::BTreeMap;

use near_mpc_bounded_collections::NonEmptyBTreeSet;

use near_time::Instant;

use crate::network::view::{
    graph::{AdjacencyMatrix, DirectedEdge, UnknownNodeError},
    health::connections::InferredConnection,
};

pub struct NetworkLinkStatuses<N, S>(BTreeMap<(N, N), S>);
impl<N: Ord, S> FromIterator<((N, N), S)> for NetworkLinkStatuses<N, S> {
    fn from_iter<I: IntoIterator<Item = ((N, N), S)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

pub struct MeasuredNetworkLinks<N, L> {
    measured_network_links: AdjacencyMatrix<N, L, DirectedEdge<N>>,
}

impl<N: Ord + Clone, L> MeasuredNetworkLinks<N, L> {
    pub fn new(nodes: &NonEmptyBTreeSet<N>) -> Self {
        Self {
            measured_network_links: AdjacencyMatrix::new(nodes),
        }
    }
}

pub struct LinkObservation<N, O> {
    pub link: DirectedEdge<N>,
    pub observation: O,
}

impl<N: Ord + Clone, L> MeasuredNetworkLinks<N, L> {
    /// errors if the nodes are not in the graph
    /// todo: rename to record_link_observation
    pub fn record_observation<U>(
        &mut self,
        link: &DirectedEdge<N>,
        observation: L::Observation,
        now: Instant,
    ) -> Result<UpdateResult<L::LinkStatus>, UnknownNodeError<N>>
    where
        L: UpdateLinkStatus<U>,
    {
        let update_result = match self.measured_network_links.edge_mut(link)? {
            Some(measured_link) => measured_link.update_with_observation(observation, now),
            None => {
                let mut measured_link = L::default();
                let new_status = measured_link.update_with_observation(observation, now);
                self.measured_network_links.set_edge(link, measured_link)?;
                new_status
            }
        };
        Ok(update_result)
    }
    /// `None` if the link has no observations yet; errors if the nodes are not in the graph.
    pub fn status(
        &self,
        link: &DirectedEdge<N>,
    ) -> Result<Option<L::LinkStatus>, UnknownNodeError<N>>
    where
        L: ReportLinkStatus,
    {
        Ok(self.measured_network_links.edge(link)?.map(L::link_status))
    }
    fn report_link_statuses(&self) -> NetworkLinkStatuses<N, L::LinkStatus>
    where
        L: ReportLinkStatus,
    {
        self.measured_network_links
            .edges()
            .map(|(from, to, link)| ((from.clone(), to.clone()), link.link_status()))
            .collect()
    }
}

pub enum UpdateResult<S> {
    // status changed, contained is the new status
    StatusChanged(S),
    StatusRemained,
}

/// Implemented once per kind of update `U` a link can take evidence from.
pub trait UpdateLinkStatus<U>: ReportLinkStatus + Default {
    type Observation;
    fn update_with_observation(
        &mut self,
        observation: Self::Observation,
        at: Instant,
    ) -> UpdateResult<Self::LinkStatus>;
}

pub trait InferConnectionStatus: ReportLinkStatus {
    type ConnectionStatus;
    /// The connection that the two links between a pair of nodes add up to. A link is `None`
    /// while it has no observations.
    fn infer_connection_status(
        a: Option<Self::LinkStatus>,
        b: Option<Self::LinkStatus>,
    ) -> InferredConnection<Self::ConnectionStatus>;
}

pub trait ReportLinkStatus {
    type LinkStatus;
    fn link_status(&self) -> Self::LinkStatus;
}

//// todo: tests
