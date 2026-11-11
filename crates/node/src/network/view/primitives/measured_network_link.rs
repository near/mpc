// todo: doc
//

use std::collections::BTreeMap;

use near_mpc_bounded_collections::NonEmptyBTreeSet;

use near_time::Instant;

use crate::network::view::primitives::{
    adjacency_matrix::AdjacencyMatrix, edge::DirectedEdge, errors::UnknownNodeError,
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

impl<N: Ord + Clone, L, O, S> MeasuredNetworkLinks<N, L>
where
    N: Ord + Clone,
    L: ObserveLinkHealth<Observation = O, LinkStatus = S> + Default + Clone,
{
    /// errors if the nodes are not in the graph
    /// todo: rename to record_link_observation
    pub fn record_observation(
        &mut self,
        link: &DirectedEdge<N>,
        observation: O,
        now: Instant,
    ) -> Result<UpdateResult<S>, UnknownNodeError<N>> {
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
    pub fn status(&self, link: &DirectedEdge<N>) -> Result<Option<S>, UnknownNodeError<N>> {
        Ok(self.measured_network_links.edge(link)?.map(L::link_status))
    }
    fn report_link_statuses(&self) -> NetworkLinkStatuses<N, S> {
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

pub trait ObserveLinkHealth {
    type Observation;
    type LinkStatus;
    fn update_with_observation(
        &mut self,
        observation: Self::Observation,
        at: Instant,
    ) -> UpdateResult<Self::LinkStatus>;
    fn link_status(&self) -> Self::LinkStatus;
}

//// todo: tests
