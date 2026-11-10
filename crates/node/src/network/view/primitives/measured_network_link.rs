// todo: doc
//

use std::collections::BTreeMap;

use near_mpc_bounded_collections::NonEmptyBTreeSet;

use near_time::Instant;
use petgraph::Directed;

use crate::network::view::primitives::adjacency_matrix::{
    AdjacencyMatrix, AdjacencyMatrixError, UnknownNodeError,
};

pub struct NetworkLinkStatuses<N, S>(BTreeMap<(N, N), S>);
impl<N: Ord, S> FromIterator<((N, N), S)> for NetworkLinkStatuses<N, S> {
    fn from_iter<I: IntoIterator<Item = ((N, N), S)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

pub struct MeasuredNetworkLinks<N, L> {
    measured_network_links: AdjacencyMatrix<N, L, Directed>,
}

impl<N: Ord + Clone, L> MeasuredNetworkLinks<N, L> {
    pub fn new(nodes: &NonEmptyBTreeSet<N>) -> Self {
        Self {
            measured_network_links: AdjacencyMatrix::new(nodes),
        }
    }
}

pub struct LinkObservation<N, O> {
    pub from: N,
    pub to: N,
    pub observation: O,
}

impl<N: Ord + Clone, L, O, S> MeasuredNetworkLinks<N, L>
where
    N: Ord + Clone,
    L: ObserveLinkHealth<Observation = O, LinkStatus = S> + Default + Clone,
{
    /// errors if from == to or if the nodes are not in the graph
    /// todo: rename to record_link_observation
    pub fn record_observation(
        &mut self,
        from: &N,
        to: &N,
        observation: O,
        now: Instant,
    ) -> Result<UpdateResult<S>, MeasuredNetworkLinkError<N>> {
        let update_result = match self.measured_network_links.edge_mut(from, to)? {
            Some(link) => link.update_with_observation(observation, now),
            None => {
                let mut link = L::default();
                let new_status = link.update_with_observation(observation, now);
                self.measured_network_links.set_edge(from, to, link)?;
                new_status
            }
        };
        Ok(update_result)
    }
    /// `None` if the link has no observations yet; errors if from == to or if the nodes are not in
    /// the graph.
    pub fn status(&self, from: &N, to: &N) -> Result<Option<S>, MeasuredNetworkLinkError<N>> {
        Ok(self
            .measured_network_links
            .edge(from, to)?
            .map(L::link_status))
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

/// Why an operation on a measured network link could not be carried out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MeasuredNetworkLinkError<N> {
    #[error(transparent)]
    UnknownNodeError(#[from] UnknownNodeError<N>),
    #[error("node {0:?} can't link to itself")]
    Loop(N),
}
impl<N> From<AdjacencyMatrixError<N>> for MeasuredNetworkLinkError<N> {
    fn from(err: AdjacencyMatrixError<N>) -> Self {
        match err {
            AdjacencyMatrixError::UnknownNodeError(n) => Self::UnknownNodeError(n),
            AdjacencyMatrixError::Loop(n) => Self::Loop(n),
        }
    }
}

//// todo: tests
