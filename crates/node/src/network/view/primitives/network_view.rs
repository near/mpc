//! todo description

use std::collections::BTreeSet;
use std::num::NonZeroUsize;

use near_mpc_bounded_collections::{NonEmptyBTreeMap, NonEmptyBTreeSet};

use crate::network::view::primitives::graph::{
    AdjacencyGraph, DirectedEdge, DirectedGraph, UndirectedEdge,
};
use crate::network::view::primitives::measured_network_link::{
    InferLinkStatus, LinkObservation, LinkStatus, MeasuredLink,
};

/// Every node, mapped to the nodes it has no usable connection with.
pub struct BrokenConnections<N>(NonEmptyBTreeMap<N, BTreeSet<N>>);

impl<N: Ord + Clone + std::fmt::Debug> BrokenConnections<N> {
    pub fn can_compute_with(&self, participants: &BTreeSet<N>) -> Result<(), CannotCompute<N>> {
        for p in participants {
            let broken = self
                .0
                .get(p)
                .ok_or_else(|| CannotCompute::UnknownNode(p.clone()))?;
            if let Some(q) = broken.iter().find(|q| participants.contains(q)) {
                return Err(CannotCompute::BrokenConnection(p.clone(), q.clone()));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct NetworkView<N, S, T> {
    network_links: DirectedGraph<N, MeasuredLink<S, T>>,
    broken_connections: AdjacencyGraph<N>,
    threshold: S,
}

// todo: nicer Bounds

impl<N, S, T> NetworkView<N, S, T>
where
    N: Ord + Clone,
    S: InferLinkStatus<T> + PartialOrd,
{
    pub fn nodes(&self) -> &NonEmptyBTreeSet<N> {
        self.network_links.nodes()
    }
    pub fn new(nodes: NonEmptyBTreeSet<N>, window: NonZeroUsize, threshold: S) -> Self {
        let broken_connections = AdjacencyGraph::edgeless(&nodes);
        Self {
            network_links: DirectedGraph::complete(nodes, |_| MeasuredLink::new(window)),
            broken_connections,
            threshold,
        }
    }
    pub fn record(
        &mut self,
        link: &DirectedEdge<N>,
        observation: LinkObservation<T>,
    ) -> Result<(), UnknownLink> {
        self.network_links
            .label_mut(link)
            .ok_or(UnknownLink)?
            .add_observation(observation);
        self.refresh_connection_status(link.undirected());
        Ok(())
    }
    /// Status of one direction of a link; `None` if the link is not part of the network.
    pub fn link_status(&self, link: &DirectedEdge<N>) -> Option<&LinkStatus<S>> {
        self.network_links.label(link).map(|link| link.status())
    }

    /// Re-derives the cache entry for one connection after one of its directions changed.
    fn refresh_connection_status(&mut self, connection: UndirectedEdge<N>) -> super::graph::Change {
        let (ab, ba) = connection.directions();
        let broken = !(self.direction_usable(&ab) && self.direction_usable(&ba));
        self.broken_connections
            .set(&connection, broken)
            .expect("shared nodes, must not fail")
    }

    fn direction_usable(&self, link: &DirectedEdge<N>) -> bool {
        self.network_links
            .label(link)
            .expect("complete graph: every link between nodes of the network exists")
            .status()
            .usable(&self.threshold)
    }
}

/// The link's endpoints are not both nodes of this network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("link is not part of the network")]
pub struct UnknownLink;

/// Why a set of nodes cannot compute together. Reports the first problem found.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CannotCompute<N> {
    #[error("node {0:?} is not part of the network")]
    UnknownNode(N),
    #[error("connection between {0:?} and {1:?} is not usable")]
    BrokenConnection(N, N),
}

// todo tests
