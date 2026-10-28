//! todo description

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::{collections::BTreeSet, time::Instant};

use near_mpc_bounded_collections::NonEmptyBTreeSet;
use petgraph::{Directed, Undirected};

use crate::network::view::primitives::LinkStatus;
use crate::network::view::primitives::{
    adjacency_matrix::{AdjacencyMatrix, AdjacencyMatrixError},
    measured_network_link::{InferLinkStatus, LinkObservation, MeasuredLink},
};

// todo: maybe split this file?

// todo: rename?
pub struct NetworkConnectionsView<N, S, T> {
    // a link is a directed connection node A --> B,
    // each link is measured, such that we can infer link quality from the measurements.
    measured_links: MeasuredNetworkLinks<N, S, T>,
    // a connection between two nodes is considered broken if one of the two links between the
    // nodes is of insufficient quality, determined by [`NetworkConnectionsView::threshold`]
    broken_connections: BrokenNetworkConnections<N>,
    // highest link state a direction may have a still be considered usable
    threshold: S,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviousViewValidity {
    Superseded,
    Valid,
}

impl<N: Ord + Clone, S: InferLinkStatus<T> + PartialOrd, T> NetworkConnectionsView<N, S, T> {
    /// Records the `reporter`'s observations and updates the status for all connections of
    /// `reporter`.
    /// Returns [`PreviousViewValidity::Superseded`] in case a connection changed status (e.g. one
    /// that used to be online is now broken, or vice-versa).
    /// Errors if the `reporter` observes itself or an unknown node.
    pub fn record_observations_from(
        &mut self,
        reporter: &N,
        observations: BTreeMap<N, LinkObservation<T>>,
    ) -> Result<PreviousViewValidity, AdjacencyMatrixError<N>> {
        let mut validity = PreviousViewValidity::Valid;
        for (origin, observation) in observations {
            self.measured_links
                .record_observation(&origin, reporter, observation)?;
            if self.refresh_connection_status(reporter, &origin)?
                == PreviousViewValidity::Superseded
            {
                validity = PreviousViewValidity::Superseded;
            }
        }
        Ok(validity)
    }

    /// The read-only snapshot for readers.
    pub fn broken_connections(&self) -> BrokenNetworkConnections<N> {
        self.broken_connections.clone()
    }

    /// errors if from == to or if the nodes are not in the graph
    fn refresh_connection_status(
        &mut self,
        a: &N,
        b: &N,
    ) -> Result<PreviousViewValidity, AdjacencyMatrixError<N>> {
        let a_to_b = self.measured_links.link_quality(a, b, &self.threshold)?;
        let b_to_a = self.measured_links.link_quality(b, a, &self.threshold)?;

        let connection_status = match (a_to_b, b_to_a) {
            (LinkQuality::InsufficientOrBroken, _) => ConnectionStatus::InsufficientOrBroken,
            (_, LinkQuality::InsufficientOrBroken) => ConnectionStatus::InsufficientOrBroken,
            _ => ConnectionStatus::LiveOrUnknown,
        };
        self.broken_connections.set(a, b, connection_status)
    }

    pub fn link_report(&self) -> LinkReport<N, S>
    where
        S: Clone,
    {
        self.measured_links.report()
    }
}

enum ConnectionStatus {
    LiveOrUnknown,
    InsufficientOrBroken,
}

impl<N: Ord + Clone, S, T> NetworkConnectionsView<N, S, T> {
    /// A view over `nodes` with no observations yet.
    ///
    /// Panics if there are more nodes than `NodeIndex` can address (65,535).
    pub fn new(nodes: &NonEmptyBTreeSet<N>, window: NonZeroUsize, threshold: S) -> Self {
        let measured_links = MeasuredNetworkLinks::new(nodes, window);
        let broken_connections = BrokenNetworkConnections::new(nodes);
        Self {
            measured_links,
            broken_connections,
            threshold,
        }
    }
}

/// Every directed link's [`MeasuredLink`], stored as an adjacency matrix.
pub struct MeasuredNetworkLinks<N, S, T> {
    measured_network_links: AdjacencyMatrix<N, MeasuredLink<S, T>, Directed>,
    measurement_window: NonZeroUsize,
}

impl<N: Ord + Clone, S, T> MeasuredNetworkLinks<N, S, T> {
    pub fn new(nodes: &NonEmptyBTreeSet<N>, measurement_window: NonZeroUsize) -> Self {
        let measured_network_links = AdjacencyMatrix::new(nodes);
        Self {
            measured_network_links,
            measurement_window,
        }
    }
}

impl<N: Ord + Clone, S: InferLinkStatus<T>, T> MeasuredNetworkLinks<N, S, T> {
    /// errors if from == to or if the nodes are not in the graph
    pub fn record_observation(
        &mut self,
        from: &N,
        to: &N,
        observation: LinkObservation<T>,
    ) -> Result<(), AdjacencyMatrixError<N>> {
        match self.measured_network_links.edge_mut(from, to)? {
            Some(link) => link.add_observation(observation),
            None => {
                let link = MeasuredLink::new(self.measurement_window, observation);
                self.measured_network_links.set_edge(from, to, link)?;
            }
        }
        Ok(())
    }

    /// errors if from == to or if the nodes are not in the graph
    pub fn link_quality(
        &self,
        from: &N,
        to: &N,
        threshold: &S,
    ) -> Result<LinkQuality, AdjacencyMatrixError<N>>
    where
        S: PartialOrd,
    {
        let Some(measured_link) = self.measured_network_links.edge(from, to)? else {
            // an unknown link status is treated as usable
            return Ok(LinkQuality::Unmeasured);
        };
        if measured_link
            .status()
            .is_absent_or_exceeds_threshold(threshold)
        {
            Ok(LinkQuality::InsufficientOrBroken)
        } else {
            Ok(LinkQuality::Sufficient)
        }
    }
    pub fn report(&self) -> LinkReport<N, S>
    where
        S: Clone,
    {
        LinkReport {
            taken_at: Instant::now(),
            links: self
                .measured_network_links
                .edges()
                .map(|(from, to, link)| LinkEntry {
                    from: from.clone(),
                    to: to.clone(),
                    status: link.status().clone(),
                })
                .collect(),
        }
    }
}

/// Every measured link's current status, sampled at one point in time.
/// Links with no observations yet are not included.
#[derive(Debug, Clone)]
pub struct LinkReport<N, S> {
    pub taken_at: Instant,
    pub links: Vec<LinkEntry<N, S>>,
}

#[derive(Debug, Clone)]
pub struct LinkEntry<N, S> {
    pub from: N,
    pub to: N,
    pub status: LinkStatus<S>,
}

enum LinkQuality {
    Unmeasured,
    Sufficient,
    InsufficientOrBroken,
}

#[derive(Clone)]
pub struct BrokenNetworkConnections<N> {
    broken_connections: AdjacencyMatrix<N, (), Undirected>,
}

impl<N: Ord + Clone> BrokenNetworkConnections<N> {
    pub fn new(nodes: &NonEmptyBTreeSet<N>) -> Self {
        Self {
            broken_connections: AdjacencyMatrix::new(nodes),
        }
    }

    pub fn can_compute_with(
        &self,
        nodes: &BTreeSet<N>,
    ) -> Result<(), NetworkConnectionsViewError<N>> {
        match self.broken_connections.find_edge_within(nodes)? {
            None => Ok(()),
            Some((p, q)) => Err(NetworkConnectionsViewError::BrokenConnection(
                p.clone(),
                q.clone(),
            )),
        }
    }

    fn set(
        &mut self,
        a: &N,
        b: &N,
        status: ConnectionStatus,
    ) -> Result<PreviousViewValidity, AdjacencyMatrixError<N>> {
        let changed = match status {
            ConnectionStatus::InsufficientOrBroken => {
                self.broken_connections.set_edge(a, b, ())?.is_none()
            }
            ConnectionStatus::LiveOrUnknown => self.broken_connections.remove_edge(a, b)?.is_some(),
        };
        if changed {
            Ok(PreviousViewValidity::Superseded)
        } else {
            Ok(PreviousViewValidity::Valid)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetworkConnectionsViewError<N> {
    #[error(transparent)]
    Participants(#[from] AdjacencyMatrixError<N>),
    #[error("connection between {0:?} and {1:?} is not usable")]
    BrokenConnection(N, N),
}

// todo tests
