//! todo description

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::num::NonZeroUsize;

use near_mpc_bounded_collections::NonEmptyBTreeSet;
use near_time::Instant;
use petgraph::{Directed, Undirected};

use crate::network::view::primitives::LinkStatus;
use crate::network::view::primitives::{
    adjacency_matrix::{AdjacencyMatrix, AdjacencyMatrixError},
    measured_network_link::{InferLinkStatus, LinkObservation, MeasuredLink},
};

// todo: maybe split this file?

pub struct MeasuredNetworkConnections<N, S, T> {
    // a link is a directed connection node A --> B,
    // each link is measured, such that we can infer link quality from the measurements.
    measured_links: MeasuredNetworkLinks<N, S, T>,
    // a connection between two nodes is as good as the worse of the two links between them
    connections: UsableNetworkConnections<N>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviousViewValidity {
    Superseded,
    Valid,
}

impl<N: Ord + Clone, S: InferLinkStatus<T> + GradeLink, T> MeasuredNetworkConnections<N, S, T> {
    /// Records the `reporter`'s observations and updates the status for all connections of
    /// `reporter`.
    /// Returns [`PreviousViewValidity::Superseded`] in case a connection changed status (e.g. one
    /// that used to be online is now broken, or vice-versa).
    /// Errors if the `reporter` observes itself or an unknown node.
    pub fn record_observations_from(
        &mut self,
        reporter: &N,
        observations: BTreeMap<N, LinkObservation<T>>,
        now: Instant,
    ) -> Result<PreviousViewValidity, AdjacencyMatrixError<N>> {
        let mut validity = PreviousViewValidity::Valid;
        for (origin, observation) in observations {
            if self.record_link_observation(&origin, reporter, observation, now)?
                == PreviousViewValidity::Superseded
            {
                validity = PreviousViewValidity::Superseded;
            }
        }
        Ok(validity)
    }

    fn record_link_observation(
        &mut self,
        origin: &N,
        receiver: &N,
        observation: LinkObservation<T>,
        now: Instant,
    ) -> Result<PreviousViewValidity, AdjacencyMatrixError<N>> {
        self.measured_links
            .record_observation(origin, receiver, observation, now)?;
        self.refresh_connection_status(origin, receiver)
    }

    /// The read-only snapshot for readers.
    pub fn usable_connections(&self) -> UsableNetworkConnections<N> {
        self.connections.clone()
    }

    /// errors if from == to or if the nodes are not in the graph
    fn refresh_connection_status(
        &mut self,
        a: &N,
        b: &N,
    ) -> Result<PreviousViewValidity, AdjacencyMatrixError<N>> {
        let a_to_b = ConnectionStatus::from(self.measured_links.link_status(a, b)?);
        let b_to_a = ConnectionStatus::from(self.measured_links.link_status(b, a)?);
        self.connections.set(a, b, a_to_b.min(b_to_a))
    }

    pub fn link_report(&self, now: Instant) -> LinkReport<N, S>
    where
        S: Clone,
    {
        self.measured_links.report(now)
    }
}

/// Uninterrupted presence a computation requires of a connection.
///
/// The tiers mirror today's consumers, signatures finishing within seconds and triple generation
/// within half a minute, and sit in this generic layer only to keep the connection matrix free of
/// a type parameter. Refactor or replace them when the consumers' needs change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Uptime {
    Any,
    Seconds,
    HalfMinute,
}

pub enum LinkSpeed {
    TooSlow,
    Up(Uptime),
}

pub trait GradeLink {
    fn grade(&self) -> LinkSpeed;
}

/// Ordered worst to best, so a pair's status is the `min` of its two directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConnectionStatus {
    Broken,
    Slow,
    Live(Uptime),
    Unknown,
}

impl ConnectionStatus {
    /// `Unknown` satisfies every uptime: a connection nobody measured yet is not held against.
    pub fn satisfies(self, required_uptime: Uptime) -> bool {
        match self {
            Self::Unknown => true,
            Self::Live(reached) => reached >= required_uptime,
            Self::Slow | Self::Broken => false,
        }
    }
}

/// `None` is an unmeasured direction, which imposes no limit.
impl<S: GradeLink> From<Option<&LinkStatus<S>>> for ConnectionStatus {
    fn from(link: Option<&LinkStatus<S>>) -> Self {
        link.map_or(Self::Unknown, Self::from)
    }
}

impl<S: GradeLink> From<&LinkStatus<S>> for ConnectionStatus {
    fn from(status: &LinkStatus<S>) -> Self {
        match status {
            LinkStatus::Absent => Self::Broken,
            LinkStatus::Present(status) => status.grade().into(),
        }
    }
}

impl From<LinkSpeed> for ConnectionStatus {
    fn from(speed: LinkSpeed) -> Self {
        match speed {
            LinkSpeed::TooSlow => Self::Slow,
            LinkSpeed::Up(uptime) => Self::Live(uptime),
        }
    }
}

impl<N: Ord + Clone, S, T> MeasuredNetworkConnections<N, S, T> {
    /// A view over `nodes` with no observations yet.
    ///
    /// Panics if there are more nodes than `NodeIndex` can address (65,535).
    pub fn new(nodes: &NonEmptyBTreeSet<N>, window: NonZeroUsize) -> Self {
        let measured_links = MeasuredNetworkLinks::new(nodes, window);
        let connections = UsableNetworkConnections::new(nodes);
        Self {
            measured_links,
            connections,
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
        now: Instant,
    ) -> Result<(), AdjacencyMatrixError<N>> {
        match self.measured_network_links.edge_mut(from, to)? {
            Some(link) => link.add_observation(observation, now),
            None => {
                let link = MeasuredLink::new(self.measurement_window, observation, now);
                self.measured_network_links.set_edge(from, to, link)?;
            }
        }
        Ok(())
    }

    /// `None` if the link has no observations yet; errors if from == to or if the nodes are not in
    /// the graph.
    pub fn link_status(
        &self,
        from: &N,
        to: &N,
    ) -> Result<Option<&LinkStatus<S>>, AdjacencyMatrixError<N>> {
        Ok(self
            .measured_network_links
            .edge(from, to)?
            .map(MeasuredLink::status))
    }
    pub fn report(&self, now: Instant) -> LinkReport<N, S>
    where
        S: Clone,
    {
        LinkReport {
            taken_at: now,
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

/// Every pair's [`ConnectionStatus`], `Unknown` until measured.
#[derive(Clone)]
pub struct UsableNetworkConnections<N> {
    connections: AdjacencyMatrix<N, ConnectionStatus, Undirected>,
}

impl<N: Ord + Clone> UsableNetworkConnections<N> {
    pub fn new(nodes: &NonEmptyBTreeSet<N>) -> Self {
        Self {
            connections: AdjacencyMatrix::complete(nodes, ConnectionStatus::Unknown),
        }
    }

    pub fn are_connected(&self, a: &N, b: &N, required_uptime: Uptime) -> bool {
        matches!(self.connections.edge(a, b), Ok(Some(status)) if status.satisfies(required_uptime))
    }

    pub fn usable_from(
        &self,
        node: &N,
        required_uptime: Uptime,
    ) -> Result<BTreeSet<N>, AdjacencyMatrixError<N>> {
        Ok(self
            .connections
            .edges_from(node)?
            .filter(|(_, status)| status.satisfies(required_uptime))
            .map(|(peer, _)| peer.clone())
            .collect())
    }

    pub fn can_compute_with(
        &self,
        nodes: &BTreeSet<N>,
        required_uptime: Uptime,
    ) -> Result<(), MeasuredNetworkConnectionsError<N>> {
        let unusable = |status: Option<&ConnectionStatus>| {
            !status.is_some_and(|status| status.satisfies(required_uptime))
        };
        match self.connections.find_pair_within(nodes, unusable)? {
            None => Ok(()),
            Some((p, q)) => Err(MeasuredNetworkConnectionsError::BrokenConnection(
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
        let previous = self.connections.set_edge(a, b, status)?;
        if previous == Some(status) {
            Ok(PreviousViewValidity::Valid)
        } else {
            Ok(PreviousViewValidity::Superseded)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MeasuredNetworkConnectionsError<N> {
    #[error(transparent)]
    Participants(#[from] AdjacencyMatrixError<N>),
    #[error("connection between {0:?} and {1:?} is not usable")]
    BrokenConnection(N, N),
}

// todo tests
