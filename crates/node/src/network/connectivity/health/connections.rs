//! todo description

use std::{collections::BTreeSet, hash::Hash};

use near_mpc_bounded_collections::NonEmptyBTreeSet;
use near_time::Instant;

use crate::network::connectivity::graph::{
    AdjacencyMatrix, TooManyNodesError, UndirectedEdge, UnknownNodeError,
};
use crate::providers::participant_selection::ComputationDuration;

/// Keeps track of bidirectional connections in the network
#[derive(Clone)]
pub struct EstablishedConnections<N, S> {
    connections: AdjacencyMatrix<N, S, UndirectedEdge<N>>,
}

impl<N: Ord + Hash + Clone, S> EstablishedConnections<N, S> {
    /// No connection is established yet.
    pub fn new(nodes: &NonEmptyBTreeSet<N>) -> Result<Self, TooManyNodesError> {
        Ok(Self {
            connections: AdjacencyMatrix::new(nodes)?,
        })
    }
}

impl<N, S> EstablishedConnections<N, S>
where
    N: Ord + Hash + Clone,
    S: PartialEq,
{
    pub fn update_connection(
        &mut self,
        connection: &UndirectedEdge<N>,
        inferred: InferredConnection<S>,
    ) -> Result<ConnectionChanged, UnknownNodeError<N>> {
        if self.connections.edge(connection)? == inferred.status() {
            return Ok(ConnectionChanged::No);
        }
        match inferred {
            InferredConnection::Established(status) => {
                self.connections.set_edge(connection, status)?;
            }
            InferredConnection::NotEstablished => {
                self.connections.remove_edge(connection)?;
            }
        }
        Ok(ConnectionChanged::Yes)
    }
}

/// Whether an update changed the connection it was applied to.
pub enum ConnectionChanged {
    Yes,
    No,
}

/// What two link statuses add up to: a connection with a status, or no connection.
pub enum InferredConnection<S> {
    Established(S),
    NotEstablished,
}

impl<S> InferredConnection<S> {
    fn status(&self) -> Option<&S> {
        match self {
            Self::Established(status) => Some(status),
            Self::NotEstablished => None,
        }
    }
}

impl<N, S> EstablishedConnections<N, S>
where
    N: Ord + Hash + Clone,
    S: CheckComputationSupport,
{
    /// Whether `nodes` can currently run a computation of `duration` together.
    /// Errors only if a node in `nodes` is not part of the network.
    pub fn check_readiness(
        &self,
        nodes: &BTreeSet<N>,
        duration: ComputationDuration,
        now: Instant,
    ) -> Result<(), NotReadyError<N>> {
        self.connections
            .pairs_within(nodes)?
            .try_for_each(|(connection, status)| {
                match status.map(|s| s.connection_supports(duration, now)) {
                    Some(ComputationSupported::Yes) => Ok(()),
                    Some(ComputationSupported::No) => Err(NotReadyError::Degraded(connection)),
                    None => Err(NotReadyError::NotConnected(connection)),
                }
            })
    }

    /// Every pair of nodes that cannot currently run a computation of `duration` together:
    /// their connection is not established, or does not support it.
    pub fn connections_not_supporting(
        &self,
        duration: ComputationDuration,
        now: Instant,
    ) -> BTreeSet<UndirectedEdge<N>> {
        self.connections
            .pairs()
            .filter(|(_, status)| {
                !matches!(
                    status.map(|s| s.connection_supports(duration, now)),
                    Some(ComputationSupported::Yes)
                )
            })
            .map(|(connection, _)| connection)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotReadyError<N> {
    #[error(transparent)]
    UnknownNode(#[from] UnknownNodeError<N>),
    #[error("connection {0} is not established")]
    NotConnected(UndirectedEdge<N>),
    #[error("connection {0} is too degraded for this computation")]
    Degraded(UndirectedEdge<N>),
}

/// can be used to estimate whether a connection is suffienct for a specific computation duration
pub trait CheckComputationSupport {
    fn connection_supports(
        &self,
        duration: ComputationDuration,
        now: Instant,
    ) -> ComputationSupported;
}

pub enum ComputationSupported {
    Yes,
    No,
}

//// todo: tests
