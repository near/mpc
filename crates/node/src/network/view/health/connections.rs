//! todo description

use std::collections::BTreeSet;

use near_mpc_bounded_collections::NonEmptyBTreeSet;

use crate::network::view::graph::{AdjacencyMatrix, UndirectedEdge, UnknownNodeError};
use crate::providers::traits::{CheckReadiness, ComputationDuration, NotReadyError};

/// Keeps track of bidirectional connections in the network
#[derive(Clone)]
pub struct LiveNetworkConnections<N, S> {
    connections: AdjacencyMatrix<N, S, UndirectedEdge<N>>,
}

impl<N: Ord + Clone, S> LiveNetworkConnections<N, S> {
    /// No connection is established yet.
    pub fn new(nodes: &NonEmptyBTreeSet<N>) -> Self {
        Self {
            connections: AdjacencyMatrix::new(nodes),
        }
    }
}

impl<N, S> LiveNetworkConnections<N, S>
where
    N: Ord + Clone,
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

impl<N, S> CheckReadiness for LiveNetworkConnections<N, S>
where
    N: Ord + Clone,
    S: ReportConnectionHealth,
{
    type Node = N;

    fn check_readiness(
        &self,
        nodes: &BTreeSet<N>,
        duration: ComputationDuration,
    ) -> Result<(), NotReadyError<N>> {
        self.connections
            .pairs_within(nodes)
            .map_err(|UnknownNodeError(node)| NotReadyError::UnknownNode(node))?
            .try_for_each(|(connection, status)| {
                match status.map(|s| s.connection_supports(duration)) {
                    Some(ComputationSupported::Yes) => Ok(()),
                    Some(ComputationSupported::No) => Err(NotReadyError::Degraded(connection)),
                    None => Err(NotReadyError::NotConnected(connection)),
                }
            })
    }
}

/// can be used to estimate whether a connection is suffienct for a specific computation duration
pub trait ReportConnectionHealth {
    fn connection_supports(&self, duration: ComputationDuration) -> ComputationSupported;
}

pub enum ComputationSupported {
    Yes,
    No,
}

//// todo: tests
