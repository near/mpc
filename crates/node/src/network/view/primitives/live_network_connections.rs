//! todo description

use std::collections::BTreeSet;

use near_mpc_bounded_collections::NonEmptyBTreeSet;
use petgraph::Undirected;

use crate::network::view::primitives::adjacency_matrix::UnknownNodeError;
use crate::network::view::primitives::adjacency_matrix::{AdjacencyMatrix, AdjacencyMatrixError};
use crate::network::view::primitives::measured_network_link::UpdateResult;
use crate::providers::traits::{CheckReadiness, ComputationDuration, NotReadyError};

/// Keeps track of bidirectional connections in the network
#[derive(Clone)]
pub struct LiveNetworkConnections<N, S> {
    connections: AdjacencyMatrix<N, S, Undirected>,
}

impl<N, S> LiveNetworkConnections<N, S>
where
    N: Ord + Clone,
    S: Default + Clone,
{
    pub fn new(nodes: &NonEmptyBTreeSet<N>) -> Self {
        Self {
            connections: AdjacencyMatrix::complete(nodes, S::default()),
        }
    }
}

impl<N, S> LiveNetworkConnections<N, S>
where
    N: Ord + Clone,
    S: PartialEq + Clone,
{
    pub fn update_connection(
        &mut self,
        a: &N,
        b: &N,
        status: S,
    ) -> Result<UpdateResult<S>, LiveNetworkConnectionTrackerError<N>> {
        let previous = self.connections.set_edge(a, b, status.clone())?;
        if previous.as_ref() == Some(&status) {
            Ok(UpdateResult::StatusRemained)
        } else {
            Ok(UpdateResult::StatusChanged(status))
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
            .try_for_each(
                |(a, b, status)| match status.map(|s| s.connection_supports(duration)) {
                    Some(ComputationSupported::Yes) => Ok(()),
                    Some(ComputationSupported::No) => Err(NotReadyError::Degraded {
                        a: a.clone(),
                        b: b.clone(),
                    }),
                    None => Err(NotReadyError::NotConnected {
                        a: a.clone(),
                        b: b.clone(),
                    }),
                },
            )
    }
}

/// can be used to estimate whether a connection is suffienct for a specific computation duration
pub trait ReportConnectionHealth {
    type LinkStatus;
    fn connection_supports(&self, duration: ComputationDuration) -> ComputationSupported;
}

pub enum ComputationSupported {
    Yes,
    No,
}

// todo: naming should be consistent
/// Why an operation on an `AdjacencyMatrix` could not be carried out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LiveNetworkConnectionTrackerError<N> {
    #[error(transparent)]
    UnknownNodeError(#[from] UnknownNodeError<N>),
    #[error("Nodes should not connect with themselves (node {0:?})")]
    Loop(N),
}

impl<N> From<AdjacencyMatrixError<N>> for LiveNetworkConnectionTrackerError<N> {
    fn from(value: AdjacencyMatrixError<N>) -> Self {
        match value {
            AdjacencyMatrixError::UnknownNodeError(node) => {
                LiveNetworkConnectionTrackerError::UnknownNodeError(node)
            }
            AdjacencyMatrixError::Loop(node) => LiveNetworkConnectionTrackerError::Loop(node),
        }
    }
}
//// todo: tests
