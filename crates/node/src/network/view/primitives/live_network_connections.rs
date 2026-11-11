//! todo description

use std::collections::BTreeSet;

use near_mpc_bounded_collections::NonEmptyBTreeSet;

use crate::network::view::primitives::adjacency_matrix::AdjacencyMatrix;
use crate::network::view::primitives::edge::UndirectedEdge;
use crate::network::view::primitives::errors::UnknownNodeError;
use crate::network::view::primitives::measured_network_link::UpdateResult;
use crate::providers::traits::{CheckReadiness, ComputationDuration, NotReadyError};

/// Keeps track of bidirectional connections in the network
#[derive(Clone)]
pub struct LiveNetworkConnections<N, S> {
    connections: AdjacencyMatrix<N, S, UndirectedEdge<N>>,
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
        connection: &UndirectedEdge<N>,
        status: S,
    ) -> Result<UpdateResult<S>, UnknownNodeError<N>> {
        let previous = self.connections.set_edge(connection, status.clone())?;
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
    type LinkStatus;
    fn connection_supports(&self, duration: ComputationDuration) -> ComputationSupported;
}

pub enum ComputationSupported {
    Yes,
    No,
}

//// todo: tests
