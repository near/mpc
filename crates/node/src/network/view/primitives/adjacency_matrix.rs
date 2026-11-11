use itertools::Itertools;
use std::{collections::BTreeMap, hash::RandomState};

use near_mpc_bounded_collections::{NonEmptyBTreeMap, NonEmptyBTreeSet};
use petgraph::{
    EdgeType,
    matrix_graph::{MatrixGraph, NodeIndex},
    visit::IntoEdgeReferences,
};

use crate::network::view::primitives::{edge::UndirectedEdge, errors::UnknownNodeError};

// todo: make a trait for the stuff our consumer needs.

/// A `MatrixGraph` over a fixed node set, addressed by node id instead of `NodeIndex`.
/// Loops are not allowed.
#[derive(Clone)]
pub struct AdjacencyMatrix<N, E, K> {
    nodes: NonEmptyBTreeMap<N, NodeIndex>,
    matrix: MatrixGraph<N, E, RandomState, K>,
}

impl<N: Ord + Clone, E, K: AddressEdge<N>> AdjacencyMatrix<N, E, K> {
    /// No edges. Panics above 65,535 nodes.
    pub fn new(nodes: &NonEmptyBTreeSet<N>) -> Self {
        let mut matrix = MatrixGraph::with_capacity(nodes.len());
        let nodes = nodes
            .iter()
            .map(|id| (id.clone(), matrix.add_node(id.clone())))
            .collect::<BTreeMap<_, _>>()
            .try_into()
            .expect("a non-empty participant set yields a non-empty map");
        Self { nodes, matrix }
    }

    fn node_indices(&self, edge: &K) -> Result<(NodeIndex, NodeIndex), UnknownNodeError<N>> {
        let (a, b) = edge.endpoints();
        Ok((self.index(a)?, self.index(b)?))
    }

    /// `None` if the graph has no such edge.
    pub fn edge(&self, edge: &K) -> Result<Option<&E>, UnknownNodeError<N>> {
        let (i, j) = self.node_indices(edge)?;
        Ok(self.matrix.get_edge_weight(i, j))
    }

    /// `None` if the graph has no such edge.
    pub fn edge_mut(&mut self, edge: &K) -> Result<Option<&mut E>, UnknownNodeError<N>> {
        let (i, j) = self.node_indices(edge)?;
        Ok(self.matrix.get_edge_weight_mut(i, j))
    }

    /// Adds or replaces the edge; returns the previous weight, if any.
    pub fn set_edge(&mut self, edge: &K, weight: E) -> Result<Option<E>, UnknownNodeError<N>> {
        let (i, j) = self.node_indices(edge)?;
        Ok(self.matrix.update_edge(i, j, weight))
    }

    /// Every node sharing an edge with `node`, with that edge's weight.
    pub fn edges_from(
        &self,
        node: &N,
    ) -> Result<impl Iterator<Item = (&N, &E)>, UnknownNodeError<N>> {
        let i = self.index(node)?;
        Ok(self
            .matrix
            .edges(i)
            .map(|(_, j, weight)| (self.matrix.node_weight(j), weight)))
    }

    fn index(&self, node: &N) -> Result<NodeIndex, UnknownNodeError<N>> {
        self.nodes
            .get(node)
            .copied()
            .ok_or(UnknownNodeError(node.clone()))
    }
}

impl<N, E, K: EdgeType> AdjacencyMatrix<N, E, K> {
    pub fn edges(&self) -> impl Iterator<Item = (&N, &N, &E)> {
        self.matrix
            .edge_references()
            .map(|(i, j, e)| (self.matrix.node_weight(i), self.matrix.node_weight(j), e))
    }
}

impl<N: Ord + Clone, E> AdjacencyMatrix<N, E, UndirectedEdge<N>> {
    /// Every pair of nodes connected with `weight`. Panics above 65,535 nodes.
    pub fn complete(nodes: &NonEmptyBTreeSet<N>, weight: E) -> Self
    where
        E: Clone,
    {
        let mut this = Self::new(nodes);
        let indices: Vec<NodeIndex> = this.nodes.values().copied().collect();
        let mut rest = indices.as_slice();
        while let Some((&i, tail)) = rest.split_first() {
            for &j in tail {
                this.matrix.update_edge(i, j, weight.clone());
            }
            rest = tail;
        }
        this
    }

    /// Every edge among `nodes`, with its weight (`None` for no edge).
    /// Errors if any node is not in the graph.
    pub fn pairs_within<'a>(
        &'a self,
        nodes: impl IntoIterator<Item = &'a N>,
    ) -> Result<impl Iterator<Item = (UndirectedEdge<N>, Option<&'a E>)> + 'a, UnknownNodeError<N>>
    {
        let indexed = nodes
            .into_iter()
            .map(|node| Ok((node, self.index(node)?)))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(indexed
            .into_iter()
            .array_combinations::<2>()
            .filter_map(move |[(a, i), (b, j)]| {
                let edge = UndirectedEdge::new(a.clone(), b.clone()).ok()?;
                Some((edge, self.matrix.get_edge_weight(i, j)))
            }))
    }
}

/// An edge type that can address an [`AdjacencyMatrix`] over nodes `N`.
pub trait AddressEdge<N>: EdgeType {
    fn endpoints(&self) -> (&N, &N);
}
