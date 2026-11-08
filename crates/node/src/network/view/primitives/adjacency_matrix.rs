use std::{collections::BTreeMap, hash::RandomState};

use near_mpc_bounded_collections::{NonEmptyBTreeMap, NonEmptyBTreeSet};
use petgraph::{
    EdgeType, Undirected,
    matrix_graph::{MatrixGraph, NodeIndex},
    visit::{IntoEdgeReferences, IntoEdges},
};

/// A `MatrixGraph` over a fixed node set, addressed by node id instead of `NodeIndex`.
/// Loops are not allowed.
#[derive(Clone)]
pub struct AdjacencyMatrix<N, E, Ty> {
    nodes: NonEmptyBTreeMap<N, NodeIndex>,
    matrix: MatrixGraph<N, E, RandomState, Ty>,
}

impl<N: Ord + Clone, E, Ty: EdgeType> AdjacencyMatrix<N, E, Ty> {
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

    /// Indices of `a` and `b`; an error if either is unknown or they are the same node.
    fn node_indices(
        &self,
        a: &N,
        b: &N,
    ) -> Result<(NodeIndex, NodeIndex), AdjacencyMatrixError<N>> {
        if a == b {
            return Err(AdjacencyMatrixError::Loop(a.clone()));
        }
        let a = self.index(a)?;
        let b = self.index(b)?;
        Ok((a, b))
    }

    /// The first pair among `nodes` whose edge weight, `None` for no edge, satisfies `predicate`.
    /// Ids are translated once; the pair loop runs on indices.
    pub fn find_pair_within<'a>(
        &self,
        nodes: impl IntoIterator<Item = &'a N>,
        mut predicate: impl FnMut(Option<&E>) -> bool,
    ) -> Result<Option<(&'a N, &'a N)>, AdjacencyMatrixError<N>>
    where
        N: 'a,
    {
        let mut indexed = Vec::new();
        for node in nodes {
            let idx = self.index(node)?;
            indexed.push((node, idx));
        }
        let mut rest = indexed.as_slice();
        while let Some((&(p, i), tail)) = rest.split_first() {
            for &(q, j) in tail {
                if predicate(self.matrix.get_edge_weight(i, j)) {
                    return Ok(Some((p, q)));
                }
            }
            rest = tail;
        }
        Ok(None)
    }

    /// `None` if there is no edge between `a` and `b`.
    pub fn edge(&self, a: &N, b: &N) -> Result<Option<&E>, AdjacencyMatrixError<N>> {
        let (i, j) = self.node_indices(a, b)?;
        Ok(self.matrix.get_edge_weight(i, j))
    }

    /// `None` if there is no edge between `a` and `b`.
    pub fn edge_mut(&mut self, a: &N, b: &N) -> Result<Option<&mut E>, AdjacencyMatrixError<N>> {
        let (i, j) = self.node_indices(a, b)?;
        Ok(self.matrix.get_edge_weight_mut(i, j))
    }

    pub fn edge_mut_or_insert_with(
        &mut self,
        a: &N,
        b: &N,
        insert: impl FnOnce() -> E,
    ) -> Result<&mut E, AdjacencyMatrixError<N>> {
        let (i, j) = self.node_indices(a, b)?;
        if !self.matrix.has_edge(i, j) {
            self.matrix.add_edge(i, j, insert());
        }
        Ok(self.matrix.edge_weight_mut(i, j))
    }

    /// Adds or replaces the edge; returns the previous weight, if any.
    pub fn set_edge(
        &mut self,
        a: &N,
        b: &N,
        weight: E,
    ) -> Result<Option<E>, AdjacencyMatrixError<N>> {
        let (i, j) = self.node_indices(a, b)?;
        Ok(self.matrix.update_edge(i, j, weight))
    }

    /// Every node sharing an edge with `node`, with that edge's weight.
    pub fn edges_from(
        &self,
        node: &N,
    ) -> Result<impl Iterator<Item = (&N, &E)>, AdjacencyMatrixError<N>> {
        let i = self.index(node)?;
        Ok(self
            .matrix
            .edges(i)
            .map(|(_, j, weight)| (self.matrix.node_weight(j), weight)))
    }

    fn index(&self, node: &N) -> Result<NodeIndex, AdjacencyMatrixError<N>> {
        self.nodes
            .get(node)
            .copied()
            .ok_or(AdjacencyMatrixError::UnknownNode(node.clone()))
    }
}

impl<N: Ord + Clone, E: Clone> AdjacencyMatrix<N, E, Undirected> {
    /// Every pair of nodes connected with `weight`. Panics above 65,535 nodes.
    pub fn complete(nodes: &NonEmptyBTreeSet<N>, weight: E) -> Self {
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
}

impl<N, E, Ty: EdgeType> AdjacencyMatrix<N, E, Ty> {
    pub fn edges(&self) -> impl Iterator<Item = (&N, &N, &E)> {
        self.matrix
            .edge_references()
            .map(|(i, j, e)| (self.matrix.node_weight(i), self.matrix.node_weight(j), e))
    }
}

/// Why an operation on an `AdjacencyMatrix` could not be carried out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AdjacencyMatrixError<N> {
    #[error("node {0:?} is not part of the network")]
    UnknownNode(N),
    #[error("this adjacency matrix does not support loops (node {0:?})")]
    Loop(N),
}
