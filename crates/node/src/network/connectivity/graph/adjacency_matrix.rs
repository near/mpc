use itertools::Itertools;
use std::{
    collections::{BTreeSet, HashMap},
    hash::{Hash, RandomState},
};

use near_mpc_bounded_collections::NonEmptyBTreeSet;
use petgraph::{
    EdgeType,
    matrix_graph::{MatrixGraph, NodeIndex},
    visit::{IntoEdgeReferences, IntoNodeIdentifiers},
};

use crate::network::connectivity::graph::{
    edge::UndirectedEdge,
    errors::{TooManyNodesError, UnknownNodeError},
};

/// A [`MatrixGraph`] over a fixed node set, addressed by node id instead of [`NodeIndex`].
/// Loops are not allowed.
#[derive(Clone)]
pub struct AdjacencyMatrix<N, E, K> {
    nodes: HashMap<N, NodeIndex>,
    matrix: MatrixGraph<N, E, RandomState, K>,
}

impl<N: Hash + Eq + Clone, E, K: AddressEdge<N>> AdjacencyMatrix<N, E, K> {
    /// No edges. Errors above 65,535 nodes. O(V²) time and memory for `V` nodes.
    pub fn new(nodes: &NonEmptyBTreeSet<N>) -> Result<Self, TooManyNodesError> {
        if nodes.len() > usize::from(u16::MAX) {
            return Err(TooManyNodesError(nodes.len()));
        }
        let mut matrix = MatrixGraph::with_capacity(nodes.len());
        let nodes = nodes
            .iter()
            .map(|id| (id.clone(), matrix.add_node(id.clone())))
            .collect();
        Ok(Self { nodes, matrix })
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

    /// Removes the edge; returns its weight, if there was one.
    pub fn remove_edge(&mut self, edge: &K) -> Result<Option<E>, UnknownNodeError<N>> {
        let (i, j) = self.node_indices(edge)?;
        Ok(self.matrix.try_remove_edge(i, j))
    }

    /// Each neighbor of `node`, with the weight of the edge to it. In a directed graph, only
    /// edges starting at `node` count.
    /// Scans the whole row of `node`: O(V) for `V` nodes, even when `node` has few edges.
    pub fn edges_from<'a>(
        &'a self,
        node: &N,
    ) -> Result<impl Iterator<Item = (&'a N, &'a E)> + use<'a, N, E, K>, UnknownNodeError<N>> {
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
    /// Each edge once. A directed edge `a --> b` comes out as `(a, b, weight)`.
    /// For an undirected edge either node may come first.
    /// Scans the whole matrix: O(V²) for `V` nodes, even when there are few edges.
    pub fn edges(&self) -> impl Iterator<Item = (&N, &N, &E)> {
        self.matrix
            .edge_references()
            .map(|(i, j, e)| (self.matrix.node_weight(i), self.matrix.node_weight(j), e))
    }
}

impl<N: Ord + Hash + Clone, E> AdjacencyMatrix<N, E, UndirectedEdge<N>> {
    /// Every pair of nodes, with the weight of the edge between them (`None` for no edge).
    pub fn pairs(&self) -> impl Iterator<Item = (UndirectedEdge<N>, Option<&E>)> + '_ {
        let nodes = self
            .matrix
            .node_identifiers()
            .map(|i| (self.matrix.node_weight(i), i));
        self.pairs_among(nodes)
    }

    /// Every pair among `nodes`, with the weight of the edge between them (`None` for no edge).
    /// Errors if any node is not in the graph.
    pub fn pairs_within<'a>(
        &'a self,
        nodes: &BTreeSet<N>,
    ) -> Result<
        impl Iterator<Item = (UndirectedEdge<N>, Option<&'a E>)> + use<'a, N, E>,
        UnknownNodeError<N>,
    > {
        let nodes = nodes
            .iter()
            .map(|node| {
                let i = self.index(node)?;
                Ok((self.matrix.node_weight(i), i))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self.pairs_among(nodes))
    }

    fn pairs_among<'a>(
        &'a self,
        nodes: impl IntoIterator<Item = (&'a N, NodeIndex)> + 'a,
    ) -> impl Iterator<Item = (UndirectedEdge<N>, Option<&'a E>)> + 'a {
        nodes
            .into_iter()
            .array_combinations::<2>()
            .filter_map(move |[(a, i), (b, j)]| {
                let edge = UndirectedEdge::new(a.clone(), b.clone()).ok()?;
                Some((edge, self.matrix.get_edge_weight(i, j)))
            })
    }
}

/// An edge type that can address an [`AdjacencyMatrix`] over nodes `N`.
pub trait AddressEdge<N>: EdgeType {
    fn endpoints(&self) -> (&N, &N);
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::collections::BTreeSet;

    use super::{AddressEdge, AdjacencyMatrix};
    use crate::network::connectivity::graph::{
        edge::{DirectedEdge, UndirectedEdge},
        errors::{TooManyNodesError, UnknownNodeError},
    };

    type DirectedGraph = AdjacencyMatrix<u32, &'static str, DirectedEdge<u32>>;
    type UndirectedGraph = AdjacencyMatrix<u32, &'static str, UndirectedEdge<u32>>;

    const UNKNOWN_NODE: u32 = 9;

    fn make_graph<K: AddressEdge<u32>>(
        edges: impl IntoIterator<Item = (K, &'static str)>,
    ) -> AdjacencyMatrix<u32, &'static str, K> {
        let nodes = BTreeSet::from([1, 2, 3, 4])
            .try_into()
            .expect("node set must be non-empty");
        let mut graph = AdjacencyMatrix::new(&nodes).expect("node count must be within the limit");
        for (edge, weight) in edges {
            graph
                .set_edge(&edge, weight)
                .expect("edge nodes must be in the graph");
        }
        graph
    }

    fn make_directed_edge(from: u32, to: u32) -> DirectedEdge<u32> {
        DirectedEdge::new(from, to).expect("nodes must be distinct")
    }

    fn make_undirected_edge(a: u32, b: u32) -> UndirectedEdge<u32> {
        UndirectedEdge::new(a, b).expect("nodes must be distinct")
    }

    #[test]
    fn new__should_reject_more_than_u16_max_nodes() {
        // Given
        let nodes = (0..=u32::from(u16::MAX))
            .collect::<BTreeSet<_>>()
            .try_into()
            .expect("node set must be non-empty");

        // When
        let error = DirectedGraph::new(&nodes).err();

        // Then
        assert_eq!(error, Some(TooManyNodesError(65_536)));
    }

    #[test]
    fn set_edge__should_replace_weight_and_return_previous() {
        // Given
        let mut graph: DirectedGraph = make_graph([]);
        let edge = make_directed_edge(1, 2);

        // When
        let added = graph.set_edge(&edge, "old");
        let replaced = graph.set_edge(&edge, "new");

        // Then
        assert_eq!(added, Ok(None));
        assert_eq!(replaced, Ok(Some("old")));
        assert_eq!(graph.edge(&edge), Ok(Some(&"new")));
    }

    #[test]
    fn set_edge__should_keep_opposite_direction_unset_in_directed_graph() {
        // Given
        let mut graph: DirectedGraph = make_graph([]);

        // When
        graph
            .set_edge(&make_directed_edge(1, 2), "forward")
            .expect("nodes must be in the graph");

        // Then
        assert_eq!(graph.edge(&make_directed_edge(2, 1)), Ok(None));
    }

    #[test]
    fn edge_mut__should_allow_changing_weight_in_place() {
        // Given
        let edge = make_directed_edge(1, 2);
        let mut graph = make_graph([(make_directed_edge(1, 2), "old")]);

        // When
        let weight = graph
            .edge_mut(&edge)
            .expect("nodes must be in the graph")
            .expect("edge must exist");
        *weight = "new";

        // Then
        assert_eq!(graph.edge(&edge), Ok(Some(&"new")));
    }

    #[test]
    fn remove_edge__should_return_removed_weight() {
        // Given
        let edge = make_undirected_edge(1, 2);
        let mut graph = make_graph([(make_undirected_edge(1, 2), "weight")]);

        // When
        let removed = graph.remove_edge(&edge);

        // Then
        assert_eq!(removed, Ok(Some("weight")));
        assert_eq!(graph.edge(&edge), Ok(None));
    }

    #[test]
    fn remove_edge__should_return_none_without_edge() {
        // Given
        let mut graph: UndirectedGraph = make_graph([]);

        // When
        let removed = graph.remove_edge(&make_undirected_edge(1, 2));

        // Then
        assert_eq!(removed, Ok(None));
    }

    #[test]
    fn edges__should_yield_directed_edges_from_source_to_target() {
        // Given
        let graph = make_graph([
            (make_directed_edge(1, 2), "a"),
            (make_directed_edge(3, 1), "b"),
        ]);

        // When
        let edges: BTreeSet<_> = graph.edges().collect();

        // Then
        assert_eq!(edges, BTreeSet::from([(&1, &2, &"a"), (&3, &1, &"b")]));
    }

    #[test]
    fn edges__should_yield_each_undirected_edge_once() {
        // Given
        let graph = make_graph([
            (make_undirected_edge(1, 2), "a"),
            (make_undirected_edge(2, 3), "b"),
        ]);

        // When
        let mut edges: Vec<_> = graph
            .edges()
            .map(|(a, b, weight)| (a.min(b), a.max(b), weight))
            .collect();
        edges.sort();

        // Then
        assert_eq!(edges, [(&1, &2, &"a"), (&2, &3, &"b")]);
    }

    #[test]
    fn edges_from__should_yield_only_outgoing_edges_in_directed_graph() {
        // Given
        let graph = make_graph([
            (make_directed_edge(1, 2), "outgoing"),
            (make_directed_edge(3, 1), "incoming"),
        ]);

        // When
        let edges: Vec<_> = graph
            .edges_from(&1)
            .expect("node must be in the graph")
            .collect();

        // Then
        assert_eq!(edges, [(&2, &"outgoing")]);
    }

    #[test]
    fn edges_from__should_yield_every_incident_edge_in_undirected_graph() {
        // Given
        let graph = make_graph([
            (make_undirected_edge(1, 2), "a"),
            (make_undirected_edge(2, 3), "b"),
        ]);

        // When
        let edges: BTreeSet<_> = graph
            .edges_from(&2)
            .expect("node must be in the graph")
            .collect();

        // Then
        assert_eq!(edges, BTreeSet::from([(&1, &"a"), (&3, &"b")]));
    }

    #[test]
    fn pairs__should_yield_every_pair_of_nodes() {
        // Given
        let graph = make_graph([(make_undirected_edge(1, 2), "connected")]);

        // When
        let pairs: Vec<_> = graph.pairs().collect();

        // Then
        assert_eq!(
            pairs,
            [
                (make_undirected_edge(1, 2), Some(&"connected")),
                (make_undirected_edge(1, 3), None),
                (make_undirected_edge(1, 4), None),
                (make_undirected_edge(2, 3), None),
                (make_undirected_edge(2, 4), None),
                (make_undirected_edge(3, 4), None),
            ]
        );
    }

    #[test]
    fn pairs_within__should_yield_every_pair_of_the_given_nodes() {
        // Given
        let graph = make_graph([
            (make_undirected_edge(1, 2), "inside"),
            (make_undirected_edge(3, 4), "outside"),
        ]);
        let nodes = BTreeSet::from([1, 2, 3]);

        // When
        let pairs: Vec<_> = graph
            .pairs_within(&nodes)
            .expect("nodes must be in the graph")
            .collect();

        // Then
        assert_eq!(
            pairs,
            [
                (make_undirected_edge(1, 2), Some(&"inside")),
                (make_undirected_edge(1, 3), None),
                (make_undirected_edge(2, 3), None),
            ]
        );
    }

    #[test]
    fn adjacency_matrix__should_reject_unknown_nodes() {
        // Given
        let mut graph: UndirectedGraph = make_graph([]);
        let edge = make_undirected_edge(1, UNKNOWN_NODE);
        let nodes = BTreeSet::from([1, UNKNOWN_NODE]);

        // When
        let errors = [
            graph.edge(&edge).err(),
            graph.edge_mut(&edge).err(),
            graph.set_edge(&edge, "weight").err(),
            graph.remove_edge(&edge).err(),
            graph.edges_from(&UNKNOWN_NODE).err(),
            graph.pairs_within(&nodes).err(),
        ];

        // Then
        assert_eq!(errors, [Some(UnknownNodeError(UNKNOWN_NODE)); 6]);
    }
}
