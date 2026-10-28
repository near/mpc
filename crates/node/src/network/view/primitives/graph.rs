//! Generic graph bookkeeping: a fixed set of nodes, a fixed set of edges, and a mutable
//! label on every edge.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use derive_more::{AsMut, AsRef, Deref, DerefMut};
use near_mpc_bounded_collections::NonEmptyBTreeSet;

use crate::network::view::primitives::network_view::UnknownLink;

/// todo make a proper type
pub type DirectedGraph<N, L> = Graph<N, DirectedEdge<N>, L>;

#[derive(Deref, DerefMut, AsRef, AsMut)]
pub struct UndirectedGraph<N, L>(Graph<N, UndirectedEdge<N>, L>);

/// Node type `N`, edge type `E`, edge label `L`.
///
/// Invariants, enforced by construction: every edge's endpoints are in `nodes`, and neither
/// the node set nor the edge set changes after construction. Only labels do.
#[derive(Debug, Clone)]
pub struct Graph<N, E, L> {
    nodes: NonEmptyBTreeSet<N>,
    edges: BTreeMap<E, L>,
}

impl<N: Ord + Clone, E: Edge<N>, L> Graph<N, E, L> {
    /// The complete graph over `nodes`: one edge per pair of distinct nodes (per *ordered*
    /// pair if `E` is directed), each labelled by `label`.
    pub fn complete(nodes: NonEmptyBTreeSet<N>, mut label: impl FnMut(&E) -> L) -> Self {
        let mut edges = BTreeMap::new();
        for a in nodes.iter() {
            for b in nodes.iter() {
                if let Some(edge) = E::new(a.clone(), b.clone()) {
                    // An undirected `E` maps (a, b) and (b, a) to the same key: label once.
                    edges.entry(edge).or_insert_with_key(|e| label(e));
                }
            }
        }
        Self { nodes, edges }
    }
}

impl<N, E: Ord, L> Graph<N, E, L> {
    pub fn nodes(&self) -> &NonEmptyBTreeSet<N> {
        &self.nodes
    }

    pub fn label(&self, edge: &E) -> Option<&L> {
        self.edges.get(edge)
    }

    pub fn label_mut(&mut self, edge: &E) -> Option<&mut L> {
        self.edges.get_mut(edge)
    }

    pub fn edges(&self) -> impl Iterator<Item = (&E, &L)> {
        self.edges.iter()
    }
}

/// The one thing a [`Graph`] needs to know about its edge type.
pub trait Edge<N>: Ord + Sized {
    /// The edge between `a` and `b`, or `None` if `a == b` (self-loops are not allowed).
    fn new(a: N, b: N) -> Option<Self>;
    /// Both endpoints. For an undirected edge the order is canonical, not meaningful.
    fn endpoints(&self) -> (&N, &N);
}

/// A link `from -> to`. Invariant: `from != to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DirectedEdge<N> {
    from: N,
    to: N,
}

// todo: fix bounds
impl<N: PartialEq + Ord + Clone> DirectedEdge<N> {
    /// Returns `None` if the edge is a loop.
    pub fn new(from: N, to: N) -> Option<Self> {
        (from != to).then_some(Self { from, to })
    }

    pub fn undirected(&self) -> UndirectedEdge<N> {
        UndirectedEdge::new(self.from.clone(), self.to.clone())
            .expect("By construction, a directed edge must not be a loop.")
    }
}

impl<N: Ord + Clone> Edge<N> for DirectedEdge<N> {
    fn new(from: N, to: N) -> Option<Self> {
        DirectedEdge::new(from, to)
    }

    fn endpoints(&self) -> (&N, &N) {
        (&self.from, &self.to)
    }
}

/// An unordered pair `{lo, hi}`. Invariant: `lo < hi`, so `{a, b}` and `{b, a}` are the
/// same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct UndirectedEdge<N> {
    lo: N,
    hi: N,
}

impl<N: Ord + Clone> UndirectedEdge<N> {
    pub fn new(a: N, b: N) -> Option<Self> {
        match a.cmp(&b) {
            Ordering::Less => Some(Self { lo: a, hi: b }),
            Ordering::Greater => Some(Self { lo: b, hi: a }),
            Ordering::Equal => None,
        }
    }
    pub fn directions(&self) -> (DirectedEdge<N>, DirectedEdge<N>) {
        (
            DirectedEdge {
                from: self.lo.clone(),
                to: self.hi.clone(),
            },
            DirectedEdge {
                from: self.hi.clone(),
                to: self.lo.clone(),
            },
        )
    }
}

impl<N: Ord + Clone> Edge<N> for UndirectedEdge<N> {
    fn new(a: N, b: N) -> Option<Self> {
        UndirectedEdge::new(a, b)
    }

    fn endpoints(&self) -> (&N, &N) {
        (&self.lo, &self.hi)
    }
}

// todo: clean this up
/// Whether a call to [`AdjacencyGraph::set`] changed the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Changed,
    Unchanged,
}

/// Undirected graph over a fixed node set, stored as the upper triangle of its adjacency
/// matrix: the edge `{lo, hi}` is recorded once, as `hi ∈ map[lo]`.
///
/// Invariants: the key set is the node set; `map[n]` only contains nodes greater than `n`
/// (so there are no self-loops and no duplicate representations of an edge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdjacencyGraph<N>(BTreeMap<N, BTreeSet<N>>);

impl<N: Ord + Clone> AdjacencyGraph<N> {
    /// The graph over `nodes` with no edges.
    pub fn edgeless(nodes: &NonEmptyBTreeSet<N>) -> Self {
        let map: BTreeMap<N, BTreeSet<N>> =
            nodes.iter().map(|n| (n.clone(), BTreeSet::new())).collect();
        Self(map)
    }

    /// Adds or removes `edge`.
    pub fn set(&mut self, edge: &UndirectedEdge<N>, present: bool) -> Result<Change, UnknownLink> {
        let (lo, hi) = edge.endpoints();
        if !self.0.contains_key(hi) {
            return Err(UnknownLink);
        }
        let above = self.0.get_mut(lo).ok_or(UnknownLink)?;
        let changed = if present {
            above.insert(hi.clone())
        } else {
            above.remove(hi)
        };
        if changed {
            Ok(Change::Changed)
        } else {
            Ok(Change::Unchanged)
        }
    }

    /// The nodes greater than `n` that `n` has an edge to; `None` if `n` is not a node.
    /// Iterating this over a sorted node set visits every edge exactly once.
    pub fn neighbours_above(&self, n: &N) -> Option<&BTreeSet<N>> {
        self.0.get(n)
    }
}
// todo: tests
