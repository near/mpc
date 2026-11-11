use std::{cmp::Ordering, fmt};

use petgraph::EdgeType;

use crate::network::view::graph::{adjacency_matrix::AddressEdge, errors::SameNodeError};

/// An edge between two distinct nodes of an undirected graph. The order the nodes are given in
/// does not matter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndirectedEdge<N> {
    low: N,
    high: N,
}

impl<N: Ord> UndirectedEdge<N> {
    pub fn new(a: N, b: N) -> Result<Self, SameNodeError<N>> {
        match a.cmp(&b) {
            Ordering::Less => Ok(Self { low: a, high: b }),
            Ordering::Greater => Ok(Self { low: b, high: a }),
            Ordering::Equal => Err(SameNodeError(a)),
        }
    }
}

impl<N> AddressEdge<N> for UndirectedEdge<N> {
    fn endpoints(&self) -> (&N, &N) {
        (&self.low, &self.high)
    }
}

impl<N> EdgeType for UndirectedEdge<N> {
    fn is_directed() -> bool {
        false
    }
}

impl<N: fmt::Debug> fmt::Display for UndirectedEdge<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} <-> {:?}", self.low, self.high)
    }
}

impl<N: Ord> From<DirectedEdge<N>> for UndirectedEdge<N> {
    fn from(DirectedEdge { from, to }: DirectedEdge<N>) -> Self {
        let (low, high) = if from < to { (from, to) } else { (to, from) };
        Self { low, high }
    }
}

/// An edge `from --> to` between two distinct nodes of a directed graph.
pub struct DirectedEdge<N> {
    from: N,
    to: N,
}

impl<N: PartialEq> DirectedEdge<N> {
    pub fn new(from: N, to: N) -> Result<Self, SameNodeError<N>> {
        if from == to {
            return Err(SameNodeError(from));
        }
        Ok(Self { from, to })
    }
}

impl<N> AddressEdge<N> for DirectedEdge<N> {
    fn endpoints(&self) -> (&N, &N) {
        (&self.from, &self.to)
    }
}

impl<N> EdgeType for DirectedEdge<N> {
    fn is_directed() -> bool {
        true
    }
}

impl<N: Clone> DirectedEdge<N> {
    /// The edge `to --> from`.
    pub fn reversed(&self) -> Self {
        Self {
            from: self.to.clone(),
            to: self.from.clone(),
        }
    }
}
