use std::{cmp::Ordering, fmt};

use crate::network::connectivity::graph::{adjacency_matrix::AddressEdge, errors::SameNodeError};

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
    const DIRECTED: bool = false;

    fn endpoints(&self) -> (&N, &N) {
        (&self.low, &self.high)
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
#[derive(Clone)]
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
    const DIRECTED: bool = true;

    fn endpoints(&self) -> (&N, &N) {
        (&self.from, &self.to)
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

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use rstest::rstest;

    use super::{DirectedEdge, UndirectedEdge};
    use crate::network::connectivity::graph::{
        adjacency_matrix::AddressEdge, errors::SameNodeError,
    };

    #[test]
    fn undirected_edge_new__should_ignore_node_order() {
        // Given
        let (a, b) = (1, 2);

        // When
        let edge = UndirectedEdge::new(a, b);
        let swapped = UndirectedEdge::new(b, a);

        // Then
        assert_eq!(edge, swapped);
    }

    #[test]
    fn undirected_edge_new__should_reject_identical_nodes() {
        // Given
        let node = 1;

        // When
        let result = UndirectedEdge::new(node, node);

        // Then
        assert_eq!(result, Err(SameNodeError(node)));
    }

    #[test]
    fn undirected_edge_to_string__should_name_lower_node_first() {
        // Given
        let edge = UndirectedEdge::new(2, 1).expect("nodes must be distinct");

        // When
        let displayed = edge.to_string();

        // Then
        assert_eq!(displayed, "1 <-> 2");
    }

    #[rstest]
    #[case::ascending(1, 2)]
    #[case::descending(2, 1)]
    fn undirected_edge_from_directed_edge__should_drop_direction(
        #[case] from: u32,
        #[case] to: u32,
    ) {
        // Given
        let directed = DirectedEdge::new(from, to).expect("nodes must be distinct");

        // When
        let undirected = UndirectedEdge::from(directed);

        // Then
        assert_eq!(UndirectedEdge::new(1, 2), Ok(undirected));
    }

    #[test]
    fn directed_edge_new__should_reject_identical_nodes() {
        // Given
        let node = 1;

        // When
        let error = DirectedEdge::new(node, node).err();

        // Then
        assert_eq!(error, Some(SameNodeError(node)));
    }

    #[test]
    fn directed_edge_reversed__should_swap_endpoints() {
        // Given
        let edge = DirectedEdge::new(1, 2).expect("nodes must be distinct");

        // When
        let reversed = edge.reversed();

        // Then
        assert_eq!(reversed.endpoints(), (&2, &1));
    }
}
