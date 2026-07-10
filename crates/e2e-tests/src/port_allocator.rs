use test_port_allocator::PortAllocationScheme;

/// Deterministic port allocator for E2E tests.
///
/// Each test gets a unique `test_id`. All ports are computed from it to avoid
/// collisions when tests run in parallel via `cargo nextest`.
///
/// Layout per test:
///   - 2 cluster-level ports (NEAR sandbox RPC/network)
///   - 8 ports per node * MAX_NODES
///
/// The offset arithmetic is delegated to [`PortAllocationScheme`]; this type only
/// assigns semantics to each offset.
#[derive(Debug, Clone)]
pub struct E2ePortAllocator {
    test_id: u16,
}

impl E2ePortAllocator {
    const BASE_PORT: u16 = test_port_allocator::E2E_PORT_BASE;
    const PORTS_PER_NODE: u16 = 8;
    const MAX_NODES: u16 = 10;
    /// Cluster-level ports that are not per-node.
    const CLUSTER_PORTS: u16 = 2;

    /// Base 20000 stays disjoint from `PortSeed` (10000+) and
    /// `test_port_allocator::reserve_port` (40000+).
    const SCHEME: PortAllocationScheme = PortAllocationScheme::new(
        Self::BASE_PORT,
        Self::CLUSTER_PORTS,
        Self::PORTS_PER_NODE,
        Self::MAX_NODES,
    );

    pub const fn new(test_id: u16) -> Self {
        Self { test_id }
    }

    // -- Cluster-level ports --

    pub fn near_node_rpc_port(&self) -> u16 {
        Self::SCHEME.cluster_port(self.test_id, 0)
    }

    pub fn near_node_network_port(&self) -> u16 {
        Self::SCHEME.cluster_port(self.test_id, 1)
    }

    // -- Per-node ports --

    pub fn p2p_port(&self, node_index: usize) -> u16 {
        Self::SCHEME.node_port(self.test_id, node_index, 0)
    }

    pub fn web_ui_port(&self, node_index: usize) -> u16 {
        Self::SCHEME.node_port(self.test_id, node_index, 1)
    }

    pub fn migration_web_ui_port(&self, node_index: usize) -> u16 {
        Self::SCHEME.node_port(self.test_id, node_index, 2)
    }

    pub fn pprof_port(&self, node_index: usize) -> u16 {
        Self::SCHEME.node_port(self.test_id, node_index, 3)
    }

    pub fn near_rpc_port(&self, node_index: usize) -> u16 {
        Self::SCHEME.node_port(self.test_id, node_index, 4)
    }

    pub fn near_network_port(&self, node_index: usize) -> u16 {
        Self::SCHEME.node_port(self.test_id, node_index, 5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(non_snake_case)]
    fn port_accessors__should_compute_ports_at_expected_offsets() {
        // Given a known test id
        // When reading each accessor
        // Then each returns its port at the expected offset (base 20000, 2 cluster + 8/node)
        let a = E2ePortAllocator::new(1);
        assert_eq!(a.near_node_rpc_port(), 20082);
        assert_eq!(a.near_node_network_port(), 20083);
        assert_eq!(a.p2p_port(0), 20084);
        assert_eq!(a.web_ui_port(0), 20085);
        assert_eq!(a.migration_web_ui_port(0), 20086);
        assert_eq!(a.pprof_port(0), 20087);
        assert_eq!(a.near_rpc_port(0), 20088);
        assert_eq!(a.near_network_port(0), 20089);
    }

    #[test]
    #[expect(non_snake_case)]
    fn port_allocation__should_not_overlap_between_tests() {
        // Given two adjacent test ids
        // When comparing the last port of test 0 to the first of test 1
        // Then the ranges are disjoint
        let a = E2ePortAllocator::new(0);
        let b = E2ePortAllocator::new(1);
        let a_last = a.near_network_port(E2ePortAllocator::MAX_NODES as usize - 1);
        let b_first = b.near_node_rpc_port();
        assert!(a_last < b_first, "{a_last} >= {b_first}");
    }

    #[test]
    #[expect(non_snake_case)]
    fn port_allocation__should_not_overlap_between_nodes() {
        // Given two adjacent nodes in one test
        // When comparing the last port of node 0 to the first of node 1
        // Then the ranges are disjoint
        let a = E2ePortAllocator::new(0);
        assert!(a.near_network_port(0) < a.p2p_port(1));
    }
}
