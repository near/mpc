use test_port_allocator::{PortAllocationScheme, TestPorts};

/// Deterministic port allocator for E2E tests.
///
/// Each test gets a unique `test_id`. All ports are computed from it to avoid
/// collisions when tests run in parallel via `cargo nextest`.
///
/// Layout per test:
///   - 2 cluster-level ports (NEAR sandbox RPC/network)
///   - 8 ports per node * MAX_NODES
#[derive(Copy, Clone, Debug)]
pub struct E2ePortAllocator {
    ports: TestPorts,
}

impl E2ePortAllocator {
    pub const MAX_NODES: u16 = 10;

    const SCHEME: PortAllocationScheme = PortAllocationScheme {
        base: test_port_allocator::E2E_PORT_BASE,
        cluster_ports: 2,
        ports_per_node: 8,
        max_nodes: Self::MAX_NODES,
        space_end: test_port_allocator::RESERVE_RANGE_START,
    };

    pub const fn new(test_id: u16) -> Self {
        Self {
            ports: TestPorts::new(Self::SCHEME, test_id),
        }
    }

    // -- Cluster-level ports --

    pub fn near_node_rpc_port(&self) -> u16 {
        self.ports.cluster_port(0)
    }

    pub fn near_node_network_port(&self) -> u16 {
        self.ports.cluster_port(1)
    }

    // -- Per-node ports --

    pub fn p2p_port(&self, node_index: usize) -> u16 {
        self.ports.node_port(node_index, 0)
    }

    pub fn web_ui_port(&self, node_index: usize) -> u16 {
        self.ports.node_port(node_index, 1)
    }

    pub fn migration_web_ui_port(&self, node_index: usize) -> u16 {
        self.ports.node_port(node_index, 2)
    }

    pub fn pprof_port(&self, node_index: usize) -> u16 {
        self.ports.node_port(node_index, 3)
    }

    pub fn near_rpc_port(&self, node_index: usize) -> u16 {
        self.ports.node_port(node_index, 4)
    }

    pub fn near_network_port(&self, node_index: usize) -> u16 {
        self.ports.node_port(node_index, 5)
    }
}

#[cfg(test)]
mod tests {
    use super::E2ePortAllocator;

    #[test]
    #[expect(non_snake_case)]
    fn e2e_port_allocator__should_pin_the_established_port_layout() {
        // Given
        let a = E2ePortAllocator::new(1);

        // When / Then
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
    fn e2e_port_allocator__should_not_overlap_between_tests() {
        // Given
        let a = E2ePortAllocator::new(0);
        let b = E2ePortAllocator::new(1);

        // When
        let a_last = a.near_network_port(E2ePortAllocator::MAX_NODES as usize - 1);
        let b_first = b.near_node_rpc_port();

        // Then
        assert!(a_last < b_first, "{a_last} >= {b_first}");
    }

    #[test]
    #[expect(non_snake_case)]
    fn e2e_port_allocator__should_not_overlap_between_nodes() {
        // Given
        let a = E2ePortAllocator::new(0);

        // When / Then
        assert!(a.near_network_port(0) < a.p2p_port(1));
    }
}
