/// Deterministic port allocator for E2E tests.
///
/// Each test gets a unique `test_id`. All ports are computed from it to avoid
/// collisions when tests run in parallel via `cargo nextest`.
///
/// Layout per test:
///   - 2 cluster-level ports (sandbox RPC, sandbox network)
///   - 8 ports per node * MAX_NODES
#[derive(Debug, Clone)]
pub struct E2ePortAllocator {
    test_id: u16,
}

impl E2ePortAllocator {
    const BASE_PORT: u16 = 20000;
    const PORTS_PER_NODE: u16 = 8;
    const MAX_NODES: u16 = 10;
    /// Cluster-level ports that are not per-node.
    const CLUSTER_PORTS: u16 = 2;
    /// Total ports reserved per test.
    const PORTS_PER_TEST: u16 = Self::CLUSTER_PORTS + Self::MAX_NODES * Self::PORTS_PER_NODE;

    pub const fn new(test_id: u16) -> Self {
        Self { test_id }
    }

    fn base(&self) -> u16 {
        Self::BASE_PORT + self.test_id * Self::PORTS_PER_TEST
    }

    // -- Cluster-level ports --

    pub fn sandbox_rpc_port(&self) -> u16 {
        self.base()
    }

    pub fn sandbox_network_port(&self) -> u16 {
        self.base() + 1
    }

    // -- Per-node ports --

    fn node_base(&self, node_index: usize) -> u16 {
        assert!(
            node_index < Self::MAX_NODES as usize,
            "node_index {node_index} exceeds MAX_NODES"
        );
        self.base() + Self::CLUSTER_PORTS + (node_index as u16) * Self::PORTS_PER_NODE
    }

    pub fn p2p_port(&self, node_index: usize) -> u16 {
        self.node_base(node_index)
    }

    pub fn web_ui_port(&self, node_index: usize) -> u16 {
        self.node_base(node_index) + 1
    }

    pub fn migration_web_ui_port(&self, node_index: usize) -> u16 {
        self.node_base(node_index) + 2
    }

    pub fn pprof_port(&self, node_index: usize) -> u16 {
        self.node_base(node_index) + 3
    }

    pub fn near_rpc_port(&self, node_index: usize) -> u16 {
        self.node_base(node_index) + 4
    }

    pub fn near_network_port(&self, node_index: usize) -> u16 {
        self.node_base(node_index) + 5
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_port_overlap_between_tests() {
        let a = E2ePortAllocator::new(0);
        let b = E2ePortAllocator::new(1);
        // Last port of test 0 must be less than first port of test 1
        let a_last = a.near_network_port(E2ePortAllocator::MAX_NODES as usize - 1);
        let b_first = b.sandbox_rpc_port();
        assert!(a_last < b_first, "{a_last} >= {b_first}");
    }

    #[test]
    fn no_port_overlap_between_nodes() {
        let a = E2ePortAllocator::new(0);
        let last_of_node0 = a.near_network_port(0);
        let first_of_node1 = a.p2p_port(1);
        assert!(last_of_node0 < first_of_node1);
    }
}
