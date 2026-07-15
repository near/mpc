//! Port allocation for tests running concurrently under `cargo nextest`. Two
//! strategies:
//!
//! - [`TestPorts`]: deterministic ports derived from a `test_id`, one scheme
//!   per test crate — [`TestPorts::mpc_node_tests`] (10000+) and
//!   [`TestPorts::e2e_tests`] (20000+).
//! - [`reserve_port`]: a random port from `40000..=65535` behind an OS-level
//!   named lock, so it's race-free across processes (`chain-gateway` tests).

use std::net::TcpListener;
use std::sync::Mutex;

use named_lock::{NamedLock, NamedLockGuard};
use rand::Rng;

/// Block-allocation arithmetic for one port space: each `test_id` owns a
/// disjoint block of `cluster_ports` shared ports followed by `max_nodes`
/// groups of `ports_per_node`, with the whole space capped at `space_end`.
/// Offsets are semantic-free — the [`TestPorts`] accessors name them.
#[derive(Copy, Clone, Debug)]
struct PortAllocationScheme {
    base: u16,
    /// Exclusive end of the space's port range. [`TestPorts::new`] rejects any
    /// `test_id` whose block would cross it.
    space_end: u16,
    cluster_ports: u16,
    ports_per_node: u16,
    max_nodes: u16,
    /// Number of disjoint [`NodeTestPorts::with_case`] sub-blocks a node's block
    /// is divided into; each occupies [`TestPorts::SHARED_NODE_PORTS`] offsets.
    cases_per_node: u16,
}

impl PortAllocationScheme {
    const fn ports_per_test(&self) -> u16 {
        self.cluster_ports + self.ports_per_node * self.max_nodes
    }

    /// Exclusive end of `test_id`'s block, widened so the check itself cannot
    /// overflow `u16`.
    const fn test_end(&self, test_id: u16) -> u32 {
        self.base as u32 + (test_id as u32 + 1) * self.ports_per_test() as u32
    }

    fn test_base(&self, test_id: u16) -> u16 {
        self.base + test_id * self.ports_per_test()
    }

    fn cluster_port(&self, test_id: u16, offset: u16) -> u16 {
        assert!(
            offset < self.cluster_ports,
            "cluster offset {offset} exceeds cluster_ports {}",
            self.cluster_ports
        );
        self.test_base(test_id) + offset
    }

    fn node_port(&self, test_id: u16, node_index: u16, offset: u16) -> u16 {
        assert!(
            node_index < self.max_nodes,
            "node_index {node_index} exceeds max_nodes {}",
            self.max_nodes
        );
        assert!(
            offset < self.ports_per_node,
            "node offset {offset} exceeds ports_per_node {}",
            self.ports_per_node
        );
        self.test_base(test_id) + self.cluster_ports + node_index * self.ports_per_node + offset
    }
}

/// A bundle of TCP ports for one `test_id`, laid out by the scheme its
/// constructor pins. The shared per-node accessors are inherent; the `near_*`
/// cluster/node ports live on [`E2eTestPorts`] and case multiplexing on
/// [`NodeTestPorts`], so each call site imports only the capability it needs.
#[derive(Copy, Clone, Debug)]
pub struct TestPorts {
    scheme: PortAllocationScheme,
    test_id: u16,
    offset_shift: u16,
}

impl TestPorts {
    const MAX_NODES: u16 = 10;

    /// Per-node offsets owned by the accessors both schemes share (p2p, web UI,
    /// migration web UI, pprof); scheme-specific offsets start here.
    const SHARED_NODE_PORTS: u16 = 4;

    /// `mpc-node` integration tests: no cluster ports; a node's block is
    /// subdivided into `cases_per_node` sub-blocks of the shared ports, so one
    /// seed can drive several disjoint test cases via [`TestPorts::with_case`].
    const MPC_NODE_TESTS_SCHEME: PortAllocationScheme = PortAllocationScheme {
        base: 10000,
        space_end: Self::E2E_TESTS_SCHEME.base,
        cluster_ports: 0,
        ports_per_node: 4 * Self::SHARED_NODE_PORTS,
        max_nodes: Self::MAX_NODES,
        cases_per_node: 4,
    };

    /// `e2e-tests` clusters: cluster-level ports for the NEAR sandbox RPC and
    /// network, then per-node ports (the shared four, the node's internal neard
    /// RPC/network, and two spare).
    const E2E_TESTS_SCHEME: PortAllocationScheme = PortAllocationScheme {
        base: 20000,
        space_end: RESERVE_RANGE_START,
        cluster_ports: 2,
        ports_per_node: 8,
        max_nodes: Self::MAX_NODES,
        cases_per_node: 1,
    };

    /// Ports for an `mpc-node` integration test (10000–19999).
    pub const fn mpc_node_tests(test_id: u16) -> Self {
        Self::new(Self::MPC_NODE_TESTS_SCHEME, test_id)
    }

    /// Ports for an `e2e-tests` cluster (20000–39999).
    pub const fn e2e_tests(test_id: u16) -> Self {
        Self::new(Self::E2E_TESTS_SCHEME, test_id)
    }

    const fn new(scheme: PortAllocationScheme, test_id: u16) -> Self {
        assert!(
            scheme.cases_per_node * Self::SHARED_NODE_PORTS <= scheme.ports_per_node,
            "cases_per_node sub-blocks must fit in a node's block"
        );
        assert!(
            scheme.test_end(test_id) <= scheme.space_end as u32,
            "test_id's port block crosses the scheme's space end; use a smaller test_id"
        );
        Self {
            scheme,
            test_id,
            offset_shift: 0,
        }
    }

    fn node_port(&self, node_index: usize, offset: u16) -> u16 {
        let node_index = u16::try_from(node_index).expect("node_index exceeds u16");
        self.scheme
            .node_port(self.test_id, node_index, self.offset_shift + offset)
    }

    pub fn p2p_port(&self, node_index: usize) -> u16 {
        self.node_port(node_index, 0)
    }

    pub fn web_ui_port(&self, node_index: usize) -> u16 {
        self.node_port(node_index, 1)
    }

    pub fn migration_web_ui_port(&self, node_index: usize) -> u16 {
        self.node_port(node_index, 2)
    }

    pub fn pprof_port(&self, node_index: usize) -> u16 {
        self.node_port(node_index, 3)
    }
}

/// The extra port capability an `mpc-node` integration test needs beyond the
/// inherent per-node accessors; implemented by [`TestPorts::mpc_node_tests`]
/// bundles.
pub trait NodeTestPorts {
    /// Shifts every per-node offset into `case`'s sub-block, so distinct cases
    /// of the same seed never collide.
    fn with_case(self, case: u16) -> Self
    where
        Self: Sized;
}

/// The extra ports an `e2e-tests` cluster needs beyond the inherent per-node
/// accessors; implemented by [`TestPorts::e2e_tests`] bundles.
pub trait E2eTestPorts {
    /// The cluster's NEAR sandbox RPC port.
    fn near_node_rpc_port(&self) -> u16;
    /// The cluster's NEAR sandbox network port.
    fn near_node_network_port(&self) -> u16;
    /// A node's internal neard RPC port.
    fn near_rpc_port(&self, node_index: usize) -> u16;
    /// A node's internal neard network port.
    fn near_network_port(&self, node_index: usize) -> u16;
}

impl NodeTestPorts for TestPorts {
    fn with_case(mut self, case: u16) -> Self {
        assert!(
            case < self.scheme.cases_per_node,
            "case {case} exceeds cases_per_node {}",
            self.scheme.cases_per_node
        );
        self.offset_shift = case * Self::SHARED_NODE_PORTS;
        self
    }
}

impl E2eTestPorts for TestPorts {
    fn near_node_rpc_port(&self) -> u16 {
        self.scheme.cluster_port(self.test_id, 0)
    }

    fn near_node_network_port(&self) -> u16 {
        self.scheme.cluster_port(self.test_id, 1)
    }

    fn near_rpc_port(&self, node_index: usize) -> u16 {
        self.node_port(node_index, Self::SHARED_NODE_PORTS)
    }

    fn near_network_port(&self, node_index: usize) -> u16 {
        self.node_port(node_index, Self::SHARED_NODE_PORTS + 1)
    }
}

/// Holds lock guards for the lifetime of the process, preventing other
/// processes from grabbing the same ports.
static RESERVED_PORT_LOCKS: Mutex<Vec<NamedLockGuard>> = Mutex::new(Vec::new());

/// `reserve_port` owns everything from here upward; the deterministic
/// [`TestPorts`] schemes partition the range below it.
const RESERVE_RANGE_START: u16 = 40000;
const RESERVE_RANGE_END: u16 = 65535;
const MAX_ATTEMPTS: u32 = 1000;

/// Reserves a random TCP port behind a process-lifetime OS named lock, so no
/// other process can grab it (unlike TOCTOU-prone bind-to-`:0`-then-drop).
pub fn reserve_port() -> u16 {
    let mut rng = rand::thread_rng();

    for _ in 0..MAX_ATTEMPTS {
        let port = rng.gen_range(RESERVE_RANGE_START..=RESERVE_RANGE_END);
        let lock_name = format!("mpc_test_reserved_port_{port}");

        let lock = match NamedLock::create(&lock_name) {
            Ok(lock) => lock,
            Err(_) => continue,
        };

        let guard = match lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => continue,
        };

        // Verify the port is actually bindable.
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            continue;
        }

        RESERVED_PORT_LOCKS
            .lock()
            .expect("RESERVED_PORT_LOCKS poisoned")
            .push(guard);

        return port;
    }

    panic!("failed to reserve a port after {MAX_ATTEMPTS} attempts");
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use super::{E2eTestPorts, NodeTestPorts, TestPorts};

    #[test]
    fn node_port__should_offset_by_test_id_node_and_offset() {
        // Given the mpc-node scheme (16 ports per node, up to 10 nodes)
        // When computing node ports
        // Then each equals base + test_id*ports_per_test + node*ports_per_node + offset
        assert_eq!(TestPorts::mpc_node_tests(0).p2p_port(0), 10000);
        assert_eq!(TestPorts::mpc_node_tests(3).p2p_port(0), 10480);
        assert_eq!(TestPorts::mpc_node_tests(1).p2p_port(0), 10160);
        assert_eq!(
            TestPorts::mpc_node_tests(22).pprof_port(9),
            10000 + 22 * 160 + 9 * 16 + 3
        );
    }

    #[test]
    fn with_case__should_shift_offsets_into_the_case_sub_block() {
        // Given an mpc-node seed
        // When selecting successive cases
        // Then per-node offsets move by case*SHARED_NODE_PORTS and stay disjoint
        let seed = TestPorts::mpc_node_tests(1);
        assert_eq!(seed.p2p_port(0), 10160);
        assert_eq!(seed.with_case(1).p2p_port(0), 10164);
        assert_eq!(seed.with_case(2).p2p_port(0), 10168);
    }

    #[test]
    #[should_panic(expected = "cases_per_node")]
    fn with_case__should_panic_when_case_exceeds_cases_per_node() {
        // The mpc-node scheme fits 4 cases per node.
        let _ = TestPorts::mpc_node_tests(0).with_case(4);
    }

    #[test]
    fn e2e_tests__should_order_cluster_ports_before_node_ports() {
        // Given the e2e scheme (2 cluster ports, 8 ports per node, ports_per_test = 82)
        // When reading each accessor for a known test id
        // Then cluster ports fill the block head and node ports follow at base 20000
        let a = TestPorts::e2e_tests(1);
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
    fn node_port__should_not_overlap_between_tests() {
        // Given two adjacent test ids on the e2e scheme
        // When comparing the last port of the earlier test to the first of the next
        // Then the ranges are disjoint
        let a_last = TestPorts::e2e_tests(0).near_network_port(9);
        let b_first = TestPorts::e2e_tests(1).near_node_rpc_port();
        assert!(a_last < b_first, "{a_last} >= {b_first}");
    }

    #[test]
    fn node_port__should_not_overlap_between_nodes() {
        // Given two adjacent nodes in one test
        // When comparing the last port of node 0 to the first of node 1
        // Then the ranges are disjoint
        let a = TestPorts::e2e_tests(0);
        assert!(a.near_network_port(0) < a.p2p_port(1));
    }

    #[test]
    fn cluster_and_node_ports__should_not_overlap() {
        // Given the e2e scheme, whose blocks start with cluster ports
        // When comparing the last cluster port to the first node port
        // Then the cluster region precedes the per-node region
        let a = TestPorts::e2e_tests(0);
        assert!(a.near_node_network_port() < a.p2p_port(0));
    }

    #[test]
    fn new__should_accept_the_last_test_id_that_fits_the_space() {
        // Given the e2e scheme, whose range ends at 40000 (82 ports per test)
        // When constructing the last block that still fits (20000 + 243*82 = 39926)
        // Then construction succeeds
        let _ = TestPorts::e2e_tests(242);
    }

    #[test]
    #[should_panic(expected = "space end")]
    fn new__should_panic_when_test_ids_block_crosses_the_space_end() {
        // 20000 + 244*82 = 40008 crosses the reserve range at 40000.
        let _ = TestPorts::e2e_tests(243);
    }

    #[test]
    #[should_panic(expected = "node_index")]
    fn node_port__should_panic_when_node_index_exceeds_max() {
        let _ = TestPorts::e2e_tests(0).near_rpc_port(10);
    }

    #[test]
    #[should_panic(expected = "cluster offset")]
    fn cluster_port__should_panic_on_a_scheme_without_cluster_ports() {
        // The mpc-node scheme has no cluster ports, so e2e-only accessors panic.
        let _ = TestPorts::mpc_node_tests(0).near_node_rpc_port();
    }
}
