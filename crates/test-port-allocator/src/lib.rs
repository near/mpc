//! Port allocation for tests running concurrently under `cargo nextest`. Two
//! strategies:
//!
//! - [`TestPorts`]: deterministic ports derived from a `test_id`, one
//!   [`PortSpace`] per allocator — `mpc-node` tests (`PortSeed`, 10000+) and
//!   `e2e-tests` clusters ([`E2ePortSpace`], 20000+).
//! - [`reserve_port`]: a random port from `40000..=65535` behind an OS-level
//!   named lock, so it's race-free across processes (`chain-gateway` tests).

use std::marker::PhantomData;
use std::net::TcpListener;
use std::sync::Mutex;

use named_lock::{NamedLock, NamedLockGuard};
use rand::Rng;

/// Block-allocation arithmetic shared by every [`PortSpace`]: each `test_id` owns
/// a disjoint block of `cluster_ports` shared ports followed by `max_nodes` groups
/// of `ports_per_node`. Offsets are semantic-free — the [`TestPorts`] accessors
/// name them.
#[derive(Copy, Clone, Debug)]
pub struct PortAllocationScheme {
    base: u16,
    cluster_ports: u16,
    ports_per_node: u16,
    max_nodes: u16,
}

impl PortAllocationScheme {
    pub const fn new(base: u16, cluster_ports: u16, ports_per_node: u16, max_nodes: u16) -> Self {
        Self {
            base,
            cluster_ports,
            ports_per_node,
            max_nodes,
        }
    }

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

    fn node_port(&self, test_id: u16, node_index: usize, offset: u16) -> u16 {
        assert!(
            (node_index as u16) < self.max_nodes,
            "node_index {node_index} exceeds max_nodes {}",
            self.max_nodes
        );
        assert!(
            offset < self.ports_per_node,
            "node offset {offset} exceeds ports_per_node {}",
            self.ports_per_node
        );
        self.test_base(test_id)
            + self.cluster_ports
            + node_index as u16 * self.ports_per_node
            + offset
    }
}

/// A port-layout space. Each implementor pins a distinct [`PortAllocationScheme`]
pub trait PortSpace {
    const SCHEME: PortAllocationScheme;
    /// Exclusive end of the space's port range. [`TestPorts::new`] rejects any
    /// `test_id` whose block would cross it.
    const SPACE_END: u16;
}

/// A [`PortSpace`] whose per-node block is subdivided into cases, so the same seed can
/// drive several disjoint test cases via [`TestPorts::with_case`].
pub trait MultiplexedPortSpace: PortSpace {
    /// Consecutive offsets each case occupies within a node's block.
    const PORTS_PER_CASE: u16;
}

/// A bundle of TCP ports for one `test_id`, laid out by space `S`. Space-specific
/// surface (cluster ports, `with_case`) is gated to the space that defines it.
#[derive(Copy, Clone, Debug)]
pub struct TestPorts<S: PortSpace> {
    test_id: u16,
    offset_shift: u16,
    _space: PhantomData<S>,
}

/// Per-node offsets owned by the accessors every space shares; a
/// [`MultiplexedPortSpace`]'s `PORTS_PER_CASE` must be at least this.
pub const SHARED_NODE_PORTS: u16 = 4;

impl<S: PortSpace> TestPorts<S> {
    pub const fn new(test_id: u16) -> Self {
        assert!(
            S::SCHEME.test_end(test_id) <= S::SPACE_END as u32,
            "test_id's port block crosses the space's end (SPACE_END); use a smaller test_id"
        );
        Self {
            test_id,
            offset_shift: 0,
            _space: PhantomData,
        }
    }

    fn node(&self, node_index: usize, offset: u16) -> u16 {
        S::SCHEME.node_port(self.test_id, node_index, self.offset_shift + offset)
    }

    fn cluster(&self, offset: u16) -> u16 {
        S::SCHEME.cluster_port(self.test_id, offset)
    }

    pub fn p2p_port(&self, node_index: usize) -> u16 {
        self.node(node_index, 0)
    }

    pub fn web_ui_port(&self, node_index: usize) -> u16 {
        self.node(node_index, 1)
    }

    pub fn migration_web_ui_port(&self, node_index: usize) -> u16 {
        self.node(node_index, 2)
    }

    pub fn pprof_port(&self, node_index: usize) -> u16 {
        self.node(node_index, 3)
    }
}

impl<S: MultiplexedPortSpace> TestPorts<S> {
    /// Shifts every per-node offset into `case`'s sub-block, so distinct cases of
    /// the same seed never collide.
    pub fn with_case(mut self, case: u16) -> Self {
        const {
            assert!(
                S::PORTS_PER_CASE >= SHARED_NODE_PORTS,
                "PORTS_PER_CASE must be at least SHARED_NODE_PORTS"
            )
        };
        self.offset_shift = case * S::PORTS_PER_CASE;
        self
    }
}

/// The space used by `e2e-tests` clusters: cluster-level ports for the NEAR
/// sandbox RPC and network, then per-node ports.
#[derive(Copy, Clone, Debug)]
pub struct E2ePortSpace;

impl E2ePortSpace {
    pub const MAX_NODES: u16 = 10;
}

impl PortSpace for E2ePortSpace {
    const SCHEME: PortAllocationScheme =
        PortAllocationScheme::new(E2E_PORT_BASE, 2, 8, E2ePortSpace::MAX_NODES);
    const SPACE_END: u16 = RESERVE_RANGE_START;
}

impl TestPorts<E2ePortSpace> {
    pub fn near_node_rpc_port(&self) -> u16 {
        self.cluster(0)
    }

    pub fn near_node_network_port(&self) -> u16 {
        self.cluster(1)
    }

    pub fn near_rpc_port(&self, node_index: usize) -> u16 {
        self.node(node_index, 4)
    }

    pub fn near_network_port(&self, node_index: usize) -> u16 {
        self.node(node_index, 5)
    }
}

/// Holds lock guards for the lifetime of the process, preventing other
/// processes from grabbing the same ports.
static RESERVED_PORT_LOCKS: Mutex<Vec<NamedLockGuard>> = Mutex::new(Vec::new());

/// Base ports for the deterministic [`TestPorts`] spaces — one space per allocator
/// so tests in different crates never collide. `reserve_port` owns everything
/// from `RESERVE_RANGE_START` upward.
pub const PORT_SEED_BASE: u16 = 10000;
pub const E2E_PORT_BASE: u16 = 20000;

// Enforce the space partition at compile time: the deterministic bases must be
// ordered and sit below the random reserve range.
const _: () = assert!(
    PORT_SEED_BASE < E2E_PORT_BASE && E2E_PORT_BASE < RESERVE_RANGE_START,
    "deterministic port bases must be ordered and below the reserve range"
);

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
mod tests {
    use super::{E2ePortSpace, MultiplexedPortSpace, PortAllocationScheme, PortSpace, TestPorts};

    // A case-multiplexed space mirroring `PortSeed`'s shape (base 10000, no cluster
    // ports, 4 cases × 4 offsets per node, up to 10 nodes) so the case arithmetic
    // is exercised here without depending on `mpc-node`.
    #[derive(Copy, Clone, Debug)]
    struct SeedSpace;
    impl PortSpace for SeedSpace {
        const SCHEME: PortAllocationScheme = PortAllocationScheme::new(10000, 0, 16, 10);
        const SPACE_END: u16 = 20000;
    }
    impl MultiplexedPortSpace for SeedSpace {
        const PORTS_PER_CASE: u16 = 4;
    }

    #[test]
    #[expect(non_snake_case)]
    fn node_port__should_offset_by_test_id_node_and_offset() {
        // Given a case-multiplexed space (16 ports per node, up to 10 nodes)
        // When computing node ports
        // Then each equals base + test_id*ports_per_test + node*ports_per_node + offset
        assert_eq!(TestPorts::<SeedSpace>::new(0).p2p_port(0), 10000);
        assert_eq!(TestPorts::<SeedSpace>::new(3).p2p_port(0), 10480);
        assert_eq!(TestPorts::<SeedSpace>::new(1).p2p_port(0), 10160);
        assert_eq!(
            TestPorts::<SeedSpace>::new(22).pprof_port(9),
            10000 + 22 * 160 + 9 * 16 + 3
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn with_case__should_shift_offsets_into_the_case_sub_block() {
        // Given a case-multiplexed space
        // When selecting successive cases
        // Then per-node offsets move by case*PORTS_PER_CASE and stay disjoint
        let seed = TestPorts::<SeedSpace>::new(1);
        assert_eq!(seed.p2p_port(0), 10160);
        assert_eq!(seed.with_case(1).p2p_port(0), 10164);
        assert_eq!(seed.with_case(2).p2p_port(0), 10168);
    }

    #[test]
    #[expect(non_snake_case)]
    fn e2e_space__should_order_cluster_ports_before_node_ports() {
        // Given the e2e space (2 cluster ports, 8 ports per node, ports_per_test = 82)
        // When reading each accessor for a known test id
        // Then cluster ports fill the block head and node ports follow at base 20000
        let a = TestPorts::<E2ePortSpace>::new(1);
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
    fn node_port__should_not_overlap_between_tests() {
        // Given two adjacent test ids on the e2e space
        // When comparing the last port of the earlier test to the first of the next
        // Then the ranges are disjoint
        let a_last = TestPorts::<E2ePortSpace>::new(0).near_network_port(9);
        let b_first = TestPorts::<E2ePortSpace>::new(1).near_node_rpc_port();
        assert!(a_last < b_first, "{a_last} >= {b_first}");
    }

    #[test]
    #[expect(non_snake_case)]
    fn node_port__should_not_overlap_between_nodes() {
        // Given two adjacent nodes in one test
        // When comparing the last port of node 0 to the first of node 1
        // Then the ranges are disjoint
        let a = TestPorts::<E2ePortSpace>::new(0);
        assert!(a.near_network_port(0) < a.p2p_port(1));
    }

    #[test]
    #[expect(non_snake_case)]
    fn cluster_and_node_ports__should_not_overlap() {
        // Given a space with cluster ports
        // When comparing the last cluster port to the first node port
        // Then the cluster region precedes the per-node region
        let a = TestPorts::<E2ePortSpace>::new(0);
        assert!(a.near_node_network_port() < a.p2p_port(0));
    }

    #[test]
    #[expect(non_snake_case)]
    fn new__should_accept_the_last_test_id_that_fits_the_space() {
        // Given the e2e space, whose range ends at 40000 (82 ports per test)
        // When constructing the last block that still fits (20000 + 243*82 = 39926)
        // Then construction succeeds
        let _ = TestPorts::<E2ePortSpace>::new(242);
    }

    #[test]
    #[should_panic(expected = "space's end")]
    #[expect(non_snake_case)]
    fn new__should_panic_when_test_ids_block_crosses_the_space_end() {
        // 20000 + 244*82 = 40008 crosses the reserve range at 40000.
        let _ = TestPorts::<E2ePortSpace>::new(243);
    }

    #[test]
    #[should_panic(expected = "node_index")]
    #[expect(non_snake_case)]
    fn node_port__should_panic_when_node_index_exceeds_max() {
        let _ = TestPorts::<E2ePortSpace>::new(0).near_rpc_port(10);
    }

    #[test]
    #[should_panic(expected = "node offset")]
    #[expect(non_snake_case)]
    fn node_port__should_panic_when_offset_exceeds_ports_per_node() {
        // The seed space has 16 ports per node; shifting a case past the block panics.
        let _ = TestPorts::<SeedSpace>::new(0).with_case(4).p2p_port(0);
    }
}
