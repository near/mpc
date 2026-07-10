//! Port allocation helpers for tests that run concurrently under `cargo
//! nextest`. Two strategies live here so callers can pick per use case:
//!
//! - [`PortAllocationScheme`]: a deterministic, collision-free scheme that derives
//!   ports from a caller-chosen `test_id`. Cheap and reproducible; callers must keep
//!   their `base` ports in disjoint ranges. Used by the `mpc-node` integration
//!   tests (`PortSeed`, `10000+`) and the `e2e-tests` clusters
//!   (`E2ePortAllocator`, `20000+`).
//! - [`reserve_port`]: a random, OS-named-lock-guarded reservation from
//!   `40000..=65535`. Race-free across processes; used where a deterministic
//!   layout isn't needed (`chain-gateway` tests).

use std::net::TcpListener;
use std::sync::Mutex;

use named_lock::{NamedLock, NamedLockGuard};
use rand::Rng;

/// A deterministic, collision-free scheme for allocating TCP ports to parallel tests.
///
/// Each `test_id` owns a disjoint block `[base + test_id*ports_per_test, …)`.
/// A block is laid out as `cluster_ports` shared ports followed by `max_nodes`
/// groups of `ports_per_node` per-node ports. Offsets carry no meaning here —
/// callers (`PortSeed`, `E2ePortAllocator`) assign the semantics.
///
/// Non-overlap across tests depends on every allocator that shares a numeric
/// range choosing a distinct `base`; see the module docs for the reserved
/// ranges.
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

    fn ports_per_test(&self) -> u16 {
        self.cluster_ports + self.ports_per_node * self.max_nodes
    }

    fn test_base(&self, test_id: u16) -> u16 {
        self.base + test_id * self.ports_per_test()
    }

    /// A cluster-level (non-per-node) port for the test.
    pub fn cluster_port(&self, test_id: u16, offset: u16) -> u16 {
        assert!(
            offset < self.cluster_ports,
            "cluster offset {offset} exceeds cluster_ports {}",
            self.cluster_ports
        );
        self.test_base(test_id) + offset
    }

    /// A per-node port for `node_index` within the test.
    pub fn node_port(&self, test_id: u16, node_index: usize, offset: u16) -> u16 {
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

/// Holds lock guards for the lifetime of the process, preventing other
/// processes from grabbing the same ports.
static RESERVED_PORT_LOCKS: Mutex<Vec<NamedLockGuard>> = Mutex::new(Vec::new());

/// Base ports for the deterministic [`PortAllocationScheme`] allocators — one lane per
/// allocator so tests in different crates never collide. `reserve_port` owns
/// everything from `PORT_RANGE_START` upward.
pub const PORT_SEED_BASE: u16 = 10000;
pub const E2E_PORT_BASE: u16 = 20000;

// Enforce the lane partition at compile time: the deterministic bases must be
// ordered and sit below the random reserve range.
const _: () = assert!(
    PORT_SEED_BASE < E2E_PORT_BASE && E2E_PORT_BASE < PORT_RANGE_START,
    "deterministic port bases must be ordered and below the reserve range"
);

const PORT_RANGE_START: u16 = 40000;
const PORT_RANGE_END: u16 = 65535;
const MAX_ATTEMPTS: u32 = 1000;

/// Reserve a TCP port using OS-level named locks for cross-process coordination.
///
/// This avoids the TOCTOU race inherent in bind-to-`:0`-then-drop patterns:
/// the named lock is held for the lifetime of the process, so no other test
/// process using this allocator can grab the same port.
///
/// Ports are chosen randomly from range 40000..65536 to avoid collisions with
/// `PortSeed` (10000+) and `E2ePortAllocator` (20000+).
///
/// Uses the same pattern as nearcore's `tcp.rs` port reservation.
pub fn reserve_port() -> u16 {
    let mut rng = rand::thread_rng();

    for _ in 0..MAX_ATTEMPTS {
        let port = rng.gen_range(PORT_RANGE_START..=PORT_RANGE_END);
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
    use super::{E2E_PORT_BASE, PORT_SEED_BASE, PortAllocationScheme};

    // Representative layouts for the two deterministic allocators. The bases are
    // the shared lane constants; the cluster/node/max fields illustrate each
    // allocator's shape and aren't force-synced with the callers.
    const PORT_SEED: PortAllocationScheme = PortAllocationScheme::new(PORT_SEED_BASE, 0, 16, 10);
    const E2E: PortAllocationScheme = PortAllocationScheme::new(E2E_PORT_BASE, 2, 8, 10);

    #[test]
    #[expect(non_snake_case)]
    fn node_port__should_offset_by_test_id_node_and_offset() {
        // Given a block with no cluster ports (16 ports per node, up to 10 nodes)
        // When computing node ports
        // Then each equals base + test_id*ports_per_test + node*ports_per_node + offset
        assert_eq!(PORT_SEED.node_port(0, 0, 0), 10000);
        assert_eq!(PORT_SEED.node_port(3, 0, 0), 10480);
        assert_eq!(PORT_SEED.node_port(1, 0, 8), 10168);
        assert_eq!(
            PORT_SEED.node_port(22, 9, 15),
            10000 + 22 * 160 + 9 * 16 + 15
        );
    }

    #[test]
    #[expect(non_snake_case)]
    fn cluster_and_node_ports__should_order_cluster_ports_before_node_ports() {
        // Given a block with 2 cluster ports and 8 ports per node (ports_per_test = 82)
        // When computing cluster and node ports across test ids
        // Then cluster ports fill the block head and node ports follow
        assert_eq!(E2E.cluster_port(0, 0), 20000);
        assert_eq!(E2E.cluster_port(0, 1), 20001);
        assert_eq!(E2E.node_port(0, 0, 0), 20002);
        assert_eq!(E2E.node_port(1, 0, 0), 20084);
        assert_eq!(E2E.node_port(0, 0, 5), 20007);
    }

    #[test]
    #[expect(non_snake_case)]
    fn node_port__should_not_overlap_between_tests() {
        // Given two adjacent test ids
        // When comparing the last port of the earlier test to the first of the next
        // Then the ranges are disjoint
        let a_last = E2E.node_port(0, 9, 7);
        let b_first = E2E.cluster_port(1, 0);
        assert!(a_last < b_first, "{a_last} >= {b_first}");
    }

    #[test]
    #[expect(non_snake_case)]
    fn node_port__should_not_overlap_between_nodes() {
        // Given two adjacent nodes in one test
        // When comparing the last port of node 0 to the first of node 1
        // Then the ranges are disjoint
        assert!(E2E.node_port(0, 0, 7) < E2E.node_port(0, 1, 0));
    }

    #[test]
    #[expect(non_snake_case)]
    fn cluster_and_node_ports__should_not_overlap() {
        // Given a block with cluster ports
        // When comparing the last cluster port to the first node port
        // Then the cluster region precedes the per-node region
        assert!(E2E.cluster_port(0, 1) < E2E.node_port(0, 0, 0));
    }

    #[test]
    #[should_panic(expected = "node_index")]
    #[expect(non_snake_case)]
    fn node_port__should_panic_when_node_index_exceeds_max() {
        let _ = E2E.node_port(0, 10, 0);
    }

    #[test]
    #[should_panic(expected = "node offset")]
    #[expect(non_snake_case)]
    fn node_port__should_panic_when_offset_exceeds_ports_per_node() {
        let _ = E2E.node_port(0, 0, 8);
    }

    #[test]
    #[should_panic(expected = "cluster offset")]
    #[expect(non_snake_case)]
    fn cluster_port__should_panic_when_offset_exceeds_cluster_ports() {
        let _ = E2E.cluster_port(0, 2);
    }
}
