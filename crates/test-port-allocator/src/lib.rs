//! Port allocation for tests running concurrently under `cargo nextest`. Two
//! strategies:
//!
//! - [`TestPorts`]: deterministic ports derived from a `test_id`. Each consumer
//!   defines a [`PortAllocationScheme`] over its own base-port range and wraps
//!   [`TestPorts`] in a type that names the offsets (`PortSeed` in `mpc-node`,
//!   `E2ePortAllocator` in `e2e-tests`).
//! - [`reserve_port`]: a random port from `40000..=65535` behind an OS-level
//!   named lock, so it's race-free across processes (`chain-gateway` tests).

use std::net::TcpListener;
use std::sync::Mutex;

use named_lock::{NamedLock, NamedLockGuard};
use rand::Rng;

/// Base ports of the deterministic [`TestPorts`] schemes — one range per
/// consumer so tests in different crates never collide. [`reserve_port`] owns
/// everything from [`RESERVE_RANGE_START`] upward.
pub const PORT_SEED_BASE: u16 = 10000;
pub const E2E_PORT_BASE: u16 = 20000;
pub const RESERVE_RANGE_START: u16 = 40000;

const _: () = assert!(
    PORT_SEED_BASE < E2E_PORT_BASE && E2E_PORT_BASE < RESERVE_RANGE_START,
    "deterministic port bases must be ordered and below the reserve range"
);

/// Port layout for one test crate: each `test_id` owns a disjoint block of
/// `cluster_ports` shared ports followed by `max_nodes` groups of
/// `ports_per_node`, starting at `base`. Blocks may not reach `space_end`
/// (enforced by [`TestPorts::new`]), keeping neighbouring ranges disjoint.
#[derive(Copy, Clone, Debug)]
pub struct PortAllocationScheme {
    pub base: u16,
    pub cluster_ports: u16,
    pub ports_per_node: u16,
    pub max_nodes: u16,
    pub space_end: u16,
}

impl PortAllocationScheme {
    const fn ports_per_test(&self) -> u16 {
        self.cluster_ports + self.ports_per_node * self.max_nodes
    }
}

/// One `test_id`'s block of ports within a [`PortAllocationScheme`].
#[derive(Copy, Clone, Debug)]
pub struct TestPorts {
    scheme: PortAllocationScheme,
    test_id: u16,
}

impl TestPorts {
    pub const fn new(scheme: PortAllocationScheme, test_id: u16) -> Self {
        // Widened to u32 so the check itself cannot overflow `u16`.
        let test_end = scheme.base as u32 + (test_id as u32 + 1) * scheme.ports_per_test() as u32;
        assert!(
            test_end <= scheme.space_end as u32,
            "test_id's port block crosses the scheme's space_end; use a smaller test_id"
        );
        Self { scheme, test_id }
    }

    fn test_base(&self) -> u16 {
        self.scheme.base + self.test_id * self.scheme.ports_per_test()
    }

    pub fn cluster_port(&self, offset: u16) -> u16 {
        assert!(
            offset < self.scheme.cluster_ports,
            "cluster offset {offset} exceeds cluster_ports {}",
            self.scheme.cluster_ports
        );
        self.test_base() + offset
    }

    pub fn node_port(&self, node_index: usize, offset: u16) -> u16 {
        assert!(
            (node_index as u16) < self.scheme.max_nodes,
            "node_index {node_index} exceeds max_nodes {}",
            self.scheme.max_nodes
        );
        assert!(
            offset < self.scheme.ports_per_node,
            "node offset {offset} exceeds ports_per_node {}",
            self.scheme.ports_per_node
        );
        self.test_base()
            + self.scheme.cluster_ports
            + node_index as u16 * self.scheme.ports_per_node
            + offset
    }
}

/// Holds lock guards for the lifetime of the process, preventing other
/// processes from grabbing the same ports.
static RESERVED_PORT_LOCKS: Mutex<Vec<NamedLockGuard>> = Mutex::new(Vec::new());

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
    use super::{PortAllocationScheme, TestPorts};

    const SCHEME: PortAllocationScheme = PortAllocationScheme {
        base: 100,
        cluster_ports: 2,
        ports_per_node: 8,
        max_nodes: 3,
        space_end: 200,
    };

    #[test]
    #[expect(non_snake_case)]
    fn node_port__should_offset_by_test_id_node_and_offset() {
        // Given
        let ports = TestPorts::new(SCHEME, 1);

        // When / Then
        assert_eq!(ports.node_port(0, 0), 100 + 26 + 2);
        assert_eq!(ports.node_port(2, 7), 100 + 26 + 2 + 2 * 8 + 7);
    }

    #[test]
    #[expect(non_snake_case)]
    fn cluster_port__should_precede_node_ports() {
        // Given
        let ports = TestPorts::new(SCHEME, 0);

        // When / Then
        assert_eq!(ports.cluster_port(0), 100);
        assert_eq!(ports.cluster_port(1), 101);
        assert_eq!(ports.node_port(0, 0), 102);
    }

    #[test]
    #[expect(non_snake_case)]
    fn node_port__should_not_overlap_between_adjacent_test_ids() {
        // Given
        let a = TestPorts::new(SCHEME, 0);
        let b = TestPorts::new(SCHEME, 1);

        // When
        let a_last = a.node_port(2, 7);
        let b_first = b.cluster_port(0);

        // Then
        assert!(a_last < b_first, "{a_last} >= {b_first}");
    }

    #[test]
    #[expect(non_snake_case)]
    fn new__should_accept_the_last_test_id_that_fits_the_space() {
        let _ = TestPorts::new(SCHEME, 2);
    }

    #[test]
    #[should_panic(expected = "space_end")]
    #[expect(non_snake_case)]
    fn new__should_panic_when_test_ids_block_crosses_the_space_end() {
        let _ = TestPorts::new(SCHEME, 3);
    }

    #[test]
    #[should_panic(expected = "cluster offset")]
    #[expect(non_snake_case)]
    fn cluster_port__should_panic_when_offset_exceeds_cluster_ports() {
        let _ = TestPorts::new(SCHEME, 0).cluster_port(2);
    }

    #[test]
    #[should_panic(expected = "node_index")]
    #[expect(non_snake_case)]
    fn node_port__should_panic_when_node_index_exceeds_max() {
        let _ = TestPorts::new(SCHEME, 0).node_port(3, 0);
    }

    #[test]
    #[should_panic(expected = "node offset")]
    #[expect(non_snake_case)]
    fn node_port__should_panic_when_offset_exceeds_ports_per_node() {
        let _ = TestPorts::new(SCHEME, 0).node_port(0, 8);
    }
}
