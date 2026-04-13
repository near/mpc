use std::net::TcpListener;
use std::sync::Mutex;

use named_lock::{NamedLock, NamedLockGuard};
use rand::Rng;

/// Holds lock guards for the lifetime of the process, preventing other
/// processes from grabbing the same ports.
static RESERVED_PORT_LOCKS: Mutex<Vec<NamedLockGuard>> = Mutex::new(Vec::new());

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
