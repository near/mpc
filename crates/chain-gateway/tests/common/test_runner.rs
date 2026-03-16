use std::{
    future::Future,
    path::Path,
    sync::atomic::{AtomicU32, Ordering},
};

use super::localnet::{Localnet, setup_localnet};

/// Counter to give each node a unique directory within a test process.
static NODE_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Returns a fresh temp directory under `target/chain-gateway-test-nodes/`.
/// The returned `TempDir` is automatically deleted when dropped.
fn make_test_home_dir(account_id: &str) -> tempfile::TempDir {
    let id = std::process::id();
    let seq = NODE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let project_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let base = project_dir.join("target/chain-gateway-test-nodes");
    std::fs::create_dir_all(&base).expect("create base test dir");
    tempfile::Builder::new()
        .prefix(&format!("{id}-{seq}-{account_id}-"))
        .tempdir_in(base)
        .expect("create temp home dir")
}

/// Runs an async test body inside a self-managed tokio runtime.
///
/// nearcore spawns detached OS threads (per-actor tokio runtimes, multithread
/// actor workers, RocksDB, thread pools, rayon, trie prefetch) that cannot be
/// joined or stopped. Dropping the tokio runtime while those threads run causes
/// SIGSEGV. We avoid this by forgetting the runtime and calling POSIX `_exit(0)`
/// to terminate the process immediately without running atexit handlers or
/// destructors.
///
/// This is the in-process equivalent of near-sandbox-rs's approach, which runs
/// nearcore as a child process and uses `kill(pid, SIGKILL)` for cleanup.
///
/// On failure we panic (before `_exit`) so the test harness captures the error.
pub fn run_localnet_test<F, Fut>(test_body: F)
where
    F: FnOnce(Localnet) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), String>> + Send,
{
    let validator_dir = make_test_home_dir("validator.near");
    let observer_dir = make_test_home_dir("observer.near");
    let validator_path = validator_dir.path().to_path_buf();
    let observer_path = observer_dir.path().to_path_buf();

    // Leak temp dirs: detached RocksDB threads outlive the runtime.
    // Dirs live under target/ and are cleaned by `cargo clean`.
    let _ = validator_dir.keep();
    let _ = observer_dir.keep();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let result = rt.block_on(async {
        let localnet = setup_localnet(validator_path, observer_path).await;
        test_body(localnet).await
    });

    // nearcore's detached threads cannot be joined or stopped. If we let the
    // tokio runtime drop, it tears down I/O drivers while threads still use
    // them → SIGSEGV. Even `std::process::exit()` can trigger SIGSEGV via
    // C++ atexit destructors (e.g. RocksDB) racing with those threads.
    //
    // `_exit(0)` terminates immediately: no atexit handlers, no destructors,
    // no stdio flush. The OS reclaims all memory and file descriptors.
    std::mem::forget(rt);

    match result {
        Ok(()) => {
            unsafe extern "C" {
                fn _exit(status: std::ffi::c_int) -> !;
            }
            // SAFETY: _exit is a standard POSIX function. We call it with a
            // valid exit code after the test has passed and all assertions
            // have been checked.
            unsafe { _exit(0) }
        }
        Err(msg) => panic!("test failed: {msg}"),
    }
}
