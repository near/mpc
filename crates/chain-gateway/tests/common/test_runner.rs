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
/// After the test body completes, each node's actor system is stopped and we
/// wait for all RocksDB instances to close before dropping the runtime. This
/// mirrors the shutdown sequence used by nearcore's own integration tests
/// (see `NodeCluster::run_and_then_shutdown`).
pub fn run_localnet_test<F, Fut>(test_body: F)
where
    F: FnOnce(Localnet) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), String>> + Send,
{
    let validator_dir = make_test_home_dir("validator.near");
    let observer_dir = make_test_home_dir("observer.near");
    let validator_path = validator_dir.path().to_path_buf();
    let observer_path = observer_dir.path().to_path_buf();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let result = rt.block_on(async {
        let localnet = setup_localnet(validator_path, observer_path).await;
        // Keep clones of the gateways so we can shut them down after the test
        // body consumes the Localnet.
        let validator_gw = localnet.validator.chain_gateway.clone();
        let observer_gw = localnet.observer.chain_gateway.clone();
        let result = test_body(localnet).await;
        validator_gw.shutdown();
        observer_gw.shutdown();
        result
    });

    // Wait for all RocksDB instances to close before dropping the runtime,
    // so background threads are not torn down while RocksDB is still open.
    near_store::db::RocksDB::block_until_all_instances_are_dropped();

    match result {
        Ok(()) => {}
        Err(msg) => panic!("test failed: {msg}"),
    }
}
