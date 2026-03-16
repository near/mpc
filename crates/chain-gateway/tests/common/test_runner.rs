use std::{
    time::Duration,
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
        let res = test_body(localnet.clone()).await;
        localnet.observer.chain_gateway.shutdown();
        localnet.validator.chain_gateway.shutdown();
        std::thread::sleep(Duration::from_secs(3));
        res
    });
   match result {
        Ok(()) => {
        }
        Err(msg) => panic!("test failed: {msg}"),
    }
}
