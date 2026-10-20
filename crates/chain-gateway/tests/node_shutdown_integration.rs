use std::time::Duration;

use near_store::{Mode, StoreConfig, Temperature, db::RocksDB};
use tokio_util::sync::CancellationToken;

use crate::common::node::{LocalNode, LocalNodeBuilder};

#[tokio::test]
#[expect(non_snake_case)]
async fn node_handle__should_close_the_node_store_when_dropped() {
    // Given
    let LocalNode {
        home_dir,
        node_handle,
        ..
    } = LocalNodeBuilder::new("validator", tempfile::tempdir().unwrap())
        .start(None, CancellationToken::new())
        .await;

    // When
    drop(node_handle);

    // Then
    RocksDB::open(
        &home_dir.path().join("data"),
        &StoreConfig::default(),
        Mode::ReadWriteExisting,
        Temperature::Hot,
    )
    .expect("the node's store should be closed");
}

#[tokio::test]
#[expect(non_snake_case)]
async fn chain_gateway_start__should_stop_the_node_when_the_token_is_cancelled() {
    // Given
    let shutdown = CancellationToken::new();
    let LocalNode {
        home_dir: _home_dir,
        node_handle,
        ..
    } = LocalNodeBuilder::new("validator", tempfile::tempdir().unwrap())
        .start(None, shutdown.clone())
        .await;

    // When
    shutdown.cancel();

    // Then
    tokio::time::timeout(Duration::from_secs(30), async {
        while node_handle.is_node_alive() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the node should stop");
}
