use near_store::{Mode, StoreConfig, Temperature, db::RocksDB};

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
        .start(None)
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
