use std::sync::LazyLock;

pub static MPC_BLOCKS_RECEIVED_FROM_INDEXER: LazyLock<prometheus::IntCounter> =
    LazyLock::new(|| {
        prometheus::register_int_counter!(
            "mpc_blocks_received_from_indexer_total",
            "Number of blocks pulled from the indexer's StreamerMessage queue by listen_blocks"
        )
        .unwrap()
    });

pub static MPC_BLOCKS_INDEXED: LazyLock<prometheus::IntCounter> = LazyLock::new(|| {
    prometheus::register_int_counter!(
        "mpc_blocks_indexed_total",
        "Number of blocks observed from the indexer and fed to the shared RecentBlocksTracker"
    )
    .unwrap()
});

pub static MPC_FINALIZED_BLOCKS_INDEXED: LazyLock<prometheus::IntCounter> = LazyLock::new(|| {
    prometheus::register_int_counter!(
        "mpc_finalized_blocks_indexed_total",
        "Number of blocks that transitioned to Final in the shared RecentBlocksTracker"
    )
    .unwrap()
});

pub static MPC_BLOCK_UPDATES_DROPPED: LazyLock<prometheus::IntCounter> = LazyLock::new(|| {
    prometheus::register_int_counter!(
        "mpc_block_updates_dropped_total",
        "Number of BlockUpdates dropped because the consumer channel was full"
    )
    .unwrap()
});
