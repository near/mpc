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

pub static MPC_BLOCKS_INDEXED_WITHOUT_PARENT: LazyLock<prometheus::IntCounter> = LazyLock::new(
    || {
        prometheus::register_int_counter!(
            "mpc_blocks_indexed_without_parent_total",
            "Number of blocks fed to the shared RecentBlocksTracker whose parent it does not track, not counting the first block"
        )
        .unwrap()
    },
);

pub static MPC_BLOCKS_MADE_NON_CANONICAL: LazyLock<prometheus::IntCounter> = LazyLock::new(|| {
    prometheus::register_int_counter!(
        "mpc_blocks_made_non_canonical_total",
        "Number of blocks the shared RecentBlocksTracker moved off the canonical chain after a reorg"
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

pub static MPC_INDEXER_NUM_RECEIPT_EXECUTION_OUTCOMES: LazyLock<prometheus::IntCounter> =
    LazyLock::new(|| {
        prometheus::register_int_counter!(
            "mpc_indexer_num_receipt_execution_outcomes",
            "Number of receipt execution outcomes processed by the near indexer"
        )
        .unwrap()
    });

pub static MPC_INDEXER_NUM_UNCONVERTIBLE_PREDECESSOR_IDS: LazyLock<prometheus::IntCounter> =
    LazyLock::new(|| {
        prometheus::register_int_counter!(
            "mpc_indexer_num_unconvertible_predecessor_ids",
            "Number of requests dropped because the receipt's predecessor could not be \
             converted between the two `near-account-id` versions in the dependency graph. \
             Expected to stay at zero; a non-zero value means those versions have diverged"
        )
        .unwrap()
    });

pub static MPC_INDEXER_LATEST_BLOCK_HEIGHT: LazyLock<prometheus::IntGauge> = LazyLock::new(|| {
    prometheus::register_int_gauge!(
        "mpc_indexer_latest_block_height",
        "Height of the last block seen by the block streamer"
    )
    .unwrap()
});

pub static MPC_INDEXER_LATEST_BLOCK_TIMESTAMP_SECONDS: LazyLock<prometheus::IntGauge> =
    LazyLock::new(|| {
        prometheus::register_int_gauge!(
            "mpc_indexer_latest_block_timestamp_seconds",
            "Unix time of the last block seen by the block streamer"
        )
        .unwrap()
    });
