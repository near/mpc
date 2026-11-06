use mpc_node_config::{IndexerConfig, SyncMode};

pub(crate) trait IndexerConfigExt {
    fn to_near_indexer_config(&self, home_dir: std::path::PathBuf) -> near_indexer::IndexerConfig;
}

impl IndexerConfigExt for IndexerConfig {
    fn to_near_indexer_config(&self, home_dir: std::path::PathBuf) -> near_indexer::IndexerConfig {
        near_indexer::IndexerConfig {
            home_dir,
            sync_mode: convert_sync_mode(self.sync_mode.clone()),
            await_for_node_synced: near_indexer::AwaitForNodeSyncedEnum::StreamWhileSyncing,
            finality: self.finality.clone(),
            validate_genesis: self.validate_genesis,
            skip_broken_blocks: false,
        }
    }
}

fn convert_sync_mode(sync_mode: SyncMode) -> near_indexer::SyncModeEnum {
    match sync_mode {
        SyncMode::Interruption => near_indexer::SyncModeEnum::FromInterruption,
        SyncMode::Latest => near_indexer::SyncModeEnum::LatestSynced,
        SyncMode::Block(args) => near_indexer::SyncModeEnum::BlockHeight(args.height),
    }
}
