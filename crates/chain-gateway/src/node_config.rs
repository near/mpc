use std::path::PathBuf;

use near_indexer::{
    AwaitForNodeSyncedEnum, IndexerConfig, SyncModeEnum, near_primitives::types::Finality,
};

pub struct NodeConfig(pub(crate) IndexerConfig);

impl NodeConfig {
    pub fn new(home_dir: PathBuf) -> Self {
        Self(IndexerConfig {
            home_dir,
            validate_genesis: false,
            // TODO(#4827): take streamer settings only together with block subscriptions
            sync_mode: SyncModeEnum::LatestSynced,
            await_for_node_synced: AwaitForNodeSyncedEnum::WaitForFullSync,
            finality: Finality::None,
            skip_broken_blocks: false,
        })
    }

    pub fn with_validate_genesis(mut self, validate_genesis: bool) -> Self {
        self.0.validate_genesis = validate_genesis;
        self
    }

    pub fn with_sync_mode(mut self, sync_mode: SyncModeEnum) -> Self {
        self.0.sync_mode = sync_mode;
        self
    }

    pub fn with_await_for_node_synced(
        mut self,
        await_for_node_synced: AwaitForNodeSyncedEnum,
    ) -> Self {
        self.0.await_for_node_synced = await_for_node_synced;
        self
    }

    pub fn with_finality(mut self, finality: Finality) -> Self {
        self.0.finality = finality;
        self
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::path::PathBuf;

    use near_indexer::{
        AwaitForNodeSyncedEnum, IndexerConfig, SyncModeEnum, near_primitives::types::Finality,
    };

    use super::NodeConfig;

    #[test]
    fn node_config__should_apply_every_override() {
        // Given
        let home_dir = PathBuf::from("near-home");
        let NodeConfig(preset) = NodeConfig::new(home_dir.clone());
        let expected = IndexerConfig {
            validate_genesis: true,
            sync_mode: SyncModeEnum::BlockHeight(42),
            await_for_node_synced: AwaitForNodeSyncedEnum::StreamWhileSyncing,
            finality: Finality::Final,
            ..preset
        };

        // When
        let NodeConfig(config) = NodeConfig::new(home_dir)
            .with_validate_genesis(expected.validate_genesis)
            .with_sync_mode(expected.sync_mode.clone())
            .with_await_for_node_synced(expected.await_for_node_synced.clone())
            .with_finality(expected.finality.clone());

        // Then
        assert_eq!(format!("{config:?}"), format!("{expected:?}"));
    }
}
