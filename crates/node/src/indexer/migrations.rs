use std::{collections::BTreeMap, sync::Arc};

use mpc_contract::node_migrations::{BackupServiceInfo, DestinationNodeInfo};
use near_sdk::AccountId;
use tokio::sync::watch;

use crate::indexer::{
    lib::{get_mpc_migration_info, wait_for_full_sync},
    IndexerState,
};

const MIGRATION_INFO_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Blocks until the indexer has a current view of the blockchain.
/// Spawns a monitoring task to fetch the [`MigrationInfo`] for this node from the contract.
/// Returns a tokio watch channel on which the latest [`MigrationInfo`] state can be received.
///
/// The interval checking for new values is defined by [`MIGRATION_INFO_REFRESH_INTERVAL`]
pub async fn monitor_migrations(
    indexer_state: Arc<IndexerState>,
) -> watch::Receiver<BTreeMap<AccountId, (Option<BackupServiceInfo>, Option<DestinationNodeInfo>)>>
{
    let init_response = fetch_migrations_once(indexer_state.clone()).await;
    let (sender, receiver) = watch::channel(init_response);

    tokio::spawn({
        let mut interval = tokio::time::interval(MIGRATION_INFO_REFRESH_INTERVAL);
        async move {
            loop {
                interval.tick().await;
                let response = fetch_migrations_once(indexer_state.clone()).await;
                tracing::debug!(target: "indexer", "fetched mpc migration state {:?}", response);
                sender.send_if_modified(|watched_state| {
                    if *watched_state != response {
                        tracing::info!("Contract state changed: {:?}", response);
                        *watched_state = response;
                        true
                    } else {
                        false
                    }
                });
            }
        }
    });

    receiver
}

async fn fetch_migrations_once(
    indexer_state: Arc<IndexerState>,
) -> BTreeMap<AccountId, (Option<BackupServiceInfo>, Option<DestinationNodeInfo>)> {
    loop {
        tracing::debug!(target: "indexer", "awaiting indexer full sync to read mpc contract state");
        wait_for_full_sync(&indexer_state.client).await;

        tracing::debug!(target: "indexer", "querying migration state");

        match get_mpc_migration_info(
            indexer_state.mpc_contract_id.clone(),
            &indexer_state.view_client,
        )
        .await
        {
            Ok((_, migrations_info)) => {
                return migrations_info;
            }
            Err(e) => {
                tracing::error!(target: "mpc", "error reading config from chain: {:?}", e);
                tokio::time::sleep(MIGRATION_INFO_REFRESH_INTERVAL).await;
            }
        }
    }
}
