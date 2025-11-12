use std::{collections::BTreeMap, sync::Arc};

use ed25519_dalek::VerifyingKey;
use mpc_contract::node_migrations::{BackupServiceInfo, DestinationNodeInfo};
use near_sdk::AccountId;
use tokio::sync::watch;

use crate::{
    indexer::{
        lib::{get_mpc_migration_info, wait_for_full_sync},
        IndexerState,
    },
    migration_service::types::MigrationInfo,
};

pub type ContractMigrationInfo =
    BTreeMap<AccountId, (Option<BackupServiceInfo>, Option<DestinationNodeInfo>)>;

const MIGRATION_INFO_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Blocks until the indexer has a current view of the blockchain.
/// Spawns a monitoring task to fetch the migration info from the contract.
/// Returns a tokio watch channel on which the latest migration state can be watched.
///
/// The interval checking for new values is defined by [`MIGRATION_INFO_REFRESH_INTERVAL`]
pub async fn monitor_migrations(
    indexer_state: Arc<IndexerState>,

    migration_state_sender: watch::Sender<(u64, ContractMigrationInfo)>,
    my_near_account_id: AccountId,
    my_p2p_public_key: VerifyingKey,
) -> watch::Receiver<MigrationInfo> {
    let init_response = fetch_migrations_once(indexer_state.clone()).await;
    let init_migration_state = MigrationInfo::from_contract_state(
        &my_near_account_id,
        &my_p2p_public_key,
        &init_response.1,
    );

    let (sender, receiver) = watch::channel(init_migration_state);

    tokio::spawn({
        let mut interval = tokio::time::interval(MIGRATION_INFO_REFRESH_INTERVAL);
        async move {
            loop {
                interval.tick().await;
                let response = fetch_migrations_once(indexer_state.clone()).await;
                tracing::debug!(target: "indexer", "fetched mpc migration state at block {}: {:?}", response.0, response.1);

                migration_state_sender.send_if_modified(|watched_state| {
                    let migration_info_changed = watched_state.1 != response.1;
                    if *watched_state != response {
                        if migration_info_changed {
                            tracing::info!("contract migration state changed: {:?}", response);
                        }
                        *watched_state = response.clone();
                        true
                    } else {
                        false
                    }
                });
                let my_migration_state = MigrationInfo::from_contract_state(
                    &my_near_account_id,
                    &my_p2p_public_key,
                    &response.1,
                );
                sender.send_if_modified(|watched_state| {
                    if *watched_state != my_migration_state {
                        tracing::info!("my migration state changed: {:?}", my_migration_state);
                        *watched_state = my_migration_state;
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

async fn fetch_migrations_once(indexer_state: Arc<IndexerState>) -> (u64, ContractMigrationInfo) {
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
            Ok(res) => {
                return res;
            }
            Err(e) => {
                tracing::error!(target: "mpc", "error reading config from chain: {:?}", e);
                tokio::time::sleep(MIGRATION_INFO_REFRESH_INTERVAL).await;
            }
        }
    }
}
