use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use mpc_contract::node_migrations::{BackupServiceInfo, DestinationNodeInfo};
use near_sdk::AccountId;
use tokio::sync::watch;

use crate::{
    indexer::{
        lib::{get_mpc_migration_info, wait_for_full_sync},
        IndexerState,
    },
    providers::PublicKeyConversion,
};

#[derive(PartialEq, Debug, Clone)]
pub struct MigrationInfo {
    pub backup_service_info: Option<BackupServiceInfo>,
    pub active_migration: bool,
}

/// Blocks until the indexer has a current view of the blockchain.
/// Spawns a monitoring task to fetch the [`MigrationInfo`] for this node from the contract.
/// Returns a tokio watch channel on which the latest [`MigrationInfo`] state can be received.
///
/// The interval checking for new values is defined by [`MIGRATION_INFO_REFRESH_INTERVAL`]
pub async fn monitor_migrations(
    indexer_state: Arc<IndexerState>,
    my_account_id: &AccountId,
    my_p2p_tls_key: &VerifyingKey,
) -> watch::Receiver<MigrationInfo> {
    let init_response =
        fetch_migrations_once(indexer_state.clone(), my_account_id, my_p2p_tls_key).await;
    let (sender, receiver) = watch::channel(init_response);

    tokio::spawn({
        let mut interval = tokio::time::interval(MIGRATION_INFO_REFRESH_INTERVAL);
        let my_account_id_cloned = my_account_id.clone();
        let my_p2p_tls_key_cloned = my_p2p_tls_key.clone();
        async move {
            loop {
                interval.tick().await;
                let response = fetch_migrations_once(
                    indexer_state.clone(),
                    &my_account_id_cloned,
                    &my_p2p_tls_key_cloned,
                )
                .await;
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

fn infer_migration_status(
    my_p2p_tls_key: &VerifyingKey,
    destination_node_info: &Option<DestinationNodeInfo>,
) -> bool {
    destination_node_info
        .as_ref()
        .map(|info| {
            ed25519_dalek::VerifyingKey::from_near_sdk_public_key(
                &info.destination_node_info.sign_pk,
            )
            .inspect_err(
                |_| tracing::warn!(target: "indexer", "Error parsing public key from chain."),
            )
            .is_ok_and(|key| key == *my_p2p_tls_key)
        })
        .unwrap_or(false)
}

const MIGRATION_INFO_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

async fn fetch_migrations_once(
    indexer_state: Arc<IndexerState>,
    my_account_id: &AccountId,
    my_p2p_tls_key: &ed25519_dalek::VerifyingKey,
) -> MigrationInfo {
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
                let (backup_service_info, active_migration) =
                    match migrations_info.get(my_account_id) {
                        Some((backup_service_info, destination_node_info)) => (
                            backup_service_info.clone(),
                            infer_migration_status(my_p2p_tls_key, destination_node_info),
                        ),
                        None => (None, false),
                    };
                return MigrationInfo {
                    backup_service_info,
                    active_migration,
                };
            }
            Err(e) => {
                tracing::error!(target: "mpc", "error reading config from chain: {:?}", e);
                tokio::time::sleep(MIGRATION_INFO_REFRESH_INTERVAL).await;
            }
        }
    }
}
