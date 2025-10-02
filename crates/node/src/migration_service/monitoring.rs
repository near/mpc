use std::sync::Arc;

use anyhow::Context;
use ed25519_dalek::VerifyingKey;
use mpc_contract::node_migrations::BackupServiceInfo;
use tokio::sync::watch;

use crate::{indexer::IndexerState, providers::PublicKeyConversion};

#[derive(PartialEq, Debug, Clone)]
pub struct MigrationInfo {
    pub backup_service_info: Option<BackupServiceInfo>,
    pub active_migration: bool,
}

const MIGRATION_INFO_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

async fn fetch_migrations_once(
    indexer_state: Arc<IndexerState>,
    my_p2p_tls_key: &ed25519_dalek::VerifyingKey,
) -> MigrationInfo {
    loop {
        tracing::debug!(target: "migration", "awaiting indexer full sync to read mpc contract state");
        indexer_state.wait_for_full_sync().await;

        tracing::debug!(target: "migration", "querying migration state");
        match indexer_state.get_mpc_my_migration_info().await {
            Ok((_, my_map)) => {
                for (_, (_, destination_node)) in my_map.iter() {
                    if let Some(destination_node_info) = destination_node {
                        let info = destination_node_info.destination_node_info.clone();

                        if let Ok(key) =
                            ed25519_dalek::VerifyingKey::from_near_sdk_public_key(&info.sign_pk)
                                .with_context(|| {
                                    format!("Invalid public key length for peer: {:?}", info.url)
                                })
                        {
                            if key == *my_p2p_tls_key {
                                // this is wrong, obviously.
                                return MigrationInfo {
                                    backup_service_info: None,
                                    active_migration: true,
                                };
                            }
                        } else {
                            tracing::error!("invalid key");
                        };
                    }
                }
                return MigrationInfo {
                    backup_service_info: None,
                    active_migration: false,
                };
                // let active_migration =
                //     my_map
                //         .iter()
                //         .map(|(account_id, (backup_service_info, migration_info))| {
                //             migration_info.is_some_and(|info| {
                //                 let destination_node_info = info.destination_node_info;

                //                 ed25519_dalek::VerifyingKey::from_near_sdk_public_key(
                //                     &info.destination_node_info.sign_pk,
                //                 )
                //                 .with_context(|| {
                //                     format!(
                //                         "Invalid public key length for peer: {:?}",
                //                         info.destination_node_info.url
                //                     )
                //                 })
                //                 .is_ok_and(|key| key == *my_p2p_tls_key)
                //             })
                //         });
                //let active_migration = destination_node_info.is_some_and(|info| {
                //    ed25519_dalek::VerifyingKey::from_near_sdk_public_key(
                //        &info.destination_node_info.sign_pk,
                //    )
                //    .with_context(|| {
                //        format!(
                //            "Invalid public key length for peer: {:?}",
                //            info.destination_node_info.url
                //        )
                //    })
                //    .is_ok_and(|key| key == *my_p2p_tls_key)
                //});

                // return MigrationInfo {
                //     backup_service_info: None,
                //     active_migration,
                // };
            }
            Err(e) => {
                tracing::error!(target: "mpc", "error reading config from chain: {:?}", e);
                tokio::time::sleep(MIGRATION_INFO_REFRESH_INTERVAL).await;
            }
        }
    }
}

// todo: move this to indexer?

/// Continuously monitors the contract state. Every time the state changes,
/// sends the new state via the provided sender. This is a long-running task.
pub async fn monitor_migrations(
    indexer_state: Arc<IndexerState>,
    my_p2p_tls_key: &VerifyingKey,
) -> watch::Receiver<MigrationInfo> {
    let init_response = fetch_migrations_once(indexer_state.clone(), &my_p2p_tls_key).await;
    let (sender, receiver) = watch::channel(init_response);

    tokio::spawn({
        let mut interval = tokio::time::interval(MIGRATION_INFO_REFRESH_INTERVAL);
        let my_p2p_tls_key = my_p2p_tls_key.clone();
        async move {
            loop {
                interval.tick().await;
                let response = fetch_migrations_once(indexer_state.clone(), &my_p2p_tls_key).await;
                //refresh_interval_tick().await;
                tracing::debug!(target: "indexer", "got mpc migration state {:?}", response);
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
