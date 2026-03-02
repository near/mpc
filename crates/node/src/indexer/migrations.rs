use std::collections::BTreeMap;

use chain_gateway::errors::ChainGatewayError;
use chain_gateway::state_viewer::{BlockHeight, ContractStateStream};
use ed25519_dalek::VerifyingKey;
use mpc_contract::node_migrations::{BackupServiceInfo, DestinationNodeInfo};
use near_account_id::AccountId;
use tokio::sync::watch;

use crate::{indexer::MpcContractStateViewer, migration_service::types::MigrationInfo};

pub type ContractMigrationInfo =
    BTreeMap<AccountId, (Option<BackupServiceInfo>, Option<DestinationNodeInfo>)>;

// Forward raw result to web sender, try to derive MigrationInfo
fn process_latest(
    latest: Result<(BlockHeight, ContractMigrationInfo), ChainGatewayError>,
    migration_state_sender: &watch::Sender<
        Result<(u64, ContractMigrationInfo), ChainGatewayError>,
    >,
    my_near_account_id: &AccountId,
    my_p2p_public_key: &VerifyingKey,
) -> Option<MigrationInfo> {
    let _ = migration_state_sender.send(latest.clone().map(|(h, s)| (h.into(), s)));
    match latest {
        Ok((_, contract_state)) => Some(MigrationInfo::from_contract_state(
            my_near_account_id,
            my_p2p_public_key,
            &contract_state,
        )),
        Err(err) => {
            tracing::warn!(%err, "error reading migration state");
            None
        }
    }
}

/// Spawns a monitoring task that subscribes to migration info from the contract.
/// Returns a tokio watch channel on which the latest migration state can be watched.
pub async fn monitor_migrations(
    contract_state_viewer: MpcContractStateViewer,
    migration_state_sender: watch::Sender<
        Result<(u64, ContractMigrationInfo), ChainGatewayError>,
    >,
    my_near_account_id: AccountId,
    my_p2p_public_key: VerifyingKey,
) -> watch::Receiver<MigrationInfo> {
    let (init_tx, init_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let mut subscription = contract_state_viewer
            .mpc_contract_viewer
            .subscribe_no_args::<ContractMigrationInfo>(
                contract_state_viewer.mpc_contract_id.clone(),
                contract_interface::method_names::MIGRATION_INFO,
            )
            .await;

        let init_migration_info = process_latest(
            subscription.latest(),
            &migration_state_sender,
            &my_near_account_id,
            &my_p2p_public_key,
        )
        .unwrap_or(MigrationInfo {
            backup_service_info: None,
            active_migration: false,
        });

        let (sender, receiver) = watch::channel(init_migration_info);
        if init_tx.send(receiver).is_err() {
            return;
        }

        loop {
            if subscription.changed().await.is_err() {
                tracing::error!("migration state subscription closed");
                break;
            }
            if let Some(state) = process_latest(
                subscription.latest(),
                &migration_state_sender,
                &my_near_account_id,
                &my_p2p_public_key,
            ) {
                sender.send_if_modified(|watched| {
                    if *watched != state {
                        tracing::info!("my migration state changed: {:?}", state);
                        *watched = state;
                        true
                    } else {
                        false
                    }
                });
            }
        }
    });

    init_rx
        .await
        .expect("migration state subscription task panicked")
}
