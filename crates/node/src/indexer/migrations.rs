use std::collections::BTreeMap;

use chain_gateway::errors::ChainGatewayError;
use chain_gateway::state_viewer::ContractStateSubscriber;
use chain_gateway::state_viewer::ContractStateStream;
use chain_gateway::types::ObservedState;
use ed25519_dalek::VerifyingKey;
use mpc_contract::node_migrations::{BackupServiceInfo, DestinationNodeInfo};
use near_account_id::AccountId;
use tokio::sync::watch;

use crate::{indexer::MpcContractStateViewer, migration_service::types::MigrationInfo};

pub type ContractMigrationInfo =
    BTreeMap<AccountId, (Option<BackupServiceInfo>, Option<DestinationNodeInfo>)>;

// Forward raw result to web sender, try to derive MigrationInfo
fn process_latest(
    latest: Result<ObservedState<ContractMigrationInfo>, ChainGatewayError>,
    my_near_account_id: &AccountId,
    my_p2p_public_key: &VerifyingKey,
) -> Option<MigrationInfo> {
    match latest {
        Ok(latest) => Some(MigrationInfo::from_contract_state(
            my_near_account_id,
            my_p2p_public_key,
            &latest.value,
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
        Result<ObservedState<ContractMigrationInfo>, ChainGatewayError>,
    >,
    my_near_account_id: AccountId,
    my_p2p_public_key: VerifyingKey,
) -> watch::Receiver<MigrationInfo> {
    let (sender, receiver) = watch::channel(MigrationInfo {
        backup_service_info: None,
        active_migration: false,
    });

    // todo: we should massively simplify this.
    // We can add a method "subscribe" to the MpcContractStateViewer that returns a
    // watch::Receiver<(BlockHeight, ContractMigrationInfo), ChainGatewayError>
    // then, we just clone a receiver for the web-server and we use this function here to simply
    // convert the result.
    // we might want to have a single struct for that?
    // I.e. something like MpcContext {
    //      my_migration_info: MigrationInfo
    //      contract_state: ProtocolContractState
    // }
    // and we pass around an Arc ref to that?
    tokio::spawn(async move {
        let mut subscription = contract_state_viewer
            .mpc_contract_viewer
            .subscribe::<ContractMigrationInfo>(
                contract_state_viewer.mpc_contract_id.clone(),
                contract_interface::method_names::MIGRATION_INFO,
            )
            .await;

        loop {
            let latest = subscription.latest();
            if let Err(err) = migration_state_sender.send(latest.clone()) {
                tracing::warn!("web server closed {}", err)
            };
            match process_latest(latest, &my_near_account_id, &my_p2p_public_key) {
                Some(state) => {
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
                None => {
                    tracing::warn!("error parsing state")
                }
            }

            if subscription.changed().await.is_err() {
                // todo: need to propagat panick?
                tracing::error!("migration state subscription closed");
                break;
            }
        }
    });
    receiver
}
