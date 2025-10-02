use ed25519_dalek::VerifyingKey;
use mpc_contract::node_migrations::{BackupServiceInfo, DestinationNodeInfo};
use near_sdk::AccountId;

use crate::{indexer::migrations::ContractMigrationInfo, providers::PublicKeyConversion};

#[derive(PartialEq, Debug, Clone)]
pub struct MigrationInfo {
    pub backup_service_info: Option<BackupServiceInfo>,
    pub active_migration: bool,
}

impl MigrationInfo {
    pub fn from_contract_state(
        my_account_id: &AccountId,
        my_p2p_tls_key: &VerifyingKey,
        contract_state: &ContractMigrationInfo,
    ) -> Self {
        infer_migration_info(my_account_id, my_p2p_tls_key, contract_state)
    }
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
            .inspect_err(|_| tracing::warn!(target: "Migration Service", "Error parsing public key from chain."))
            .is_ok_and(|key| key == *my_p2p_tls_key)
        })
        .unwrap_or(false)
}

fn infer_migration_info(
    my_account_id: &AccountId,
    my_p2p_tls_key: &VerifyingKey,
    contract_state: &ContractMigrationInfo,
) -> MigrationInfo {
    let (backup_service_info, active_migration) = match contract_state.get(my_account_id) {
        Some((backup_service_info, destination_node_info)) => (
            backup_service_info.clone(),
            infer_migration_status(my_p2p_tls_key, destination_node_info),
        ),
        None => (None, false),
    };
    MigrationInfo {
        backup_service_info,
        active_migration,
    }
}
