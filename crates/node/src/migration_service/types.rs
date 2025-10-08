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
        let (backup_service_info, active_migration) = match contract_state.get(my_account_id) {
            Some((backup_service_info, destination_node_info)) => (
                backup_service_info.clone(),
                infer_migration_status(my_p2p_tls_key, destination_node_info),
            ),
            None => (None, false),
        };
        Self {
            backup_service_info,
            active_migration,
        }
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

#[cfg(test)]
mod tests {
    use mpc_contract::{
        node_migrations::{BackupServiceInfo, DestinationNodeInfo},
        primitives::test_utils::{
            bogus_ed25519_near_public_key, bogus_ed25519_public_key, gen_participant,
        },
    };

    use crate::{indexer::migrations::ContractMigrationInfo, providers::PublicKeyConversion};

    use super::MigrationInfo;

    #[test]
    fn test_migration_status_constructor_empty() {
        let state = ContractMigrationInfo::new();
        let (account_id, _) = gen_participant(0);
        let signer_account_pk = bogus_ed25519_near_public_key();
        let p2p_public_key =
            ed25519_dalek::VerifyingKey::from_near_sdk_public_key(&signer_account_pk).unwrap();

        let res = MigrationInfo::from_contract_state(&account_id, &p2p_public_key, &state);
        assert!(!res.active_migration);
        assert_eq!(res.backup_service_info, None);
    }

    #[test]
    fn test_migration_status_constructor_populated() {
        let mut state = ContractMigrationInfo::new();
        let (account_id_0, participant_info_0) = gen_participant(0);
        let (account_id_1, _) = gen_participant(1);
        let signer_account_pk = bogus_ed25519_near_public_key();
        let destination_node_info = DestinationNodeInfo {
            signer_account_pk: signer_account_pk.clone(),
            destination_node_info: participant_info_0.clone(),
        };

        let backup_service_info = BackupServiceInfo {
            public_key: bogus_ed25519_public_key(),
        };
        state.insert(
            account_id_1.clone(),
            (
                Some(backup_service_info.clone()),
                Some(destination_node_info.clone()),
            ),
        );
        let participating_key =
            ed25519_dalek::VerifyingKey::from_near_sdk_public_key(&participant_info_0.sign_pk)
                .unwrap();
        let non_participating_key =
            ed25519_dalek::VerifyingKey::from_near_sdk_public_key(&signer_account_pk).unwrap();

        let res = MigrationInfo::from_contract_state(&account_id_0, &participating_key, &state);
        assert!(!res.active_migration);
        assert_eq!(res.backup_service_info, None);

        let res = MigrationInfo::from_contract_state(&account_id_1, &non_participating_key, &state);
        assert!(!res.active_migration);
        assert_eq!(res.backup_service_info, Some(backup_service_info.clone()));

        let res = MigrationInfo::from_contract_state(&account_id_1, &participating_key, &state);
        assert!(res.active_migration);
        assert_eq!(res.backup_service_info, Some(backup_service_info.clone()));
    }
}
