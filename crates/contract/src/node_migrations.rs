use std::collections::BTreeMap;

use near_account_id::AccountId;
use near_mpc_contract_interface::types::{BackupServiceInfo, DestinationNodeInfo, MigrationInfo};
use near_sdk::{near, store::IterableMap};

use crate::{
    storage_keys::StorageKey,
    tee::{attested_service::AttestedService, tee_state::TeeState},
};

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct NodeMigrations {
    backup_services_info: IterableMap<AccountId, BackupServiceInfo>,
    ongoing_migrations: IterableMap<AccountId, DestinationNodeInfo>,
    pub(crate) backup_service_tee_state: TeeState,
}

impl Default for NodeMigrations {
    fn default() -> Self {
        Self::new(
            IterableMap::new(StorageKey::BackupServicesInfo),
            IterableMap::new(StorageKey::NodeMigrations),
        )
    }
}

impl NodeMigrations {
    pub(crate) fn new(
        backup_services_info: IterableMap<AccountId, BackupServiceInfo>,
        ongoing_migrations: IterableMap<AccountId, DestinationNodeInfo>,
    ) -> Self {
        Self {
            backup_services_info,
            ongoing_migrations,
            backup_service_tee_state: TeeState::new(AttestedService::BackupService),
        }
    }

    pub(crate) fn backup_services_info(&self) -> &IterableMap<AccountId, BackupServiceInfo> {
        &self.backup_services_info
    }
    pub fn set_backup_service_info(&mut self, account_id: AccountId, info: BackupServiceInfo) {
        self.backup_services_info.insert(account_id, info);
    }

    pub fn set_destination_node_info(
        &mut self,
        account_id: AccountId,
        destination_node_info: DestinationNodeInfo,
    ) {
        self.ongoing_migrations
            .insert(account_id, destination_node_info);
    }

    pub fn remove_account_data(&mut self, account_id: &AccountId) {
        self.backup_services_info.remove(account_id);
        self.ongoing_migrations.remove(account_id);
    }

    pub fn ongoing_migration(&self, account_id: &AccountId) -> Option<&DestinationNodeInfo> {
        self.ongoing_migrations.get(account_id)
    }

    pub fn remove_migration(&mut self, account_id: &AccountId) -> Option<DestinationNodeInfo> {
        self.ongoing_migrations.remove(account_id)
    }

    pub fn get_for_account(
        &self,
        account_id: &AccountId,
    ) -> (
        AccountId,
        Option<BackupServiceInfo>,
        Option<DestinationNodeInfo>,
    ) {
        (
            account_id.clone(),
            self.backup_services_info.get(account_id).cloned(),
            self.ongoing_migrations.get(account_id).cloned(),
        )
    }

    pub fn get_all(&self) -> MigrationInfo {
        let mut combined = BTreeMap::new();

        for (id, backup_serivce_info) in self.backup_services_info.iter() {
            combined.insert(id.clone(), (Some(backup_serivce_info.clone()), None));
        }

        for (id, destination_node_info) in self.ongoing_migrations.iter() {
            combined
                .entry(id.clone())
                .and_modify(|entry| entry.1 = Some(destination_node_info.clone()))
                .or_insert((None, Some(destination_node_info.clone())));
        }

        combined.into()
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {

    use std::{
        collections::{BTreeMap, BTreeSet},
        time::Duration,
    };

    use mpc_attestation::attestation::MockAttestation;
    use near_mpc_contract_interface::types::{self as dtos, BackupServiceInfo};
    use near_sdk::{MockedBlockchain, mock::with_mocked_blockchain};

    use crate::{
        api::test_utils::destination_of,
        node_migrations::NodeMigrations,
        primitives::{
            key_state::AuthenticatedAccountId,
            test_utils::{
                authenticate_account_as, bogus_ed25519_public_key, gen_account_id,
                gen_participants, node_for,
            },
        },
        tee::{
            tee_state::TeeState,
            test_utils::{dummy_code_hash, dummy_launcher_hash, make_measurement},
        },
    };

    #[test]
    fn node_migrations__should_keep_the_backup_service_tee_state_apart_from_mpc_nodes() {
        // Given
        let participants = gen_participants(1);
        let (account_id, _, _) = &participants.participants()[0];
        let voter = authenticate_account_as(account_id, &participants);
        let node = node_for(account_id);
        let mpc_node_keys = storage_keys_written_by(|| {
            write_storage_keyed_collections(&mut TeeState::default(), &voter, node.clone())
        });

        // When
        let backup_service_keys = storage_keys_written_by(|| {
            write_storage_keyed_collections(
                &mut NodeMigrations::default().backup_service_tee_state,
                &voter,
                node.clone(),
            )
        });

        // Then
        assert!(!mpc_node_keys.is_empty());
        assert_eq!(backup_service_keys.len(), mpc_node_keys.len());
        assert_eq!(
            mpc_node_keys
                .intersection(&backup_service_keys)
                .collect::<Vec<_>>(),
            Vec::<&Vec<u8>>::new()
        );
    }

    /// Collections write to storage only once dropped, so the closure must drop what it writes to.
    fn storage_keys_written_by(write: impl FnOnce()) -> BTreeSet<Vec<u8>> {
        with_mocked_blockchain(MockedBlockchain::take_storage);
        write();
        with_mocked_blockchain(MockedBlockchain::take_storage)
            .into_keys()
            .collect()
    }

    fn write_storage_keyed_collections(
        tee_state: &mut TeeState,
        voter: &AuthenticatedAccountId,
        node: dtos::NodeInfo,
    ) {
        let proposal = 1;
        tee_state.vote_mpc_node_manifest_digest(dummy_code_hash(proposal), voter.clone());
        tee_state.vote_launcher(
            &dtos::LauncherVoteAction::Add(dummy_launcher_hash(proposal)),
            voter.clone(),
        );
        tee_state.vote_measurement(
            &dtos::MeasurementVoteAction::Add(make_measurement(proposal)),
            voter.clone(),
        );
        tee_state
            .verify_and_store_mock(node, MockAttestation::Valid, Duration::MAX)
            .unwrap();
    }

    #[test]
    fn test_set_backup_service_info() {
        let mut migrations = NodeMigrations::default();
        let backup_service_pk = bogus_ed25519_public_key();

        let account_id = gen_account_id();
        let info = BackupServiceInfo {
            public_key: backup_service_pk,
        };

        // sanity check
        assert!(migrations.backup_services_info.get(&account_id).is_none());
        assert_eq!(
            migrations.get_for_account(&account_id),
            (account_id.clone(), None, None)
        );
        assert!(migrations.get_all().is_empty());

        migrations.set_backup_service_info(account_id.clone(), info.clone());

        assert_eq!(
            migrations.backup_services_info.get(&account_id).unwrap(),
            &info
        );
        assert_eq!(
            migrations.get_for_account(&account_id),
            (account_id.clone(), Some(info.clone()), None)
        );
        assert_eq!(
            *migrations.get_all(),
            BTreeMap::from([(account_id.clone(), (Some(info.clone()), None))])
        );
    }

    #[test]
    fn test_ongoing_migrations() {
        let mut migrations = NodeMigrations::default();
        let account_id = gen_account_id();
        let destination_node_info = destination_of(&node_for(&account_id));
        // sanity checks
        assert!(migrations.ongoing_migrations.get(&account_id).is_none());
        assert!(migrations.remove_migration(&account_id).is_none());
        assert_eq!(
            migrations.get_for_account(&account_id),
            (account_id.clone(), None, None)
        );
        assert!(migrations.get_all().is_empty());

        migrations.set_destination_node_info(account_id.clone(), destination_node_info.clone());
        assert_eq!(
            migrations.ongoing_migrations.get(&account_id).unwrap(),
            &destination_node_info
        );

        assert_eq!(
            migrations.get_for_account(&account_id),
            (
                account_id.clone(),
                None,
                Some(destination_node_info.clone())
            )
        );
        assert_eq!(
            *migrations.get_all(),
            BTreeMap::from([(
                account_id.clone(),
                (None, Some(destination_node_info.clone()))
            )])
        );

        // check removing works
        assert_eq!(
            migrations.remove_migration(&account_id).unwrap(),
            destination_node_info
        );
        // ensure the entry has been removed
        assert!(migrations.ongoing_migrations.get(&account_id).is_none());
        assert_eq!(
            migrations.get_for_account(&account_id),
            (account_id.clone(), None, None)
        );
        assert!(migrations.get_all().is_empty());
        // sanity check
        assert!(migrations.remove_migration(&account_id).is_none());
    }

    #[test]
    fn test_remove_account_data() {
        let mut migrations = NodeMigrations::default();
        let account_id = gen_account_id();
        let backup_service_pk = bogus_ed25519_public_key();

        let info = BackupServiceInfo {
            public_key: backup_service_pk,
        };

        let destination_node_info = destination_of(&node_for(&account_id));

        // sanity checks
        assert!(migrations.ongoing_migrations.get(&account_id).is_none());
        assert!(migrations.remove_migration(&account_id).is_none());
        assert!(migrations.backup_services_info.get(&account_id).is_none());

        migrations.set_backup_service_info(account_id.clone(), info.clone());
        migrations.set_destination_node_info(account_id.clone(), destination_node_info.clone());

        // those asserts only fail if one of the above test fails. Still good to keep them.
        assert_eq!(
            migrations.backup_services_info.get(&account_id).unwrap(),
            &info
        );
        assert_eq!(
            migrations.ongoing_migrations.get(&account_id).unwrap(),
            &destination_node_info
        );

        assert_eq!(
            migrations.get_for_account(&account_id),
            (
                account_id.clone(),
                Some(info.clone()),
                Some(destination_node_info.clone())
            )
        );
        assert_eq!(
            *migrations.get_all(),
            BTreeMap::from([(
                account_id.clone(),
                (Some(info.clone()), Some(destination_node_info.clone()))
            )])
        );

        migrations.remove_account_data(&account_id);
        // sanity checks
        assert!(migrations.ongoing_migrations.get(&account_id).is_none());
        assert!(migrations.backup_services_info.get(&account_id).is_none());
        assert_eq!(
            migrations.get_for_account(&account_id),
            (account_id.clone(), None, None)
        );
        assert!(migrations.get_all().is_empty());
        // sanity check
        assert!(migrations.remove_migration(&account_id).is_none());
    }
}
