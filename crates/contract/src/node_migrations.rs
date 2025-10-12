use std::collections::BTreeMap;

use contract_interface::types::Ed25519PublicKey;
use near_sdk::{near, store::IterableMap, AccountId};

use crate::{primitives::participants::ParticipantInfo, storage_keys::StorageKey};

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct NodeMigrations {
    backup_services_info: IterableMap<AccountId, BackupServiceInfo>,
    ongoing_migrations: IterableMap<AccountId, DestinationNodeInfo>,
}

impl Default for NodeMigrations {
    fn default() -> Self {
        Self {
            backup_services_info: IterableMap::new(StorageKey::BackupServicesInfo),
            ongoing_migrations: IterableMap::new(StorageKey::NodeMigrations),
        }
    }
}

impl NodeMigrations {
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

    pub fn get_all(
        &self,
    ) -> BTreeMap<AccountId, (Option<BackupServiceInfo>, Option<DestinationNodeInfo>)> {
        let mut combined: BTreeMap<
            AccountId,
            (Option<BackupServiceInfo>, Option<DestinationNodeInfo>),
        > = BTreeMap::new();

        for (id, backup_serivce_info) in self.backup_services_info.iter() {
            combined.insert(id.clone(), (Some(backup_serivce_info.clone()), None));
        }

        for (id, destination_node_info) in self.ongoing_migrations.iter() {
            combined
                .entry(id.clone())
                .and_modify(|entry| entry.1 = Some(destination_node_info.clone()))
                .or_insert((None, Some(destination_node_info.clone())));
        }

        combined
    }
}

#[derive(Debug, PartialEq, PartialOrd, Clone)]
#[near(serializers=[borsh, json])]
pub struct BackupServiceInfo {
    pub public_key: Ed25519PublicKey,
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
#[near(serializers=[borsh, json])]
pub struct DestinationNodeInfo {
    /// the public key used by the node to sign transactions to the contract
    /// this key is different from the TLS key called `sign_pk` and stored in `ParticipantInfo`.
    pub signer_account_pk: near_sdk::PublicKey,
    // the participant info for the node
    pub destination_node_info: ParticipantInfo,
}

#[cfg(test)]
mod tests {

    use std::collections::BTreeMap;

    use crate::{
        node_migrations::{BackupServiceInfo, DestinationNodeInfo, NodeMigrations},
        primitives::test_utils::{
            bogus_ed25519_near_public_key, bogus_ed25519_public_key, gen_account_id,
            gen_participant,
        },
    };

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
            migrations.get_all(),
            BTreeMap::from([(account_id.clone(), (Some(info.clone()), None))])
        );
    }

    #[test]
    fn test_ongoing_migrations() {
        let mut migrations = NodeMigrations::default();
        let (account_id, participant_info) = gen_participant(0);
        let signer_account_pk = bogus_ed25519_near_public_key();
        let destination_node_info = DestinationNodeInfo {
            signer_account_pk,
            destination_node_info: participant_info,
        };
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
            migrations.get_all(),
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
        let (account_id, participant_info) = gen_participant(0);
        let signer_account_pk = bogus_ed25519_near_public_key();
        let backup_service_pk = bogus_ed25519_public_key();

        let info = BackupServiceInfo {
            public_key: backup_service_pk,
        };

        let destination_node_info = DestinationNodeInfo {
            signer_account_pk,
            destination_node_info: participant_info,
        };

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
            migrations.get_all(),
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
