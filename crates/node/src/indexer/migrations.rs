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
                tracing::debug!(target: "indexer", "fetched mpc migration state {:?}", response);
                process_migration_response(
                    &response,
                    &migration_state_sender,
                    &sender,
                    &my_near_account_id,
                    &my_p2p_public_key,
                );
            }
        }
    });

    receiver
}

/// Processes a single migration fetch response and updates the watch channels if needed.
/// Returns true if any channel was updated, false otherwise.
fn process_migration_response(
    response: &(u64, ContractMigrationInfo),
    migration_state_sender: &watch::Sender<(u64, ContractMigrationInfo)>,
    my_migration_sender: &watch::Sender<MigrationInfo>,
    my_near_account_id: &AccountId,
    my_p2p_public_key: &VerifyingKey,
) -> bool {
    let contract_updated = migration_state_sender.send_if_modified(|watched_state| {
        // Only compare the migration info, not the block height
        if watched_state.1 != response.1 {
            tracing::info!("contract migration state changed: {:?}", response);
            *watched_state = response.clone();
            true
        } else {
            false
        }
    });

    let my_migration_state =
        MigrationInfo::from_contract_state(my_near_account_id, my_p2p_public_key, &response.1);
    let my_state_updated = my_migration_sender.send_if_modified(|watched_state| {
        if *watched_state != my_migration_state {
            tracing::info!("my migration state changed: {:?}", my_migration_state);
            *watched_state = my_migration_state;
            true
        } else {
            false
        }
    });

    contract_updated | my_state_updated
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

#[cfg(test)]
mod tests {
    use crate::trait_extensions::convert_to_contract_dto::IntoContractInterfaceType;

    use super::*;
    use mpc_contract::node_migrations::BackupServiceInfo;
    use std::collections::BTreeMap;

    type TestChannels = (
        watch::Sender<(u64, ContractMigrationInfo)>,
        watch::Receiver<(u64, ContractMigrationInfo)>,
        watch::Sender<MigrationInfo>,
        watch::Receiver<MigrationInfo>,
    );

    fn create_migration_info_with_account(
        account_id: &str,
    ) -> (
        AccountId,
        (Option<BackupServiceInfo>, Option<DestinationNodeInfo>),
    ) {
        let account: AccountId = account_id.parse().unwrap();
        (account, (None, None))
    }

    fn test_account_and_key() -> (AccountId, VerifyingKey) {
        let account = "test.near".parse().unwrap();
        let key = VerifyingKey::from_bytes(&[1u8; 32]).unwrap();
        (account, key)
    }

    fn create_test_state(
        initial_block_height: u64,
        initial_migration_info: ContractMigrationInfo,
    ) -> TestChannels {
        let initial_state = (initial_block_height, initial_migration_info);
        let (contract_migration_sender, contract_migration_receiver) =
            watch::channel(initial_state);

        let initial_my_state = MigrationInfo {
            backup_service_info: None,
            active_migration: false,
        };
        let (my_migration_sender, my_migration_receiver) = watch::channel(initial_my_state);

        (
            contract_migration_sender,
            contract_migration_receiver,
            my_migration_sender,
            my_migration_receiver,
        )
    }

    #[test]
    fn test_process_migration_response_does_not_update_on_block_height_change_only() {
        // Given: Initial state with migration info
        let migration_info: ContractMigrationInfo = BTreeMap::new();
        let (
            contract_migration_sender,
            contract_migration_receiver,
            my_migration_sender,
            my_migration_receiver,
        ) = create_test_state(100, migration_info.clone());
        let (my_account, my_key) = test_account_and_key();

        // When: Processing a response with same migration info but different block height
        let new_response = (200u64, migration_info);
        let updated = process_migration_response(
            &new_response,
            &contract_migration_sender,
            &my_migration_sender,
            &my_account,
            &my_key,
        );

        // Then: No channels should be updated
        assert!(!updated, "Should not update when only block height changes");
        assert!(!contract_migration_receiver.has_changed().unwrap());
        assert!(!my_migration_receiver.has_changed().unwrap());
    }

    #[test]
    fn test_process_migration_response_updates_on_migration_info_change() {
        // Given: Initial empty migration state
        let empty_migration_info: ContractMigrationInfo = BTreeMap::new();
        let (
            contract_migration_sender,
            mut contract_migration_receiver,
            my_migration_sender,
            my_migration_receiver,
        ) = create_test_state(100, empty_migration_info);
        let (my_account, my_key) = test_account_and_key();

        // When: Processing a response with new migration info
        let mut new_migration_info = BTreeMap::new();
        let (account_id, migration_data) = create_migration_info_with_account("another.near");
        new_migration_info.insert(account_id, migration_data);
        let new_response = (200u64, new_migration_info.clone());

        let updated = process_migration_response(
            &new_response,
            &contract_migration_sender,
            &my_migration_sender,
            &my_account,
            &my_key,
        );

        // Then: Contract channel should be updated, but not my migration channel (since my account isn't in the migration)
        assert!(updated, "Should update when migration info changes");
        assert!(contract_migration_receiver.has_changed().unwrap());
        assert!(
            !my_migration_receiver.has_changed().unwrap(),
            "My migration channel should not update when my account is not involved"
        );

        let contract_state = contract_migration_receiver.borrow_and_update();
        assert_eq!(
            contract_state.1, new_migration_info,
            "Contract state should match new migration info"
        );
    }

    #[test]
    fn test_process_migration_response_updates_my_migration_when_i_am_added() {
        // Given: Initial state without my account
        let empty_migration_info: ContractMigrationInfo = BTreeMap::new();
        let (
            contract_migration_sender,
            mut contract_migration_receiver,
            my_migration_sender,
            mut my_migration_receiver,
        ) = create_test_state(100, empty_migration_info);
        let (my_account, my_key) = test_account_and_key();

        // When: Processing a response where my account is added
        let expected_backup_service = BackupServiceInfo {
            public_key: my_key.into_contract_interface_type(),
        };
        let mut new_migration_info = BTreeMap::new();
        new_migration_info.insert(
            my_account.clone(),
            (Some(expected_backup_service.clone()), None),
        );
        let new_block_height: u64 = 200u64;
        let new_response = (new_block_height, new_migration_info.clone());

        let updated = process_migration_response(
            &new_response,
            &contract_migration_sender,
            &my_migration_sender,
            &my_account,
            &my_key,
        );

        // Then: Both channels should be updated (contract state changed AND my account was added)
        assert!(updated, "Should update when my account is added");
        assert!(contract_migration_receiver.has_changed().unwrap());
        assert!(my_migration_receiver.has_changed().unwrap());

        let contract_state = contract_migration_receiver.borrow_and_update();
        assert_eq!(contract_state.0, new_block_height);
        assert_eq!(contract_state.1, new_migration_info);

        let my_state = my_migration_receiver.borrow_and_update();
        assert_eq!(my_state.backup_service_info, Some(expected_backup_service));
        assert!(!my_state.active_migration);
    }

    #[test]
    fn test_process_migration_response_handles_multiple_sequential_updates() {
        // Given: Initial empty state
        let empty_migration_info: ContractMigrationInfo = BTreeMap::new();
        let (
            contract_migration_sender,
            contract_migration_receiver,
            my_migration_sender,
            my_migration_receiver,
        ) = create_test_state(100, empty_migration_info);
        let (my_account, my_key) = test_account_and_key();

        // When: Processing multiple responses with block height changes (no migration changes)
        for block_height in 101..105 {
            let response = (block_height, BTreeMap::new());
            let updated = process_migration_response(
                &response,
                &contract_migration_sender,
                &my_migration_sender,
                &my_account,
                &my_key,
            );

            // Then: Should not update on any block height-only change
            assert!(
                !updated,
                "Should not update on block height {} when migration info unchanged",
                block_height
            );
        }

        // Verify no spurious updates occurred on either channel
        assert!(!contract_migration_receiver.has_changed().unwrap());
        assert!(!my_migration_receiver.has_changed().unwrap());
    }
}
