use ed25519_dalek::VerifyingKey;
use near_account_id::AccountId;
use near_contract_transport::ViewContract;
use near_mpc_contract_interface::client::MpcContractHandle;
pub use near_mpc_contract_interface::types::MigrationInfo as ContractMigrationInfo;
use tokio::sync::watch;

use crate::migration_service::types::{MigrationInfo, active_migration, backup_service_tls_key};

const MIGRATION_INFO_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Blocks until the indexer has a current view of the blockchain.
/// Spawns monitoring tasks to fetch the migration info and this account's attested backup service
/// from the contract. Returns a tokio watch channel on which the latest migration state can be
/// watched.
///
/// The interval checking for new values is defined by [`MIGRATION_INFO_REFRESH_INTERVAL`]
pub async fn monitor_migrations<V: ViewContract + Clone + Send + Sync + 'static>(
    contract: MpcContractHandle<V>,
    migration_state_sender: watch::Sender<(u64, ContractMigrationInfo)>,
    my_near_account_id: AccountId,
    my_p2p_public_key: VerifyingKey,
) -> watch::Receiver<MigrationInfo> {
    let init_response = fetch_migrations_once(&contract).await;
    let (sender, receiver) = watch::channel(MigrationInfo {
        backup_service_tls_key: None,
        active_migration: active_migration(
            &my_near_account_id,
            &my_p2p_public_key,
            &init_response.1,
        ),
    });

    tokio::spawn(monitor_attested_backup_service(
        contract.clone(),
        my_near_account_id.clone(),
        sender.clone(),
    ));
    tokio::spawn({
        let mut interval = tokio::time::interval(MIGRATION_INFO_REFRESH_INTERVAL);
        async move {
            loop {
                interval.tick().await;
                let response = fetch_migrations_once(&contract).await;
                tracing::debug!(target: "indexer", "fetched mpc migration state at block {}: {:?}", response.0, response.1);

                let mut migration_info_changed = false;
                migration_state_sender.send_if_modified(|watched_state| {
                    migration_info_changed = watched_state.1 != response.1;
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

                // Re-deriving an unchanged view would repeat its diagnostics on every tick.
                if !migration_info_changed {
                    continue;
                }

                let migrating =
                    active_migration(&my_near_account_id, &my_p2p_public_key, &response.1);
                sender.send_if_modified(|watched_state| {
                    let changed = std::mem::replace(&mut watched_state.active_migration, migrating)
                        != migrating;
                    if changed {
                        tracing::info!(active_migration = migrating, "my migration state changed");
                    }
                    changed
                });
            }
        }
    });

    receiver
}

async fn monitor_attested_backup_service<V: ViewContract + Clone + Send + Sync + 'static>(
    contract: MpcContractHandle<V>,
    my_near_account_id: AccountId,
    sender: watch::Sender<MigrationInfo>,
) {
    let mut interval = tokio::time::interval(MIGRATION_INFO_REFRESH_INTERVAL);
    let mut view_failed = false;
    loop {
        interval.tick().await;
        let response = contract
            .attested_backup_service(my_near_account_id.clone())
            .await;
        // A contract that predates the view fails every poll, so warn only when failures start
        if let Err(err) = &response
            && !view_failed
        {
            tracing::warn!(?err, "could not read the attested backup service");
        }
        view_failed = response.is_err();
        let tls_key = response
            .ok()
            .and_then(|observed| observed.value)
            .as_ref()
            .and_then(backup_service_tls_key);
        sender.send_if_modified(|watched_state| {
            let changed =
                std::mem::replace(&mut watched_state.backup_service_tls_key, tls_key) != tls_key;
            if changed {
                tracing::info!(?tls_key, "attested backup service changed");
            }
            changed
        });
    }
}

async fn fetch_migrations_once<C: ViewContract + Clone + Send + 'static>(
    contract: &MpcContractHandle<C>,
) -> (u64, ContractMigrationInfo) {
    loop {
        tracing::debug!(target: "indexer", "querying migration state");

        match contract.migration_info().await {
            Ok(observed) => {
                return (observed.observed_at.into(), observed.value);
            }
            Err(e) => {
                tracing::error!(target: "mpc", "error reading config from chain during migration_info: {:?}", e);
                tokio::time::sleep(MIGRATION_INFO_REFRESH_INTERVAL).await;
            }
        }
    }
}

#[cfg(test)]
#[expect(non_snake_case)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use ed25519_dalek::SigningKey;
    use near_contract_transport::{
        SerializedObservation,
        mock::{MockViewContract, MockViewError, observed},
    };
    use near_mpc_contract_interface::{
        call_args::AccountIdArgs,
        method_names::{ATTESTED_BACKUP_SERVICE, MIGRATION_INFO},
        types::BackupServiceInfo,
    };
    use rstest::rstest;

    use super::*;
    use crate::indexer::tests::contract;

    fn my_account_id() -> AccountId {
        "operator.near".parse().unwrap()
    }

    fn backup_service_key() -> VerifyingKey {
        SigningKey::from_bytes(&[1; 32]).verifying_key()
    }

    fn backup_service() -> BackupServiceInfo {
        BackupServiceInfo {
            public_key: (&backup_service_key()).into(),
        }
    }

    fn attested() -> Result<SerializedObservation, MockViewError> {
        observed(&Some(backup_service()))
    }

    fn view_missing() -> Result<SerializedObservation, MockViewError> {
        Err(MockViewError("no such view"))
    }

    /// Lists the backup service in the migration info whatever the attested view returns
    fn viewer(
        attested_backup_service: Result<SerializedObservation, MockViewError>,
    ) -> MockViewContract {
        let viewer = MockViewContract::new(Err(MockViewError("unexpected view")));
        let migration_info = ContractMigrationInfo::from(BTreeMap::from([(
            my_account_id(),
            (Some(backup_service()), None),
        )]));
        viewer.set_view_response_for_method(MIGRATION_INFO, observed(&migration_info));
        viewer.set_view_response_for_method(ATTESTED_BACKUP_SERVICE, attested_backup_service);
        viewer
    }

    async fn start_monitor(viewer: &MockViewContract) -> watch::Receiver<MigrationInfo> {
        monitor_migrations(
            contract(viewer),
            watch::Sender::new(Default::default()),
            my_account_id(),
            SigningKey::from_bytes(&[2; 32]).verifying_key(),
        )
        .await
    }

    #[rstest]
    #[case::valid(attested(), Some(backup_service_key()))]
    #[case::not_attested(observed(&None::<BackupServiceInfo>), None)]
    #[case::view_missing(view_missing(), None)]
    #[tokio::test(start_paused = true)]
    async fn monitor_migrations__should_expect_a_backup_service_only_while_its_attestation_is_valid(
        #[case] attested_backup_service: Result<SerializedObservation, MockViewError>,
        #[case] expected_backup_service_tls_key: Option<VerifyingKey>,
    ) {
        // Given
        let viewer = viewer(attested());
        let mut migration_info = start_monitor(&viewer).await;
        migration_info
            .wait_for(|info| info.backup_service_tls_key.is_some())
            .await
            .unwrap();

        // When
        viewer.set_view_response_for_method(ATTESTED_BACKUP_SERVICE, attested_backup_service);
        tokio::time::sleep(MIGRATION_INFO_REFRESH_INTERVAL * 2).await;

        // Then
        let queried_args: BTreeSet<_> = viewer
            .calls()
            .into_iter()
            .filter(|call| call.method_name == ATTESTED_BACKUP_SERVICE)
            .map(|call| call.args)
            .collect();
        assert_eq!(
            (queried_args, migration_info.borrow().clone()),
            (
                BTreeSet::from([serde_json::to_vec(&AccountIdArgs::new(my_account_id())).unwrap()]),
                MigrationInfo {
                    backup_service_tls_key: expected_backup_service_tls_key,
                    active_migration: false,
                }
            )
        );
    }

    #[tokio::test(start_paused = true)]
    async fn monitor_migrations__should_start_while_the_backup_service_view_is_missing() {
        // Given
        let viewer = viewer(view_missing());

        // When
        let migration_info =
            tokio::time::timeout(MIGRATION_INFO_REFRESH_INTERVAL, start_monitor(&viewer))
                .await
                .unwrap();

        // Then
        assert_eq!(
            *migration_info.borrow(),
            MigrationInfo {
                backup_service_tls_key: None,
                active_migration: false,
            }
        );
    }
}
