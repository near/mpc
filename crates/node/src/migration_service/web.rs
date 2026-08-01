#![allow(dead_code)]
pub mod authentication;
pub mod client;
pub mod encryption;
pub mod serialization;
pub mod server;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
pub mod types;

#[cfg(test)]
mod tests {

    use ed25519_dalek::SigningKey;
    use near_mpc_contract_interface::types::BackupServiceInfo;
    use rand::SeedableRng as _;
    use rand::rngs::{OsRng, StdRng};
    use serial_test::serial;

    use super::test_utils::setup;
    use crate::keyshare::{Keyshare, test_utils::KeysetBuilder};
    use crate::metrics;
    use crate::migration_service::web::client::{
        connect_to_web_server, make_hello_request, make_keyshare_get_request,
        make_set_keyshares_request,
    };
    use crate::{migration_service::types::MigrationInfo, p2p::testing::port_seed};

    #[tokio::test]
    async fn test_web_success_hello_world() {
        let test_setup = setup(port_seed::MIGRATION_WEBSERVER_SUCCESS_TEST).await;

        let mut send_request = connect_to_web_server(
            &test_setup.client_key,
            &test_setup.target_address,
            &test_setup.server_key.verifying_key(),
        )
        .await
        .unwrap();
        let res = make_hello_request(&mut send_request).await.unwrap();
        assert_eq!("Hello, world!", res);
    }

    #[tokio::test]
    async fn test_web_failure() {
        let test_setup = setup(port_seed::MIGRATION_WEBSERVER_FAILURE_TEST).await;
        let wrong_backup_service_info = MigrationInfo {
            backup_service_info: Some(BackupServiceInfo {
                public_key: SigningKey::generate(&mut OsRng).to_bytes().into(),
            }),
            active_migration: false,
        };
        test_setup
            .migration_state_sender
            .send(wrong_backup_service_info)
            .unwrap();

        // the handshake will still pass. it is only after we try to send data that we realize the
        // server closed the connection.
        let mut send_request = connect_to_web_server(
            &test_setup.client_key,
            &test_setup.target_address,
            &test_setup.server_key.verifying_key(),
        )
        .await
        .unwrap();

        let res = make_hello_request(&mut send_request).await;
        let _ = res.expect_err("Hello request should fail after server closes connection");
    }

    #[tokio::test]
    async fn test_web_success_get_keyshares() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let test_setup = setup(port_seed::MIGRATION_WEBSERVER_SUCCESS_TEST_GET_KEYSHARES).await;

        let mut send_request = connect_to_web_server(
            &test_setup.client_key,
            &test_setup.target_address,
            &test_setup.server_key.verifying_key(),
        )
        .await
        .unwrap();
        let keyset_dto: near_mpc_contract_interface::types::Keyset = KeysetBuilder::new(1).keyset();
        let res = make_keyshare_get_request(
            &mut send_request,
            &keyset_dto,
            &test_setup.backup_encryption_key,
        )
        .await
        .unwrap();

        let expected: Vec<Keyshare> = Vec::new();
        assert_eq!(expected, res);

        let keyset_builder = KeysetBuilder::new_populated(0, 8, &mut rng);

        test_setup
            .keyshare_storage
            .write()
            .await
            .import_backup(
                keyset_builder.keyshares().to_vec(),
                &keyset_builder.keyset(),
            )
            .await
            .unwrap();
        let keyset_dto: near_mpc_contract_interface::types::Keyset = keyset_builder.keyset();
        let res = make_keyshare_get_request(
            &mut send_request,
            &keyset_dto,
            &test_setup.backup_encryption_key,
        )
        .await
        .unwrap();
        assert_eq!(keyset_builder.keyshares().to_vec(), res);
    }

    #[serial(backup_metrics)]
    #[tokio::test]
    #[expect(non_snake_case)]
    async fn migration_web_server__should_record_backup_served_when_keyshares_are_returned() {
        // Given
        let mut rng = StdRng::seed_from_u64(42);
        let epoch_id = 5;
        let test_setup = setup(port_seed::MIGRATION_WEBSERVER_BACKUP_SERVED_TEST).await;
        let mut send_request = connect_to_web_server(
            &test_setup.client_key,
            &test_setup.target_address,
            &test_setup.server_key.verifying_key(),
        )
        .await
        .unwrap();
        let keyset_builder = KeysetBuilder::new_populated(epoch_id, 8, &mut rng);
        let keyset_dto = keyset_builder.keyset();
        test_setup
            .keyshare_storage
            .write()
            .await
            .import_backup(keyset_builder.keyshares().to_vec(), &keyset_dto)
            .await
            .unwrap();

        // When
        make_keyshare_get_request(
            &mut send_request,
            &keyset_dto,
            &test_setup.backup_encryption_key,
        )
        .await
        .unwrap();

        // Then
        assert_eq!(
            metrics::MPC_LAST_BACKUP_SERVED_EPOCH.get(),
            i64::try_from(epoch_id).unwrap()
        );
        assert!(metrics::MPC_LAST_BACKUP_SERVED_TIMESTAMP_SECONDS.get() > 0);
    }

    #[serial(backup_metrics)]
    #[tokio::test]
    #[expect(non_snake_case)]
    async fn migration_web_server__should_not_record_backup_served_for_an_empty_keyset() {
        // Given
        let test_setup = setup(port_seed::MIGRATION_WEBSERVER_EMPTY_KEYSET_TEST).await;
        let mut send_request = connect_to_web_server(
            &test_setup.client_key,
            &test_setup.target_address,
            &test_setup.server_key.verifying_key(),
        )
        .await
        .unwrap();
        let epoch_before = metrics::MPC_LAST_BACKUP_SERVED_EPOCH.get();
        let timestamp_before = metrics::MPC_LAST_BACKUP_SERVED_TIMESTAMP_SECONDS.get();

        // When
        let keyshares = make_keyshare_get_request(
            &mut send_request,
            &KeysetBuilder::new(5).keyset(),
            &test_setup.backup_encryption_key,
        )
        .await
        .unwrap();

        // Then
        assert!(keyshares.is_empty());
        assert_eq!(metrics::MPC_LAST_BACKUP_SERVED_EPOCH.get(), epoch_before);
        assert_eq!(
            metrics::MPC_LAST_BACKUP_SERVED_TIMESTAMP_SECONDS.get(),
            timestamp_before
        );
    }

    #[serial(backup_metrics)]
    #[tokio::test]
    #[expect(non_snake_case)]
    async fn migration_web_server__should_not_record_backup_served_for_a_keyset_it_does_not_hold() {
        // Given
        let mut rng = StdRng::seed_from_u64(42);
        let test_setup = setup(port_seed::MIGRATION_WEBSERVER_BACKUP_NOT_SERVED_TEST).await;
        let mut send_request = connect_to_web_server(
            &test_setup.client_key,
            &test_setup.target_address,
            &test_setup.server_key.verifying_key(),
        )
        .await
        .unwrap();
        let held = KeysetBuilder::new_populated(5, 8, &mut rng);
        test_setup
            .keyshare_storage
            .write()
            .await
            .import_backup(held.keyshares().to_vec(), &held.keyset())
            .await
            .unwrap();
        let requested = KeysetBuilder::new_populated(6, 8, &mut rng).keyset();
        let epoch_before = metrics::MPC_LAST_BACKUP_SERVED_EPOCH.get();
        let timestamp_before = metrics::MPC_LAST_BACKUP_SERVED_TIMESTAMP_SECONDS.get();

        // When
        let res = make_keyshare_get_request(
            &mut send_request,
            &requested,
            &test_setup.backup_encryption_key,
        )
        .await;

        // Then
        let err = res.expect_err("request for a keyset the node does not hold should fail");
        assert!(err.to_string().contains("500"), "{err}");
        assert_eq!(metrics::MPC_LAST_BACKUP_SERVED_EPOCH.get(), epoch_before);
        assert_eq!(
            metrics::MPC_LAST_BACKUP_SERVED_TIMESTAMP_SECONDS.get(),
            timestamp_before
        );
    }

    #[tokio::test]
    async fn test_web_success_set_keyshares() {
        let mut rng = rand::rngs::StdRng::from_seed([1u8; 32]);
        let mut test_setup = setup(port_seed::MIGRATION_WEBSERVER_SUCCESS_TEST_SET_KEYSHARES).await;

        let mut send_request = connect_to_web_server(
            &test_setup.client_key,
            &test_setup.target_address,
            &test_setup.server_key.verifying_key(),
        )
        .await
        .unwrap();

        let received = test_setup
            .import_keyshares_receiver
            .borrow_and_update()
            .clone();
        let expected: Vec<Keyshare> = Vec::new();
        assert_eq!(expected, received);

        let keyset_builder = KeysetBuilder::new_populated(0, 8, &mut rng);
        make_set_keyshares_request(
            &mut send_request,
            keyset_builder.keyshares(),
            &test_setup.backup_encryption_key,
        )
        .await
        .unwrap();

        let received = test_setup
            .import_keyshares_receiver
            .borrow_and_update()
            .clone();
        assert_eq!(keyset_builder.keyshares().to_vec(), received);
    }

    #[tokio::test]
    async fn test_cancellation_if_migration_info_changes() {
        let test_setup = setup(port_seed::MIGRATION_WEBSERVER_CHANGE_MIGRATION_INFO).await;

        let mut send_request = connect_to_web_server(
            &test_setup.client_key,
            &test_setup.target_address,
            &test_setup.server_key.verifying_key(),
        )
        .await
        .unwrap();
        let res = make_hello_request(&mut send_request).await.unwrap();
        assert_eq!("Hello, world!", res);
        let wrong_backup_service_info = MigrationInfo {
            backup_service_info: Some(BackupServiceInfo {
                public_key: SigningKey::generate(&mut OsRng).to_bytes().into(),
            }),
            active_migration: false,
        };
        test_setup
            .migration_state_sender
            .send(wrong_backup_service_info)
            .unwrap();
        let _ = make_hello_request(&mut send_request)
            .await
            .expect_err("Hello request should fail after migration info changes");
    }
}
