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
    use mpc_contract::node_migrations::BackupServiceInfo;
    use rand::rngs::OsRng;

    use super::test_utils::setup;
    use crate::keyshare::{test_utils::KeysetBuilder, Keyshare};
    use crate::migration_service::web::client::{
        connect_to_web_server, make_hello_request, make_keyshare_get_request,
        make_set_keyshares_request,
    };
    use crate::{migration_service::types::MigrationInfo, p2p::testing::PortSeed};

    #[tokio::test]
    async fn test_web_success_hello_world() {
        let test_setup = setup(PortSeed::MIGRATION_WEBSERVER_SUCCESS_TEST).await;

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
        let test_setup = setup(PortSeed::MIGRATION_WEBSERVER_FAILURE_TEST).await;
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
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_web_success_get_keyshares() {
        let test_setup = setup(PortSeed::MIGRATION_WEBSERVER_SUCCESS_TEST_GET_KEYSHARES).await;

        let mut send_request = connect_to_web_server(
            &test_setup.client_key,
            &test_setup.target_address,
            &test_setup.server_key.verifying_key(),
        )
        .await
        .unwrap();
        let res = make_keyshare_get_request(
            &mut send_request,
            &KeysetBuilder::new(1).keyset(),
            &test_setup.backup_encryption_key,
        )
        .await
        .unwrap();

        let expected: Vec<Keyshare> = Vec::new();
        assert_eq!(expected, res);

        let keyset_builder = KeysetBuilder::new_populated(0, 8);

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
        let res = make_keyshare_get_request(
            &mut send_request,
            &keyset_builder.keyset(),
            &test_setup.backup_encryption_key,
        )
        .await
        .unwrap();
        assert_eq!(keyset_builder.keyshares().to_vec(), res);
    }

    #[tokio::test]
    async fn test_web_success_set_keyshares() {
        let mut test_setup = setup(PortSeed::MIGRATION_WEBSERVER_SUCCESS_TEST_SET_KEYSHARES).await;

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

        let keyset_builder = KeysetBuilder::new_populated(0, 8);
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
        let test_setup = setup(PortSeed::MIGRATION_WEBSERVER_CHANGE_MIGRATION_INFO).await;

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
        assert!(make_hello_request(&mut send_request).await.is_err());
    }
}
