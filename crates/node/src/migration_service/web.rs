#![allow(dead_code)]
pub mod authentication;
pub mod client;
pub mod server;
pub mod types;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use mpc_contract::node_migrations::BackupServiceInfo;
    use rand::rngs::OsRng;
    use tokio::sync::watch;
    use tokio_util::sync::CancellationToken;

    use crate::keyshare::{Keyshare, test_utils::KeysetBuilder};
    use crate::migration_service::web::client::{
        connect_to_web_server, make_hello_request, make_keyshare_get_request,
        make_set_keyshares_request,
    };
    use crate::migration_service::web::{server::start_web_server, types::WebServerState};
    use crate::{
        config::WebUIConfig, migration_service::types::MigrationInfo, p2p::testing::PortSeed,
    };

    const LOCALHOST_IP: &str = "127.0.0.1";

    struct TestSetup {
        client_key: SigningKey,
        server_key: SigningKey,
        target_address: String,
        migration_state_sender: watch::Sender<MigrationInfo>,
        import_keyshares_receiver: watch::Receiver<Vec<Keyshare>>,
        export_keyshares_sender: watch::Sender<Vec<Keyshare>>,
    }

    async fn setup(port_seed: PortSeed) -> TestSetup {
        let client_key = SigningKey::generate(&mut OsRng);
        let server_key = SigningKey::generate(&mut OsRng);

        let port: u16 = port_seed.p2p_port(0);
        let config = WebUIConfig {
            host: LOCALHOST_IP.to_string(),
            port,
        };
        let (migration_state_sender, migration_state_receiver) = watch::channel(MigrationInfo {
            backup_service_info: Some(BackupServiceInfo {
                public_key: client_key.verifying_key().to_bytes().into(),
            }),
            active_migration: false,
        });
        let (import_keyshares_sender, import_keyshares_receiver) = watch::channel(vec![]);
        let (export_keyshares_sender, export_keyshares_receiver) = watch::channel(vec![]);
        let web_server_state = Arc::new(WebServerState {
            import_keyshares_sender,
            export_keyshares_receiver,
        });
        assert!(start_web_server(
            web_server_state.clone(),
            config,
            migration_state_receiver,
            &server_key,
            CancellationToken::new()
        )
        .await
        .is_ok());
        let target_address = format!("{LOCALHOST_IP}:{port}");
        TestSetup {
            client_key,
            server_key,
            target_address,
            migration_state_sender,
            import_keyshares_receiver,
            export_keyshares_sender,
        }
    }

    #[tokio::test]
    async fn test_web_success_hello_world() {
        let test_setup = setup(PortSeed::MIGRATION_WEBSERVER_SUCCESS_TEST).await;

        let mut send_request = connect_to_web_server(
            &test_setup.client_key,
            &test_setup.target_address,
            test_setup.server_key.verifying_key(),
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
            test_setup.server_key.verifying_key(),
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
            test_setup.server_key.verifying_key(),
        )
        .await
        .unwrap();
        let res = make_keyshare_get_request(&mut send_request).await.unwrap();

        let expected: Vec<Keyshare> = Vec::new();
        assert_eq!(expected, res);

        let keyset_builder = KeysetBuilder::new_populated(0, 8);
        test_setup
            .export_keyshares_sender
            .send(keyset_builder.keyshares().to_vec())
            .unwrap();
        let res = make_keyshare_get_request(&mut send_request).await.unwrap();
        assert_eq!(keyset_builder.keyshares().to_vec(), res);
    }

    #[tokio::test]
    async fn test_web_success_set_keyshares() {
        let mut test_setup = setup(PortSeed::MIGRATION_WEBSERVER_SUCCESS_TEST_SET_KEYSHARES).await;

        let mut send_request = connect_to_web_server(
            &test_setup.client_key,
            &test_setup.target_address,
            test_setup.server_key.verifying_key(),
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
        make_set_keyshares_request(&mut send_request, keyset_builder.keyshares().to_vec())
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
            test_setup.server_key.verifying_key(),
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
