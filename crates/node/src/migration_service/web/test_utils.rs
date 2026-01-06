use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use aes_gcm::{Aes256Gcm, KeyInit};
use ed25519_dalek::SigningKey;
use mpc_contract::node_migrations::BackupServiceInfo;
use rand::rngs::OsRng;
use tempfile::TempDir;
use tokio::sync::{watch, RwLock};

use crate::{
    config::AesKey256,
    keyshare::{generate_key_storage, Keyshare, KeyshareStorage},
    migration_service::{
        types::MigrationInfo,
        web::{server::start_web_server, types::WebServerState},
    },
    p2p::testing::PortSeed,
};

pub struct TestSetup {
    pub backup_encryption_key: AesKey256,
    pub client_key: SigningKey,
    pub server_key: SigningKey,
    pub target_address: SocketAddr,
    pub migration_state_sender: watch::Sender<MigrationInfo>,
    pub import_keyshares_receiver: watch::Receiver<Vec<Keyshare>>,
    pub keyshare_storage: Arc<RwLock<KeyshareStorage>>,
    pub _tmpdir: TempDir,
}

pub async fn setup(port_seed: PortSeed) -> TestSetup {
    let backup_encryption_key = Aes256Gcm::generate_key(OsRng);
    let client_key = SigningKey::generate(&mut OsRng);
    let server_key = SigningKey::generate(&mut OsRng);

    let port: u16 = port_seed.migration_web_port(0);
    let target_address = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);

    let (migration_state_sender, migration_state_receiver) = watch::channel(MigrationInfo {
        backup_service_info: Some(BackupServiceInfo {
            public_key: client_key.verifying_key().to_bytes().into(),
        }),
        active_migration: false,
    });

    let (storage, _tmpdir) = generate_key_storage().await;
    let keyshare_storage = Arc::new(RwLock::new(storage));

    let (import_keyshares_sender, import_keyshares_receiver) = watch::channel(vec![]);
    let web_server_state = Arc::new(WebServerState {
        import_keyshares_sender: import_keyshares_sender.clone(),
        keyshare_storage: keyshare_storage.clone(),
        backup_encryption_key: backup_encryption_key.into(),
    });
    assert!(start_web_server(
        web_server_state.clone(),
        target_address,
        migration_state_receiver,
        &server_key,
    )
    .await
    .is_ok());
    TestSetup {
        backup_encryption_key: backup_encryption_key.into(),
        client_key,
        server_key,
        target_address,
        migration_state_sender,
        import_keyshares_receiver,
        keyshare_storage,
        _tmpdir,
    }
}
